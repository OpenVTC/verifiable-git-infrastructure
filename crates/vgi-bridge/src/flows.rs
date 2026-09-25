//! Flows that wait for a person: namespace binds, account links, and the
//! GitHub App registration.
//!
//! Each waits under a single-use `state` (256 bits from the CSPRNG) that the
//! forge hands back on its redirect. The pending record is **taken** —
//! deleted — before the callback is acted on, so a `state` completes at most
//! once whatever happens next. A flow nobody completes ends, at its expiry,
//! in a `failed` result with code `expired` (spec: job rule 5).

use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{TimeZone, Utc};
use serde_json::{Value, json};
use vgi_forge::{
    BindCallback, BindRequest, BindStep, ForgeAccount, ForgeError, LinkCallback, LinkStep,
    NamespaceKind, Resource,
};

use crate::bridge::{Bridge, now};
use crate::jobs::Ctx;
use crate::mapping::{self, Report};
use crate::store::{
    DevicePoll, JobRecord, JobState, NamespaceRecord, NamespaceState, PendingFlow, Table,
};
use crate::wire::job;

/// A fresh flow `state`.
pub(crate) fn new_state() -> String {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).expect("system RNG");
    URL_SAFE_NO_PAD.encode(b)
}

fn device_secret(state: &str) -> String {
    format!("pending/{state}/device")
}

pub(crate) fn rfc3339(unix: i64) -> String {
    Utc.timestamp_opt(unix, 0)
        .single()
        .unwrap_or_else(Utc::now)
        .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The job response's `next`, checked against the generated type (an
/// `https` URL, bounded lengths).
fn next(url: &str, user_code: Option<&str>, expires_at: i64) -> Result<Value, Report> {
    let mut v = json!({ "url": url, "expiresAt": rfc3339(expires_at) });
    if let Some(c) = user_code {
        v["userCode"] = json!(c);
    }
    match serde_json::from_value::<job::ResponseNext>(v.clone()) {
        Ok(_) => Ok(v),
        Err(e) => {
            let mut r = Report::default();
            r.fail_with(
                "forgeError",
                format!("the forge's link is not a valid `next` ({e})"),
            );
            Err(r)
        }
    }
}

/// Start a `beginBind` or `beginAccountLink` job: returns the job
/// response's `next`, or the report of why it could not start.
pub(crate) async fn begin(bridge: &Arc<Bridge>, p: &job::Payload) -> Result<Value, Report> {
    let job_id = p.job_id.to_string();
    let ns_id = p.namespace.to_string();
    let fail = |e: &ForgeError| {
        let mut r = Report::default();
        r.fail(e);
        r
    };
    let expires_at = now() + bridge.cfg.flow_ttl_secs as i64;
    match p.kind {
        job::PayloadKind::BeginBind => {
            let target = p.target.as_ref().expect("checked by kind");
            let resource =
                Resource::namespace_of(&target.forge, &target.owner).map_err(|e| fail(&e))?;
            let adapter = bridge.adapters.for_resource(&resource).ok_or_else(|| {
                fail(&ForgeError::NotBound {
                    namespace: resource.to_string(),
                })
            })?;
            let _ = bridge.store.put_new(
                Table::Namespaces,
                &ns_id,
                &NamespaceRecord::pending(ns_id.clone(), resource.clone()),
            );
            let state = new_state();
            let step = adapter
                .forge()
                .begin_bind(BindRequest::new(resource.clone(), state.clone()))
                .await
                .map_err(|e| fail(&e))?;
            let url = match step {
                BindStep::Redirect { url } => url,
                other => return Err(fail(&ForgeError::Protocol(format!("{other:?}")))),
            };
            let flow = PendingFlow::Bind {
                job_id,
                namespace: ns_id,
                resource,
                expires_at,
            };
            bridge
                .store
                .put(Table::Pending, &state, &flow)
                .map_err(|e| fail(&ForgeError::Unavailable(e.to_string())))?;
            next(&url, None, expires_at)
        }
        job::PayloadKind::BeginAccountLink => {
            let member = p.subject.as_ref().expect("checked by kind").to_string();
            let ctx = Ctx::load(bridge, &ns_id).map_err(|m| {
                let mut r = Report::default();
                r.fail_with("notCapable", m);
                r
            })?;
            let host = ctx.ns.resource.host().to_string();
            let step = ctx
                .adapter
                .forge()
                .begin_account_link(&member)
                .await
                .map_err(|e| fail(&e))?;
            match step {
                LinkStep::DeviceCode {
                    device_code,
                    user_code,
                    verification_uri,
                    expires_in,
                    interval,
                } => {
                    let state = new_state();
                    let expires_at = now() + expires_in as i64;
                    let n = next(&verification_uri, Some(&user_code), expires_at)?;
                    // The device code redeems the member's authorisation:
                    // sealed, like every other secret.
                    bridge
                        .store
                        .put_secret(&device_secret(&state), device_code.as_bytes())
                        .map_err(|e| fail(&ForgeError::Unavailable(e.to_string())))?;
                    let flow = PendingFlow::Link {
                        job_id,
                        namespace: ns_id,
                        host,
                        member,
                        expires_at,
                        device: Some(DevicePoll {
                            interval,
                            expires_in,
                        }),
                    };
                    bridge
                        .store
                        .put(Table::Pending, &state, &flow)
                        .map_err(|e| fail(&ForgeError::Unavailable(e.to_string())))?;
                    spawn_device_poll(bridge, state);
                    Ok(n)
                }
                LinkStep::Redirect { url } => {
                    // The adapter's own member-bound `state` is in the URL;
                    // the callback comes back with it.
                    let state = url::Url::parse(&url)
                        .ok()
                        .and_then(|u| {
                            u.query_pairs()
                                .find(|(k, _)| k == "state")
                                .map(|(_, v)| v.into_owned())
                        })
                        .ok_or_else(|| {
                            fail(&ForgeError::Protocol("link URL carries no state".into()))
                        })?;
                    let n = next(&url, None, expires_at)?;
                    let flow = PendingFlow::Link {
                        job_id,
                        namespace: ns_id,
                        host,
                        member,
                        expires_at,
                        device: None,
                    };
                    bridge
                        .store
                        .put(Table::Pending, &state, &flow)
                        .map_err(|e| fail(&ForgeError::Unavailable(e.to_string())))?;
                    Ok(n)
                }
                other => Err(fail(&ForgeError::Protocol(format!("{other:?}")))),
            }
        }
        _ => unreachable!("only begin* jobs start a flow"),
    }
}

/// Take the pending flow `state` (single use), if it has not expired.
fn take(bridge: &Bridge, state: &str) -> Result<PendingFlow> {
    let flow = bridge
        .store
        .update::<PendingFlow, _>(Table::Pending, state, |f| Ok((None, f)))?
        .ok_or_else(|| anyhow!("this link is unknown, used, or expired"))?;
    if flow.expires_at() < now() {
        bail!("this link has expired; start again");
    }
    Ok(flow)
}

/// A bind callback (GitHub App setup URL, Forgejo OAuth redirect) for
/// `host`. Returns a line for the admin's browser.
pub(crate) async fn bind_callback(
    bridge: &Arc<Bridge>,
    host: &str,
    route_owner: Option<&str>,
    params: BTreeMap<String, String>,
) -> Result<String> {
    let state = params.get("state").cloned().unwrap_or_default();
    let flow = take(bridge, &state)?;
    let PendingFlow::Bind {
        job_id,
        namespace,
        resource,
        ..
    } = flow
    else {
        bail!("this link is not a namespace bind");
    };
    if resource.host() != host {
        bail!("this bind was started for another forge");
    }
    // A GitHub App's setup redirect names its owner: it must be the App that
    // serves the namespace being bound.
    if let Some(o) = route_owner
        && !bridge
            .cfg
            .github_for(host, resource.owner())
            .is_some_and(|g| g.app_owner.eq_ignore_ascii_case(o))
    {
        bail!("this bind was started for another organisation's App");
    }
    let adapter = bridge
        .adapters
        .for_resource(&resource)
        .context("that forge's adapter is not in service")?;
    let outcome = adapter
        .forge()
        .complete_bind(BindCallback::new(params, state, resource.clone()))
        .await;
    match outcome {
        Ok(binding) => {
            let caps = binding
                .capabilities
                .clone()
                .unwrap_or_else(|| adapter.forge().capabilities(&binding.namespace));
            let mut record = NamespaceRecord::pending(namespace.clone(), resource);
            if let Ok(Some(existing)) = bridge
                .store
                .get::<NamespaceRecord>(Table::Namespaces, &namespace)
            {
                record = existing;
            }
            record.state = NamespaceState::Bound;
            record.required_workflow = binding.capabilities.as_ref().map(|c| c.required_workflow);
            record.capabilities = Some(caps);
            record.binding = Some(binding.clone());
            #[cfg(feature = "forge-github")]
            if let Some(g) = adapter.github() {
                record.bridge_checks = g.bridge_checks_ready(&record.resource);
            }
            bridge.store.put(Table::Namespaces, &namespace, &record)?;
            adapter.restore(&record)?;
            // The VTC grants the bridge's DID `git.commit.sign` on the
            // namespace once it hears the bind completed; look a little
            // later, and warn if the Dependabot re-sign would lack it.
            #[cfg(feature = "forge-github")]
            if adapter.github().is_some() {
                // Weak: a pending warning must not keep a stopped bridge
                // (and its store's lock) alive.
                let me = Arc::downgrade(bridge);
                let id = namespace.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(std::time::Duration::from_secs(120)).await;
                    if let Some(me) = me.upgrade() {
                        crate::resign::warn_if_ungranted(&me, &id).await;
                    }
                });
            }
            let kind = match binding.namespace.kind {
                NamespaceKind::User => "user",
                _ => "organization",
            };
            let owner_id = binding
                .namespace
                .owner_id
                .map(|i| i.to_string())
                .unwrap_or_default();
            let ev = json!({ "type": "bindCompleted", "jobId": job_id, "ownerId": owner_id, "kind": kind });
            bridge.send_event(&namespace, ev, None).await?;
            let mut report = Report::default();
            if !binding.missing_permissions.is_empty() {
                report.step(
                    "permissions",
                    mapping::StepStatus::Unchanged,
                    Some(format!(
                        "the installation lacks: {}",
                        binding.missing_permissions.join(", ")
                    )),
                );
            }
            bridge.finish_job(&job_id, report).await;
            Ok("The namespace is bound. You can close this window.".into())
        }
        Err(e) => {
            let mut report = Report::default();
            report.fail(&e);
            bridge.finish_job(&job_id, report).await;
            Err(anyhow!("the bind did not complete: {e}"))
        }
    }
}

/// An account-link redirect for `host`.
pub(crate) async fn link_callback(
    bridge: &Arc<Bridge>,
    host: &str,
    params: BTreeMap<String, String>,
) -> Result<String> {
    let state = params.get("state").cloned().unwrap_or_default();
    let flow = take(bridge, &state)?;
    let PendingFlow::Link {
        job_id,
        namespace,
        host: flow_host,
        member,
        device: None,
        ..
    } = flow
    else {
        bail!("this link is not an account link");
    };
    if flow_host != host {
        bail!("this link was started for another forge");
    }
    let adapter = bridge
        .adapters
        .get(host)
        .context("that forge's adapter is not in service")?;
    let outcome = adapter
        .forge()
        .complete_account_link(LinkCallback::redirect(params, member))
        .await;
    complete_link(bridge, &job_id, &namespace, host, outcome).await?;
    Ok("Your account is linked. You can close this window.".into())
}

async fn complete_link(
    bridge: &Bridge,
    job_id: &str,
    namespace: &str,
    host: &str,
    outcome: vgi_forge::Result<ForgeAccount>,
) -> Result<()> {
    match outcome {
        Ok(account) => {
            let ev = json!({
                "type": "accountLinked",
                "jobId": job_id,
                "account": mapping::wire_account(host, &account),
            });
            bridge.send_event(namespace, ev, None).await?;
            bridge.finish_job(job_id, Report::default()).await;
            Ok(())
        }
        Err(e) => {
            let mut report = Report::default();
            match &e {
                ForgeError::LinkFailed(m) if m.contains("expired") => {
                    report.fail_with("expired", m.clone())
                }
                _ => report.fail(&e),
            }
            bridge.finish_job(job_id, report).await;
            Err(anyhow!("the link did not complete: {e}"))
        }
    }
}

fn spawn_device_poll(bridge: &Arc<Bridge>, state: String) {
    let bridge = Arc::clone(bridge);
    tokio::spawn(async move {
        if let Err(e) = poll_device(&bridge, &state).await {
            tracing::info!(error = %e, "account link ended");
        }
    });
}

async fn poll_device(bridge: &Bridge, state: &str) -> Result<()> {
    let Some(PendingFlow::Link {
        job_id,
        namespace,
        host,
        device: Some(poll),
        expires_at,
        ..
    }) = bridge.store.get::<PendingFlow>(Table::Pending, state)?
    else {
        return Ok(());
    };
    let device_code = bridge
        .store
        .get_secret_string(&device_secret(state))?
        .context("the device code is gone")?;
    let adapter = bridge
        .adapters
        .get(&host)
        .context("adapter not in service")?;
    let remaining = (expires_at - now()).max(0) as u64;
    let cb = LinkCallback::DeviceCode {
        device_code: device_code.to_string(),
        interval: poll.interval,
        expires_in: remaining.min(poll.expires_in),
    };
    let outcome = adapter.forge().complete_account_link(cb).await;
    // Single use, whatever the outcome.
    bridge.store.delete(Table::Pending, state)?;
    bridge.store.delete_secret(&device_secret(state))?;
    complete_link(bridge, &job_id, &namespace, &host, outcome).await
}

/// After a restart: poll again every device-flow link still in its window.
pub(crate) fn resume_device_polls(bridge: &Arc<Bridge>) -> Result<()> {
    for (state, flow) in bridge.store.list::<PendingFlow>(Table::Pending)? {
        if let PendingFlow::Link {
            device: Some(_),
            expires_at,
            ..
        } = flow
            && expires_at > now()
        {
            spawn_device_poll(bridge, state);
        }
    }
    Ok(())
}

/// End every flow past its expiry: a `failed` result with code `expired`
/// for its job.
pub async fn expire(bridge: &Arc<Bridge>) {
    let Ok(flows) = bridge.store.list::<PendingFlow>(Table::Pending) else {
        return;
    };
    let now = now();
    for (state, flow) in flows {
        // Device polls end on their own; give them a grace minute.
        let grace = if matches!(
            flow,
            PendingFlow::Link {
                device: Some(_),
                ..
            }
        ) {
            60
        } else {
            0
        };
        if flow.expires_at() + grace >= now {
            continue;
        }
        let _ = bridge.store.delete(Table::Pending, &state);
        let _ = bridge.store.delete_secret(&device_secret(&state));
        if let Some(job_id) = flow.job_id() {
            let waiting = matches!(
                bridge.store.get::<JobRecord>(Table::Jobs, job_id),
                Ok(Some(j)) if j.state == JobState::Waiting
            );
            if waiting {
                let mut report = Report::default();
                report.fail_with("expired", "nobody completed it in time");
                bridge.finish_job(job_id, report).await;
            }
        }
    }
}

// ── GitHub App registration (manifest flow) ─────────────────────────────

/// For each configured GitHub App not registered yet — one per
/// organisation — open a registration and log where that organisation's
/// admin goes. The URL carries a one-time `state`; nobody without it can
/// start a registration.
#[cfg(feature = "forge-github")]
pub fn offer_registrations(bridge: &Bridge) -> Result<Vec<String>> {
    let mut urls = Vec::new();
    for g in &bridge.cfg.github {
        if bridge
            .store
            .get_secret(&crate::registry::github_app_secret(&g.host, &g.app_owner))?
            .is_some()
        {
            continue;
        }
        let existing = bridge
            .store
            .list::<PendingFlow>(Table::Pending)?
            .into_iter()
            .find(|(_, f)| {
                matches!(f, PendingFlow::Manifest { host, owner: Some(o), expires_at }
                    if *host == g.host && o.eq_ignore_ascii_case(&g.app_owner) && *expires_at > now())
            });
        let state = match existing {
            Some((s, _)) => s,
            None => {
                let s = new_state();
                bridge.store.put(
                    Table::Pending,
                    &s,
                    &PendingFlow::Manifest {
                        host: g.host.clone(),
                        owner: Some(g.app_owner.clone()),
                        expires_at: now() + 86_400,
                    },
                )?;
                s
            }
        };
        let url = bridge.cfg.url(&format!(
            "github/{}/{}/register?state={state}",
            g.host,
            g.owner_key()
        ));
        tracing::warn!(
            host = %g.host,
            owner = %g.app_owner,
            "the GitHub App for `{}` is not registered yet; an admin of `{}` opens {url} to register it",
            g.app_owner,
            g.app_owner
        );
        urls.push(url.to_string());
    }
    Ok(urls)
}

#[cfg(feature = "forge-github")]
fn github_bases(g: &crate::config::GitHubForgeConfig) -> Result<(url::Url, url::Url)> {
    if let (Some(a), Some(w)) = (&g.api_base, &g.web_base) {
        return Ok((a.clone(), w.clone()));
    }
    if g.host == "github.com" {
        return Ok((
            "https://api.github.com".parse()?,
            "https://github.com".parse()?,
        ));
    }
    let web: url::Url = format!("https://{}", g.host).parse()?;
    Ok((web.join("api/v3")?, web))
}

/// The `[[github]]` entry a registration is for: the one owned by `owner`
/// (exactly — a registration never falls back to another organisation's
/// entry), or, for a registration recorded without an owner, the host's only
/// entry.
#[cfg(feature = "forge-github")]
fn registration_entry<'a>(
    bridge: &'a Bridge,
    host: &str,
    owner: Option<&str>,
) -> Result<&'a crate::config::GitHubForgeConfig> {
    let mut on_host = bridge.cfg.github_on(host);
    match owner {
        Some(o) => on_host
            .find(|g| g.app_owner.eq_ignore_ascii_case(o))
            .with_context(|| format!("no `[[github]]` entry for `{o}` on `{host}`")),
        None => {
            let first = on_host.next().context("not configured")?;
            if on_host.next().is_some() {
                bail!(
                    "this registration names no organisation and `{host}` has several; start again"
                );
            }
            Ok(first)
        }
    }
}

/// Whether the owner a route names (`/github/<host>/<owner>/…`) is the one
/// the flow was opened for. A legacy route (`None`) names none.
fn same_owner(route: Option<&str>, flow: Option<&str>) -> bool {
    match (route, flow) {
        (None, _) => true,
        (Some(r), Some(f)) => r.eq_ignore_ascii_case(f),
        (Some(_), None) => false,
    }
}

/// The page that POSTs the manifest to GitHub (the manifest flow starts
/// with a form submission from the admin's browser). `route_owner`: the
/// organisation the link's path names (`None` on the pre-multi-App path).
#[cfg(feature = "forge-github")]
pub(crate) fn manifest_page(
    bridge: &Bridge,
    host: &str,
    route_owner: Option<&str>,
    state: &str,
) -> Result<String> {
    use vgi_forge_github::manifest::{ManifestParams, app_manifest, registration_url};
    let flow = bridge
        .store
        .get::<PendingFlow>(Table::Pending, state)?
        .ok_or_else(|| anyhow!("unknown or used registration link"))?;
    let PendingFlow::Manifest {
        host: h,
        owner,
        expires_at,
    } = flow
    else {
        bail!("not a registration link");
    };
    if h != host || expires_at < now() || !same_owner(route_owner, owner.as_deref()) {
        bail!("unknown or expired registration link");
    }
    let g = registration_entry(bridge, host, owner.as_deref())?;
    let (_, web) = github_bases(g)?;
    // Every App's own routes: its webhook secret, its setup redirect.
    let base = format!("github/{host}/{}", g.owner_key());
    let params = ManifestParams::new(
        g.app_name.clone(),
        bridge.cfg.public_url.to_string(),
        bridge.cfg.url(&format!("{base}/webhook")).to_string(),
        bridge.cfg.url(&format!("{base}/registered")).to_string(),
    )
    .with_setup_url(bridge.cfg.url(&format!("{base}/setup")).to_string());
    let manifest = app_manifest(&params).to_string();
    // An organisation's App is registered from its settings; a personal
    // account's from the admin's own.
    let org = if g.app_owner_is_user {
        None
    } else {
        Some(g.app_owner.as_str())
    };
    let action = registration_url(&web, org, state);
    Ok(format!(
        "<!doctype html><html><head><meta charset=\"utf-8\"><title>Register the GitHub App</title></head>\
         <body><form id=\"f\" method=\"post\" action=\"{}\">\
         <input type=\"hidden\" name=\"manifest\" value=\"{}\">\
         <button type=\"submit\">Register the community's GitHub App</button></form>\
         <script>document.getElementById('f').submit()</script></body></html>",
        html_escape(action.as_str()),
        html_escape(&manifest)
    ))
}

/// GitHub's redirect after the admin approved the manifest: exchange the
/// code for the App's credentials, seal them, and put the adapter in
/// service.
#[cfg(feature = "forge-github")]
pub(crate) async fn manifest_callback(
    bridge: &Arc<Bridge>,
    host: &str,
    route_owner: Option<&str>,
    code: &str,
    state: &str,
) -> Result<String> {
    use vgi_forge_github::manifest::exchange_code;
    // Read, not taken: the state is consumed only once the exchange has
    // succeeded, so a failed exchange (GitHub down, a network error) can be
    // retried from the same link. GitHub's `code` is single-use itself.
    let flow = bridge
        .store
        .get::<PendingFlow>(Table::Pending, state)?
        .ok_or_else(|| anyhow!("this link is unknown, used, or expired"))?;
    if flow.expires_at() < now() {
        bail!("this link has expired; start again");
    }
    let PendingFlow::Manifest { host: h, owner, .. } = flow else {
        bail!("not a registration link");
    };
    if h != host || !same_owner(route_owner, owner.as_deref()) {
        bail!("this registration was started for another forge or organisation");
    }
    let g = registration_entry(bridge, host, owner.as_deref())?.clone();
    let secret_name = crate::registry::github_app_secret(host, &g.app_owner);
    if bridge.store.get_secret(&secret_name)?.is_some() {
        bail!(
            "an App is already registered for `{}` on {host}; delete the new one on GitHub",
            g.app_owner
        );
    }
    let (api, web) = github_bases(&g)?;
    let expected_owner = g.app_owner.clone();
    let creds = exchange_code(&api, code, &expected_owner).await?;
    bridge.store.delete(Table::Pending, state)?;
    let stored = crate::registry::StoredApp {
        app_id: creds.app_id,
        owner: Some(g.owner_key()),
        slug: creds.slug.clone(),
        client_id: creds.client_id.clone(),
        client_secret: creds.client_secret.expose().to_string(),
        webhook_secret: creds.webhook_secret.expose().to_string(),
        pem: creds.pem.expose().to_string(),
    };
    let json = zeroize::Zeroizing::new(serde_json::to_vec(&stored)?);
    bridge.store.put_secret(&secret_name, &json)?;
    drop(stored);
    // VTA mode: the App's key exists nowhere else (GitHub shows it once), so
    // say whether it reached the VTA before the admin walks away.
    let persisted = bridge.store.flush(std::time::Duration::from_secs(30)).await;
    if !persisted {
        tracing::error!(
            %host,
            "the App's credentials are not in the VTA yet (it is unreachable); the bridge keeps \
             trying — do not stop it until this log says the state was written"
        );
    }
    let forge = crate::registry::build_github(&bridge.store, &g)?
        .context("the App was sealed but does not load")?;
    let keyring = match &g.platform_keyring_file {
        Some(p) => Some(crate::registry::read_keyring(p)?),
        None => None,
    };
    bridge.adapters.insert(
        crate::registry::Adapter::GitHub(forge),
        Some(&g.app_owner),
        crate::registry::vgi_config(&bridge.cfg, keyring),
    );
    bridge.restore_app(host, &g.app_owner)?;
    let settings = web
        .join(&if g.app_owner_is_user {
            format!("settings/apps/{}", creds.slug)
        } else {
            format!(
                "organizations/{expected_owner}/settings/apps/{}",
                creds.slug
            )
        })
        .map(|u| u.to_string())
        .unwrap_or_default();
    let warning = if persisted {
        ""
    } else {
        " Note: the bridge could not write the App's credentials to its VTA yet and keeps trying; \
         its operator should not stop it until its log says the state was written."
    };
    Ok(format!(
        "The App `{}` is registered. One more step: tick \"Enable Device Flow\" on its settings \
         page ({settings}) so members can link their accounts.{warning}",
        creds.slug
    ))
}

/// Minimal HTML escaping for text put into an attribute or element.
pub(crate) fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

// ── Forgejo bot token rotation ───────────────────────────────────────────

/// Rotate each Forgejo bot token that is due, in two phases: mint (the
/// adapter verifies and starts using the new token), **persist** it sealed,
/// and only then retire the old one — so a crash in between leaves at worst
/// an extra live token, never a dead credential.
#[cfg(feature = "forge-forgejo")]
pub(crate) async fn rotate_forgejo_tokens(bridge: &Bridge) {
    for f in &bridge.cfg.forgejo {
        let Some(days) = f.rotate_token_days else {
            continue;
        };
        let Ok(host) = f.host() else { continue };
        let key = format!("forgejo/{host}/rotated-at");
        let last: i64 = bridge
            .store
            .get(Table::Meta, &key)
            .ok()
            .flatten()
            .unwrap_or(0);
        if last == 0 {
            // First run: start the clock rather than rotate a token the
            // operator has just stored.
            let _ = bridge.store.put(Table::Meta, &key, &now());
            continue;
        }
        if now() - last < (days as i64) * 86_400 {
            continue;
        }
        let Some(adapter) = bridge.adapters.get(&host) else {
            continue;
        };
        let Some(forgejo) = adapter.forgejo() else {
            continue;
        };
        match forgejo.mint_token().await {
            Ok(minted) => {
                let name = crate::registry::forgejo_secret(&host, "bot-token");
                if let Err(e) = bridge
                    .store
                    .put_secret(&name, minted.secret.expose().as_bytes())
                {
                    // The adapter already uses the new token; the old one is
                    // left alive so a restart still has a working one.
                    tracing::error!(%host, error = %e, "could not persist the new bot token; the old one is kept");
                    continue;
                }
                let _ = bridge.store.put(Table::Meta, &key, &now());
                // VTA mode: the old token is retired only once the new one is
                // in the VTA — a host lost before that restarts with the old.
                if !bridge.store.flush(std::time::Duration::from_secs(30)).await {
                    tracing::warn!(%host, token = %minted.token.name, "the new bot token is not in the VTA yet; the old one is kept alive (delete it by hand later)");
                    continue;
                }
                match &minted.previous {
                    Some(old) => {
                        if let Err(e) = forgejo.retire_token(old).await {
                            tracing::warn!(%host, error = %e, "could not delete the old bot token; delete it by hand");
                        }
                    }
                    None => {
                        tracing::warn!(%host, "the old bot token could not be identified; delete it by hand")
                    }
                }
                tracing::info!(%host, token = %minted.token.name, "rotated the Forgejo bot token");
            }
            Err(e) => tracing::warn!(%host, error = %e, "bot token rotation failed; will retry"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_what_breaks_out_of_an_attribute() {
        assert_eq!(
            html_escape(r#"{"a":"<x>&'"}"#),
            "{&quot;a&quot;:&quot;&lt;x&gt;&amp;&#39;&quot;}"
        );
    }

    #[test]
    fn states_are_long_and_url_safe() {
        let s = new_state();
        assert!(s.len() >= 43);
        assert!(
            s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        );
    }
}
