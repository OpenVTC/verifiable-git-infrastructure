//! Forge webhooks → `git-ns/bridge/event`s.
//!
//! The adapter verifies the delivery's signature before a byte of it is
//! parsed ([`vgi_forge::Forge::parse_event`]); a delivery that fails is
//! refused with 401 and never reported (spec: MUST NOT report an event from
//! an unverified webhook). A verified event is only ever a prompt: the
//! bridge inspects the repository it names and reports what the forge shows
//! *now*, with the complete drift — so a replayed or reordered delivery
//! costs a read, not a wrong state at the VTC. Repeats are dropped by
//! delivery id as well.
//!
//! Raw payloads are never forwarded (spec: they carry far more than any
//! event needs): only the forge-neutral fields below leave the bridge.

use std::sync::Arc;

use http::{HeaderMap, StatusCode};
use serde_json::json;
use vgi_forge::{ForgeEventKind, HookDecision, InstallationChange, Resource};

use crate::bridge::{Bridge, now};
use crate::jobs::{self, Ctx};
use crate::mapping::Report;
use crate::store::{BranchLedger, NamespaceRecord, NamespaceState, RepoRecord, Table, repo_key};

/// The namespace-level repository the GitHub adapter keeps for the
/// required workflow. Part of the binding, never reported as unmanaged
/// (spec).
const NAMESPACE_REPOS: [&str; 1] = [".vgi"];

/// The adapter a delivery is for: the GitHub App the route names
/// (`/github/<host>/<owner>/webhook`), or the Forgejo host's. Its own
/// webhook secret must verify the delivery.
fn webhook_adapter(
    bridge: &Bridge,
    host: &str,
    owner: Option<&str>,
) -> Option<crate::registry::Adapter> {
    match owner {
        Some(o) => bridge.adapters.get_github(host, o),
        None => bridge.adapters.get(host),
    }
}

/// Handle a webhook for `host` (and, on GitHub, the App `owner` owns).
/// Returns the status to answer the forge with.
pub(crate) async fn on_webhook(
    bridge: &Arc<Bridge>,
    host: &str,
    owner: Option<&str>,
    headers: &HeaderMap,
    body: &[u8],
) -> StatusCode {
    let Some(adapter) = webhook_adapter(bridge, host, owner) else {
        return StatusCode::NOT_FOUND;
    };

    #[cfg(feature = "forge-github")]
    if let Some(g) = adapter.github() {
        // A push: the Dependabot re-sign's provenance ledger.
        match g.parse_push(headers, body) {
            Ok(Some(push)) => return crate::resign::on_push(bridge, host, push),
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(%host, error = %e, "refused a webhook");
                return StatusCode::UNAUTHORIZED;
            }
        }
        match g.parse_check_trigger(headers, body) {
            Ok(triggers) if !triggers.is_empty() => {
                let key = triggers[0]
                    .delivery_id
                    .as_deref()
                    .map(|d| format!("{host}#{d}"));
                if let Some(k) = &key
                    && already_seen(bridge, k)
                {
                    return StatusCode::OK;
                }
                // A Dependabot pull request may be re-signed; that runs on
                // its own, beside the check.
                crate::resign::on_pull_request_triggers(bridge, &triggers);
                // Recorded as handled only once every check it called for
                // was posted (or deliberately skipped): a delivery whose
                // check failed to post is processed again when GitHub
                // redelivers it.
                crate::checks::spawn(bridge, triggers, move |b| {
                    if let Some(k) = key {
                        let _ = b.store.put(Table::Deliveries, &k, &now());
                    }
                });
                return StatusCode::ACCEPTED;
            }
            Ok(_) => {}
            Err(e) => {
                tracing::warn!(%host, error = %e, "refused a webhook");
                return StatusCode::UNAUTHORIZED;
            }
        }
    }

    let event = match adapter.forge().parse_event(headers, body) {
        Ok(Some(e)) => e,
        Ok(None) => return StatusCode::NO_CONTENT,
        Err(e) => {
            tracing::warn!(%host, error = %e, "refused a webhook");
            return StatusCode::UNAUTHORIZED;
        }
    };
    if seen(bridge, host, event.delivery_id.as_deref()) {
        return StatusCode::OK;
    }
    let event = match adapter.hooks().on_event(&event) {
        HookDecision::Modify(e) => e,
        HookDecision::Abort(why) => {
            tracing::info!(%why, "an adapter hook dropped an event");
            return StatusCode::NO_CONTENT;
        }
        _ => event,
    };
    let me = Arc::clone(bridge);
    // Answer the forge now; the inspection that follows may take a while.
    tokio::spawn(async move { handle(&me, event.kind).await });
    StatusCode::ACCEPTED
}

/// Whether delivery `key` was already handled.
fn already_seen(bridge: &Bridge, key: &str) -> bool {
    matches!(bridge.store.get::<i64>(Table::Deliveries, key), Ok(Some(_)))
}

/// Record a delivery id; `true` if it was already handled.
fn seen(bridge: &Bridge, host: &str, delivery: Option<&str>) -> bool {
    let Some(d) = delivery else { return false };
    !bridge
        .store
        .put_new(Table::Deliveries, &format!("{host}#{d}"), &now())
        .unwrap_or(true)
}

/// The bound namespace containing `r`.
fn namespace_for(bridge: &Bridge, r: &Resource) -> Option<NamespaceRecord> {
    bridge
        .store
        .list::<NamespaceRecord>(Table::Namespaces)
        .ok()?
        .into_iter()
        .map(|(_, n)| n)
        .find(|n| n.state == NamespaceState::Bound && n.resource.contains(r))
}

fn repo_by_id(bridge: &Bridge, host: &str, id: u64) -> Option<RepoRecord> {
    bridge
        .store
        .get::<RepoRecord>(Table::Repos, &repo_key(host, id))
        .ok()
        .flatten()
}

/// Stop governing repository `forge_id` on `host`: its record, its place in
/// every managed set (the store's and the adapter's, which would otherwise
/// write it back), and the Dependabot provenance ledgers kept for it.
/// Nothing of it is carried anywhere: a repository that comes back — into
/// this namespace or another one this bridge serves — starts unmanaged
/// (event 0.2: rights never follow a repository out of its namespace).
pub(crate) fn detach(bridge: &Bridge, host: &str, forge_id: u64) {
    let _ = bridge.store.delete(Table::Repos, &repo_key(host, forge_id));
    let namespaces = bridge
        .store
        .list::<NamespaceRecord>(Table::Namespaces)
        .unwrap_or_default();
    for (id, ns) in namespaces {
        if ns.resource.host() != host || !ns.managed.contains(&forge_id) {
            continue;
        }
        let managed = bridge
            .store
            .update::<NamespaceRecord, _>(Table::Namespaces, &id, |n| {
                let Some(mut n) = n else {
                    return Ok((None, None));
                };
                n.managed.remove(&forge_id);
                let m = n.managed.clone();
                Ok((Some(n), Some(m)))
            });
        #[cfg(feature = "forge-github")]
        if let (Ok(Some(m)), Some(g)) = (
            managed,
            bridge
                .adapters
                .for_resource(&ns.resource)
                .and_then(|a| a.github().cloned()),
        ) {
            g.set_managed_repositories(&ns.resource, m);
        }
        #[cfg(not(feature = "forge-github"))]
        let _ = managed;
    }
    let prefix = format!("{host}#{forge_id}#");
    if let Ok(ledgers) = bridge.store.list::<BranchLedger>(Table::Branches) {
        for (key, _) in ledgers.into_iter().filter(|(k, _)| k.starts_with(&prefix)) {
            let _ = bridge.store.delete(Table::Branches, &key);
        }
    }
}

/// Detach every repository namespace `ns_id` records at `resource` under a
/// forge id other than `forge_id`: the name was reused (event 0.2 — the
/// governed repository was deleted or moved without an event, and the
/// newcomer inherits nothing). Returns whether there was one.
pub(crate) fn detach_reused_name(
    bridge: &Bridge,
    ns_id: &str,
    resource: &Resource,
    forge_id: u64,
) -> bool {
    let stale: Vec<RepoRecord> = bridge
        .store
        .list::<RepoRecord>(Table::Repos)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, r)| r)
        .filter(|r| r.namespace == ns_id && r.resource == *resource && r.forge_id != forge_id)
        .collect();
    for r in &stale {
        tracing::warn!(
            %resource, old = r.forge_id, new = forge_id,
            "a new repository took a governed name; the old one is no longer managed"
        );
        detach(bridge, resource.host(), r.forge_id);
    }
    !stale.is_empty()
}

/// Report `resource` (forge id `forge_id`) to namespace `ns` as a repository
/// the VTC did not create or adopt — unless it is the bridge's own
/// namespace-level repository, or one it manages. A repository this
/// namespace records at the same name under another forge id is detached
/// first (name reuse).
pub(crate) async fn report_unmanaged(
    bridge: &Bridge,
    ns: &NamespaceRecord,
    resource: &Resource,
    forge_id: u64,
) {
    if NAMESPACE_REPOS.contains(&resource.repo_name().unwrap_or_default())
        || repo_by_id(bridge, resource.host(), forge_id).is_some()
    {
        return;
    }
    detach_reused_name(bridge, &ns.id, resource, forge_id);
    let ev = json!({ "type": "repoCreatedUnmanaged", "forgeId": forge_id.to_string(), "resource": resource.as_str() });
    report(bridge, &ns.id, ev).await;
}

/// A repository left namespace `from_ns` (from `from` to `to`): detach it
/// and report `repoTransferred` there. When `to` lies in another namespace
/// this bridge serves, it arrives there unmanaged and is reported so —
/// its state here is never carried across.
pub(crate) async fn transferred_out(
    bridge: &Bridge,
    from_ns: &NamespaceRecord,
    from: &Resource,
    to: &Resource,
    forge_id: u64,
) {
    detach(bridge, to.host(), forge_id);
    if NAMESPACE_REPOS.contains(&from.repo_name().unwrap_or_default()) {
        return;
    }
    let ev = json!({ "type": "repoTransferred", "forgeId": forge_id.to_string(), "from": from.as_str(), "to": to.as_str() });
    report(bridge, &from_ns.id, ev).await;
    if let Some(to_ns) = namespace_for(bridge, to)
        && to_ns.id != from_ns.id
    {
        report_unmanaged(bridge, &to_ns, to, forge_id).await;
    }
}

async fn inspect_in(bridge: &Bridge, ns: &NamespaceRecord, repo: &Resource) {
    let Ok(ctx) = Ctx::load(bridge, &ns.id) else {
        return;
    };
    let lock = bridge.ns_lock(&ns.id);
    let _g = lock.lock().await;
    if let Err(e) = jobs::inspect_repo(bridge, &ctx, repo, true, None).await {
        tracing::warn!(%repo, error = %e, "could not inspect after a webhook");
    }
}

async fn report(bridge: &Bridge, ns: &str, ev: serde_json::Value) {
    if let Err(e) = bridge.send_event(ns, ev, None).await {
        tracing::error!(error = %e, "could not report an event");
    }
}

async fn handle(bridge: &Arc<Bridge>, kind: ForgeEventKind) {
    match kind {
        ForgeEventKind::RepoCreated { repo, forge_id } => {
            let Some(ns) = namespace_for(bridge, &repo) else {
                return;
            };
            let name = repo.repo_name().unwrap_or_default();
            if NAMESPACE_REPOS.contains(&name)
                || repo_by_id(bridge, repo.host(), forge_id).is_some()
            {
                // The bridge's own (it creates, then records) or part of the
                // binding.
                return;
            }
            // A repository the bridge is creating right now has no record
            // until its create returns; give it a moment before calling it
            // unmanaged.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            // At a governed name, with another forge id: the name was
            // reused, and the repository governed there is detached first.
            report_unmanaged(bridge, &ns, &repo, forge_id).await;
        }
        ForgeEventKind::RepoDeleted { repo, forge_id } => {
            let Some(ns) = namespace_for(bridge, &repo) else {
                return;
            };
            if NAMESPACE_REPOS.contains(&repo.repo_name().unwrap_or_default()) {
                return;
            }
            detach(bridge, repo.host(), forge_id);
            let ev = json!({ "type": "repoDeleted", "forgeId": forge_id.to_string(), "resource": repo.as_str() });
            report(bridge, &ns.id, ev).await;
        }
        ForgeEventKind::RepoRenamed { forge_id, from, to } => {
            let Some(ns) = namespace_for(bridge, &to) else {
                return;
            };
            // A rename stays with its owner. One whose `from` lies outside
            // the namespace is not a rename the VTC may act on (event 0.2:
            // every resource in an event lies inside its namespace).
            if !ns.resource.contains(&from) {
                tracing::warn!(%from, %to, "ignoring a rename that crosses namespaces");
                return;
            }
            // Renamed onto a name the namespace still records for another
            // repository: that one is gone, and nothing of it passes on.
            detach_reused_name(bridge, &ns.id, &to, forge_id);
            let _ = bridge.store.update::<RepoRecord, _>(
                Table::Repos,
                &repo_key(to.host(), forge_id),
                |r| {
                    Ok((
                        r.map(|mut r| {
                            r.resource = to.clone();
                            r
                        }),
                        (),
                    ))
                },
            );
            let ev = json!({ "type": "repoRenamed", "forgeId": forge_id.to_string(), "from": from.as_str(), "to": to.as_str() });
            report(bridge, &ns.id, ev).await;
        }
        ForgeEventKind::RepoTransferred {
            forge_id,
            from_namespace,
            to,
        } => {
            let rec = repo_by_id(bridge, to.host(), forge_id);
            let from = rec.as_ref().map(|r| r.resource.clone()).or_else(|| {
                from_namespace
                    .as_ref()
                    .and_then(|n| n.join(to.repo_name().unwrap_or_default()).ok())
            });
            let from_ns = from.as_ref().and_then(|f| namespace_for(bridge, f));
            match (from_ns, from) {
                // Out of a namespace this bridge serves — to another owner,
                // and so out of the namespace, wherever `to` is (a namespace
                // is one owner on one forge). The bridge stops governing it
                // and carries nothing across: if `to` is in another
                // namespace it serves, it arrives there unmanaged (event
                // 0.2: a transfer detaches; rights never move).
                (Some(from_ns), Some(from)) if from_ns.resource.contains(&from) => {
                    transferred_out(bridge, &from_ns, &from, &to, forge_id).await;
                }
                // Transferred *in* from outside every bound namespace: to
                // this namespace it is a repository the VTC did not create
                // or adopt, reported as such — never as `repoTransferred`,
                // whose `from` would lie outside it.
                _ => {
                    if let Some(t) = namespace_for(bridge, &to) {
                        report_unmanaged(bridge, &t, &to, forge_id).await;
                    }
                }
            }
        }
        ForgeEventKind::CollaboratorChanged {
            repo,
            forge_id,
            account,
            ..
        } => {
            let Some(ns) = namespace_for(bridge, &repo) else {
                return;
            };
            let Ok(ctx) = Ctx::load(bridge, &ns.id) else {
                return;
            };
            // What the account holds now, from the forge — not from the
            // delivery, which may be old.
            let role = match ctx.adapter.forge().inspect(&repo).await {
                Ok(state) => state
                    .collaborators
                    .iter()
                    .find(|c| c.account.id == account.id)
                    .map(|c| c.role.to_string()),
                Err(e) => {
                    tracing::warn!(%repo, error = %e, "could not read roles after a webhook");
                    return;
                }
            };
            let mut ev = json!({
                "type": "roleChanged",
                "forgeId": forge_id.to_string(),
                "resource": repo.as_str(),
                "account": crate::mapping::wire_account(repo.host(), &account),
            });
            if let Some(r) = role {
                ev["role"] = json!(r);
            }
            report(bridge, &ns.id, ev).await;
            // Then the complete drift for the repository.
            if repo_by_id(bridge, repo.host(), forge_id).is_some() {
                inspect_in(bridge, &ns, &repo).await;
            }
        }
        ForgeEventKind::ProtectionChanged {
            repo: Some(repo), ..
        } => {
            if let Some(ns) = namespace_for(bridge, &repo) {
                inspect_in(bridge, &ns, &repo).await;
            }
        }
        ForgeEventKind::ProtectionChanged {
            repo: None,
            namespace,
            ..
        } => {
            // An owner-level rule (the org required workflow): every managed
            // repository may be affected.
            if let Some(ns) = namespace_for(bridge, &namespace)
                && let Ok(ctx) = Ctx::load(bridge, &ns.id)
            {
                let lock = bridge.ns_lock(&ns.id);
                let _g = lock.lock().await;
                let mut r = Report::default();
                jobs::sweep(bridge, &ctx, false, &mut r).await;
            }
        }
        ForgeEventKind::InstallationChanged {
            namespace, change, ..
        } => {
            let Some(ns) = namespace_for(bridge, &namespace) else {
                return;
            };
            match change {
                InstallationChange::Deleted | InstallationChange::Suspended => {
                    report(bridge, &ns.id, json!({ "type": "installationRemoved" })).await;
                }
                // The owner approved new permissions (or the installation
                // came back): the bridge-posted check may be possible now.
                // A change of guard shows up as drift on the next inspect,
                // which the VTC answers with a bootstrap.
                _ => bridge.probe_bridge_checks(&ns.id).await,
            }
        }
        other => tracing::debug!(event = ?other, "no event to report for this delivery"),
    }
}
