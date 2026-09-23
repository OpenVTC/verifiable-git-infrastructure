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
use crate::store::{NamespaceRecord, NamespaceState, RepoRecord, Table, repo_key};

/// The namespace-level repository the GitHub adapter keeps for the
/// required workflow. Part of the binding, never reported as unmanaged
/// (spec).
const NAMESPACE_REPOS: [&str; 1] = [".vgi"];

/// Handle a webhook for `host`. Returns the status to answer the forge
/// with.
pub(crate) async fn on_webhook(
    bridge: &Arc<Bridge>,
    host: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> StatusCode {
    let Some(adapter) = bridge.adapters.get(host) else {
        return StatusCode::NOT_FOUND;
    };

    #[cfg(feature = "forge-github")]
    if let Some(g) = adapter.github() {
        match g.parse_check_trigger(headers, body) {
            Ok(Some(trigger)) => {
                if seen(bridge, host, trigger.delivery_id.as_deref()) {
                    return StatusCode::OK;
                }
                crate::checks::spawn(bridge, trigger);
                return StatusCode::ACCEPTED;
            }
            Ok(None) => {}
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
            if repo_by_id(bridge, repo.host(), forge_id).is_some() {
                return;
            }
            let ev = json!({ "type": "repoCreatedUnmanaged", "forgeId": forge_id.to_string(), "resource": repo.as_str() });
            report(bridge, &ns.id, ev).await;
        }
        ForgeEventKind::RepoDeleted { repo, forge_id } => {
            let Some(ns) = namespace_for(bridge, &repo) else {
                return;
            };
            if NAMESPACE_REPOS.contains(&repo.repo_name().unwrap_or_default()) {
                return;
            }
            let _ = bridge
                .store
                .delete(Table::Repos, &repo_key(repo.host(), forge_id));
            let _ = bridge
                .store
                .update::<NamespaceRecord, _>(Table::Namespaces, &ns.id, |n| {
                    Ok((
                        n.map(|mut n| {
                            n.managed.remove(&forge_id);
                            n
                        }),
                        (),
                    ))
                });
            let ev = json!({ "type": "repoDeleted", "forgeId": forge_id.to_string(), "resource": repo.as_str() });
            report(bridge, &ns.id, ev).await;
        }
        ForgeEventKind::RepoRenamed { forge_id, from, to } => {
            let Some(ns) = namespace_for(bridge, &to) else {
                return;
            };
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
            let Some(from) = from else { return };
            let from_ns = namespace_for(bridge, &from);
            let to_ns = namespace_for(bridge, &to);
            let Some(ns) = from_ns.clone().or(to_ns.clone()) else {
                return;
            };
            match (&rec, &to_ns) {
                (Some(r), Some(t)) => {
                    let _ = bridge
                        .store
                        .update::<RepoRecord, _>(Table::Repos, &r.key(), |x| {
                            Ok((
                                x.map(|mut x| {
                                    x.resource = to.clone();
                                    x.namespace = t.id.clone();
                                    x
                                }),
                                (),
                            ))
                        });
                }
                (Some(r), None) => {
                    // Out of every bound namespace: no longer governed.
                    let _ = bridge.store.delete(Table::Repos, &r.key());
                }
                _ => {}
            }
            let ev = json!({ "type": "repoTransferred", "forgeId": forge_id.to_string(), "from": from.as_str(), "to": to.as_str() });
            report(bridge, &ns.id, ev).await;
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
            if matches!(
                change,
                InstallationChange::Deleted | InstallationChange::Suspended
            ) && let Some(ns) = namespace_for(bridge, &namespace)
            {
                report(bridge, &ns.id, json!({ "type": "installationRemoved" })).await;
            }
        }
        other => tracing::debug!(event = ?other, "no event to report for this delivery"),
    }
}
