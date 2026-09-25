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

/// Whose deliveries these are. A GitHub App's webhook secret is set by the
/// organisation that owns the App, so a delivery it verifies speaks for that
/// organisation **only**: every namespace, repository and installation it
/// may touch is its owner's. A Forgejo bot's covers its host.
#[derive(Debug, Clone)]
pub(crate) struct Scope {
    host: String,
    /// The GitHub App's owner (lowercase); `None` for Forgejo.
    owner: Option<String>,
}

impl Scope {
    /// Whether `r` lies in this scope.
    pub(crate) fn covers(&self, r: &Resource) -> bool {
        r.host() == self.host
            && self
                .owner
                .as_ref()
                .is_none_or(|o| r.owner().eq_ignore_ascii_case(o))
    }

    /// Whether a delivery about repository `repo` (forge id `id`) may be
    /// acted on: `repo` is in scope, and the repository the bridge records
    /// under that id (if any) is too — a delivery cannot name another
    /// owner's repository by its id. With `need_record`, the id must be one
    /// the bridge manages.
    pub(crate) fn admits_repo(
        &self,
        bridge: &Bridge,
        repo: &Resource,
        id: u64,
        need_record: bool,
    ) -> bool {
        if !self.covers(repo) {
            return false;
        }
        match repo_record(bridge, &self.host, id) {
            Some(rec) => {
                self.covers(&rec.resource)
                    && namespace_record(bridge, &rec.namespace)
                        .is_some_and(|n| self.covers(&n.resource))
            }
            None => !need_record,
        }
    }

    /// Whether every resource an event names lies in scope. A transfer may
    /// name the other side's owner (it moved in or out), but one of its
    /// sides must be this owner's.
    fn admits(&self, kind: &ForgeEventKind) -> bool {
        match kind {
            ForgeEventKind::RepoCreated { repo, .. }
            | ForgeEventKind::RepoDeleted { repo, .. }
            | ForgeEventKind::RepoArchived { repo, .. }
            | ForgeEventKind::RepoVisibilityChanged { repo, .. }
            | ForgeEventKind::CollaboratorChanged { repo, .. } => self.covers(repo),
            ForgeEventKind::RepoRenamed { from, to, .. } => self.covers(from) && self.covers(to),
            ForgeEventKind::RepoTransferred {
                from_namespace, to, ..
            } => self.covers(to) || from_namespace.as_ref().is_some_and(|f| self.covers(f)),
            ForgeEventKind::OrgMembershipChanged { namespace, .. }
            | ForgeEventKind::TeamMembershipChanged { namespace, .. }
            | ForgeEventKind::InstallationChanged { namespace, .. } => self.covers(namespace),
            ForgeEventKind::ProtectionChanged {
                repo, namespace, ..
            } => self.covers(namespace) && repo.as_ref().is_none_or(|r| self.covers(r)),
            _ => false,
        }
    }
}

fn repo_record(bridge: &Bridge, host: &str, id: u64) -> Option<RepoRecord> {
    bridge
        .store
        .get::<RepoRecord>(Table::Repos, &repo_key(host, id))
        .ok()
        .flatten()
}

fn namespace_record(bridge: &Bridge, id: &str) -> Option<NamespaceRecord> {
    bridge
        .store
        .get::<NamespaceRecord>(Table::Namespaces, id)
        .ok()
        .flatten()
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
    let scope = Scope {
        host: host.to_string(),
        owner: owner.map(str::to_ascii_lowercase),
    };

    #[cfg(feature = "forge-github")]
    if let Some(g) = adapter.github() {
        // A push: the Dependabot re-sign's provenance ledger.
        match g.parse_push(headers, body) {
            Ok(Some(push)) => {
                // The provenance ledger the re-sign trusts: only for a
                // repository this owner's namespace manages.
                if !scope.admits_repo(bridge, &push.repo, push.repo_id, true) {
                    tracing::warn!(%host, owner = ?scope.owner, repo = %push.repo, id = push.repo_id,
                        "dropping a push for a repository outside the App's organisation");
                    return StatusCode::NO_CONTENT;
                }
                return crate::resign::on_push(bridge, host, push);
            }
            Ok(None) => {}
            Err(e) => {
                tracing::warn!(%host, error = %e, "refused a webhook");
                return StatusCode::UNAUTHORIZED;
            }
        }
        match g.parse_check_trigger(headers, body) {
            Ok(mut triggers) if !triggers.is_empty() => {
                let before = triggers.len();
                triggers.retain(|t| scope.admits_repo(bridge, &t.repo, t.repo_id, false));
                if triggers.len() != before {
                    tracing::warn!(%host, owner = ?scope.owner,
                        "dropping check triggers for repositories outside the App's organisation");
                }
                if triggers.is_empty() {
                    return StatusCode::NO_CONTENT;
                }
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
    if !scope.admits(&event.kind) {
        tracing::warn!(%host, owner = ?scope.owner, event = ?event.kind,
            "dropping an event that names a namespace or repository outside the App's organisation");
        return StatusCode::NO_CONTENT;
    }
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
    tokio::spawn(async move { handle(&me, &scope, event.kind).await });
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

/// The bound namespace containing `r`, if it lies in `scope`.
fn namespace_in(bridge: &Bridge, scope: &Scope, r: &Resource) -> Option<NamespaceRecord> {
    if !scope.covers(r) {
        return None;
    }
    bridge
        .store
        .list::<NamespaceRecord>(Table::Namespaces)
        .ok()?
        .into_iter()
        .map(|(_, n)| n)
        .find(|n| {
            n.state == NamespaceState::Bound && n.resource.contains(r) && scope.covers(&n.resource)
        })
}

/// The repository the bridge records under forge id `id` in namespace
/// `ns` — never one of another namespace, whatever id a delivery names.
fn repo_in(bridge: &Bridge, ns: &NamespaceRecord, id: u64) -> Option<RepoRecord> {
    repo_record(bridge, ns.resource.host(), id).filter(|r| r.namespace == ns.id)
}

/// Whether some other namespace than `ns` records or manages forge id `id`.
fn claimed_elsewhere(bridge: &Bridge, ns: &NamespaceRecord, id: u64) -> bool {
    let host = ns.resource.host();
    if repo_record(bridge, host, id).is_some_and(|r| r.namespace != ns.id) {
        return true;
    }
    bridge
        .store
        .list::<NamespaceRecord>(Table::Namespaces)
        .unwrap_or_default()
        .into_iter()
        .any(|(_, n)| n.id != ns.id && n.resource.host() == host && n.managed.contains(&id))
}

/// [`detach`] forge id `id` from `ns` — refused (and logged) when another
/// namespace records or manages it: a delivery for one namespace never
/// detaches another's repository.
fn detach_from(bridge: &Bridge, ns: &NamespaceRecord, id: u64) -> bool {
    if claimed_elsewhere(bridge, ns, id) {
        tracing::warn!(namespace = %ns.id, forge_id = id,
            "not detaching a repository another namespace governs");
        return false;
    }
    detach(bridge, ns.resource.host(), id);
    true
}

/// Whether the bridge records forge id `id` on `host` at all (any
/// namespace): such a repository is not reported as unmanaged.
fn known_repo(bridge: &Bridge, host: &str, id: u64) -> bool {
    repo_record(bridge, host, id).is_some()
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
        || known_repo(bridge, resource.host(), forge_id)
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
    if !detach_from(bridge, from_ns, forge_id) {
        return;
    }
    if NAMESPACE_REPOS.contains(&from.repo_name().unwrap_or_default()) {
        return;
    }
    let ev = json!({ "type": "repoTransferred", "forgeId": forge_id.to_string(), "from": from.as_str(), "to": to.as_str() });
    report(bridge, &from_ns.id, ev).await;
    // The receiving side, only when it is this same owner's (a jobs-path
    // transfer between its own namespaces); another owner's App reports its
    // own side.
    let same_owner = Scope {
        host: from_ns.resource.host().to_string(),
        owner: Some(from_ns.resource.owner().to_ascii_lowercase()),
    };
    if let Some(to_ns) = namespace_in(bridge, &same_owner, to)
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

async fn handle(bridge: &Arc<Bridge>, scope: &Scope, kind: ForgeEventKind) {
    match kind {
        ForgeEventKind::RepoCreated { repo, forge_id } => {
            let Some(ns) = namespace_in(bridge, scope, &repo) else {
                return;
            };
            let name = repo.repo_name().unwrap_or_default();
            if NAMESPACE_REPOS.contains(&name) || known_repo(bridge, repo.host(), forge_id) {
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
            let Some(ns) = namespace_in(bridge, scope, &repo) else {
                return;
            };
            if NAMESPACE_REPOS.contains(&repo.repo_name().unwrap_or_default()) {
                return;
            }
            if !detach_from(bridge, &ns, forge_id) {
                return;
            }
            let ev = json!({ "type": "repoDeleted", "forgeId": forge_id.to_string(), "resource": repo.as_str() });
            report(bridge, &ns.id, ev).await;
        }
        ForgeEventKind::RepoRenamed { forge_id, from, to } => {
            let Some(ns) = namespace_in(bridge, scope, &to) else {
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
            if claimed_elsewhere(bridge, &ns, forge_id) {
                tracing::warn!(%from, %to, "ignoring a rename of a repository another namespace governs");
                return;
            }
            detach_reused_name(bridge, &ns.id, &to, forge_id);
            let ns_id = ns.id.clone();
            let _ = bridge.store.update::<RepoRecord, _>(
                Table::Repos,
                &repo_key(to.host(), forge_id),
                |r| {
                    Ok((
                        r.map(|mut r| {
                            if r.namespace == ns_id {
                                r.resource = to.clone();
                            }
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
            // Only this owner's record of the repository counts, and only a
            // `from` in this owner's scope.
            let rec = repo_record(bridge, to.host(), forge_id).filter(|r| {
                scope.covers(&r.resource)
                    && namespace_record(bridge, &r.namespace)
                        .is_some_and(|n| scope.covers(&n.resource))
            });
            let from = rec.as_ref().map(|r| r.resource.clone()).or_else(|| {
                from_namespace
                    .as_ref()
                    .filter(|n| scope.covers(n))
                    .and_then(|n| n.join(to.repo_name().unwrap_or_default()).ok())
            });
            let from_ns = from.as_ref().and_then(|f| namespace_in(bridge, scope, f));
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
                    if let Some(t) = namespace_in(bridge, scope, &to) {
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
            let Some(ns) = namespace_in(bridge, scope, &repo) else {
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
            if repo_in(bridge, &ns, forge_id).is_some() {
                inspect_in(bridge, &ns, &repo).await;
            }
        }
        ForgeEventKind::ProtectionChanged {
            repo: Some(repo), ..
        } => {
            if let Some(ns) = namespace_in(bridge, scope, &repo) {
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
            if let Some(ns) = namespace_in(bridge, scope, &namespace)
                && let Ok(ctx) = Ctx::load(bridge, &ns.id)
            {
                let lock = bridge.ns_lock(&ns.id);
                let _g = lock.lock().await;
                let mut r = Report::default();
                jobs::sweep(bridge, &ctx, false, &mut r).await;
            }
        }
        ForgeEventKind::InstallationChanged {
            namespace,
            installation_id,
            change,
        } => {
            let Some(ns) = namespace_in(bridge, scope, &namespace) else {
                return;
            };
            // The namespace's own installation, as recorded at the bind.
            let recorded = ns
                .binding
                .as_ref()
                .and_then(|b| b.namespace.installation_id);
            if recorded != Some(installation_id) {
                tracing::warn!(namespace = %ns.id, installation_id, ?recorded,
                    "ignoring an installation event for another installation");
                return;
            }
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
