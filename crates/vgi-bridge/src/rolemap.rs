//! The role map the bridge projects rights with, reported to the VTC
//! (`git-ns/bridge/event` 0.3, `roleMapReported`).
//!
//! The map is the community's to configure (`role_map`, BRIDGE.md §6c), and
//! until 0.3 the VTC could only assume the default: it showed forge roles
//! the bridge did not give, and derived the right to adopt a drifted role
//! from a map that was not the bridge's. The bridge now tells it, per
//! namespace:
//!
//! - `roleMap` — the map **as the forge applies it**: each tier's configured
//!   role rounded down onto the namespace's ladder (a GitHub personal
//!   account has only `write`; Forgejo's `maintain` is the adapter's own
//!   rung, `write` plus the merge allow-list);
//! - `ladder` — that ladder, which the VTC holds every map to;
//! - `repos` — each configured repository whose map differs;
//! - `stale` — each managed repository whose roles were last projected
//!   under a map other than the one the bridge now applies to it, which the
//!   VTC re-projects.
//!
//! It is sent for a namespace whenever the bridge starts serving it — at
//! start-up (the only time the configuration, and so the map, can change)
//! and when a binding completes ([`Bridge::started_serving`]) — and for every
//! bound namespace whenever the link to the VTC comes up
//! ([`Bridge::link_up`]: a new mediator session, or sends succeeding again
//! after they failed). One outbox key per namespace, so a newer report
//! replaces an unacknowledged one.
//!
//! The VTC takes the report with the latest `issuedAt` and ignores an
//! earlier one arriving late (event 0.3, request step 5.2). So every send of
//! a report — a resend of an unacknowledged one included — is built afresh
//! from the map the bridge applies at that moment ([`Bridge::send_outbox`]):
//! a later `issuedAt` never carries an older map, and the document is always
//! inside the VTC's freshness window. A map that rounding leaves unordered
//! (a defective adapter) is logged and not reported.
//!
//! There is still no entry for `git.ns.admin`: a namespace admin gets no
//! forge role whatever the map says.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use vgi_forge::{EffectiveRights, Forge, ForgeRole, Namespace, Resource, Right, RoleMap};

use crate::bridge::Bridge;
use crate::jobs::Ctx;
use crate::store::{NamespaceRecord, NamespaceState, RepoRecord, Table};

/// The outbox key prefix of role-map reports.
pub const OUTBOX_PREFIX: &str = "event:roleMap:";

/// The outbox key of namespace `ns_id`'s role-map report.
pub fn outbox_key(ns_id: &str) -> String {
    format!("{OUTBOX_PREFIX}{ns_id}")
}

/// `map` as `forge` applies it in `ns`: each tier's role rounded onto the
/// namespace's ladder, exactly as a `projectRoles` job maps it.
///
/// Rounding down is monotone and never raises `commit` above `write`, so the
/// result is ordered. `None` if an adapter's `map_role` ever broke that: the
/// map is not what the forge applies, and the configured one is not either,
/// so nothing is reported for it (the error is logged).
pub fn effective_for(forge: &dyn Forge, ns: &Namespace, map: &RoleMap) -> Option<RoleMap> {
    let role = |r: Right| forge.map_role(ns, EffectiveRights::from_granted([r]), map);
    match RoleMap::new(
        role(Right::RepoOwn),
        role(Right::RepoMaintain),
        role(Right::CommitSign),
    ) {
        Ok(m) => Some(m),
        Err(e) => {
            tracing::error!(
                namespace = %ns.resource,
                error = %e,
                "the forge adapter rounds the configured role map to an unordered one; \
                 the role map is not reported"
            );
            None
        }
    }
}

/// [`effective_for`] in a job's namespace.
pub(crate) fn effective(ctx: &Ctx, map: &RoleMap) -> Option<RoleMap> {
    effective_for(ctx.adapter.forge(), &ctx.namespace, map)
}

/// The namespace's ladder as the forge offers it, lowest first, without
/// `none` (event 0.3, *Ladder*).
pub fn ladder_for(forge: &dyn Forge, ns: &Namespace) -> Vec<ForgeRole> {
    let mut levels: Vec<ForgeRole> = forge
        .capabilities(ns)
        .role_levels
        .into_iter()
        .filter(|l| *l != ForgeRole::None)
        .collect();
    levels.sort();
    levels.dedup();
    levels
}

/// The `roleMapReported` event body for `ns`, or `None` when the namespace
/// is not bound, no adapter serves its host, or a map rounds unordered.
pub(crate) fn event(bridge: &Bridge, ns: &NamespaceRecord) -> Option<Value> {
    if ns.state != NamespaceState::Bound {
        return None;
    }
    let namespace = &ns.binding.as_ref()?.namespace;
    let adapter = bridge.adapters.for_resource(&ns.resource)?;
    let forge = adapter.forge();
    let at = |r: &Resource| effective_for(forge, namespace, &bridge.cfg.role_map(r));

    let base = at(&ns.resource)?;
    let mut repos: Vec<Value> = Vec::new();
    for r in bridge.cfg.role_map_repos(&ns.resource) {
        let m = at(&r)?;
        if m != base {
            repos.push(json!({ "resource": r.to_string(), "roleMap": m }));
        }
    }
    let default = effective_for(forge, namespace, &RoleMap::default())?;
    // Every configured repository's map rounded ordered above, so a
    // repository's map here is `base` or one of those; one that still would
    // not round counts as stale, to be re-projected.
    let stale: BTreeSet<String> = bridge
        .store
        .list::<RepoRecord>(Table::Repos)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, rec)| rec)
        .filter(|rec| rec.namespace == ns.id && rec.roles_known && !rec.archived)
        .filter(|rec| ns.resource.contains(&rec.resource))
        .filter(|rec| Some(rec.role_map.unwrap_or(default)) != at(&rec.resource))
        .map(|rec| rec.resource.to_string())
        .collect();

    let mut ev = json!({
        "type": "roleMapReported",
        "roleMap": base,
        "ladder": ladder_for(forge, namespace),
    });
    if !repos.is_empty() {
        ev["repos"] = Value::Array(repos);
    }
    if !stale.is_empty() {
        ev["stale"] = json!(stale);
    }
    Some(ev)
}

/// Set once the bridge has said, per process, that its VTC takes an event
/// version without `roleMapReported`.
static SAID_NO_REPORT: AtomicBool = AtomicBool::new(false);

impl Bridge {
    /// Report the role map of namespace `ns_id` to the VTC, replacing any
    /// earlier report still unacknowledged. Nothing under event 0.1 or 0.2,
    /// where a report still pending (queued before the version was lowered)
    /// is dropped rather than sent under a version without the type.
    pub async fn report_role_map(&self, ns_id: &str) {
        if !self.cfg.event_version.reports_role_map() {
            let _ = self.store.delete(Table::Outbox, &outbox_key(ns_id));
            if !SAID_NO_REPORT.swap(true, Ordering::Relaxed) {
                tracing::info!(
                    "event_version is below 0.3: the VTC is not told this bridge's role map, \
                     and assumes the default"
                );
            }
            return;
        }
        let Ok(Some(ns)) = self.store.get::<NamespaceRecord>(Table::Namespaces, ns_id) else {
            return;
        };
        let Some(ev) = event(self, &ns) else {
            return;
        };
        if let Err(e) = self
            .send_event_keyed(ns_id, ev, None, Some(outbox_key(ns_id)))
            .await
        {
            tracing::error!(namespace = ns_id, error = %e, "could not report the role map");
        }
    }

    /// Namespace `ns_id` became this bridge's to serve — its binding
    /// completed, or it was handed to this bridge: report its role map, so
    /// the VTC does not go on assuming the default (or another bridge's).
    /// A namespace the bridge serves from a restored store is covered by
    /// the report [`Bridge::restore`] sends for every bound namespace.
    pub async fn started_serving(&self, ns_id: &str) {
        self.report_role_map(ns_id).await;
    }

    /// Resolves once a send has succeeded after sends failed — the link-up
    /// [`Bridge::background`] answers with [`Bridge::link_up`]. For tests
    /// and supervisors that run their own loop.
    pub async fn link_recovered(&self) {
        self.link_recovered.notified().await;
    }

    /// Report the role map of every bound namespace (at each link-up).
    pub async fn report_role_maps(&self) {
        let Ok(all) = self.store.list::<NamespaceRecord>(Table::Namespaces) else {
            return;
        };
        for (_, ns) in all {
            if ns.state == NamespaceState::Bound {
                self.report_role_map(&ns.id).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vgi_forge::{
        ApplyReport, BindCallback, BindRequest, BindStep, BootstrapStep, Capabilities,
        ForgeAccount, ForgeEvent, ForgeKind, LinkCallback, LinkStep, NamespaceBinding,
        NamespaceKind, RepoSpec, RepoState, RoleAssignment, StepOutcome, Unlisted, VgiConfig,
        async_trait,
    };

    /// An adapter whose `map_role` is defective: it gives committers
    /// `admin` and everyone above them `read`, whatever the map asks.
    struct Defective;

    #[async_trait]
    impl Forge for Defective {
        fn kind(&self) -> ForgeKind {
            ForgeKind::Forgejo
        }
        fn host(&self) -> &str {
            "codeberg.org"
        }
        fn capabilities(&self, _ns: &Namespace) -> Capabilities {
            let mut c = Capabilities::default();
            c.role_levels = vec![ForgeRole::Read, ForgeRole::Write, ForgeRole::Admin];
            c
        }
        fn map_role(&self, _ns: &Namespace, rights: EffectiveRights, _map: &RoleMap) -> ForgeRole {
            if rights.holds(Right::RepoMaintain) {
                ForgeRole::Read
            } else {
                ForgeRole::Admin
            }
        }
        async fn begin_bind(&self, _req: BindRequest) -> vgi_forge::Result<BindStep> {
            unimplemented!()
        }
        async fn complete_bind(&self, _cb: BindCallback) -> vgi_forge::Result<NamespaceBinding> {
            unimplemented!()
        }
        async fn begin_account_link(&self, _member: &str) -> vgi_forge::Result<LinkStep> {
            unimplemented!()
        }
        async fn complete_account_link(
            &self,
            _cb: LinkCallback,
        ) -> vgi_forge::Result<ForgeAccount> {
            unimplemented!()
        }
        async fn inspect(&self, _repo: &Resource) -> vgi_forge::Result<RepoState> {
            unimplemented!()
        }
        async fn create_repo(&self, _spec: &RepoSpec) -> vgi_forge::Result<RepoState> {
            unimplemented!()
        }
        async fn archive_repo(&self, _repo: &Resource) -> vgi_forge::Result<()> {
            unimplemented!()
        }
        async fn apply_roles(
            &self,
            _repo: &Resource,
            _desired: &[RoleAssignment],
            _unlisted: Unlisted,
        ) -> vgi_forge::Result<ApplyReport> {
            unimplemented!()
        }
        fn bootstrap_plan(
            &self,
            _repo: &RepoSpec,
            _cfg: &VgiConfig,
        ) -> vgi_forge::Result<Vec<BootstrapStep>> {
            unimplemented!()
        }
        async fn run_step(
            &self,
            _repo: &Resource,
            _step: &BootstrapStep,
        ) -> vgi_forge::Result<StepOutcome> {
            unimplemented!()
        }
        fn parse_event(
            &self,
            _headers: &http::HeaderMap,
            _body: &[u8],
        ) -> vgi_forge::Result<Option<ForgeEvent>> {
            Ok(None)
        }
    }

    fn ns() -> Namespace {
        Namespace::new(
            Resource::parse("codeberg.org/acme").unwrap(),
            NamespaceKind::Organization,
        )
    }

    #[test]
    fn a_map_that_rounds_unordered_is_not_reported() {
        // Neither the rounded map nor the configured one is what the forge
        // applies, so there is no map to report (event 0.3: a bridge MUST
        // NOT report an unordered map).
        assert_eq!(effective_for(&Defective, &ns(), &RoleMap::default()), None);
    }

    #[test]
    fn the_ladder_is_the_forges_levels_lowest_first_without_none() {
        assert_eq!(
            ladder_for(&Defective, &ns()),
            vec![ForgeRole::Read, ForgeRole::Write, ForgeRole::Admin]
        );
    }
}
