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
//! - `repos` — each configured repository whose map differs;
//! - `stale` — each managed repository whose roles were last projected
//!   under a map other than the one the bridge now applies to it, which the
//!   VTC re-projects.
//!
//! It is sent for every bound namespace at start-up (the only time the
//! configuration can change) and when a binding completes, under one outbox
//! key per namespace so a newer report replaces an unacknowledged one. There
//! is still no entry for `git.ns.admin`: a namespace admin gets no forge
//! role whatever the map says.

use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};

use serde_json::{Value, json};
use vgi_forge::{EffectiveRights, Forge, Namespace, Resource, Right, RoleMap};

use crate::bridge::Bridge;
use crate::jobs::Ctx;
use crate::store::{NamespaceRecord, NamespaceState, RepoRecord, Table};

/// The outbox key of namespace `ns_id`'s role-map report.
pub fn outbox_key(ns_id: &str) -> String {
    format!("event:roleMap:{ns_id}")
}

/// `map` as `forge` applies it in `ns`: each tier's role rounded onto the
/// namespace's ladder, exactly as a `projectRoles` job maps it.
pub fn effective_for(forge: &dyn Forge, ns: &Namespace, map: &RoleMap) -> RoleMap {
    let role = |r: Right| forge.map_role(ns, EffectiveRights::from_granted([r]), map);
    // Rounding down is monotone and never raises `commit` above `write`, so
    // the result is ordered; the configured map is the fallback if an
    // adapter's `map_role` ever broke that.
    RoleMap::new(
        role(Right::RepoOwn),
        role(Right::RepoMaintain),
        role(Right::CommitSign),
    )
    .unwrap_or(*map)
}

/// [`effective_for`] in a job's namespace.
pub(crate) fn effective(ctx: &Ctx, map: &RoleMap) -> RoleMap {
    effective_for(ctx.adapter.forge(), &ctx.namespace, map)
}

/// The `roleMapReported` event body for `ns`, or `None` when the namespace
/// is not bound or no adapter serves its host.
pub(crate) fn event(bridge: &Bridge, ns: &NamespaceRecord) -> Option<Value> {
    if ns.state != NamespaceState::Bound {
        return None;
    }
    let namespace = &ns.binding.as_ref()?.namespace;
    let adapter = bridge.adapters.for_resource(&ns.resource)?;
    let forge = adapter.forge();
    let at = |r: &Resource| effective_for(forge, namespace, &bridge.cfg.role_map(r));

    let base = at(&ns.resource);
    let repos: Vec<Value> = bridge
        .cfg
        .role_map_repos(&ns.resource)
        .into_iter()
        .filter_map(|r| {
            let m = at(&r);
            (m != base).then(|| json!({ "resource": r.to_string(), "roleMap": m }))
        })
        .collect();
    let default = effective_for(forge, namespace, &RoleMap::default());
    let stale: BTreeSet<String> = bridge
        .store
        .list::<RepoRecord>(Table::Repos)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, rec)| rec)
        .filter(|rec| rec.namespace == ns.id && rec.roles_known && !rec.archived)
        .filter(|rec| ns.resource.contains(&rec.resource))
        .filter(|rec| rec.role_map.unwrap_or(default) != at(&rec.resource))
        .map(|rec| rec.resource.to_string())
        .collect();

    let mut ev = json!({ "type": "roleMapReported", "roleMap": base });
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
    /// earlier report still unacknowledged. Nothing under event 0.1 or 0.2.
    pub async fn report_role_map(&self, ns_id: &str) {
        if !self.cfg.event_version.reports_role_map() {
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

    /// Report the role map of every bound namespace (at start-up).
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
