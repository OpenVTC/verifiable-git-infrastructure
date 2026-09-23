//! What the bridge knows about its standing on a forge, beyond what the
//! specification's payloads carry, for the VTC's admin console.
//!
//! It rides in the payload's `ext` member (Trust Tasks SPEC §4.5.1: keys are
//! reverse-DNS namespaces, the structure under each is the namespace
//! owner's) of every `git-ns/bridge/result` and `git-ns/bridge/event`, under
//! [`EXT_KEY`]:
//!
//! ```json
//! { "org.openvtc.git-ns": { "namespace": { … }, "repo": { … } } }
//! ```
//!
//! The payload — `ext` included — is what the bridge signs, so the report is
//! as authentic as the rest of the document. It is for display only: the VTC
//! changes no right and takes no decision on it. A member the bridge does
//! not know is left out, never sent as `null` or a guessed `false`, and a
//! document with nothing to report carries no `ext` at all (the framework
//! requires at least one member when it is present).

use serde_json::{Map, Value, json};
use vgi_forge::{CheckSourceGuard, Drift, ProtectionGap, RepoState};

use crate::bridge::Bridge;
use crate::store::{NamespaceRecord, PendingFlow, RepoRecord, Table};

/// The `ext` key the VTC reads the report from.
pub const EXT_KEY: &str = "org.openvtc.git-ns";

/// What keeps a pull request from satisfying its own check (design §9), as
/// the VTC names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Guard {
    /// A namespace workflow pinned by an org ruleset (GitHub).
    RequiredWorkflow,
    /// `CODEOWNERS` plus a required code-owner review on workflow changes
    /// (GitHub, two or more owners).
    CodeOwnerReview,
    /// The bridge runs the check itself and the ruleset accepts it only from
    /// the bridge's App (GitHub).
    BridgePostedCheck,
    /// The branch rule's protected file patterns cover the workflow
    /// (Forgejo).
    ProtectedFiles,
    /// Nothing holds: a solo repository with no review requirement, or a
    /// guard that is set up but weakened.
    None,
}

impl Guard {
    /// The VTC's word for it.
    pub fn as_str(self) -> &'static str {
        match self {
            Guard::RequiredWorkflow => "requiredWorkflow",
            Guard::CodeOwnerReview => "codeOwnerReview",
            Guard::BridgePostedCheck => "bridgePostedCheck",
            Guard::ProtectedFiles => "protectedFiles",
            Guard::None => "none",
        }
    }

    /// The guard actually in force on an inspected repository: the one the
    /// adapter observed, unless the drift says what keeps the check's source
    /// out of a pull request's reach is weakened — then `none`.
    pub fn in_force(state: &RepoState, drift: &[Drift]) -> Guard {
        let weakened = drift.iter().any(|d| match d {
            Drift::ProtectionWeakened { gaps } => gaps.iter().any(|g| {
                matches!(
                    g,
                    ProtectionGap::CheckSourceUnprotected { .. }
                        | ProtectionGap::UnprotectedPaths { .. }
                )
            }),
            _ => false,
        });
        let p = &state.protection;
        let observed = match &p.check_source_guard {
            CheckSourceGuard::BridgePosted => Guard::BridgePostedCheck,
            CheckSourceGuard::RequiredWorkflow => Guard::RequiredWorkflow,
            CheckSourceGuard::OwnerReview { .. } => Guard::CodeOwnerReview,
            CheckSourceGuard::Unreviewed => Guard::None,
            // An adapter with no guard of its own (Forgejo) protects the
            // workflow by the branch rule's protected file patterns.
            _ if p.present && !p.protected_paths.is_empty() => Guard::ProtectedFiles,
            _ => Guard::None,
        };
        if weakened && observed != Guard::BridgePostedCheck {
            Guard::None
        } else {
            observed
        }
    }
}

/// The namespace half of the report: the installation, the App, the
/// owner's plan and the check modes, as far as the bridge knows them.
pub(crate) fn namespace_report(bridge: &Bridge, ns: &NamespaceRecord) -> Map<String, Value> {
    let mut out = Map::new();
    let host = ns.resource.host();
    let adapter = bridge.adapters.get(host);
    let github = bridge.cfg.github.iter().find(|g| g.host == host);

    if let Some(g) = github {
        out.insert("appName".into(), json!(g.app_name));
        #[cfg(feature = "forge-github")]
        if let Some(slug) = adapter
            .as_ref()
            .and_then(|a| a.github())
            .map(|f| f.config().app_slug.clone())
        {
            out.insert("appSlug".into(), json!(slug));
        }
        let registration = if adapter.is_some() {
            "registered"
        } else if manifest_pending(bridge, host) {
            "pending"
        } else {
            "unregistered"
        };
        out.insert("appRegistration".into(), json!(registration));
    }

    let Some(binding) = ns.binding.as_ref() else {
        return out;
    };
    if let Some(id) = binding.namespace.installation_id {
        out.insert("installationId".into(), json!(id.to_string()));
    }
    if github.is_some() && binding.namespace.installation_id.is_some() {
        if !binding.missing_permissions.is_empty() {
            out.insert(
                "missingPermissions".into(),
                json!(binding.missing_permissions),
            );
        }
        // The installation has not approved everything the App asks for:
        // an App updated since it was installed (or one registered before
        // the bridge-posted check's permissions were in the manifest).
        // Unknown (not probed yet) is left out.
        let checks_wanted = github.is_some_and(|g| g.bridge_checks);
        let pending = if !binding.missing_permissions.is_empty() {
            Some(true)
        } else if checks_wanted {
            ns.bridge_checks.map(|ready| !ready)
        } else {
            Some(false)
        };
        if let Some(p) = pending {
            out.insert("permissionUpgradePending".into(), json!(p));
        }
        // Org rulesets (and so a required workflow) on the owner's plan, as
        // last found; `None` until probed.
        if let Some(available) = ns.required_workflow {
            out.insert("orgRulesets".into(), json!(available));
        }
    }
    if let Some(a) = &adapter {
        let caps = a.forge().capabilities(&binding.namespace);
        if caps.automation {
            out.insert("requiredWorkflow".into(), json!(caps.required_workflow));
            out.insert("bridgePostedCheck".into(), json!(caps.bridge_posted_check));
        }
    }
    out
}

/// A registration link for `host` is open and unexpired.
fn manifest_pending(bridge: &Bridge, host: &str) -> bool {
    let now = crate::bridge::now();
    bridge
        .store
        .list::<PendingFlow>(Table::Pending)
        .unwrap_or_default()
        .into_iter()
        .any(|(_, f)| {
            matches!(f, PendingFlow::Manifest { host: h, expires_at, .. }
                if h == host && expires_at > now)
        })
}

/// The repository half: the guard in force and the last check the bridge
/// posted, as recorded.
pub(crate) fn repo_report(rec: &RepoRecord) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(g) = &rec.guard {
        out.insert("guard".into(), json!(g));
    }
    if let Some(c) = &rec.last_check {
        out.insert(
            "lastCheck".into(),
            json!({
                "sha": c.sha,
                "conclusion": c.conclusion,
                "at": crate::flows::rfc3339(c.at),
            }),
        );
    }
    out
}

/// The `ext` member for a document about namespace `ns_id` and, when given,
/// the repository `repo` (`(host, forge id)`). `None` when there is nothing
/// to say.
pub(crate) fn ext(bridge: &Bridge, ns_id: &str, repo: Option<(&str, u64)>) -> Option<Value> {
    let mut report = Map::new();
    if let Ok(Some(ns)) = bridge
        .store
        .get::<NamespaceRecord>(Table::Namespaces, ns_id)
    {
        let n = namespace_report(bridge, &ns);
        if !n.is_empty() {
            report.insert("namespace".into(), Value::Object(n));
        }
    }
    if let Some((host, id)) = repo
        && let Ok(Some(rec)) = bridge
            .store
            .get::<RepoRecord>(Table::Repos, &crate::store::repo_key(host, id))
    {
        let r = repo_report(&rec);
        if !r.is_empty() {
            report.insert("repo".into(), Value::Object(r));
        }
    }
    (!report.is_empty()).then(|| json!({ EXT_KEY: report }))
}

/// `payload` with `ext` added, when there is one and the result still fits
/// the specification's type `P` (which bounds what `ext` may hold). A
/// report that does not fit is dropped, never the document it rides on.
pub(crate) fn attach<P: serde::de::DeserializeOwned>(payload: Value, ext: Option<Value>) -> Value {
    let Some(ext) = ext else {
        return payload;
    };
    let mut with = payload.clone();
    with["ext"] = ext;
    match serde_json::from_value::<P>(with.clone()) {
        Ok(_) => with,
        Err(e) => {
            tracing::error!(error = %e, "the status report does not fit the payload; sent without it");
            payload
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vgi_forge::{ForgeAccount, ProtectionState, Resource};

    fn state(guard: CheckSourceGuard, protected: &[&str]) -> RepoState {
        let mut p = ProtectionState::default();
        p.present = true;
        p.check_source_guard = guard;
        p.protected_paths = protected.iter().map(|s| s.to_string()).collect();
        let mut s = RepoState::new(Resource::parse("github.com/acme/widgets").unwrap(), 7);
        s.protection = p;
        s
    }

    #[test]
    fn the_guard_in_force_is_named_as_the_vtc_names_it() {
        let weakened = [Drift::ProtectionWeakened {
            gaps: vec![ProtectionGap::CheckSourceUnprotected {
                detail: "CODEOWNERS gone".into(),
            }],
        }];
        let review = CheckSourceGuard::OwnerReview {
            reviewers: vec![ForgeAccount::new(1, "bob")],
            issues: vec![],
        };
        let cases = [
            (
                state(CheckSourceGuard::RequiredWorkflow, &[]),
                &[][..],
                "requiredWorkflow",
            ),
            (state(review.clone(), &[]), &[][..], "codeOwnerReview"),
            (state(review, &[]), &weakened[..], "none"),
            (
                state(CheckSourceGuard::BridgePosted, &[]),
                &[][..],
                "bridgePostedCheck",
            ),
            (state(CheckSourceGuard::Unreviewed, &[]), &[][..], "none"),
            (
                state(CheckSourceGuard::Unknown, &[".forgejo/workflows/**"]),
                &[][..],
                "protectedFiles",
            ),
            (state(CheckSourceGuard::Unknown, &[]), &[][..], "none"),
        ];
        for (s, drift, want) in cases {
            assert_eq!(Guard::in_force(&s, drift).as_str(), want, "{s:?}");
        }
    }
}
