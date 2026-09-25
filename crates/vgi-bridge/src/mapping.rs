//! Between the adapters' forge-neutral types (`vgi_forge`) and the
//! specification's wire types.
//!
//! Everything that leaves the bridge is built as the generated type, from
//! JSON the generated deserializer checks against the schema's patterns and
//! bounds — so a value the specification would refuse fails here, not at the
//! VTC.

use anyhow::{Context, Result};
use serde_json::{Value, json};
use vgi_forge::{
    BootstrapComponent, Drift, ForgeAccount, ForgeError, ProtectionGap, Resource, Right,
    StepOutcome, Visibility,
};

use crate::wire::{clip, event, job, result};

/// The step and error-message bound in the result schema.
const DETAIL_MAX: usize = 1024;
/// The drift `observed` / `expected` bound.
const DRIFT_TEXT_MAX: usize = 256;

/// A right on the wire → the adapters' [`Right`].
pub fn right(r: &job::Right) -> Option<Right> {
    Right::from_action(&r.to_string())
}

/// A visibility on the wire → the adapters' [`Visibility`].
pub fn visibility(v: &job::RepoVisibility) -> Visibility {
    match v {
        job::RepoVisibility::Private => Visibility::Private,
        _ => Visibility::Public,
    }
}

/// A wire account → the adapters' account (numeric id, current login).
pub fn account(a: &job::ForgeAccount) -> Result<ForgeAccount> {
    let id: u64 =
        a.id.parse()
            .with_context(|| format!("forge account id `{}` is not numeric", *a.id))?;
    Ok(ForgeAccount::new(id, a.login.to_string()))
}

/// An adapter account → its wire form on `host`.
pub fn wire_account(host: &str, a: &ForgeAccount) -> Value {
    json!({ "forge": host, "id": a.id.to_string(), "login": clip(&a.login, 100) })
}

/// How one step went, for the result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStatus {
    /// Changed the forge.
    Applied,
    /// Already as required.
    Unchanged,
    /// Could not be applied.
    Failed,
    /// Not attempted.
    Skipped,
}

impl StepStatus {
    fn as_str(self) -> &'static str {
        match self {
            StepStatus::Applied => "applied",
            StepStatus::Unchanged => "unchanged",
            StepStatus::Failed => "failed",
            StepStatus::Skipped => "skipped",
        }
    }

    /// From an adapter step outcome.
    pub fn of(o: StepOutcome) -> Self {
        match o {
            StepOutcome::Unchanged => StepStatus::Unchanged,
            _ => StepStatus::Applied,
        }
    }

    fn rank(self) -> u8 {
        match self {
            StepStatus::Unchanged => 0,
            StepStatus::Applied => 1,
            StepStatus::Skipped => 2,
            StepStatus::Failed => 3,
        }
    }
}

/// The spec's step name for an adapter step: the four forge-neutral bootstrap
/// components by their names, anything else by its id's first part in
/// lowerCamelCase (`merge-style` → `mergeStyle`, `file:LICENSE` → `file`).
pub fn step_name(id: &str, component: BootstrapComponent) -> String {
    match component {
        BootstrapComponent::Workflow => "workflow".into(),
        BootstrapComponent::Keyring => "keyring".into(),
        BootstrapComponent::Variables => "variables".into(),
        BootstrapComponent::RequiredCheck => "requiredCheck".into(),
        _ => camel(id.split(':').next().unwrap_or(id)),
    }
}

fn camel(s: &str) -> String {
    let mut out = String::new();
    let mut upper = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            if out.is_empty() {
                if c.is_ascii_alphabetic() {
                    out.push(c.to_ascii_lowercase());
                }
            } else if upper {
                out.push(c.to_ascii_uppercase());
            } else {
                out.push(c);
            }
            upper = false;
        } else {
            upper = true;
        }
    }
    if out.is_empty() { "step".into() } else { out }
}

/// A job's report as it accumulates.
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// `(name, status, detail)`, merged by name: a name reported twice
    /// keeps its worst status.
    pub steps: Vec<(String, StepStatus, Option<String>)>,
    /// The repository the job reached.
    pub repo: Option<(Resource, u64)>,
    /// Why it failed or stopped: `(code, message)`.
    pub error: Option<(String, String)>,
}

impl Report {
    /// Record a step.
    pub fn step(&mut self, name: impl Into<String>, status: StepStatus, detail: Option<String>) {
        let name = name.into();
        if let Some(existing) = self.steps.iter_mut().find(|(n, _, _)| *n == name) {
            if status.rank() > existing.1.rank() {
                existing.1 = status;
                existing.2 = detail;
            }
            return;
        }
        self.steps.push((name, status, detail));
    }

    /// Record the failure that stopped the job (the first one wins).
    pub fn fail(&mut self, e: &ForgeError) {
        if self.error.is_none() {
            self.error = Some((error_code(e).into(), e.to_string()));
        }
    }

    /// Record a failure with an explicit code.
    pub fn fail_with(&mut self, code: &str, message: impl Into<String>) {
        if self.error.is_none() {
            self.error = Some((code.into(), message.into()));
        }
    }

    /// `succeeded`, `failed` or `partial`, per the spec: failed when nothing
    /// was applied, partial when something was and something failed.
    pub fn outcome(&self) -> &'static str {
        let failed = self.error.is_some()
            || self
                .steps
                .iter()
                .any(|(_, s, _)| matches!(s, StepStatus::Failed));
        if !failed {
            return "succeeded";
        }
        let any_done = self
            .steps
            .iter()
            .any(|(_, s, _)| matches!(s, StepStatus::Applied | StepStatus::Unchanged));
        if any_done { "partial" } else { "failed" }
    }

    /// The result payload for `job_id`.
    pub fn to_result(&self, job_id: &str) -> Result<result::Payload> {
        let mut v = json!({ "jobId": job_id, "outcome": self.outcome() });
        if let Some((r, id)) = &self.repo {
            v["repo"] = json!({ "resource": r.as_str(), "forgeId": id.to_string() });
        }
        if !self.steps.is_empty() {
            v["steps"] = Value::Array(
                self.steps
                    .iter()
                    .map(|(name, status, detail)| {
                        let mut s = json!({ "step": name, "outcome": status.as_str() });
                        if let Some(d) = detail {
                            s["detail"] = json!(clip(d, DETAIL_MAX));
                        }
                        s
                    })
                    .collect(),
            );
        }
        if self.outcome() != "succeeded" {
            let (code, message) = self
                .error
                .clone()
                .unwrap_or_else(|| ("forgeError".into(), "a step failed; see steps".into()));
            v["error"] = json!({ "code": code, "message": clip(&message, DETAIL_MAX) });
        }
        serde_json::from_value(v).context("building the job result")
    }
}

/// The spec's forge-neutral error code for an adapter error.
pub fn error_code(e: &ForgeError) -> &'static str {
    match e {
        ForgeError::AlreadyExists { .. } => "nameTaken",
        ForgeError::NotFound { .. } | ForgeError::Moved { .. } => "notFound",
        ForgeError::Forbidden(_) | ForgeError::Unauthorized(_) => "forbidden",
        ForgeError::Unsupported { .. } | ForgeError::NotBound { .. } => "notCapable",
        ForgeError::RateLimited { .. } => "rateLimited",
        _ => "forgeError",
    }
}

/// Whether the gaps leave the check unenforced — the spec's
/// `requiredCheck: false`. Force-push and deletion gaps weaken the
/// protection but do not let an unchecked change merge.
pub fn check_enforced(gaps: &[ProtectionGap]) -> bool {
    !gaps.iter().any(|g| {
        !matches!(
            g,
            ProtectionGap::ForcePushAllowed | ProtectionGap::DeletionAllowed
        )
    })
}

/// The spec's drift items for one repository's drift.
pub fn drift_items(host: &str, resource: &Resource, drift: &[Drift]) -> Vec<Value> {
    let item = |ty: &str| json!({ "type": ty, "resource": resource.as_str() });
    let text = |s: String| json!(clip(&s, DRIFT_TEXT_MAX));
    let mut out = Vec::new();
    for d in drift {
        match d {
            Drift::UnexpectedRole { account, observed } => {
                let mut v = item("roleAdded");
                v["account"] = wire_account(host, account);
                v["observed"] = text(observed.to_string());
                out.push(v);
            }
            Drift::MissingRole { account, expected } => {
                let mut v = item("roleRemoved");
                v["account"] = wire_account(host, account);
                v["expected"] = text(expected.to_string());
                out.push(v);
            }
            Drift::RoleMismatch {
                account,
                expected,
                observed,
            } => {
                let mut v = item("roleChanged");
                v["account"] = wire_account(host, account);
                v["expected"] = text(expected.to_string());
                v["observed"] = text(observed.to_string());
                out.push(v);
            }
            Drift::ProtectionWeakened { gaps } => {
                let missing = gaps.iter().find_map(|g| match g {
                    ProtectionGap::CheckNotRequired { check } => Some(check.clone()),
                    ProtectionGap::Missing => Some(String::new()),
                    _ => None,
                });
                if let Some(check) = missing {
                    let mut v = item("requiredCheckMissing");
                    let name = if check.is_empty() {
                        "the verify-trust check".to_string()
                    } else {
                        check
                    };
                    v["observed"] = text(format!("{name}: not required"));
                    v["expected"] = text(format!("{name}: required"));
                    out.push(v);
                }
                let rest: Vec<String> = gaps
                    .iter()
                    .filter(|g| {
                        !matches!(
                            g,
                            ProtectionGap::CheckNotRequired { .. } | ProtectionGap::Missing
                        )
                    })
                    .map(gap_text)
                    .collect();
                if !rest.is_empty() {
                    let mut v = item("protectionWeakened");
                    v["observed"] = text(rest.join("; "));
                    v["expected"] = text("no bypass, PR required, no force-push".into());
                    out.push(v);
                }
            }
            Drift::ReplanNeeded { reason } => {
                let mut v = item("bootstrapMissing");
                v["observed"] = text(reason.clone());
                out.push(v);
            }
            // Renames and replacements travel as events (`repoRenamed`,
            // `repoDeleted`); archive and visibility differences have no
            // drift type in the specification and are logged instead.
            other => {
                tracing::info!(resource = %resource, drift = ?other, "drift with no wire form")
            }
        }
    }
    out
}

fn gap_text(g: &ProtectionGap) -> String {
    match g {
        ProtectionGap::NotEnforced => "rule not enforced".into(),
        ProtectionGap::DefaultBranchNotCovered => "default branch not covered".into(),
        ProtectionGap::PullRequestNotRequired => "pull requests not required".into(),
        ProtectionGap::ForcePushAllowed => "force-push allowed".into(),
        ProtectionGap::DeletionAllowed => "deletion allowed".into(),
        ProtectionGap::BypassActors { actors } => format!("bypass actors: {}", actors.join(", ")),
        ProtectionGap::UnprotectedPaths { paths } => {
            format!("unprotected paths: {}", paths.join(", "))
        }
        ProtectionGap::MergeMethodAllowed { method } => format!("merge method allowed: {method:?}"),
        ProtectionGap::CiDisabled => "CI disabled".into(),
        ProtectionGap::CheckSourceUnprotected { detail } => {
            format!("check source unprotected: {detail}")
        }
        other => format!("{other:?}"),
    }
}

/// An event payload: `event` (the `ForgeEvent` JSON) in `namespace`, with
/// `drift` when the event concerns repositories.
pub fn event_payload(
    namespace: &str,
    event_json: Value,
    drift: Option<Vec<Value>>,
) -> Result<event::Payload> {
    let mut v = json!({ "namespace": namespace, "event": event_json });
    if let Some(d) = drift
        && !d.is_empty()
    {
        v["drift"] = Value::Array(d);
    }
    serde_json::from_value(v).context("building the event")
}

/// The first resource in an event that lies outside `namespace`, by
/// whole-segment containment (event 0.2: the VTC refuses such an event
/// whole, so the bridge never sends one): the `resource` of any event, the
/// `from` of any event, a `repoRenamed`'s `to`, and every drift item's
/// `resource`, and a `roleMapReported`'s `repos[].resource` and `stale`
/// entries. A `repoTransferred`'s `to` is exempt — a transfer leaves the
/// namespace by definition. A resource that does not parse counts as
/// outside, as does every resource when there is no `namespace` to hold it.
pub fn outside_namespace(
    namespace: Option<&Resource>,
    event: &Value,
    drift: &[Value],
) -> Option<String> {
    let renamed = event.get("type").and_then(Value::as_str) == Some("repoRenamed");
    let mut members = vec![event.get("resource"), event.get("from")];
    if renamed {
        members.push(event.get("to"));
    }
    if event.get("type").and_then(Value::as_str) == Some("roleMapReported") {
        let listed = |k: &str| event.get(k).and_then(Value::as_array).into_iter().flatten();
        members.extend(listed("repos").map(|r| r.get("resource")));
        members.extend(listed("stale").map(Some));
    }
    members.extend(drift.iter().map(|d| d.get("resource")));
    members.into_iter().flatten().find_map(|v| {
        let s = v.as_str().unwrap_or_default();
        match Resource::parse(s) {
            Ok(r) if namespace.is_some_and(|n| n.contains(&r)) => None,
            _ => Some(s.to_string()),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn res() -> Resource {
        Resource::parse("github.com/acme/widgets").unwrap()
    }

    #[test]
    fn step_names_fit_the_schema() {
        assert_eq!(
            step_name("required-workflow", BootstrapComponent::Workflow),
            "workflow"
        );
        assert_eq!(
            step_name("merge-style", BootstrapComponent::Extra),
            "mergeStyle"
        );
        assert_eq!(step_name("file:LICENSE", BootstrapComponent::Extra), "file");
        assert_eq!(
            step_name("cleanup:variable:VTC_DID", BootstrapComponent::Variables),
            "variables"
        );
        assert_eq!(step_name("--", BootstrapComponent::Extra), "step");
    }

    #[test]
    fn outcomes_follow_the_spec() {
        let mut r = Report::default();
        r.step("create", StepStatus::Applied, None);
        assert_eq!(r.outcome(), "succeeded");
        r.step("runner", StepStatus::Failed, Some("no runner".into()));
        assert_eq!(r.outcome(), "partial");
        let p = r.to_result("job_1").unwrap();
        let v = serde_json::to_value(&p).unwrap();
        assert_eq!(v["error"]["code"], "forgeError");
        let mut r = Report::default();
        r.fail(&ForgeError::AlreadyExists {
            resource: "x".into(),
            forge_id: Some(1),
        });
        assert_eq!(r.outcome(), "failed");
        assert_eq!(
            serde_json::to_value(r.to_result("j").unwrap()).unwrap()["error"]["code"],
            "nameTaken"
        );
    }

    #[test]
    fn a_weakened_ruleset_maps_to_required_check_missing_and_the_rest() {
        let drift = [Drift::ProtectionWeakened {
            gaps: vec![
                ProtectionGap::CheckNotRequired {
                    check: "Verify commit trust".into(),
                },
                ProtectionGap::BypassActors {
                    actors: vec!["Team:1:always".into()],
                },
            ],
        }];
        let items = drift_items("github.com", &res(), &drift);
        assert_eq!(items[0]["type"], "requiredCheckMissing");
        assert_eq!(items[1]["type"], "protectionWeakened");
        // Every item is a valid wire drift item.
        let p = event_payload(
            "ns_1",
            json!({ "type": "protectionChanged", "forgeId": "1", "resource": res().as_str(), "requiredCheck": false }),
            Some(items),
        )
        .unwrap();
        assert_eq!(p.drift.len(), 2);
        assert!(!check_enforced(&[ProtectionGap::Missing]));
        assert!(check_enforced(&[ProtectionGap::ForcePushAllowed]));
    }

    #[test]
    fn every_resource_but_a_transfers_destination_lies_in_the_namespace() {
        let ns = Resource::parse("github.com/acme").unwrap();
        let out = |ev: Value, drift: &[Value]| outside_namespace(Some(&ns), &ev, drift);
        let m = json!({"own":"admin","maintain":"maintain","commit":"none"});
        // Inside: nothing to refuse.
        assert_eq!(
            out(
                json!({"type":"roleMapReported","roleMap":m,
                       "repos":[{"resource":"github.com/acme/a","roleMap":m}],
                       "stale":["github.com/acme/b"]}),
                &[]
            ),
            None
        );
        assert_eq!(
            out(
                json!({"type":"repoRenamed","forgeId":"1","from":"github.com/acme/a","to":"github.com/acme/b"}),
                &[]
            ),
            None
        );
        // A transfer's `to` is where the repository went: exempt.
        assert_eq!(
            out(
                json!({"type":"repoTransferred","forgeId":"1","from":"github.com/acme/a","to":"github.com/acme-labs/a"}),
                &[]
            ),
            None
        );
        // A transfer's `from`, a rename's either end, a resource, a drift
        // item: each must be inside.
        let cases = [
            (
                json!({"type":"repoTransferred","forgeId":"1","from":"github.com/other/a","to":"github.com/acme/a"}),
                vec![],
                "github.com/other/a",
            ),
            (
                json!({"type":"repoRenamed","forgeId":"1","from":"github.com/acme/a","to":"github.com/acme-labs/a"}),
                vec![],
                "github.com/acme-labs/a",
            ),
            (
                json!({"type":"repoRenamed","forgeId":"1","from":"github.com/acme-labs/a","to":"github.com/acme/a"}),
                vec![],
                "github.com/acme-labs/a",
            ),
            (
                json!({"type":"repoCreatedUnmanaged","forgeId":"1","resource":"github.com/acmex/a"}),
                vec![],
                "github.com/acmex/a",
            ),
            (
                json!({"type":"repoDeleted","forgeId":"1","resource":"codeberg.org/acme/a"}),
                vec![],
                "codeberg.org/acme/a",
            ),
            (
                json!({"type":"protectionChanged","forgeId":"1","resource":"github.com/acme/a","requiredCheck":true}),
                vec![json!({"type":"protectionWeakened","resource":"github.com/other/a"})],
                "github.com/other/a",
            ),
            (
                json!({"type":"roleMapReported","roleMap":m,
                       "repos":[{"resource":"github.com/acme-labs/a","roleMap":m}]}),
                vec![],
                "github.com/acme-labs/a",
            ),
            (
                json!({"type":"roleMapReported","roleMap":m,
                       "stale":["github.com/acme/a","codeberg.org/acme/b"]}),
                vec![],
                "codeberg.org/acme/b",
            ),
        ];
        for (ev, drift, bad) in cases {
            assert_eq!(out(ev.clone(), &drift).as_deref(), Some(bad), "{ev}");
        }
        // Events without resources are never refused.
        assert_eq!(out(json!({"type":"installationRemoved"}), &[]), None);
        // No namespace: nothing is inside it.
        let ev = json!({"type":"repoDeleted","forgeId":"1","resource":"github.com/acme/a"});
        assert!(outside_namespace(None, &ev, &[]).is_some());
        assert!(outside_namespace(None, &json!({"type":"installationRemoved"}), &[]).is_none());
    }
}
