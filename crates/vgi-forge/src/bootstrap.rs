//! Bootstrap plans: the steps that turn commit trust on for a repository.
//!
//! An adapter turns a [`VgiConfig`] into an ordered list of
//! [`BootstrapStep`]s (§5.3 is GitHub's list), and runs them one at a time.
//! Every step is check-then-apply, so a plan that failed half-way is retried
//! from the top and the steps already done report
//! [`StepOutcome::Unchanged`].
//!
//! Order matters and is the adapter's to get right: files must land before
//! the protection that forbids direct pushes, because the protection has no
//! bypass actors — not even the bridge.

use serde::{Deserialize, Serialize};

use crate::error::{ForgeError, Result};
use crate::forge::Forge;
use crate::model::ForgeAccount;
use crate::resource::Resource;

/// The required status check's default name: the verify-trust job's `name`.
pub const DEFAULT_REQUIRED_CHECK: &str = "Verify commit trust";

/// Which Trust Registry binding the verify-trust workflow uses — the
/// action's `transport` input.
///
/// `Auto` (the default) is verify-trust's strict preference: TSP, then
/// DIDComm, then HTTPS, whichever the registry's DID document advertises,
/// with no fallback when the chosen one fails. A community whose registry
/// mediator does not yet admit a CI run's throwaway DID pins `Https`.
/// A closed set, so a value can be written into a workflow as-is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum VerifyTransport {
    /// Strict preference: TSP, then DIDComm, then HTTPS.
    #[default]
    Auto,
    /// TSP only.
    Tsp,
    /// DIDComm only.
    Didcomm,
    /// HTTPS (the registry's `#rest` endpoint) only.
    Https,
}

impl VerifyTransport {
    /// The action input's value.
    pub fn as_str(self) -> &'static str {
        match self {
            VerifyTransport::Auto => "auto",
            VerifyTransport::Tsp => "tsp",
            VerifyTransport::Didcomm => "didcomm",
            VerifyTransport::Https => "https",
        }
    }

    /// Whether this is the default.
    pub fn is_auto(&self) -> bool {
        *self == VerifyTransport::Auto
    }

    /// The workflow's `transport:` input line (indented for the action's
    /// `with:` block), or nothing for the default — so a workflow written
    /// before this option existed is unchanged byte for byte.
    pub fn workflow_input_line(self, indent: &str) -> String {
        if self.is_auto() {
            String::new()
        } else {
            format!("{indent}transport: {}\n", self.as_str())
        }
    }
}

impl std::fmt::Display for VerifyTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Forge-neutral inputs to a bootstrap plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VgiConfig {
    /// DID of the Trust Registry (`TRUST_REGISTRY_DID`).
    pub trust_registry_did: String,
    /// DID of this VTC (`VTC_DID`) — the only authority a bootstrapped repo
    /// trusts (§4.1).
    pub vtc_did: String,
    /// The verify-trust action reference the workflow `uses:`, pinned to a
    /// commit, e.g. `OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@<sha>`.
    pub verify_trust_action: String,
    /// The VGI release the action downloads (`version:` input), e.g. `v0.5.0`.
    pub verify_trust_version: String,
    /// SHA-256 of the release tarball the runner downloads (`sha256:` input,
    /// 64 lowercase hex). Where the runner cannot verify the release's build
    /// attestation (Forgejo), this pin in the reviewed workflow is what
    /// survives a replaced release asset; an adapter for such a forge refuses
    /// a plan without it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub verify_trust_sha256: Option<String>,
    /// Name of the required status check. The workflow's job is given this
    /// name, so the two cannot disagree.
    pub required_check: String,
    /// Armored PGP keyring of the forge's platform keys (GitHub's `web-flow`)
    /// for the exempt keyring. Supplied by configuration; adapters do not
    /// fetch it on their own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub platform_keyring: Option<Vec<u8>>,
    /// Extra files a community commits to every new repo (§5.8 layer 3:
    /// a `CODEOWNERS`, a licence). Committed before protection is enabled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_files: Vec<ExtraFile>,
    /// The registry binding the workflow's verify-trust uses (`transport:`
    /// input); the default writes no input.
    #[serde(default, skip_serializing_if = "VerifyTransport::is_auto")]
    pub verify_trust_transport: VerifyTransport,
}

impl VgiConfig {
    /// A config with the default check name and no keyring or extra files.
    pub fn new(
        trust_registry_did: impl Into<String>,
        vtc_did: impl Into<String>,
        verify_trust_action: impl Into<String>,
        verify_trust_version: impl Into<String>,
    ) -> Self {
        VgiConfig {
            trust_registry_did: trust_registry_did.into(),
            vtc_did: vtc_did.into(),
            verify_trust_action: verify_trust_action.into(),
            verify_trust_version: verify_trust_version.into(),
            verify_trust_sha256: None,
            required_check: DEFAULT_REQUIRED_CHECK.into(),
            platform_keyring: None,
            extra_files: Vec::new(),
            verify_trust_transport: VerifyTransport::Auto,
        }
    }

    /// Pin the registry binding the workflow uses.
    pub fn with_verify_trust_transport(mut self, transport: VerifyTransport) -> Self {
        self.verify_trust_transport = transport;
        self
    }

    /// Pin the release tarball's SHA-256.
    pub fn with_verify_trust_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.verify_trust_sha256 = Some(sha256.into());
        self
    }

    /// Set the platform keyring.
    pub fn with_platform_keyring(mut self, armored: impl Into<Vec<u8>>) -> Self {
        self.platform_keyring = Some(armored.into());
        self
    }

    /// Add a community file.
    pub fn with_extra_file(
        mut self,
        path: impl Into<String>,
        contents: impl Into<Vec<u8>>,
    ) -> Self {
        self.extra_files.push(ExtraFile {
            path: path.into(),
            contents: contents.into(),
        });
        self
    }
}

/// A community-supplied file to commit during bootstrap.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtraFile {
    /// Repository-relative path.
    pub path: String,
    /// Contents.
    pub contents: Vec<u8>,
}

/// Which part of the VTC's bootstrap status (§4.3 `bootstrap`) a step
/// satisfies — the four dots on the Repos page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum BootstrapComponent {
    /// The verify-trust workflow.
    Workflow,
    /// The exempt platform keyring.
    Keyring,
    /// The `TRUST_REGISTRY_DID` / `VTC_DID` variables.
    Variables,
    /// The protection that requires the check.
    RequiredCheck,
    /// Anything else (community files, forge-specific settings).
    Extra,
}

/// Branch protection to enforce on the default branch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProtectionSpec {
    /// The status check that must pass.
    pub required_check: String,
    /// Changes must come through a pull request.
    pub require_pull_request: bool,
    /// Block force-pushes.
    pub block_force_push: bool,
    /// Block deletion.
    pub block_deletion: bool,
    /// Require [`ProtectionSpec::required_check`] in this rule. `false` when
    /// the check is enforced at the namespace level instead (a required
    /// workflow, [`StepAction::RequireNamespaceWorkflow`]), so this rule
    /// carries only the PR, force-push and deletion parts.
    #[serde(default = "yes")]
    pub require_status_check: bool,
    /// Pull requests need an approving review, including a code owner's for
    /// files that have one ([`StepAction::RequireOwnerReview`]).
    #[serde(default)]
    pub require_code_owner_review: bool,
    /// Paths (forge glob syntax) a pull request may not change and still
    /// merge: the workflows and the exempt keyring. Without this a PR could
    /// rewrite the check it is judged by — CI runs the PR's own copy of the
    /// workflow — and pass itself. Empty where the forge enforces this some
    /// other way or not at all.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_paths: Vec<String>,
}

fn yes() -> bool {
    true
}

impl ProtectionSpec {
    /// The §5.3 protection: PR required, `check` required, no force-push, no
    /// deletion. There is deliberately no bypass field — the design allows
    /// no bypass actors, so there is nothing to configure.
    pub fn standard(check: impl Into<String>) -> Self {
        ProtectionSpec {
            required_check: check.into(),
            require_pull_request: true,
            block_force_push: true,
            block_deletion: true,
            require_status_check: true,
            require_code_owner_review: false,
            protected_paths: Vec::new(),
        }
    }

    /// Also forbid pull requests that change `paths`.
    pub fn with_protected_paths<I, S>(mut self, paths: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.protected_paths = paths.into_iter().map(Into::into).collect();
        self
    }

    /// Leave the check out of this rule: a namespace-level required workflow
    /// enforces it.
    pub fn with_check_enforced_by_namespace(mut self) -> Self {
        self.require_status_check = false;
        self
    }

    /// Require an approving review, and a code owner's where one is named.
    pub fn with_code_owner_review(mut self) -> Self {
        self.require_code_owner_review = true;
        self
    }
}

/// A way a pull request can land on the default branch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum MergeMethod {
    /// Fast-forward only: the PR's own commits land unchanged, DID
    /// signatures and all. The one method that needs no platform key.
    FastForward,
    /// A merge commit, made (and signed, if at all) by the forge.
    MergeCommit,
    /// The PR's commits re-created on the base by the forge.
    Rebase,
    /// Rebase, then a merge commit (Forgejo's `rebase-merge`).
    RebaseMerge,
    /// One new commit, made by the forge.
    Squash,
}

/// Repository settings a bootstrap enforces alongside the protection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RepoSettings {
    /// The only merge methods to allow; the first is the default. Empty
    /// leaves the forge's merge settings alone.
    pub merge_methods: Vec<MergeMethod>,
    /// Turn the forge's CI on for the repository. Off, the required check
    /// never reports and nothing can merge.
    pub enable_ci: bool,
}

impl RepoSettings {
    /// Allow exactly `methods` (the first the default) and enable CI.
    pub fn merge_methods(methods: impl Into<Vec<MergeMethod>>) -> Self {
        RepoSettings {
            merge_methods: methods.into(),
            enable_ci: true,
        }
    }
}

/// What a step does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum StepAction {
    /// Make a file on the default branch have exactly these contents.
    WriteFile {
        /// Repository-relative path.
        path: String,
        /// Desired contents.
        contents: Vec<u8>,
        /// Commit message if a commit is needed.
        message: String,
    },
    /// Make a CI variable have this value.
    SetVariable {
        /// Variable name.
        name: String,
        /// Desired value.
        value: String,
    },
    /// Enforce protection on the default branch.
    ProtectDefaultBranch(ProtectionSpec),
    /// Run the check from a workflow the namespace holds outside the
    /// repository, pinned to a revision, and require it on this repository's
    /// default branch. The change under test cannot alter what checks it
    /// (§9: the PR must not be able to satisfy its own check).
    RequireNamespaceWorkflow {
        /// The workflow's contents.
        contents: Vec<u8>,
        /// The check (job) name it reports, for inspection.
        check: String,
        /// Commit message if the workflow has to be (re)written.
        message: String,
    },
    /// Make every change to `paths` need an approving review from one of
    /// `owners` — the fallback where no namespace-level workflow is
    /// available (§9). The adapter resolves each account's current login at
    /// run time; the numeric id is what is planned.
    RequireOwnerReview {
        /// Repository paths (directories end in `/`), e.g. `/.github/`.
        paths: Vec<String>,
        /// Who may approve. Never empty.
        owners: Vec<ForgeAccount>,
        /// The community's own owner rules, in the forge's format, kept
        /// ahead of the managed rule (which therefore wins for `paths`).
        /// Rules already in the repository take their place when present.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        community_rules: Vec<u8>,
        /// Commit message if the rules have to be (re)written.
        message: String,
    },
    /// Make sure a file is absent from the default branch (clean-up after
    /// a change of guard).
    RemoveFile {
        /// Repository-relative path.
        path: String,
        /// Commit message if a commit is needed.
        message: String,
    },
    /// Make sure a CI variable is absent.
    RemoveVariable {
        /// Variable name.
        name: String,
    },
    /// Make the repository's settings (merge methods, CI) match.
    ConfigureRepo(RepoSettings),
    /// Rewrite files the default branch's protection forbids changing — the
    /// managed workflow, the exempt keyring — through a temporary exception
    /// for the bridge alone, restoring the protection exactly afterwards
    /// (and attempting to even when a write failed). A maintenance job, not
    /// part of a bootstrap: it is the one sanctioned way the bridge changes
    /// a protected path, so it runs as one audited step.
    RefreshProtectedFiles {
        /// The files, each with its desired contents.
        files: Vec<ExtraFile>,
        /// Commit message for each file that changes.
        message: String,
    },
}

/// One step of a bootstrap plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BootstrapStep {
    /// Stable id for progress reporting and retries, e.g. `workflow`,
    /// `variable:VTC_DID`.
    pub id: String,
    /// The status component it satisfies.
    pub component: BootstrapComponent,
    /// What to do.
    pub action: StepAction,
}

impl BootstrapStep {
    /// A step.
    pub fn new(id: impl Into<String>, component: BootstrapComponent, action: StepAction) -> Self {
        BootstrapStep {
            id: id.into(),
            component,
            action,
        }
    }
}

/// What running one step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum StepOutcome {
    /// Already as desired; nothing written.
    Unchanged,
    /// Did not exist; created.
    Created,
    /// Existed but differed; corrected.
    Updated,
}

/// Result of [`run_plan`]. In-process only (it carries [`ForgeError`]); the
/// bridge reports it to the VTC in its own job-result shape.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct BootstrapReport {
    /// Steps that ran, with their outcome, in order.
    pub completed: Vec<(String, StepOutcome)>,
    /// The step that failed, and why; the rest did not run.
    pub failed: Option<(String, ForgeError)>,
    /// Ids of steps not attempted because an earlier one failed.
    pub not_run: Vec<String>,
}

impl BootstrapReport {
    /// Whether every step completed.
    pub fn is_complete(&self) -> bool {
        self.failed.is_none()
    }
}

/// Run `steps` in order against `repo`, stopping at the first failure.
///
/// Stopping is the point: a later step (protection) can lock out an earlier
/// one (files), so running past a failure could leave a repo protected
/// before its workflow exists — a required check that can never report.
pub async fn run_plan(
    forge: &dyn Forge,
    repo: &Resource,
    steps: &[BootstrapStep],
) -> BootstrapReport {
    let mut report = BootstrapReport::default();
    for (i, step) in steps.iter().enumerate() {
        match forge.run_step(repo, step).await {
            Ok(outcome) => report.completed.push((step.id.clone(), outcome)),
            Err(e) => {
                report.failed = Some((step.id.clone(), e));
                report.not_run = steps[i + 1..].iter().map(|s| s.id.clone()).collect();
                break;
            }
        }
    }
    report
}

/// Validate a repository-relative path for a [`StepAction::WriteFile`]: no
/// absolute paths, no empty, `.` or `..` segments, no backslashes. Adapters
/// call this before building a URL from it.
pub fn validate_repo_path(path: &str) -> Result<()> {
    let bad = path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path
            .split('/')
            .any(|s| s.is_empty() || s == "." || s == ".." || s.chars().any(char::is_control));
    if bad {
        return Err(ForgeError::Config(format!(
            "`{path}` is not a clean repository-relative path (no leading `/`, no empty, `.` or \
             `..` segments)"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repo_paths_are_checked() {
        assert!(validate_repo_path(".github/workflows/verify-trust.yml").is_ok());
        assert!(validate_repo_path("CODEOWNERS").is_ok());
        for bad in ["", "/etc/x", "a//b", "a/../b", "./a", "a\\b", "a/\n"] {
            assert!(validate_repo_path(bad).is_err(), "{bad:?}");
        }
    }
}
