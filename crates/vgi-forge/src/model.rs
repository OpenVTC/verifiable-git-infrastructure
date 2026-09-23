//! The data an adapter is handed and hands back.
//!
//! Everything here is forge-neutral and serialisable: these are the payloads
//! of the VTC ↔ bridge jobs (`git-ns/bridge/*`), so a third-party bridge in
//! another language sees the same shapes. Types that are expected to grow are
//! `#[non_exhaustive]`; construct them with their constructors or
//! `Default` and field assignment.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::bootstrap::MergeMethod;
use crate::resource::Resource;
use crate::rights::ForgeRole;

/// Which forge software an adapter speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum ForgeKind {
    /// github.com or GitHub Enterprise Server.
    GitHub,
    /// Forgejo (and Gitea, best effort).
    Forgejo,
}

impl ForgeKind {
    /// Stable lowercase name: `github`, `forgejo`.
    pub fn as_str(self) -> &'static str {
        match self {
            ForgeKind::GitHub => "github",
            ForgeKind::Forgejo => "forgejo",
        }
    }
}

impl fmt::Display for ForgeKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Whether a namespace is an organisation or a personal account (§3, §8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum NamespaceKind {
    /// An organisation: real roles, bot repo creation.
    Organization,
    /// A personal account: the reduced capability set of §8.
    User,
}

/// A bound namespace, as the adapter needs it (§4.1). The VTC's record has
/// more (`id`, `boundBy`, `boundAt`); the adapter needs only what locates the
/// owner on the forge and the credential that acts on it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Namespace {
    /// `host/owner`, e.g. `github.com/acme`.
    pub resource: Resource,
    /// The forge's numeric id for the owner — survives renames.
    pub owner_id: Option<u64>,
    /// Organisation or personal account.
    pub kind: NamespaceKind,
    /// The automation credential's handle on this namespace (a GitHub App
    /// installation id). `None` is manual mode: the VTC governs rights and
    /// the registry, but nothing acts on the forge.
    pub installation_id: Option<u64>,
}

impl Namespace {
    /// A namespace with no owner id and no installation (manual mode).
    pub fn new(resource: Resource, kind: NamespaceKind) -> Self {
        Namespace {
            resource,
            owner_id: None,
            kind,
            installation_id: None,
        }
    }

    /// Set the owner's numeric id.
    pub fn with_owner_id(mut self, id: u64) -> Self {
        self.owner_id = Some(id);
        self
    }

    /// Set the installation id.
    pub fn with_installation(mut self, id: u64) -> Self {
        self.installation_id = Some(id);
        self
    }
}

/// How a forge makes a status check required (§5.8 table).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum RequiredCheckKind {
    /// The forge cannot require a check: repos are flagged *unprotected*.
    #[default]
    None,
    /// A repository ruleset with a required status check (GitHub).
    Ruleset,
    /// Branch protection `status_check_contexts` (Forgejo).
    BranchProtection,
}

/// How a member links their forge account (§4.4).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum LinkMethod {
    /// No automated link; the core records a binding some other way.
    #[default]
    None,
    /// OAuth device flow — works from a terminal (GitHub).
    DeviceFlow,
    /// OAuth2 authorisation code with PKCE, through a browser (Forgejo).
    AuthorizationCodePkce,
}

/// What a forge — and one namespace on it — can do (§5.8).
///
/// The core and the UX branch on this, never on [`ForgeKind`]. A personal
/// GitHub account is not a special case: it is the GitHub adapter returning
/// a smaller set here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Capabilities {
    /// The adapter holds a credential for this namespace and can act on it
    /// at all. `false` is manual mode: every forge-side step is a human's.
    pub automation: bool,
    /// The bridge can create repositories here. Without it, `repo/create`
    /// reserves the name and returns manual steps.
    pub bot_can_create_repos: bool,
    /// The forge roles available on repositories here, lowest first.
    /// [`crate::collapse_to_ladder`] fits a requested role onto it.
    pub role_levels: Vec<ForgeRole>,
    /// How the verify-trust check is made required.
    pub required_checks: RequiredCheckKind,
    /// Whether the forge pushes change events. Without them, drift is found
    /// by a scheduled `inspect` sweep.
    pub webhooks: bool,
    /// How members link their forge accounts.
    pub account_link: LinkMethod,
    /// Whether the credential can be narrowed to one repository per job.
    pub per_repo_tokens: bool,
}

/// A person's account on a forge. The numeric id is authoritative; the login
/// is for display and can be renamed and re-registered (§4.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForgeAccount {
    /// Numeric account id.
    pub id: u64,
    /// Login at the time it was read. Display only.
    pub login: String,
}

impl ForgeAccount {
    /// An account from its id and current login.
    pub fn new(id: u64, login: impl Into<String>) -> Self {
        ForgeAccount {
            id,
            login: login.into(),
        }
    }
}

/// One person's desired role on one repository.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RoleAssignment {
    /// Who.
    pub account: ForgeAccount,
    /// The role they should hold.
    pub role: ForgeRole,
}

impl RoleAssignment {
    /// Assign `role` to `account`.
    pub fn new(account: ForgeAccount, role: ForgeRole) -> Self {
        RoleAssignment { account, role }
    }
}

/// What to do with direct collaborators the desired set does not mention.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub enum Unlisted {
    /// Leave them. Drift mode `report` (the default for roles, §5.6): the
    /// core reports them and a human adopts or reverts.
    #[default]
    Keep,
    /// Remove them. Drift mode `enforce`.
    Remove,
}

/// Repository visibility.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Visibility {
    /// Anyone can read.
    #[default]
    Public,
    /// Only collaborators and org members with access.
    Private,
    /// Enterprise members (GitHub Enterprise).
    Internal,
}

/// A repository to create (§5.2 `git-ns/repo/create`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RepoSpec {
    /// The full resource, `host/owner/name`.
    pub resource: Resource,
    /// Visibility.
    pub visibility: Visibility,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl RepoSpec {
    /// A public repository with no description.
    pub fn new(resource: Resource) -> Self {
        RepoSpec {
            resource,
            visibility: Visibility::Public,
            description: None,
        }
    }

    /// Set the visibility.
    pub fn with_visibility(mut self, visibility: Visibility) -> Self {
        self.visibility = visibility;
        self
    }

    /// Set the description.
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }
}

/// A collaborator as observed on the forge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Collaborator {
    /// Who.
    pub account: ForgeAccount,
    /// Their role (the base role, for a forge with custom roles).
    pub role: ForgeRole,
    /// An invitation not yet accepted. Counts as present for drift: the
    /// adapter has done its part.
    pub pending: bool,
}

impl Collaborator {
    /// An accepted collaborator.
    pub fn new(account: ForgeAccount, role: ForgeRole) -> Self {
        Collaborator {
            account,
            role,
            pending: false,
        }
    }

    /// A pending invitation.
    pub fn invited(account: ForgeAccount, role: ForgeRole) -> Self {
        Collaborator {
            account,
            role,
            pending: true,
        }
    }
}

/// The default-branch protection that makes the check mean something, as
/// observed. Each flag is the *protective* state, so `Default` is "nothing
/// protected".
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProtectionState {
    /// The managed rule (ruleset, branch protection) exists.
    pub present: bool,
    /// It is enforced, not disabled or in evaluate-only mode.
    pub enforced: bool,
    /// It covers the default branch.
    pub covers_default_branch: bool,
    /// Changes must come through a pull request.
    pub requires_pull_request: bool,
    /// Status checks the rule requires (by context name).
    pub required_checks: Vec<String>,
    /// Force-pushes are blocked.
    pub blocks_force_push: bool,
    /// Branch deletion is blocked.
    pub blocks_deletion: bool,
    /// Actors allowed to bypass it. Must be empty (§5.3).
    pub bypass_actors: Vec<String>,
    /// Paths a pull request may not change (forge glob syntax), for a forge
    /// that protects the workflow this way. Empty when not read.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub protected_paths: Vec<String>,
    /// The merge methods the repository allows, for an adapter that reads
    /// them. `None`: not observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_methods: Option<Vec<MergeMethod>>,
    /// Whether the forge's CI is enabled on the repository, for an adapter
    /// that reads it. `None`: not observed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ci_enabled: Option<bool>,
}

/// A repository as observed on the forge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RepoState {
    /// Where it is now (after any rename or transfer).
    pub resource: Resource,
    /// The forge's numeric repo id — rights are keyed on this (§9).
    pub forge_id: u64,
    /// Visibility.
    pub visibility: Visibility,
    /// Archived (read-only).
    pub archived: bool,
    /// The default branch, if the repository has any commits.
    pub default_branch: Option<String>,
    /// Direct collaborators and pending invitations.
    pub collaborators: Vec<Collaborator>,
    /// The managed default-branch protection.
    pub protection: ProtectionState,
}

impl RepoState {
    /// A state with no collaborators and no protection.
    pub fn new(resource: Resource, forge_id: u64) -> Self {
        RepoState {
            resource,
            forge_id,
            visibility: Visibility::Public,
            archived: false,
            default_branch: None,
            collaborators: Vec::new(),
            protection: ProtectionState::default(),
        }
    }
}

/// What the VTC says a repository should look like on the forge: the
/// enforced projection of §2.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct Projection {
    /// The resource the VTC holds for the repository.
    pub resource: Resource,
    /// The forge id the VTC recorded, if it has one. When set, a state with
    /// the same id at a different resource is a rename, not a new repo.
    pub forge_id: Option<u64>,
    /// Desired roles for people with linked accounts. Nobody else should
    /// hold a direct role.
    pub roles: Vec<RoleAssignment>,
    /// The check that must be required on the default branch
    /// (`Verify commit trust`). `None` for a repo not yet bootstrapped.
    pub required_check: Option<String>,
    /// Whether the repository should be archived.
    pub archived: bool,
    /// The visibility the VTC recorded, if it tracks one.
    pub visibility: Option<Visibility>,
}

impl Projection {
    /// A projection with no roles and no required check.
    pub fn new(resource: Resource) -> Self {
        Projection {
            resource,
            forge_id: None,
            roles: Vec::new(),
            required_check: None,
            archived: false,
            visibility: None,
        }
    }
}

/// What happened to one person in [`crate::Forge::apply_roles`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct RoleChange {
    /// Who.
    pub account: ForgeAccount,
    /// Role before.
    pub from: ForgeRole,
    /// Role requested.
    pub to: ForgeRole,
    /// What the forge did.
    pub outcome: RoleOutcome,
}

impl RoleChange {
    /// A change of `account` from `from` to `to`, with its outcome.
    pub fn new(
        account: ForgeAccount,
        from: ForgeRole,
        to: ForgeRole,
        outcome: RoleOutcome,
    ) -> Self {
        RoleChange {
            account,
            from,
            to,
            outcome,
        }
    }
}

/// Outcome of one role change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "detail")]
#[non_exhaustive]
pub enum RoleOutcome {
    /// Applied directly.
    Applied,
    /// An invitation was sent (or updated); the person must accept.
    Invited,
    /// The forge refused; the message says why.
    Failed(String),
}

/// Result of converging a repository's roles.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ApplyReport {
    /// Every change attempted, in order.
    pub changes: Vec<RoleChange>,
    /// People already at their desired role.
    pub unchanged: Vec<ForgeAccount>,
    /// Direct collaborators not in the desired set that were left alone
    /// because the call said [`Unlisted::Keep`].
    pub kept_unlisted: Vec<Collaborator>,
}

impl ApplyReport {
    /// Whether every attempted change went through.
    pub fn is_complete(&self) -> bool {
        !self
            .changes
            .iter()
            .any(|c| matches!(c.outcome, RoleOutcome::Failed(_)))
    }
}

/// Start binding a namespace (§4.1 step 1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BindRequest {
    /// The namespace to bind, `host/owner`.
    pub namespace: Resource,
    /// Single-use nonce the caller generated and stored (with its 15-minute
    /// expiry); the forge will hand it back on the callback.
    pub state: String,
}

impl BindRequest {
    /// Bind `namespace`, with `state` as the nonce.
    pub fn new(namespace: Resource, state: impl Into<String>) -> Self {
        BindRequest {
            namespace,
            state: state.into(),
        }
    }
}

/// Where to send the admin next.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum BindStep {
    /// Open this URL in the admin's browser (App install, OAuth consent).
    Redirect {
        /// The URL.
        url: String,
    },
}

/// The forge's redirect back to the bridge after a bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct BindCallback {
    /// The callback's query parameters, as received.
    pub params: BTreeMap<String, String>,
    /// The nonce the caller issued for this bind, looked up from its store.
    /// The adapter compares it in constant time; the caller consumes it
    /// whatever the outcome, so it is single-use.
    pub expected_state: String,
    /// The namespace the bind was started for. An install on any other owner
    /// is refused.
    pub expected_namespace: Resource,
}

impl BindCallback {
    /// A callback for `expected_namespace`, with the issued nonce.
    pub fn new(
        params: BTreeMap<String, String>,
        expected_state: impl Into<String>,
        expected_namespace: Resource,
    ) -> Self {
        BindCallback {
            params,
            expected_state: expected_state.into(),
            expected_namespace,
        }
    }
}

/// A completed bind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct NamespaceBinding {
    /// The namespace, with owner id, kind and installation filled in.
    pub namespace: Namespace,
    /// Permissions the adapter needs that the installation does not grant
    /// (an owner who declined an upgrade). Empty when fully capable.
    pub missing_permissions: Vec<String>,
}

impl NamespaceBinding {
    /// A binding, with the permissions the installation lacks.
    pub fn new(namespace: Namespace, missing_permissions: Vec<String>) -> Self {
        NamespaceBinding {
            namespace,
            missing_permissions,
        }
    }
}

/// Where a member goes to link their account.
///
/// `Debug` is hand-written: `device_code` redeems the member's authorisation
/// once they approve, so it must not reach a log.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum LinkStep {
    /// OAuth device flow: show `user_code` and `verification_uri`; the
    /// bridge polls with `device_code`.
    DeviceCode {
        /// Opaque handle the bridge polls with. Keep it server-side: it is
        /// what redeems the member's authorisation.
        device_code: String,
        /// Short code the member types in.
        user_code: String,
        /// Where they type it.
        verification_uri: String,
        /// Seconds until the codes expire.
        expires_in: u64,
        /// Minimum seconds between polls.
        interval: u64,
    },
    /// Open this URL (authorisation-code flows).
    Redirect {
        /// The URL.
        url: String,
    },
}

impl fmt::Debug for LinkStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkStep::DeviceCode {
                user_code,
                verification_uri,
                expires_in,
                interval,
                ..
            } => f
                .debug_struct("DeviceCode")
                .field("device_code", &"<redacted>")
                .field("user_code", user_code)
                .field("verification_uri", verification_uri)
                .field("expires_in", expires_in)
                .field("interval", interval)
                .finish(),
            LinkStep::Redirect { url } => f.debug_struct("Redirect").field("url", url).finish(),
        }
    }
}

/// Completion input for a link. `Debug` redacts the device code, as for
/// [`LinkStep`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
#[non_exhaustive]
pub enum LinkCallback {
    /// Poll a device flow to completion.
    DeviceCode {
        /// From [`LinkStep::DeviceCode`].
        device_code: String,
        /// From [`LinkStep::DeviceCode`].
        interval: u64,
        /// From [`LinkStep::DeviceCode`]; polling stops at this deadline.
        expires_in: u64,
    },
    /// An authorisation-code redirect.
    Redirect {
        /// Query parameters received.
        params: BTreeMap<String, String>,
    },
}

impl fmt::Debug for LinkCallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkCallback::DeviceCode {
                interval,
                expires_in,
                ..
            } => f
                .debug_struct("DeviceCode")
                .field("device_code", &"<redacted>")
                .field("interval", interval)
                .field("expires_in", expires_in)
                .finish(),
            LinkCallback::Redirect { params } => f
                .debug_struct("Redirect")
                .field("params", &params.keys().collect::<Vec<_>>())
                .finish(),
        }
    }
}

impl LinkCallback {
    /// The callback that polls the device flow `step` started. `None` for a
    /// step that is not a device flow.
    pub fn from_device_step(step: &LinkStep) -> Option<LinkCallback> {
        match step {
            LinkStep::DeviceCode {
                device_code,
                interval,
                expires_in,
                ..
            } => Some(LinkCallback::DeviceCode {
                device_code: device_code.clone(),
                interval: *interval,
                expires_in: *expires_in,
            }),
            LinkStep::Redirect { .. } => None,
        }
    }
}
