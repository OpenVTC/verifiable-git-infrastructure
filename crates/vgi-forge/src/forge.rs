//! The [`Forge`] trait (§5.8).

use async_trait::async_trait;
use http::HeaderMap;

use crate::bootstrap::{BootstrapStep, StepOutcome, VgiConfig};
use crate::error::{ForgeError, Result};
use crate::event::{Drift, ForgeEvent, default_diff};
use crate::model::{
    ApplyReport, BindCallback, BindRequest, BindStep, Capabilities, ForgeAccount, ForgeKind,
    LinkCallback, LinkStep, Namespace, NamespaceBinding, Projection, RepoSpec, RepoState,
    RoleAssignment, Unlisted,
};
use crate::resource::Resource;
use crate::rights::{EffectiveRights, ForgeRole, RoleMap, collapse_to_ladder};

/// One forge implementation. Stateless apart from its credentials and the
/// namespaces it has been told about; the core owns all desired state and
/// hands the adapter a plan.
///
/// Object-safe (through `async-trait`) so a bridge can hold one
/// `Box<dyn Forge>` per forge host and dispatch on a resource's host. Methods
/// with a sensible forge-neutral answer have a default; an adapter overrides
/// only what its forge does differently.
#[async_trait]
pub trait Forge: Send + Sync {
    /// Which forge software this is.
    fn kind(&self) -> ForgeKind;

    /// The forge host this adapter serves (`github.com`, a GHES host,
    /// `codeberg.org`). Every resource it accepts starts with it; a
    /// resource on another host is refused rather than sent to the wrong
    /// forge.
    fn host(&self) -> &str;

    /// What this forge, and this namespace on it, can do. The core and the
    /// UX branch on this, never on [`Forge::kind`].
    fn capabilities(&self, ns: &Namespace) -> Capabilities;

    // ── identity and binding ─────────────────────────────────────────────

    /// Start binding a namespace: where to send the admin.
    async fn begin_bind(&self, req: BindRequest) -> Result<BindStep>;

    /// Finish a bind from the forge's callback. Validates the state nonce and
    /// that the credential landed on the expected owner.
    async fn complete_bind(&self, cb: BindCallback) -> Result<NamespaceBinding>;

    /// Start linking a member's forge account. `member` is their DID, for
    /// the adapter's audit trail; nothing forge-side sees it.
    async fn begin_account_link(&self, member: &str) -> Result<LinkStep>;

    /// Finish linking: the account's numeric id and current login.
    async fn complete_account_link(&self, cb: LinkCallback) -> Result<ForgeAccount>;

    // ── resources ────────────────────────────────────────────────────────

    /// Canonical form of a forge path. The default applies the
    /// `owner[/repo]` grammar GitHub and Forgejo share and refuses a
    /// resource on another host.
    fn normalize(&self, raw: &str) -> Result<Resource> {
        let resource = Resource::parse_owner_repo(raw)?;
        if resource.host() != self.host() {
            return Err(ForgeError::WrongResource {
                resource: resource.to_string(),
                expected: format!("a resource on `{}`", self.host()),
            });
        }
        Ok(resource)
    }

    /// Observe a repository's current state.
    async fn inspect(&self, repo: &Resource) -> Result<RepoState>;

    // ── repo lifecycle ───────────────────────────────────────────────────

    /// Create a repository. Refuses one that already exists with
    /// [`ForgeError::AlreadyExists`] — adopting it is a separate, elevated
    /// decision (§5.6), not something a retry should do silently.
    async fn create_repo(&self, spec: &RepoSpec) -> Result<RepoState>;

    /// Archive a repository. Idempotent.
    async fn archive_repo(&self, repo: &Resource) -> Result<()>;

    // ── projection ───────────────────────────────────────────────────────

    /// Rights → this forge's role for one person on one repository in `ns`.
    /// The default asks `map` for a role and rounds it down onto the
    /// namespace's ladder.
    fn map_role(&self, ns: &Namespace, rights: EffectiveRights, map: &RoleMap) -> ForgeRole {
        collapse_to_ladder(map.requested(rights), &self.capabilities(ns).role_levels)
    }

    /// Converge people's direct roles on a repository to `desired`.
    /// Collaborators `desired` does not mention are handled per `unlisted`.
    async fn apply_roles(
        &self,
        repo: &Resource,
        desired: &[RoleAssignment],
        unlisted: Unlisted,
    ) -> Result<ApplyReport>;

    /// Whether the account with forge id `account` must never be taken off a
    /// repository in `ns`, whatever a job asks: the namespace's owner (on a
    /// personal account, the implicit admin of every repository in it) and
    /// the adapter's own automation identity (a Forgejo bot, a GitHub App's
    /// bot user), without which nothing the bridge does would keep working.
    ///
    /// Matched by numeric id, never by login. The default protects the
    /// owner; an adapter that knows its automation account's id adds it.
    fn is_protected_account(&self, ns: &Namespace, account: u64) -> bool {
        ns.owner_id == Some(account)
    }

    /// The steps that turn commit trust on for this forge's CI.
    fn bootstrap_plan(&self, repo: &RepoSpec, cfg: &VgiConfig) -> Result<Vec<BootstrapStep>>;

    /// Run one step, check-then-apply.
    async fn run_step(&self, repo: &Resource, step: &BootstrapStep) -> Result<StepOutcome>;

    // ── events and drift ─────────────────────────────────────────────────

    /// Verify and translate a webhook. `Ok(None)` for a verified delivery
    /// the core has no use for; `Err` for one that failed verification —
    /// which must not be acted on.
    fn parse_event(&self, headers: &HeaderMap, body: &[u8]) -> Result<Option<ForgeEvent>>;

    /// Compare observed state with the projection.
    fn diff(&self, observed: &RepoState, desired: &Projection) -> Vec<Drift> {
        default_diff(observed, desired)
    }
}
