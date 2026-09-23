//! Forge-neutral adapter layer for VGI git namespaces.
//!
//! A VTC governs who may create, own, maintain and commit to repositories in
//! a namespace; the forge (GitHub, Forgejo, …) is where that is *enforced*.
//! This crate is the seam between the two: the [`Forge`] trait an adapter
//! implements, the [`ForgeHooks`] it may add, and the data both sides
//! exchange — [`Resource`]s, [`EffectiveRights`], [`Capabilities`],
//! bootstrap plans, [`ForgeEvent`]s and [`Drift`].
//!
//! Nothing here talks to a forge. Adapters live in their own crates
//! (`vgi-forge-github` first), so the core compiles without any forge's
//! HTTP stack, and a forge's limitations reach the core only as
//! [`Capabilities`] — never as a branch on which forge it is.
//!
//! Three rules hold across every adapter:
//!
//! - **Resources are forge-qualified and normalised** by the one grammar in
//!   [`vgi_core::resource`], so a grant, a registry tuple and a verify-trust
//!   query name a repository with the same bytes.
//! - **Roles round down.** A forge with fewer role levels gives less than
//!   the community asked for, never more ([`collapse_to_ladder`]).
//! - **Accounts are numeric ids.** Logins are display-only; a renamed and
//!   re-registered login must never inherit a role.

mod bootstrap;
mod error;
mod event;
mod forge;
mod hooks;
mod model;
mod resource;
mod rights;

pub use bootstrap::{
    BootstrapComponent, BootstrapReport, BootstrapStep, DEFAULT_REQUIRED_CHECK, ExtraFile,
    ProtectionSpec, StepAction, StepOutcome, VgiConfig, run_plan, validate_repo_path,
};
pub use error::{ForgeError, Result};
pub use event::{
    Drift, ForgeEvent, ForgeEventKind, InstallationChange, MemberChange, ProtectionGap,
    default_diff, protection_gaps,
};
pub use forge::Forge;
pub use hooks::{ForgeHooks, HookDecision, NoHooks};
pub use model::{
    ApplyReport, BindCallback, BindRequest, BindStep, Capabilities, Collaborator, ForgeAccount,
    ForgeKind, LinkCallback, LinkMethod, LinkStep, Namespace, NamespaceBinding, NamespaceKind,
    Projection, ProtectionState, RepoSpec, RepoState, RequiredCheckKind, RoleAssignment,
    RoleChange, RoleOutcome, Unlisted, Visibility,
};
pub use resource::{OWNER_REPO_DEPTH, Resource};
pub use rights::{EffectiveRights, ForgeRole, Right, RoleMap, collapse_to_ladder};

// Re-exported so adapters and callers name one `async_trait`.
pub use async_trait::async_trait;
