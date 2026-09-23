//! Lifecycle hooks (§5.8, layer 2).
//!
//! The core calls a [`ForgeHooks`] implementation around each operation. A
//! hook does not act on the forge itself: it returns a decision, and a
//! [`HookDecision::Modify`] hands the core a changed plan that the core then
//! runs through the [`crate::Forge`] methods. Keeping every forge write on
//! that one path is what keeps it audited and retryable — which is also why
//! the hooks are synchronous: they compute, they do not call out.

use crate::bootstrap::{BootstrapStep, StepOutcome};
use crate::event::{Drift, ForgeEvent};
use crate::model::{RepoSpec, RepoState, RoleAssignment};
use crate::resource::Resource;

/// What a hook wants the core to do.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum HookDecision<P> {
    /// Proceed as planned.
    Continue,
    /// Proceed with this plan instead.
    Modify(P),
    /// Stop; the reason is shown and audited.
    Abort(String),
}

/// Optional per-adapter hooks. Every method defaults to
/// [`HookDecision::Continue`]; an adapter overrides only what its forge does
/// differently.
pub trait ForgeHooks: Send + Sync {
    /// Before a repository is created. `Modify` replaces the spec.
    fn before_create(&self, _spec: &RepoSpec) -> HookDecision<RepoSpec> {
        HookDecision::Continue
    }

    /// After a repository is created. `Modify` adds steps for the core to
    /// run before the bootstrap plan (Forgejo sets fast-forward-only merges
    /// here).
    fn after_create(&self, _state: &RepoState) -> HookDecision<Vec<BootstrapStep>> {
        HookDecision::Continue
    }

    /// Before roles are converged. `Modify` replaces the desired set.
    fn before_apply_roles(
        &self,
        _repo: &Resource,
        _desired: &[RoleAssignment],
    ) -> HookDecision<Vec<RoleAssignment>> {
        HookDecision::Continue
    }

    /// After a bootstrap plan ran. `Modify` adds follow-up steps.
    fn after_bootstrap(
        &self,
        _repo: &Resource,
        _outcomes: &[(String, StepOutcome)],
    ) -> HookDecision<Vec<BootstrapStep>> {
        HookDecision::Continue
    }

    /// On a verified event. `Modify` replaces it; `Abort` drops it.
    fn on_event(&self, _event: &ForgeEvent) -> HookDecision<ForgeEvent> {
        HookDecision::Continue
    }

    /// On drift found for a repository. `Modify` replaces the list (to
    /// suppress a forge's known false positives).
    fn on_drift(&self, _repo: &Resource, _drift: &[Drift]) -> HookDecision<Vec<Drift>> {
        HookDecision::Continue
    }
}

/// Hooks that do nothing.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl ForgeHooks for NoHooks {}
