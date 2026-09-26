//! Running jobs: each kind mapped onto the forge-neutral adapter calls, with
//! the adapter's [`vgi_forge::ForgeHooks`] around each operation.
//!
//! Every job is convergent: the adapter checks the forge and changes only
//! what differs, so a job interrupted by a restart simply runs again.

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::json;
use sha2::{Digest, Sha256};
use vgi_forge::{
    BootstrapStep, Drift, EffectiveRights, ForgeAccount, ForgeError, ForgeRole, HookDecision,
    Namespace, Projection, RepoSpec, RepoState, Resource, RoleAssignment, RoleMap, RoleOutcome,
    StepOutcome, Unlisted,
};

use crate::bridge::Bridge;
use crate::mapping::{self, Report, StepStatus};
use crate::registry::Adapter;
use crate::status::Guard;
use crate::store::{NamespaceRecord, PinRecord, RepoRecord, Table, repo_key};
use crate::wire::job;

/// Run one job to its report.
pub(crate) async fn run(bridge: &Arc<Bridge>, p: &job::Payload) -> Report {
    let mut report = Report::default();
    let ns_id = p.namespace.to_string();
    let ctx = match Ctx::load(bridge, &ns_id) {
        Ok(c) => c,
        Err(msg) => {
            report.fail_with("notCapable", msg);
            return report;
        }
    };
    let repo = p.repo.as_ref().map(|r| Resource::parse(r));
    let repo = match repo.transpose() {
        Ok(r) => r,
        Err(e) => {
            report.fail(&e);
            return report;
        }
    };
    use job::PayloadKind as K;
    match (p.kind, repo) {
        (K::ProjectRoles, Some(repo)) => {
            let roles = p.desired_roles.clone().unwrap_or_default();
            let remove = p.remove_accounts.clone().unwrap_or_default();
            project_roles(bridge, &ctx, &repo, &roles, &remove, &mut report).await;
        }
        (K::CreateRepo, Some(repo)) => create_repo(bridge, &ctx, &repo, p, &mut report).await,
        (K::Bootstrap, Some(repo)) => {
            let only: Option<BTreeSet<String>> = p
                .steps
                .as_ref()
                .map(|s| s.iter().map(|n| n.to_string()).collect());
            bootstrap(bridge, &ctx, &repo, only.as_ref(), &mut report).await;
        }
        (K::Archive, Some(repo)) => archive(bridge, &ctx, &repo, &mut report).await,
        (K::Inspect, Some(repo)) => {
            if let Err(e) = inspect_repo(bridge, &ctx, &repo, true, Some(&mut report)).await {
                report.fail(&e);
            }
        }
        (K::Inspect, None) => sweep(bridge, &ctx, true, &mut report).await,
        (kind, _) => report.fail_with("notCapable", format!("`{kind}` is not run here")),
    }
    report
}

/// A job's namespace, adapter and the adapter's view of the namespace.
pub(crate) struct Ctx {
    pub(crate) ns: NamespaceRecord,
    pub(crate) adapter: Adapter,
    pub(crate) namespace: Namespace,
}

impl Ctx {
    pub(crate) fn load(bridge: &Bridge, ns_id: &str) -> Result<Ctx, String> {
        let ns = bridge
            .bound_namespace(ns_id)
            .map_err(|r| r.0.message.unwrap_or_default())?;
        let adapter = bridge
            .adapters
            .for_resource(&ns.resource)
            .ok_or_else(|| format!("no adapter for `{}`", ns.resource.host()))?;
        let namespace = ns.binding.as_ref().expect("bound").namespace.clone();
        Ok(Ctx {
            ns,
            adapter,
            namespace,
        })
    }

    fn host(&self) -> &str {
        self.ns.resource.host()
    }
}

/// The repository record for `host`/`forge_id`, if the bridge knows it.
fn repo_record(bridge: &Bridge, host: &str, forge_id: u64) -> Option<RepoRecord> {
    bridge
        .store
        .get::<RepoRecord>(Table::Repos, &repo_key(host, forge_id))
        .ok()
        .flatten()
}

/// The record for a repository known by resource only.
pub(crate) fn repo_record_by_resource(bridge: &Bridge, r: &Resource) -> Option<RepoRecord> {
    bridge
        .store
        .list::<RepoRecord>(Table::Repos)
        .ok()?
        .into_iter()
        .map(|(_, rec)| rec)
        .find(|rec| rec.resource == *r)
}

/// The job's desired roles on `repo` as forge roles, under `repo`'s role map
/// (the bridge config's `role_map` layers), and the owners among them.
///
/// A namespace admin gets no forge role (decided 2026-09-25): an entry whose
/// right is `git.ns.admin` (or `git.repo.create`) asks for
/// [`ForgeRole::None`], whatever the map says. An account listed with
/// `None` has **any** direct collaborator role on the repository removed —
/// one given by hand on the forge as much as one the bridge projected —
/// because the adapter converges every listed account to exactly its
/// desired role. (Only unlisted accounts are left alone, `Unlisted::Keep`.)
///
/// `git-ns/bridge/job` 0.4 has the VTC send `git.ns.admin` for a namespace
/// admin with no right of their own on the repository, never the `own` it
/// implies; that is the only version this bridge takes.
fn desired_roles(
    bridge: &Bridge,
    ctx: &Ctx,
    repo: &Resource,
    roles: &[job::DesiredRole],
) -> Result<(Vec<RoleAssignment>, Vec<ForgeAccount>), String> {
    let forge = ctx.adapter.forge();
    let map: RoleMap = bridge.cfg.role_map(repo);
    let mut out = Vec::new();
    let mut owners = Vec::new();
    for r in roles {
        if *r.account.forge != *ctx.host() {
            return Err(format!(
                "`{}`'s account is on `{}`, not `{}`",
                *r.subject,
                *r.account.forge,
                ctx.host()
            ));
        }
        let account = mapping::account(&r.account).map_err(|e| e.to_string())?;
        let right =
            mapping::right(&r.right).ok_or_else(|| format!("unknown right `{}`", r.right))?;
        if right == vgi_forge::Right::RepoOwn {
            owners.push(account.clone());
        }
        let role = forge.map_role(&ctx.namespace, EffectiveRights::from_granted([right]), &map);
        out.push(RoleAssignment::new(account, role));
    }
    Ok((out, owners))
}

/// Accounts a job asks to take off a repository (`removeAccounts`), sorted
/// into those the adapter may remove and those it must never touch.
#[derive(Debug, Default)]
struct Removals {
    /// To remove, by id; the login is the job's, display only.
    remove: Vec<ForgeAccount>,
    /// Refused, with why: the namespace's owner, the bridge's own bot.
    refused: Vec<String>,
}

impl Removals {
    fn sort(ctx: &Ctx, accounts: &[job::ForgeAccount]) -> Result<Removals, String> {
        let mut out = Removals::default();
        for a in accounts {
            let account = mapping::account(a).map_err(|e| e.to_string())?;
            if ctx
                .adapter
                .forge()
                .is_protected_account(&ctx.namespace, account.id)
            {
                out.refused.push(format!(
                    "{} ({}): the namespace's owner and the bridge's own account are never removed",
                    account.login, account.id
                ));
            } else {
                out.remove.push(account);
            }
        }
        Ok(out)
    }
}

/// Converge roles on `repo` to `desired`: people not listed lose a role the
/// bridge projected before; roles it never projected are left and reported
/// as drift (spec: *desiredRoles*) — except the accounts in `removals`,
/// whose direct role goes whatever it is and whoever gave it (job 0.4
/// `removeAccounts`).
#[allow(clippy::too_many_arguments)]
async fn apply_roles(
    bridge: &Bridge,
    ctx: &Ctx,
    repo: &Resource,
    forge_id: Option<u64>,
    desired: Vec<RoleAssignment>,
    owners: Vec<ForgeAccount>,
    removals: Removals,
    report: &mut Report,
) {
    let previous = forge_id
        .and_then(|id| repo_record(bridge, ctx.host(), id))
        .map(|r| r.roles)
        .unwrap_or_default();
    let mut want = desired.clone();
    for p in previous {
        if p.role != ForgeRole::None && !want.iter().any(|w| w.account.id == p.account.id) {
            want.push(RoleAssignment::new(p.account, ForgeRole::None));
        }
    }
    // By id: the adapter reads each one's current login from the forge, so
    // a login renamed since the VTC saw it is still the account removed. An
    // account with no role is already converged.
    for account in &removals.remove {
        let account = account.clone();
        match want.iter_mut().find(|w| w.account.id == account.id) {
            // A formerly projected role, or an account `desiredRoles` lists
            // at `git.ns.admin` (no role already): the only overlap job 0.4
            // allows (checked at admission).
            Some(w) => w.role = ForgeRole::None,
            None => want.push(RoleAssignment::new(account, ForgeRole::None)),
        }
    }
    let want = match ctx.adapter.hooks().before_apply_roles(repo, &want) {
        HookDecision::Modify(w) => w,
        HookDecision::Abort(why) => {
            report.step("roles", StepStatus::Failed, Some(why.clone()));
            report.fail_with("forgeError", why);
            return;
        }
        _ => want,
    };
    match ctx
        .adapter
        .forge()
        .apply_roles(repo, &want, Unlisted::Keep)
        .await
    {
        Ok(r) => {
            let mut failures: Vec<String> = removals
                .refused
                .iter()
                .cloned()
                .chain(r.changes.iter().filter_map(|c| match &c.outcome {
                    RoleOutcome::Failed(m) => Some(format!("{}: {m}", c.account.login)),
                    _ => None,
                }))
                .collect();
            failures.extend(remaining_access(ctx, repo, &removals.remove, &r).await);
            let status = if !failures.is_empty() {
                StepStatus::Failed
            } else if r.changes.is_empty() {
                StepStatus::Unchanged
            } else {
                StepStatus::Applied
            };
            report.step(
                "roles",
                status,
                (!failures.is_empty()).then(|| failures.join("; ")),
            );
            // The map these roles were projected under, for the role-map
            // report's `stale` — only once every role took: a partly failed
            // projection leaves the repository stale, so it is re-projected.
            // A map that rounds unordered is not recorded either (it is
            // logged, and never reported).
            let applied_map = if failures.is_empty() {
                crate::rolemap::effective(ctx, &bridge.cfg.role_map(repo))
            } else {
                None
            };
            if let Some(id) = forge_id {
                let _ = bridge.store.update::<RepoRecord, _>(
                    Table::Repos,
                    &repo_key(ctx.host(), id),
                    |rec| {
                        let mut rec = rec.unwrap_or_else(|| {
                            RepoRecord::new(ctx.ns.id.clone(), repo.clone(), id)
                        });
                        rec.roles = desired
                            .iter()
                            .filter(|d| d.role != ForgeRole::None)
                            .cloned()
                            .collect();
                        rec.roles_known = true;
                        rec.owners = owners.clone();
                        if applied_map.is_some() {
                            rec.role_map = applied_map;
                        }
                        Ok((Some(rec), ()))
                    },
                );
            }
        }
        Err(e) => {
            report.step("roles", StepStatus::Failed, Some(e.to_string()));
            report.fail(&e);
        }
    }
}

/// Access the accounts `removeAccounts` named still have to `repo` once
/// their direct role is gone — through a team, as an organisation owner or
/// member — one line each, for the failed `roles` step (job 0.4: the bridge
/// reports it and never changes the team or the organisation). An account
/// whose removal itself failed is already reported.
async fn remaining_access(
    ctx: &Ctx,
    repo: &Resource,
    removed: &[ForgeAccount],
    applied: &vgi_forge::ApplyReport,
) -> Vec<String> {
    let mut out = Vec::new();
    for account in removed {
        let failed = applied
            .changes
            .iter()
            .any(|c| c.account.id == account.id && matches!(c.outcome, RoleOutcome::Failed(_)));
        if failed {
            continue;
        }
        match ctx.adapter.forge().indirect_access(repo, account).await {
            Ok(None) => {}
            Ok(Some(access)) => out.push(format!(
                "{} ({}): no direct role any more, but still {access}; the bridge does not \
                 change teams or the organisation",
                account.login, account.id
            )),
            Err(e) => out.push(format!(
                "{} ({}): the direct role is gone, but whether access remains through a team or \
                 the organisation could not be read: {e}",
                account.login, account.id
            )),
        }
    }
    out
}

async fn project_roles(
    bridge: &Bridge,
    ctx: &Ctx,
    repo: &Resource,
    roles: &[job::DesiredRole],
    remove: &[job::ForgeAccount],
    report: &mut Report,
) {
    let (desired, owners) = match desired_roles(bridge, ctx, repo, roles) {
        Ok(x) => x,
        Err(m) => {
            report.fail_with("forgeError", m);
            return;
        }
    };
    let removals = match Removals::sort(ctx, remove) {
        Ok(r) => r,
        Err(m) => {
            report.fail_with("forgeError", m);
            return;
        }
    };
    let forge_id = match forge_id_of(bridge, ctx, repo).await {
        Ok(id) => id,
        Err(e) => {
            report.fail(&e);
            return;
        }
    };
    report.repo = Some((repo.clone(), forge_id));
    apply_roles(
        bridge,
        ctx,
        repo,
        Some(forge_id),
        desired,
        owners,
        removals,
        report,
    )
    .await;
}

/// The repository's forge id: from the record, or by inspecting it.
async fn forge_id_of(bridge: &Bridge, ctx: &Ctx, repo: &Resource) -> Result<u64, ForgeError> {
    if let Some(r) = repo_record_by_resource(bridge, repo) {
        return Ok(r.forge_id);
    }
    Ok(ctx.adapter.forge().inspect(repo).await?.forge_id)
}

async fn create_repo(
    bridge: &Arc<Bridge>,
    ctx: &Ctx,
    repo: &Resource,
    p: &job::Payload,
    report: &mut Report,
) {
    let job_spec = p.spec.as_ref().expect("checked by kind");
    let (desired, owners) =
        match desired_roles(bridge, ctx, repo, p.desired_roles.as_deref().unwrap_or(&[])) {
            Ok(x) => x,
            Err(m) => {
                report.fail_with("forgeError", m);
                return;
            }
        };
    let mut spec =
        RepoSpec::new(repo.clone()).with_visibility(mapping::visibility(&job_spec.visibility));
    if let Some(d) = &job_spec.description {
        spec = spec.with_description(d.to_string());
    }
    for o in &owners {
        spec = spec.with_owner(o.clone());
    }
    let spec = match ctx.adapter.hooks().before_create(&spec) {
        HookDecision::Modify(s) => s,
        HookDecision::Abort(why) => {
            report.step("create", StepStatus::Failed, Some(why.clone()));
            report.fail_with("forgeError", why);
            return;
        }
        _ => spec,
    };

    let forge = ctx.adapter.forge();
    let state = match forge.create_repo(&spec).await {
        Ok(state) => {
            report.step("create", StepStatus::Applied, None);
            state
        }
        // Our own earlier attempt (a retry after a crash): carry on.
        Err(ForgeError::AlreadyExists {
            forge_id: Some(id), ..
        }) if repo_record(bridge, ctx.host(), id).is_some_and(|r| r.namespace == ctx.ns.id) => {
            match forge.inspect(repo).await {
                Ok(s) => {
                    report.step("create", StepStatus::Unchanged, None);
                    s
                }
                Err(e) => {
                    report.step("create", StepStatus::Failed, Some(e.to_string()));
                    report.fail(&e);
                    return;
                }
            }
        }
        Err(e) => {
            report.step("create", StepStatus::Failed, Some(e.to_string()));
            report.fail(&e);
            return;
        }
    };
    report.repo = Some((state.resource.clone(), state.forge_id));
    manage(bridge, ctx, &state, &owners);

    let mut extra = Vec::new();
    match ctx.adapter.hooks().after_create(&state) {
        HookDecision::Modify(steps) => extra = steps,
        HookDecision::Abort(why) => {
            report.fail_with("forgeError", why);
            return;
        }
        _ => {}
    }
    if !run_bootstrap(bridge, ctx, &spec, extra, None, report).await {
        report.step("roles", StepStatus::Skipped, None);
        refresh_guard(bridge, ctx, report).await;
        return;
    }
    apply_roles(
        bridge,
        ctx,
        &state.resource,
        Some(state.forge_id),
        desired,
        owners,
        Removals::default(),
        report,
    )
    .await;
    refresh_guard(bridge, ctx, report).await;
}

/// Record a repository as managed, in the store and (GitHub) the adapter's
/// managed set — which the org ruleset lists.
fn manage(bridge: &Bridge, ctx: &Ctx, state: &RepoState, owners: &[ForgeAccount]) {
    let key = repo_key(ctx.host(), state.forge_id);
    let _ = bridge
        .store
        .update::<RepoRecord, _>(Table::Repos, &key, |rec| {
            let mut rec = rec.unwrap_or_else(|| {
                RepoRecord::new(ctx.ns.id.clone(), state.resource.clone(), state.forge_id)
            });
            rec.resource = state.resource.clone();
            if !owners.is_empty() {
                rec.owners = owners.to_vec();
            }
            rec.archived = false;
            Ok((Some(rec), ()))
        });
    let managed = bridge
        .store
        .update::<NamespaceRecord, _>(Table::Namespaces, &ctx.ns.id, |ns| {
            let mut ns = ns.expect("bound namespace");
            ns.managed.insert(state.forge_id);
            let m = ns.managed.clone();
            Ok((Some(ns), m))
        });
    #[cfg(feature = "forge-github")]
    if let (Ok(m), Some(g)) = (managed, ctx.adapter.github()) {
        g.set_managed_repositories(&ctx.ns.resource, m);
    }
    #[cfg(not(feature = "forge-github"))]
    let _ = managed;
}

/// After a plan ran on GitHub: persist the pin and managed set the adapter
/// now holds, so a restart hands back exactly these.
fn persist_adapter_state(bridge: &Bridge, ctx: &Ctx) {
    #[cfg(feature = "forge-github")]
    if let Some(g) = ctx.adapter.github() {
        let pin = g.required_workflow_pin(&ctx.ns.resource);
        let managed = g.managed_repositories(&ctx.ns.resource);
        let _ = bridge
            .store
            .update::<NamespaceRecord, _>(Table::Namespaces, &ctx.ns.id, |ns| {
                let mut ns = ns.expect("bound namespace");
                if let Some(p) = pin {
                    ns.pin = Some(PinRecord {
                        repository_id: p.repository_id,
                        sha: p.sha,
                        check: p.check,
                    });
                }
                if let Some(m) = managed {
                    ns.managed = m;
                }
                Ok((Some(ns), ()))
            });
    }
    #[cfg(not(feature = "forge-github"))]
    let _ = (bridge, ctx);
}

/// A capability the adapter found changed mid-plan: persist it, tell the
/// adapter, and have the caller plan again.
fn capability_changed(bridge: &Bridge, ctx: &Ctx, capability: &str, available: bool) {
    let _ = bridge
        .store
        .update::<NamespaceRecord, _>(Table::Namespaces, &ctx.ns.id, |ns| {
            let mut ns = ns.expect("bound namespace");
            if capability == "required_workflow" {
                ns.required_workflow = Some(available);
                if let Some(c) = ns.capabilities.as_mut() {
                    c.required_workflow = available;
                }
            }
            Ok((Some(ns), ()))
        });
    #[cfg(feature = "forge-github")]
    if capability == "required_workflow"
        && let Some(g) = ctx.adapter.github()
    {
        g.set_required_workflow(&ctx.ns.resource, available);
    }
}

/// Plan and run the bootstrap (after `extra` steps from a hook), keeping
/// only the neutral step names in `only` when given. Re-plans once if the
/// adapter reports a capability change. `true` if every step went through.
async fn run_bootstrap(
    bridge: &Bridge,
    ctx: &Ctx,
    spec: &RepoSpec,
    extra: Vec<BootstrapStep>,
    only: Option<&BTreeSet<String>>,
    report: &mut Report,
) -> bool {
    let forge = ctx.adapter.forge();
    let Some(vgi) = bridge.adapters.vgi(ctx.host()) else {
        report.fail_with("forgeError", "no bootstrap configuration for this forge");
        return false;
    };
    let repo = &spec.resource;
    let reported_before = report.steps.len();
    for attempt in 0..2 {
        let plan = match forge.bootstrap_plan(spec, &vgi) {
            Ok(p) => p,
            Err(e) => {
                report.fail(&e);
                return false;
            }
        };
        let steps: Vec<BootstrapStep> = extra
            .iter()
            .cloned()
            .chain(plan)
            .filter(|s| only.is_none_or(|o| o.contains(&mapping::step_name(&s.id, s.component))))
            .collect();
        let mut done: Vec<(String, StepOutcome)> = Vec::new();
        let mut failed = false;
        let mut replan = false;
        for step in &steps {
            let name = mapping::step_name(&step.id, step.component);
            if failed {
                report.step(name, StepStatus::Skipped, None);
                continue;
            }
            match forge.run_step(repo, step).await {
                Ok(o) => {
                    report.step(name, StepStatus::of(o), None);
                    done.push((step.id.clone(), o));
                }
                Err(ForgeError::CapabilityChanged {
                    capability,
                    available,
                    reason,
                    ..
                }) if attempt == 0 => {
                    tracing::info!(%capability, available, %reason, "capability changed; planning again");
                    capability_changed(bridge, ctx, &capability, available);
                    replan = true;
                    break;
                }
                Err(e) => {
                    report.step(name, StepStatus::Failed, Some(e.to_string()));
                    report.fail(&e);
                    failed = true;
                }
            }
        }
        if replan {
            // The steps already reported are re-run by the new plan.
            report.steps.truncate(reported_before);
            continue;
        }
        persist_adapter_state(bridge, ctx);
        if failed {
            return false;
        }
        if let HookDecision::Modify(more) = ctx.adapter.hooks().after_bootstrap(repo, &done) {
            for step in &more {
                let name = mapping::step_name(&step.id, step.component);
                match forge.run_step(repo, step).await {
                    Ok(o) => report.step(name, StepStatus::of(o), None),
                    Err(e) => {
                        report.step(name, StepStatus::Failed, Some(e.to_string()));
                        report.fail(&e);
                        return false;
                    }
                }
            }
        }
        let _ = bridge.store.update::<RepoRecord, _>(
            Table::Repos,
            &repo_key(ctx.host(), report.repo.as_ref().map(|r| r.1).unwrap_or(0)),
            |rec| {
                Ok((
                    rec.map(|mut r| {
                        r.required_check = Some(vgi.required_check.clone());
                        r
                    }),
                    (),
                ))
            },
        );
        return true;
    }
    report.fail_with("forgeError", "the adapter kept changing its capabilities");
    false
}

async fn bootstrap(
    bridge: &Bridge,
    ctx: &Ctx,
    repo: &Resource,
    only: Option<&BTreeSet<String>>,
    report: &mut Report,
) {
    let state = match ctx.adapter.forge().inspect(repo).await {
        Ok(s) => s,
        Err(e) => {
            report.fail(&e);
            return;
        }
    };
    report.repo = Some((state.resource.clone(), state.forge_id));
    let owners = repo_record(bridge, ctx.host(), state.forge_id)
        .map(|r| r.owners)
        .unwrap_or_default();
    manage(bridge, ctx, &state, &owners);
    let mut spec = RepoSpec::new(state.resource.clone()).with_visibility(state.visibility);
    for o in owners {
        spec = spec.with_owner(o);
    }
    run_bootstrap(bridge, ctx, &spec, Vec::new(), only, report).await;
    refresh_guard(bridge, ctx, report).await;
}

async fn archive(bridge: &Bridge, ctx: &Ctx, repo: &Resource, report: &mut Report) {
    let forge = ctx.adapter.forge();
    let state = match forge.inspect(repo).await {
        Ok(s) => s,
        Err(e) => {
            report.step("archive", StepStatus::Failed, Some(e.to_string()));
            report.fail(&e);
            return;
        }
    };
    report.repo = Some((state.resource.clone(), state.forge_id));
    match forge.archive_repo(repo).await {
        Ok(()) => {
            report.step(
                "archive",
                if state.archived {
                    StepStatus::Unchanged
                } else {
                    StepStatus::Applied
                },
                None,
            );
            let _ = bridge.store.update::<RepoRecord, _>(
                Table::Repos,
                &repo_key(ctx.host(), state.forge_id),
                |rec| {
                    Ok((
                        rec.map(|mut r| {
                            r.archived = true;
                            r
                        }),
                        (),
                    ))
                },
            );
            // An archived repository takes no pull requests: it leaves the
            // managed set (and the org ruleset with it).
            let _ =
                bridge
                    .store
                    .update::<NamespaceRecord, _>(Table::Namespaces, &ctx.ns.id, |ns| {
                        let mut ns = ns.expect("bound namespace");
                        ns.managed.remove(&state.forge_id);
                        Ok((Some(ns), ()))
                    });
            persist_adapter_state(bridge, ctx);
        }
        Err(e) => {
            report.step("archive", StepStatus::Failed, Some(e.to_string()));
            report.fail(&e);
        }
    }
}

/// The projection the bridge holds for a repository.
fn projection(
    bridge: &Bridge,
    ctx: &Ctx,
    state: &RepoState,
    rec: Option<&RepoRecord>,
) -> Projection {
    let mut p = Projection::new(
        rec.map(|r| r.resource.clone())
            .unwrap_or_else(|| state.resource.clone()),
    );
    if let Some(r) = rec {
        p.forge_id = Some(r.forge_id);
        p.roles = r.roles.clone();
        p.owners = r.owners.clone();
        p.archived = r.archived;
        p.required_check = r
            .required_check
            .clone()
            .or_else(|| bridge.adapters.vgi(ctx.host()).map(|v| v.required_check));
    }
    p
}

/// Inspect one repository, compare it with the projection, and report the
/// drift as a `protectionChanged` event (always when `always`, else only
/// when it differs from what was last reported). A rename found here is
/// reported as `repoRenamed` first.
pub(crate) async fn inspect_repo(
    bridge: &Bridge,
    ctx: &Ctx,
    repo: &Resource,
    always: bool,
    mut report: Option<&mut Report>,
) -> Result<(), ForgeError> {
    let state = ctx.adapter.forge().inspect(repo).await?;
    let rec = repo_record(bridge, ctx.host(), state.forge_id);
    if !ctx.ns.resource.contains(&state.resource) {
        // The forge answered for the old name with a repository now under
        // another owner: it was transferred without an event reaching the
        // bridge. That is a transfer, never a rename, which would name a
        // repository outside the namespace (event 0.2).
        if let Some(r) = &rec
            && ctx.ns.resource.contains(&r.resource)
        {
            crate::events::transferred_out(
                bridge,
                &ctx.ns,
                &r.resource,
                &state.resource,
                state.forge_id,
            )
            .await;
        } else {
            tracing::warn!(
                asked = %repo, found = %state.resource,
                "the forge answered with a repository outside the namespace; nothing reported"
            );
        }
        return Ok(());
    }
    if rec.is_none()
        && crate::events::detach_reused_name(bridge, &ctx.ns.id, &state.resource, state.forge_id)
    {
        // A repository the bridge does not manage, at a name it governed
        // under another forge id: the name was reused without an event.
        // The old one is detached; the newcomer is reported unmanaged.
        crate::events::report_unmanaged(bridge, &ctx.ns, &state.resource, state.forge_id).await;
    }
    if let Some(r) = &rec
        && r.resource != state.resource
    {
        // Renamed onto a name still recorded for another repository: that
        // one is gone, and nothing of it passes on.
        crate::events::detach_reused_name(bridge, &ctx.ns.id, &state.resource, state.forge_id);
        let ev = json!({
            "type": "repoRenamed",
            "forgeId": state.forge_id.to_string(),
            "from": r.resource.as_str(),
            "to": state.resource.as_str(),
        });
        if let Err(e) = bridge.send_event(&ctx.ns.id, ev, None).await {
            tracing::error!(error = %e, "could not report a rename");
        }
        let _ = bridge
            .store
            .update::<RepoRecord, _>(Table::Repos, &r.key(), |x| {
                Ok((
                    x.map(|mut x| {
                        x.resource = state.resource.clone();
                        x
                    }),
                    (),
                ))
            });
    }
    let rec = repo_record(bridge, ctx.host(), state.forge_id);
    let proj = projection(bridge, ctx, &state, rec.as_ref());
    let mut proj_now = proj.clone();
    proj_now.resource = state.resource.clone();
    let mut drift = ctx.adapter.forge().diff(&state, &proj_now);
    if !rec.as_ref().is_some_and(|r| r.roles_known) {
        // No projection of roles yet: every collaborator would look
        // unexpected.
        drift.retain(|d| {
            !matches!(
                d,
                Drift::UnexpectedRole { .. }
                    | Drift::MissingRole { .. }
                    | Drift::RoleMismatch { .. }
            )
        });
    }
    if let HookDecision::Modify(d) = ctx.adapter.hooks().on_drift(&state.resource, &drift) {
        drift = d;
    }
    let enforced = drift.iter().all(|d| match d {
        Drift::ProtectionWeakened { gaps } => mapping::check_enforced(gaps),
        _ => true,
    }) && proj.required_check.is_some();
    let items = mapping::drift_items(ctx.host(), &state.resource, &drift);
    // The guard in force, for the status report; a change of guard alone is
    // news too.
    let guard = Guard::in_force(&state, &drift).as_str();
    if let Some(r) = &rec {
        record_guard(bridge, &r.key(), guard);
    }
    let digest = hex::encode(Sha256::digest(
        serde_json::to_vec(&json!([items, guard])).unwrap_or_default(),
    ));
    let changed = rec.as_ref().and_then(|r| r.last_drift.as_deref()) != Some(digest.as_str());
    if let Some(report) = report.as_deref_mut() {
        report.repo = Some((state.resource.clone(), state.forge_id));
    }
    // Only a repository the bridge manages has a check to be in place; an
    // unmanaged one is reported as it is, with nothing expected of it.
    if let (Some(report), true) = (report, rec.is_some()) {
        report.step(
            "requiredCheck",
            if enforced {
                StepStatus::Unchanged
            } else {
                StepStatus::Failed
            },
            (!enforced).then(|| "the forge does not require the verify-trust check".to_string()),
        );
    }
    if rec.is_some() && (always || changed) {
        let ev = json!({
            "type": "protectionChanged",
            "forgeId": state.forge_id.to_string(),
            "resource": state.resource.as_str(),
            "requiredCheck": enforced,
        });
        if let Err(e) = bridge.send_event(&ctx.ns.id, ev, Some(items)).await {
            tracing::error!(error = %e, "could not report drift");
        } else if let Some(r) = &rec {
            let _ = bridge
                .store
                .update::<RepoRecord, _>(Table::Repos, &r.key(), |x| {
                    Ok((
                        x.map(|mut x| {
                            x.last_drift = Some(digest.clone());
                            x
                        }),
                        (),
                    ))
                });
        }
    }
    Ok(())
}

/// Record the guard found in force on the repository stored under `key`.
fn record_guard(bridge: &Bridge, key: &str, guard: &str) {
    let _ = bridge
        .store
        .update::<RepoRecord, _>(Table::Repos, key, |x| {
            Ok((
                x.map(|mut x| {
                    x.guard = Some(guard.to_string());
                    x
                }),
                (),
            ))
        });
}

/// After a create or bootstrap: read which guard the repository ended up
/// with, for the result's status report. Best effort — a read that fails
/// leaves what was recorded before.
async fn refresh_guard(bridge: &Bridge, ctx: &Ctx, report: &Report) {
    let Some((resource, forge_id)) = &report.repo else {
        return;
    };
    let Some(rec) = repo_record(bridge, ctx.host(), *forge_id) else {
        return;
    };
    let state = match ctx.adapter.forge().inspect(resource).await {
        Ok(s) => s,
        Err(e) => {
            tracing::info!(repo = %resource, error = %e, "could not read the guard in force");
            return;
        }
    };
    let mut proj = projection(bridge, ctx, &state, Some(&rec));
    proj.resource = state.resource.clone();
    let drift = ctx.adapter.forge().diff(&state, &proj);
    record_guard(bridge, &rec.key(), Guard::in_force(&state, &drift).as_str());
}

/// Inspect every repository the bridge manages in the namespace.
pub(crate) async fn sweep(bridge: &Bridge, ctx: &Ctx, always: bool, report: &mut Report) {
    let repos: Vec<RepoRecord> = bridge
        .store
        .list::<RepoRecord>(Table::Repos)
        .unwrap_or_default()
        .into_iter()
        .map(|(_, r)| r)
        .filter(|r| r.namespace == ctx.ns.id && !r.archived)
        .collect();
    let mut failures = Vec::new();
    for r in repos {
        if let Err(e) = inspect_repo(bridge, ctx, &r.resource, always, None).await {
            failures.push(format!("{}: {e}", r.resource));
        }
    }
    if !failures.is_empty() {
        report.fail_with("forgeError", failures.join("; "));
    }
}

/// The scheduled sweep for forges that push no events (`webhooks: false`).
pub(crate) async fn sweep_without_webhooks(bridge: &Arc<Bridge>) {
    let Ok(namespaces) = bridge.store.list::<NamespaceRecord>(Table::Namespaces) else {
        return;
    };
    for (id, _) in namespaces {
        let Ok(ctx) = Ctx::load(bridge, &id) else {
            continue;
        };
        if ctx.adapter.forge().capabilities(&ctx.namespace).webhooks {
            continue;
        }
        let lock = bridge.ns_lock(&id);
        let _g = lock.lock().await;
        let mut report = Report::default();
        sweep(bridge, &ctx, false, &mut report).await;
        if let Some((_, m)) = report.error {
            tracing::warn!(namespace = %id, "drift sweep: {m}");
        }
    }
}
