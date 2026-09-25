# vgi-forge

Forge-neutral adapter layer for [Verifiable Git Infrastructure (VGI)][vgi]
git namespaces — the seam between a community's VTC, which decides who may
create, own, maintain and commit to repositories, and the forge (GitHub,
Forgejo, …) where that is enforced.

- **`Forge`** — the trait an adapter implements: bind a namespace, link a
  member's account, create / inspect / archive repositories, converge roles,
  plan and run the commit-trust bootstrap, verify and translate webhooks, and
  diff forge state against the VTC's projection. Object-safe, so a bridge can
  hold one `Box<dyn Forge>` per forge host. `normalize`, `map_role` and `diff`
  have forge-neutral defaults.
- **`ForgeHooks`** — optional lifecycle hooks (`before_create`,
  `after_create`, `before_apply_roles`, `after_bootstrap`, `on_event`,
  `on_drift`) returning `Continue`, `Modify(plan)` or `Abort(reason)`. Hooks
  compute; the core runs every resulting forge write through `Forge`, so there
  is one audited path.
- **`Capabilities`** — what a forge, and one namespace on it, can do. The core
  branches on these flags, never on which forge it is: a GitHub personal
  account is the GitHub adapter reporting `bot_can_create_repos: false` and a
  one-level role ladder. `required_workflow` says whether the check runs
  from a namespace-level workflow pinned to a commit (so a pull request
  cannot change what checks it); without it the repository's own workflow
  is guarded by owner review where there are two or more owners, and
  `single_owner_repos_unreviewed` tells the UI that a single-owner
  repository's workflow edits are not review-protected.
  `ProtectionState::check_source_guard` says which guard a repository has,
  and `Projection::owners` lets `diff` hold it to the owner count
  (`Drift::ReplanNeeded` when that crosses one ↔ two).
- **`Resource`** — a normalised, forge-qualified resource
  (`github.com/acme/widgets`), built on the one grammar in
  [`vgi-core`][vgi-core] so the registry, the verifier and every adapter name
  a repository with the same bytes.
- **`EffectiveRights` / `RoleMap` / `collapse_to_ladder`** — the five git
  rights with implication (`own ⇒ maintain ⇒ commit`, `ns.admin ⇒ create +
  own`), and their projection onto a forge's roles. Roles round *down* onto a
  forge's ladder: fewer levels means less access, never more. Implication
  decides what a person may do, not their forge role: `ns.admin` never
  projects (`EffectiveRights::forge_tier`), and `RoleMap` has no entry for
  it. A `RoleMap` is always ordered (`own ≥ maintain ≥ commit`, `commit ≤
  write`).
- **Bootstrap plans, `ForgeEvent`, `Drift`** — check-then-apply steps with
  `run_plan` (which stops at the first failure, so protection is never enabled
  ahead of the workflow it requires), neutral webhook events, and drift
  classified by whether it removes the commit-trust guarantee.

Nothing here talks to a forge; adapters are separate crates
([`vgi-forge-github`][github], [`vgi-forge-forgejo`][forgejo]).

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[vgi-core]: https://crates.io/crates/vgi-core
[github]: https://crates.io/crates/vgi-forge-github
[forgejo]: https://crates.io/crates/vgi-forge-forgejo
