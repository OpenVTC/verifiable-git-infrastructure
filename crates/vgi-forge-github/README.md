# vgi-forge-github

GitHub adapter for [Verifiable Git Infrastructure (VGI)][vgi] git namespaces:
implements [`vgi-forge`][vgi-forge]'s `Forge` for github.com and GitHub
Enterprise Server, acting as **one community's own GitHub App**.

- **App registration** through the manifest flow, with a fixed permission set
  — repository Administration, Contents, Variables and Checks (write),
  Metadata, Pull requests and Merge queues (read); organisation Members
  (read) and Administration (write), nothing else. Organisation Administration is there for one thing, the org
  ruleset that makes verify-trust a required workflow (below); an owner who
  declines it gets the owner-review fallback. Checks, Pull requests and
  Merge queues are there for one thing too, the check the bridge posts
  itself outside a required workflow (below); an installation without them
  (or without the `pull_request` / `merge_group` events — an App registered
  before they were in the manifest) keeps the Actions workflow
  (`detect_bridge_checks`, `set_bridge_checks_ready`). The code exchange refuses an App that GitHub
  registered with more than that, and returns the key and secrets in a type
  that zeroizes on drop and never prints them.
- **Auth.** An RS256 App JWT (`iat` backdated 60 s, nine-minute lifetime)
  signed through `AppKeySigner` — in-process, or an enclave that signs but
  never exports. Each operation mints its own installation token, scoped to
  one repository and that operation's permissions, and drops it on return.
- **Binding** a namespace via the App's install page and a `state` nonce,
  compared in constant time; the installation must be this App's and on the
  expected owner.
- **Account linking** with the OAuth device flow (`authorization_pending` and
  `slow_down` handled); the bridge keeps the numeric id and login and revokes
  the user token (given the App's client secret) or, without it, discards it. Enable *Device Flow* on the App's settings page — the
  manifest format cannot.
- **Repositories**: create (organisations; a personal account reports the
  reduced capability set and gets manual instructions), inspect (people,
  pending invitations, ruleset), archive, and role convergence keyed on
  numeric account ids, never logins.
- **Bootstrap** (check-then-apply, idempotent), with a ruleset on the default
  branch — PR required, no force-push, no deletion, no bypass actors — and a
  guard so that **a pull request cannot satisfy its own check**. A
  `pull_request` workflow runs from the pull request's own files, so a writer
  could edit it (or add any job named "Verify commit trust") to pass; pinning
  the check to the Actions App does not help, the forged run is an Actions run
  too. The guard is chosen per namespace (`Capabilities`) and per repository
  (`ProtectionState::check_source_guard`):
  - **Required workflow** (organisations with org rulesets,
    `required_workflow: true`). The workflow lives in a bridge-managed,
    public `<org>/.vgi` repository, itself protected by a ruleset (PRs only,
    no force-push, no deletion, no bypass), and an org ruleset (`VGI
    required workflow`: `workflows` rule, **pinned commit SHA**, enforced on
    creation, default branch, the bridge's managed repositories by numeric
    id, enforcement `active`, no bypass actors) requires it on every managed
    repository. Nothing is committed to the repository itself; a repository
    that had the fallback guard gets its workflow, keyring, variables and
    status-check rule cleaned up. The DIDs are literals in the workflow (a
    repository variable would override an org one) and the `web-flow`
    keyring is written from it, not read from the repository. The pin only
    moves to a commit whose workflow the bridge has read back as its own.
    The org ruleset is read, changed and written under a per-namespace lock,
    lists exactly the managed set the bridge hands the adapter
    (`set_managed_repositories`; archived repositories drop out), and is read
    back afterwards — a concurrent edit that lost the repository is a
    retryable error.
  - **Owner review** (personal accounts and organisations without org
    rulesets, repositories with **two or more** owners). The workflow and
    keyring are committed, with the DIDs as literals and the check required
    **and pinned to the GitHub Actions App**. The `CODEOWNERS` GitHub reads
    (`.github/`, else root, else `docs/`; an adopted file keeps its rules and
    its place) ends with a managed block giving `/.github/` — and the file
    itself, if it is not under `.github/` — to every owner (logins looked up
    from numeric ids at run time), and the ruleset requires one approving
    review from a code owner, dismissed by later pushes and never the last
    pusher's own.
  - **Bridge-posted check** (the same namespaces, with
    `GitHubConfig::with_bridge_checks`, which the bridge sets): no workflow
    at all. The bridge receives `pull_request` / `merge_group` webhooks,
    runs verify-trust against the commits itself (never the pull request's
    code) and posts the "Verify commit trust" check run as the App
    (`checks` module: `parse_check_trigger` — pull request opened,
    synchronize, reopened and base edits, merge groups, this App's
    rerequests — `default_branch`, `pull_request`, `compare_commits` (every
    page), `contents_read_token`, `start_check_run`, `finish_check_run`).
    The caller posts only for the protected base: a check run attaches to a
    commit, so a success against any other base would count for the
    protected one too. The
    ruleset pins the required check to **the App's own integration id**,
    which no workflow can post as, so this closes the forged-check-run gap
    below. `inspect` counts only a check pinned to the App and reports
    `CheckSourceGuard::BridgePosted`; an old in-repo workflow is removed.
    The bridge becomes a merge dependency, as the registry already is.
  - **Solo** (the same namespaces, a repository with **one** owner): the
    check alone, no review requirement — the owner could weaken their own
    workflow, which is accepted since they control the repository anyway.
    `single_owner_repos_unreviewed` lets the UI say "solo: workflow edits
    not review-protected". A change of owner count across one ↔ two is a
    `Drift::ReplanNeeded`.
- **Availability** of the required workflow is probed at bind (the result is
  also returned in `NamespaceBinding::capabilities`, for the bridge to
  persist) or with `detect_required_workflow`: `GET /orgs/{org}/rulesets`
  with an organisation Administration token. GitHub offers org rulesets on
  Team and Enterprise plans only, so a Free organisation (403), or an owner
  who declined the permission (422 on the token), falls back. GitHub
  documents the `workflows` rule for Enterprise Cloud: if creating the org
  ruleset is refused *because of the plan* (a 403/422 whose message or
  documentation link says so), the step returns
  `ForgeError::CapabilityChanged` for the bridge to persist and re-plan;
  any other refusal is returned as it is and changes nothing.
- **Drift** is reported by `inspect` as critical
  (`ProtectionGap::CheckSourceUnprotected`) and put back by the bootstrap:
  - required workflow: the org ruleset missing, not `active`, with bypass
    actors, pinning another commit, not enforced on creation, selecting
    repositories by name or property, or no longer including the
    repository; `.vgi` missing, not public, unprotected, or without the
    pinned commit; the pin unknown to the bridge (fail closed);
  - owner review (against the projection's owners): `CODEOWNERS` gone, not
    ending with the managed block, naming other accounts than the owners,
    or with an error GitHub reports on the managed lines
    (`GET /repos/{o}/{r}/codeowners/errors`); the review rule weakened in
    any of its four parts;
  - either: GitHub Actions disabled, or an allowed-actions policy that
    blocks `actions/checkout` or the verify-trust action.

  **Limits.**
  - Organisation owners can still edit or delete the org ruleset, and
    repository admins their ruleset — inherent to GitHub; the drift monitor
    catches it and re-applies.
  - **Outside a required workflow, repository writers are trusted not to
    forge check runs.** Anyone who can push a branch can add a workflow
    there whose job is named "Verify commit trust"; its run is a GitHub
    Actions check run like the real one, and GitHub cannot tell them apart
    for the required status check. Owner review stops edits to *this*
    workflow, not that. The required workflow closes it, and so does the
    bridge-posted check.
  - What GitHub does with a required workflow in a repository whose Actions
    are disabled has not been verified against a live organisation yet;
    `inspect` reports disabled Actions as drift either way.
  - Once a branch is protected, the bridge's own rewrite of a protected file
    (`CODEOWNERS`, the in-repo workflow, a clean-up, or `.vgi`'s workflow) is
    refused and lands through a pull request a human merges; `.vgi`'s new
    commit is pinned once merged.
  - After a restart the bridge must hand back the pin
    (`required_workflow_pin` / `set_required_workflow_pin`) and the managed
    set, or `inspect` reports the pin as unverified and the step refuses to
    run.
- **Webhooks**: `X-Hub-Signature-256` verified in constant time over the raw
  body before parsing; repository, member, team membership, organization
  membership, ruleset, branch protection and installation events become
  `ForgeEvent`s.

## Why not octocrab

octocrab 0.54 covers rulesets and the device flow, but not what the security
model needs: its installation tokens are requested with an empty body (no
per-repository or per-permission scoping) and cached for reuse; its App JWT
takes an in-memory `jsonwebtoken` key, so the key cannot live in an enclave
signer; it has no Actions-variables API; and it follows redirects. It would
also add hyper-rustls with a second crypto provider, tower, snafu and
jsonwebtoken to a graph that already carries reqwest. The adapter instead uses
a thin reqwest client (~300 lines) over the dozen endpoints it calls, with
redirects off and a configurable base URL (GHES, tests).

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[vgi-forge]: https://crates.io/crates/vgi-forge
