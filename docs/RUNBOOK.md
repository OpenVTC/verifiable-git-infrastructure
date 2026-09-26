# VGI operator runbook

Running commit trust on a forge's repositories. Read this if you run the
Trust Registry, the VTA, the VTC, or the repositories the check protects.

The shape to hold in your head: **VGI verifies, the VTC decides.** A commit
names its signer DID on its own `committer` header; `verify-trust` proves that
DID signed it, then asks the registry whether that DID is authorized. Who may
sign, key rotation, and revocation are registry and VTA concerns — nothing
about them lives in the repository.

**Which path.** There are two ways to put the registry's answers into
repositories, and this runbook serves both:

| You have | Path | Read |
|---|---|---|
| A VTC with git namespaces, and a VGI bridge next to it | **VTC-managed** (recommended): rights are records in the VTC, which publishes the commit rights to the registry; the bridge creates repositories, sets up the check, projects roles and reports drift | set up: [SETUP-GITHUB-VTC.md](SETUP-GITHUB-VTC.md); the bridge: [BRIDGE.md](BRIDGE.md); day two: [§8](#8-operating-a-vtc-managed-namespace) |
| A registry and a VTC, no bridge — a forge no bridge serves, or a few repositories | **Manual**: you issue each grant and set up each repository by hand | §1–§7 |

§1–§7 are also the reference both paths share: the grant tuple (§2),
contributors' machines (§3, §3a), what the check needs from a repository
(§4, §4a), and every verdict with its fix (§5).

---

## 1. Prerequisites

These are outside VGI, and standing them up is the long pole.

| What | Why VGI needs it | What you take away |
|---|---|---|
| A **VTA** with a persona and Ed25519 signing key per contributor | `did-git-sign` fetches the key at sign time; no private key touches disk | each contributor's `did:webvh:…#key-N` |
| A **Trust Registry** speaking TRQP | answers "is this DID authorized, right now" | `TRUST_REGISTRY_DID` |
| Your **VTC's DID** | the community whose authority each trust tuple is evaluated under — TRQP's `authority_id` | `VTC_DID` |

Two DIDs, no URLs. The registry's endpoint is discovered from its own DID
document (§4), so there is nothing to keep in sync with it.

Provisioning the VTA and registry themselves is documented in
[verifiable-trust-infrastructure][vti], not here.

## 2. Enrol the signers

For each contributor, issue a grant in the registry over the tuple:

```
entity    = did:webvh:…            the contributor's DID (no fragment)
authority = <VTC_DID>              your VTC — TRQP calls this authority_id
action    = git.commit.sign
resource  = <owner>/<repo>         or <owner> for an org-wide grant (legacy)
resource  = <forge-host>/<owner>/<repo>
                                   or <forge-host>/<owner> (qualified)
```

`entity` is the **bare DID**, not the verification-method id. A commit signed
as `did:webvh:QmAbc:example.com#key-0` is queried as
`did:webvh:QmAbc:example.com` — the fragment names which key, and which key is
already settled by then.

**Which resource form.** The check's `resource-format` decides which of the two
`resource` forms it queries, and a grant only counts if it is written in that
form:

| `resource-format` | Repo grant | Org grant |
|---|---|---|
| `legacy` (default for now) | `acme/widgets` | `acme` |
| `qualified` | `github.com/acme/widgets` | `github.com/acme` |

The qualified form is `<forge-host>/<owner>[/<repo>]`, all lowercase. The forge
host is the one CI runs against — `github.com`, your GitHub Enterprise Server
host, or a Forgejo instance such as `codeberg.org` — so the same `acme` on two
forges is two different resources. `verify-trust` derives it from the runner's
environment; the port of a self-hosted instance is not part of it.

Migration is staged:

1. **Now** — `legacy` is the default; nothing deployed changes. To move a
   repository over, issue its grants in qualified form (during the window the
   VTC can write both forms for each grant), then set
   `resource-format: qualified` on its workflow.
2. **A later minor release** flips the default to `qualified`. A workflow that
   still needs the old form pins `resource-format: legacy`.
3. **The release after** removes `legacy`, and the legacy grants can go.

A run queries one form only — never "qualified, else legacy". Accepting either
would widen who may sign for as long as both exist, with nothing in the
repository to show it.

Choose the resource scope deliberately. A repo-scoped grant authorizes one
repository; an org-scoped grant authorizes every repository that passes
`fallback-resource: <owner>` (`<forge-host>/<owner>` under `qualified`). Grant
semantics are OR, so a repo-level record **cannot veto** an org-level grant —
narrowing is a matter of not issuing the broad grant in the first place.

The fallback is checked against the resource. Under `qualified` it must
contain it: `github.com/acme` for `github.com/acme/widgets`, or the resource
itself. A fallback naming another owner or another forge is refused, and the
run fails before it queries anything. Under `legacy`, a fallback that parses
as forge-qualified is refused, because one run uses one form. That includes a
legacy value whose first segment has a dot, such as `john.doe/repo`, which
reads as host `john.doe`. A legacy fallback is a bare owner (`acme`, or
`john.doe`), and those still pass unchanged. Both checks exist only in
verify-trust releases that include them: pin one (`version:`) for them to take
effect. An older release accepts any fallback as given.

This step is the whole access-control decision. There is no second list to
maintain, and nothing to commit to the repository.

## 3. Set up a contributor's machine

Once per contributor:

```sh
cargo install did-git-sign
did-git-sign init --global --vta-did did:webvh:scid:your-vta.example.com
did-git-sign health
```

`init` resolves the VTA, mints a temporary admin did:key, and prints a
`pnm contexts create …` command. Run that in your Personal Network Manager to
authorise the setup session, press Enter, then pick the persona and signing
key. It configures git:

- `gpg.format = ssh`, `gpg.ssh.program = did-git-sign`, `commit.gpgsign = true`
- **`did-git-sign.key = <DID#key-id>`** — this is load-bearing. It selects the
  signing persona, and a `commit-msg` hook writes it into a `Signed-by-DID:`
  trailer, which is the only place a commit states which identity signed it.
- **`core.hooksPath`** — points at the directory holding that hook. The
  directory also carries a delegating stub for every other standard hook, each
  execing the repo's own `.git/hooks/<name>`, so existing hooks keep running.
  `init` refuses to take `core.hooksPath` from a tool that already owns it
  (husky, lefthook, pre-commit) rather than silently disabling it.
  The hook needs git ≥ 2.20 (`interpret-trailers --no-divider`, also in 2.19.2).

The hook is written once, by `init`; upgrading the binary does not replace it.
`did-git-sign health` compares the hook's `# did-git-sign-hook-version:` line
with the binary's and prints `Commit-msg hook: OUTDATED` when it is older —
re-run `did-git-sign init` (same scope as the original install). Hooks before
v2 put the trailer above any `---` line in the message (Dependabot-style
messages, some templates), where neither `git log --format='%(trailers)'` nor
`verify-trust` reads it, so those commits fail `noSignerDid`.

`user.email` is deliberately left alone: it stays an ordinary address so GitHub
and GitLab can attribute commits to the author's account. A commit that reaches
CI with no `Signed-by-DID:` trailer and a non-DID `user.email` fails
`noSignerDid` even with a valid signature — that means the hook did not run
(`--no-verify`, or a `core.hooksPath` taken by something else).

Use `--global` for all repositories, or plain `init` for one. Verify with
`did-git-sign health` before the first push, not after the PR check fails.

`--global` also sets `did-git-sign.key` and `core.hooksPath` machine-wide. Fine
for a contributor in one community; if they are in two, use §3a instead — `init`
prints that alternative when run with `--global`.

`did-git-sign` refuses to sign a commit whose DID claim differs from the key it
is about to use, so a mismatch fails at `git commit` with both halves named
rather than in CI as `unknownKey`.

## 3a. Contributors in more than one community

One setting picks the identity: it selects the key *and*, read by the
`commit-msg` hook, becomes the commit's claim. `did-git-sign` and the hook
resolve it in the same order —

1. `DID_GIT_SIGN_KEY` (per-invocation),
2. `did-git-sign.key` in git config (per-repo),
3. the `did_key_id` in the config file (the `init` default).

**Do not hand-manage per-repo config.** `git config --local` works but does not
survive a fresh clone, and when you forget it you get no error — you get a
commit signed as the wrong community. Where the community *is* the
authorization boundary, silent misattribution is the failure to design against.

Use git's **conditional includes**, one file per community, carrying the
identity and the key selection together so they cannot drift:

```ini
# ~/.gitconfig
[includeIf "hasconfig:remote.*.url:https://github.com/OpenVTC/**"]
    path = ~/.config/git/community-openvtc
[includeIf "hasconfig:remote.*.url:https://github.com/OtherOrg/**"]
    path = ~/.config/git/community-other
```

```ini
# ~/.config/git/community-openvtc
[user]
    email = you@openvtc.example
    name  = Your Name
[did-git-sign]
    key = did:webvh:QmAbc:openvtc.example#key-0
```

`hasconfig:remote.*.url` (git ≥ 2.36) keys off the remote rather than the
filesystem, so membership follows the repository rather than where you happened
to clone it — and a throwaway clone outside your usual tree still gets the right
persona. Use `includeIf "gitdir:~/devel/openvtc/"` instead if your layout is
authoritative and you prefer path matching.

`did-git-sign.key` is the whole of it — there is no second setting to keep in
step, which is what used to drift. Set `user.name` and `user.email` however you
like alongside it; they affect forge attribution, not verifiability.

`DID_GIT_SIGN_KEY` is fine for one-off overrides: the hook honours it too, so
`DID_GIT_SIGN_KEY=… git commit` moves the key and the claim together.

## 4. Set up the repository

**In a VTC-governed namespace without a bridge** (bound `--mode manual`, or a
personal account the community's App is not on), `vgi repo init` does this
section for you — the same plan the bridge runs, as you — and is what
`cnm git create`'s manual steps name:

```sh
cargo install vgi-cli                  # the `vgi` command
gh auth login                          # GitHub: vgi acts through your gh login
vgi repo init --vtc <vtc-did> --resource github.com/alice/gadgets --dry-run
vgi repo init --vtc <vtc-did> --resource github.com/alice/gadgets
cnm git adopt github.com/alice/gadgets --owner <owner-did>   # it prints this line
```

It commits the workflow (DIDs as literals, `resource-format: qualified`, the
namespace as `fallback-resource`, as the bridge writes it) and the `web-flow`
keyring, removes stale `TRUST_REGISTRY_DID` / `VTC_DID` variables,
and converges the "VGI commit trust" ruleset: pull request required, the check
required and pinned to GitHub Actions, no force-push or deletion, no bypass.
These are **per-repository guards**: it does not set the organisation's
required workflow, which only the community's bridge does.

The owners are you (on a personal repository, its account holder) plus each
`--code-owner <login>`, each counted once. With two or more, `.github/`
changes need a code owner's review. With one, only the check is required, and
on an **organisation** repository that is refused unless you pass `--solo`:
any other member with write access could edit the workflow in the very pull
request it judges. Prefer `--code-owner`.

On Forgejo set `FORGEJO_TOKEN` (`write:repository`, `read:user`); it does
§4a. It sends the token only after `GET /api/v1/version`, asked without it,
answers as Forgejo or Gitea, and only to the repository's own host
(`--forgejo-url` may add a port or sub-path, not change the host). With
`--forge auto` any host but `github.com` is taken for Forgejo; for GitHub
Enterprise Server pass `--forge github`.

The registry DID comes from the VTC's `TrustRegistry` referral unless you pass
`--registry`; the report says which. The action commit (the
`--verify-trust-version` tag, dereferenced) and, on Forgejo, the release's
SHA-256 are what GitHub serves when you run it — trust on first use, labelled
so in the report; pass `--verify-trust-action` / `--verify-trust-sha256` to
pin values you checked. Re-running changes nothing; `--dry-run` shows every
change with its contents. It cannot adopt the repository itself — that is a
Trust Task signed with a VTA session — so it prints the `cnm git adopt` command.
In **bridge** mode skip it: adopting runs the bootstrap.

**Upgrading the check** (a new `--verify-trust-version`) once the repository
is protected:

- **GitHub:** the ruleset has no bypass, so the new workflow lands through a
  pull request, like any change. `vgi repo init --dry-run
  --verify-trust-version <tag>` prints the file to commit (each line after
  its `      | ` margin); open the pull
  request with it (a code owner reviews it where there are two owners), merge,
  and a re-run of `vgi repo init` then reports nothing to change.
- **Forgejo:** no one can push to the default branch and the workflow
  directories are protected file patterns, so an admin lifts the protection
  for the change — deletes the default branch's protection rule (or allows
  pushes and clears its protected file patterns) — and re-runs
  `vgi repo init --verify-trust-version <tag>`, which writes the new workflow
  and puts the protection back. The branch is unprotected in between: do it
  in one sitting. Where a bridge manages the repository, it does this instead.

Outside a VTC-governed namespace, or to see what it writes, set it up by hand:

**Workflow** — `.github/workflows/verify-trust.yml`:

```yaml
on: pull_request

jobs:
  verify:
    name: Verify commit trust
    if: vars.TRUST_REGISTRY_DID != ''
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
        with: { fetch-depth: 0 }        # so origin/<base>..HEAD resolves
      - uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.4.6
        with:
          range:        origin/${{ github.base_ref }}..HEAD
          registry-did: ${{ vars.TRUST_REGISTRY_DID }}
          vtc-did:      ${{ vars.VTC_DID }}
          exempt-keyring: .github/trusted-platform-keys.asc
          resolve-agent-names: true     # optional; one HTTPS fetch per claimed name
          # resource-format: qualified  # once the grants are qualified (§2)
```

`fetch-depth: 0` is not optional — without the base ref present the range does
not resolve.

**Registry discovery.** There is no `registry-url` to set, and the registry
does not need a REST interface. The binding comes from the registry's own DID
document, which advertises one service entry per binding it serves:

```json
"service": [
  { "id": "…#rest",    "type": ["TRQPRest", "TrustRegistry"],
    "serviceEndpoint": { "uri": "https://registry.example",
                         "profile": "https://trustoverip.org/profiles/trqp/v2" } },
  { "id": "…#didcomm", "type": "DIDCommMessaging",
    "serviceEndpoint": { "uri": "did:web:mediator.example", "accept": ["didcomm/v2"] } },
  { "id": "…#tsp",     "type": "TSPTransport",
    "serviceEndpoint": "did:web:mediator.example" }
]
```

Selection takes the highest-preference binding present in **both** the document
and the verifier: **TSP → DIDComm → HTTPS**. The released verifier speaks all
three, so any one entry is enough — `#rest` is optional. If your registry
advertises none of what the verifier speaks, the run fails naming both sides'
bindings rather than downgrading quietly.

Note the `#tsp` and `#didcomm` endpoints are **mediator DIDs**, not URLs — a
consumer of those bindings resolves a second hop. Only `#rest` carries a URL.

*Over TSP or DIDComm*, each run queries as a fresh `did:peer:2` generated in
memory for that run (never written to disk or logs) whose service names the
registry's mediator, so the reply routes back. The verdict does not rest on
that identifier: an answer is believed only if the binding authenticated it as
`registry-did` (authcrypt / TSP sender) and it answers the query asked. If the
mediator refuses the run's DID, or no such answer arrives within 30 seconds,
the commits are `UNAVAILABLE` and the check fails — never passes.

Because the run's DID is new every time, **the registry's mediator must admit
DIDs it has not seen** for this to work:

| Mediator setting | Needed | Why |
|---|---|---|
| `mediator_acl_mode` | `explicit_deny` | in `explicit_allow` an unknown DID cannot authenticate |
| `global_acl_default` | an open inbox (`MODE_EXPLICIT_DENY`, or `ALLOW_ALL`) | a new DID cannot add the registry to its own allowlist, so an allowlist inbox never receives the answer |
| `global_acl_default` (DIDComm) | `SEND_FORWARDED,RECEIVE_FORWARDED` | the query and the reply are routing forwards |

The narrowest default that serves both bindings is
`DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,SEND_FORWARDED,RECEIVE_FORWARDED,MODE_EXPLICIT_DENY`.
The mediator's *shipped* default (`DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES`)
admits the DID but closes its inbox, so every run is `UNAVAILABLE`. The
registry's own `ACL_MODE` (default `ExplicitDeny`) must also accept unknown
senders.

There is **no automatic fallback** from a refused mediator binding to HTTPS —
a blocked mediator must never quietly downgrade the check. `transport: auto`
(the default) picks the most-preferred binding advertised, and a failure
there is a failure. **If your registry's mediator is not configured as above
yet, set `transport: https`** on the action (the registry must still publish
`#rest`), or `transport = "https"` under `[verify_trust]` in the bridge config
for the workflows it writes:

```yaml
      - uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@vX.Y.Z
        with:
          # …
          transport: https   # until the registry's mediator admits CI's throwaway DIDs
```

`transport` takes `auto`, `tsp`, `didcomm` or `https`. A named binding the
registry does not advertise, or the verifier cannot speak, fails the run with
both sides named. `registry-url` implies `https`.

> **Release note — behaviour change.** verify-trust now queries the Trust
> Registry over the binding its DID document advertises, preferring TSP, then
> DIDComm, then HTTPS; the REST interface is optional. A registry that
> advertises `#tsp` or `#didcomm` is now queried over it instead of `#rest`,
> as a throwaway `did:peer` per run, and the registry's mediator must admit
> such DIDs (`explicit_deny`, and an open-inbox `global_acl_default` —
> see *Registry discovery* in the runbook). There is no fallback: until the
> mediator is configured, runs fail `registryUnavailable`. To keep today's
> HTTPS behaviour, set `transport: https` (Action), `--transport https` (CLI),
> or `transport = "https"` in the bridge's `[verify_trust]` (the workflows it
> writes). A DIDComm reply is believed only if the authcrypt sender key id is
> the key its key agreement actually used, and each query carries a random id.
> The bridge-posted check queries `#rest` (HTTPS) only.
> `UNKNOWN-KEY` now says what usually causes it: the signer rotated their
> key, and the commit must be re-signed with the current one.

The runner needs outbound HTTPS and WebSocket (`wss://`) to the mediator.

`registry-url` remains as an explicit **HTTPS override** — for a registry that
publishes no service entry (local, dev), or to pin HTTPS. Prefer discovery:
over HTTPS the registry's reply is unsigned — `registry-did` is only stamped
on the *outgoing* request as `recipient` — so trust in the answer rests on
reaching the right host. Two independently settable values that nothing
cross-checks is exactly the gap an override reintroduces.

**Platform keyring** — `.github/trusted-platform-keys.asc`:

```sh
curl -sS https://github.com/web-flow.gpg > .github/trusted-platform-keys.asc
```

GitHub's web-UI merge commits — including the merge a pull-request check runs
on — are PGP-signed by `web-flow`, not by a DID. Without this file every merge
commit fails `pgpRejected`. Committing the key is what makes the exemption
explicit and auditable.

The key exempts **merge commits only**, and only a clean merge of parents that
themselves pass. `web-flow` signs *everything* GitHub writes on someone's
behalf — web-UI file edits (a fork author's included), REST Contents API
commits by any writer, squash merges, Dependabot commits — so its signature on
a single-parent commit says nothing about who chose the content. Those fail
`platformSignedEdit` (§5). In practice:

- **Merge with a merge commit.** Squash merges, and a merge queue set to
  squash, produce single-parent `web-flow` commits that fail wherever they are
  checked; use the *merge* method. (Rebase-and-merge doesn't help either:
  GitHub rewrites the commits, so their DID signatures are lost.)
- **Don't edit files in the web UI** on a branch that is checked; commit
  locally with `did-git-sign`.
- **Resolve conflicts locally**, not in the web conflict editor: a merge whose
  tree is not the clean merge of its parents fails `platformMergeAltered`.
- **Dependabot pull requests** fail until a maintainer re-signs them (§5) —
  except where a GitHub bridge serves the namespace: it re-signs a
  Dependabot pull request itself when only Dependabot has pushed to its
  branch (BRIDGE.md §6a).

Verifying a platform-signed merge recomputes it with `merge-tree`, pinned to
ignore `.gitattributes` (so a `merge=union` attribute cannot make a conflict
look clean). That needs **git 2.40 or newer** on the runner; GitHub-hosted
runners ship a newer one, and an older git fails the run with an error saying
so rather than checking unpinned. The checkout also needs full history
(`fetch-depth: 0`, already required).

**Repository variables** — plain variables, not secrets; they are public values
and fork PRs must be able to read them:

```sh
gh variable set TRUST_REGISTRY_DID --body 'did:webvh:…registry'
gh variable set VTC_DID            --body 'did:webvh:…your-community'
```

Setting these is what un-dormants the `if:` guard. Until then the job is a
no-op, which is deliberate: it keeps the workflow harmless in a repo that has
not been enrolled, and in forks.

**Branch protection** — the check is worthless unless it is *required*. On a
ruleset for `main`:

- require a pull request before merging
- require the **"Verify commit trust"** status check to pass
- block force-pushes and branch deletion

**Protect the check from the pull request it checks.** The workflow above runs
on `pull_request`, which means it runs *from the pull request's own files*.
Anyone who can push a branch can edit `verify-trust.yml` in their PR (or add
any job named "Verify commit trust") so that it passes, and merge unsigned
commits. Requiring the check "from GitHub Actions" does not help: the forged
run is an Actions run too. The same goes for
`.github/trusted-platform-keys.asc`: a PR that adds its own key to it exempts
its own commits. Pick one:

- **Organisation with org rulesets (recommended).** Keep the workflow out of
  the repository. Put it in a separate repository in the org (the VGI bridge
  uses a public `<org>/.vgi`; public, because a private repository's workflow
  may only be required on private repositories), with the DIDs written in as
  literals rather than `vars.*` (a repository variable overrides an org one of
  the same name) and the `web-flow` key embedded in the workflow rather than
  read from the repository. Then add an **org ruleset** with *Require
  workflows to pass before merging*, pointing at that file **pinned to a
  commit SHA**, targeting the default branch of the enrolled repositories,
  with no bypass list. The PR cannot change what runs. Org rulesets need
  GitHub Team or Enterprise, and GitHub documents the workflows rule for
  Enterprise Cloud; if the org cannot create it, use the next option.
- **Personal account, or an org without org rulesets — two or more
  owners.** Write the DIDs into the workflow as literals too (not
  `vars.*`: any repository admin can change a repository variable). Make the
  `CODEOWNERS` GitHub actually reads — `.github/CODEOWNERS`, else
  `CODEOWNERS` at the root, else `docs/CODEOWNERS`; GitHub uses the first it
  finds, so don't add a second one that shadows an existing file — end with

  ```
  /.github/ @owner1 @owner2
  /CODEOWNERS @owner1 @owner2    # only if the file is not under .github/
  ```

  (last, so no later rule narrows it; every name a person with write access,
  or GitHub skips the line — check the file's page, or
  `GET /repos/{owner}/{repo}/codeowners/errors`). In the ruleset's pull
  request rule set **all four**: required approvals **1**, **require review
  from Code Owners**, **dismiss stale approvals when new commits are
  pushed**, and **require approval of the most recent reviewable push** —
  without the last two, a reviewed change can be swapped after approval, or
  approved by the person who pushed it. Every change to the workflow, the
  keyring or `CODEOWNERS` then needs another owner's approval.
- **The same, with a single owner.** Skip the review rule: nobody else could
  approve, and the owner controls the repository anyway. The check is still
  required, but its owner could weaken their own workflow; the VGI bridge
  shows such repositories as *solo: workflow edits not review-protected*,
  and switches to the two-owner setup when a second owner arrives.

Whichever you choose, keep **GitHub Actions enabled** on the repository and
let it run `actions/checkout` and the verify-trust action (Settings →
Actions → General). A repository admin who switches Actions off or narrows
the allowed actions stops the check from running; the bridge reports it as
drift. (What GitHub does with a *required workflow* when Actions is off in the
target repository has not been verified against a live org yet.)

**Limits.**

- Org owners and repository admins can still edit the rulesets themselves:
  that is inherent to GitHub. Watch them (`repository_ruleset` webhooks, or
  the VGI bridge's drift monitor, which re-applies them) rather than assuming
  they stay put.
- **Without a required workflow, repository writers are trusted not to forge
  check runs.** Anyone who can push a branch can add a workflow on that
  branch whose job is named "Verify commit trust"; its run is a GitHub
  Actions check run like the real one, and the required status check cannot
  tell them apart. Owner review protects the real workflow file, not the
  check's name. Only the org required workflow closes this; outside it, give
  write access only to people you would trust with that.

## 4a. Set up a Forgejo repository

The same composite action runs on Forgejo Actions (Codeberg or a self-hosted
instance). What differs:

**Workflow** — `.forgejo/workflows/verify-trust.yml`, with the action referenced
by **full URL**. A bare `uses: owner/repo/...` is resolved against the
instance's own default actions host, which is not where this action lives:

```yaml
on: pull_request

jobs:
  verify:
    name: Verify commit trust
    if: vars.TRUST_REGISTRY_DID != ''
    runs-on: docker                   # whatever label your runner registers
                                      # (the bridge: `runs_on` in [[forgejo]])
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: https://github.com/OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@vX.Y.Z
        with:
          range:           origin/${{ github.base_ref }}..HEAD
          registry-did:    ${{ vars.TRUST_REGISTRY_DID }}
          vtc-did:         ${{ vars.VTC_DID }}
          resource-format: qualified
          version:         vX.Y.Z             # pin it on Forgejo
          sha256:          <SHA-256 of the Linux tarball, see below>
```

**Use `resource-format: qualified` from day one.** A new Forgejo repository has
no legacy grants to keep working, and the qualified resource
(`codeberg.org/acme/widgets`) cannot be confused with the same owner/repo on
another forge. `verify-trust` takes the host from `FORGEJO_SERVER_URL` (falling
back to `GITHUB_SERVER_URL`, which Forgejo also sets) and the repository from
`FORGEJO_REPOSITORY`. Issue the grants in that form (§2).

**The runner.** It needs outbound HTTPS to GitHub to download the
`verify-trust` release, a glibc new enough for the Linux binary, and git 2.40
or newer if instance-signed merges are exempted (see *Platform keyring* in §4). Codeberg
and small instances may offer no shared runner, so confirm one picks the job up
before making the check required. What the install needs and what it verifies
there are under [Forgejo Actions runners](#forgejo-actions-runners) below.

**Merge commits.** The `web-flow` keyring above is GitHub-specific. On Forgejo,
prefer **fast-forward-only** merges (the repository's allowed merge styles):
the DID-signed commits then land unchanged, and no platform key is needed at
all. If you need merge commits, the instance must sign them
(`[repository.signing]` in its configuration), and you commit the instance's
public key as the exempt keyring. It exempts clean merge commits only; an
instance-signed squash commit fails `platformSignedEdit`:

```sh
curl -sS https://git.example.org/api/v1/signing-key.gpg > .forgejo/trusted-platform-keys.asc
```

and pass `exempt-keyring: .forgejo/trusted-platform-keys.asc`. With neither,
every web-UI merge fails `pgpRejected` (or `unsigned`, if the instance does not
sign at all).

**Branch protection** — on the default branch: enable status checks and require
the verify-trust job's context, disable force-push, and restrict who may push
and merge. The context name may not match what GitHub would show;
copy the one a completed run reports rather than guessing. Forgejo names it
`<workflow name> / <job name> (<event>)`, and matches required contexts as glob
patterns — keep `*?[]{}\` out of the name. Also:

- **Protect the workflows.** A pull request runs its *own* copy of the
  workflow, so one that edits `verify-trust.yml` (or adds a workflow whose job
  reports the same context) passes itself. List
  `.forgejo/workflows/**;.gitea/workflows/**;.github/workflows/**` — and the
  exempt keyring, if you commit one — under *protected file patterns*
  (`**`, because Forgejo's `*` stops at `/` and `.`), and enable *apply to
  administrators* so admins cannot merge past it.
- **Disable direct pushes** rather than allow-listing pushers: a direct push
  skips status checks entirely. Merges go through the *merge allow-list*.
- **Only one rule may match the branch.** Forgejo compares plain rule names
  case-insensitively and applies the oldest match, so a stray `Main` rule can
  quietly replace your `main` rule.
- **Anyone who can write can post the check's status** — maintainers, and any
  workflow that runs pull-request code with a write token. Forgejo cannot pin
  a required check to Actions, so those writers are trusted.

To change a protected workflow later, lift the protection for the change and
restore it exactly. A community bridge does this as one audited step
(`refresh-managed-files`): it allows pushes from the bridge's bot alone, writes
the files, restores the rule and reads it back; a rule left open shows as
critical drift. The restore is attempted even when opening the rule failed,
since a failed request may still have been applied. The bootstrap's own
workflow and keyring steps use the same step, so re-running the bootstrap
brings an outdated workflow up to date. It stops early, writing nothing, when
another branch-protection rule shadows the managed one (for example a stray
`Main` rule next to `main`). Remove that rule, then run the bootstrap again.

The same problem as on GitHub applies (§4, *Protect the check from the pull
request it checks*): a Forgejo `pull_request` workflow also runs from the PR's
own files, and Forgejo has no required workflows. Add
`.forgejo/workflows/*`, `.gitea/workflows/*`, `.github/workflows/*` and the
exempt keyring's path to the branch protection's **protected file patterns**,
so no PR that touches them can merge through the UI; change them with a
direct, audited push by a namespace admin instead.

### Forgejo Actions runners

The same action runs on a Forgejo runner (forgejo-runner), referenced by full
URL — Forgejo resolves a bare `owner/repo` against the instance's configured
default actions URL, which is usually not GitHub:

```yaml
      - uses: https://github.com/OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@vX.Y.Z
        with:
          range:        origin/${{ github.base_ref }}..HEAD
          registry-did: ${{ vars.TRUST_REGISTRY_DID }}
          vtc-did:      ${{ vars.VTC_DID }}
          version:      vX.Y.Z            # pin it; `latest` moves under you
          sha256:       <SHA-256 of verify-trust-x86_64-unknown-linux-gnu.tar.gz in vX.Y.Z>
```

This needs a release of the action that includes the portable installer;
earlier ones install with `gh` and the job token, which a Forgejo runner lacks.

**What the runner needs.** bash, curl, tar, `sha256sum` or `shasum`, and
outbound HTTPS to `github.com` (and the release-asset CDN it redirects to).
No `gh` and no token: the release is public and downloaded anonymously. The
platform is taken from `RUNNER_OS`/`RUNNER_ARCH`, or from `uname` when the
runner does not set them; prebuilt binaries exist for Linux x86-64, macOS
(arm64, x86-64) and Windows x86-64, and any other platform fails naming
itself. The Linux binary is built on GitHub's `ubuntu-latest` and needs
**glibc 2.39 or newer** — Ubuntu 24.04 or Debian 13 (trixie) job images work;
Debian 12 (bookworm)-based images such as `node:20-bookworm` do not.

**The job token stays on Forgejo.** On a Forgejo runner `github.token` is the
Forgejo instance's token. The action hands it only to `gh attestation verify`,
and only when `GITHUB_SERVER_URL` is `https://github.com` — so on Forgejo it is
never sent anywhere.

**Integrity is weaker unless you pin a checksum.** What the install checks:

| Runner | Checks | Protects against |
|---|---|---|
| GitHub (`gh` present, `verify-attestation: auto`) | SHA-256 published with the release, **and** the build-provenance attestation: signed by this repo's `release.yml` on a GitHub-hosted runner, for the release tag | transport corruption **and** a release asset replaced after the build |
| Forgejo (no `gh`, no GitHub token) | SHA-256 published with the release | transport corruption only — whoever can replace a release asset can replace its checksum too |
| Either, with `sha256:` set | the above, plus the checksum pinned in your workflow | a replaced asset, provided your workflow is reviewed |

Attestation verification is not available on a Forgejo runner: it needs
GitHub's attestation API and a GitHub token. `verify-attestation: true` fails
there rather than quietly downgrading. So on Forgejo, pin `version` and set
`sha256` to the tarball's hash — taken from a machine where you have verified
the attestation:

```sh
gh release download vX.Y.Z --repo OpenVTC/verifiable-git-infrastructure \
  --pattern verify-trust-x86_64-unknown-linux-gnu.tar.gz
gh attestation verify verify-trust-x86_64-unknown-linux-gnu.tar.gz \
  --repo OpenVTC/verifiable-git-infrastructure \
  --signer-workflow OpenVTC/verifiable-git-infrastructure/.github/workflows/release.yml \
  --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
sha256sum verify-trust-x86_64-unknown-linux-gnu.tar.gz
```

Pinning the action itself to a commit SHA rather than a tag (`…/verify-trust@<sha>`)
closes the remaining gap: the installer's own code.

Releases before v0.4.9 carry no attestation; on a GitHub runner they need
`verify-attestation: false`.

## 5. Verdicts and what to do about them

`trusted` and `exempt` pass. Everything else fails, with a distinct status so
the remediation is unambiguous:

| Verdict | Cause | Fix |
|---|---|---|
| `unsigned` | no `gpgsig` header | signing is off — `did-git-sign health` |
| `noSignerDid` | signed, but no DID in the trailer or committer | the `commit-msg` hook did not run — `--no-verify`, or `core.hooksPath` taken by another tool — or an outdated (pre-v2) hook put the trailer above a `---` line; check `did-git-sign health`, re-run `init`, then amend |
| `conflictingSignerDids` | `Signed-by-DID:` trailer and DID committer name different identities | a hand-written trailer, or a rebase carrying an old one; amend so one claim remains |
| `unresolvedSigner` | the claimed DID would not resolve | DID document unreachable, or publishes no Ed25519 method |
| `unknownKey` | the claimed DID publishes no such key | usually the signer **rotated their key** after signing — the DID no longer publishes the old one, so re-sign the commit with the current key (below). Otherwise it was signed by a key that identity never held: `did-git-sign init` for the right key |
| `badSignature` | key is published, signature fails | the commit was altered after signing |
| `unauthorized` | valid signature, registry says no | no grant — issue one, or the signer was revoked |
| `registryUnavailable` | the registry could not be consulted | registry outage — or, over TSP/DIDComm, a registry mediator that does not admit the run's throwaway DID (§4, *Registry discovery*; set `transport: https` meanwhile). The check fails closed by design |
| `pgpRejected` | PGP-signed by no key in the exempt keyring | no keyring configured, or a platform key other than the committed one |
| `platformSignedEdit` | signed by the platform key, but not a merge: a web-UI or API edit, a squash merge, a Dependabot commit | re-sign it with `did-git-sign` (below); for squash merges, merge with a merge commit instead |
| `platformMergeUnverifiedParent` | platform-signed merge with a parent (named) that neither passes nor is on the base branch | fix the named parent; the merge cannot vouch for it |
| `platformMergeAltered` | platform-signed merge whose tree is not the clean merge of its parents | conflicts resolved in the web UI; merge locally and sign with `did-git-sign` |

`exempt` is a clean, platform-signed merge commit whose parents all pass (see
*Platform keyring* in §4).

**Re-signing after a key rotation** (`unknownKey`). Once your DID document
stops publishing the old key, every commit you signed with it that is not yet
merged fails. **After rotating your signing key, re-sign the commits in your
open pull requests**: the same `git rebase -i` recipe below, adding the
`exec git commit --amend --no-edit -S` line after each of *your* commits,
then force-push. Every check verifies against the DID documents as they are
*now*, so a commit already merged is only affected if a later range includes
it again.

**Re-signing platform-written commits** (a Dependabot pull request, a web-UI
edit). A maintainer who is an enrolled signer, with `did-git-sign` configured,
re-signs **only the commits the check refused** — not the whole branch:

```sh
gh pr checkout <number>
git rebase -i origin/main
# in the todo list, after the `pick` of each refused commit, add a line:
#   exec git commit --amend --no-edit -S
# and leave every other pick as it is
git push --force-with-lease
```

`--amend` keeps the original author and makes the maintainer the committer, so
each re-signed commit is signed by, and attributed to, the DID that vouched for
it. Don't `--exec` across the whole branch: a commit another contributor
already signed carries their `Signed-by-DID:` trailer, which the hook leaves in
place, and `did-git-sign` then refuses to sign it as you. For the same reason,
a refused commit whose message already carries someone else's
`Signed-by-DID:` trailer (a squash of signed commits, say) needs that trailer
removed first — use `exec git commit --amend -S` and delete the line in the
editor.

Dependabot stops updating a pull request once someone else has pushed to it;
comment `@dependabot recreate` to start over. Where a GitHub bridge serves the
namespace it re-signs clean Dependabot pull requests itself (BRIDGE.md §6a;
§8e for when it does not). Dependabot commits are refused
rather than exempted because nothing binds a commit to Dependabot but its
`author` header, and GitHub does not tie that header to the Dependabot app —
any exemption keyed on it could be claimed by others.

`registryUnavailable` makes registry availability a merge-blocking dependency.
That is the intended trade — "denied" and "unreachable" are indistinguishable
on the wire, so passing on doubt would be the wrong default — but plan
monitoring for it accordingly.

`--json` emits the same report machine-readably, with full signer DIDs and a
`signerNames` map carrying each name's provenance.

## 6. Day-to-day operations

**Add a contributor.** One grant in the registry. No pull request, no repo
change, effective on the next run. If the grant is org-scoped, it covers every
repository configured with that `fallback-resource`.

**Revoke a contributor.** Revoke the grant. Effective on the next run. Their
existing commits stay in history and keep verifying cryptographically — they
simply stop being authorized, which is the honest description of what changed.

**Rotate a key.** Update the DID document. The DID is unchanged, so the grant
stays valid and no repository is touched. This is why enrolment is by identity
rather than by key. **After rotating, re-sign the commits in your open pull
requests** — they were signed with the key the DID no longer publishes, so
they now fail as `unknownKey` (§5, *Re-signing after a key rotation*).

**Retire a repository.** Nothing to clean up in the repo; drop the grants whose
resource named it.

In a VTC-managed namespace each of these is a change to the VTC's records
instead: §8.

## 7. Things that carry more weight than they look like

**`resource` is the only scope.** With no committed signer list, the tuple
resource is the sole thing binding a signer to this repository. Widening
`resource` or `fallback-resource` widens who may sign, and nothing in the
repository will contradict it. Treat both as security-relevant configuration
and review changes to them as you would a permissions change.

Switching `resource-format` changes which grants count, so review it the same
way: a repository moved to `qualified` before its qualified grants exist fails
every commit `unauthorized`, and one moved back to `legacy` is governed by
whatever legacy grants remain.

**The registry is the single gate.** Enrolment, authorization and revocation
all resolve to one TRQP answer. This is the design's premise, not an oversight
— but it means registry compromise is sufficient to authorize commits, so the
registry's own operational security is the system's floor.

**`max-signers` bounds attacker-directed resolution.** The signer set comes
from the commits, so a pull request chooses which DIDs CI resolves — and for
`did:web` / `did:webvh` that is an outbound fetch to a host the author picked.
DIDs are deduplicated, then capped (default 32). Raise it only for a range
that is legitimately that wide.

**GitHub's own "Verified" badge is a separate axis.** These SSH signatures show
as verified in the GitHub UI only if the contributor also adds that Ed25519
public key to their GitHub account as a signing key. VGI's check is entirely
independent of it. If you additionally enable GitHub's built-in *Require signed
commits* rule, it will reject DID-signed commits whose keys are not registered
with GitHub — enable one or the other deliberately, not both by reflex.

**Squash and rebase merges rewrite commits.** A squash merge is a
single-parent commit signed by `web-flow`, which the exempt keyring does not
exempt (`platformSignedEdit`); a rebase-merge drops the DID signatures. The
pull request itself was verified, but any later range containing the result
fails. Merge with merge commits (§4).

## 8. Operating a VTC-managed namespace

Day two for a namespace bound in bridge mode (set up with
[SETUP-GITHUB-VTC.md](SETUP-GITHUB-VTC.md)). Everything here is a change to
the VTC's records, not to the forge or the registry: the VTC publishes the
commit rights to the registry and has the bridge converge the forge. Nothing
in the repository changes when people come and go.

Where to do it:

- **`cnm git …`** — each change is a signed `git-ns/*` Trust Task, authorized
  by the **profile DID's own git rights**. The listings (`cnm git namespace
  list`, `cnm git repos`, `cnm git view --admin`) use an admin session.
- **openvtc** — for members: *Communities* → the community → `r` opens
  *Repos*. On a repository: `a` grant, `x` revoke, `t` transfer, `A` archive;
  on the list: `n` new repository; anywhere: `l` link a forge account, `r`
  refresh.
- **The admin console's Repos page** (`/admin/repos`) — every namespace,
  repository, right, drift item and job. Its changes are signed with the
  browser's console key where one is enrolled, or handed over as the `cnm`
  command.

Under the default `[git_ns] elevated_requires_admin = true`, **elevated**
actions — granting or revoking `git.repo.own` or `git.repo.create`,
transfer, archive, adopt — and **destructive** ones — bind, unbind, granting
or revoking `git.ns.admin` — are accepted only from a community
administrator who also holds the git right that entitles them. Granting and
revoking `maintain` and `git.commit.sign`, and creating a repository, are
normal-class. (Why: SETUP-GITHUB-VTC.md §1.)

A change reaches the registry within a projector pass (`tick_seconds`,
default 5; at least once a minute regardless) and the forge when the bridge
runs the job. `GET /v1/git-ns/projection` shows what is published and how many
changes are pending; `GET /v1/git-ns/jobs` shows the bridge jobs. Both are on
the console.

### 8a. Add or remove a contributor

**Add.** An owner of the repository (or a namespace admin over it; a
maintainer too, if the policy sets `maintainer_grants_commit`):

```sh
cnm git grant --subject did:webvh:…:carol --right git.commit.sign \
  --resource github.com/acme/widgets --expires-in 90d --reason "widgets v2"
```

Effective on the next check run — re-run the check on an open pull request.
Committers get **no GitHub role**: they contribute through forks, and the
required check decides what lands. To give someone a role, grant
`git.repo.maintain` (§8b).

- The subject must be a **current member** under the shipped policy; anyone
  else is `git-ns:policyDenied` (`external-signers-not-enabled`). Admitting
  outside contributors is a policy change the community makes deliberately —
  for example, `git.commit.sign` only, expiring within 90 days.
- A namespace-wide grant (`--resource github.com/acme`) covers every
  repository of the namespace: every check a bridge sets up queries the
  namespace as its fallback resource. A workflow written by a bridge before
  that did not; until it is upgraded (BRIDGE.md §6b) only grants on the
  repository count there.
- What the upgraded workflows change:
  - **The forge host must match.** The workflow passes the forge host the
    bridge is configured with (`[[github]] host`, the Forgejo host) plus the
    owner the runner reports. verify-trust derives the repository's resource
    from the runner's server URL (`GITHUB_SERVER_URL`,
    `FORGEJO_SERVER_URL`). If the two hosts differ, for example a bridge
    configured with `github.com` for a GHES organisation, the fallback no
    longer contains the resource. The whole check then fails before any
    commit is verified, not only the namespace-granted commits. Configure the
    bridge with the host the runners report.
  - **Containment needs a current release.** The refusal of a fallback outside
    the repository's namespace (§2) holds only with a verify-trust release
    that has it, pinned in `[verify_trust] version`. With an older one, the
    fallback still names only the running repository's owner, but nothing
    enforces it.
  - **Forgejo:** re-running the bootstrap updates the protected workflow
    through the audited refresh (§4a). It stops early when another rule
    shadows the managed one: resolve that first.

**Remove.**

```sh
cnm git revoke --subject did:webvh:…:carol --right git.commit.sign \
  --resource github.com/acme/widgets --reason "left the project"
```

Effective on the next run. Their merged commits keep verifying
cryptographically and are not checked again; open pull requests with their
commits now fail `unauthorized`. Only recorded rights can be revoked: an
owner's commit right is implied, not recorded, so revoking `git.commit.sign`
from an owner is `git-ns/right/revoke:notGranted` — revoke the ownership
instead.

### 8b. Owners and maintainers

```sh
# a maintainer: merge and triage on GitHub (normal-class; an owner may)
cnm git grant  --subject did:…:dave --right git.repo.maintain --resource github.com/acme/widgets
# a co-owner: admin on GitHub (elevated: a community administrator)
cnm git grant  --subject did:…:erin --right git.repo.own      --resource github.com/acme/widgets
cnm git revoke --subject did:…:dave --right git.repo.maintain --resource github.com/acme/widgets
```

- **Roles follow linked accounts.** By default `own` projects to `admin`
  and `maintain` to `maintain` in an organisation (on Forgejo: `write` plus
  the merge allow-list); on a personal account both become `write`, the only
  collaborator role there. Committers get no role (fork pull requests). The
  bridge's `role_map` changes this per bridge, forge, namespace or
  repository — maintainers as `admin`, committers `write` on a repository
  that opts in ([BRIDGE.md §6c](BRIDGE.md#6c-roles-the-role-map)). A member
  with no linked GitHub account gets no role until they link (openvtc `l`).
- **A role-map change reaches the forge by re-projection.** After you change
  `role_map` and restart the bridge, it reports its map to the VTC
  (`git-ns/bridge/event` 0.3) with the repositories projected under the old
  one — and again at every reconnection to the VTC and whenever it starts
  serving a newly bound namespace, so the VTC's copy is never older than
  its link — and the VTC re-projects those by itself; the console shows the map
  each right projects to. On a bridge set to `event_version = "0.2"`, or to
  force it anyway, re-project by hand:
  `cnm git reproject --resource github.com/acme` (a namespace) or
  `--resource github.com/acme/widgets` (one repository), or **Re-project
  roles** on the console's Repos page. A community administrator or a
  namespace admin may; no right changes.
- **A repository keeps an owner.** Revoking the last one is
  `git-ns:lastOwner`; grant the replacement first. Only an owner record
  **without an expiry** counts for this, so an expiring grant cannot be the
  one that keeps it.
- **Handing over your own ownership** is
  `cnm git transfer github.com/acme/widgets --to did:…:erin` — the VTC's
  record, not a GitHub transfer (elevated).
- **Going from one owner to two**, or back, changes the owner-review guard
  (solo ↔ `CODEOWNERS` review). The bridge reports it as a `bootstrapMissing`
  drift item; revert it (§8d) to re-run the bootstrap. The required workflow
  and the bridge-posted check do not depend on the owners.
- **Archive** (`cnm git archive github.com/acme/widgets`, elevated) makes the
  repository read-only on GitHub and revokes every commit right on it. No
  task reverses it.
- **Namespace admins get no forge role.** The bridge does not project
  `git.ns.admin` — not as an organisation owner (it refuses a
  namespace-level role projection, `notCapable`) and not as a repository
  role (a desired role carrying `git.ns.admin` projects nothing), and no
  `role_map` can change that. Who owns the organisation is yours to manage.
  A namespace admin who should also hold a role on a repository needs that
  repository's right (`own`, `maintain`) in their own name.

### 8c. A member leaves

Remove them from the community as usual (the console's *Members* page,
`DELETE /v1/members/{did}`). The VTC then, on its own:

1. revokes **every git right they held**, everywhere — withdrawn from the
   registry, and their GitHub roles removed by the next role projection (a
   projection job retries until it succeeds);
2. marks each repository they owned alone **`orphaned`**, governed by the
   namespace admins until one of them names an owner
   (`cnm git grant … --right git.repo.own`);
3. removes their linked forge accounts.

**Grants they issued stay** — they were made under the community's
authority. Review them: the console lists *issued by departed members*
(`GET /v1/git-ns/rights/issued-by-departed`); revoke with `cnm git revoke`
whatever should not outlive its granter. A community that wants them gone
automatically sets `cascade_on_departure` in its `gitNamespace` policy's
`settings`; the departure sweep then revokes them too.

If the departed member was the namespace's **last admin**, it is now
headless (§8g).

Access their account has other than a direct role on the repository — an
organisation team, organisation ownership — is not the bridge's to change. A
projection that cannot take it away reports its `roles` step as failed,
naming the team or the ownership: remove it on GitHub.

### 8d. Drift: adopt or revert

The bridge compares each repository with what the VTC projects and reports
every difference as a drift item. Members see them in
`cnm git view --resource github.com/acme/widgets` (and openvtc); administrators
on the console (`GET /v1/git-ns/drift`). An owner of the repository, or a
namespace admin over it, answers each one.

| Item | Means | Adopt | Revert |
|---|---|---|---|
| `roleAdded` | an account holds a role the rights do not give | records it as a right (below) | removes the direct role (`git-ns/bridge/job` 0.2 `removeAccounts`) |
| `roleChanged` | a role other than the projected one | if it raises a linked member: records the higher right | re-sends the complete desired roles |
| `roleRemoved` | a projected role is gone | — | re-sends the complete desired roles |
| `requiredCheckMissing` | the ruleset no longer requires the check | — | re-runs the `requiredCheck` bootstrap step |
| `protectionWeakened` | bypass actors, force-push, an unprotected check source, Actions disabled, … | — | re-runs the `requiredCheck` bootstrap step |
| `bootstrapMissing` | the plan must change (owner count, org rulesets gained) | — | re-runs the whole bootstrap |

A required check that disappears is put back without anyone asking: the VTC
re-runs the `requiredCheck` step as soon as the bridge reports it. Role drift
is only reported, unless the policy sets `role_drift = "enforce"`.

**Revert** changes no right and has the bridge undo the forge change:

```sh
cnm git drift resolve github.com/acme/widgets revert --type roleAdded \
  --account-id 5550123 --account-login eve-dev
cnm git drift resolve github.com/acme/widgets revert --type protectionWeakened
```

A role item is selected by the account's **numeric id** (`--account-id`, as
`git view` shows it), never by login. Reverting an `admin` role has the
impact of revoking `own`, and is elevated.

**Adopt** records the forge-side role as a right, evaluated exactly as a
grant from you — the same fixed rules, policy (seen as `right.grant` with
`via: "drift.adopt"`) and consent class. It needs the value you read, so a
forge that changed since adopts nothing:

```sh
cnm git drift resolve github.com/acme/widgets adopt --type roleAdded \
  --account-id 5550124 --account-login dave --observed maintain
```

Adoptable: a `roleAdded`, or a `roleChanged` that raises the member, held by
an account **linked to a current member**, at a role a right projects to —
`admin` → `git.repo.own`, `maintain` → `git.repo.maintain`, and on a personal
account `write` → `git.repo.maintain`. `write` in an organisation, `triage`
and `read` project nothing and cannot be adopted: revert them.

Every resolution is followed by an inspection, so it is confirmed rather than
assumed. Refusals are in §8k.

### 8e. Dependabot pull requests

**The bridge re-signs them** with its own DID when Dependabot alone has
pushed to the branch since creating it, the pull request comes from the same
repository and targets the default branch, and no commit touches
`.github/workflows/` (BRIDGE.md §6a has every condition). It needs
`platform_keyring_file` set, the App subscribed to `push`, and the bridge's
service grant in the registry. After a re-sign Dependabot stops rebasing:
comment `@dependabot rebase`, and the bridge re-signs the result. Turn it off
for a namespace with `[github.namespaces.<owner>] resign_dependabot = false`
in the bridge config.

When the check still fails, its summary (bridge-posted) or the job's
`PLAT-EDIT` lines say which commits. The usual causes:

- **The pull request changes a workflow** (`github-actions` updates). Never
  re-signed: the bridge will not vouch for what CI runs, and its App has no
  `workflows` permission to push such a change anyway.
- **Someone else pushed to the branch**, or the bridge missed a push while it
  was down: the record is broken. Close the pull request and delete the
  branch; Dependabot opens it afresh and the bridge re-signs the new one.
- **The re-signed commits fail `unauthorized`.** The bridge's service grant
  is missing (its log warns, naming the namespace), or the repository's
  workflow predates the namespace fallback — it queries only the repository,
  not the namespace the grant is on. Upgrade the workflow (BRIDGE.md §6b).

**Re-signing by hand.** A maintainer who is an enrolled signer reviews the
change, then re-signs only the refused commits (the reasoning is in §5):

```sh
gh pr checkout <number>
git rebase -i origin/main
#   after the `pick` of each refused commit, add:
#   exec git commit --amend --no-edit -S
git push --force-with-lease
```

GitHub refuses a push that changes `.github/workflows/` from a credential
without the `workflow` scope: with `gh` as the git credential helper, run
`gh auth refresh -s workflow` first. In an owner-review repository the change
to `.github/` then needs another owner's approval, which is the point.
Dependabot will not update the pull request after your push;
`@dependabot recreate` starts it over (and discards the re-sign).

### 8f. GitHub App permission upgrades

A manifest change reaches only new App registrations. When a release adds a
permission or an event — the bridge-posted check (Checks, Pull requests,
Merge queues; `pull_request`, `merge_group`, `check_run`, `check_suite`), the
Dependabot re-sign (`push`) — an existing App keeps working with what it has,
and the bridge says what it lacks: in its log, on the console's namespace card
(*missing permissions*, *permission upgrade pending*), and in
`cnm --json git namespace list` (`forgeStatus.missingPermissions`,
`forgeStatus.permissionUpgradePending`).

1. On the App's settings page (*Permissions & events*) add what is missing,
   and save.
2. An organisation owner accepts the new permissions on the installation
   (GitHub shows a banner there).
3. GitHub tells the bridge (`installation` `new_permissions_accepted`); it
   reads the installation again, and each repository moves to the new mode
   at its next inspection.

A newly subscribed `push` re-signs only Dependabot branches created after it.
The detail of each upgrade is in BRIDGE.md §3.

### 8g. A headless namespace: reseat

A namespace whose every `git.ns.admin` has left the community or lapsed is
**headless**: nobody can adopt, name an owner for an orphaned repository, or
grant namespace rights. The console and `GET /v1/git-ns/namespaces` flag it
(`headless`). A community administrator restores it:

```sh
cnm git reseat ns_… --subject did:webvh:…:alice \
  --statement "Both admins left in the September reorganisation; Alice leads infra."
```

It grants a current member a **permanent** `git.ns.admin`, with the statement
as its reason, and the audit record keeps the statement and how each earlier
admin record ended. While any live admin record of a current member remains
it is refused `git-ns/namespace/reseat:notHeadless` — that admin grants
instead — so it cannot be used to go around an admin.

Prevent it: keep **two admins without an expiry**. The last-admin invariant
counts only those, but a departure can still take the last one.

### 8h. Transfers, renames and a reused name

The VTC keys repositories by the forge's **numeric id**, not by name.

- **Renamed within the namespace:** the rights move with it (`repoRenamed`).
  The old name's registry records are withdrawn before any are published
  under the new one.
- **Transferred out** — to another organisation, another forge, or another
  namespace this same VTC governs: the repository is **detached** and every
  right on it withdrawn (`repoTransferred`). Rights never move with it; the
  receiving namespace's admins granted none of them. If this bridge serves the
  destination, the repository appears there as **unmanaged**, and its admins
  adopt it and grant afresh:

  ```sh
  cnm git adopt github.com/acme-labs/widgets --owner did:…:alice
  ```

- **A new repository at a governed name** (created or transferred in, with a
  different forge id): the governed one went without an event, so it is
  detached, and the newcomer is reported unmanaged. It inherits nothing.
- **Deleted on GitHub:** detached (`repoDeleted`), its rights withdrawn.
- **Reusing a name:** creating or adopting at a name whose earlier records
  are still being withdrawn from the registry is refused `unavailable`
  (*… are still being withdrawn from the Trust Registry; retry once they are
  gone*). Retry after a projector pass.

`cnm git transfer` is none of these: it hands ownership over in the VTC's
records and moves nothing on GitHub.

### 8i. The bridge: backup, restore, restart

**A bridge in VTA mode** (BRIDGE.md §2a) keeps its DID, keys, secrets and
state in its trust context of the VTC's VTA. There is nothing on its host to
back up, and a lost host is recovered by:

1. revoking the old host's context credential in the VTA, and issuing a new
   one (an admin scoped to the bridge's context only);
2. putting it on the new host (`credential_file`, owner-only) with the same
   config and an **empty** data directory;
3. `vgi-bridge vta setup`, then starting the bridge.

It comes back as the same DID with its namespaces, managed repositories,
required-workflow pin and App credentials: no rebind, no unbind, no rights
change, no App re-registration. What it loses: jobs in flight (the VTC sends
unfinished ones again), unacknowledged results (the VTC repeats their jobs),
binds and account links waiting for a person (start them again), and the
provenance of Dependabot branches pushed to while the VTA was unreachable.

The rest of this section is the self-contained mode. Everything is in
`data_dir/state.redb`, sealed with the master key (BRIDGE.md §5).

- **Back up** the file and the key **separately**. For a consistent copy,
  stop the bridge (or snapshot the volume) and copy the one file.
- **Restore:** stop the bridge, put the file back, start it with the same
  master key. It re-sends every result and event the VTC had not
  acknowledged; the VTC repeats its own unfinished jobs, which the bridge
  answers from its job ledger rather than running twice.
- **Restart** needs nothing: the bridge hands its adapters the managed
  repository set and the required-workflow pin back from the store. If a
  restored store is older than the organisation's `VGI required workflow`
  ruleset (the pin moved after the backup), inspections report the pin as
  unverified — critical drift — until the required-workflow step runs again:
  revert the item (§8d).
- **What a restore loses:** Dependabot branches created after the backup
  have no provenance record, so they are not re-signed until Dependabot
  recreates them; a Forgejo bot token rotated after the backup is not in the
  store (§8j).
- **The identity** is worth keeping even when the store is not: `vgi-bridge
  identity export` once (BRIDGE.md §5), `identity import` into a fresh store,
  and the bridge keeps the DID the VTC recorded for its namespaces.
- **Losing the store, or the key,** of a self-contained bridge means
  registering a new GitHub App and
  binding again — and there is no re-attach. The VTC still holds the
  namespace as bound to that bridge, and binding it again needs
  `cnm git namespace unbind` first, which **revokes every right in the
  namespace** and detaches every repository; everything is then granted and
  adopted afresh. Back the store up — or move the bridge to VTA mode, which
  does not have this limit.

The VTC's own backup (VTI `docs/03-vtc/backup-restore.md`) carries the
git-namespace records; its bridge-job queue and the registry-projection mirror
are not backed up. The projector rebuilds the mirror from the registry at
start. A change whose job was lost shows up as drift at the repository's next
inspection.

### 8j. Rotating the Forgejo bot token

**Automatically:** set `rotate_token_days` in the `[[forgejo]]` entry and
store the bot's password (`vgi-bridge secret set forgejo/<host>/bot-password`;
the bot must not use two-factor auth). The bridge looks hourly; the first
look only starts the clock. It mints a new token, checks it is the bot's,
seals it, and only then deletes the old one — a crash in between leaves an
extra live token (its name starts `vgi-bridge-`; delete it on the bot's
*Settings → Applications*), never a dead credential.

**By hand:**

1. As the bot, create a token with the scopes `write:organization` and
   `write:repository`.
2. Stop the bridge; `vgi-bridge secret set forgejo/<host>/bot-token` (reads
   standard input); start it. The bridge reads its secrets at start.
3. Delete the old token on the bot's *Settings → Applications*.

Delete the old token before the new one is in place and every job fails
(`forbidden`) until it is. The same `secret set` replaces the OAuth client
secret or the webhook secret; change the webhook secret on the
organisation's webhook at the same time, or deliveries fail verification.

### 8k. Troubleshooting

**Check verdicts** in a managed repository. The general cause and fix of each
are in §5; this is what they usually mean here.

| Verdict | Usually | Fix |
|---|---|---|
| `trusted`, `exempt` | passes | — |
| `unsigned` | signing not set up on that machine | `did-git-sign health`; commit again |
| `malformed` | the signature is not an Ed25519 sshsig (an RSA or ECDSA SSH key, or corrupt) | sign with `did-git-sign`; amend |
| `noSignerDid` | the commit-msg hook did not run, or is older than v2 | `did-git-sign health`, re-run `init`; amend |
| `conflictingSignerDids` | a carried-over `Signed-by-DID:` trailer | amend so one claim remains |
| `unresolvedSigner` | the signer's DID document is unreachable, or names a non-public host (refused, never fetched) | fix the DID's hosting |
| `unknownKey` | signed with a key the DID does not publish — most often one rotated out since | re-sign with the current key (§5); if it never was the DID's key, `did-git-sign init` for the right key |
| `badSignature` | the commit changed after it was signed | re-sign |
| `unauthorized` | no right on this repository or its namespace: never granted, revoked, lapsed, the member left — or a namespace-level right (a namespace admin's, the bridge's re-signed Dependabot commits) under a workflow that predates the namespace fallback (§8a, §8e) | `cnm git view --resource <repository>`; grant on the repository; upgrade the workflow (BRIDGE.md §6b) |
| `registryUnavailable` | the registry could not be asked | a registry outage, or a registry mediator that refuses the throwaway DID (TSP/DIDComm) — `transport: https` until it is configured; the check fails closed by design |
| `pgpRejected` | a PGP signature from a key not in the exempt keyring | set `platform_keyring_file` in the bridge config (GitHub's current `web-flow.gpg`) |
| `platformSignedEdit` | a web-UI edit, a squash merge, a Dependabot commit not re-signed | re-sign (§8e); merge with merge commits |
| `platformMergeUnverifiedParent` | a GitHub-signed merge over a failing parent | fix that parent |
| `platformMergeAltered` | conflicts resolved in the web editor | merge locally and sign with `did-git-sign` |

Under the bridge-posted check, a check that never appears means the bridge is
down or its App lacks the check permissions (§8f). *No commits were verified*
and *The head is already part of `main`* are failures by design.

**VTC refusals** — what `cnm`, openvtc and the console report; `cnm` adds the
fix where one applies.

| Code | Cause | Fix |
|---|---|---|
| `git-ns/namespace/bind:noBridge` | no `[git_ns] bridges` entry for the forge host, or the VTC not restarted since | add it and restart the VTC; or bind `--mode manual` |
| `git-ns/namespace/bind:alreadyBound` | bound, or a bind is pending | `cnm git namespace list`; a pending bind is dropped after 24 h |
| `git-ns:namespaceNotBound` | the bind has not completed | finish the step at the URL `namespace bind` printed |
| `git-ns:unknownNamespace` | no bound namespace contains the resource, or no namespace has that id | a forge-qualified, lowercase resource; ids from `namespace list` |
| `git-ns:unknownRepo` | the VTC records no repository there | `cnm git adopt` it |
| `git-ns:repoNotActive` | the repository is pending, archived or detached | `cnm git repos` for its state |
| `git-ns:scopeViolation` | the resource lies outside what the right can cover (another namespace or forge, a namespace right on a repository) | name the right resource |
| `git-ns:escalation` | granting more than you hold, or re-delegating `repo.create` | someone who holds it grants; `cnm git view` shows yours |
| `git-ns:membersOnly` | a namespace right (`ns.admin`, `repo.create`) for a non-member | members only — a fixed rule |
| `git-ns:policyDenied` | the community's `gitNamespace` policy refused (`not-a-member`, `external-signers-not-enabled`, or its own code) | a policy change, if the community wants one |
| `git-ns:lastOwner` / `git-ns:lastAdmin` | it would leave no owner / no admin without an expiry | grant the replacement first |
| `git-ns/right/revoke:notGranted` | no live record matches — often an implied right | revoke the right that implies it |
| `git-ns/right/grant:expiryInPast` | the expiry is in the past | a future one |
| `git-ns/repo/create:nameTaken` | the VTC records a repository at that name | `cnm git view --resource …` |
| `git-ns/repo/adopt:alreadyManaged` | it is governed already | nothing to do |
| `git-ns/repo/transfer:notOwner` / `selfTransfer` | you hold no ownership record to hand over / you named yourself | a namespace admin grants `own` instead |
| `git-ns/drift/resolve:driftNotFound` | resolved already, or the forge changed since you read it | read it again with `git view` |
| `git-ns/drift/resolve:notAdoptable` / `accountNotLinked` / `noMatchingRight` | the item records no right: a protection item; `write`, `triage` or `read`; an unlinked account; a role no higher than one held | revert it — or, to accept a lowering, revoke the right |
| `git-ns/drift/resolve:notRevertible` | manual mode; or the account is a member's and the projection gives it a role there; or the bridge implements only job 0.1 | undo it on the forge; revoke the member's right; upgrade the bridge |
| `git-ns/namespace/reseat:notHeadless` | a live admin remains | that admin grants `git.ns.admin` |
| `git-ns/account/link:unsupportedForge` | no bridge-mode namespace on that forge | bind one in bridge mode |
| `git-ns/account/link-status:unknownLink` | the link attempt is unknown, or forgotten (after 7 days) | start again (`l`) |
| `permissionDenied` | the signer lacks the right; or an elevated or destructive action from someone who is not a community administrator (`elevated_requires_admin`); or a bind or reseat without the community-administrator capability | a community administrator does it |
| `malformedRequest` | a DID that is not DID-core (`did:<method>:<id>`, the id only letters, digits, `.` `-` `_` `:` and `%`-escapes — no fragment, spaces or shell characters); a resource that is not forge-qualified; an unknown right | fix the value; `cnm` refuses these before signing |
| `unavailable` | the bridge did not answer an in-line job (bind, link), or refused it — the message carries its code, e.g. `noMatchingProtocol` (no DIDComm service in the bridge's DID document: a `did:key` from an earlier release — `vgi-bridge identity mint --replace --backup <file>` — or a `did:webvh` whose template lacks it); earlier records at the name still being withdrawn (§8h); **two governed repositories recorded at one name** | check the bridge and its DID document, retry; for two at one name, below |

*Two governed repositories at one name* is refused rather than guessed at
(*N governed repositories are recorded at …; an administrator must resolve
which one it is*). No task resolves it today; the console's repository list
shows both. Report it: events alone should not produce it.

**Bridge job failures** — the console's job list and a repository's step
outcomes (`GET /v1/git-ns/jobs`, `GET /v1/git-ns/repos`).

| Code | Cause | Fix |
|---|---|---|
| `git-ns/bridge/job:notCapable` | the bridge cannot do it here: no adapter for the host (App not registered), `createRepo` on a personal account or in manual mode, a namespace-level role projection | the message says which: register the App; create by hand (`vgi repo init` in manual mode) and adopt; manage organisation roles yourself |
| `git-ns:unknownNamespace` (from the bridge) | the bridge has no such namespace — its store was lost, or restored from before the bind (self-contained mode) | §8i |
| VTA-mode start refused: "rolled back or replayed", "has no record of … not even a deletion", or a secret "does not open … at the version it is stored at" | the context's app-state went back in time, or someone other than the bridge rewrote it | restore the VTA's current state or recreate the context; re-set the secret; revoke credentials that are not the bridge's |
| bind fails `notCapable` ("not bound") for an organisation on a host with several Apps | no `[[github]]` entry (and registered App) for that organisation: add one and register its App (BRIDGE.md §3) | — |
| bridge `/healthz` 503, log "another bridge … is writing the same VTA context" | two hosts (or a stolen credential) on one bridge context; the bridge stopped writing its state and holds its results | §8i; BRIDGE.md §2a |
| bridge `/healthz` 503 "state not reaching the VTA: N change(s) waiting" | every write to the VTA has failed for five minutes: the VTA unreachable, or its app-state lease kept by another writer (logs: "another writer holds the bridge's app-state lease") | bring the VTA back; if the lease is the cause, find the other writer on the context and stop it (revoke the credential if it is not yours) |
| `git-ns/bridge/job:jobIdReused` | a job id came again with other content | a VTC fault; report it |
| step `forbidden` | the App lacks a permission or was uninstalled; a Forgejo token revoked | §8f; reinstall; §8j |
| step `notFound` | the repository is gone, or outside the installation's repository selection | an inspection that finds nothing detaches it; install the App on *All repositories* |
| step `nameTaken` | the name exists on the forge already | adopt it, or pick another name |
| step `rateLimited` | the forge's rate limit | the job is retried |
| step `forgeError` | anything else the forge refused (the detail says what) | read the detail; jobs are check-then-apply, so sending again is safe |
| a `roles` step fails naming a team or organisation ownership | the direct role went; access remains through the team or ownership | remove it on the forge |
| events refused as an unsupported type | a VTC older than `git-ns/bridge/event` 0.3 (the bridge's default) | update the VTC, or `event_version = "0.2"` (or `"0.1"` for a VTC older than 0.2) meanwhile; the VTC is then not told the role map (BRIDGE.md §7) |

[vti]: https://github.com/OpenVTC/verifiable-trust-infrastructure
