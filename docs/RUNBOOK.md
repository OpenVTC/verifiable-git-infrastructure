# VGI operator runbook

Activating commit trust on a repository, end to end. Read this if you run the
Trust Registry, the VTA, or the repositories the check protects.

The shape to hold in your head: **VGI verifies, the VTC decides.** A commit
names its signer DID on its own `committer` header; `verify-trust` proves that
DID signed it, then asks the registry whether that DID is authorized. Who may
sign, key rotation, and revocation are registry and VTA concerns — nothing
about them lives in the repository.

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

**Registry endpoint discovery.** There is no `registry-url` to set. The
endpoint comes from the registry's own DID document, which advertises one
service entry per binding it serves:

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
and the verifier: **TSP → DIDComm → HTTPS**. `verify-trust` is built with
`trql-client`'s default features, so today it can construct only HTTPS and
selects that; if your registry advertises none of what the verifier speaks, the
run fails naming both sides' transports rather than downgrading quietly.

Note the `#tsp` and `#didcomm` endpoints are **mediator DIDs**, not URLs — a
consumer of those bindings resolves a second hop. Only `#rest` carries a URL.

`registry-url` remains as an override for a registry that publishes no service
entry (local, dev). Prefer discovery: over HTTPS the registry's reply is
unsigned — `registry-did` is only stamped on the *outgoing* request as
`recipient` — so trust in the answer rests on reaching the right host. Two
independently settable values that nothing cross-checks is exactly the gap an
override reintroduces.

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
- **Dependabot pull requests** fail until a maintainer re-signs them (§5).

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
critical drift.

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
| `noSignerDid` | signed, but no DID in the trailer or committer | the `commit-msg` hook did not run — `--no-verify`, or `core.hooksPath` taken by another tool; check `did-git-sign health`, then re-run `init` |
| `conflictingSignerDids` | `Signed-by-DID:` trailer and DID committer name different identities | a hand-written trailer, or a rebase carrying an old one; amend so one claim remains |
| `unresolvedSigner` | the claimed DID would not resolve | DID document unreachable, or publishes no Ed25519 method |
| `unknownKey` | the claimed DID publishes no such key | signed by a key that identity does not hold |
| `badSignature` | key is published, signature fails | the commit was altered after signing |
| `unauthorized` | valid signature, registry says no | no grant — issue one, or the signer was revoked |
| `registryUnavailable` | the registry could not be consulted | registry outage; the check fails closed by design |
| `pgpRejected` | PGP-signed by no key in the exempt keyring | no keyring configured, or a platform key other than the committed one |
| `platformSignedEdit` | signed by the platform key, but not a merge: a web-UI or API edit, a squash merge, a Dependabot commit | re-sign it with `did-git-sign` (below); for squash merges, merge with a merge commit instead |
| `platformMergeUnverifiedParent` | platform-signed merge with a parent (named) that neither passes nor is on the base branch | fix the named parent; the merge cannot vouch for it |
| `platformMergeAltered` | platform-signed merge whose tree is not the clean merge of its parents | conflicts resolved in the web UI; merge locally and sign with `did-git-sign` |

`exempt` is a clean, platform-signed merge commit whose parents all pass (see
*Platform keyring* in §4).

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
comment `@dependabot recreate` to start over. A VGI bridge bot that re-signs
Dependabot pull requests is planned. Dependabot commits are refused
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
rather than by key.

**Retire a repository.** Nothing to clean up in the repo; drop the grants whose
resource named it.

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

**Squash and rebase merges rewrite commits.** The result is signed by
`web-flow` and passes via the exempt keyring, not as `trusted`. That is
expected: the DID-signed commits in the pull request are what got verified.

[vti]: https://github.com/OpenVTC/verifiable-trust-infrastructure
