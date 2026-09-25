# Running the VGI bridge

The bridge is the one service that holds a community's forge credentials —
its own GitHub App key, its Forgejo bot's token — and acts on the forges for
its VTC (design §5.7). Each community runs its own, next to its VTC. This
guide is for the operator who deploys it.

The shape to hold in your head: **the VTC decides, the bridge acts.** The
VTC sends `git-ns/bridge/job`s over DIDComm; the bridge changes the forge,
answers with exactly one `git-ns/bridge/result` per job, and reports what it
sees happening on the forge as `git-ns/bridge/event`s. It serves exactly one
VTC and refuses a job signed by anyone else.

Setting up a namespace end to end — the VTC's `[git_ns]` config, binding,
rights, members, the first repository — is
[SETUP-GITHUB-VTC.md](SETUP-GITHUB-VTC.md); operating one day to day
(people, drift, restores, troubleshooting) is
[RUNBOOK.md §8](RUNBOOK.md#8-operating-a-vtc-managed-namespace). This guide is
the bridge itself.

---

## 1. What it needs

| | Why |
|---|---|
| A **DID** for the bridge | the VTC records which bridge serves a namespace and accepts results and events only from it |
| The **VTC's DID** and **mediator DID** | the bridge accepts jobs only from that DID, over DIDComm through that mediator |
| The **Trust Registry's DID** | written into every bootstrapped repository, and used by the check the bridge posts itself |
| A **public HTTPS URL** behind a TLS-terminating proxy | the forges send App-setup and OAuth redirects and signed webhooks to it |
| A **master key** (32 bytes, base64) | seals every secret in the store; from a file, or an environment variable that the bridge clears once read |
| A writable **data directory** | one redb file, `state.redb` |
| `git` on the path (the container has it) | the bridge-posted check fetches commit objects — never runs anything from them |

### Network

Inbound (through your proxy, HTTPS only):

| Path | From |
|---|---|
| `POST /github/<host>/webhook`, `POST /forgejo/<host>/webhook` | the forges |
| `GET /github/<host>/register`, `/registered`, `/setup` | admins' browsers, redirected by GitHub |
| `GET /forgejo/<host>/bind`, `/link` | admins' and members' browsers, redirected by Forgejo |
| `GET /healthz` | your orchestrator (keep it internal) |

Outbound:

- the **mediator** (websocket) — the DIDComm link to the VTC;
- the **forges' APIs** (`api.github.com` / your GHES, your Forgejo
  instances) and, for the check, their git endpoints (HTTPS fetch);
- **DID resolution** for the VTC's DID (`did:webvh` / `did:web` hosts), and —
  for the bridge-posted check — for the registry's DID and the DIDs commits
  claim. Signer DIDs are resolved under verify-trust's public-hosts-only
  policy: a DID naming an internal host is refused, not fetched;
- the **Trust Registry**'s `#rest` endpoint, for the bridge-posted check.

Terminate TLS at the proxy; the bridge speaks plain HTTP/1 behind it and
refuses to start with a `public_url` that is not `https`. Keep the proxy's
own body limit at or above `max_body_bytes` (default 2 MiB), so the bridge's
limit is the one that answers.

## 2. First start

```sh
# 1. Config: start from crates/vgi-bridge/bridge.example.toml.
cp bridge.example.toml /etc/vgi-bridge/bridge.toml

# 2. The master key and the bridge's identity. `init` writes the key file
#    named by `master_key_file` (0600, never overwritten) and, if the store
#    has no identity, mints a did:peer whose document names `mediator_did`.
#    It prints the DID.
vgi-bridge --config /etc/vgi-bridge/bridge.toml init

# 3. Back the identity up apart from the store (see §5).
vgi-bridge --config /etc/vgi-bridge/bridge.toml identity export /secure/bridge-identity.json
```

**A `did:webvh` identity instead** (recommended for production, the same way
the VTC's is provisioned): provision a DID for the bridge from the
community's VTA with a DID template that has an Ed25519 signing key and an
X25519 key-agreement key, export its secrets bundle, and import it:

```sh
vgi-bridge --config /etc/vgi-bridge/bridge.toml identity import bundle.json
shred -u bundle.json
```

Register the printed DID at the VTC as the bridge serving its namespaces:
the VTC's `[git_ns] bridges` maps each forge host to it.

The VTC reaches the bridge through a transport the bridge's DID document
advertises: it resolves the DID and needs a `DIDCommMessaging` service naming
the mediator the bridge listens at. Both identities carry one:

- **The `did:peer:2` `init` mints** encodes its keys *and* that service in
  the identifier, so there is nothing to host. The flip side: the mediator is
  part of the DID. Change `mediator_did` and the bridge refuses to start
  rather than have the VTC deliver jobs where it no longer listens. For a
  bridge serving bound namespaces the fix is to set `mediator_did` back: a new
  DID is a different bridge (below). `init` refuses a mediator whose own DID would make the `did:peer`
  longer than the 1000 bytes DID resolvers accept.
- **A `did:webvh`** publishes the service in its document (the VTA template
  adds it), and can move mediators without changing DID.

A store from an earlier release may hold a `did:key`, which advertises no
service: no VTC can send it jobs (they fail `noMatchingProtocol`). `run` warns
about it at start; mint a `did:peer` in its place (`identity mint --replace
--backup <file>`) and register that.

**Replacing the identity is not a key rotation.** `identity mint --replace`
and an `identity import` of a different DID write the current identity to
`--backup <file>` first (required), and refuse — listing them — while the
store holds namespaces bound or being bound to it, or when the current DID
is one the bridge did not mint (a VTA-provisioned `did:webvh`), unless given
`--abandon-current-did`. What a new DID breaks: the VTC's `[git_ns] bridges`
must name it; the VTC accepts a namespace's results and events only from the
DID it bound, so those namespaces are no longer served; the registry's
`git.commit.sign` service grant is held by the old DID, so Dependabot commits
the new one re-signs fail the check; and with no re-attach yet, binding them
again needs an unbind, which revokes every right in them.

The admin commands (`init`, `identity`, `secret`) open the store directly,
and redb allows one process at a time: stop the bridge first.

### The container

```sh
docker build -f crates/vgi-bridge/Dockerfile -t vgi-bridge .
docker run -d --name vgi-bridge \
  -v /etc/vgi-bridge:/etc/vgi-bridge:ro \
  -v vgi-bridge-data:/var/lib/vgi-bridge \
  -v /run/secrets/vgi-bridge-master-key:/run/secrets/vgi-bridge-master-key:ro \
  -p 127.0.0.1:8080:8080 vgi-bridge
```

Run `init` / `identity import` / `identity export` with the same volumes and
`vgi-bridge init` as the command before the first `run`.

## 3. GitHub: register the App (manifest flow)

One App per community, registered by the bridge itself so nobody copies a
key by hand.

1. Set `app_owner` (required) to the organisation that will own the App —
   or to your account, with `app_owner_is_user = true`. Optionally put
   GitHub's `web-flow` key where `platform_keyring_file` says:
   `curl -fsSL https://github.com/web-flow.gpg > /etc/vgi-bridge/web-flow.asc`.
   It is the exempt keyring for commits GitHub signs (web-UI merges, merge
   queues). The in-repo and required-workflow plans refuse to plan without
   it; the bridge-posted check works without it, and then fails any
   platform-signed commit.
2. Start the bridge. With no App registered for a configured host, it logs
   a **one-time registration URL** (valid 24 hours):
   `…/github/github.com/register?state=…`.
3. An owner of the `app_owner` organisation opens it. The page posts the
   manifest to GitHub; they approve it; GitHub redirects back to
   `/github/github.com/registered`, and the bridge exchanges the code for the
   App's id, private key and webhook secret, **seals them**, and puts the
   adapter in service. It refuses an App registered under another account,
   a public App, or one with any permission beyond the reviewed set. If the
   exchange fails (GitHub unavailable, say), open the same link again: it is
   spent only once the App is registered.
4. **Enable Device Flow** on the App's settings page (the manifest format
   cannot): *Settings → Developer settings → GitHub Apps → the App → Enable
   Device Flow*. Members link their accounts with it.

The App asks for: repository Administration, Contents, Variables and Checks
(write), Metadata, Pull requests and Merge queues (read); organisation
Members (read) and Administration (write); and the events
`branch_protection_rule`, `check_run`, `check_suite`, `member`,
`membership`, `merge_group`, `organization`, `pull_request`, `push`,
`repository`, `repository_ruleset`. Organisation Administration is for the
org ruleset that makes verify-trust a required workflow; Checks, Pull
requests, Merge queues and the `pull_request` / `merge_group` / `check_*`
events are for the check the bridge posts itself where there is none (§6);
`push` (delivered under Contents) is the provenance record the Dependabot
re-sign acts on, and Contents (write) is also what it pushes the re-signed
commits with (§6a). No secrets, Actions logs, code scanning or packages.

### Upgrading an App registered before the bridge-posted check

A manifest change does not reach an App that already exists: GitHub only
applies it to new registrations. Until the App has Checks (write), Pull
requests and Merge queues (read) and the `pull_request` and `merge_group`
events, the bridge **keeps the in-repo Actions workflow** for namespaces
without a required workflow, and says so in its log and in the bind's
`missing_permissions`. To upgrade:

1. On the App's settings page (*Permissions & events*), add those
   permissions and subscribe to `pull_request`, `merge_group`, `check_run`
   and `check_suite`. Save.
2. An owner of each organisation (or account) the App is installed on
   approves the new permissions (GitHub shows a banner on the installation).
3. GitHub tells the bridge (`installation` `new_permissions_accepted`); the
   bridge reads the installation again and switches the namespace to the
   bridge-posted check. Each repository's next inspection reports its
   ruleset as drift (the check is still pinned to Actions), and the VTC's
   bootstrap job moves it over: the ruleset is pinned to the App and the
   in-repo workflow removed.

### Upgrading an App registered before the Dependabot re-sign

An App registered before `push` was in the manifest receives no pushes, so
the bridge never sees a Dependabot branch as clean and **re-signs nothing**
(Dependabot pull requests fail the check, as they would without a bridge).
Nothing else changes. To turn it on, subscribe the App to the `push` event
on its settings page (*Permissions & events*; it needs no new permission —
Contents is already granted) and save. Only branches created after that are
re-signed: an older branch has no record of its creation, so close its pull
request and delete the branch and Dependabot opens it afresh.

**Binding a namespace** starts at the VTC (`git-ns/namespace/bind`): the VTC
sends the bridge a `beginBind` job, the admin follows the `next` URL to the
App's install page, and GitHub's redirect to `/github/<host>/setup` completes
it. The bridge probes whether the organisation has org rulesets (the
required-workflow guard) and records the answer.

## 4. Forgejo: the bot

Forgejo has no App: the bridge acts as a bot user.

1. Create a user for the bot (`acme-vgi-bot`), without two-factor auth if
   the bridge is to rotate its token.
2. Create an access token for it with the scopes `write:organization` and
   `write:repository` (the adapter's `BOT_TOKEN_SCOPES`).
3. Create an OAuth2 application (confidential) with the redirect URIs
   `https://<public_url>/forgejo/<host>/bind` and
   `https://<public_url>/forgejo/<host>/link`. Its client id goes in the
   config.
4. Store the secrets (read from standard input, sealed immediately):

   ```sh
   vgi-bridge secret set forgejo/codeberg.org/bot-token
   vgi-bridge secret set forgejo/codeberg.org/oauth-client-secret
   vgi-bridge secret set forgejo/codeberg.org/webhook-secret
   # only for automatic rotation (`rotate_token_days`):
   vgi-bridge secret set forgejo/codeberg.org/bot-password
   ```

The bind (an org owner signing in through the OAuth app) adds the bot to a
`vgi-bridge` team and creates the org webhook to
`/forgejo/<host>/webhook`, signed with the webhook secret.

**The runner label.** The workflow the bootstrap writes
(`.forgejo/workflows/verify-trust.yml`) asks for `runs-on: docker` unless the
`[[forgejo]]` entry names another label — whatever the instance's runners
register:

```toml
[[forgejo]]
base_url = "https://git.example.org/"
# …
runs_on = "ubuntu-24.04"   # default "docker"; letters, digits, `-`, `_`, `.`
```

The job image needs glibc 2.39+ (Ubuntu 24.04, Debian 13) for the
verify-trust Linux binary. A bad label fails the start. A change applies to
new bootstraps; a repository bootstrapped under the old label keeps it until
its bootstrap runs again, which rewrites the protected workflow through the
audited `refresh-managed-files` step (RUNBOOK §4a).

**Token rotation**, when `rotate_token_days` is set and the password is
stored, runs in two phases: mint a new token (verified to be the bot's), seal
it, and only then delete the old one. A crash in between leaves an extra live
token (delete it by hand; its name starts `vgi-bridge-`), never a dead
credential. Rotating by hand: [RUNBOOK.md §8j](RUNBOOK.md#8j-rotating-the-forgejo-bot-token).

**Limit (documented, not closed):** Forgejo commit statuses cannot be pinned
to a poster, so repository writers are trusted not to forge a status. The
protected workflow paths keep a pull request from rewriting its own check.

## 5. What the bridge keeps, and backups

Everything is in `data_dir/state.redb`:

| What | Why it must survive |
|---|---|
| The job ledger | `jobId` idempotency: a repeated job is answered from here, never run twice; results wait here until the VTC acknowledges them |
| Namespaces | the binding each VTC namespace id maps to; capabilities; on GitHub the managed repository set and the required-workflow pin, which the adapter refuses org-mode steps without |
| Repositories | forge ids, owners and projected roles — the projection drift is measured against |
| Pending flows | binds and links waiting for a person |
| Sealed secrets | the identity, the App key and secrets, Forgejo tokens — ciphertext only |
| The provenance ledger | every push to each `dependabot/*` branch since its creation; the Dependabot re-sign acts only on an unbroken record (§6a), so after losing it, open Dependabot pull requests are not re-signed until Dependabot re-creates their branches |

**Back up `state.redb` and the master key separately.** The store is
useless without the key, and the key must never sit in the same backup as
the store. For a consistent copy, stop the bridge (or snapshot the volume)
and copy the single file. After a restore the bridge re-sends every
unacknowledged result and event; the VTC treats repeats as harmless, and
repeats its own jobs, which the bridge answers from the ledger.

**Back the identity up too, once, apart from both:** `vgi-bridge identity
export <file>` writes its secrets bundle (0600, never over an existing file),
and `identity import <file>` puts it into a fresh store. The VTC records each
namespace's bridge by DID and accepts results and events only from it, the
registry holds the bridge's `git.commit.sign` grant under it, and the
Dependabot commits it re-signed name it — so a bridge that keeps its DID is
still the one the VTC bound. (A VTA-provisioned `did:webvh` can instead be
exported from the VTA again.)

Losing the store entirely — even with the identity restored — still means
re-registering the GitHub App and re-binding the namespaces, and re-binding
means unbinding first, which revokes every right in them
([RUNBOOK.md §8i](RUNBOOK.md#8i-the-bridge-backup-restore-restart)).

## 6. The check the bridge posts itself

Where GitHub offers no org required workflow — personal accounts, and
organisations on plans without org rulesets — a check pinned to the GitHub
Actions App is forgeable by any writer (a workflow on another branch can post
a passing "Verify commit trust" onto someone else's pull request). There the
bridge posts the check itself (§9, "forged check runs"), once the App has the
permissions and events above. (A personal account the App is not installed
on has no bridge at all: the account holder runs `vgi repo init`, which
commits the in-repo workflow with the owner-review or solo guard, and there
repository writers are trusted not to forge the check —
[RUNBOOK.md §4](RUNBOOK.md#4-set-up-the-repository).)

- **Only against the protected branch.** A check run attaches to a commit,
  not to a pull request, so a success on a head commit counts for every
  pull request with that head. The bridge therefore posts only for pull
  requests and merge groups whose base is the repository's **default
  branch** — the branch the managed ruleset protects — read from GitHub at
  check time, never from the delivery. For any other base it posts nothing.
  A pull request's current base and head are re-read from GitHub; a base
  change (`pull_request` `edited`) is checked again against the new base; a
  pull request that moved on is left to the delivery for its new head. Runs
  are keyed by repository, head and base branch (`external_id` is
  `<base>@<head>`).
- **What it checks.** The commits in `base...head` (all pages, at most
  `checks.max_commits`; a truncated list fails), fetched as **commit objects
  only** (a partial clone with `--filter=tree:0`, falling back to
  `blob:none`, stopped past `checks.max_fetch_bytes`) into a throwaway bare
  repository with a read-only token, and verified by verify-trust — the
  repository's qualified resource, with the namespace as the fallback
  resource. An empty range (the head is already in the base) is a success
  only when the head *is* the base tip; otherwise it is a failure.
- **How it asks the registry.** Over HTTPS, at the `#rest` endpoint the
  registry's DID document names — the bridge-posted check needs the registry
  to publish one. It does not query over DIDComm: a reply arriving on the
  bridge's mediator session reaches it already unpacked, without the envelope
  needed to bind the authcrypt sender key id to the key actually used, so its
  sender cannot be proven to be the registry. (The CI workflows take the
  packed envelope and do check that binding; they can use TSP and DIDComm.)
- **The workflows it writes** take `transport` under `[verify_trust]` —
  `auto` (default: TSP, then DIDComm, then HTTPS, no fallback; writes no
  input), `tsp`, `didcomm` or `https` — passed to the action as its
  `transport` input. Set `https` while the registry's mediator does not admit
  a CI run's throwaway DID.
- It completes "Verify commit trust" as **success** or **failure** with a
  per-commit table. Anything that goes wrong fails the check (closed).
- **Re-running.** "Re-run" on the check in GitHub (`check_run` /
  `check_suite` `rerequested`) runs it again. A delivery whose check could
  not be posted (GitHub unavailable) is not recorded as handled, so GitHub's
  redelivery — automatic, or from the App's *Advanced* page — runs it again.
- The repository ruleset requires the check **from the App's own
  integration id**, and the bootstrap commits no workflow.

Nothing from the pull request runs: git is invoked with a cleared
environment, no config from the repository, hooks pointed at nothing, lazy
fetching off, redirects refused and only `https` allowed.

This makes the bridge a **merge dependency** for those namespaces, as the
registry already is: while it is down, pull requests wait for their check.
Organisations with org rulesets use the required workflow instead and do not
depend on the bridge to merge.

## 6a. Dependabot pull requests: the re-sign

verify-trust passes a commit GitHub signed (`web-flow`) only when it is a
clean merge, so Dependabot's commits fail the check — nothing in a commit
proves Dependabot wrote it: any writer can have GitHub write and sign a
commit with any author through the Contents API. So that Dependabot pull
requests still merge without a human step, a GitHub bridge **re-signs them
with its own DID** (design §9, "Dependabot re-sign bot"). Provenance comes
from **signed `push` webhooks, never from who a commit says wrote it**:

- **The record.** Every verified `push` to a `dependabot/*` branch is kept:
  before, after, who GitHub says pushed (login and numeric id), and whether
  the push created the branch. Deleting the branch clears its record, and
  creating it again starts a new one — but only a delivery at least as new
  as every one recorded (by GitHub's `repository.pushed_at`, which the
  webhook signature covers) may clear or restart a record, and a delivery
  more than six days old is not recorded at all: the bridge forgets
  delivery ids after seven, so an older one could be a replay. Up to 64
  `dependabot/*` branches are tracked per repository; past that the one
  untouched longest is forgotten, and a forgotten branch is never
  re-signed.
- **When it re-signs.** On `pull_request` opened / synchronize / reopened —
  and when a push arrives for a branch whose pull request it has already
  seen — the bridge re-reads the pull request from GitHub and re-signs only
  if **all** of these hold:
  - it was opened by `dependabot[bot]` (login *and* id — `dependabot_login`,
    `dependabot_id`), its head is a `dependabot/*` branch **in the same
    repository**, and it targets the repository's default branch;
  - every push recorded on the branch came from Dependabot or was one of the
    bridge's own re-sign pushes, and walking back from the head through
    those pushes reaches the branch's creation, by Dependabot, with no gap
    (a re-sign push whose webhook the bridge missed still links the walk,
    by the exact old and new head it recorded before pushing);
  - the namespace has the re-sign on (the default; see the config below) and
    `platform_keyring_file` names GitHub's `web-flow` key;
  - each commit has one parent, carries only the standard headers, is
    `web-flow`-signed with a signature that verifies against that key, is
    authored by Dependabot's noreply address, carries no `Signed-by-DID:`
    trailer of its own, and **changes nothing under `.github/workflows/`**
    (read from the commits' trees; if they cannot be read, nothing is
    re-signed).

  Anything else — a push by anyone else, a push the bridge never saw (it was
  down), a pull request from a fork — and nothing is re-signed. The check
  fails as it would anyway, and its summary says why and what to do: a
  maintainer re-signs the commits (runbook §5), or Dependabot starts the
  branch over (close the pull request and delete the branch).
- **Workflow changes are never re-signed.** A Dependabot pull request that
  touches `.github/workflows/` — a `github-actions` update, typically —
  waits for a maintainer to review it and re-sign it by hand (runbook §5);
  the check says so. The bridge will not vouch for what CI runs, and the App
  has no `workflows` permission, which GitHub requires to push such a change
  (and which the manifest deliberately does not ask for).
- **How.** Each commit is rebuilt with the **same tree** and the same author
  line; the committer is the bridge (`[resign]`), the message gains a
  `Signed-by-DID: <bridge DID>#<key>` trailer, and it is signed (sshsig,
  namespace `git`) with the bridge's Ed25519 DID key. The new commits are
  force-pushed with a lease on the exact old head (a push that landed in
  between is never overwritten), with a contents-write token for that one
  repository, over the same hardened git as the check. The bridge records
  that push as its own before sending it, so its webhook does not make the
  branch unclean. A head already carrying the bridge's signature is left
  alone. Re-signs run `checks.concurrency` at a time, one at a time per
  branch.
- **Dependabot after a re-sign.** Dependabot stops rebasing a pull request
  someone else has pushed to — and the re-sign is such a push. Comment
  `@dependabot rebase` when it falls behind: Dependabot's push is recorded,
  and the bridge re-signs the result.

**What the VTC must grant.** The re-signed commits pass only if the
registry authorizes the bridge's DID for `git.commit.sign` on the namespace
(`github.com/<owner>`). The VTC grants this at bind, as a service grant
(`grantedBy` = the VTC) that its default policy allows for the namespace's
own bridge; a VTC release without that grant needs it made by hand (a
`git.commit.sign` grant to the bridge's DID on the namespace). The bridge checks at start (and a couple of minutes after a
bind) and logs a warning naming the namespace if the registry says the grant
is missing; it re-signs regardless, and the re-signed commits then fail as
`unauthorized` until the grant exists.

**What the bridge's DID must publish.** verify-trust resolves the DID in the
trailer and accepts the signature only from an Ed25519 key its DID document
lists as a verification method (`publicKeyMultibase`). The bridge signs with
the same key that signs its Trust Task documents: a locally minted `did:peer`
always publishes it; for a VTA-provisioned `did:webvh`, the Ed25519 key in
the imported bundle must be a verification method of the DID's document
(VTA templates publish it). The commit signature's `git` namespace keeps it
from ever passing as a document proof, and the other way round.

Config (all optional):

```toml
# The committer on re-signed commits (the signer is the DID in the trailer).
[resign]
committer_name = "VGI bridge"
committer_email = "vgi-bridge@noreply.invalid"

[[github]]
# …
# Dependabot's account as GitHub reports it (github.com: GET /users/dependabot[bot]).
# A GHES instance has its own id: look it up there.
# dependabot_login = "dependabot[bot]"
# dependabot_id = 49699333

# Turn the re-sign off for one namespace (the owner's login, lowercase).
# [github.namespaces.acme]
# resign_dependabot = false
```

## 6b. The namespace as the check's fallback resource

The VTC publishes a namespace's commit rights on the **namespace** resource
(`github.com/acme`), not on each repository: every `git.ns.admin`'s implied
`git.commit.sign`, a namespace-wide `git.commit.sign` grant, and the
bridge's own service grant, on which the commits it re-signs for Dependabot
pass (§6a). So every check the bridge sets up queries the repository first
and the namespace as the fallback (git-ns `right/grant` 0.1):

- **The bridge-posted check** (§6) passes the namespace it serves.
- **The workflows the bootstrap writes** — the organisation's required
  workflow in `<org>/.vgi`, the in-repo workflow, the Forgejo workflow —
  pass, next to `resource-format: qualified`,

  ```yaml
            # The namespace: where the VTC publishes namespace-wide commit rights.
            fallback-resource: github.com/${{ github.repository_owner }}
  ```

  with the forge's host (a GHES host, `codeberg.org`, your Forgejo's). The
  owner is the one the runner runs the job for, read at run time: one
  `.vgi` workflow serves every repository of the organisation, and a copy
  in another owner's repository names that owner, never this one. The value
  reaches verify-trust through the action's environment, never a script,
  and verify-trust refuses a qualified fallback that does not contain the
  repository's resource — another owner, another forge — and a
  forge-qualified one under `resource-format: legacy`.

**Upgrading.** Workflows written by a bridge before this passed no fallback:
there, namespace admins who do not own the repository, namespace-wide
grants and the bridge's re-signed Dependabot commits fail `unauthorized`.
The bootstrap renders the new workflow; how it lands depends on the guard,
because the bridge can never push past the protection it set up. Once
landed, the next bootstrap reports the step unchanged. The bridge does not
report an outdated workflow as drift, so nothing re-sends the bootstrap on
its own: have the VTC send the repository's bootstrap job again where the
steps below say so.

- **Required workflow.** `.vgi` takes changes through pull requests only, so
  the next bootstrap of any managed repository fails its `workflow` step
  ("…`.vgi` is protected, so a new workflow lands through a pull request
  there; the bridge pins it once it is merged") and **the pin does not
  move**: the old workflow stays required, with no gap. An owner of the
  organisation opens a pull request in `<org>/.vgi` adding the two lines
  above to `.github/workflows/verify-trust.yml`, directly below
  `resource-format: qualified`, indented like it, and merges it. Then send
  the bootstrap again for any one managed repository: the bridge reads the
  new head, finds exactly the workflow it renders, and moves the org
  ruleset's pin to that commit — for every repository at once. It pins only a
  commit whose file is byte for byte its own rendering; anything else in
  `.vgi` is never pinned — if the bootstrap still fails, compare the file
  with the lines above.
- **In-repo workflow** (owner review, solo). The repository ruleset has no
  bypass actors, the bridge included, so the bootstrap's `workflow` step
  fails the same way. An owner opens a pull request adding the two lines to
  `.github/workflows/verify-trust.yml` (under owner review, another owner
  approves it); the pull request is checked by the workflow it carries, so
  it can already use the namespace fallback. Then send the bootstrap again.
- **Bridge-posted check.** Nothing to do.
- **Forgejo.** No pull request: send the bootstrap again, and its
  `workflow` step sees the stale protected file and takes the audited refresh
  (`refresh_managed_files`) — the managed rule opened to the bot alone, the
  file written, the rule's exact prior settings restored and read back.

The fallback needs no new verify-trust release: every release that knows
`resource-format` passes `fallback-resource` on. The refusal of a fallback
outside the repository's namespace is in the release after this change;
pinning an older one loses only that defence in depth, since the value the
workflows pass can only name the running repository's own owner.

## 6c. Roles: the role map

Each repository right becomes one forge role for a person with a linked
account (design §4.2, §5.8 "community hooks"). The default is the design's:

| Right | Default role | GitHub organisation | Forgejo | GitHub personal account |
|---|---|---|---|---|
| `git.repo.own` | `admin` | `admin` | `admin` collaborator | `write` (the only role) |
| `git.repo.maintain` | `maintain` | `maintain` | `write` **and** a place on the default branch's merge allow-list | `write` |
| `git.commit.sign` | `none` | none — fork pull requests | none | none |
| `git.ns.admin` | **none, always** | — | — | — |

A forge without a level rounds it **down**, never up. The map can be
overridden, field by field, at four levels; the most specific wins:

```toml
# Every forge this bridge serves.
[role_map]
# own = "admin"
# maintain = "maintain"
# commit = "none"

[[forgejo]]
base_url = "https://codeberg.org/"
# …
# Every namespace on this instance: maintainers as repository admins
# instead of `write` plus the merge allow-list.
[forgejo.role_map]
maintain = "admin"

# One namespace (the owner's login, lowercase).
[forgejo.namespaces.acme.role_map]
maintain = "maintain"

# One repository (its name, lowercase): committers push branches here.
[forgejo.namespaces.acme.repos.widgets.role_map]
commit = "write"
```

`[github.role_map]`, `[github.namespaces.<owner>.role_map]` and
`[github.namespaces.<owner>.repos.<name>.role_map]` work the same way (the
`[github.namespaces.<owner>]` table is the one that also holds
`resign_dependabot`). Values are `none`, `read`, `triage`, `write`,
`maintain`, `admin`. The start fails unless every map the layers can make is
ordered — `own ≥ maintain ≥ commit` — with `commit` at most `write` (merging
is a maintainer's; the check, not a role, decides whose commits land).

**A namespace admin gets no forge role, and no configuration can give them
one** (decided 2026-09-25). There is no key for `git.ns.admin` — `ns_admin`,
`admin` or any other unknown key fails the start — and a job whose desired
role carries `git.ns.admin` projects nothing. Nothing here means *no
direct role at all*: an account a job lists with no role has **any** direct
collaborator role on that repository removed, one given by hand on the
forge as much as one the bridge projected (only accounts a job does not
list are left alone). A namespace-level role job (organisation owners) is
refused `notCapable`.

This holds end to end only when the VTC sends `git.ns.admin` for a
namespace admin. A VTC that folds `ns.admin` into `git.repo.own` by
implication before sending — as VTC releases before the fix for this do —
sends namespace admins as owners, and the bridge, which cannot tell them
apart, projects them as owners. `git.ns.admin` is exercised through the VTC
and the bridge; who owns the organisation stays yours to manage by hand.
Someone who is both a namespace admin and, in their own name, a
repository's owner or maintainer gets that repository right's role.

**When a change applies.** The bridge maps rights to roles when a
`projectRoles` or `createRepo` job arrives. Roles already projected are not
re-mapped on restart: a repository picks up a new map at its next role
projection, which the VTC sends when that repository's rights or linked
accounts change. Roles the bridge projected under the old map are the
baseline drift is measured against until then, so they are not reported.

## 7. Operating it

- **Logs** go to standard error (`RUST_LOG=info` by default). They never
  contain secrets.
- **`/healthz`** answers `ok` while the HTTP server runs.
- The DIDComm link reconnects on its own with capped backoff; results and
  events queued meanwhile go out when it is back.
- A job that fails half-way reports `partial` with each step's outcome; every
  step is check-then-apply, so the VTC may simply send it again.
- **What the VTC's console shows about the forge** comes from the bridge: each
  result and event carries a status report in its `ext` member
  (`org.openvtc.git-ns`) — the App installation and what it lacks, whether a
  permission upgrade waits for the owner's approval, org rulesets, the check
  mode, and per repository the guard in force and the last check the bridge
  posted. After a posted check the bridge inspects the repository and sends
  a `protectionChanged` carrying it, at most once a minute per repository.

### Event versions

The bridge sends `git-ns/bridge/event` **0.2** by default. A VTC that does
not understand 0.2 yet refuses it as an unsupported type; until it is
updated, set in the config

```toml
event_version = "0.1"   # "0.1" or "0.2" (the default)
```

and restart. Switch back to `"0.2"` (or remove the line) once the VTC takes
0.2. The two versions are wire-identical: an event is the same payload under
either type URI, and events still queued when you switch go out under the
new one. The VTC's acknowledgement is accepted in either version.

What 0.2 changes is what the VTC does with an event. The bridge's own
handling is the same whichever version it sends:

- **A transfer detaches.** A managed repository moved to another owner —
  another organisation, another forge, or another namespace this same bridge
  serves — is reported to its old namespace as `repoTransferred` (whose `to`
  may lie anywhere: it only says where the repository went). The bridge
  drops it from that namespace: its record, its place in the managed set
  (and the org ruleset's repository list), and its Dependabot provenance
  ledger. Nothing is carried into the receiving namespace; if this bridge
  serves it, the repository is reported there as `repoCreatedUnmanaged`, for
  that namespace's admins to adopt and grant afresh. A transfer the forge
  sent no webhook for is found the same way by the next inspection (the
  forge answers for the old name with the new home).
- **A reused name detaches the old repository.** A new repository — created
  or transferred in — at a name the namespace governs under a different
  forge id means the governed one went without an event. The bridge detaches
  the old one and reports the newcomer as `repoCreatedUnmanaged`; it
  inherits nothing. (A managed repository renamed onto such a name is
  reported as `repoRenamed`; the stale record at the name is dropped.)
- **Every resource lies inside its event's namespace.** The bridge never
  sends an event whose `resource`, `from`, `repoRenamed` `to`, or drift
  `resource` lies outside the namespace it reports to — such an event is
  logged (`not reporting an event that names a repository outside its
  namespace`) and dropped. Only a `repoTransferred`'s `to` may lie outside.

**With a 0.1 VTC**, a `repoTransferred` whose `to` lies in another namespace
the VTC governs is handled by 0.1 as a rename: the VTC moves the
repository's rights to the new namespace. The bridge does not follow — it
has detached the repository and reports it there as unmanaged — so jobs the
VTC sends for it in the new namespace act on a repository the bridge does
not manage until it is adopted. Update the VTC to 0.2 before relying on
transfers between namespaces.
