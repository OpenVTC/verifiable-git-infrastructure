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
- the **Trust Registry** endpoint its DID document names.

Terminate TLS at the proxy; the bridge speaks plain HTTP/1 behind it and
refuses to start with a `public_url` that is not `https`. Keep the proxy's
own body limit at or above `max_body_bytes` (default 2 MiB), so the bridge's
limit is the one that answers.

## 2. First start

```sh
# 1. Config: start from crates/vgi-bridge/bridge.example.toml.
cp bridge.example.toml /etc/vgi-bridge/bridge.toml

# 2. The master key and the bridge's identity. `init` writes the key file
#    named by `master_key_file` (0600, never overwritten) and mints a
#    did:key identity if the store has none. It prints the DID.
vgi-bridge --config /etc/vgi-bridge/bridge.toml init
```

**A `did:webvh` identity instead** (recommended for production, the same way
the VTC's is provisioned): provision a DID for the bridge from the
community's VTA with a DID template that has an Ed25519 signing key and an
X25519 key-agreement key, export its secrets bundle, and import it:

```sh
vgi-bridge --config /etc/vgi-bridge/bridge.toml identity import bundle.json
shred -u bundle.json
```

Register the printed DID at the VTC as the bridge serving its namespaces.

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

Run `init` / `identity import` with the same volumes and `vgi-bridge init`
as the command before the first `run`.

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

**Token rotation**, when `rotate_token_days` is set and the password is
stored, runs in two phases: mint a new token (verified to be the bot's), seal
it, and only then delete the old one. A crash in between leaves an extra live
token (delete it by hand; its name starts `vgi-bridge-`), never a dead
credential.

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
repeats its own jobs, which the bridge answers from the ledger. Losing the
store entirely means re-registering the GitHub App and re-binding the
namespaces.

## 6. The check the bridge posts itself

Where GitHub offers no org required workflow — personal accounts, and
organisations on plans without org rulesets — a check pinned to the GitHub
Actions App is forgeable by any writer (a workflow on another branch can post
a passing "Verify commit trust" onto someone else's pull request). There the
bridge posts the check itself (§9, "forged check runs"), once the App has the
permissions and events above:

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
the same key that signs its Trust Task documents: a locally minted `did:key`
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
