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
| A **master key** (32 bytes, base64) — *or*, in VTA mode (§2a), a **context credential** for the bridge's trust context in the VTC's VTA | seals every secret in the store; from a file, or an environment variable that the bridge clears once read. In VTA mode there is no master key: secrets and state live in the VTA |
| A writable **data directory** | one redb file, `state.redb` (in VTA mode a cache the bridge rebuilds from the VTA) |
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

Two ways to run a bridge:

- **VTA mode (recommended; §2a).** Like every companion service around a
  VTC, the bridge's DID, keys, secrets and state live in its own trust context
  of the VTC's VTA; the host holds only a context-scoped credential. A lost
  host costs nothing: issue a new credential, start the bridge.
- **Self-contained** (below): a sealed store and a locally held identity
  (`did:peer`, or an imported bundle). For development and testing, or where
  there is no VTA.

### Self-contained

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

## 2a. VTA mode

The bridge works off the VTC's VTA (design §5.7). What lives where:

| What | Where |
|---|---|
| The bridge's DID (`did:webvh`) and its keys (Ed25519 signing, X25519 key agreement) | the context, in the VTA; fetched into memory at start-up, never written to disk or logs |
| The GitHub App's credentials, webhook secrets, Forgejo tokens | the context's `vta/app-state`, namespace `vgi-bridge`, **sealed** under a key only the context's admins can export (`vgi-bridge/app-state-seal`, created by `vta setup`) — app-state is not a secret store, so the bridge never puts a secret there in the clear |
| Namespaces (binding, installation, capabilities, managed repositories, the required-workflow pin), repository records, the Dependabot provenance ledger, bookkeeping | the context's `vta/app-state`, one record each |
| The job ledger, the outbox, pending binds and links, webhook delivery ids | the local store only (a lost host loses them: the VTC repeats unfinished jobs, every job is convergent, and a person restarts a bind or link) |
| The credential | this host, and nothing else |

Every signature the bridge makes is its own: it signs its Trust Task
documents, results and Dependabot re-signs with its own Ed25519 key, never as
the VTC.

**1. The context and the DID.** In the VTA, create a context for the bridge
(`vgi-bridge`, say) and provision a `did:webvh` into it from a DID template
with an Ed25519 signing key (`#key-0`), an X25519 key-agreement key (`#key-1`)
and a `DIDCommMessaging` service naming `mediator_did`.

**2. The credential.** Issue a `did:key` credential that is an **admin
scoped to that context only** — exporting the context's keys needs the VTA's
`key-export` capability, which only `admin` carries — and hand it to the
bridge host as a file (owner-only, JSON: `did`, `privateKeyMultibase`,
`vtaDid`, `vtaUrl`):

```sh
pnm auth-credential create --role admin --contexts vgi-bridge --recipient req.json
# (or `pnm acl create --did <did:key> --role admin --contexts vgi-bridge`)
# open the sealed bundle into the credential JSON:
pnm bootstrap open --bundle bundle.armor --expect-digest <digest> --out /run/secrets/vgi-bridge-vta-credential
chmod 600 /run/secrets/vgi-bridge-vta-credential
```

A context-scoped admin reaches that context (and any context below it) and
nothing else: every key, sign and app-state operation checks the key's or
record's own context, so the credential can read neither the VTC's keys nor
any other context's. It can administer its own context (create keys and ACL
entries in it), which is why it is issued to the bridge host alone.

**3. The config.** Add a `[vta]` section and remove `master_key_file` /
`master_key_env` (the bridge refuses both together):

```toml
[vta]
context = "vgi-bridge"
credential_file = "/run/secrets/vgi-bridge-vta-credential"
# The VTA is reached over DIDComm, through the bridge's `mediator_did`
# unless this names another:
# mediator_did = "did:web:mediator.acme-vtc.example"
```

The bridge talks to the VTA over DIDComm only: the VTA releases a private
key only over a channel confidential end to end, never over REST, where the
key would exist wherever TLS terminates.

**4. Check it.** `vta setup` verifies the context has a DID with both keys,
the credential can fetch them and read, write and delete app-state, creates
the sealing key, warns if the credential reaches any other context, and
prints the DID to register at the VTC:

```sh
vgi-bridge --config /etc/vgi-bridge/bridge.toml vta setup
```

Then `run` as usual, with an **empty** `data_dir` the first time (a store left
by a self-contained bridge is refused: the state of VTA mode comes from the
VTA). `secret set` / `secret list` work on the context's app-state in VTA mode
(restart the bridge after a `secret set`); `identity import`, `export` and
`mint` are refused — the identity is the context's.

**Start-up and an unreachable VTA.** The bridge cannot run without its keys:
start-up retries an unreachable VTA with capped backoff for
`start_timeout_secs` (default 300), and gives up at once on a refusal (a
revoked credential) or on state it will not run on (rolled back, replayed —
below): retrying would read the same state again. While running, state changes reach the VTA from a
background task a moment after they happen, retried with backoff; a result
or event goes to the VTC only once the state it reports is in the VTA (it is
held in the outbox until then), a Forgejo bot token is retired only once its
successor is in the VTA, and the App registration page says so if the App's
credentials could not be written yet. If changes wait five minutes with
every write failing — the VTA unreachable, or its app-state lease kept by
another writer — `/healthz` answers 503 with how many are waiting, so
results held behind them do not go unnoticed.

**One writer at a time.** Writers of the context's app-state (the running
bridge, `secret set`, `vta setup`) take a lease record first. It lasts two
minutes unless renewed, judged by the **VTA's** time of the write, not the
holder's claim: a writer with a wrong clock, or one that claims the lease
for longer, holds it for at most two minutes past its last write. Every
app-state request is given up after 20 seconds, well inside the half-lease
the bridge keeps in hand before each write.

**A second writer.** Every write is conditional on the version this host
last saw. If another bridge — or anyone holding the credential — writes the
same context, the bridge stops writing its state (fail closed), holds its
results, logs why, and `/healthz` answers 503. Stop the other writer (revoke
the credential if it is not yours) and restart this bridge.

**The VTA is the authority on a restart.** A host that comes back on an old
data directory does not bring back what another host changed meanwhile:

- a record it had mirrored that the VTA deleted (the recovery host) is
  dropped from its cache, not written back. While the VTA's change feed
  still reaches back to the start it carries every deletion, so a mirrored
  record the VTA has **no record of at all** was lost, not deleted: a
  rollback, which stops the start even when the counter has moved past the
  restore point since. Only once the VTA has reaped old deletions (and
  answers with a snapshot) is a missing record taken for deleted;
- only records it never managed to mirror are written;
- a record the VTA holds at an *older* version than this host wrote (a
  rolled-back or replayed store) stops the start, and so does a VTA whose
  counter is behind the last version this host wrote (restored from a
  snapshot taken before some of its records existed: those are missing,
  not deleted).

**One writer at a time.** The running bridge, `secret set` and `vta setup`
take a short lease (`lease/writer` in app-state, 2 minutes, renewed while
held) before writing, so each secret is sealed once to the version it lands
at and is never left in the VTA in a form that does not open. `secret set`
while the bridge runs waits its turn.

Each secret is sealed to its own record version, so a ciphertext put back
later does not open (the start is refused, naming the secret). The sealing
key must be the only active key labelled `vgi-bridge/app-state-seal` in the
context; the bridge refuses to guess between two.

**Key rotation.** The bridge's **current DID document** decides which of its
keys it holds: every signing (`assertionMethod`) and key-agreement key the
document lists, with the same public key, and nothing else. The private
halves come from the VTA; one the VTA no longer releases but the document
still lists stays in memory.

**Which key signs.** A verifier (the VTC) may hold a cached copy of the
bridge's DID document for up to its cache horizon, so a newly listed key is
not known to all of them at once. The bridge records when it first saw each
signing key listed; the record is mirrored to the VTA, so a restart or a new
host keeps it. It keeps signing with the oldest listed key it may use until
a newer one has been listed for `vta.signing_switch_after_secs` (default
86400, the proposed 24-hour verifier cache cap; at least
`did_cache_ttl_secs`), then switches to the newest. If the older key stops
being listed first, the next key signs at once. A key the VTA no longer
releases never signs. (When the VTA exposes key-role states with
`activatesAt`, the bridge will switch at that time instead.)

Every `key_refresh_secs` (default 60), or at once on `SIGHUP`, the bridge
compares the key list and the document. It reads public halves only and
exports the secrets again only when something changed. Through a planned
rotation that means:

1. The VTA mints the successor keys: not listed yet, so not used.
2. The document lists old and new (the overlap): the bridge holds all of
   them, and DIDComm reconnects with every listed key-agreement key, so a
   job encrypted to either key opens. The old key keeps signing until the new
   one has been listed for the horizon; then the new one signs.
3. The document stops listing the old keys (the end of the overlap): the
   bridge drops them.

No grace timer is involved; the overlap is the document's. A key whose id
the document lists with another public key is not used, and a rotation that
names another DID is refused (the VTC knows the bridge by its DID).

**Recovering a lost host:** issue a new context credential (and revoke the
old one), put it on the new host, and start the bridge on an empty data
directory. It fetches its DID and keys, pulls its namespaces, repositories,
pin and App credentials back from the VTA, and serves the same namespaces
under the same DID — no rebind, no App re-registration, no org owner proving
control again. What a lost host does lose is listed in the table above.

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
   spent only once the App is registered. In VTA mode the credentials go to
   the context's app-state (sealed), not to the local store.
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

**In VTA mode** (§2a) there is nothing on the host to back up: the VTA holds
the bridge's identity, secrets and state, and is backed up with the VTC's
ecosystem. The rest of this section is the self-contained mode.

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
([RUNBOOK.md §8i](RUNBOOK.md#8i-the-bridge-backup-restore-restart)). VTA mode
does not have this limit.

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
# Every namespace on this instance: maintainers as plain `write`,
# without the merge allow-list.
[forgejo.role_map]
maintain = "write"

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
is a maintainer's; the check, not a role, decides whose commits land), and
**only `own` may map to `admin`**. `maintain` and `commit.sign` are rights a
member may grant themselves, so a map that made either a forge admin would let
them make themselves a repository administrator on their own authority; the
start fails with an error naming the layer (`git-ns/bridge/job` 0.4 requires
this). On a personal account `own` and `maintain` both become `write`, so
there the forge cannot tell an owner from a maintainer: separation of duties
is enforced at the VTC, not the forge.

**A namespace admin gets no forge role, and no configuration can give them
one** (decided 2026-09-25). There is no key for `git.ns.admin` — `ns_admin`,
`admin` or any other unknown key fails the start — and a job whose desired
role carries `git.ns.admin` projects nothing. Nothing here means *no
direct role at all*: an account a job lists with no role has **any** direct
collaborator role on that repository removed, one given by hand on the
forge as much as one the bridge projected (only accounts a job does not
list are left alone). `git-ns/bridge/job` 0.4 has no namespace-level role
job (organisation owners): one without `repo` is `malformedRequest`. The
bridge takes 0.4 only — older versions are refused `unsupportedVersion` —
and answers `trust-task-discovery/0.2` from its VTC with the 0.4 type URI,
which is how a VTC learns it may send 0.4.

Job 0.4 has the VTC send `git.ns.admin` for a namespace admin with no right
of their own on a repository, never the `git.repo.own` it implies; a VTC
that sent earlier versions folded the two together, which is why this
bridge takes 0.4 only. `git.ns.admin` is exercised through the VTC
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
- **`/healthz`** answers `ok` while the HTTP server runs, and 503 in VTA mode
  once another writer was found on the bridge's context, or once changes
  have waited five minutes with every write to the VTA failing (§2a).
- **DID documents are cached** for `did_cache_ttl_secs` (default 60, at most
  3600): the VTC's (job proofs), the registry's (and its endpoint) and commit
  signers' (the bridge-posted check). That bounds how long a key its owner
  rotated out is still accepted. A job proof, or a commit whose key the cached
  document does not publish, is checked once more against a fresh resolution
  before it is refused — so a rotated-in key is not refused for the cache's
  lifetime — and refused (closed) if it still fails.
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
