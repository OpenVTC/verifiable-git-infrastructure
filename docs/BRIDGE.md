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
| A **master key** (32 bytes, base64) | seals every secret in the store |
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

1. Put GitHub's `web-flow` key where the config says:
   `curl -fsSL https://github.com/web-flow.gpg > /etc/vgi-bridge/web-flow.asc`.
   It is the exempt keyring for merge commits made in GitHub's web UI.
2. Start the bridge. With no App registered for a configured host, it logs
   a **one-time registration URL** (valid 24 hours):
   `…/github/github.com/register?state=…`.
3. An owner of the `app_owner` organisation opens it. The page posts the
   manifest to GitHub; they approve it; GitHub redirects back to
   `/github/github.com/registered`, and the bridge exchanges the code for the
   App's id, private key and webhook secret, **seals them**, and puts the
   adapter in service. It refuses an App registered under another account,
   a public App, or one with any permission beyond the reviewed set.
4. **Enable Device Flow** on the App's settings page (the manifest format
   cannot): *Settings → Developer settings → GitHub Apps → the App → Enable
   Device Flow*. Members link their accounts with it.

The App asks for: repository Administration, Contents, Variables and Checks
(write), Metadata (read); organisation Members (read) and Administration
(write). Organisation Administration is for the org ruleset that makes
verify-trust a required workflow; Checks is for the check the bridge posts
itself where there is none (§6). No secrets, Actions logs, code scanning or
packages.

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
bridge posts the check itself (§9, "forged check runs"):

- on `pull_request` (`opened`, `synchronize`, `reopened`) and `merge_group`
  webhooks it lists the commits in `base...head`, fetches exactly those
  objects into a throwaway bare repository with a read-only token for that
  repository, and runs verify-trust against them — the repository's
  qualified resource, with the namespace as the fallback resource;
- it completes "Verify commit trust" as **success** or **failure** with a
  per-commit table. Anything that goes wrong fails the check (closed);
- the repository ruleset requires the check **from the App's own
  integration id**, and the bootstrap commits no workflow.

Nothing from the pull request runs: git is invoked with no config from the
repository, hooks pointed at nothing, redirects refused and only `https`
allowed. Work is bounded by `checks.max_commits` (default 250) and
`checks.max_signers` (16 distinct signer DIDs).

This makes the bridge a **merge dependency** for those namespaces, as the
registry already is: while it is down, pull requests wait for their check.
Organisations with org rulesets use the required workflow instead and do not
depend on the bridge to merge.

## 7. Operating it

- **Logs** go to standard error (`RUST_LOG=info` by default). They never
  contain secrets.
- **`/healthz`** answers `ok` while the HTTP server runs.
- The DIDComm link reconnects on its own with capped backoff; results and
  events queued meanwhile go out when it is back.
- A job that fails half-way reports `partial` with each step's outcome; every
  step is check-then-apply, so the VTC may simply send it again.
