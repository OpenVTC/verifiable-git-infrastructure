# vgi-bridge

The per-community bridge for [VGI][vgi] git namespaces (design §5.7): the one
service that holds a community's forge credentials — its own GitHub App key,
its Forgejo bot's token — and acts on the forges for its VTC. The VTC decides;
the bridge carries it out and reports back.

```
 VTC ──TSP or DIDComm (via mediator)──▶ vgi-bridge ──adapters──▶ GitHub / Forgejo
     ◀── git-ns/bridge/result, /event ──            ◀── webhooks, OAuth redirects (HTTPS)
```

- **Identity.** Its own DID. In **VTA mode** (recommended), the `did:webvh`
  of its own trust context in the VTC's VTA: the host holds only a
  context-scoped credential, the keys are fetched into memory at start-up
  (and replaced when the VTA rotates them), and the App keys, tokens and the
  bridge's state live in the context's app-state (secrets sealed) — a lost
  host is recovered by issuing a new credential. Self-contained, an imported
  bundle or a locally minted `did:peer:2` whose identifier names the mediator
  the VTC reaches it through, with every key sealed (AES-256-GCM under a
  mounted master key) in a redb store. It serves **one** VTC and refuses a
  document from any other DID, whatever its proof.
- **Protocol.** `git-ns/bridge/job` 0.5 and 0.4 in (older versions refused
  `unsupportedVersion`; `trust-task-discovery/0.2` from the VTC is answered
  with both type URIs); exactly one `git-ns/bridge/result`
  per job; `git-ns/bridge/event`s for what happens on the forge. The payload
  types are generated from the normative specifications
  (`trust_tasks_rs::specs::git_ns`); every document is Data-Integrity signed
  (`eddsa-jcs-2022`, proof purpose `authentication`; any other purpose is
  refused) and every inbound one checked — issuer, transport sender,
  recipient, freshness, then proof — before its payload is read.
- **Jobs.** `jobId` idempotency from a durable ledger (a repeat is answered,
  never run twice; a finished job repeated has its result sent again;
  different content is `jobIdReused`). `createRepo`, `bootstrap`,
  `projectRoles`, `archive`, `inspect` and (0.5) `closePullRequest` map onto
  the forge-neutral `Forge` trait with the adapter's `ForgeHooks` around each operation; `beginBind`
  and `beginAccountLink` answer with `next` and complete through the forge's
  redirect or the device flow, reporting `bindCompleted` / `accountLinked`
  then the result. A 0.2 `projectRoles` may name `removeAccounts` — the
  revert of a forge-side `roleAdded` drift — whose direct roles on the
  repository go by forge id whoever gave them; the namespace's owner and the
  bridge's own App or bot are never removed. Access such an account keeps
  through a team, as an organisation owner or through the organisation's
  base permission is read back (GitHub's and Forgejo's effective
  collaborator permission) and reported as a failed `roles` step naming
  where it comes from; teams and organisations are never changed.
  Results and events are retried until the VTC acknowledges them.
- **Status for the VTC's console.** Every result and event carries, in its
  payload's `ext` member under `org.openvtc.git-ns`, what the bridge knows
  that the specification's payloads do not: `namespace` (the installation,
  the App and its registration, missing permissions, a pending permission
  upgrade, org rulesets, the check mode in force) and `repo` (the guard in
  force — `requiredWorkflow`, `codeOwnerReview`, `bridgePostedCheck`,
  `protectedFiles` or `none` — and the last check the bridge posted). It is
  signed with the rest of the payload; anything unknown is left out.
- **State that must survive a restart** — bindings, capabilities (and
  `CapabilityChanged`), GitHub's managed sets and required-workflow pins,
  pending flows, Forgejo's rotated bot token — is restored into the adapters
  before any job runs.
- **Events and drift.** Webhooks are verified before they are parsed, then
  used only as a prompt to inspect; forges without webhooks are swept on a
  schedule.
- **The pull-request gate.** With `event_version = "0.4"` (opt-in: only for
  a VTC that lists event 0.4), a GitHub pull request opened or reopened on a
  managed repository is reported as `pullRequestOpened` — who and where,
  never what. A `closePullRequest` job (job 0.5) posts the community's
  message and closes it, idempotently: nothing for one already closed or
  reopened by someone else since the job, and never a second comment for the
  same job (a hidden marker on the App's own comment). Needs the App's
  `pull_requests: write`; hygiene, not the merge gate.
- **The bridge-posted check.** Where GitHub has no org required workflow
  (personal accounts, organisations without org rulesets), the bridge runs
  verify-trust as a library against each pull request's commits — fetched as
  objects, never executed — and posts "Verify commit trust" as the App; the
  ruleset requires the check from the App's own integration id, so a
  workflow on another branch cannot forge it.
- **Dependabot re-sign.** On GitHub, a Dependabot pull request whose branch
  only Dependabot has pushed to — as recorded from signed `push` webhooks,
  never read from the commits — is re-signed with the bridge's own DID
  (same trees and authors, a `Signed-by-DID:` trailer, an sshsig by the DID
  key) and force-pushed with a lease on the old head, so it passes the check
  without a human step. The VTC must grant the bridge's DID
  `git.commit.sign` on the namespace.

## Install

- **From crates.io:** `cargo install vgi-bridge --locked` (Rust
  1.95 or later). On Linux the build links libdbus, so install its
  headers first (`apt-get install libdbus-1-dev pkg-config`).
- **A prebuilt binary** from the
  [GitHub Release](https://github.com/OpenVTC/verifiable-git-infrastructure/releases)
  for the tag: `vgi-bridge-<target>.tar.gz` for `x86_64-unknown-linux-gnu`,
  `aarch64-apple-darwin` and `x86_64-apple-darwin` (no Windows build: the
  owner-only checks on the master key and sealed credentials are Unix-only).
  Each has a `.sha256` beside it and a build-provenance attestation; verify
  before running it:

  ```sh
  gh release download vX.Y.Z --repo OpenVTC/verifiable-git-infrastructure \
    --pattern 'vgi-bridge-x86_64-unknown-linux-gnu.tar.gz*'
  gh attestation verify vgi-bridge-x86_64-unknown-linux-gnu.tar.gz \
    --repo OpenVTC/verifiable-git-infrastructure \
    --signer-workflow OpenVTC/verifiable-git-infrastructure/.github/workflows/release.yml \
    --source-ref refs/tags/vX.Y.Z --deny-self-hosted-runners
  sha256sum -c vgi-bridge-x86_64-unknown-linux-gnu.tar.gz.sha256   # macOS: shasum -a 256 -c
  ```

  The tarball carries the binary, this README and `bridge.example.toml`.
  The Linux binary needs `libdbus-1-3` and `git` at runtime.
- **A container**, built from the `Dockerfile` here:
  `docker build -f crates/vgi-bridge/Dockerfile -t vgi-bridge .` from the
  repository root. No image is published; build it from the tag you run.

The operator guide is [`docs/BRIDGE.md`][guide]; `bridge.example.toml` is a
starting config.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[guide]: ../../docs/BRIDGE.md

## License

Apache-2.0.
