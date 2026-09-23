# vgi-bridge

The per-community bridge for [VGI][vgi] git namespaces (design §5.7): the one
service that holds a community's forge credentials — its own GitHub App key,
its Forgejo bot's token — and acts on the forges for its VTC. The VTC decides;
the bridge carries it out and reports back.

```
 VTC ──DIDComm (authcrypt, via mediator)──▶ vgi-bridge ──adapters──▶ GitHub / Forgejo
     ◀── git-ns/bridge/result, /event ────            ◀── webhooks, OAuth redirects (HTTPS)
```

- **Identity.** Its own DID — a VTA-provisioned `did:webvh` (imported) or a
  locally minted `did:key` — with every key sealed (AES-256-GCM under a
  mounted master key) in a redb store. It serves **one** VTC and refuses a
  document from any other DID, whatever its proof.
- **Protocol.** `git-ns/bridge/job` in; exactly one `git-ns/bridge/result`
  per job; `git-ns/bridge/event`s for what happens on the forge. The payload
  types are generated from the normative specifications
  (`trust_tasks_rs::specs::git_ns`); every document is Data-Integrity signed
  (`eddsa-jcs-2022`) and every inbound one checked — issuer, transport sender,
  recipient, freshness, then proof — before its payload is read.
- **Jobs.** `jobId` idempotency from a durable ledger (a repeat is answered,
  never run twice; a finished job repeated has its result sent again;
  different content is `jobIdReused`). `createRepo`, `bootstrap`,
  `projectRoles`, `archive`, `inspect` map onto the forge-neutral `Forge`
  trait with the adapter's `ForgeHooks` around each operation; `beginBind`
  and `beginAccountLink` answer with `next` and complete through the forge's
  redirect or the device flow, reporting `bindCompleted` / `accountLinked`
  then the result. Results and events are retried until the VTC
  acknowledges them.
- **State that must survive a restart** — bindings, capabilities (and
  `CapabilityChanged`), GitHub's managed sets and required-workflow pins,
  pending flows, Forgejo's rotated bot token — is restored into the adapters
  before any job runs.
- **Events and drift.** Webhooks are verified before they are parsed, then
  used only as a prompt to inspect; forges without webhooks are swept on a
  schedule.
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

Not published to crates.io: it is a service, shipped as a container
(`Dockerfile` here). The operator guide is [`docs/BRIDGE.md`][guide];
`bridge.example.toml` is a starting config.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[guide]: ../../docs/BRIDGE.md

## License

Apache-2.0.
