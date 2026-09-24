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
- **Protocol.** `git-ns/bridge/job` (0.2, and 0.1 from a VTC that has not
  moved) in; exactly one `git-ns/bridge/result`
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
