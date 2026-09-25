# Verifiable Git Infrastructure (VGI)

**Commit trust for DIDs** — sign git commits with keys held by a Verifiable
Trust Agent (VTA), and verify, in CI, that every commit in a pull request is
signed by a DID your community's Trust Registry currently authorizes.

VGI is the git-layer sibling of
[verifiable-trust-infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure).
It is **not** a generic git-signing library: it is bound to the DID /
Trust-Registry ecosystem — you need a VTA to sign and a Trust Registry to
verify against. See the [operator runbook](docs/RUNBOOK.md) for the full
activation flow.

To have your community's VTC govern a whole GitHub organisation (or a Forgejo
one) — repositories created and protected for you, rights turned into forge
roles, drift reported — follow
[Put a GitHub organisation under a VTC](docs/SETUP-GITHUB-VTC.md), then run it
day to day with the runbook's
[§8](docs/RUNBOOK.md#8-operating-a-vtc-managed-namespace).

## Crates

| Crate | Role |
|---|---|
| [`vgi-core`](crates/vgi-core) | Shared, dependency-light primitives: the PROTOCOL.sshsig encoder, git commit-object handling, and DID-document Ed25519 key extraction. No network, keyring, or VTA. |
| [`verify-trust`](crates/verify-trust) | The CI verifier (`verify-trust` binary). Checks a commit range against the registry. Depends on `vgi-core`, a DID resolver, the query client, and `vta-sdk`'s display-name rendering — it never opens a VTA session or touches a keyring, so PR runs stay small. |
| [`did-git-sign`](crates/did-git-sign) | The signer (`did-git-sign`, a git `gpg.ssh.program`). Signs commits with a DID key held by your VTA; carries the dev-machine stack (VTA client, keyring, prompts). |
| [`vgi-forge`](crates/vgi-forge) | Forge-neutral adapter layer for VTC-governed git namespaces: the `Forge` trait and `ForgeHooks`, capabilities, forge-qualified resources, rights → role projection, bootstrap plans, events and drift. No forge I/O. |
| [`vgi-forge-github`](crates/vgi-forge-github) | The GitHub adapter: one community's own GitHub App (manifest registration, scoped per-job installation tokens), namespace binding, device-flow account linking, repo creation and the commit-trust bootstrap, role projection, verified webhooks. |
| [`vgi-forge-forgejo`](crates/vgi-forge-forgejo) | The Forgejo (and Gitea) adapter: a scoped bot user with token rotation, version-probed capabilities, OAuth2 + PKCE binding and account linking, repo creation and the commit-trust bootstrap (fast-forward-only merges, protected workflow paths), merge allow-list role projection, verified webhooks. |
| [`vgi-bridge`](crates/vgi-bridge) | The per-community bridge service (not published; a container): its own DID, `git-ns/bridge/*` jobs from its one VTC over DIDComm, the adapters, a sealed redb store, and — where GitHub has no required workflow — the "Verify commit trust" check posted by the bridge itself. Operator guide: [`docs/BRIDGE.md`](docs/BRIDGE.md); end-to-end setup: [`docs/SETUP-GITHUB-VTC.md`](docs/SETUP-GITHUB-VTC.md). |
| [`vgi-cli`](crates/vgi-cli) | The `vgi` command (`cargo install vgi-cli`). `vgi repo init --vtc <did> --resource <host>/<owner>/<repo>` turns commit trust on for one repository where no bridge acts — a manual-mode namespace, or a personal account without the App — running the adapters' own bootstrap plan as you, through `gh` on GitHub or `FORGEJO_TOKEN` on Forgejo, with per-repository guards (not an organisation required workflow, which is the bridge's), and prints the `cnm git adopt` command that finishes the job. |

## The CI check

Verify every commit in a PR against the Trust Registry:

```sh
verify-trust \
  --range origin/main..HEAD \
  --registry-did  did:webvh:...registry \
  --vtc-did       did:webvh:...your-community \
  --resource      your-org/your-repo
```

In a GitHub (or Forgejo) PR check, use the composite action instead — it downloads the
prebuilt `verify-trust` binary (no Rust toolchain on the runner) and runs it:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # so origin/<base>..HEAD resolves
- uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.4.6
  with:
    range:        origin/${{ github.base_ref }}..HEAD
    registry-did: ${{ vars.TRUST_REGISTRY_DID }}
    vtc-did:      ${{ vars.VTC_DID }}
    exempt-keyring: .github/trusted-platform-keys.asc   # optional
```

Two DIDs, and nothing to commit: **who may sign is a registry grant**, not a
file in the repository. Each commit names its signer DID on its own `committer`
header; that DID must publish the key that signed, and the registry must
authorize it. Enrolling a contributor is one grant, and it covers every repo
the grant's resource covers.

There is no registry URL to configure either, and the registry's REST
interface is optional — the binding is discovered from `registry-did`'s DID
document, taking the highest-preference one both sides support: **TSP, then
DIDComm, then HTTPS**. Over TSP and DIDComm each run queries as a throwaway
`did:peer` and believes only an answer authenticated as the registry's DID;
the registry's mediator must admit unknown DIDs for that (see the
[runbook](docs/RUNBOOK.md)), and a refusal fails the check closed.
There is no fallback: while the registry's mediator is not configured for that,
set `transport: https` (inputs: `auto` — the default — `tsp`, `didcomm`,
`https`). `registry-url` is the explicit HTTPS override, for a registry that
publishes no service entry.

`resource` defaults to the current repo and is security-relevant — it is the
only thing scoping a signer to this repository. It comes in two forms, chosen
by `resource-format`: `legacy` (the default today) is the bare `owner/repo`
slug; `qualified` names the forge too — `github.com/owner/repo`, org fallback
`github.com/owner`, lowercased — so `github.com/acme` and `codeberg.org/acme`
can never be confused. Registry grants must be written in the form the check
uses. The default flips to `qualified` in a later release and `legacy` is then
removed; see the [runbook](docs/RUNBOOK.md#2-enrol-the-signers) for the
migration. `version` selects which release to download (default `latest`).

The action also runs on **Forgejo Actions** runners, referenced by full URL
(`uses: https://github.com/OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@vX.Y.Z`).
It downloads the release anonymously with `curl` — no `gh`, no token — so the
runner needs only bash, curl, tar, `sha256sum` or `shasum`, and outbound HTTPS
to github.com. Integrity differs by runner: on GitHub runners the tarball's
build-provenance attestation is verified with `gh`; elsewhere only the SHA-256
published with the release is checked, which catches transport corruption but
not a replaced release, so pin `version` and set `sha256` there. See
[the runbook](docs/RUNBOOK.md#forgejo-actions-runners). Verdicts: `trusted` / `exempt` pass;
`unsigned`, `noSignerDid`, `unresolvedSigner`, `unknownKey`, `badSignature`,
`unauthorized`, `registryUnavailable`, `pgpRejected`, `platformSignedEdit`,
`platformMergeUnverifiedParent`, `platformMergeAltered` fail. Fails closed at
every layer. `exempt` is only ever a clean merge commit signed by a committed
platform key (GitHub's `web-flow`) whose parents all pass: web-UI edits and
Dependabot commits must be DID-signed (see the
[runbook](docs/RUNBOOK.md#5-verdicts-and-what-to-do-about-them)).

## Signing

`did-git-sign init` configures git to sign your commits with a DID key held by
your VTA (SSH-signature format; the DID's verification-method id binds each
commit to the DID). No private key touches disk.

## Status

Extracted from `OpenVTC/openvtc` (where it was developed and dogfooded), with
history preserved. Prebuilt release binaries and a versioned, download-based
GitHub Action follow.

## License

Apache-2.0.
