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

## Crates

| Crate | Role |
|---|---|
| [`vgi-core`](crates/vgi-core) | Shared, dependency-light primitives: the PROTOCOL.sshsig encoder, git commit-object handling, and DID-document Ed25519 key extraction. No network, keyring, or VTA. |
| [`verify-trust`](crates/verify-trust) | The CI verifier (`verify-trust` binary). Checks a commit range against the registry. Depends on `vgi-core`, a DID resolver, the query client, and `vta-sdk`'s display-name rendering — it never opens a VTA session or touches a keyring, so PR runs stay small. |
| [`did-git-sign`](crates/did-git-sign) | The signer (`did-git-sign`, a git `gpg.ssh.program`). Signs commits with a DID key held by your VTA; carries the dev-machine stack (VTA client, keyring, prompts). |

## The CI check

Verify every commit in a PR against the Trust Registry:

```sh
verify-trust \
  --range origin/main..HEAD \
  --registry-did  did:webvh:...registry \
  --vtc-did       did:webvh:...your-community \
  --resource      your-org/your-repo
```

In a GitHub PR check, use the composite action instead — it downloads the
prebuilt `verify-trust` binary (no Rust toolchain on the runner) and runs it:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # so origin/<base>..HEAD resolves
- uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.4.0
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

There is no registry URL to configure either — the endpoint is discovered from
`registry-did`'s DID document, taking the highest-preference binding both sides
support: **TSP, then DIDComm, then HTTPS**. `registry-url` exists only to
override discovery for a registry that publishes no service entry.

`resource` defaults to the current repo and is security-relevant — it is the
only thing scoping a signer to this repository. `version` selects which release
to download (default `latest`). Verdicts: `trusted` / `exempt` pass;
`unsigned`, `noSignerDid`, `unresolvedSigner`, `unknownKey`, `badSignature`,
`unauthorized`, `registryUnavailable` fail. Fails closed at every layer.

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
