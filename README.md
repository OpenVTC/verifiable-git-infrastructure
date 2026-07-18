# Verifiable Git Infrastructure (VGI)

**Commit trust for DIDs** — sign git commits with keys held by a Verifiable
Trust Agent (VTA), and verify, in CI, that every commit in a pull request is
signed by a DID your community's Trust Registry currently authorizes.

VGI is the git-layer sibling of
[verifiable-trust-infrastructure](https://github.com/OpenVTC/verifiable-trust-infrastructure).
It is **not** a generic git-signing library: it is bound to the DID /
Trust-Registry ecosystem — you need a VTA to sign and a Trust Registry to
verify against. See the operator runbook for the full activation flow.

## Crates

| Crate | Role |
|---|---|
| [`vgi-core`](crates/vgi-core) | Shared, dependency-light primitives: the PROTOCOL.sshsig encoder, git commit-object handling, and DID-document Ed25519 key extraction. No network, keyring, or VTA. |
| [`verify-trust`](crates/verify-trust) | The CI verifier (`verify-trust` binary). Checks a commit range against the registry. Depends only on `vgi-core`, a DID resolver, and the query client — no VTA or keyring, so PR runs stay small. |
| [`did-git-sign`](crates/did-git-sign) | The signer (`did-git-sign`, a git `gpg.ssh.program`). Signs commits with a DID key held by your VTA; carries the dev-machine stack (VTA client, keyring, prompts). |

## The CI check

Verify every commit in a PR against the Trust Registry:

```sh
verify-trust \
  --range origin/main..HEAD \
  --registry-url  https://registry.example.com \
  --registry-did  did:webvh:...registry \
  --authority     did:webvh:...your-community \
  --resource      your-org/your-repo
```

In a GitHub PR check, use the composite action instead — it downloads the
prebuilt `verify-trust` binary (no Rust toolchain on the runner) and runs it:

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }        # so origin/<base>..HEAD resolves
- uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v1
  with:
    range:        origin/${{ github.base_ref }}..HEAD
    registry-url: ${{ vars.TRUST_REGISTRY_URL }}
    registry-did: ${{ vars.TRUST_REGISTRY_DID }}
    authority:    ${{ vars.TRUST_AUTHORITY_DID }}
    exempt-keyring: .github/trusted-platform-keys.asc   # optional
```

`resource` defaults to the current repo; `version` selects which release to
download (default `latest`). Verdicts: `trusted` / `exempt` pass; `unsigned`,
`unknownKey`, `badSignature`, `unauthorized`, `registryUnavailable` fail. Fails
closed at every layer.

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
