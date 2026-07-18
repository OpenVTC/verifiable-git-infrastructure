# verify-trust

The CI verifier of [Verifiable Git Infrastructure (VGI)][vgi]. For every commit
in a range it answers two questions, and **fails closed** on any doubt:

1. **Who signed it, cryptographically?** The commit's `gpgsig` header is parsed
   as a PROTOCOL.sshsig blob; the embedded Ed25519 key is matched against the
   keys published in the DID documents of the repository's declared signers,
   and the signature is verified over the exact bytes git signed.
2. **Is that DID trusted, right now?** The signer DID is checked against a Trust
   Registry with a TRQP authorization query.

Signers are declared as DIDs in a committed index (default `.did-signers`) —
identities, not keys — so key rotation never touches the repository, and
revoking a signer is a registry operation that takes effect on the next run.

> **Not a generic git-signature checker.** verify-trust is bound to the DID /
> Trust-Registry ecosystem: you need a Trust Registry to verify against and
> signers whose keys are published in resolvable DID documents.

## Install

```sh
cargo install verify-trust
```

Or use the prebuilt binary via the GitHub Action (no toolchain on the runner):

```yaml
- uses: actions/checkout@v4
  with: { fetch-depth: 0 }
- uses: OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@v0.1.1
  with:
    range:        origin/${{ github.base_ref }}..HEAD
    registry-url: ${{ vars.TRUST_REGISTRY_URL }}
    registry-did: ${{ vars.TRUST_REGISTRY_DID }}
    authority:    ${{ vars.TRUST_AUTHORITY_DID }}
```

## Usage

```sh
verify-trust \
  --range origin/main..HEAD \
  --registry-url https://registry.example.com \
  --registry-did did:webvh:...registry \
  --authority    did:webvh:...your-community \
  --resource     your-org/your-repo
```

Exits `0` only when every commit is `trusted` (registry-authorized) or `exempt`
(a platform commit verified against a committed PGP keyring). The verdicts
`unsigned`, `unknownKey`, `badSignature`, `unauthorized`, and
`registryUnavailable` each fail with a distinct status. `--json` emits a
machine-readable report.

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
