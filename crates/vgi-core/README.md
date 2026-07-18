# vgi-core

Shared primitives for [Verifiable Git Infrastructure (VGI)][vgi] — the
dependency-light building blocks that both the signer (`did-git-sign`) and the
CI verifier (`verify-trust`) rely on, kept in one crate so their wire formats
cannot drift.

- **`create_ssh_signature`** — the PROTOCOL.sshsig encoder for Ed25519 keys
  (and `GIT_SSHSIG_NAMESPACE`, the namespace git uses for commit signatures).
- **`split_signed_commit` / `normalize_sshsig_armor`** — reconstruct the exact
  bytes git signed from a raw commit object, and re-wrap sshsig armor to the
  70-column width strict PEM parsers require.
- **`ed25519_keys_from_doc`** — extract Ed25519 verification keys from a DID
  document (`publicKeyMultibase`, multicodec `0xED01`).

Nothing here touches the network, a keyring, or a VTA — that is what lets the
CI verifier stay small.

This is a support crate for the VGI tools; most users want
[`verify-trust`][verify-trust] (CI) or [`did-git-sign`][did-git-sign] (signing)
rather than depending on `vgi-core` directly.

## License

Apache-2.0.

[vgi]: https://github.com/OpenVTC/verifiable-git-infrastructure
[verify-trust]: https://crates.io/crates/verify-trust
[did-git-sign]: https://crates.io/crates/did-git-sign
