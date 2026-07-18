//! Shared primitives for Verifiable Git Infrastructure (VGI).
//!
//! Pure, dependency-light building blocks that both the signer
//! (`did-git-sign`) and the CI verifier (`verify-trust`) rely on, kept in one
//! crate so their wire formats cannot drift:
//!
//! - the PROTOCOL.sshsig encoder ([`create_ssh_signature`]) and the git
//!   sshsig namespace ([`GIT_SSHSIG_NAMESPACE`]),
//! - git commit-object handling ([`split_signed_commit`],
//!   [`normalize_sshsig_armor`]),
//! - DID-document Ed25519 key extraction ([`ed25519_keys_from_doc`]).
//!
//! Nothing here touches the network, a keyring, or a VTA — that is what lets
//! the CI verifier stay a small, fast dependency.

mod commit;
mod did;
mod sshsig;

pub use commit::{normalize_sshsig_armor, split_signed_commit};
pub use did::{ED25519_MULTICODEC_PREFIX, ed25519_keys_from_doc};
pub use sshsig::{GIT_SSHSIG_NAMESPACE, create_ssh_signature};
