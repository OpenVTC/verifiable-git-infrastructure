//! PROTOCOL.sshsig encoding for Ed25519 keys.
//!
//! The signer produces armored SSH signatures with [`create_ssh_signature`];
//! the verifier decodes them with the `ssh-key` crate. Keeping the encoder
//! here means the format the signer writes and the format the verifier expects
//! are defined against one another in a single crate.

use anyhow::Result;
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha512};

/// The sshsig namespace git uses for commit and tag signatures.
pub const GIT_SSHSIG_NAMESPACE: &str = "git";

/// Magic preamble for SSH signatures (PROTOCOL.sshsig).
const SSHSIG_MAGIC: &[u8; 6] = b"SSHSIG";

/// Create an armored SSH signature following the PROTOCOL.sshsig format,
/// signing locally with `signing_key`: [`sshsig_signed_data`] over the SHA-512
/// of `message`, wrapped as [`armor_ssh_signature`] describes.
pub fn create_ssh_signature(
    signing_key: &SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    namespace: &str,
    message: &[u8],
) -> Result<String> {
    use ed25519_dalek::Signer;

    let message_hash = sshsig_message_hash(message);
    let sig = signing_key.sign(&sshsig_signed_data(namespace, &message_hash));
    Ok(armor_ssh_signature(verifying_key, namespace, &sig))
}

/// `H(message)` for an SSHSIG signature: SHA-512, the hash git and
/// `ssh-keygen -Y sign` use.
pub fn sshsig_message_hash(message: &[u8]) -> [u8; 64] {
    Sha512::digest(message).into()
}

/// The bytes an SSHSIG signature is made over, for a SHA-512 `message_hash`
/// (PROTOCOL.sshsig §4):
///
///   MAGIC_PREAMBLE ("SSHSIG")
///   namespace (string)
///   reserved (empty string)
///   hash_algorithm (string: "sha512")
///   H(message) (string)
///
/// A VTA serving `keys/sign-sshsig/0.1` builds the same bytes from the digest
/// and signs them; [`assemble_ssh_signature`] checks the answer against them.
pub fn sshsig_signed_data(namespace: &str, message_hash: &[u8; 64]) -> Vec<u8> {
    let mut signed_data = Vec::new();
    signed_data.extend_from_slice(SSHSIG_MAGIC);
    write_ssh_string(&mut signed_data, namespace.as_bytes());
    write_ssh_string(&mut signed_data, b""); // reserved
    write_ssh_string(&mut signed_data, b"sha512");
    write_ssh_string(&mut signed_data, message_hash);
    signed_data
}

/// Armor a signature made elsewhere — by a VTA that holds the key — as an
/// SSHSIG signature over `message`.
///
/// The signature is verified against `verifying_key` over the SSHSIG signed
/// data before it is armored, so a wrong key, a wrong namespace or a signature
/// over anything else is refused here rather than written into a commit that
/// would fail verification later.
pub fn assemble_ssh_signature(
    verifying_key: &ed25519_dalek::VerifyingKey,
    namespace: &str,
    message: &[u8],
    signature: &[u8],
) -> Result<String> {
    use ed25519_dalek::Verifier;

    let sig = ed25519_dalek::Signature::from_slice(signature)
        .map_err(|e| anyhow::anyhow!("remote signature is not an Ed25519 signature: {e}"))?;
    let signed_data = sshsig_signed_data(namespace, &sshsig_message_hash(message));
    verifying_key.verify(&signed_data, &sig).map_err(|_| {
        anyhow::anyhow!(
            "remote signature does not verify as an SSHSIG signature by this key in namespace \
             {namespace:?}"
        )
    })?;
    Ok(armor_ssh_signature(verifying_key, namespace, &sig))
}

/// Wrap a signature over [`sshsig_signed_data`] in the SSHSIG blob and its
/// armor.
///
/// The signature blob structure is:
///   MAGIC_PREAMBLE
///   version (uint32: 1)
///   publickey (SSH wire format)
///   namespace (string)
///   reserved (empty string)
///   hash_algorithm (string)
///   signature (SSH wire format)
fn armor_ssh_signature(
    verifying_key: &ed25519_dalek::VerifyingKey,
    namespace: &str,
    sig: &ed25519_dalek::Signature,
) -> String {
    let pubkey_blob = encode_ssh_ed25519_pubkey(verifying_key);
    let sig_blob = encode_ssh_ed25519_signature(sig);

    let mut sshsig_blob = Vec::new();
    sshsig_blob.extend_from_slice(SSHSIG_MAGIC);
    write_u32(&mut sshsig_blob, 1); // version
    write_ssh_string(&mut sshsig_blob, &pubkey_blob); // publickey
    write_ssh_string(&mut sshsig_blob, namespace.as_bytes()); // namespace
    write_ssh_string(&mut sshsig_blob, b""); // reserved
    write_ssh_string(&mut sshsig_blob, b"sha512"); // hash algorithm
    write_ssh_string(&mut sshsig_blob, &sig_blob); // signature

    // Armor with PEM-style headers
    // Note: base64 output is always valid ASCII/UTF-8, so from_utf8 cannot fail here.
    let b64 = base64_encode(&sshsig_blob);
    let mut armored = String::new();
    armored.push_str("-----BEGIN SSH SIGNATURE-----\n");
    // OpenSSH wraps sshsig base64 at 70 columns (sshbuf_dtob64). Match it
    // exactly: RustCrypto's ssh-encoding PEM parser rejects other widths, so
    // any deviation makes our signatures unreadable to non-OpenSSH verifiers.
    for chunk in b64.as_bytes().chunks(70) {
        armored.push_str(std::str::from_utf8(chunk).expect("base64 output is always valid UTF-8"));
        armored.push('\n');
    }
    armored.push_str("-----END SSH SIGNATURE-----\n");
    armored
}

/// Encode an Ed25519 public key in SSH wire format:
///   string "ssh-ed25519"
///   string <32-byte public key>
fn encode_ssh_ed25519_pubkey(key: &ed25519_dalek::VerifyingKey) -> Vec<u8> {
    let mut buf = Vec::new();
    write_ssh_string(&mut buf, b"ssh-ed25519");
    write_ssh_string(&mut buf, key.as_bytes());
    buf
}

/// Encode an Ed25519 signature in SSH wire format:
///   string "ssh-ed25519"
///   string <64-byte signature>
fn encode_ssh_ed25519_signature(sig: &ed25519_dalek::Signature) -> Vec<u8> {
    let mut buf = Vec::new();
    write_ssh_string(&mut buf, b"ssh-ed25519");
    write_ssh_string(&mut buf, &sig.to_bytes());
    buf
}

/// Write a uint32 in big-endian.
fn write_u32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_be_bytes());
}

/// Write an SSH "string" (uint32 length prefix + raw bytes).
fn write_ssh_string(buf: &mut Vec<u8>, data: &[u8]) {
    write_u32(buf, data.len() as u32);
    buf.extend_from_slice(data);
}

/// Base64-encode without line wrapping (we handle wrapping separately).
fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A signature made over [`sshsig_signed_data`] by whoever holds the key —
    /// a VTA serving `keys/sign-sshsig` — armors to exactly what signing
    /// locally produces. Ed25519 is deterministic, so the two are byte-equal.
    #[test]
    fn a_remote_signature_assembles_to_the_local_one() {
        use ed25519_dalek::Signer;
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"tree 4b825dc6\nauthor A <a@x> 1 +0000\n\nmsg\n";

        // What the VTA signs, from the digest alone.
        let remote = signing_key.sign(&sshsig_signed_data("git", &sshsig_message_hash(message)));
        let assembled =
            assemble_ssh_signature(&verifying_key, "git", message, &remote.to_bytes()).unwrap();
        let local = create_ssh_signature(&signing_key, &verifying_key, "git", message).unwrap();
        assert_eq!(assembled, local);
    }

    /// Anything but an SSHSIG signature by this key, in this namespace, over
    /// this message is refused before it is armored.
    #[test]
    fn a_remote_signature_that_does_not_verify_is_refused() {
        use ed25519_dalek::Signer;
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = signing_key.verifying_key();
        let message = b"a commit";
        let hash = sshsig_message_hash(message);

        let other_namespace = signing_key.sign(&sshsig_signed_data("file", &hash));
        let raw_digest = signing_key.sign(&hash);
        let other_key = SigningKey::from_bytes(&[7u8; 32]).sign(&sshsig_signed_data("git", &hash));
        for sig in [other_namespace, raw_digest, other_key] {
            assert!(
                assemble_ssh_signature(&verifying_key, "git", message, &sig.to_bytes()).is_err()
            );
        }
        assert!(assemble_ssh_signature(&verifying_key, "git", message, &[0u8; 12]).is_err());
    }

    #[test]
    fn test_ssh_string_encoding() {
        let mut buf = Vec::new();
        write_ssh_string(&mut buf, b"ssh-ed25519");
        assert_eq!(buf.len(), 4 + 11);
        assert_eq!(&buf[..4], &[0, 0, 0, 11]);
        assert_eq!(&buf[4..], b"ssh-ed25519");
    }

    #[test]
    fn test_pubkey_blob_format() {
        let seed = [0u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let blob = encode_ssh_ed25519_pubkey(&verifying_key);
        // "ssh-ed25519" (4+11) + pubkey (4+32) = 51 bytes
        assert_eq!(blob.len(), 51);
    }

    #[test]
    fn test_signature_is_valid_sshsig() {
        let seed = [42u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let result = create_ssh_signature(&signing_key, &verifying_key, "git", b"test commit data");
        assert!(result.is_ok());
        let armored = result.unwrap();
        assert!(armored.starts_with("-----BEGIN SSH SIGNATURE-----\n"));
        assert!(armored.ends_with("-----END SSH SIGNATURE-----\n"));
    }

    #[test]
    fn test_sshsig_blob_contains_magic_and_version() {
        let seed = [7u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let armored = create_ssh_signature(&signing_key, &verifying_key, "git", b"hello").unwrap();

        // Extract base64 content between the armor headers
        let b64: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let blob =
            base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &b64).unwrap();

        // First 6 bytes must be "SSHSIG" magic
        assert_eq!(&blob[..6], b"SSHSIG");
        // Next 4 bytes must be version 1 (big-endian u32)
        assert_eq!(&blob[6..10], &[0, 0, 0, 1]);
    }

    #[test]
    fn test_signature_deterministic_for_same_inputs() {
        let seed = [99u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let msg = b"same message";

        let sig1 = create_ssh_signature(&signing_key, &verifying_key, "git", msg).unwrap();
        let sig2 = create_ssh_signature(&signing_key, &verifying_key, "git", msg).unwrap();
        // Ed25519 signatures are deterministic
        assert_eq!(sig1, sig2);
    }

    #[test]
    fn test_signature_differs_for_different_messages() {
        let seed = [55u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();

        let sig1 = create_ssh_signature(&signing_key, &verifying_key, "git", b"msg A").unwrap();
        let sig2 = create_ssh_signature(&signing_key, &verifying_key, "git", b"msg B").unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_signature_differs_for_different_namespaces() {
        let seed = [88u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let msg = b"same data";

        let sig1 = create_ssh_signature(&signing_key, &verifying_key, "git", msg).unwrap();
        let sig2 = create_ssh_signature(&signing_key, &verifying_key, "file", msg).unwrap();
        assert_ne!(sig1, sig2);
    }

    #[test]
    fn test_signature_blob_wraps_at_70_like_openssh() {
        let seed = [1u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let armored =
            create_ssh_signature(&signing_key, &verifying_key, "git", b"check line wrap").unwrap();

        let body: Vec<&str> = armored
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        // Every full line is exactly 70 columns (only the last may be
        // shorter) — the width ssh-keygen emits and strict PEM parsers
        // (RustCrypto ssh-encoding) require.
        for line in &body[..body.len() - 1] {
            assert_eq!(line.len(), 70, "base64 line is {} chars", line.len());
        }
        assert!(body[body.len() - 1].len() <= 70);
    }

    #[test]
    fn test_write_u32_big_endian() {
        let mut buf = Vec::new();
        write_u32(&mut buf, 0x01020304);
        assert_eq!(buf, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_signature_blob_encoding() {
        use ed25519_dalek::Signer;
        let seed = [0xBB; 32];
        let signing_key = SigningKey::from_bytes(&seed);
        let sig = signing_key.sign(b"test");
        let blob = encode_ssh_ed25519_signature(&sig);
        // "ssh-ed25519" (4+11) + signature (4+64) = 83 bytes
        assert_eq!(blob.len(), 83);
        // Type string is "ssh-ed25519"
        assert_eq!(&blob[4..15], b"ssh-ed25519");
    }
}
