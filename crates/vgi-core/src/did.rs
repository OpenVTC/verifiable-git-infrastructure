//! DID-document key extraction.
//!
//! Signers are declared as DIDs; their signing keys are resolved from the
//! `verificationMethod` entries of their DID documents at verification time,
//! so key rotation never requires touching the repository.

/// Multicodec prefix for an Ed25519 public key in `publicKeyMultibase`.
pub const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xED, 0x01];

/// Extract every Ed25519 public key from a DID document's verification
/// methods (`publicKeyMultibase`, multicodec `0xED01`).
pub fn ed25519_keys_from_doc(doc: &serde_json::Value) -> Vec<[u8; 32]> {
    let Some(methods) = doc.get("verificationMethod").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    methods
        .iter()
        .filter_map(|method| method.get("publicKeyMultibase")?.as_str())
        .filter_map(|encoded| multibase::decode(encoded).ok())
        .filter_map(|(_base, bytes)| {
            let raw = bytes.strip_prefix(&ED25519_MULTICODEC_PREFIX)?;
            <[u8; 32]>::try_from(raw).ok()
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_keys_are_extracted_from_a_did_document() {
        let public = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        let mut multicodec = ED25519_MULTICODEC_PREFIX.to_vec();
        multicodec.extend_from_slice(&public);
        let encoded = multibase::encode(multibase::Base::Base58Btc, &multicodec);

        let doc = serde_json::json!({
            "id": "did:example:signer",
            "verificationMethod": [
                { "id": "did:example:signer#key-0", "publicKeyMultibase": encoded },
                { "id": "did:example:signer#key-x", "publicKeyMultibase": "zInvalid!" },
                { "id": "did:example:signer#key-jwk" }
            ]
        });
        let keys = ed25519_keys_from_doc(&doc);
        assert_eq!(keys, vec![public]);
    }
}
