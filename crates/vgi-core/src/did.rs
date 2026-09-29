//! DID-document key extraction.
//!
//! Signers are declared as DIDs; their signing keys are resolved from the
//! `assertionMethod` relationship of their DID documents at verification time,
//! so key rotation never requires touching the repository.

use serde_json::Value;

/// Multicodec prefix for an Ed25519 public key in `publicKeyMultibase`.
pub const ED25519_MULTICODEC_PREFIX: [u8; 2] = [0xED, 0x01];

/// Extract the Ed25519 public keys a DID document authorizes for signing: the
/// methods its `assertionMethod` relationship lists (`publicKeyMultibase`,
/// multicodec `0xED01`).
///
/// A commit signature is an assertion made as the DID, so a key the document
/// merely *contains* is not enough: a key agreement, recovery or custodian key
/// listed in `verificationMethod` but not under `assertionMethod` was never
/// authorized to sign as the DID, and must not verify commits as it.
///
/// An entry is either a reference to one of the document's own
/// `verificationMethod`s — absolute (`did:…#key-0`) or relative (`#key-0`) —
/// or a method embedded in the relationship. A reference to a method the
/// document does not contain is not followed. A method whose `controller`
/// names a different DID is skipped: its key is someone else's to use.
pub fn ed25519_signing_keys_from_doc(doc: &Value) -> Vec<[u8; 32]> {
    let did = doc.get("id").and_then(Value::as_str).unwrap_or_default();
    let absolute = |id: &str| {
        if id.starts_with('#') {
            format!("{did}{id}")
        } else {
            id.to_string()
        }
    };
    let own_key = |method: &Value| -> Option<[u8; 32]> {
        if let Some(controller) = method.get("controller")
            && controller.as_str() != Some(did)
        {
            return None;
        }
        let encoded = method.get("publicKeyMultibase")?.as_str()?;
        let (_base, bytes) = multibase::decode(encoded).ok()?;
        let raw = bytes.strip_prefix(&ED25519_MULTICODEC_PREFIX)?;
        <[u8; 32]>::try_from(raw).ok()
    };
    let methods: Vec<(String, &Value)> = doc
        .get("verificationMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|method| Some((absolute(method.get("id")?.as_str()?), method)))
        .collect();

    let mut keys: Vec<[u8; 32]> = Vec::new();
    for entry in doc
        .get("assertionMethod")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let key = match entry {
            Value::String(reference) => {
                let id = absolute(reference);
                methods
                    .iter()
                    .find(|(method_id, _)| *method_id == id)
                    .and_then(|(_, method)| own_key(method))
            }
            embedded => own_key(embedded),
        };
        if let Some(key) = key
            && !keys.contains(&key)
        {
            keys.push(key);
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const DID: &str = "did:example:signer";

    fn encoded(seed: u8) -> ([u8; 32], String) {
        let public = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        let mut multicodec = ED25519_MULTICODEC_PREFIX.to_vec();
        multicodec.extend_from_slice(&public);
        (
            public,
            multibase::encode(multibase::Base::Base58Btc, &multicodec),
        )
    }

    #[test]
    fn assertion_method_keys_are_extracted() {
        let (public, key) = encoded(7);
        let doc = json!({
            "id": DID,
            "verificationMethod": [
                { "id": format!("{DID}#key-0"), "controller": DID, "publicKeyMultibase": key },
                { "id": format!("{DID}#key-x"), "publicKeyMultibase": "zInvalid!" },
                { "id": format!("{DID}#key-jwk") }
            ],
            "assertionMethod": [
                format!("{DID}#key-0"), format!("{DID}#key-x"), format!("{DID}#key-jwk")
            ]
        });
        assert_eq!(ed25519_signing_keys_from_doc(&doc), vec![public]);
    }

    #[test]
    fn relative_references_and_embedded_methods_count() {
        let (relative, relative_key) = encoded(1);
        let (embedded, embedded_key) = encoded(2);
        let doc = json!({
            "id": DID,
            "verificationMethod": [
                { "id": "#key-0", "controller": DID, "publicKeyMultibase": relative_key }
            ],
            "assertionMethod": [
                "#key-0",
                { "id": "#key-1", "controller": DID, "publicKeyMultibase": embedded_key }
            ]
        });
        assert_eq!(
            ed25519_signing_keys_from_doc(&doc),
            vec![relative, embedded]
        );
    }

    /// VGI-02: an Ed25519 key the document lists for some other purpose was
    /// never authorized to sign as the DID.
    #[test]
    fn a_key_not_listed_under_assertion_method_is_not_a_signing_key() {
        let (signing, signing_key) = encoded(1);
        let (_, other_key) = encoded(2);
        let doc = json!({
            "id": DID,
            "verificationMethod": [
                { "id": format!("{DID}#key-0"), "controller": DID, "publicKeyMultibase": signing_key },
                { "id": format!("{DID}#recovery"), "controller": DID, "publicKeyMultibase": other_key }
            ],
            "authentication": [format!("{DID}#recovery")],
            "capabilityInvocation": [format!("{DID}#recovery")],
            "assertionMethod": [format!("{DID}#key-0")]
        });
        assert_eq!(ed25519_signing_keys_from_doc(&doc), vec![signing]);
    }

    #[test]
    fn a_document_without_assertion_method_has_no_signing_keys() {
        let (_, key) = encoded(1);
        let doc = json!({
            "id": DID,
            "verificationMethod": [
                { "id": format!("{DID}#key-0"), "controller": DID, "publicKeyMultibase": key }
            ],
            "authentication": [format!("{DID}#key-0")]
        });
        assert!(ed25519_signing_keys_from_doc(&doc).is_empty());
    }

    #[test]
    fn a_method_controlled_by_another_did_is_skipped() {
        let (_, key) = encoded(1);
        let doc = json!({
            "id": DID,
            "verificationMethod": [{
                "id": format!("{DID}#key-0"),
                "controller": "did:example:someone-else",
                "publicKeyMultibase": key
            }],
            "assertionMethod": [
                format!("{DID}#key-0"),
                { "id": "#key-1", "controller": "did:example:someone-else", "publicKeyMultibase": key }
            ]
        });
        assert!(ed25519_signing_keys_from_doc(&doc).is_empty());
    }

    #[test]
    fn a_reference_to_a_method_the_document_lacks_is_not_followed() {
        let doc = json!({ "id": DID, "assertionMethod": ["did:example:other#key-0"] });
        assert!(ed25519_signing_keys_from_doc(&doc).is_empty());
    }
}
