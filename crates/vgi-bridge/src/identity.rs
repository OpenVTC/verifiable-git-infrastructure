//! The bridge's own DID and keys.
//!
//! The bridge is a companion service with its own DID (design §5.1): the VTC
//! records, per namespace, which bridge DID serves it, and refuses results
//! and events from any other. Two shapes, per the VTI house rules:
//!
//! - **`did:webvh`, provisioned by the community's VTA** (recommended). The
//!   operator provisions a DID for the bridge from the VTA the same way the
//!   VTC's is (a DID template), and imports the resulting secrets bundle with
//!   `vgi-bridge identity import`. The VTA mints; the bridge only holds.
//! - **`did:key`**, minted locally by `vgi-bridge init` — for a first
//!   deployment or a test community. Nothing to host, nothing to rotate
//!   without re-registering the bridge DID at the VTC.
//!
//! Either way the private keys are held only in the sealed store, and the
//! same keys serve DIDComm (authcrypt) and the Data Integrity proofs on every
//! Trust Task document the bridge sends.

use std::fmt;

use affinidi_tdk::affinidi_crypto::KeyType;
use affinidi_tdk::secrets_resolver::secrets::Secret;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use trust_tasks_proof::affinidi::{SignOptions, sign_trust_task};
use vta_sdk::did_secrets::DidSecretsBundle;
use zeroize::Zeroizing;

use crate::store::Store;

/// The sealed secret the identity is stored under.
pub const IDENTITY_SECRET: &str = "identity";

/// What the sealed identity secret holds.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", tag = "type")]
enum StoredIdentity {
    /// A locally minted `did:key`: its 32-byte Ed25519 seed, hex.
    DidKey { did: String, seed: String },
    /// A VTA-provisioned DID: its secrets bundle.
    Bundle { bundle: DidSecretsBundle },
}

/// The bridge's DID and the secrets behind it.
#[derive(Clone)]
pub struct BridgeIdentity {
    did: String,
    signing: Secret,
    secrets: Vec<Secret>,
}

impl fmt::Debug for BridgeIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BridgeIdentity")
            .field("did", &self.did)
            .field("secrets", &self.secrets.len())
            .finish()
    }
}

impl BridgeIdentity {
    /// A new `did:key` from a fresh Ed25519 seed. Returns the identity and
    /// the seed to seal.
    pub fn generate_did_key() -> Result<(Self, Zeroizing<[u8; 32]>)> {
        let mut seed = Zeroizing::new([0u8; 32]);
        aws_lc_rs::rand::fill(seed.as_mut())
            .map_err(|_| anyhow::anyhow!("system RNG unavailable"))?;
        let identity = Self::from_seed(&seed)?;
        Ok((identity, seed))
    }

    /// The `did:key` for an Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let public = ed25519_dalek::SigningKey::from_bytes(seed)
            .verifying_key()
            .to_bytes();
        let did = format!(
            "did:key:{}",
            vta_sdk::did_key::ed25519_multibase_pubkey(&public)
        );
        let s = vta_sdk::did_key::secrets_from_did_key(&did, seed)
            .map_err(|e| anyhow::anyhow!("did:key secrets: {e}"))?;
        Ok(BridgeIdentity {
            did,
            signing: s.signing.clone(),
            secrets: vec![s.signing, s.key_agreement],
        })
    }

    /// An identity from a VTA-provisioned secrets bundle. Its first Ed25519
    /// key signs; every key goes to DIDComm.
    pub fn from_bundle(bundle: &DidSecretsBundle) -> Result<Self> {
        let secrets = vta_sdk::did_key::secrets_from_bundle(bundle)
            .map_err(|e| anyhow::anyhow!("DID secrets bundle: {e}"))?;
        for s in &secrets {
            if !s.id.starts_with(&format!("{}#", bundle.did)) {
                bail!(
                    "bundle key `{}` does not belong to `{}`: refusing a bundle for another DID",
                    s.id,
                    bundle.did
                );
            }
        }
        let signing = secrets
            .iter()
            .find(|s| s.get_key_type() == KeyType::Ed25519)
            .cloned()
            .context("the bundle has no Ed25519 key to sign documents with")?;
        if !secrets.iter().any(|s| s.get_key_type() == KeyType::X25519) {
            bail!("the bundle has no X25519 key-agreement key; DIDComm needs one");
        }
        Ok(BridgeIdentity {
            did: bundle.did.clone(),
            signing,
            secrets,
        })
    }

    /// Seal a `did:key` seed as the bridge's identity.
    pub fn store_did_key(store: &Store, seed: &[u8; 32]) -> Result<Self> {
        let identity = Self::from_seed(seed)?;
        let stored = StoredIdentity::DidKey {
            did: identity.did.clone(),
            seed: hex::encode(seed),
        };
        let json = Zeroizing::new(serde_json::to_vec(&stored)?);
        store.put_secret(IDENTITY_SECRET, &json)?;
        Ok(identity)
    }

    /// Seal a VTA-provisioned bundle as the bridge's identity.
    pub fn store_bundle(store: &Store, bundle: DidSecretsBundle) -> Result<Self> {
        let identity = Self::from_bundle(&bundle)?;
        let json = Zeroizing::new(serde_json::to_vec(&StoredIdentity::Bundle { bundle })?);
        store.put_secret(IDENTITY_SECRET, &json)?;
        Ok(identity)
    }

    /// Load the sealed identity. `None` before `init` / `identity import`.
    pub fn load(store: &Store) -> Result<Option<Self>> {
        let Some(bytes) = store.get_secret(IDENTITY_SECRET)? else {
            return Ok(None);
        };
        let stored: StoredIdentity =
            serde_json::from_slice(&bytes).context("decoding the sealed identity")?;
        Ok(Some(match stored {
            StoredIdentity::DidKey { did, seed } => {
                let raw = Zeroizing::new(hex::decode(seed).context("identity seed")?);
                let seed: [u8; 32] = raw
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("identity seed is not 32 bytes"))?;
                let id = Self::from_seed(&seed)?;
                if id.did != did {
                    bail!("the sealed seed does not derive the sealed DID `{did}`");
                }
                id
            }
            StoredIdentity::Bundle { bundle } => Self::from_bundle(&bundle)?,
        }))
    }

    /// The bridge's DID.
    pub fn did(&self) -> &str {
        &self.did
    }

    /// Every secret DIDComm needs (signing and key agreement).
    pub fn messaging_secrets(&self) -> Vec<Secret> {
        self.secrets.clone()
    }

    /// Sign a Trust Task document (`eddsa-jcs-2022`, `assertionMethod`).
    /// `doc.issuer` must already be this DID.
    pub async fn sign(&self, doc: &Value) -> Result<Value> {
        sign_trust_task(doc, &self.signing, SignOptions::new())
            .await
            .map_err(|e| anyhow::anyhow!("signing a document: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::MasterKey;
    use trust_tasks_proof::affinidi::Verifier;

    #[tokio::test]
    async fn a_did_key_signs_what_a_did_key_verifier_accepts() {
        let (id, seed) = BridgeIdentity::generate_did_key().unwrap();
        assert!(id.did().starts_with("did:key:z6Mk"));
        let doc = serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/git-ns/bridge/result/0.1",
            "issuer": id.did(),
            "payload": { "jobId": "j", "outcome": "succeeded" },
        });
        let signed = id.sign(&doc).await.unwrap();
        Verifier::for_did_key().verify_raw(&signed).await.unwrap();

        let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        BridgeIdentity::store_did_key(&store, &seed).unwrap();
        let back = BridgeIdentity::load(&store).unwrap().unwrap();
        assert_eq!(back.did(), id.did());
        assert_eq!(back.messaging_secrets().len(), 2);
        assert!(!format!("{back:?}").contains(&hex::encode(*seed)));
    }

    #[tokio::test]
    async fn signing_for_another_issuer_is_refused() {
        let (id, _) = BridgeIdentity::generate_did_key().unwrap();
        let doc = serde_json::json!({ "id": "x", "issuer": "did:key:z6MkOther", "payload": {} });
        assert!(id.sign(&doc).await.is_err());
    }
}
