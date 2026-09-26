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
//! - **`did:peer:2`**, minted locally by `vgi-bridge init`. Nothing to host:
//!   the identifier carries the keys *and* a `DIDCommMessaging` service
//!   naming the mediator the bridge listens at, which is how the VTC finds
//!   where to send jobs (it picks a transport from the services the bridge's
//!   DID document advertises, and a `did:key` advertises none). Because the
//!   mediator is part of the identifier, moving the bridge to another
//!   mediator means a new DID, registered again at the VTC.
//! - **`did:key`**: still loaded from a store that holds one (earlier
//!   releases minted it), but a VTC cannot send it jobs; `run` says so.
//!
//! In VTA mode ([`crate::vta`]) the identity is the `did:webvh` of the
//! bridge's own context in the VTC's VTA: its keys are fetched into memory at
//! start-up and never stored here, and a rotation in the VTA replaces them at
//! run time ([`crate::Bridge::replace_identity`]).
//!
//! Otherwise the private keys are held only in the sealed store, and the
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

/// The longest DID the bridge mints. Every `DIDCacheClient` refuses to parse
/// a longer one (`max_did_size_in_bytes`, default 1000), and neither end of a
/// DIDComm session says that is why it failed: the connect times out. A
/// `did:peer:2` carries its service inside the identifier, so a mediator with
/// a long DID (a `did:peer` of its own) can push it past this.
pub const MAX_DID_BYTES: usize = 1000;

/// The DID-document service `type` of a DIDComm v2 endpoint (W3C) — what
/// the VTC selects a bridge's transport by.
pub const DIDCOMM_SERVICE_TYPE: &str = "DIDCommMessaging";

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

    /// A new `did:peer:2` whose document advertises DIDComm through
    /// `mediator_did`: an Ed25519 key that signs (and authenticates), an
    /// X25519 key for key agreement, and one `DIDCommMessaging` service. The
    /// returned bundle is what to seal ([`Self::store_bundle`]).
    pub fn generate_did_peer(mediator_did: &str) -> Result<(Self, DidSecretsBundle)> {
        use affinidi_tdk::dids::{
            DID, OneOrMany, PeerKeyRole, PeerService, PeerServiceEndpoint, PeerServiceEndpointLong,
        };
        if mediator_did.trim().is_empty() || !mediator_did.starts_with("did:") {
            bail!("`{mediator_did}` is not a mediator DID");
        }
        let service = PeerService {
            type_: DIDCOMM_SERVICE_TYPE.into(),
            endpoint: PeerServiceEndpoint::Long(OneOrMany::One(PeerServiceEndpointLong {
                uri: mediator_did.to_string(),
                accept: vec!["didcomm/v2".into()],
                routing_keys: vec![],
            })),
            id: None,
        };
        let (did, secrets) = DID::generate_did_peer_with_services(
            vec![
                (
                    PeerKeyRole::Verification,
                    affinidi_tdk::dids::KeyType::Ed25519,
                ),
                (PeerKeyRole::Encryption, affinidi_tdk::dids::KeyType::X25519),
            ],
            Some(vec![service]),
        )
        .map_err(|e| anyhow::anyhow!("minting a did:peer: {e}"))?;
        if did.len() > MAX_DID_BYTES {
            bail!(
                "the did:peer this would mint is {} bytes, past the {MAX_DID_BYTES}-byte limit \
                 every DID resolver enforces, so the VTC could not resolve it. A did:peer \
                 carries its mediator inside the identifier: use a mediator with a short DID \
                 (a did:web or did:webvh), or provision a did:webvh for the bridge instead",
                did.len()
            );
        }
        let bundle = bundle_of(&did, &secrets)?;
        let identity = Self::from_bundle(&bundle)?;
        match advertised_mediator(&did)? {
            Some(m) if m == mediator_did => {}
            other => {
                bail!("the minted did:peer advertises {other:?}, not `{mediator_did}`: refusing it")
            }
        }
        Ok((identity, bundle))
    }

    /// The identity as a secrets bundle — the format `identity import`
    /// reads, so an export is restored by importing it. Key material.
    pub fn to_bundle(&self) -> Result<DidSecretsBundle> {
        bundle_of(&self.did, &self.secrets)
    }

    /// The sealed identity as a secrets bundle, for export: an imported or
    /// minted bundle exactly as stored — every key it carries, whatever its
    /// type — and a `did:key` seed as the bundle of its two keys. `None`
    /// before `init` / `identity import`.
    pub fn stored_bundle(store: &Store) -> Result<Option<DidSecretsBundle>> {
        let Some(bytes) = store.get_secret(IDENTITY_SECRET)? else {
            return Ok(None);
        };
        let stored: StoredIdentity =
            serde_json::from_slice(&bytes).context("decoding the sealed identity")?;
        match stored {
            StoredIdentity::Bundle { bundle } => Ok(Some(bundle)),
            StoredIdentity::DidKey { .. } => {
                Self::load(store)?.map(|id| id.to_bundle()).transpose()
            }
        }
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

    /// An identity from secrets already checked against the DID's current
    /// document (VTA mode, [`crate::vta`]): `signing` signs, every secret
    /// goes to DIDComm (all the key-agreement keys the document lists, so a
    /// message encrypted to any of them — during a rotation's overlap —
    /// still opens).
    pub fn from_secrets(did: &str, signing: Secret, secrets: Vec<Secret>) -> Result<Self> {
        for s in &secrets {
            if !s.id.starts_with(&format!("{did}#")) {
                bail!("key `{}` does not belong to `{did}`", s.id);
            }
        }
        if signing.get_key_type() != KeyType::Ed25519 || !secrets.iter().any(|s| s.id == signing.id)
        {
            bail!(
                "the signing key `{}` is not an Ed25519 key of the set",
                signing.id
            );
        }
        Ok(BridgeIdentity {
            did: did.to_string(),
            signing,
            secrets,
        })
    }

    /// The verification method that signs.
    pub fn signing_key_id(&self) -> &str {
        &self.signing.id
    }

    /// Every secret held.
    pub(crate) fn secrets(&self) -> &[Secret] {
        &self.secrets
    }

    /// Whether `other` holds the same keys (ids and public halves).
    pub fn same_keys(&self, other: &BridgeIdentity) -> bool {
        let keys = |i: &BridgeIdentity| {
            let mut v: Vec<(String, Vec<u8>)> = i
                .secrets
                .iter()
                .map(|s| (s.id.clone(), s.get_public_bytes().to_vec()))
                .collect();
            v.sort();
            v
        };
        self.did == other.did && self.signing.id == other.signing.id && keys(self) == keys(other)
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

/// A secrets bundle for `did` from its secrets.
fn bundle_of(did: &str, secrets: &[Secret]) -> Result<DidSecretsBundle> {
    use vta_sdk::did_secrets::SecretEntry;
    use vta_sdk::keys::KeyType as BundleKeyType;
    let secrets = secrets
        .iter()
        .map(|s| {
            let key_type = match s.get_key_type() {
                KeyType::Ed25519 => BundleKeyType::Ed25519,
                KeyType::X25519 => BundleKeyType::X25519,
                other => bail!("key `{}` is {other:?}, which a bundle does not carry", s.id),
            };
            Ok(SecretEntry {
                key_id: s.id.clone(),
                key_type,
                private_key_multibase: s
                    .get_private_keymultibase()
                    .map_err(|e| anyhow::anyhow!("encoding key `{}`: {e}", s.id))?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DidSecretsBundle {
        did: did.to_string(),
        secrets,
    })
}

/// Where a DID resolvable without the network (`did:key`, `did:peer`) says
/// it takes DIDComm: the `serviceEndpoint` URI of its `DIDCommMessaging`
/// service — for a mediated party, the mediator's DID. `Ok(None)`: the
/// document advertises no DIDComm service, as a `did:key`'s never does.
/// `Err` for a DID that needs the network to resolve (`did:webvh`,
/// `did:web`): its document is its host's to publish, not the bridge's to
/// second-guess.
pub fn advertised_mediator(did: &str) -> Result<Option<String>> {
    if !(did.starts_with("did:key:") || did.starts_with("did:peer:")) {
        bail!("`{did}` is not resolvable without the network");
    }
    let parsed: affinidi_tdk::did_common::DID = did
        .parse()
        .map_err(|e| anyhow::anyhow!("`{did}` is not a DID: {e}"))?;
    let doc = parsed
        .resolve()
        .map_err(|e| anyhow::anyhow!("resolving `{did}`: {e}"))?;
    let doc = serde_json::to_value(&doc)?;
    let Some(services) = doc.get("service").and_then(Value::as_array) else {
        return Ok(None);
    };
    Ok(services.iter().find_map(|svc| {
        let typed = match svc.get("type") {
            Some(Value::String(t)) => t == DIDCOMM_SERVICE_TYPE,
            Some(Value::Array(ts)) => ts.iter().any(|t| t == DIDCOMM_SERVICE_TYPE),
            _ => false,
        };
        typed
            .then(|| svc.get("serviceEndpoint").and_then(endpoint_uri))
            .flatten()
    }))
}

fn endpoint_uri(endpoint: &Value) -> Option<String> {
    match endpoint {
        Value::String(s) => Some(s.clone()),
        Value::Object(map) => map.get("uri")?.as_str().map(str::to_string),
        Value::Array(arr) => arr.iter().find_map(endpoint_uri),
        _ => None,
    }
}

/// Whether the VTC can reach `did` through `mediator_did` — the check `run`
/// and `identity import` make before a bridge goes into service.
///
/// - `Ok(None)`: yes, or it cannot be told locally (a `did:webvh` publishes
///   its own document; the VTC resolves it).
/// - `Ok(Some(warning))`: the DID advertises no DIDComm service (a
///   `did:key`), so no VTC can send it jobs. The bridge still runs — results
///   and events still go out — but the operator must know.
/// - `Err`: the DID names another mediator. A `did:peer` names its mediator
///   forever; served from a different one, the VTC would deliver jobs where
///   the bridge no longer listens, and nothing would say why.
pub fn check_reachable(did: &str, mediator_did: &str) -> Result<Option<String>> {
    if !(did.starts_with("did:key:") || did.starts_with("did:peer:")) {
        return Ok(None);
    }
    match advertised_mediator(did)? {
        Some(m) if m == mediator_did => Ok(None),
        Some(m) => bail!(
            "the bridge's DID `{did}` advertises the mediator `{m}`, but the config names \
             `{mediator_did}`. A did:peer names its mediator in its identifier, so the VTC \
             would send jobs to `{m}`, where this bridge would not be listening.\n\
             Fix (recommended, and the only one that keeps bound namespaces working): set \
             `mediator_did = \"{m}\"` back in the config.\n\
             Only for a bridge that serves no bound namespace: mint a new identity \
             (`vgi-bridge identity mint --replace --backup <file>`) and register the new DID \
             at the VTC — see `identity mint --help` for what a new DID breaks"
        ),
        None => Ok(Some(format!(
            "the bridge's DID `{did}` advertises no DIDComm service, so no VTC can send it \
             jobs (they fail with `noMatchingProtocol`). Mint a did:peer that names the \
             mediator (`vgi-bridge identity mint --replace --backup <file>`) and register \
             the new DID at the VTC"
        ))),
    }
}

/// The key the bridge signs git commits with (the Dependabot re-sign): its
/// DID's Ed25519 signing key, and the verification method that names it.
/// The key is wiped when this is dropped.
pub struct GitSigningKey {
    /// The verification method id (`<did>#<fragment>`), for the
    /// `Signed-by-DID:` trailer.
    pub verification_method: String,
    /// The key.
    pub key: ed25519_dalek::SigningKey,
}

impl fmt::Debug for GitSigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GitSigningKey")
            .field("verification_method", &self.verification_method)
            .finish_non_exhaustive()
    }
}

impl BridgeIdentity {
    /// The key the bridge signs git commits with: the same Ed25519 key that
    /// signs its Trust Task documents, which its DID document publishes as a
    /// verification method (a `did:peer` or `did:key` always does; a VTA-provisioned
    /// `did:webvh` does for the key in its bundle). verify-trust resolves the
    /// DID and accepts a commit signature only from a key the document
    /// publishes. The sshsig `git` namespace keeps a commit signature from
    /// ever being mistaken for a document proof, and the other way round.
    pub fn git_signing_key(&self) -> Result<GitSigningKey> {
        let private = self.signing.get_private_bytes();
        let seed: Zeroizing<[u8; 32]> = Zeroizing::new(
            private
                .get(..32)
                .and_then(|s| <[u8; 32]>::try_from(s).ok())
                .context("the signing key is not an Ed25519 seed")?,
        );
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        if key.verifying_key().as_bytes().as_slice() != self.signing.get_public_bytes() {
            bail!("the signing key's public half does not match the identity");
        }
        if !self.signing.id.starts_with(&format!("{}#", self.did)) {
            bail!(
                "the signing key `{}` is not a verification method of `{}`",
                self.signing.id,
                self.did
            );
        }
        Ok(GitSigningKey {
            verification_method: self.signing.id.clone(),
            key,
        })
    }

    /// Sign with a chosen `proofPurpose` — for tests of the purpose check
    /// only; every document the bridge sends is an `assertionMethod` proof.
    #[doc(hidden)]
    pub async fn sign_with_purpose(&self, doc: &Value, purpose: &str) -> Result<Value> {
        sign_trust_task(
            doc,
            &self.signing,
            SignOptions::new().with_proof_purpose(purpose),
        )
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

    #[test]
    fn the_git_signing_key_is_the_did_key() {
        let id = BridgeIdentity::from_seed(&[5u8; 32]).unwrap();
        let k = id.git_signing_key().unwrap();
        assert_eq!(k.key.to_bytes(), [5u8; 32]);
        let mb = id.did().strip_prefix("did:key:").unwrap();
        assert_eq!(k.verification_method, format!("{}#{mb}", id.did()));
        assert!(
            format!("{k:?}").ends_with(", .. }"),
            "no key material in Debug"
        );
    }

    const MEDIATOR: &str = "did:web:mediator.acme-vtc.example";

    #[tokio::test]
    async fn a_did_peer_advertises_didcomm_through_its_mediator() {
        let (id, bundle) = BridgeIdentity::generate_did_peer(MEDIATOR).unwrap();
        assert!(id.did().starts_with("did:peer:2."), "{}", id.did());
        assert!(id.did().len() <= MAX_DID_BYTES);
        // A bare DID by the Trust Task `Did` syntax, and one a commit
        // trailer's `#`/`?`/`/` split leaves whole (the Dependabot re-sign):
        // base64url, no padding.
        assert!(
            id.did()
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || ":.-_".contains(c)),
            "{}",
            id.did()
        );
        // What the VTC selects a transport by: a `DIDCommMessaging` service
        // naming the mediator, found in the document the DID resolves to.
        assert_eq!(
            advertised_mediator(id.did()).unwrap().as_deref(),
            Some(MEDIATOR)
        );
        assert_eq!(check_reachable(id.did(), MEDIATOR).unwrap(), None);
        // The ids DIDComm looks secrets up by are the ones the document
        // names: `#key-1` signs and authenticates, `#key-2` agrees keys.
        let doc: affinidi_tdk::did_common::DID = id.did().parse().unwrap();
        let doc = serde_json::to_value(doc.resolve().unwrap()).unwrap();
        let x25519 = id
            .messaging_secrets()
            .into_iter()
            .find(|s| s.get_key_type() == KeyType::X25519)
            .unwrap();
        assert_eq!(x25519.id, format!("{}#key-2", id.did()));
        assert_eq!(doc["keyAgreement"], serde_json::json!([x25519.id]));
        assert_eq!(
            doc["assertionMethod"],
            serde_json::json!([format!("{}#key-1", id.did())])
        );
        // Served from another mediator, the DID would send the VTC to the
        // wrong place: refused.
        let err = check_reachable(id.did(), "did:web:elsewhere.example")
            .unwrap_err()
            .to_string();
        // Setting the mediator back is the first fix offered: it is the one
        // that keeps bound namespaces working.
        let first_fix = err
            .find(&format!("`mediator_did = \"{MEDIATOR}\"`"))
            .unwrap();
        assert!(first_fix < err.find("mint").unwrap(), "{err}");

        // It signs what the production verifier accepts ([`crate::proof_checker`]
        // is the same resolver-backed one the VTC's side is): a did:peer
        // resolves without the network.
        let doc = serde_json::json!({
            "id": "urn:uuid:1",
            "type": "https://trusttasks.org/spec/git-ns/bridge/result/0.1",
            "issuer": id.did(),
            "payload": { "jobId": "j", "outcome": "succeeded" },
        });
        let signed = id.sign(&doc).await.unwrap();
        crate::proof_checker()
            .await
            .unwrap()
            .verify_raw(&signed)
            .await
            .unwrap();
        let k = id.git_signing_key().unwrap();
        assert_eq!(k.verification_method, format!("{}#key-1", id.did()));

        // Sealed as a bundle, loaded back the same.
        let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
        BridgeIdentity::store_bundle(&store, bundle).unwrap();
        let back = BridgeIdentity::load(&store).unwrap().unwrap();
        assert_eq!(back.did(), id.did());
        assert_eq!(back.messaging_secrets().len(), 2);
    }

    /// The VTC's own selection (`vtc-service` `git_ns::bridge`): resolve the
    /// bridge's DID with the DID cache client, read its services by type,
    /// and intersect with what the VTC speaks. A did:key fails exactly here
    /// (`noMatchingProtocol`); a did:peer minted by `init` picks DIDComm
    /// through its mediator.
    #[tokio::test]
    async fn the_vtc_selects_didcomm_for_a_did_peer_and_nothing_for_a_did_key() {
        use affinidi_tdk::did_resolver::DIDCacheClient;
        use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;
        use vta_sdk::protocol::matching::{Protocol, ServiceCapabilities, select_protocol};
        let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
            .await
            .unwrap();
        let (peer, _) = BridgeIdentity::generate_did_peer(MEDIATOR).unwrap();
        let key = BridgeIdentity::from_seed(&[5u8; 32]).unwrap();
        for (id, want) in [(&peer, Some(Protocol::Didcomm)), (&key, None)] {
            let resolved = resolver.resolve(id.did()).await.unwrap();
            let doc = serde_json::to_value(&resolved.doc).unwrap();
            let theirs = ServiceCapabilities::from_did_document(&doc);
            let ours = ServiceCapabilities {
                tsp: Some(id.did().to_string()),
                didcomm: Some(id.did().to_string()),
                rest: None,
            };
            let got = select_protocol(&ours, &theirs, id.did())
                .ok()
                .map(|m| m.protocol);
            assert_eq!(got, want, "{}", id.did());
            if want.is_some() {
                assert_eq!(theirs.didcomm.as_deref(), Some(MEDIATOR));
                // DIDComm only: the bridge speaks no TSP, so advertising it
                // would have the VTC prefer a transport nobody answers.
                assert_eq!(theirs.tsp, None);
                // verify-trust finds the key the bridge re-signs Dependabot
                // commits with in the same document.
                let signing = id.git_signing_key().unwrap().key.verifying_key().to_bytes();
                assert!(vgi_core::ed25519_keys_from_doc(&doc).contains(&signing));
            }
        }
    }

    #[test]
    fn a_did_key_is_reachable_by_no_vtc() {
        let id = BridgeIdentity::from_seed(&[5u8; 32]).unwrap();
        assert_eq!(advertised_mediator(id.did()).unwrap(), None);
        let warning = check_reachable(id.did(), MEDIATOR).unwrap().unwrap();
        assert!(warning.contains("noMatchingProtocol"), "{warning}");
        // A DID with a published document is not second-guessed.
        assert_eq!(
            check_reachable("did:webvh:QmScid:bridge.example", MEDIATOR).unwrap(),
            None
        );
    }

    #[test]
    fn a_mediator_with_a_long_did_is_refused_at_mint() {
        let long = format!("did:web:{}.example", "m".repeat(900));
        let err = BridgeIdentity::generate_did_peer(&long).unwrap_err();
        assert!(err.to_string().contains("1000-byte"), "{err}");
        assert!(BridgeIdentity::generate_did_peer("not-a-did").is_err());
    }

    #[test]
    fn an_exported_identity_imports_as_the_same_did_and_keys() {
        for id in [
            BridgeIdentity::generate_did_peer(MEDIATOR).unwrap().0,
            BridgeIdentity::from_seed(&[7u8; 32]).unwrap(),
        ] {
            let text = serde_json::to_string(&id.to_bundle().unwrap()).unwrap();
            let store = Store::in_memory(MasterKey::generate().unwrap()).unwrap();
            let back =
                BridgeIdentity::store_bundle(&store, serde_json::from_str(&text).unwrap()).unwrap();
            assert_eq!(back.did(), id.did());
            assert_eq!(
                back.git_signing_key().unwrap().key.to_bytes(),
                id.git_signing_key().unwrap().key.to_bytes()
            );
            let reloaded = BridgeIdentity::load(&store).unwrap().unwrap();
            assert_eq!(reloaded.did(), id.did());
        }
    }

    #[tokio::test]
    async fn signing_for_another_issuer_is_refused() {
        let (id, _) = BridgeIdentity::generate_did_key().unwrap();
        let doc = serde_json::json!({ "id": "x", "issuer": "did:key:z6MkOther", "payload": {} });
        assert!(id.sign(&doc).await.is_err());
    }
}
