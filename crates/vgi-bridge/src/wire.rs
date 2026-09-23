//! Trust Task documents on the VTC ↔ bridge link.
//!
//! The payload types are the ones generated from the normative
//! `git-ns/bridge/*` specifications (`trust_tasks_rs::specs::git_ns`); this
//! module adds only behaviour: checking an inbound document before anything
//! reads its payload, the rules JSON Schema cannot state (which members each
//! job `kind` carries), and building signed outbound documents.
//!
//! **An inbound document is checked in this order**, each step before the
//! next reads anything the previous one has not vouched for:
//!
//! 1. the envelope parses (framework members only — the payload is still
//!    opaque JSON);
//! 2. `issuer` is the one VTC this bridge serves — anything else is
//!    `permissionDenied`, whatever its proof (spec: *Authorization*). Checked
//!    before the proof so that a stranger's document never makes the bridge
//!    resolve a DID the stranger chose;
//! 3. the transport's authenticated sender, when there is one, is that same
//!    DID (`identityMismatch`);
//! 4. `recipient` is this bridge (`wrongRecipient`);
//! 5. `issuedAt` is present and fresh (a stale job replayed after later ones
//!    would push the forge back to an old state);
//! 6. the Data Integrity proof verifies, over the document exactly as it
//!    arrived, under a verification method the issuer controls;
//! 7. only then is the payload parsed into its generated type.

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use serde::Serialize;
use serde_json::Value;
use trust_tasks_rs::{
    ErrorPayload, FreshnessPolicy, RejectReason, StandardCode, TrustTask, TypeUri,
    VerificationError,
};

use crate::identity::BridgeIdentity;

pub use trust_tasks_rs::specs::git_ns::bridge::event::v0_1 as event;
pub use trust_tasks_rs::specs::git_ns::bridge::job::v0_1 as job;
pub use trust_tasks_rs::specs::git_ns::bridge::result::v0_1 as result;

/// The DIDComm message type that carries a Trust Task document as its body
/// (the Trust Tasks DIDComm binding; the same constant vtc-service routes on).
pub const ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

/// Checks a document's Data Integrity proof. A seam so tests can verify
/// `did:key` proofs offline; production resolves `did:webvh` too.
#[async_trait]
pub trait ProofCheck: Send + Sync {
    /// Verify `doc`'s proof as received, bound to its in-band `issuer`.
    async fn verify_raw(&self, doc: &Value) -> Result<(), VerificationError>;
}

#[async_trait]
impl ProofCheck for trust_tasks_proof::affinidi::Verifier {
    async fn verify_raw(&self, doc: &Value) -> Result<(), VerificationError> {
        trust_tasks_proof::affinidi::Verifier::verify_raw(self, doc).await
    }
}

/// A document that passed steps 1–6: from the VTC, to this bridge, fresh,
/// and signed. Only [`DocChecker::check`] makes one.
#[derive(Debug, Clone)]
pub struct VerifiedDoc {
    /// The envelope, payload still untyped.
    pub doc: TrustTask<Value>,
}

impl VerifiedDoc {
    /// The bare type URI (`…/git-ns/bridge/job/0.1`, `…#response`).
    pub fn type_uri(&self) -> String {
        self.doc.type_uri.to_string()
    }
}

/// Why an inbound document was refused, as the error response carries it.
#[derive(Debug)]
pub struct Refusal {
    /// The error payload to send back.
    pub payload: ErrorPayload,
    /// The envelope, when it parsed far enough to answer.
    pub doc: Option<TrustTask<Value>>,
}

impl Refusal {
    fn standard(
        code: StandardCode,
        message: impl Into<String>,
        doc: Option<TrustTask<Value>>,
    ) -> Box<Self> {
        Box::new(Refusal {
            payload: ErrorPayload::new(code).with_message(message),
            doc,
        })
    }
}

/// Steps 1–6 of the module docs.
pub struct DocChecker {
    vtc_did: String,
    bridge_did: String,
    freshness: FreshnessPolicy,
    proof: Arc<dyn ProofCheck>,
}

impl std::fmt::Debug for DocChecker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DocChecker")
            .field("vtc_did", &self.vtc_did)
            .field("bridge_did", &self.bridge_did)
            .finish_non_exhaustive()
    }
}

impl DocChecker {
    /// A checker for documents from `vtc_did` to `bridge_did`, no older than
    /// `max_age_secs`.
    pub fn new(
        vtc_did: impl Into<String>,
        bridge_did: impl Into<String>,
        max_age_secs: u64,
        proof: Arc<dyn ProofCheck>,
    ) -> Self {
        DocChecker {
            vtc_did: vtc_did.into(),
            bridge_did: bridge_did.into(),
            freshness: FreshnessPolicy::consequential()
                .with_max_age(TimeDelta::seconds(max_age_secs as i64)),
            proof,
        }
    }

    /// The VTC this bridge serves.
    pub fn vtc_did(&self) -> &str {
        &self.vtc_did
    }

    /// Check `raw`, which arrived from `authenticated_sender` when the
    /// transport proved one.
    pub async fn check(
        &self,
        raw: &Value,
        authenticated_sender: Option<&str>,
    ) -> Result<VerifiedDoc, Box<Refusal>> {
        // 1. The envelope.
        let doc: TrustTask<Value> = serde_json::from_value(raw.clone()).map_err(|e| {
            Refusal::standard(
                StandardCode::MalformedRequest,
                format!("not a Trust Task document: {e}"),
                None,
            )
        })?;
        // 2. Only our VTC.
        if doc.issuer.as_deref() != Some(self.vtc_did.as_str()) {
            return Err(Refusal::standard(
                StandardCode::PermissionDenied,
                "this bridge serves one VTC, and this document is not from it",
                Some(doc),
            ));
        }
        // 3. The transport agrees.
        if let Some(sender) = authenticated_sender
            && sender != self.vtc_did
        {
            return Err(Refusal::standard(
                StandardCode::IdentityMismatch,
                "the transport-authenticated sender is not the document's issuer",
                Some(doc),
            ));
        }
        // 4. Addressed to us.
        if doc.recipient.as_deref() != Some(self.bridge_did.as_str()) {
            return Err(Refusal::standard(
                StandardCode::WrongRecipient,
                "the document is not addressed to this bridge",
                Some(doc),
            ));
        }
        // 5. Fresh.
        if let Err(reason) = doc.validate_freshness(Utc::now(), &self.freshness) {
            let payload: ErrorPayload = reason.into();
            return Err(Box::new(Refusal {
                payload,
                doc: Some(doc),
            }));
        }
        // 6. Signed by the issuer.
        if raw.get("proof").is_none() {
            return Err(Refusal::standard(
                StandardCode::ProofRequired,
                "a proof is required on every document from the VTC",
                Some(doc),
            ));
        }
        if let Err(e) = self.proof.verify_raw(raw).await {
            tracing::warn!(error = %e, id = %doc.id, "refusing a document whose proof does not verify");
            let payload: ErrorPayload = RejectReason::ProofInvalid {
                reason: e.to_string(),
            }
            .into();
            return Err(Box::new(Refusal {
                payload,
                doc: Some(doc),
            }));
        }
        Ok(VerifiedDoc { doc })
    }
}

/// A fresh `urn:uuid` document id.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).expect("system RNG");
    // RFC 4122 version 4, variant 1.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "urn:uuid:{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Build and sign a new request document (`result`, `event`) from the bridge
/// to the VTC, of type `type_uri`, carrying `payload`. Returns its id and the
/// signed document.
pub async fn signed_request(
    identity: &BridgeIdentity,
    vtc_did: &str,
    type_uri: &str,
    payload: Value,
) -> Result<(String, Value)> {
    let id = new_id();
    let type_uri: TypeUri = type_uri
        .parse()
        .map_err(|e| anyhow::anyhow!("type URI `{type_uri}`: {e}"))?;
    let mut doc = TrustTask::new(id.clone(), type_uri, payload);
    doc.thread_id = Some(id.clone());
    doc.issuer = Some(identity.did().to_string());
    doc.recipient = Some(vtc_did.to_string());
    doc.issued_at = Some(Utc::now());
    let signed = identity.sign(&serde_json::to_value(&doc)?).await?;
    Ok((id, signed))
}

/// Build and sign the response to `request`.
pub async fn signed_response<R: Serialize>(
    identity: &BridgeIdentity,
    request: &TrustTask<Value>,
    payload: R,
) -> Result<Value> {
    let resp = request.respond_with(new_id(), payload);
    identity.sign(&serde_json::to_value(&resp)?).await
}

/// Build and sign an error response to `request`.
pub async fn signed_error(
    identity: &BridgeIdentity,
    request: &TrustTask<Value>,
    payload: ErrorPayload,
) -> Result<Value> {
    let mut resp = request.reject_with(new_id(), payload);
    // Addressed from this bridge even when the request named someone else.
    resp.issuer = Some(identity.did().to_string());
    identity.sign(&serde_json::to_value(&resp)?).await
}

/// Check that a job carries exactly the members its `kind` uses (the
/// specification's kind table, which the schema cannot express).
pub fn check_kind_members(p: &job::Payload) -> std::result::Result<(), String> {
    use job::PayloadKind as K;
    let has = |present: bool, name: &str, allowed: bool, required: bool| {
        if required && !present {
            Err(format!("`{}` requires `{name}`", p.kind))
        } else if present && !allowed {
            Err(format!("`{}` does not use `{name}`", p.kind))
        } else {
            Ok(())
        }
    };
    // (repo, spec, desiredRoles, steps, target, subject): (allowed, required)
    let rules: [(bool, bool); 6] = match p.kind {
        K::ProjectRoles => [
            (true, false),
            (false, false),
            (true, true),
            (false, false),
            (false, false),
            (false, false),
        ],
        K::CreateRepo => [
            (true, true),
            (true, true),
            (true, false),
            (false, false),
            (false, false),
            (false, false),
        ],
        K::Bootstrap => [
            (true, true),
            (false, false),
            (false, false),
            (true, false),
            (false, false),
            (false, false),
        ],
        K::Archive => [
            (true, true),
            (false, false),
            (false, false),
            (false, false),
            (false, false),
            (false, false),
        ],
        K::Inspect => [
            (true, false),
            (false, false),
            (false, false),
            (false, false),
            (false, false),
            (false, false),
        ],
        K::BeginBind => [
            (false, false),
            (false, false),
            (false, false),
            (false, false),
            (true, true),
            (false, false),
        ],
        K::BeginAccountLink => [
            (false, false),
            (false, false),
            (false, false),
            (false, false),
            (false, false),
            (true, true),
        ],
        _ => return Err(format!("unknown job kind `{}`", p.kind)),
    };
    let present = [
        p.repo.is_some(),
        p.spec.is_some(),
        p.desired_roles.is_some(),
        p.steps.is_some(),
        p.target.is_some(),
        p.subject.is_some(),
    ];
    let names = ["repo", "spec", "desiredRoles", "steps", "target", "subject"];
    for i in 0..6 {
        has(present[i], names[i], rules[i].0, rules[i].1)?;
    }
    if let Some(steps) = &p.steps {
        let mut seen = std::collections::BTreeSet::new();
        if steps.is_empty() || !steps.iter().all(|s| seen.insert(s.to_string())) {
            return Err("`steps` must be a non-empty list of distinct names".into());
        }
    }
    if let Some(roles) = &p.desired_roles {
        let mut seen = std::collections::BTreeSet::new();
        if !roles.iter().all(|r| seen.insert(r.account.id.to_string())) {
            return Err("`desiredRoles` names one account twice".into());
        }
    }
    Ok(())
}

/// Truncate `s` to at most `max` bytes on a character boundary (the result
/// schema bounds `detail` and `message` at 1024).
pub fn clip(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max.saturating_sub(1);
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &s[..end.saturating_sub(2)])
}

/// Whether `v` is one of this module's request types, by bare type URI.
pub fn is_type<P: trust_tasks_rs::Payload>(v: &VerifiedDoc) -> bool {
    v.doc.type_uri.to_string() == P::TYPE_URI
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use trust_tasks_proof::affinidi::Verifier;
    use trust_tasks_rs::Payload as _;

    fn checker(vtc: &BridgeIdentity, bridge: &str) -> DocChecker {
        DocChecker::new(vtc.did(), bridge, 300, Arc::new(Verifier::for_did_key()))
    }

    async fn job_doc(vtc: &BridgeIdentity, bridge: &str, payload: Value) -> Value {
        let doc = json!({
            "id": new_id(),
            "type": job::Payload::TYPE_URI,
            "issuer": vtc.did(),
            "recipient": bridge,
            "issuedAt": Utc::now().to_rfc3339(),
            "payload": payload,
        });
        vtc.sign(&doc).await.unwrap()
    }

    #[tokio::test]
    async fn a_signed_fresh_job_from_the_vtc_passes() {
        let (vtc, _) = BridgeIdentity::generate_did_key().unwrap();
        let (bridge, _) = BridgeIdentity::generate_did_key().unwrap();
        let raw = job_doc(
            &vtc,
            bridge.did(),
            json!({"jobId": "j1", "namespace": "ns", "kind": "inspect"}),
        )
        .await;
        let v = checker(&vtc, bridge.did())
            .check(&raw, Some(vtc.did()))
            .await
            .unwrap();
        assert!(is_type::<job::Payload>(&v));
        let p: job::Payload = serde_json::from_value(v.doc.payload).unwrap();
        check_kind_members(&p).unwrap();
    }

    #[tokio::test]
    async fn every_step_refuses_what_it_should() {
        let (vtc, _) = BridgeIdentity::generate_did_key().unwrap();
        let (other, _) = BridgeIdentity::generate_did_key().unwrap();
        let (bridge, _) = BridgeIdentity::generate_did_key().unwrap();
        let c = checker(&vtc, bridge.did());
        let payload = json!({"jobId": "j1", "namespace": "ns", "kind": "inspect"});
        let code = |r: Box<Refusal>| r.payload.code.to_string();

        // Another DID, validly signed: permission denied, before any proof work.
        let raw = job_doc(&other, bridge.did(), payload.clone()).await;
        assert_eq!(
            code(c.check(&raw, None).await.unwrap_err()),
            "permissionDenied"
        );

        // Right issuer, wrong transport sender.
        let raw = job_doc(&vtc, bridge.did(), payload.clone()).await;
        assert_eq!(
            code(c.check(&raw, Some(other.did())).await.unwrap_err()),
            "identityMismatch"
        );

        // Addressed elsewhere.
        let raw = job_doc(&vtc, other.did(), payload.clone()).await;
        assert_eq!(
            code(c.check(&raw, None).await.unwrap_err()),
            "wrongRecipient"
        );

        // Tampered after signing.
        let mut raw = job_doc(&vtc, bridge.did(), payload.clone()).await;
        raw["payload"]["kind"] = json!("archive");
        assert_eq!(code(c.check(&raw, None).await.unwrap_err()), "proofInvalid");

        // Claiming the VTC as issuer but signed by someone else.
        let mut forged = json!({
            "id": new_id(), "type": job::Payload::TYPE_URI, "issuer": other.did(),
            "recipient": bridge.did(), "issuedAt": Utc::now().to_rfc3339(), "payload": payload,
        });
        forged = other.sign(&forged).await.unwrap();
        forged["issuer"] = json!(vtc.did());
        assert_eq!(
            code(c.check(&forged, None).await.unwrap_err()),
            "proofInvalid"
        );

        // No proof at all.
        let mut raw = job_doc(
            &vtc,
            bridge.did(),
            json!({"jobId": "j", "namespace": "n", "kind": "inspect"}),
        )
        .await;
        raw.as_object_mut().unwrap().remove("proof");
        assert_eq!(
            code(c.check(&raw, None).await.unwrap_err()),
            "proofRequired"
        );

        // Stale.
        let old = json!({
            "id": new_id(), "type": job::Payload::TYPE_URI, "issuer": vtc.did(),
            "recipient": bridge.did(), "issuedAt": "2020-01-01T00:00:00Z",
            "payload": {"jobId": "j", "namespace": "n", "kind": "inspect"},
        });
        let old = vtc.sign(&old).await.unwrap();
        assert_eq!(code(c.check(&old, None).await.unwrap_err()), "expired");
    }

    #[test]
    fn kinds_carry_exactly_their_members() {
        let parse = |v: Value| serde_json::from_value::<job::Payload>(v).unwrap();
        let ok = [
            json!({"jobId":"j","namespace":"n","kind":"archive","repo":"github.com/a/b"}),
            json!({"jobId":"j","namespace":"n","kind":"inspect"}),
            json!({"jobId":"j","namespace":"n","kind":"projectRoles","desiredRoles":[]}),
            json!({"jobId":"j","namespace":"n","kind":"beginBind","target":{"forge":"github.com","owner":"acme"}}),
        ];
        for v in ok {
            check_kind_members(&parse(v.clone())).unwrap_or_else(|e| panic!("{v}: {e}"));
        }
        let bad = [
            json!({"jobId":"j","namespace":"n","kind":"archive"}),
            json!({"jobId":"j","namespace":"n","kind":"inspect","subject":"did:key:z6Mk"}),
            json!({"jobId":"j","namespace":"n","kind":"createRepo","repo":"github.com/a/b"}),
            json!({"jobId":"j","namespace":"n","kind":"beginAccountLink"}),
        ];
        for v in bad {
            assert!(check_kind_members(&parse(v.clone())).is_err(), "{v}");
        }
        // Credentials have no member to ride in on.
        assert!(
            serde_json::from_value::<job::Payload>(
                json!({"jobId":"j","namespace":"n","kind":"archive","repo":"github.com/a/b","token":"ghs_x"})
            )
            .is_err()
        );
    }

    #[test]
    fn clip_keeps_char_boundaries() {
        let s = "é".repeat(1000);
        let c = clip(&s, 1024);
        assert!(c.len() <= 1024);
        assert_eq!(clip("short", 1024), "short");
    }
}
