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

/// `git-ns/bridge/event` 0.1, still sent to a VTC configured for it.
pub use trust_tasks_rs::specs::git_ns::bridge::event::v0_1 as event_v0_1;
/// `git-ns/bridge/event` 0.2, the type every event is built as. 0.1 is
/// wire-identical (0.2 changes only what the VTC does with a transfer, a
/// reused name, and a resource outside the namespace), so an event for a
/// VTC configured for 0.1 is the same payload under the 0.1 type URI: see
/// [`event_type_uri`].
pub use trust_tasks_rs::specs::git_ns::bridge::event::v0_2 as event;
/// The payload types of `git-ns/bridge/job` 0.4, the only version this
/// bridge takes. It adds rules the schema does not state, checked in
/// [`check_kind_members`]: a namespace admin with no right of their own on
/// a repository is listed at `git.ns.admin` and gets no role; there is no
/// namespace-level `projectRoles`; each account appears once.
pub use trust_tasks_rs::specs::git_ns::bridge::job::v0_4 as job;
pub use trust_tasks_rs::specs::git_ns::bridge::result::v0_1 as result;

/// `git-ns/bridge/job/0.4`'s type URI.
pub const JOB_TYPE: &str = <job::Payload as trust_tasks_rs::Payload>::TYPE_URI;

/// `trust-task-discovery/0.2`, which a VTC asks before it sends 0.4 jobs
/// (`git-ns/bridge/job` 0.4 forbids sending 0.4 to a bridge that has not
/// shown it takes it).
pub const DISCOVERY_TYPE: &str = "https://trusttasks.org/spec/trust-task-discovery/0.2";

/// Whether `type_uri` (bare) is a job this bridge takes: `git-ns/bridge/job`
/// 0.4 only.
pub fn is_job_type(type_uri: &str) -> bool {
    type_uri == JOB_TYPE
}

/// Whether `type_uri` (bare) is another version of `git-ns/bridge/job`,
/// which this bridge refuses with `unsupportedVersion`: before 0.4 a
/// namespace admin was sent as an owner, and nothing here reads that.
pub fn is_other_job_version(type_uri: &str) -> bool {
    type_uri != JOB_TYPE && type_uri.starts_with("https://trusttasks.org/spec/git-ns/bridge/job/")
}

/// The `trust-task-discovery` answer: the job type this bridge takes, if
/// any of `patterns` (SPEC §10.2 grammar; empty means `*`) selects its
/// slug.
pub fn discovery_answer(patterns: &[String]) -> Value {
    const SLUG: &str = "git-ns/bridge/job";
    let selects = |p: &str| {
        p == "*"
            || p == SLUG
            || p.strip_suffix("/*")
                .is_some_and(|prefix| SLUG.starts_with(&format!("{prefix}/")))
    };
    let listed = patterns.is_empty() || patterns.iter().any(|p| selects(p));
    let types: Vec<&str> = if listed { vec![JOB_TYPE] } else { Vec::new() };
    serde_json::json!({ "supportedTypes": types })
}

/// The type URI an event is sent under, for the version the VTC takes.
pub fn event_type_uri(version: crate::config::EventVersion) -> &'static str {
    use crate::config::EventVersion;
    use trust_tasks_rs::Payload as _;
    match version {
        EventVersion::V0_1 => event_v0_1::Payload::TYPE_URI,
        _ => event::Payload::TYPE_URI,
    }
}

/// Whether `type_uri` (bare) is the VTC's acknowledgement of an event, of
/// either version (a VTC acknowledges an event in the version it was sent,
/// and the configured version may have changed since).
pub fn is_event_response_type(type_uri: &str) -> bool {
    use trust_tasks_rs::Payload as _;
    type_uri == event::Response::TYPE_URI || type_uri == event_v0_1::Response::TYPE_URI
}

/// Parse a `git-ns/bridge/job` 0.4 payload.
pub fn parse_job(payload: &Value) -> std::result::Result<job::Payload, String> {
    serde_json::from_value(payload.clone()).map_err(|e| format!("job payload: {e}"))
}

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

/// Drops a DID's cached document, so the next resolution fetches it again.
#[async_trait]
pub trait Evict: Send + Sync {
    /// Forget `did`'s cached document.
    async fn evict(&self, did: &str);
}

#[async_trait]
impl Evict for affinidi_tdk::did_resolver::DIDCacheClient {
    async fn evict(&self, did: &str) {
        let _ = self.remove(did).await;
    }
}

/// A [`ProofCheck`] that tries a failed proof once more against a fresh
/// resolution of the issuer's DID: a document cached from before the
/// issuer rotated its key would otherwise refuse the new key until it
/// expired. Fails closed after the second try, and a document that verified
/// is never re-checked — a key rotated *out* is trusted at most for the
/// cache's lifetime.
pub struct ReResolving {
    inner: Arc<dyn ProofCheck>,
    cache: Arc<dyn Evict>,
    /// When each DID was last resolved again: at most once per
    /// [`RE_RESOLVE_EVERY`], so a stream of bad proofs cannot make the bridge
    /// hammer (or be steered into flooding) the DID's host.
    last: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

/// The least time between two fresh resolutions of one DID on a failure.
pub const RE_RESOLVE_EVERY: std::time::Duration = std::time::Duration::from_secs(30);

impl ReResolving {
    /// Over `inner`, evicting from `cache`.
    pub fn new(inner: Arc<dyn ProofCheck>, cache: Arc<dyn Evict>) -> Self {
        ReResolving {
            inner,
            cache,
            last: Default::default(),
        }
    }

    /// Whether `did` may be resolved again now (and note that it is).
    fn may_re_resolve(&self, did: &str) -> bool {
        let mut last = self.last.lock().expect("lock");
        let now = std::time::Instant::now();
        if last
            .get(did)
            .is_some_and(|t| now.duration_since(*t) < RE_RESOLVE_EVERY)
        {
            return false;
        }
        if last.len() > 1024 {
            last.retain(|_, t| now.duration_since(*t) < RE_RESOLVE_EVERY);
        }
        last.insert(did.to_string(), now);
        true
    }
}

#[async_trait]
impl ProofCheck for ReResolving {
    async fn verify_raw(&self, doc: &Value) -> Result<(), VerificationError> {
        match self.inner.verify_raw(doc).await {
            Ok(()) => Ok(()),
            Err(first) => {
                let Some(issuer) = doc.get("issuer").and_then(Value::as_str) else {
                    return Err(first);
                };
                // Only a network-resolved DID can have changed.
                if issuer.starts_with("did:key:")
                    || issuer.starts_with("did:peer:")
                    || !self.may_re_resolve(issuer)
                {
                    return Err(first);
                }
                tracing::info!(%issuer, "a proof failed against the cached DID document; resolving it again");
                self.cache.evict(issuer).await;
                self.inner.verify_raw(doc).await
            }
        }
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
    /// The bare type URI (`…/git-ns/bridge/job/0.4`, `…#response`).
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
        // The specification asks for an assertion: a proof made for any
        // other purpose (authentication, say) is not the issuer asserting
        // this document, however valid its signature. Checked here, before
        // the signature, and bound by it (the purpose is signed).
        if raw.pointer("/proof/proofPurpose").and_then(Value::as_str) != Some("assertionMethod") {
            return Err(Refusal::standard(
                StandardCode::ProofInvalid,
                "the proof's purpose must be assertionMethod",
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
        // 0.4: no namespace-level `projectRoles`.
        K::ProjectRoles => [
            (true, true),
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
        if !roles
            .iter()
            .all(|r| seen.insert((r.account.forge.to_string(), r.account.id.to_string())))
        {
            return Err("`desiredRoles` names one account twice".into());
        }
    }
    check_remove_accounts(p)
}

/// `removeAccounts`: `projectRoles` only, at least one account, none twice,
/// and none also in `desiredRoles` except at `git.ns.admin` (job 0.4: that
/// entry asks for no role, as the removal does) — an account is matched by
/// `forge` and `id`, never by its display `login`.
/// Whether each account is on the namespace's forge is checked once the
/// namespace is known (the bridge's admission).
fn check_remove_accounts(p: &job::Payload) -> std::result::Result<(), String> {
    let Some(remove) = &p.remove_accounts else {
        return Ok(());
    };
    if p.kind != job::PayloadKind::ProjectRoles {
        return Err(format!("`{}` does not use `removeAccounts`", p.kind));
    }
    if remove.is_empty() {
        return Err("`removeAccounts` must name at least one account".into());
    }
    let key = |a: &job::ForgeAccount| (a.forge.to_string(), a.id.to_string());
    let mut seen = std::collections::BTreeSet::new();
    if !remove.iter().all(|a| seen.insert(key(a))) {
        return Err("`removeAccounts` names one account twice".into());
    }
    if let Some(overlap) = p
        .desired_roles
        .iter()
        .flatten()
        .find(|r| seen.contains(&key(&r.account)) && r.right != job::Right::GitNsAdmin)
    {
        return Err(format!(
            "account {} on `{}` is in both `desiredRoles` and `removeAccounts`",
            *overlap.account.id, *overlap.account.forge
        ));
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
    /// Fails until the cache is evicted once — a document cached from
    /// before the issuer rotated its key.
    struct Stale {
        evicted: std::sync::atomic::AtomicBool,
        checks: std::sync::atomic::AtomicU32,
        fresh_passes: bool,
    }

    #[async_trait]
    impl ProofCheck for Stale {
        async fn verify_raw(&self, _doc: &Value) -> Result<(), VerificationError> {
            use std::sync::atomic::Ordering::SeqCst;
            self.checks.fetch_add(1, SeqCst);
            if self.evicted.load(SeqCst) && self.fresh_passes {
                Ok(())
            } else {
                Err(VerificationError::UnsupportedCryptosuite("stale".into()))
            }
        }
    }

    #[async_trait]
    impl Evict for Stale {
        async fn evict(&self, _did: &str) {
            self.evicted
                .store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[tokio::test]
    async fn a_failed_proof_is_checked_once_more_against_a_fresh_document() {
        use std::sync::atomic::Ordering::SeqCst;
        let doc = serde_json::json!({ "issuer": "did:webvh:QmVtc:acme-vtc.example" });
        for fresh_passes in [true, false] {
            let s = Arc::new(Stale {
                evicted: false.into(),
                checks: 0.into(),
                fresh_passes,
            });
            let r = ReResolving::new(s.clone(), s.clone());
            assert_eq!(r.verify_raw(&doc).await.is_ok(), fresh_passes);
            assert_eq!(
                s.checks.load(SeqCst),
                2,
                "once more, never again (fails closed)"
            );
            assert!(s.evicted.load(SeqCst));
        }
        // Once per DID per interval: a second failure soon after is refused
        // without resolving again.
        let s = Arc::new(Stale {
            evicted: false.into(),
            checks: 0.into(),
            fresh_passes: false,
        });
        let r = ReResolving::new(s.clone(), s.clone());
        assert!(r.verify_raw(&doc).await.is_err());
        assert!(r.verify_raw(&doc).await.is_err());
        assert_eq!(
            s.checks.load(SeqCst),
            3,
            "the second failure is not re-resolved"
        );
        // A did:key cannot have changed: no second try.
        let s = Arc::new(Stale {
            evicted: false.into(),
            checks: 0.into(),
            fresh_passes: true,
        });
        let r = ReResolving::new(s.clone(), s.clone());
        assert!(
            r.verify_raw(&serde_json::json!({ "issuer": "did:key:z6Mk" }))
                .await
                .is_err()
        );
        assert_eq!(s.checks.load(SeqCst), 1);
    }

    use super::*;
    use serde_json::json;
    use trust_tasks_proof::affinidi::Verifier;

    fn checker(vtc: &BridgeIdentity, bridge: &str) -> DocChecker {
        DocChecker::new(vtc.did(), bridge, 300, Arc::new(Verifier::for_did_key()))
    }

    async fn job_doc(vtc: &BridgeIdentity, bridge: &str, payload: Value) -> Value {
        let doc = json!({
            "id": new_id(),
            "type": JOB_TYPE,
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
        assert!(is_job_type(&v.type_uri()));
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
            "id": new_id(), "type": JOB_TYPE, "issuer": other.did(),
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

        // Signed, but for authentication rather than as an assertion.
        let auth = vtc
            .sign_with_purpose(
                &json!({
                    "id": new_id(), "type": JOB_TYPE, "issuer": vtc.did(),
                    "recipient": bridge.did(), "issuedAt": Utc::now().to_rfc3339(),
                    "payload": {"jobId": "j", "namespace": "n", "kind": "inspect"},
                }),
                "authentication",
            )
            .await
            .unwrap();
        let r = c.check(&auth, None).await.unwrap_err();
        assert_eq!(r.payload.code.to_string(), "proofInvalid");
        assert!(
            r.payload
                .message
                .unwrap_or_default()
                .contains("assertionMethod")
        );

        // Stale.
        let old = json!({
            "id": new_id(), "type": JOB_TYPE, "issuer": vtc.did(),
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
            json!({"jobId":"j","namespace":"n","kind":"projectRoles","repo":"github.com/a/b","desiredRoles":[]}),
            json!({"jobId":"j","namespace":"n","kind":"beginBind","target":{"forge":"github.com","owner":"acme"}}),
            // An account listed at `git.ns.admin` (no role) may also be removed.
            json!({"jobId":"j","namespace":"n","kind":"projectRoles","repo":"github.com/a/b",
                "desiredRoles":[{"subject":"did:key:z6MkAdmin","account":{"forge":"github.com","id":"7","login":"a"},"right":"git.ns.admin"}],
                "removeAccounts":[{"forge":"github.com","id":"7","login":"a"}]}),
        ];
        for v in ok {
            check_kind_members(&parse(v.clone())).unwrap_or_else(|e| panic!("{v}: {e}"));
        }
        let bad = [
            json!({"jobId":"j","namespace":"n","kind":"archive"}),
            json!({"jobId":"j","namespace":"n","kind":"inspect","subject":"did:key:z6Mk"}),
            json!({"jobId":"j","namespace":"n","kind":"createRepo","repo":"github.com/a/b"}),
            json!({"jobId":"j","namespace":"n","kind":"beginAccountLink"}),
            // 0.4: there is no namespace-level `projectRoles`.
            json!({"jobId":"j","namespace":"n","kind":"projectRoles","desiredRoles":[]}),
            // One account, twice.
            json!({"jobId":"j","namespace":"n","kind":"projectRoles","repo":"github.com/a/b","desiredRoles":[
                {"subject":"did:key:z6MkOne","account":{"forge":"github.com","id":"7","login":"a"},"right":"git.repo.own"},
                {"subject":"did:key:z6MkTwo","account":{"forge":"github.com","id":"7","login":"b"},"right":"git.ns.admin"}]}),
            // An account listed at a right that maps to a role is not also removed.
            json!({"jobId":"j","namespace":"n","kind":"projectRoles","repo":"github.com/a/b",
                "desiredRoles":[{"subject":"did:key:z6MkOwner","account":{"forge":"github.com","id":"7","login":"a"},"right":"git.repo.own"}],
                "removeAccounts":[{"forge":"github.com","id":"7","login":"a"}]}),
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
    fn only_job_0_4_is_taken() {
        assert!(is_job_type(JOB_TYPE));
        for v in ["0.1", "0.2", "0.3"] {
            let t = format!("https://trusttasks.org/spec/git-ns/bridge/job/{v}");
            assert!(!is_job_type(&t));
            assert!(is_other_job_version(&t));
        }
        assert!(!is_other_job_version(JOB_TYPE));
    }

    #[test]
    fn discovery_lists_job_0_4_for_a_pattern_that_selects_it() {
        for p in [
            vec![],
            vec!["*".to_string()],
            vec!["git-ns/*".into()],
            vec!["git-ns/bridge/job".into()],
        ] {
            assert_eq!(
                discovery_answer(&p)["supportedTypes"],
                json!([JOB_TYPE]),
                "{p:?}"
            );
        }
        for p in [
            vec!["acl/*".to_string()],
            vec!["git-ns/bridge".into()],
            vec!["git-ns/bridge/job/0.4".into()],
        ] {
            assert_eq!(discovery_answer(&p)["supportedTypes"], json!([]), "{p:?}");
        }
    }

    #[test]
    fn clip_keeps_char_boundaries() {
        let s = "é".repeat(1000);
        let c = clip(&s, 1024);
        assert!(c.len() <= 1024);
        assert_eq!(clip("short", 1024), "short");
    }
}
