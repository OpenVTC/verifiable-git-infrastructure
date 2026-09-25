//! Reaching the Trust Registry: which binding to use, and the bindings.
//!
//! The registry's DID document advertises one service per binding it serves:
//! `#tsp` and `#didcomm` (whose endpoints are the registry's **mediator DID**)
//! and, optionally, `#rest` (a base URL). [`discover_registry_route`] picks
//! the highest-preference binding present in both that document and this
//! build — TSP, then DIDComm, then HTTPS — so a registry that publishes no
//! REST service at all is queried over a mediator instead.
//!
//! # Who asks, and why the answer can be believed
//!
//! Over the mediator bindings a query has to come *from* a DID, so the reply
//! has somewhere to go. Two senders exist:
//!
//! - **A fresh `did:peer:2` per run** ([`Registry::ephemeral`]) — the CI
//!   paths (the GitHub required and in-repo workflows, the Forgejo workflow,
//!   a local run). It is generated in memory when the first query is sent,
//!   carries a DIDComm service naming the registry's mediator so replies route
//!   back, and is never written anywhere: not to disk, not to a log, not to
//!   the environment. It identifies nothing and is trusted for nothing — it is
//!   a return address. The mediator accepts it only if it admits unknown
//!   senders (the registry's default access-list mode, `ExplicitDeny`); one
//!   that refuses it fails the query, and so the check, closed.
//! - **A caller-owned channel** ([`Registry::over_channel`]) — the bridge,
//!   which already holds a stable, VTA-provisioned DID and a live session on
//!   its mediator. The mediator permits one websocket per DID, so the bridge
//!   lends its session rather than verify-trust opening a second one.
//!
//! Neither sender's identity is what makes the answer trustworthy. That rests
//! on the **registry's** key: a reply is accepted only when the binding
//! authenticated it as the registry DID (DIDComm authcrypt whose sender key
//! belongs to that DID and whose `from` names it; a TSP message whose
//! verified sender VID is that DID). Anything else — a correlated reply from
//! some other DID included — is ignored, and a query that never gets a proven
//! answer times out as `registryUnavailable`, never as a pass.
//!
//! Over HTTPS the answer carries no signature, as before: trust rests on
//! reaching the endpoint the registry's DID document names (or the explicit
//! `--registry-url` override).

use std::sync::Arc;
#[cfg(any(feature = "didcomm", feature = "tsp"))]
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde_json::Value;
use trql_client::{
    HttpsTransport, HttpsTransportConfig, ServiceCapabilities, TransportChoice, TransportKind,
    TrqlClient, TrqlError, TrqlTransport,
};
use trust_tasks_trql::TrustTask;

#[cfg(any(feature = "didcomm", feature = "tsp"))]
pub use mediated::EphemeralIdentity;

/// The bindings this build can query over, in preference order.
///
/// HTTPS is always present; DIDComm and TSP follow the crate features of the
/// same names (both default).
#[must_use]
// The pushes are feature-gated, which `vec![]` cannot express.
#[allow(clippy::vec_init_then_push)]
pub fn supported_transports() -> Vec<TransportKind> {
    let mut kinds = Vec::with_capacity(3);
    #[cfg(feature = "tsp")]
    kinds.push(TransportKind::Tsp);
    #[cfg(feature = "didcomm")]
    kinds.push(TransportKind::Didcomm);
    kinds.push(TransportKind::Https);
    kinds
}

/// Which binding to use: the strict preference order, or one named binding.
///
/// `Auto` takes the highest-preference binding the registry advertises and
/// this build speaks (TSP, then DIDComm, then HTTPS). There is **no
/// fallback**: if that binding then fails — a mediator that refuses the run's
/// DID, say — the query fails; it is never retried over a lower one. A named
/// binding is used only if the registry advertises it and this build speaks
/// it; otherwise the run fails, naming both sides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, clap::ValueEnum)]
pub enum TransportSelector {
    /// TSP, then DIDComm, then HTTPS — whichever is advertised first.
    #[default]
    Auto,
    /// TSP only.
    Tsp,
    /// DIDComm only.
    Didcomm,
    /// HTTPS only: the `#rest` endpoint the DID document names.
    Https,
}

impl TransportSelector {
    /// The one binding this names; `None` for `Auto`.
    #[must_use]
    pub fn kind(self) -> Option<TransportKind> {
        match self {
            Self::Auto => None,
            Self::Tsp => Some(TransportKind::Tsp),
            Self::Didcomm => Some(TransportKind::Didcomm),
            Self::Https => Some(TransportKind::Https),
        }
    }
}

impl std::fmt::Display for TransportSelector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind() {
            Some(kind) => write!(f, "{kind}"),
            None => f.write_str("auto"),
        }
    }
}

/// The binding `selector` picks from `caps`, given what `ours` can build.
///
/// `Auto` is [`select_route`]. A named binding must be in `ours` and
/// advertised in `caps` (with a mediator DID for TSP/DIDComm); anything else
/// is an error that names what each side offers — never a quiet substitute.
pub fn choose_route(
    caps: &ServiceCapabilities,
    selector: TransportSelector,
    ours: &[TransportKind],
) -> Result<TransportChoice> {
    let Some(kind) = selector.kind() else {
        return Ok(select_route(caps, ours)?);
    };
    if !ours.contains(&kind) {
        bail!(
            "transport {kind} was requested, but this verifier cannot query over it \
             (it speaks: {})",
            list(ours)
        );
    }
    let Some(endpoint) = caps.endpoint(kind) else {
        bail!(
            "transport {kind} was requested, but the registry's DID document advertises no \
             {kind} service (it advertises: {})",
            list(&caps.advertised())
        );
    };
    if kind != TransportKind::Https && !endpoint.starts_with("did:") {
        bail!(
            "transport {kind} was requested, but the registry's {kind} endpoint {endpoint} is \
             not a mediator DID"
        );
    }
    Ok(TransportChoice {
        kind,
        endpoint: endpoint.to_string(),
    })
}

fn list(kinds: &[TransportKind]) -> String {
    if kinds.is_empty() {
        return "nothing".to_string();
    }
    kinds
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Discover how to reach `registry_did`: resolve its DID document and pick
/// the binding `selector` asks for among those in both it and `ours` (see
/// [`choose_route`]).
///
/// There is deliberately **no fallback to guessing a URL from the DID's
/// domain**: a wrong host is one whose authorization answers we would
/// believe. A registry that advertises nothing usable is an error, and
/// `--registry-url` is the explicit override.
pub async fn discover_registry_route(
    tdk: &affinidi_tdk::TDK,
    registry_did: &str,
    selector: TransportSelector,
    ours: &[TransportKind],
) -> Result<TransportChoice> {
    let response = tdk
        .did_resolver()
        .resolve(registry_did)
        .await
        .map_err(|e| anyhow::anyhow!("could not resolve registry DID {registry_did}: {e}"))?;
    let doc = serde_json::to_value(&response.doc)
        .with_context(|| format!("DID document for {registry_did} did not serialize"))?;
    let choice = choose_route(&ServiceCapabilities::from_document(&doc), selector, ours)
        .with_context(|| format!("no usable Trust Registry transport on {registry_did}"))?;
    tracing::debug!(kind = %choice.kind, endpoint = %choice.endpoint, "selected registry binding");
    Ok(choice)
}

/// The highest-preference binding advertised in `caps` that `ours` can
/// construct.
///
/// A TSP or DIDComm endpoint must be a DID (the mediator's); one that is not
/// cannot be routed to, so that binding is passed over for the next one
/// rather than handed to a transport as if it were an address. When nothing
/// is left the error names both sides' bindings.
pub fn select_route(
    caps: &ServiceCapabilities,
    ours: &[TransportKind],
) -> Result<TransportChoice, TrqlError> {
    let mut remaining = ours.to_vec();
    loop {
        let choice = caps.select(&remaining)?;
        match choice.kind {
            TransportKind::Https => return Ok(choice),
            _ if choice.endpoint.starts_with("did:") => return Ok(choice),
            kind => {
                tracing::warn!(
                    %kind,
                    endpoint = %choice.endpoint,
                    "registry advertises a {kind} endpoint that is not a mediator DID; skipping it"
                );
                remaining.retain(|k| *k != kind);
            }
        }
    }
}

/// A channel to the registry owned by the caller, for [`Registry::over_channel`].
///
/// The bridge implements this over its existing mediator session, so its
/// queries go out as its own DID on the socket it already holds.
#[async_trait::async_trait]
pub trait RegistryChannel: Send + Sync {
    /// The binding this channel speaks.
    fn kind(&self) -> TransportKind;

    /// The DID queries are sent as. Stamped as the documents' `issuer`, which
    /// the registry checks against the transport-authenticated sender.
    fn sender_did(&self) -> &str;

    /// Send the Trust Task `request` document to `recipient` and return the
    /// reply document.
    ///
    /// **Contract:** return only a reply the transport authenticated as sent
    /// by `recipient`. Everything above this — correlation, the tuple echo,
    /// the verdict — assumes it. A wait must be finite: a registry that never
    /// answers is a [`TrqlError::Timeout`].
    async fn exchange(&self, recipient: &str, request: Value) -> Result<Value, TrqlError>;
}

/// How verify-trust queries the registry for one run: the client, and the
/// session behind it when there is one.
pub struct Registry {
    client: TrqlClient,
    kind: TransportKind,
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    session: Option<Arc<mediated::MediatedTransport>>,
}

impl std::fmt::Debug for Registry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Registry")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl Registry {
    /// Query over HTTPS, at `url` (`POST <url>/trust-tasks`), as today.
    pub fn https(url: &str, registry_did: &str) -> Result<Self> {
        let transport = HttpsTransport::new(HttpsTransportConfig::new(url))?;
        Ok(Self {
            client: TrqlClient::new(Arc::new(transport), registry_did),
            kind: TransportKind::Https,
            #[cfg(any(feature = "didcomm", feature = "tsp"))]
            session: None,
        })
    }

    /// Query through a channel the caller owns (the bridge's session).
    pub fn over_channel(channel: Arc<dyn RegistryChannel>, registry_did: &str) -> Self {
        let kind = channel.kind();
        let sender = channel.sender_did().to_string();
        Self {
            client: TrqlClient::new(Arc::new(ChannelTransport(channel)), registry_did)
                .with_client_did(sender),
            kind,
            #[cfg(any(feature = "didcomm", feature = "tsp"))]
            session: None,
        }
    }

    /// Query over the TSP or DIDComm binding at `route`, as a fresh
    /// `did:peer:2` generated for this run (see the module docs).
    ///
    /// Nothing is generated or connected here: the identity is minted and the
    /// session opened when the first query is sent, so a range with nothing to
    /// ask about never touches the mediator. A session that cannot be opened
    /// fails every query with the reason — `registryUnavailable` per signer,
    /// never a pass.
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    pub fn ephemeral(
        tdk: &affinidi_tdk::TDK,
        route: &TransportChoice,
        registry_did: &str,
    ) -> Result<Self> {
        Self::ephemeral_with_timeout(tdk, route, registry_did, None)
    }

    /// [`Registry::ephemeral`], waiting at most `reply_timeout` (default
    /// 30s) for each answer — for tests that expect none.
    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    #[doc(hidden)]
    pub fn ephemeral_with_timeout(
        tdk: &affinidi_tdk::TDK,
        route: &TransportChoice,
        registry_did: &str,
        reply_timeout: Option<Duration>,
    ) -> Result<Self> {
        let mut transport = mediated::MediatedTransport::new(
            tdk.get_shared_state(),
            route.kind,
            &route.endpoint,
            registry_did,
        )?;
        if let Some(timeout) = reply_timeout {
            transport = transport.with_reply_timeout(timeout);
        }
        let transport = Arc::new(transport);
        Ok(Self {
            client: TrqlClient::new(transport.clone(), registry_did),
            kind: route.kind,
            session: Some(transport),
        })
    }

    /// The client for `route`: HTTPS directly, the mediator bindings as an
    /// ephemeral sender ([`Registry::ephemeral`]).
    pub fn for_route(
        tdk: &affinidi_tdk::TDK,
        route: &TransportChoice,
        registry_did: &str,
    ) -> Result<Self> {
        match route.kind {
            TransportKind::Https => Self::https(&route.endpoint, registry_did),
            #[cfg(any(feature = "didcomm", feature = "tsp"))]
            _ => Self::ephemeral(tdk, route, registry_did),
            #[cfg(not(any(feature = "didcomm", feature = "tsp")))]
            kind => {
                let _ = tdk;
                bail!("this verify-trust was built without the {kind} binding")
            }
        }
    }

    /// The binding in use.
    #[must_use]
    pub fn kind(&self) -> TransportKind {
        self.kind
    }

    /// The query client, for a caller asking something other than the
    /// commit check (the bridge's start-up grant probe).
    #[must_use]
    pub fn client(&self) -> &TrqlClient {
        &self.client
    }

    /// End the run's session, if one was opened: the websocket closes and the
    /// ephemeral keys are dropped from the resolver. Idempotent.
    pub async fn close(&self) {
        #[cfg(any(feature = "didcomm", feature = "tsp"))]
        if let Some(session) = &self.session {
            session.close().await;
        }
    }
}

/// [`TrqlTransport`] over a [`RegistryChannel`], in JSON so the channel's
/// owner needs no `trust-tasks-rs` of this line.
struct ChannelTransport(Arc<dyn RegistryChannel>);

#[async_trait::async_trait]
impl TrqlTransport for ChannelTransport {
    fn kind(&self) -> TransportKind {
        self.0.kind()
    }

    async fn exchange(&self, request: TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> {
        let recipient = request.recipient.clone().ok_or_else(|| {
            TrqlError::Config("request document has no recipient to route to".to_string())
        })?;
        let body = serde_json::to_value(&request)
            .map_err(|e| TrqlError::Contract(format!("request did not serialize: {e}")))?;
        let reply = self.0.exchange(&recipient, body).await?;
        serde_json::from_value(reply)
            .map_err(|e| TrqlError::Contract(format!("reply is not a Trust Task document: {e}")))
    }
}

/// The DID part of a DID URL (`did:x:y#key-1` → `did:x:y`).
#[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(dead_code))]
fn did_of(did_url: &str) -> &str {
    did_url.split_once('#').map_or(did_url, |(did, _)| did)
}

/// Whether a mediator-delivered reply is one we may believe: the binding
/// proved it came from `registry_did`, and it answers `request_id`.
///
/// Pure, so the rule every binding applies is tested once. `authenticated_as`
/// is the sender the transport *proved* (the DIDComm authcrypt key's DID, or
/// the TSP-verified sender VID) — `None` for anything anonymous. `claimed_from`
/// is the plaintext sender header where the binding has one.
#[cfg_attr(not(any(feature = "didcomm", feature = "tsp")), allow(dead_code))]
pub(crate) fn accept_reply(
    authenticated_as: Option<&str>,
    claimed_from: Option<&str>,
    registry_did: &str,
    document: &TrustTask<Value>,
    request_id: &str,
) -> Result<(), String> {
    let Some(proven) = authenticated_as else {
        return Err("reply was not authenticated to any sender".to_string());
    };
    if did_of(proven) != registry_did {
        return Err(format!(
            "reply was authenticated as {}, not the registry {registry_did}",
            did_of(proven)
        ));
    }
    if let Some(claimed) = claimed_from
        && did_of(claimed) != registry_did
    {
        return Err(format!(
            "reply claims to be from {claimed}, not the registry {registry_did}"
        ));
    }
    if document.thread_id.as_deref() != Some(request_id) {
        return Err(format!(
            "reply threadId {:?} does not answer request {request_id}",
            document.thread_id
        ));
    }
    Ok(())
}

#[cfg(any(feature = "didcomm", feature = "tsp"))]
mod mediated {
    //! The TSP and DIDComm bindings, as a fresh `did:peer:2` on the
    //! registry's mediator.

    use super::*;

    use affinidi_tdk::common::TDKSharedState;
    use affinidi_tdk::dids::{DID, KeyType, PeerKeyRole};
    use affinidi_tdk::messaging::ATM;
    use affinidi_tdk::messaging::config::ATMConfig;
    use affinidi_tdk::messaging::profiles::ATMProfile;
    use affinidi_tdk::secrets_resolver::SecretsResolver;
    use affinidi_tdk::secrets_resolver::secrets::Secret;
    use tokio::time::Instant;

    /// `trust-tasks-didcomm`'s envelope message type (0.21 line).
    #[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
    pub(crate) const DIDCOMM_ENVELOPE_TYPE: &str =
        "https://trusttasks.org/binding/didcomm/0.1/envelope";
    /// `trust-tasks-tsp`'s envelope `type` (0.21 line).
    #[cfg_attr(not(feature = "tsp"), allow(dead_code))]
    pub(crate) const TSP_ENVELOPE_TYPE: &str = "https://trusttasks.org/binding/tsp/0.1/envelope";
    /// DIDComm problem reports: how a mediator says it refused a message.
    const PROBLEM_REPORT_TYPE: &str = "https://didcomm.org/report-problem/2.0/problem-report";

    /// Connecting to the mediator (resolve, authenticate, websocket).
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
    /// Waiting for the registry's answer to one query (or to a TSP
    /// relationship invite). A registry that answers at all answers in well
    /// under a second; this bounds how long a mediator that silently drops
    /// the query can hold the check.
    const REPLY_TIMEOUT: Duration = Duration::from_secs(30);
    /// One pickup poll.
    const POLL: Duration = Duration::from_secs(5);
    /// The run identity's profile alias in the SDK.
    const PROFILE_ALIAS: &str = "verify-trust";

    /// A per-run `did:peer:2`: an Ed25519 key (V) and an X25519 key (E), and
    /// a DIDComm service whose endpoint is the mediator DID the replies are
    /// to be routed through.
    ///
    /// The keys exist only in this value and in the in-memory secrets
    /// resolver the session hands them to; `Debug` prints the DID alone.
    pub struct EphemeralIdentity {
        did: String,
        pub(crate) secrets: Vec<Secret>,
    }

    impl std::fmt::Debug for EphemeralIdentity {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("EphemeralIdentity")
                .field("did", &self.did)
                .finish_non_exhaustive()
        }
    }

    impl EphemeralIdentity {
        /// A fresh identity whose replies route through `mediator_did`.
        pub fn generate(mediator_did: &str) -> Result<Self> {
            let (did, secrets) = DID::generate_did_peer(
                vec![
                    (PeerKeyRole::Verification, KeyType::Ed25519),
                    (PeerKeyRole::Encryption, KeyType::X25519),
                ],
                Some(mediator_did.to_string()),
            )
            .map_err(|e| anyhow::anyhow!("generating the run's did:peer: {e}"))?;
            Ok(Self { did, secrets })
        }

        /// The DID.
        #[must_use]
        pub fn did(&self) -> &str {
            &self.did
        }
    }

    /// An open session: the messaging SDK, and the run identity's profile on
    /// the mediator.
    struct Session {
        atm: ATM,
        profile: Arc<ATMProfile>,
        #[cfg_attr(not(feature = "didcomm"), allow(dead_code))]
        did: String,
        secret_ids: Vec<String>,
    }

    #[derive(Default)]
    struct State {
        session: Option<Session>,
        /// Why queries now fail without being sent: the session could not be
        /// opened, or an earlier query went unanswered. Set once, never
        /// cleared — a mediator that refused or dropped one query is not
        /// asked again in the same run, so a range with many signers fails in
        /// one timeout rather than one per signer.
        failed: Option<String>,
        closed: bool,
    }

    /// [`TrqlTransport`] for the TSP and DIDComm bindings, as an ephemeral
    /// sender, checking every reply with [`accept_reply`].
    pub(crate) struct MediatedTransport {
        kind: TransportKind,
        mediator_did: String,
        registry_did: String,
        shared: Arc<TDKSharedState>,
        state: tokio::sync::Mutex<State>,
        reply_timeout: Duration,
        /// The last run DID minted, so a test can check its keys are gone.
        #[cfg(test)]
        pub(crate) last_did: std::sync::Mutex<Option<String>>,
    }

    impl MediatedTransport {
        pub(crate) fn new(
            shared: Arc<TDKSharedState>,
            kind: TransportKind,
            mediator_did: &str,
            registry_did: &str,
        ) -> Result<Self> {
            match kind {
                #[cfg(feature = "didcomm")]
                TransportKind::Didcomm => {}
                #[cfg(feature = "tsp")]
                TransportKind::Tsp => {}
                other => bail!("the {other} binding is not a mediator binding in this build"),
            }
            if !mediator_did.starts_with("did:") {
                bail!("the {kind} endpoint {mediator_did} is not a mediator DID");
            }
            Ok(Self {
                kind,
                mediator_did: mediator_did.to_string(),
                registry_did: registry_did.to_string(),
                shared,
                state: tokio::sync::Mutex::new(State::default()),
                reply_timeout: REPLY_TIMEOUT,
                #[cfg(test)]
                last_did: std::sync::Mutex::new(None),
            })
        }

        fn transport_error(&self, detail: impl Into<String>) -> TrqlError {
            TrqlError::Transport {
                kind: self.kind,
                detail: detail.into(),
            }
        }

        /// Mint the run identity, connect it to the mediator, and (TSP) form
        /// the relationship with the registry. On any failure the keys are
        /// dropped from the resolver and the SDK is shut down before the
        /// error is returned.
        async fn open(&self) -> Result<Session, String> {
            let identity =
                EphemeralIdentity::generate(&self.mediator_did).map_err(|e| e.to_string())?;
            let did = identity.did.clone();
            #[cfg(test)]
            {
                *self.last_did.lock().unwrap_or_else(|p| p.into_inner()) = Some(did.clone());
            }
            let secret_ids: Vec<String> = identity.secrets.iter().map(|s| s.id.clone()).collect();
            for secret in identity.secrets {
                self.shared.secrets_resolver().insert(secret).await;
            }
            let forget_keys = || async {
                for id in &secret_ids {
                    let _ = self.shared.secrets_resolver().remove_secret(id).await;
                }
            };

            let atm = match ATMConfig::builder().build() {
                Ok(config) => ATM::new(config, Arc::clone(&self.shared))
                    .await
                    .map_err(|e| format!("messaging SDK: {e}")),
                Err(e) => Err(format!("messaging config: {e}")),
            };
            let atm = match atm {
                Ok(atm) => atm,
                Err(e) => {
                    forget_keys().await;
                    return Err(e);
                }
            };
            let profile = match self.connect(&atm, &did).await {
                Ok(p) => p,
                Err(e) => {
                    let _ = atm.profile_remove(PROFILE_ALIAS).await;
                    atm.graceful_shutdown().await;
                    forget_keys().await;
                    return Err(e);
                }
            };
            let session = Session {
                atm,
                profile,
                did,
                secret_ids,
            };
            #[cfg(feature = "tsp")]
            if self.kind == TransportKind::Tsp
                && let Err(e) = self.form_relationship(&session).await
            {
                close_session(&self.shared, session).await;
                return Err(e);
            }
            Ok(session)
        }

        /// Register the run identity's profile and open its websocket.
        async fn connect(&self, atm: &ATM, did: &str) -> Result<Arc<ATMProfile>, String> {
            let profile = ATMProfile::new(
                atm,
                Some(PROFILE_ALIAS.to_string()),
                did.to_string(),
                Some(self.mediator_did.clone()),
            )
            .await
            .map_err(|e| format!("mediator {}: {e}", self.mediator_did))?;
            let profile = atm
                .profile_add(&profile, false)
                .await
                .map_err(|e| format!("messaging profile: {e}"))?;
            match tokio::time::timeout(CONNECT_TIMEOUT, atm.profile_enable_websocket(&profile))
                .await
            {
                Ok(Ok(())) => Ok(profile),
                Ok(Err(e)) => Err(format!(
                    "mediator {} did not accept this run's ephemeral DID — it must admit DIDs \
                     it has not seen (acl mode explicit_deny, and a global_acl_default \
                     granting LOCAL): {e}",
                    self.mediator_did
                )),
                Err(_) => Err(format!(
                    "mediator {} did not answer within {}s",
                    self.mediator_did,
                    CONNECT_TIMEOUT.as_secs()
                )),
            }
        }

        pub(crate) fn with_reply_timeout(mut self, timeout: Duration) -> Self {
            self.reply_timeout = timeout;
            self
        }

        pub(crate) async fn close(&self) {
            let mut state = self.state.lock().await;
            state.closed = true;
            if let Some(session) = state.session.take() {
                close_session(&self.shared, session).await;
            }
        }
    }

    async fn close_session(shared: &TDKSharedState, session: Session) {
        let _ = session.atm.profile_remove(PROFILE_ALIAS).await;
        session.atm.graceful_shutdown().await;
        for id in &session.secret_ids {
            let _ = shared.secrets_resolver().remove_secret(id).await;
        }
    }

    #[async_trait::async_trait]
    impl TrqlTransport for MediatedTransport {
        fn kind(&self) -> TransportKind {
            self.kind
        }

        async fn exchange(&self, request: TrustTask<Value>) -> Result<TrustTask<Value>, TrqlError> {
            // One exchange at a time: the session has one pickup stream, and
            // queries are sequential anyway.
            let mut state = self.state.lock().await;
            if let Some(why) = &state.failed {
                return Err(self.transport_error(why.clone()));
            }
            if state.closed {
                return Err(self.transport_error("the registry session is closed"));
            }
            if state.session.is_none() {
                match self.open().await {
                    Ok(session) => {
                        tracing::debug!(
                            kind = %self.kind,
                            mediator = %self.mediator_did,
                            "opened an ephemeral registry session"
                        );
                        state.session = Some(session);
                    }
                    Err(e) => {
                        state.failed = Some(e.clone());
                        return Err(self.transport_error(e));
                    }
                }
            }
            let Some(session) = state.session.as_ref() else {
                return Err(self.transport_error("no registry session"));
            };
            let result = match self.kind {
                #[cfg(feature = "didcomm")]
                TransportKind::Didcomm => self.didcomm_exchange(session, request).await,
                #[cfg(feature = "tsp")]
                TransportKind::Tsp => self.tsp_exchange(session, request).await,
                other => Err(self.transport_error(format!("{other} is not a mediator binding"))),
            };
            if let Err(e @ (TrqlError::Timeout { .. } | TrqlError::Transport { .. })) = &result {
                state.failed = Some(format!("an earlier registry query failed: {e}"));
            }
            result
        }
    }

    #[cfg(feature = "didcomm")]
    impl MediatedTransport {
        async fn didcomm_exchange(
            &self,
            session: &Session,
            request: TrustTask<Value>,
        ) -> Result<TrustTask<Value>, TrqlError> {
            use affinidi_tdk::didcomm::Message;

            let request_id = request.id.clone();
            let body = serde_json::to_value(&request)
                .map_err(|e| TrqlError::Contract(format!("request did not serialize: {e}")))?;
            let envelope_id = uuid::Uuid::new_v4().to_string();
            let envelope =
                Message::build(envelope_id.clone(), DIDCOMM_ENVELOPE_TYPE.to_string(), body)
                    .from(session.did.clone())
                    .to(self.registry_did.clone())
                    .thid(request_id.clone())
                    .finalize();
            let (packed, _) = session
                .atm
                .pack_encrypted(
                    &envelope,
                    &self.registry_did,
                    Some(&session.did),
                    Some(&session.did),
                )
                .await
                .map_err(|e| self.transport_error(format!("packing for the registry: {e}")))?;
            session
                .atm
                .forward_and_send_message(
                    &session.profile,
                    false,
                    &packed,
                    Some(&envelope_id),
                    &self.mediator_did,
                    &self.registry_did,
                    None,
                    None,
                    false,
                )
                .await
                .map_err(|e| {
                    self.transport_error(format!(
                        "mediator {} refused the query: {e}",
                        self.mediator_did
                    ))
                })?;

            let deadline = Instant::now() + self.reply_timeout;
            loop {
                let wait = deadline.saturating_duration_since(Instant::now());
                if wait.is_zero() {
                    return Err(TrqlError::Timeout {
                        kind: self.kind,
                        waited_secs: self.reply_timeout.as_secs(),
                    });
                }
                let next = session
                    .atm
                    .message_pickup()
                    .live_stream_next(&session.profile, Some(wait.min(POLL)), true)
                    .await
                    .map_err(|e| self.transport_error(format!("pickup: {e}")))?;
                let Some((message, meta)) = next else {
                    continue;
                };
                if message.typ == PROBLEM_REPORT_TYPE {
                    return Err(self.transport_error(format!(
                        "{} reported a problem: {}",
                        message.from.as_deref().unwrap_or("the mediator"),
                        problem_comment(&message.body)
                    )));
                }
                if message.typ != DIDCOMM_ENVELOPE_TYPE {
                    tracing::debug!(r#type = %message.typ, "ignoring a non-Trust-Task message");
                    continue;
                }
                let document: TrustTask<Value> = match serde_json::from_value(message.body) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!("ignoring a malformed Trust Task envelope: {e}");
                        continue;
                    }
                };
                let proven = meta
                    .authenticated
                    .then_some(meta.encrypted_from_kid.as_deref())
                    .flatten()
                    .filter(|_| !meta.anonymous_sender);
                match accept_reply(
                    proven,
                    message.from.as_deref(),
                    &self.registry_did,
                    &document,
                    &request_id,
                ) {
                    Ok(()) => return Ok(document),
                    Err(why) => tracing::warn!("ignoring a DIDComm reply: {why}"),
                }
            }
        }
    }

    /// A problem report's human-readable `comment`, or the whole body.
    fn problem_comment(body: &Value) -> String {
        body.get("comment")
            .and_then(Value::as_str)
            .map_or_else(|| body.to_string(), str::to_string)
    }

    #[cfg(feature = "tsp")]
    impl MediatedTransport {
        /// Rev 3 §7.2.2: an application message needs a relationship first.
        /// Send the invite and wait for the registry's accept, so the query
        /// that follows is not processed ahead of the invite and dropped.
        async fn form_relationship(&self, session: &Session) -> Result<(), String> {
            use affinidi_tdk::messaging::protocols::tsp::InboundTsp;
            use affinidi_tdk::tsp::message::control::ControlType;

            session
                .atm
                .tsp()
                .form_relationship(&session.profile, &self.registry_did)
                .await
                .map_err(|e| format!("TSP relationship invite to the registry: {e}"))?;
            let deadline = Instant::now() + self.reply_timeout;
            loop {
                let wait = deadline.saturating_duration_since(Instant::now());
                if wait.is_zero() {
                    return Err(format!(
                        "the registry did not accept the TSP relationship within {}s",
                        self.reply_timeout.as_secs()
                    ));
                }
                let Some(frame) = self.next_tsp(session, wait).await? else {
                    continue;
                };
                if let InboundTsp::Control {
                    control, sender, ..
                } = frame
                {
                    if sender != self.registry_did {
                        tracing::warn!("ignoring a TSP control message from {sender}");
                        continue;
                    }
                    session
                        .atm
                        .tsp()
                        .record_incoming_control(&session.profile, &sender, &control)
                        .await
                        .map_err(|e| format!("recording the registry's TSP answer: {e}"))?;
                    match control.control_type {
                        ControlType::RelationshipFormingAccept => return Ok(()),
                        ControlType::RelationshipCancel => {
                            return Err("the registry declined the TSP relationship".to_string());
                        }
                        ControlType::RelationshipFormingInvite => {}
                    }
                }
            }
        }

        /// The next TSP frame on the session, unpacked. `Ok(None)`: nothing
        /// usable arrived this poll. A DIDComm problem report (the mediator
        /// refusing something) fails.
        async fn next_tsp(
            &self,
            session: &Session,
            wait: Duration,
        ) -> Result<Option<affinidi_tdk::messaging::protocols::tsp::InboundTsp>, String> {
            use affinidi_tdk::messaging::protocols::message_pickup::InboundFrame;

            let frame = session
                .atm
                .message_pickup()
                .live_stream_next_frame(&session.profile, Some(wait.min(POLL)), true)
                .await
                .map_err(|e| format!("pickup: {e}"))?;
            match frame {
                Some(InboundFrame::Tsp(packed)) => {
                    let tsp = session.atm.tsp();
                    let qb2 = match tsp.decode(&packed) {
                        Ok(b) => b,
                        Err(e) => {
                            tracing::warn!("ignoring an undecodable TSP frame: {e}");
                            return Ok(None);
                        }
                    };
                    match tsp.unpack_message(&session.profile, &qb2).await {
                        Ok(m) => Ok(Some(m)),
                        Err(e) => {
                            tracing::warn!("ignoring a TSP frame that did not unpack: {e}");
                            Ok(None)
                        }
                    }
                }
                Some(InboundFrame::DidComm(message, _)) if message.typ == PROBLEM_REPORT_TYPE => {
                    Err(format!(
                        "{} reported a problem: {}",
                        message.from.as_deref().unwrap_or("the mediator"),
                        problem_comment(&message.body)
                    ))
                }
                _ => Ok(None),
            }
        }

        async fn tsp_exchange(
            &self,
            session: &Session,
            request: TrustTask<Value>,
        ) -> Result<TrustTask<Value>, TrqlError> {
            use affinidi_tdk::messaging::protocols::tsp::InboundTsp;

            let request_id = request.id.clone();
            let envelope = build_tsp_envelope(&request)?;
            session
                .atm
                .tsp()
                .send(&session.profile, &self.registry_did, &envelope)
                .await
                .map_err(|e| {
                    self.transport_error(format!(
                        "mediator {} refused the query: {e}",
                        self.mediator_did
                    ))
                })?;

            let deadline = Instant::now() + self.reply_timeout;
            loop {
                let wait = deadline.saturating_duration_since(Instant::now());
                if wait.is_zero() {
                    return Err(TrqlError::Timeout {
                        kind: self.kind,
                        waited_secs: self.reply_timeout.as_secs(),
                    });
                }
                let frame = self
                    .next_tsp(session, wait)
                    .await
                    .map_err(|e| self.transport_error(e))?;
                let Some(InboundTsp::Application { payload, sender }) = frame else {
                    continue;
                };
                let document = match parse_tsp_envelope(&payload) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::warn!("ignoring a TSP message from {sender}: {e}");
                        continue;
                    }
                };
                // The TSP sender VID is the one the message's signature was
                // verified against; there is no separate plaintext claim.
                match accept_reply(
                    Some(&sender),
                    None,
                    &self.registry_did,
                    &document,
                    &request_id,
                ) {
                    Ok(()) => return Ok(document),
                    Err(why) => tracing::warn!("ignoring a TSP reply: {why}"),
                }
            }
        }
    }

    /// Frame a document in the `trust-tasks-tsp` binding envelope.
    #[cfg(feature = "tsp")]
    pub(crate) fn build_tsp_envelope(document: &TrustTask<Value>) -> Result<Vec<u8>, TrqlError> {
        let document = serde_json::to_value(document)
            .map_err(|e| TrqlError::Contract(format!("request did not serialize: {e}")))?;
        serde_json::to_vec(&serde_json::json!({ "type": TSP_ENVELOPE_TYPE, "document": document }))
            .map_err(|e| TrqlError::Contract(format!("envelope did not serialize: {e}")))
    }

    /// Parse a `trust-tasks-tsp` binding envelope.
    #[cfg(feature = "tsp")]
    pub(crate) fn parse_tsp_envelope(payload: &[u8]) -> Result<TrustTask<Value>, String> {
        let envelope: Value = serde_json::from_slice(payload)
            .map_err(|e| format!("invalid TSP envelope JSON: {e}"))?;
        match envelope.get("type").and_then(Value::as_str) {
            Some(t) if t == TSP_ENVELOPE_TYPE => {}
            other => return Err(format!("unexpected TSP envelope type: {other:?}")),
        }
        let document = envelope
            .get("document")
            .cloned()
            .ok_or_else(|| "TSP envelope missing `document`".to_string())?;
        serde_json::from_value(document).map_err(|e| format!("invalid Trust Task document: {e}"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    const REGISTRY: &str = "did:webvh:QmRegistryScid:registry.example";

    fn reply_to(request_id: &str) -> TrustTask<Value> {
        let mut doc = TrustTask::new(
            "urn:uuid:reply".to_string(),
            "https://trusttasks.org/spec/registry/authorization/0.1#response"
                .parse()
                .unwrap(),
            serde_json::json!({}),
        );
        doc.thread_id = Some(request_id.to_string());
        doc
    }

    #[test]
    fn this_build_speaks_every_binding_in_preference_order() {
        // The published crate's default features are the release binaries'.
        let kinds = supported_transports();
        #[cfg(all(feature = "tsp", feature = "didcomm"))]
        assert_eq!(
            kinds,
            vec![
                TransportKind::Tsp,
                TransportKind::Didcomm,
                TransportKind::Https
            ]
        );
        assert_eq!(kinds.last(), Some(&TransportKind::Https));
    }

    fn caps_only(kind: &str, endpoint: &str) -> ServiceCapabilities {
        ServiceCapabilities::from_document(&serde_json::json!({
            "id": REGISTRY,
            "service": [{
                "id": format!("{REGISTRY}#x"),
                "type": kind,
                "serviceEndpoint": endpoint
            }]
        }))
    }

    #[cfg(feature = "tsp")]
    #[test]
    fn a_tsp_only_registry_is_selected_not_refused() {
        // No #rest service at all: this used to fail with "set --registry-url".
        let choice = select_route(
            &caps_only("TSPTransport", "did:web:mediator.example"),
            &supported_transports(),
        )
        .unwrap();
        assert_eq!(choice.kind, TransportKind::Tsp);
        assert_eq!(choice.endpoint, "did:web:mediator.example");
    }

    #[cfg(feature = "didcomm")]
    #[test]
    fn a_didcomm_only_registry_is_selected_not_refused() {
        let choice = select_route(
            &caps_only("DIDCommMessaging", "did:web:mediator.example"),
            &supported_transports(),
        )
        .unwrap();
        assert_eq!(choice.kind, TransportKind::Didcomm);
    }

    fn all_three() -> ServiceCapabilities {
        ServiceCapabilities::from_document(&serde_json::json!({
            "id": REGISTRY,
            "service": [
                { "id": "#rest", "type": "TRQPRest",
                  "serviceEndpoint": { "uri": "https://registry.example" } },
                { "id": "#dc", "type": "DIDCommMessaging",
                  "serviceEndpoint": { "uri": "did:web:mediator.example" } },
                { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:web:mediator.example" }
            ]
        }))
    }

    #[test]
    fn a_named_transport_picks_that_binding_and_auto_is_strict_preference() {
        let every = [
            TransportKind::Tsp,
            TransportKind::Didcomm,
            TransportKind::Https,
        ];
        let pick = |s| choose_route(&all_three(), s, &every).unwrap();
        assert_eq!(pick(TransportSelector::Auto).kind, TransportKind::Tsp);
        assert_eq!(pick(TransportSelector::Tsp).kind, TransportKind::Tsp);
        assert_eq!(
            pick(TransportSelector::Didcomm).kind,
            TransportKind::Didcomm
        );
        let https = pick(TransportSelector::Https);
        assert_eq!(https.kind, TransportKind::Https);
        assert_eq!(
            https.endpoint, "https://registry.example",
            "the #rest endpoint"
        );
    }

    #[test]
    fn a_named_transport_the_registry_does_not_advertise_is_an_error() {
        // Never a quiet substitute: asking for HTTPS of a registry with no
        // #rest fails, even though TSP is right there.
        let caps = caps_only("TSPTransport", "did:web:mediator.example");
        let every = [
            TransportKind::Tsp,
            TransportKind::Didcomm,
            TransportKind::Https,
        ];
        for s in [TransportSelector::Https, TransportSelector::Didcomm] {
            let e = choose_route(&caps, s, &every).unwrap_err().to_string();
            assert!(e.contains("advertises no") && e.contains("tsp"), "{e}");
        }
    }

    #[test]
    fn a_named_transport_this_build_cannot_speak_is_an_error() {
        let e = choose_route(
            &all_three(),
            TransportSelector::Tsp,
            &[TransportKind::Https],
        )
        .unwrap_err()
        .to_string();
        assert!(
            e.contains("cannot query over it") && e.contains("https"),
            "{e}"
        );
    }

    #[test]
    fn a_named_mediator_transport_needs_a_mediator_did() {
        let caps = caps_only("TSPTransport", "https://oops.example");
        let e = choose_route(&caps, TransportSelector::Tsp, &[TransportKind::Tsp])
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a mediator DID"), "{e}");
    }

    #[test]
    fn an_https_only_build_still_refuses_a_mediator_only_registry() {
        let error = select_route(
            &caps_only("TSPTransport", "did:web:mediator.example"),
            &[TransportKind::Https],
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("https") && error.contains("tsp"), "{error}");
    }

    #[cfg(all(feature = "tsp", feature = "didcomm"))]
    #[test]
    fn a_mediator_endpoint_that_is_not_a_did_is_passed_over() {
        // A TSP endpoint that is a URL cannot be routed to as a mediator; the
        // next binding is used rather than a transport being handed a URL.
        let caps = ServiceCapabilities::from_document(&serde_json::json!({
            "id": REGISTRY,
            "service": [
                { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "https://oops.example" },
                { "id": "#dc", "type": "DIDCommMessaging",
                  "serviceEndpoint": { "uri": "did:web:mediator.example" } }
            ]
        }));
        let choice = select_route(&caps, &supported_transports()).unwrap();
        assert_eq!(choice.kind, TransportKind::Didcomm);
    }

    // --- the reply rule ---

    #[test]
    fn a_reply_authenticated_as_the_registry_is_accepted() {
        let doc = reply_to("urn:uuid:q");
        accept_reply(
            Some(&format!("{REGISTRY}#key-2")),
            Some(REGISTRY),
            REGISTRY,
            &doc,
            "urn:uuid:q",
        )
        .unwrap();
        // TSP: the verified sender VID, no separate claim.
        accept_reply(Some(REGISTRY), None, REGISTRY, &doc, "urn:uuid:q").unwrap();
    }

    #[test]
    fn a_correlated_reply_from_anyone_else_is_refused() {
        // The thread id is right; the sender is not the registry. This is the
        // check trql-client's own mediator transports do not make.
        let doc = reply_to("urn:uuid:q");
        let why = accept_reply(
            Some("did:peer:2.Vz6MkAttacker#key-1"),
            Some("did:peer:2.Vz6MkAttacker"),
            REGISTRY,
            &doc,
            "urn:uuid:q",
        )
        .unwrap_err();
        assert!(why.contains("not the registry"), "{why}");
    }

    #[test]
    fn an_anonymous_reply_is_refused() {
        let doc = reply_to("urn:uuid:q");
        assert!(accept_reply(None, Some(REGISTRY), REGISTRY, &doc, "urn:uuid:q").is_err());
    }

    #[test]
    fn a_from_header_contradicting_the_proven_sender_is_refused() {
        let doc = reply_to("urn:uuid:q");
        assert!(
            accept_reply(
                Some(&format!("{REGISTRY}#key-2")),
                Some("did:web:someone.else"),
                REGISTRY,
                &doc,
                "urn:uuid:q",
            )
            .is_err()
        );
    }

    #[test]
    fn an_uncorrelated_reply_from_the_registry_is_refused() {
        let doc = reply_to("urn:uuid:other");
        assert!(accept_reply(Some(REGISTRY), None, REGISTRY, &doc, "urn:uuid:q").is_err());
    }

    // --- the run identity ---

    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    #[tokio::test]
    async fn the_run_identity_is_fresh_routes_via_the_mediator_and_prints_no_key() {
        let mediator = "did:web:mediator.example";
        let a = EphemeralIdentity::generate(mediator).unwrap();
        let b = EphemeralIdentity::generate(mediator).unwrap();
        assert!(a.did().starts_with("did:peer:2."), "{}", a.did());
        assert_ne!(a.did(), b.did(), "a fresh DID per run");

        // did:peer:2 is self-describing: its document carries the service
        // that tells the registry where to send the reply.
        let tdk = crate::build_resolver(false).await.unwrap();
        let doc = tdk.did_resolver().resolve(a.did()).await.unwrap().doc;
        let doc = serde_json::to_value(doc).unwrap();
        assert!(
            doc.to_string().contains(mediator),
            "the service names the mediator: {doc}"
        );

        // No key material in what a log line would print.
        let debug = format!("{a:?}");
        for secret in &a.secrets {
            let private = hex::encode(secret.get_private_bytes());
            assert!(!debug.contains(&private));
        }
        assert!(debug.contains(a.did()));
    }

    #[cfg(any(feature = "didcomm", feature = "tsp"))]
    #[tokio::test]
    async fn a_mediator_that_cannot_be_reached_fails_every_query_closed() {
        // The mediator DID names a non-public host, which the resolver's
        // public-hosts-only policy refuses without touching the network: the
        // session cannot open. Every query must fail as a transport error —
        // which `query_registry` records as `registryUnavailable` — and the
        // second must fail at once rather than trying again.
        let tdk = crate::build_resolver(false).await.unwrap();
        let route = TransportChoice {
            kind: supported_transports()[0],
            endpoint: "did:web:127.0.0.1%3A9".to_string(),
        };
        let registry = Registry::ephemeral(&tdk, &route, REGISTRY).unwrap();
        let query = || trql_client::TrqpQuery::new("did:example:e", "did:example:a", "x", "y");

        let first = registry.client().authorization(query()).await.unwrap_err();
        assert!(
            matches!(first, TrqlError::Transport { .. }),
            "expected a transport failure, got {first}"
        );
        let started = std::time::Instant::now();
        let second = registry.client().authorization(query()).await.unwrap_err();
        assert!(matches!(second, TrqlError::Transport { .. }));
        assert!(started.elapsed() < Duration::from_secs(1), "fails fast");

        // The run's keys lived only in the in-memory resolver, and a session
        // that failed to open has already dropped them from it.
        use affinidi_tdk::secrets_resolver::SecretsResolver;
        let session = registry.session.as_ref().unwrap();
        let did = session
            .last_did
            .lock()
            .unwrap()
            .clone()
            .expect("a DID was minted");
        for key in ["#key-1", "#key-2"] {
            assert!(
                tdk.get_shared_state()
                    .secrets_resolver()
                    .get_secret(&format!("{did}{key}"))
                    .await
                    .is_none(),
                "{did}{key} must not outlive the failed session"
            );
        }
        registry.close().await;
    }

    #[cfg(feature = "tsp")]
    #[test]
    fn the_tsp_envelope_round_trips_and_names_the_binding() {
        let mut doc = reply_to("urn:uuid:q");
        doc.id = "urn:uuid:1".into();
        let bytes = mediated::build_tsp_envelope(&doc).unwrap();
        let back = mediated::parse_tsp_envelope(&bytes).unwrap();
        assert_eq!(back.id, "urn:uuid:1");
        let wrong =
            serde_json::to_vec(&serde_json::json!({"type": "https://x", "document": {}})).unwrap();
        assert!(mediated::parse_tsp_envelope(&wrong).is_err());
    }

    #[test]
    fn the_envelope_types_are_the_bindings_the_registry_serves() {
        // Hard-coded to avoid two more crates on the trust-tasks line; pinned
        // here against the registry's own constants' values.
        #[cfg(any(feature = "didcomm", feature = "tsp"))]
        {
            assert_eq!(
                mediated::DIDCOMM_ENVELOPE_TYPE,
                "https://trusttasks.org/binding/didcomm/0.1/envelope"
            );
            assert_eq!(
                mediated::TSP_ENVELOPE_TYPE,
                "https://trusttasks.org/binding/tsp/0.1/envelope"
            );
        }
    }
}
