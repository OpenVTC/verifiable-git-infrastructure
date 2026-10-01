//! The bridge's messaging link: to the VTC, and to the Trust Registry for
//! the bridge-posted check.
//!
//! **TSP, then DIDComm**, per the VTI order of preference (TSP, then DIDComm,
//! then REST), both on the **one** mediator websocket the mediator permits
//! per DID: the messaging SDK's delivery transport surfaces both protocols
//! off that socket, tagged, so there is no second session to hold.
//!
//! - **Inbound.** A Trust Task document arrives over either. A TSP frame is
//!   taken only with a sender VID the TSP unpack verified (there is no
//!   plaintext sender to fall back on), and only inside the published
//!   `trust-tasks-tsp` binding envelope; a DIDComm message carries its
//!   authcrypt sender when the SDK verified one. Either way the proven sender
//!   travels with the document as [`InboundDoc::authenticated_sender`], and
//!   the job path refuses a document whose issuer it is not
//!   (`identityMismatch`).
//! - **Replies** go back over the transport the request came in on (the VTC
//!   waits for its job's answer on that transport's correlation).
//! - **Everything else** — results, events, registry queries — goes over the
//!   first of TSP, DIDComm the peer's DID document advertises
//!   ([`preferred_via`]); [`VtcLink::send_via`] pins one instead.
//! - **TSP relationships.** A relationship invite is accepted only from the
//!   peers the link was connected for (the VTC and the registry): a
//!   relationship carries no authority, but there is no reason to form one
//!   with anybody else. The relationship store is in memory, so on every
//!   connect the bridge invites the VTC again ([`MediatorLink::relate`]),
//!   which is what lets a VTC that kept its half reach a restarted bridge.
//!
//! The transport's authentication is not what authorises a job — the
//! document's own proof is (spec: "on every transport") — but the proven
//! sender is still passed on, and a mismatch with the document's issuer is
//! refused (`identityMismatch`).
//!
//! Sending is best effort: a send `Ok` means the mediator took the frame, not
//! that the VTC has it (rule R1.1). Delivery of what matters — results and
//! events — is confirmed by the VTC's response and retried from the outbox
//! until it comes ([`crate::Bridge::resend_unacknowledged`]).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_messaging_core::{InboundKind, MessageTransport, Protocol, RelationshipRequest};
use affinidi_messaging_delivery::{Delivery, InMemoryOutboxStore, MessagingService, OutboxStore};
use affinidi_messaging_sdk::protocols::tsp::{SendReadiness, invite_refusal_is_benign};
use affinidi_tdk::common::TDKSharedState;
use affinidi_tdk::common::config::TDKConfig;
use affinidi_tdk::didcomm::Message;
use affinidi_tdk::messaging::ATM;
use affinidi_tdk::messaging::DidCommTransport;
use affinidi_tdk::messaging::config::ATMConfig;
use affinidi_tdk::messaging::profiles::ATMProfile;
use affinidi_tdk::secrets_resolver::SecretsResolver;
use anyhow::{Context, Result, anyhow};
use async_trait::async_trait;
use futures_util::StreamExt;
use futures_util::stream::BoxStream;
use serde_json::Value;
use tokio::sync::RwLock;
use vta_sdk::protocol::matching::ServiceCapabilities;

use crate::identity::BridgeIdentity;
use crate::wire::{ENVELOPE_TYPE, new_id};

/// The transport a document travels over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Via {
    /// The Trust Spanning Protocol, in the `trust-tasks-tsp` binding.
    Tsp,
    /// DIDComm v2 authcrypt, in the `trust-tasks-didcomm` binding.
    Didcomm,
}

impl std::fmt::Display for Via {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Via::Tsp => "TSP",
            Via::Didcomm => "DIDComm",
        })
    }
}

/// The transport to reach a peer by, from what its DID document advertises:
/// TSP when it lists a `TSPTransport` service, else DIDComm (a peer that
/// advertises neither is tried over DIDComm, which needs only its keys).
pub fn preferred_via(caps: &ServiceCapabilities) -> Via {
    if caps.tsp.is_some() {
        Via::Tsp
    } else {
        Via::Didcomm
    }
}

/// A signed Trust Task document out to a peer.
#[async_trait]
pub trait VtcLink: Send + Sync {
    /// Send `doc` to `to`: a response over the transport its request came in
    /// on, anything else over the peer's preferred transport
    /// ([`preferred_via`]). `Ok` is hop acceptance only.
    async fn send(&self, to: &str, doc: &Value) -> Result<()>;

    /// Send `doc` to `to` over `via`, and no other transport.
    async fn send_via(&self, to: &str, doc: &Value, via: Via) -> Result<()>;
}

/// One document in from the transport.
#[derive(Debug, Clone)]
pub struct InboundDoc {
    /// The Trust Task document.
    pub doc: Value,
    /// The sender the transport proved (DIDComm authcrypt, or the TSP sender
    /// VID the message's signature verified against), if any.
    pub authenticated_sender: Option<String>,
    /// The transport it came in on.
    pub via: Via,
}

/// How long connecting to the mediator may take.
const MEDIATOR_TIMEOUT: Duration = Duration::from_secs(30);

/// How many inbound requests' transports are remembered, so their responses
/// go back the same way. A response follows its request within seconds; a
/// bridge that answers later (a repeat answered from the ledger) is answered
/// over the peer's preferred transport, which the VTC also listens on.
const ARRIVALS_KEPT: usize = 1024;

/// Which transport recent inbound documents came in on, by document id.
#[derive(Default)]
struct Arrivals(Mutex<VecDeque<(String, Via)>>);

impl Arrivals {
    fn record(&self, id: &str, via: Via) {
        let mut q = self.0.lock().unwrap_or_else(|p| p.into_inner());
        if q.len() >= ARRIVALS_KEPT {
            q.pop_front();
        }
        q.push_back((id.to_string(), via));
    }

    fn of(&self, id: &str) -> Option<Via> {
        let q = self.0.lock().unwrap_or_else(|p| p.into_inner());
        q.iter().rev().find(|(i, _)| i == id).map(|(_, v)| *v)
    }
}

/// The mediator session: TSP and DIDComm on one websocket.
pub struct MediatorLink {
    atm: Arc<ATM>,
    tdk: Arc<TDKSharedState>,
    profile: Arc<ATMProfile>,
    service: Arc<MessagingService>,
    did: String,
    mediator_did: String,
    arrivals: Arc<Arrivals>,
}

/// What the inbound stream needs to answer TSP relationship requests.
struct InboundCtx {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    /// The DIDs whose TSP relationship invites are accepted.
    peers: Vec<String>,
    arrivals: Arc<Arrivals>,
}

impl MediatorLink {
    /// Connect `identity` to `mediator_did` and return the link and the
    /// stream of inbound Trust Task documents. `peers` are the DIDs whose
    /// TSP relationship invites the link accepts (the VTC, the registry).
    /// The stream ending means the session is dead: reconnect (see
    /// [`SupervisedLink`]).
    ///
    /// Unlike vta-sdk's session helpers this never flushes the mediator
    /// inbox: jobs queued while the bridge was down are exactly what it has
    /// to read.
    pub async fn connect(
        identity: &BridgeIdentity,
        mediator_did: &str,
        peers: Vec<String>,
    ) -> Result<(Self, BoxStream<'static, InboundDoc>)> {
        let tdk = Arc::new(
            TDKSharedState::new(TDKConfig::builder().build()?)
                .await
                .map_err(|e| anyhow!("TDK: {e}"))?,
        );
        for secret in identity.messaging_secrets() {
            tdk.secrets_resolver().insert(secret).await;
        }
        let atm = Arc::new(
            ATM::new(ATMConfig::builder().build()?, Arc::clone(&tdk))
                .await
                .map_err(|e| anyhow!("messaging: {e}"))?,
        );
        match Self::attach(&atm, identity.did(), mediator_did).await {
            Ok((profile, service)) => {
                let arrivals = Arc::new(Arrivals::default());
                let ctx = Arc::new(InboundCtx {
                    atm: Arc::clone(&atm),
                    profile: Arc::clone(&profile),
                    peers,
                    arrivals: Arc::clone(&arrivals),
                });
                let stream = inbound_stream(service.subscribe(), ctx);
                Ok((
                    MediatorLink {
                        atm,
                        tdk,
                        profile,
                        service,
                        did: identity.did().to_string(),
                        mediator_did: mediator_did.to_string(),
                        arrivals,
                    },
                    stream,
                ))
            }
            Err(e) => {
                // The ATM owns live tasks from the moment it exists; a failed
                // connect must not leave a socket holding the mediator's one
                // slot for this DID.
                atm.graceful_shutdown().await;
                Err(e)
            }
        }
    }

    async fn attach(
        atm: &Arc<ATM>,
        did: &str,
        mediator_did: &str,
    ) -> Result<(Arc<ATMProfile>, Arc<MessagingService>)> {
        let profile = ATMProfile::new(atm, None, did.to_string(), Some(mediator_did.to_string()))
            .await
            .map_err(|e| anyhow!("building the messaging profile: {e}"))?;
        let profile = atm
            .profile_add(&profile, false)
            .await
            .map_err(|e| anyhow!("registering the messaging profile: {e}"))?;
        tokio::time::timeout(MEDIATOR_TIMEOUT, atm.profile_enable_websocket(&profile))
            .await
            .context("the mediator did not answer in time")?
            .map_err(|e| anyhow!("mediator websocket: {e}"))?;
        // The delivery transport surfaces DIDComm *and* TSP frames off this
        // one socket, tagged by protocol.
        let transport: Arc<dyn MessageTransport> = Arc::new(
            DidCommTransport::new((**atm).clone(), profile.clone())
                .await
                .map_err(|e| anyhow!("messaging transport: {e}"))?,
        );
        // Nothing durable here: results and events are retried from the
        // bridge's own store until the VTC acknowledges them.
        let outbox: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
        Ok((profile, Arc::new(MessagingService::new(transport, outbox))))
    }

    /// The transport `peer` is best reached by, from its DID document.
    pub async fn preferred(&self, peer: &str) -> Result<Via> {
        let resolved = self
            .tdk
            .did_resolver()
            .resolve(peer)
            .await
            .map_err(|e| anyhow!("resolving `{peer}`: {e}"))?;
        let doc = serde_json::to_value(&resolved.doc)
            .map_err(|e| anyhow!("reading `{peer}`'s DID document: {e}"))?;
        Ok(preferred_via(&ServiceCapabilities::from_did_document(&doc)))
    }

    /// Form a TSP relationship with `peer` now, if it is reached over TSP
    /// and none is on record (this side's store is in memory, so a restart
    /// loses it). A peer that kept its half re-accepts (TSP §7.2.2: an
    /// application message from a VID without a relationship is dropped
    /// silently, so without this the peer's next job would vanish).
    pub async fn relate(&self, peer: &str) -> Result<()> {
        if self.preferred(peer).await? != Via::Tsp {
            return Ok(());
        }
        let tsp = self.atm.tsp();
        if tsp
            .send_readiness(&self.profile, peer)
            .await
            .map_err(|e| anyhow!("TSP relationship with `{peer}`: {e}"))?
            == SendReadiness::Reestablish
        {
            tsp.form_relationship_routed(&self.profile, peer)
                .await
                .map_err(|e| anyhow!("TSP relationship invite to `{peer}`: {e}"))?;
        }
        Ok(())
    }

    /// Stop the websocket and the messaging tasks. There is no `Drop`: an
    /// abandoned session keeps reconnecting and holds the mediator's slot.
    pub async fn shutdown(&self) {
        let _ = self.atm.profile_remove(&self.did).await;
        self.atm.graceful_shutdown().await;
    }

    async fn send_didcomm(&self, to: &str, doc: &Value) -> Result<()> {
        let thread = doc
            .get("threadId")
            .and_then(Value::as_str)
            .map(str::to_string);
        let mut msg = Message::build(new_id(), ENVELOPE_TYPE.to_string(), doc.clone())
            .from(self.did.clone())
            .to(to.to_string());
        if let Some(t) = thread {
            msg = msg.thid(t);
        }
        let msg = msg.finalize();
        let (packed, _) = self
            .atm
            .pack_encrypted(&msg, to, Some(&self.did), Some(&self.did))
            .await
            .map_err(|e| anyhow!("packing for `{to}`: {e}"))?;
        self.service
            .send(to, packed.into_bytes(), Delivery::BestEffort)
            .await
            .map_err(|e| anyhow!("sending to `{to}`: {e}"))?;
        Ok(())
    }

    /// The recovery-aware TSP send (Rev 3 §7.2.2), wherever `to` lives:
    /// invite first when no relationship is on record, then the document
    /// behind it (§3.6). A peer on another mediator is reached through that
    /// mediator (its `TSPTransport` endpoint), since a mediator delivers a
    /// direct message only to an account it hosts.
    async fn send_tsp(&self, to: &str, doc: &Value) -> Result<()> {
        let document =
            serde_json::to_vec(doc).map_err(|e| anyhow!("serialising the document: {e}"))?;
        let body = vta_sdk::tsp_binding::wrap_envelope(&document);
        let tsp = self.atm.tsp();
        let peer_mediator = tsp
            .peer_mediator(&self.profile, to)
            .await
            .map_err(|e| anyhow!("finding `{to}`'s TSP mediator: {e}"))?
            .filter(|m| *m != self.mediator_did);
        let sent = match peer_mediator {
            None => {
                tsp.send_reestablishing(
                    &self.profile,
                    to,
                    &[self.mediator_did.clone(), to.to_string()],
                    &body,
                )
                .await
            }
            Some(peer_mediator) => {
                let invite = async {
                    if tsp.send_readiness(&self.profile, to).await? == SendReadiness::Reestablish
                        && let Err(e) = tsp.form_relationship_routed(&self.profile, to).await
                        && !invite_refusal_is_benign(tsp.send_readiness(&self.profile, to).await?)
                    {
                        return Err(e);
                    }
                    Ok(())
                };
                match invite.await {
                    Ok(()) => {
                        tsp.send_nested_routed(
                            &self.profile,
                            &[self.mediator_did.clone(), peer_mediator],
                            to,
                            &body,
                        )
                        .await
                    }
                    Err(e) => Err(e),
                }
            }
        };
        sent.map_err(|e| anyhow!("sending to `{to}` over TSP: {e}"))
    }
}

#[async_trait]
impl VtcLink for MediatorLink {
    async fn send(&self, to: &str, doc: &Value) -> Result<()> {
        let answered = doc
            .get("threadId")
            .and_then(Value::as_str)
            .and_then(|t| self.arrivals.of(t));
        let via = match answered {
            Some(via) => via,
            None => self.preferred(to).await?,
        };
        self.send_via(to, doc, via).await
    }

    async fn send_via(&self, to: &str, doc: &Value, via: Via) -> Result<()> {
        match via {
            Via::Tsp => self.send_tsp(to, doc).await,
            Via::Didcomm => self.send_didcomm(to, doc).await,
        }
    }
}

/// Inbound frames → Trust Task documents. Anything that is not a Trust Task
/// in its transport's binding is dropped here, with a log line; a TSP
/// relationship request is answered here and goes no further.
fn inbound_stream(
    stream: BoxStream<'static, affinidi_messaging_core::Inbound>,
    ctx: Arc<InboundCtx>,
) -> BoxStream<'static, InboundDoc> {
    stream
        .filter_map(move |inbound| {
            let ctx = Arc::clone(&ctx);
            async move {
                let doc = match inbound.message.protocol {
                    Protocol::DIDComm => didcomm_doc(&inbound),
                    Protocol::TSP => tsp_doc(&ctx, inbound).await,
                    other => {
                        tracing::warn!(protocol = ?other, "dropping an inbound message in a protocol this bridge does not speak");
                        None
                    }
                }?;
                if let Some(id) = doc.doc.get("id").and_then(Value::as_str) {
                    ctx.arrivals.record(id, doc.via);
                }
                Some(doc)
            }
        })
        .boxed()
}

/// A DIDComm message's Trust Task document: the envelope's body, with the
/// authcrypt sender only when the transport verified it.
fn didcomm_doc(inbound: &affinidi_messaging_core::Inbound) -> Option<InboundDoc> {
    let m = &inbound.message;
    let sender = m.sender.clone().filter(|_| m.verified);
    let msg: Message = match serde_json::from_slice(&m.payload) {
        Ok(msg) => msg,
        Err(e) => {
            tracing::warn!(error = %e, "dropping an inbound message that is not DIDComm");
            return None;
        }
    };
    if msg.typ != ENVELOPE_TYPE {
        tracing::debug!(r#type = %msg.typ, "ignoring a DIDComm message that is not a Trust Task");
        return None;
    }
    Some(InboundDoc {
        doc: msg.body,
        authenticated_sender: sender,
        via: Via::Didcomm,
    })
}

/// The sender a TSP frame proves, or `None`. `sender` is the VID TSP's
/// unpack verified the message's signature against, and `verified` says the
/// check happened; both are required. There is no plaintext-sender fallback:
/// an unproven TSP frame is not a document at all.
fn tsp_sender(m: &affinidi_messaging_core::ReceivedMessage) -> Option<String> {
    m.sender.clone().filter(|_| m.verified)
}

/// A TSP frame's Trust Task document, or `None` (a relationship request,
/// answered here; anything unproven or outside the binding envelope).
async fn tsp_doc(
    ctx: &InboundCtx,
    inbound: affinidi_messaging_core::Inbound,
) -> Option<InboundDoc> {
    let Some(sender) = tsp_sender(&inbound.message) else {
        tracing::warn!("dropping a TSP frame with no verified sender");
        return None;
    };
    match inbound.kind {
        InboundKind::Application => {}
        InboundKind::RelationshipControl {
            request,
            thread_digest,
            reply_expected,
            ..
        } => {
            answer_control(ctx, &sender, request, thread_digest, reply_expected).await;
            return None;
        }
        _ => {
            tracing::debug!(%sender, "ignoring a TSP frame that is not application data");
            return None;
        }
    }
    let document = match vta_sdk::tsp_binding::open_envelope(&inbound.message.payload) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(%sender, error = %e, "dropping a TSP message outside the Trust Task binding");
            return None;
        }
    };
    let doc: Value = match serde_json::from_slice(&document) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(%sender, error = %e, "dropping a TSP Trust Task that is not JSON");
            return None;
        }
    };
    Some(InboundDoc {
        doc,
        authenticated_sender: Some(sender),
        via: Via::Tsp,
    })
}

/// What to do about one inbound TSP relationship request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlDecision {
    /// Send an accept (the transport already recorded the invite).
    Accept,
    /// Answer a peer's cancellation the transport could not answer itself
    /// (§7.3).
    AnswerCancel,
    /// Nothing is due.
    Nothing,
}

/// Decide how to answer a relationship request from `sender`. An invite is
/// accepted only from a peer the link serves: a relationship carries no
/// authority (every document is still checked), but the bridge has no reason
/// to hold one with anybody else.
fn decide_control(
    request: RelationshipRequest,
    reply_expected: bool,
    from_peer: bool,
) -> ControlDecision {
    match request {
        RelationshipRequest::Invite if from_peer => ControlDecision::Accept,
        RelationshipRequest::Cancel if reply_expected => ControlDecision::AnswerCancel,
        _ => ControlDecision::Nothing,
    }
}

async fn answer_control(
    ctx: &InboundCtx,
    sender: &str,
    request: RelationshipRequest,
    thread_digest: [u8; 32],
    reply_expected: bool,
) {
    let from_peer = ctx.peers.iter().any(|p| p == sender);
    let tsp = ctx.atm.tsp();
    match decide_control(request, reply_expected, from_peer) {
        ControlDecision::Accept => {
            match tsp
                .accept_relationship(&ctx.profile, sender, thread_digest)
                .await
            {
                Ok(_) => tracing::info!(%sender, "accepted a TSP relationship"),
                Err(e) => {
                    tracing::warn!(%sender, error = %e, "could not accept a TSP relationship")
                }
            }
        }
        ControlDecision::AnswerCancel => {
            if let Err(e) = tsp
                .answer_cancellation(&ctx.profile, sender, thread_digest)
                .await
            {
                tracing::warn!(%sender, error = %e, "could not answer a TSP relationship cancellation");
            }
        }
        ControlDecision::Nothing => {
            if request == RelationshipRequest::Invite {
                tracing::warn!(%sender, "not accepting a TSP relationship invite from a DID this bridge does not serve");
            }
        }
    }
}

/// A [`VtcLink`] whose connection can be replaced after a reconnect. Sends
/// while disconnected fail, and the outbox sends them again.
#[derive(Default)]
pub struct SupervisedLink {
    current: RwLock<Option<Arc<dyn VtcLink>>>,
}

impl SupervisedLink {
    /// No connection yet.
    pub fn new() -> Self {
        SupervisedLink::default()
    }

    /// Put `link` in service.
    pub async fn set(&self, link: Option<Arc<dyn VtcLink>>) {
        *self.current.write().await = link;
    }
}

#[async_trait]
impl VtcLink for SupervisedLink {
    async fn send(&self, to: &str, doc: &Value) -> Result<()> {
        let link = self.current.read().await.clone();
        match link {
            Some(l) => l.send(to, doc).await,
            None => Err(anyhow!("not connected to the mediator")),
        }
    }

    async fn send_via(&self, to: &str, doc: &Value, via: Via) -> Result<()> {
        let link = self.current.read().await.clone();
        match link {
            Some(l) => l.send_via(to, doc, via).await,
            None => Err(anyhow!("not connected to the mediator")),
        }
    }
}

/// In-process links for tests: whatever the bridge sends lands on a
/// channel, as the fake VTC's inbox.
pub mod memory {
    use super::*;
    use tokio::sync::mpsc;

    /// A link that delivers to a channel. Every send counts as the
    /// transport it was asked for; [`ChannelLink::pinned`] lists the ones
    /// pinned with [`VtcLink::send_via`].
    pub struct ChannelLink {
        tx: mpsc::UnboundedSender<(String, Value)>,
        pinned: std::sync::Mutex<Vec<Via>>,
    }

    impl ChannelLink {
        /// The link, and the receiving end of what it sends.
        pub fn new() -> (Self, mpsc::UnboundedReceiver<(String, Value)>) {
            let (tx, rx) = mpsc::unbounded_channel();
            (
                ChannelLink {
                    tx,
                    pinned: Default::default(),
                },
                rx,
            )
        }

        /// The transports sends were pinned to, in order.
        pub fn pinned(&self) -> Vec<Via> {
            self.pinned
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .clone()
        }
    }

    #[async_trait]
    impl VtcLink for ChannelLink {
        async fn send(&self, to: &str, doc: &Value) -> Result<()> {
            self.tx
                .send((to.to_string(), doc.clone()))
                .map_err(|_| anyhow!("the peer is gone"))
        }

        async fn send_via(&self, to: &str, doc: &Value, via: Via) -> Result<()> {
            self.pinned
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .push(via);
            self.send(to, doc).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caps(tsp: bool, didcomm: bool) -> ServiceCapabilities {
        ServiceCapabilities {
            tsp: tsp.then(|| "did:web:mediator.example".to_string()),
            didcomm: didcomm.then(|| "did:web:mediator.example".to_string()),
            rest: None,
        }
    }

    #[test]
    fn tsp_is_preferred_over_didcomm() {
        assert_eq!(preferred_via(&caps(true, true)), Via::Tsp);
        assert_eq!(preferred_via(&caps(true, false)), Via::Tsp);
        assert_eq!(preferred_via(&caps(false, true)), Via::Didcomm);
        assert_eq!(preferred_via(&caps(false, false)), Via::Didcomm);
    }

    #[test]
    fn only_a_served_peer_gets_a_relationship() {
        assert_eq!(
            decide_control(RelationshipRequest::Invite, false, true),
            ControlDecision::Accept
        );
        assert_eq!(
            decide_control(RelationshipRequest::Invite, false, false),
            ControlDecision::Nothing
        );
        // Answering a cancellation forms nothing, so it is owed to anyone.
        assert_eq!(
            decide_control(RelationshipRequest::Cancel, true, false),
            ControlDecision::AnswerCancel
        );
        assert_eq!(
            decide_control(RelationshipRequest::Cancel, false, true),
            ControlDecision::Nothing
        );
        assert_eq!(
            decide_control(RelationshipRequest::Accept, false, true),
            ControlDecision::Nothing
        );
    }

    #[test]
    fn an_unverified_tsp_sender_is_no_sender() {
        let mut m = affinidi_messaging_core::ReceivedMessage {
            id: "x".into(),
            sender: Some("did:example:vtc".into()),
            recipient: "did:example:bridge".into(),
            payload: vec![],
            protocol: Protocol::TSP,
            verified: false,
            encrypted: true,
        };
        assert_eq!(tsp_sender(&m), None);
        m.verified = true;
        assert_eq!(tsp_sender(&m).as_deref(), Some("did:example:vtc"));
        m.sender = None;
        assert_eq!(tsp_sender(&m), None);
    }

    #[test]
    fn a_response_goes_back_the_way_its_request_came() {
        let a = Arrivals::default();
        a.record("urn:uuid:job", Via::Tsp);
        a.record("urn:uuid:other", Via::Didcomm);
        assert_eq!(a.of("urn:uuid:job"), Some(Via::Tsp));
        assert_eq!(a.of("urn:uuid:other"), Some(Via::Didcomm));
        assert_eq!(a.of("urn:uuid:unknown"), None);
        for i in 0..ARRIVALS_KEPT {
            a.record(&format!("urn:uuid:{i}"), Via::Didcomm);
        }
        assert_eq!(a.of("urn:uuid:job"), None, "the oldest are forgotten");
    }
}
