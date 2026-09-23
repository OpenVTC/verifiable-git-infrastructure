//! The link to the VTC.
//!
//! **DIDComm** (authcrypt through the community's mediator) is the transport,
//! per the VTI order of preference (TSP, then DIDComm, then REST): the VTC's
//! outbound Trust Task path is DIDComm today (it starts no TSP sends), so a
//! TSP leg would be one-way. Adding it later is a second [`VtcLink`] on the
//! same socket, not a change here.
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

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_core::MessageTransport;
use affinidi_messaging_delivery::{Delivery, InMemoryOutboxStore, MessagingService, OutboxStore};
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

use crate::identity::BridgeIdentity;
use crate::wire::{ENVELOPE_TYPE, new_id};

/// A signed Trust Task document out to a peer.
#[async_trait]
pub trait VtcLink: Send + Sync {
    /// Send `doc` to `to`. `Ok` is hop acceptance only.
    async fn send(&self, to: &str, doc: &Value) -> Result<()>;
}

/// One document in from the transport.
#[derive(Debug, Clone)]
pub struct InboundDoc {
    /// The Trust Task document.
    pub doc: Value,
    /// The sender the transport proved (DIDComm authcrypt), if any.
    pub authenticated_sender: Option<String>,
}

/// How long connecting to the mediator may take.
const MEDIATOR_TIMEOUT: Duration = Duration::from_secs(30);

/// A DIDComm connection through the mediator.
pub struct DidcommLink {
    atm: Arc<ATM>,
    profile: Arc<ATMProfile>,
    service: Arc<MessagingService>,
    did: String,
}

impl DidcommLink {
    /// Connect `identity` to `mediator_did` and return the link and the
    /// stream of inbound Trust Task documents. The stream ending means the
    /// session is dead: reconnect (see [`SupervisedLink`]).
    ///
    /// Unlike vta-sdk's session helpers this never flushes the mediator
    /// inbox: jobs queued while the bridge was down are exactly what it has
    /// to read.
    pub async fn connect(
        identity: &BridgeIdentity,
        mediator_did: &str,
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
                let stream = inbound_stream(service.subscribe());
                Ok((
                    DidcommLink {
                        atm,
                        profile,
                        service,
                        did: identity.did().to_string(),
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
        let transport: Arc<dyn MessageTransport> = Arc::new(
            DidCommTransport::new((**atm).clone(), profile.clone())
                .await
                .map_err(|e| anyhow!("DIDComm transport: {e}"))?,
        );
        // Nothing durable here: results and events are retried from the
        // bridge's own store until the VTC acknowledges them.
        let outbox: Arc<dyn OutboxStore> = Arc::new(InMemoryOutboxStore::new());
        Ok((profile, Arc::new(MessagingService::new(transport, outbox))))
    }

    /// Stop the websocket and the messaging tasks. There is no `Drop`: an
    /// abandoned session keeps reconnecting and holds the mediator's slot.
    pub async fn shutdown(&self) {
        let _ = self.atm.profile_remove(&self.did).await;
        self.atm.graceful_shutdown().await;
    }
}

#[async_trait]
impl VtcLink for DidcommLink {
    async fn send(&self, to: &str, doc: &Value) -> Result<()> {
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
        let _ = &self.profile;
        self.service
            .send(to, packed.into_bytes(), Delivery::BestEffort)
            .await
            .map_err(|e| anyhow!("sending to `{to}`: {e}"))?;
        Ok(())
    }
}

/// Inbound DIDComm → Trust Task documents. Anything that is not the Trust
/// Task envelope is dropped here, with a log line; the envelope's body is
/// the document, and the authcrypt sender travels with it only when the
/// transport verified it.
fn inbound_stream(
    stream: BoxStream<'static, affinidi_messaging_core::Inbound>,
) -> BoxStream<'static, InboundDoc> {
    stream
        .filter_map(|inbound| async move {
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
            })
        })
        .boxed()
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
}

/// In-process links for tests: whatever the bridge sends lands on a
/// channel, as the fake VTC's inbox.
pub mod memory {
    use super::*;
    use tokio::sync::mpsc;

    /// A link that delivers to a channel.
    pub struct ChannelLink {
        tx: mpsc::UnboundedSender<(String, Value)>,
    }

    impl ChannelLink {
        /// The link, and the receiving end of what it sends.
        pub fn new() -> (Self, mpsc::UnboundedReceiver<(String, Value)>) {
            let (tx, rx) = mpsc::unbounded_channel();
            (ChannelLink { tx }, rx)
        }
    }

    #[async_trait]
    impl VtcLink for ChannelLink {
        async fn send(&self, to: &str, doc: &Value) -> Result<()> {
            self.tx
                .send((to.to_string(), doc.clone()))
                .map_err(|_| anyhow!("the peer is gone"))
        }
    }
}
