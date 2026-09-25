//! The bridge's channel to the Trust Registry for the bridge-posted check.
//!
//! When the registry's DID document advertises DIDComm, the bridge queries it
//! **as its own DID** — the stable, VTA-provisioned identity the community
//! already knows — over the mediator session it already holds for the VTC
//! ([`VtcLink`]). It does not open a second session: the mediator permits one
//! websocket per DID, and a second would take the job link's slot.
//!
//! Replies come back on the same inbound stream as the VTC's jobs.
//! [`Bridge::handle_inbound`](crate::Bridge::handle_inbound) offers each
//! inbound document to [`RegistryReplies::route`] first; a document is taken
//! only when the transport proved it came from the registry's DID **and** it
//! answers a query in flight (`threadId`). Everything else — including a
//! registry that is also the VTC, sending a job — carries on to the job path
//! untouched.
//!
//! The answer's integrity rests on the registry's key (DIDComm authcrypt), not
//! on the bridge's: a reply the transport did not authenticate as the
//! registry is never delivered to a waiting query, which then times out as
//! `registryUnavailable`.
//!
//! The authenticated sender is taken from the messaging SDK, which hands the
//! bridge each message already unpacked — the envelope is not available here
//! for verify-trust's own header check. It is believed because the SDK
//! (affinidi-messaging-sdk 0.27.2 / affinidi-messaging-didcomm 0.15.9 and
//! later, which this workspace requires) binds an authcrypt message's
//! reported sender to the key its key agreement actually used. On top of it,
//! the sender must be a *verified* one, the reply's thread must be a query in
//! flight — every query carries a fresh random id (verify-trust's channel
//! transport) — and the first failure is latched for the rest of the check. A registry whose mediator refuses the bridge's DID
//! (access-list mode `ExplicitAllow` without the bridge on the list) fails the
//! same way — closed.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::oneshot;
use trql_client::{TransportKind, TrqlError};
use verify_trust::RegistryChannel;

use crate::transport::{InboundDoc, VtcLink};

/// How long a registry query waits for its reply.
const REPLY_TIMEOUT: Duration = Duration::from_secs(30);

/// Registry queries in flight, keyed by request document id.
#[derive(Debug)]
pub struct RegistryReplies {
    registry_did: String,
    pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
}

impl RegistryReplies {
    /// For the registry at `registry_did`.
    pub fn new(registry_did: impl Into<String>) -> Self {
        RegistryReplies {
            registry_did: registry_did.into(),
            pending: Mutex::new(HashMap::new()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, oneshot::Sender<Value>>> {
        self.pending.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn register(&self, id: &str) -> oneshot::Receiver<Value> {
        let (tx, rx) = oneshot::channel();
        self.lock().insert(id.to_string(), tx);
        rx
    }

    fn abandon(&self, id: &str) {
        self.lock().remove(id);
    }

    /// Take `inbound` if it is the registry's answer to a query in flight.
    /// Returns whether it was taken; if not, it belongs to the job path.
    pub fn route(&self, inbound: &InboundDoc) -> bool {
        let Some(sender) = inbound.authenticated_sender.as_deref() else {
            return false;
        };
        let sender = sender.split_once('#').map_or(sender, |(did, _)| did);
        if sender != self.registry_did {
            return false;
        }
        let Some(thread) = inbound.doc.get("threadId").and_then(Value::as_str) else {
            return false;
        };
        let Some(waiter) = self.lock().remove(thread) else {
            return false;
        };
        // A waiter that gave up (timed out) still means the document was a
        // registry reply, not a job.
        let _ = waiter.send(inbound.doc.clone());
        true
    }
}

/// [`RegistryChannel`] over the bridge's VTC link, as the bridge's DID.
pub struct BridgeRegistryChannel {
    link: Arc<dyn VtcLink>,
    did: String,
    replies: Arc<RegistryReplies>,
    timeout: Duration,
}

impl BridgeRegistryChannel {
    /// Send as `did` over `link`; replies arrive through `replies`.
    pub fn new(
        link: Arc<dyn VtcLink>,
        did: impl Into<String>,
        replies: Arc<RegistryReplies>,
    ) -> Self {
        BridgeRegistryChannel {
            link,
            did: did.into(),
            replies,
            timeout: REPLY_TIMEOUT,
        }
    }

    /// Wait at most `timeout` for each reply (tests).
    #[doc(hidden)]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
}

#[async_trait]
impl RegistryChannel for BridgeRegistryChannel {
    fn kind(&self) -> TransportKind {
        TransportKind::Didcomm
    }

    fn sender_did(&self) -> &str {
        &self.did
    }

    async fn exchange(&self, recipient: &str, request: Value) -> Result<Value, TrqlError> {
        let transport = |detail: String| TrqlError::Transport {
            kind: TransportKind::Didcomm,
            detail,
        };
        if recipient != self.replies.registry_did {
            return Err(TrqlError::Config(format!(
                "registry channel is for {}, not {recipient}",
                self.replies.registry_did
            )));
        }
        let id = request
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| TrqlError::Contract("request document has no id".to_string()))?
            .to_string();
        // Register before sending, so a fast reply cannot be lost.
        let reply = self.replies.register(&id);
        if let Err(e) = self.link.send(recipient, &request).await {
            self.replies.abandon(&id);
            return Err(transport(format!("sending to the registry: {e:#}")));
        }
        match tokio::time::timeout(self.timeout, reply).await {
            Ok(Ok(doc)) => Ok(doc),
            Ok(Err(_)) => {
                self.replies.abandon(&id);
                Err(transport("the reply channel closed".to_string()))
            }
            Err(_) => {
                self.replies.abandon(&id);
                Err(TrqlError::Timeout {
                    kind: TransportKind::Didcomm,
                    waited_secs: self.timeout.as_secs(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::memory::ChannelLink;

    const REGISTRY: &str = "did:webvh:QmReg:registry.example";

    fn inbound(sender: Option<&str>, doc: Value) -> InboundDoc {
        InboundDoc {
            doc,
            authenticated_sender: sender.map(str::to_string),
        }
    }

    #[tokio::test]
    async fn a_query_goes_out_as_the_bridge_and_its_proven_answer_comes_back() {
        let (link, mut sent) = ChannelLink::new();
        let replies = Arc::new(RegistryReplies::new(REGISTRY));
        let channel =
            BridgeRegistryChannel::new(Arc::new(link), "did:key:z6MkBridge", replies.clone());

        let answer = tokio::spawn(async move {
            channel
                .exchange(
                    REGISTRY,
                    serde_json::json!({ "id": "urn:uuid:q", "issuer": "did:key:z6MkBridge" }),
                )
                .await
        });
        let (to, doc) = sent.recv().await.unwrap();
        assert_eq!(to, REGISTRY);
        assert_eq!(doc["issuer"], "did:key:z6MkBridge");

        // A correlated reply the transport did not prove is from the
        // registry is not an answer: it stays with the job path.
        let forged =
            serde_json::json!({ "threadId": "urn:uuid:q", "payload": { "authorized": true } });
        assert!(!replies.route(&inbound(Some("did:key:z6MkMallory"), forged.clone())));
        assert!(!replies.route(&inbound(None, forged)));

        let real =
            serde_json::json!({ "threadId": "urn:uuid:q", "payload": { "authorized": false } });
        assert!(replies.route(&inbound(Some(&format!("{REGISTRY}#key-2")), real)));
        let got = answer.await.unwrap().unwrap();
        assert_eq!(got["payload"]["authorized"], false);
    }

    #[tokio::test]
    async fn a_registry_that_never_answers_times_out_and_later_mail_is_not_taken() {
        let (link, _sent) = ChannelLink::new();
        let replies = Arc::new(RegistryReplies::new(REGISTRY));
        let channel =
            BridgeRegistryChannel::new(Arc::new(link), "did:key:z6MkBridge", replies.clone())
                .with_timeout(Duration::from_millis(20));
        let e = channel
            .exchange(REGISTRY, serde_json::json!({ "id": "urn:uuid:q" }))
            .await
            .unwrap_err();
        assert!(matches!(e, TrqlError::Timeout { .. }), "{e}");
        // The late reply — or a job from a registry that is also the VTC —
        // goes on to the job path.
        let late = serde_json::json!({ "threadId": "urn:uuid:q" });
        assert!(!replies.route(&inbound(Some(REGISTRY), late)));
    }

    #[tokio::test]
    async fn a_link_that_is_down_fails_the_query_rather_than_waiting() {
        let link = crate::transport::SupervisedLink::new(); // never connected
        let replies = Arc::new(RegistryReplies::new(REGISTRY));
        let channel = BridgeRegistryChannel::new(Arc::new(link), "did:key:z6MkBridge", replies);
        let e = channel
            .exchange(REGISTRY, serde_json::json!({ "id": "urn:uuid:q" }))
            .await
            .unwrap_err();
        assert!(matches!(e, TrqlError::Transport { .. }), "{e}");
    }
}
