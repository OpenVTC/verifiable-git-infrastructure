//! The bridge-posted check's registry query over TSP, end to end: the
//! bridge's real `MediatorLink` on an in-process mediator, as the bridge's own
//! DID, against a fake registry on the same mediator. What is under test is
//! that an honest answer arrives through `RegistryReplies::route`, and that a
//! correlated reply from another VID — one naming the registry as its issuer
//! — never answers the query: the TSP-verified sender VID is what is
//! believed, not anything the document says. A VID the link does not serve
//! gets no relationship and none of its messages reach the bridge at all.

#![cfg(feature = "forge-github")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_messaging_test_mediator::{
    AccessListModeType, MediatorACLSet, TestEnvironment, TestMediator, TestUser,
};
use affinidi_tdk::affinidi_crypto::KeyType;
use futures_util::StreamExt;
use serde_json::{Value, json};
use tokio::sync::mpsc;
use trql_client::{TrqlError, TrqpQuery};
use vgi_bridge::BridgeIdentity;
use vgi_bridge::registry_channel::{BridgeRegistryChannel, RegistryReplies};
use vgi_bridge::transport::{MediatorLink, Via};

const TSP_ENVELOPE: &str = "https://trusttasks.org/binding/tsp/0.1/envelope";
const CANARY_THREAD: &str = "urn:uuid:canary";

async fn open_mediator() -> Arc<TestEnvironment> {
    let handle = TestMediator::builder()
        .acl_mode(AccessListModeType::ExplicitDeny)
        .global_acl_default(
            MediatorACLSet::from_string_ruleset(
                "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,SEND_FORWARDED,\
                 RECEIVE_FORWARDED,MODE_EXPLICIT_DENY",
            )
            .unwrap(),
        )
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    Arc::new(TestEnvironment::new(handle).await.unwrap())
}

fn answer(request: &Value, issuer: &str) -> Value {
    let p = &request["payload"];
    json!({
        "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
        "type": "https://trusttasks.org/spec/registry/authorization/0.1#response",
        "threadId": request["id"],
        "issuer": issuer,
        "recipient": request["issuer"],
        "payload": {
            "entity_id": p["entity_id"], "authority_id": p["authority_id"],
            "action": p["action"], "resource": p["resource"],
            "authorized": true, "time_evaluated": "2026-09-25T00:00:00Z"
        }
    })
}

fn envelope(doc: &Value) -> Vec<u8> {
    serde_json::to_vec(&json!({ "type": TSP_ENVELOPE, "document": doc })).unwrap()
}

/// What the fake registry (or its impostor) got onto the mediator.
#[derive(Debug, PartialEq)]
enum Delivered {
    Honest,
    /// Mallory, holding the thread, answering as "the registry".
    Impostor,
    /// An uncorrelated registry message sent after the impostor's: its
    /// arrival proves the bridge's stream was live past the impostor's.
    Canary,
}

/// The fake registry over TSP: accepts the bridge's relationship invite and
/// answers each query — itself, or (`impostor`) by having Mallory send a
/// correlated answer naming the registry as issuer, then a canary of its own.
fn serve(
    env: Arc<TestEnvironment>,
    registry: TestUser,
    mallory: TestUser,
    impostor: bool,
    delivered: mpsc::UnboundedSender<Delivered>,
) -> tokio::task::JoinHandle<()> {
    use affinidi_tdk::messaging::protocols::message_pickup::InboundFrame;
    use affinidi_tdk::messaging::protocols::tsp::InboundTsp;
    tokio::spawn(async move {
        let tsp = env.atm.tsp();
        loop {
            let frame = env
                .atm
                .message_pickup()
                .live_stream_next_frame(&registry.profile, Some(Duration::from_millis(500)), true)
                .await;
            let Ok(Some(InboundFrame::Tsp(packed))) = frame else {
                continue;
            };
            let qb2 = tsp.decode(&packed).unwrap();
            match tsp.unpack_message(&registry.profile, &qb2).await.unwrap() {
                InboundTsp::Control {
                    control,
                    sender,
                    thread_digest,
                } => {
                    tsp.record_incoming_control(&registry.profile, &sender, &control)
                        .await
                        .unwrap();
                    let _ = tsp
                        .accept_relationship(&registry.profile, &sender, thread_digest)
                        .await;
                }
                InboundTsp::Application { payload, sender } => {
                    let env_doc: Value = serde_json::from_slice(&payload).unwrap();
                    assert_eq!(env_doc["type"], TSP_ENVELOPE);
                    let reply = answer(&env_doc["document"], &registry.did);
                    if impostor {
                        // Mallory's own, valid TSP message: she cannot sign
                        // as the registry, so she says she is it instead.
                        tsp.form_relationship(&mallory.profile, &sender)
                            .await
                            .unwrap();
                        tsp.send(&mallory.profile, &sender, &envelope(&reply))
                            .await
                            .unwrap();
                        let _ = delivered.send(Delivered::Impostor);
                        let canary = json!({
                            "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                            "threadId": CANARY_THREAD,
                            "issuer": registry.did,
                        });
                        tsp.send(&registry.profile, &sender, &envelope(&canary))
                            .await
                            .unwrap();
                        let _ = delivered.send(Delivered::Canary);
                    } else {
                        tsp.send(&registry.profile, &sender, &envelope(&reply))
                            .await
                            .unwrap();
                        let _ = delivered.send(Delivered::Honest);
                    }
                }
                _ => {}
            }
        }
    })
}

struct Run {
    result: Result<bool, TrqlError>,
    delivered: Vec<Delivered>,
    surfaced: Vec<(Value, Option<String>, Via)>,
    registry_did: String,
    /// Whether the bridge's link held a TSP relationship with Mallory once
    /// her invite and reply had been processed.
    mallory_related: bool,
}

async fn run(impostor: bool) -> Run {
    let env = open_mediator().await;
    let registry = env.add_user("Registry").await.unwrap();
    let mallory = env.add_user("Mallory").await.unwrap();
    for u in [&registry, &mallory] {
        env.atm.profile_enable_websocket(&u.profile).await.unwrap();
    }
    // The bridge's DID, minted by the mediator's harness (a `TSPTransport`
    // service naming it). Only the bridge's own link connects as it.
    let bridge = env.add_tsp_mediated_user("Bridge").await.unwrap();
    let signing = bridge
        .secrets
        .iter()
        .find(|s| s.get_key_type() == KeyType::Ed25519)
        .unwrap()
        .clone();
    let identity =
        BridgeIdentity::from_secrets(&bridge.did, signing, bridge.secrets.clone()).unwrap();

    let (delivered_tx, mut delivered_rx) = mpsc::unbounded_channel();
    let server = serve(
        env.clone(),
        registry.clone(),
        mallory.clone(),
        impostor,
        delivered_tx,
    );

    let (link, mut inbound) = MediatorLink::connect(
        &identity,
        env.mediator.did(),
        "did:example:vtc",
        vec![registry.did.clone()],
    )
    .await
    .unwrap();
    let link = Arc::new(link);
    let replies = Arc::new(RegistryReplies::new(registry.did.clone()));
    let surfaced = Arc::new(Mutex::new(Vec::new()));
    let pump = {
        let replies = Arc::clone(&replies);
        let surfaced = Arc::clone(&surfaced);
        tokio::spawn(async move {
            while let Some(doc) = inbound.next().await {
                surfaced.lock().unwrap().push((
                    doc.doc.clone(),
                    doc.authenticated_sender.clone(),
                    doc.via,
                ));
                let _ = replies.route(&doc);
            }
        })
    };
    let channel = BridgeRegistryChannel::new(link.clone(), identity.did(), replies, Via::Tsp)
        .with_timeout(Duration::from_secs(8));
    let client = verify_trust::Registry::over_channel(Arc::new(channel), &registry.did);
    let result = client
        .client()
        .authorization(TrqpQuery::new(
            "did:example:alice",
            "did:example:vtc",
            "git.commit.sign",
            "github.com/acme",
        ))
        .await
        .map(|r| r.authorized);
    // Let a canary sent right after the impostor's reply land.
    if impostor {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        while tokio::time::Instant::now() < deadline
            && !surfaced
                .lock()
                .unwrap()
                .iter()
                .any(|(d, _, _)| d["threadId"] == CANARY_THREAD)
        {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let mallory_related = link.has_relationship(&mallory.did).await.unwrap();
    pump.abort();
    server.abort();
    link.shutdown().await;
    let mut delivered = Vec::new();
    while let Ok(d) = delivered_rx.try_recv() {
        delivered.push(d);
    }
    let surfaced = std::mem::take(&mut *surfaced.lock().unwrap());
    Run {
        result,
        delivered,
        surfaced,
        registry_did: registry.did,
        mallory_related,
    }
}

#[tokio::test]
async fn the_bridge_queries_the_registry_over_tsp_as_its_own_did() {
    let run = run(false).await;
    assert!(run.result.unwrap(), "the honest answer is authorized");
    assert_eq!(run.delivered, [Delivered::Honest]);
    let (_, sender, via) = run.surfaced.first().expect("the answer surfaced");
    assert_eq!(sender.as_deref(), Some(run.registry_did.as_str()));
    assert_eq!(*via, Via::Tsp);
}

#[tokio::test]
async fn a_correlated_tsp_reply_from_another_vid_is_not_believed() {
    let run = run(true).await;
    assert!(
        matches!(run.result, Err(TrqlError::Timeout { .. })),
        "an impostor's reply must not answer the bridge's query: {:?}",
        run.result
    );
    assert_eq!(run.delivered, [Delivered::Impostor, Delivered::Canary]);
    // Not vacuous: the canary the registry sent after the impostor's invite
    // and reply came through, so the link was live past them — and they
    // never surfaced, and left no relationship behind.
    let canary = run
        .surfaced
        .iter()
        .find(|(d, _, _)| d["threadId"] == CANARY_THREAD)
        .expect("the canary sent after the impostor's reply reached the bridge");
    assert_eq!(canary.1.as_deref(), Some(run.registry_did.as_str()));
    assert_eq!(canary.2, Via::Tsp);
    assert!(
        run.surfaced
            .iter()
            .all(|(d, _, _)| d["threadId"] == CANARY_THREAD),
        "a stranger's TSP message must not reach the bridge: {:?}",
        run.surfaced
    );
    assert!(
        !run.mallory_related,
        "a stranger's invite must leave no relationship"
    );
}
