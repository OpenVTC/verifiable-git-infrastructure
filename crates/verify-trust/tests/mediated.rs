//! The mediator bindings end to end, against an in-process mediator.
//!
//! verify-trust mints a `did:peer:2` for the run, connects it to the
//! mediator, and queries a fake registry — another DID on the same mediator
//! that answers Trust Task envelopes the way the registry's DIDComm and TSP
//! bindings do. What is under test is verify-trust's side: the session opens,
//! the reply routes back to the ephemeral DID, a reply from anyone but the
//! registry is not believed, and a mediator that admits only listed DIDs
//! fails the query closed.

#![cfg(any(feature = "didcomm", feature = "tsp"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_test_mediator::{
    AccessListModeType, MediatorACLSet, TestEnvironment, TestMediator, TestUser,
};
use serde_json::{Value, json};
use trql_client::{TransportChoice, TransportKind, TrqlError, TrqpQuery};
use verify_trust::Registry;

const DIDCOMM_ENVELOPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";
const TSP_ENVELOPE: &str = "https://trusttasks.org/binding/tsp/0.1/envelope";

/// The registry's `#response` to an authorization request document.
fn answer(request: &Value, authorized: bool, issuer: &str) -> Value {
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
            "authorized": authorized, "time_evaluated": "2026-09-25T00:00:00Z"
        }
    })
}

/// The narrowest `global_acl_default` under which a run's fresh DID can
/// query a registry and hear back: an inbox open to senders it has never
/// listed (`MODE_EXPLICIT_DENY` — it cannot list the registry itself; this is
/// all TSP needs), plus the forwarded-message bits DIDComm travels under (the
/// query is a routing `forward`, and so is the registry's reply). Without
/// `SEND_FORWARDED` the mediator answers the query with a problem report,
/// which fails it at once.
const ADMITS_EPHEMERAL: &str = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES,\
                                SEND_FORWARDED,RECEIVE_FORWARDED,MODE_EXPLICIT_DENY";
/// The mediator's shipped `global_acl_default`: a new DID's inbox is an
/// empty allowlist, so nobody can answer it.
const SHIPPED_DEFAULT: &str = "DENY_ALL,LOCAL,SEND_MESSAGES,RECEIVE_MESSAGES";

/// A mediator in `mode`, giving DIDs it has not seen `global_acl`.
async fn mediator(mode: AccessListModeType, global_acl: &str) -> Arc<TestEnvironment> {
    let handle = TestMediator::builder()
        .acl_mode(mode)
        .global_acl_default(MediatorACLSet::from_string_ruleset(global_acl).unwrap())
        .local_direct_delivery(true, false)
        .spawn()
        .await
        .unwrap();
    Arc::new(TestEnvironment::new(handle).await.unwrap())
}

async fn open_mediator() -> Arc<TestEnvironment> {
    mediator(AccessListModeType::ExplicitDeny, ADMITS_EPHEMERAL).await
}

fn query() -> TrqpQuery {
    TrqpQuery::new(
        "did:example:alice",
        "did:example:vtc",
        "git.commit.sign",
        "github.com/acme/widgets",
    )
}

async fn online(env: &TestEnvironment, user: &TestUser) {
    env.atm
        .profile_enable_websocket(&user.profile)
        .await
        .unwrap();
}

/// Answer DIDComm Trust Task envelopes addressed to `registry`, as
/// `reply_as` (the registry itself, or an impostor holding the thread).
fn serve_didcomm(
    env: Arc<TestEnvironment>,
    registry: TestUser,
    reply_as: TestUser,
) -> tokio::task::JoinHandle<()> {
    use affinidi_tdk::didcomm::Message;
    tokio::spawn(async move {
        loop {
            let next = env
                .atm
                .message_pickup()
                .live_stream_next(&registry.profile, Some(Duration::from_millis(500)), true)
                .await;
            let Ok(Some((message, _))) = next else {
                continue;
            };
            if message.typ != DIDCOMM_ENVELOPE {
                continue;
            }
            let sender = message.from.clone().expect("authcrypt names the sender");
            let reply = answer(&message.body, true, &reply_as.did);
            let id = uuid::Uuid::new_v4().to_string();
            let envelope = Message::build(id.clone(), DIDCOMM_ENVELOPE.to_string(), reply)
                .from(reply_as.did.clone())
                .to(sender.clone())
                .thid(message.body["id"].as_str().unwrap().to_string())
                .finalize();
            let (packed, _) = env
                .atm
                .pack_encrypted(&envelope, &sender, Some(&reply_as.did), Some(&reply_as.did))
                .await
                .unwrap();
            let _ = env
                .atm
                .forward_and_send_message(
                    &reply_as.profile,
                    false,
                    &packed,
                    Some(&id),
                    env.mediator.did(),
                    &sender,
                    None,
                    None,
                    false,
                )
                .await;
        }
    })
}

async fn ephemeral(
    env: &TestEnvironment,
    kind: TransportKind,
    registry_did: &str,
    timeout: Duration,
) -> Registry {
    let tdk = verify_trust::build_resolver(false).await.unwrap();
    let route = TransportChoice {
        kind,
        endpoint: env.mediator.did().to_string(),
    };
    Registry::ephemeral_with_timeout(&tdk, &route, registry_did, Some(timeout)).unwrap()
}

#[cfg(feature = "didcomm")]
#[tokio::test]
async fn a_didcomm_query_from_the_runs_own_did_is_answered_by_the_registry() {
    let env = open_mediator().await;
    let registry = env.add_user("Registry").await.unwrap();
    online(&env, &registry).await;
    let server = serve_didcomm(env.clone(), registry.clone(), registry.clone());

    let client = ephemeral(
        &env,
        TransportKind::Didcomm,
        &registry.did,
        Duration::from_secs(20),
    )
    .await;
    let answer = client.client().authorization(query()).await.unwrap();
    assert!(answer.authorized);
    // A second query rides the same session.
    assert!(
        client
            .client()
            .authorization(query())
            .await
            .unwrap()
            .authorized
    );
    client.close().await;
    server.abort();
}

#[cfg(feature = "didcomm")]
#[tokio::test]
async fn a_correlated_didcomm_reply_from_another_did_is_not_believed() {
    let env = open_mediator().await;
    let registry = env.add_user("Registry").await.unwrap();
    let mallory = env.add_user("Mallory").await.unwrap();
    online(&env, &registry).await;
    online(&env, &mallory).await;
    // Mallory sees the query and answers "authorized" on its thread, sealed
    // with her own key. The answer is never accepted; the query times out.
    let server = serve_didcomm(env.clone(), registry.clone(), mallory.clone());

    let client = ephemeral(
        &env,
        TransportKind::Didcomm,
        &registry.did,
        Duration::from_secs(4),
    )
    .await;
    let error = client.client().authorization(query()).await.unwrap_err();
    assert!(matches!(error, TrqlError::Timeout { .. }), "{error}");
    client.close().await;
    server.abort();
}

#[tokio::test]
async fn a_mediator_that_admits_only_listed_dids_fails_the_query_closed() {
    // The registry's mediator in `ExplicitAllow` mode: the registry is on its
    // list, the run's fresh did:peer cannot be. The query fails as a
    // transport error — `registryUnavailable` — never as an answer.
    let env = mediator(AccessListModeType::ExplicitAllow, ADMITS_EPHEMERAL).await;
    let registry = env.add_user("Registry").await.unwrap();
    online(&env, &registry).await;
    let server = serve_didcomm(env.clone(), registry.clone(), registry.clone());

    for kind in verify_trust::registry::supported_transports() {
        if kind == TransportKind::Https {
            continue;
        }
        let client = ephemeral(&env, kind, &registry.did, Duration::from_secs(4)).await;
        let error = client.client().authorization(query()).await.unwrap_err();
        assert!(
            matches!(error, TrqlError::Transport { .. }),
            "{kind}: {error}"
        );
        client.close().await;
    }
    server.abort();
}

#[cfg(feature = "didcomm")]
#[tokio::test]
async fn a_mediator_on_its_shipped_acl_default_fails_the_query_closed() {
    // Open mode, but the shipped `global_acl_default`: the run's DID
    // connects, and nothing can be delivered to it (nor forwarded for it).
    // Unavailable, not a pass — and the reason operators must widen the
    // default for CI to reach a registry this way (docs/RUNBOOK.md).
    let env = mediator(AccessListModeType::ExplicitDeny, SHIPPED_DEFAULT).await;
    let registry = env.add_user("Registry").await.unwrap();
    online(&env, &registry).await;
    let server = serve_didcomm(env.clone(), registry.clone(), registry.clone());

    let client = ephemeral(
        &env,
        TransportKind::Didcomm,
        &registry.did,
        Duration::from_secs(4),
    )
    .await;
    let error = client.client().authorization(query()).await.unwrap_err();
    assert!(
        matches!(
            error,
            TrqlError::Transport { .. } | TrqlError::Timeout { .. }
        ),
        "{error}"
    );
    client.close().await;
    server.abort();
}

/// Answer TSP: accept the relationship invite, then answer each Trust Task
/// envelope, as the registry.
#[cfg(feature = "tsp")]
fn serve_tsp(env: Arc<TestEnvironment>, registry: TestUser) -> tokio::task::JoinHandle<()> {
    use affinidi_tdk::messaging::protocols::message_pickup::InboundFrame;
    use affinidi_tdk::messaging::protocols::tsp::InboundTsp;
    tokio::spawn(async move {
        loop {
            let frame = env
                .atm
                .message_pickup()
                .live_stream_next_frame(&registry.profile, Some(Duration::from_millis(500)), true)
                .await;
            let Ok(Some(InboundFrame::Tsp(packed))) = frame else {
                continue;
            };
            let tsp = env.atm.tsp();
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
                    tsp.accept_relationship(&registry.profile, &sender, thread_digest)
                        .await
                        .unwrap();
                }
                InboundTsp::Application { payload, sender } => {
                    let envelope: Value = serde_json::from_slice(&payload).unwrap();
                    assert_eq!(envelope["type"], TSP_ENVELOPE);
                    let reply = answer(&envelope["document"], true, &registry.did);
                    let bytes =
                        serde_json::to_vec(&json!({ "type": TSP_ENVELOPE, "document": reply }))
                            .unwrap();
                    tsp.send(&registry.profile, &sender, &bytes).await.unwrap();
                }
                _ => {}
            }
        }
    })
}

#[cfg(feature = "tsp")]
#[tokio::test]
async fn a_tsp_query_forms_the_relationship_and_is_answered_by_the_registry() {
    let env = open_mediator().await;
    let registry = env.add_user("Registry").await.unwrap();
    online(&env, &registry).await;
    let server = serve_tsp(env.clone(), registry.clone());

    let client = ephemeral(
        &env,
        TransportKind::Tsp,
        &registry.did,
        Duration::from_secs(20),
    )
    .await;
    let answer = client.client().authorization(query()).await.unwrap();
    assert!(answer.authorized);
    client.close().await;
    server.abort();
}
