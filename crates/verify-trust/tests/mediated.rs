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
// Some helpers serve only one binding's tests.
#![cfg_attr(not(all(feature = "didcomm", feature = "tsp")), allow(dead_code))]

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

// --- the authcrypt sender binding, end to end ---

use affinidi_tdk::affinidi_crypto::jose::{aes_kw, content_encryption, ecdh, key_agreement::*};
use affinidi_tdk::did_common::document::DocumentExt;
use sha2::{Digest, Sha256};

fn b64url(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Authcrypt with the *sender's own* key (`skid` = `real_kid`), but with
/// PartyUInfo (`apu`) naming `claimed_kid`: an envelope whose two sender
/// members disagree. verify-trust must not believe `claimed_kid`.
fn forge_jwe(
    plaintext: &[u8],
    real_kid: &str,
    claimed_kid: &str,
    sender_private: &PrivateKeyAgreement,
    recipient_kid: &str,
    recipient_pub: &PublicKeyAgreement,
) -> String {
    let ephemeral = EphemeralKeyPair::generate(Curve::X25519);
    let apu_raw = claimed_kid.as_bytes();
    let apv_raw = Sha256::digest(recipient_kid.as_bytes()).to_vec();
    let cek = content_encryption::generate_cek();
    let iv = content_encryption::generate_iv();
    let header = json!({
        "typ": "application/didcomm-encrypted+json",
        "alg": "ECDH-1PU+A256KW",
        "enc": "A256CBC-HS512",
        "skid": real_kid,
        "apu": b64url(apu_raw),
        "apv": b64url(&apv_raw),
        "epk": ephemeral.public.to_jwk(),
    });
    let protected_b64 = b64url(header.to_string().as_bytes());
    let (ct, tag) =
        content_encryption::encrypt(plaintext, &cek, &iv, protected_b64.as_bytes()).unwrap();
    let kek = ecdh::derive_sender_key_1pu(
        &ephemeral,
        sender_private,
        recipient_pub,
        apu_raw,
        &apv_raw,
        &tag,
    )
    .unwrap();
    let wrapped = aes_kw::wrap(&kek, &cek).unwrap();
    json!({
        "protected": protected_b64,
        "recipients": [{ "header": { "kid": recipient_kid }, "encrypted_key": b64url(&wrapped) }],
        "iv": b64url(&iv),
        "ciphertext": b64url(&ct),
        "tag": b64url(&tag),
    })
    .to_string()
}

async fn ka(tdk: &affinidi_tdk::TDK, did: &str) -> (String, PublicKeyAgreement) {
    let doc = tdk.did_resolver().resolve(did).await.unwrap().doc;
    let kid = doc.find_key_agreement(None)[0].to_string();
    let (_, bytes) = doc
        .get_verification_method(&kid)
        .unwrap()
        .decode_public_key()
        .unwrap();
    (
        kid,
        PublicKeyAgreement::from_raw_bytes(Curve::X25519, &bytes).unwrap(),
    )
}

/// Regression: a reply sealed with another DID's key but naming the
/// registry's key in its party info must never be believed — the query
/// times out (`registryUnavailable`), never answers.
#[cfg(feature = "didcomm")]
#[tokio::test]
async fn a_reply_whose_key_agreement_names_another_key_is_not_believed() {
    use affinidi_tdk::didcomm::Message;
    let env = open_mediator().await;
    let registry = env.add_user("Registry").await.unwrap();
    let mallory = env.add_user("Mallory").await.unwrap();
    online(&env, &registry).await;
    online(&env, &mallory).await;
    let tdk = verify_trust::build_resolver(false).await.unwrap();
    let (registry_kid, _) = ka(&tdk, &registry.did).await;
    let (mallory_kid, _) = ka(&tdk, &mallory.did).await;
    let msecret = mallory
        .secrets
        .iter()
        .find(|s| s.id == mallory_kid)
        .expect("mallory ka secret");
    let mpriv =
        PrivateKeyAgreement::from_raw_bytes(Curve::X25519, msecret.get_private_bytes()).unwrap();

    // The registry never answers. Its inbox is read only to learn the
    // threadId (stands in for a guessed/leaked request id); the reply is
    // built and sent by Mallory with Mallory's key alone.
    let env2 = env.clone();
    let reg2 = registry.clone();
    let mal2 = mallory.clone();
    let tdk2 = verify_trust::build_resolver(false).await.unwrap();
    let server = tokio::spawn(async move {
        loop {
            let Ok(Some((message, _))) = env2
                .atm
                .message_pickup()
                .live_stream_next(&reg2.profile, Some(Duration::from_millis(500)), true)
                .await
            else {
                continue;
            };
            if message.typ != DIDCOMM_ENVELOPE {
                continue;
            }
            let sender = message.from.clone().unwrap();
            let mut reply = answer(&message.body, true, &reg2.did);
            reply["payload"]["authorized"] = json!(true);
            let id = uuid::Uuid::new_v4().to_string();
            let msg = Message::build(id.clone(), DIDCOMM_ENVELOPE.to_string(), reply)
                .from(reg2.did.clone())
                .to(sender.clone())
                .thid(message.body["id"].as_str().unwrap().to_string())
                .finalize();
            let (rkid, rpub) = ka(&tdk2, &sender).await;
            let plaintext = serde_json::to_vec(&msg).unwrap();
            let forged = forge_jwe(
                &plaintext,
                &mallory_kid,
                &registry_kid,
                &mpriv,
                &rkid,
                &rpub,
            );
            let r = env2
                .atm
                .forward_and_send_message(
                    &mal2.profile,
                    false,
                    &forged,
                    Some(&id),
                    env2.mediator.did(),
                    &sender,
                    None,
                    None,
                    false,
                )
                .await;
            let _ = r;
        }
    });

    let client = ephemeral(
        &env,
        TransportKind::Didcomm,
        &registry.did,
        Duration::from_secs(10),
    )
    .await;
    let result = client.client().authorization(query()).await;
    client.close().await;
    server.abort();
    assert!(
        matches!(result, Err(TrqlError::Timeout { .. })),
        "a forged reply must not answer the query: {result:?}"
    );
}
