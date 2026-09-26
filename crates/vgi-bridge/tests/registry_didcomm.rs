//! The bridge-posted check's registry query over DIDComm, end to end: the
//! bridge's real `DidcommLink` on an in-process mediator, as the bridge's own
//! DID, against a fake registry on the same mediator. What is under test is
//! that an honest answer arrives through `RegistryReplies::route`, and that a
//! reply sealed with another DID's key but naming the registry's key in its
//! party info never does — the messaging SDK refuses it before it reaches the
//! bridge (the fix this path depends on), and the query times out.

#![cfg(feature = "forge-github")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use affinidi_messaging_test_mediator::{
    AccessListModeType, MediatorACLSet, TestEnvironment, TestMediator, TestUser,
};
use affinidi_tdk::affinidi_crypto::jose::{aes_kw, content_encryption, ecdh, key_agreement::*};
use affinidi_tdk::did_common::document::DocumentExt;
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::mpsc;
use trql_client::{TrqlError, TrqpQuery};
use vgi_bridge::BridgeIdentity;
use vgi_bridge::registry_channel::{BridgeRegistryChannel, RegistryReplies};
use vgi_bridge::transport::DidcommLink;

const DIDCOMM_ENVELOPE: &str = "https://trusttasks.org/binding/didcomm/0.1/envelope";

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

/// What the fake registry got onto the mediator.
#[derive(Debug, PartialEq)]
enum Delivered {
    Honest,
    Forged,
    /// An uncorrelated registry message sent right after a forged reply: its
    /// arrival proves the bridge's stream was live past the forged one.
    Canary,
}

const CANARY_THREAD: &str = "urn:uuid:canary";

/// The fake registry: answers each query to `registry` — honestly, or with
/// an envelope Mallory seals with her own key while naming the registry's
/// key as the party the key agreement is for, followed by an honest canary.
/// Each message the mediator accepted is reported on `delivered`.
fn serve(
    env: Arc<TestEnvironment>,
    registry: TestUser,
    mallory: TestUser,
    forged: bool,
    delivered: mpsc::UnboundedSender<Delivered>,
) -> tokio::task::JoinHandle<()> {
    use affinidi_tdk::didcomm::Message;
    tokio::spawn(async move {
        let tdk = verify_trust::build_resolver(false).await.unwrap();
        let (registry_kid, _) = ka(&tdk, &registry.did).await;
        let (mallory_kid, _) = ka(&tdk, &mallory.did).await;
        let msecret = mallory
            .secrets
            .iter()
            .find(|s| s.id == mallory_kid)
            .unwrap()
            .clone();
        let mpriv = PrivateKeyAgreement::from_raw_bytes(Curve::X25519, msecret.get_private_bytes())
            .unwrap();
        // Seal `body` honestly as the registry, or forged by Mallory, and
        // forward it to `to` through the mediator.
        let send = async |body: Value, thid: String, to: &str, forge: bool| {
            let id = uuid::Uuid::new_v4().to_string();
            let msg = Message::build(id.clone(), DIDCOMM_ENVELOPE.to_string(), body)
                .from(registry.did.clone())
                .to(to.to_string())
                .thid(thid)
                .finalize();
            let (packed, via) = if forge {
                let (rkid, rpub) = ka(&tdk, to).await;
                let plaintext = serde_json::to_vec(&msg).unwrap();
                (
                    forge_jwe(
                        &plaintext,
                        &mallory_kid,
                        &registry_kid,
                        &mpriv,
                        &rkid,
                        &rpub,
                    ),
                    &mallory,
                )
            } else {
                let (p, _) = env
                    .atm
                    .pack_encrypted(&msg, to, Some(&registry.did), Some(&registry.did))
                    .await
                    .unwrap();
                (p, &registry)
            };
            env.atm
                .forward_and_send_message(
                    &via.profile,
                    false,
                    &packed,
                    Some(&id),
                    env.mediator.did(),
                    to,
                    None,
                    None,
                    false,
                )
                .await
                .map(|_| ())
        };
        loop {
            let Ok(Some((message, _))) = env
                .atm
                .message_pickup()
                .live_stream_next(&registry.profile, Some(Duration::from_millis(500)), true)
                .await
            else {
                continue;
            };
            if message.typ != DIDCOMM_ENVELOPE {
                continue;
            }
            let sender = message.from.clone().unwrap();
            let reply = answer(&message.body, &registry.did);
            let thid = message.body["id"].as_str().unwrap().to_string();
            send(reply, thid, &sender, forged)
                .await
                .expect("the mediator accepts the reply");
            let _ = delivered.send(if forged {
                Delivered::Forged
            } else {
                Delivered::Honest
            });
            if forged {
                let canary = json!({
                    "id": format!("urn:uuid:{}", uuid::Uuid::new_v4()),
                    "threadId": CANARY_THREAD,
                    "issuer": registry.did,
                });
                send(canary, CANARY_THREAD.to_string(), &sender, false)
                    .await
                    .expect("the mediator accepts the canary");
                let _ = delivered.send(Delivered::Canary);
            }
        }
    })
}

/// One query's outcome, what the fake registry delivered, and every
/// document the bridge's link surfaced (with its authenticated sender).
struct Run {
    result: Result<bool, TrqlError>,
    delivered: Vec<Delivered>,
    surfaced: Vec<(Value, Option<String>)>,
    registry_did: String,
}

async fn run(forged: bool) -> Run {
    let env = open_mediator().await;
    let registry = env.add_user("Registry").await.unwrap();
    let mallory = env.add_user("Mallory").await.unwrap();
    for u in [&registry, &mallory] {
        env.atm.profile_enable_websocket(&u.profile).await.unwrap();
    }
    let (delivered_tx, mut delivered_rx) = mpsc::unbounded_channel();
    let server = serve(env.clone(), registry.clone(), mallory, forged, delivered_tx);

    // The bridge: a did:peer routed through this mediator, on its real link.
    let (identity, _) = BridgeIdentity::generate_did_peer(env.mediator.did()).unwrap();
    let (link, mut inbound) = DidcommLink::connect(&identity, env.mediator.did())
        .await
        .unwrap();
    let link = Arc::new(link);
    let replies = Arc::new(RegistryReplies::new(registry.did.clone()));
    let surfaced = Arc::new(Mutex::new(Vec::new()));
    // The bridge's inbound loop, reduced to the registry-reply hook, noting
    // everything the link surfaces.
    let pump = {
        let replies = Arc::clone(&replies);
        let surfaced = Arc::clone(&surfaced);
        tokio::spawn(async move {
            while let Some(doc) = inbound.next().await {
                surfaced
                    .lock()
                    .unwrap()
                    .push((doc.doc.clone(), doc.authenticated_sender.clone()));
                let _ = replies.route(&doc);
            }
        })
    };
    let channel = BridgeRegistryChannel::new(link.clone(), identity.did(), replies)
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
    }
}

#[tokio::test]
async fn the_bridge_queries_the_registry_over_didcomm_as_its_own_did() {
    let run = run(false).await;
    assert!(run.result.unwrap(), "the honest answer is authorized");
    assert_eq!(run.delivered, [Delivered::Honest]);
}

#[tokio::test]
async fn a_reply_whose_key_agreement_names_another_key_never_reaches_the_bridge() {
    let run = run(true).await;
    assert!(
        matches!(run.result, Err(TrqlError::Timeout { .. })),
        "a forged reply must not answer the bridge's query: {:?}",
        run.result
    );
    // Not vacuous: the forged reply was on the mediator, and the honest
    // canary sent after it came out of the bridge's link authenticated as
    // the registry — so the link was live past the forged envelope, and the
    // messaging SDK refused that one rather than never seeing it.
    assert_eq!(run.delivered, [Delivered::Forged, Delivered::Canary]);
    let canary = run
        .surfaced
        .iter()
        .find(|(doc, _)| doc["threadId"] == CANARY_THREAD)
        .expect("the canary sent after the forged reply reached the bridge");
    assert_eq!(
        canary.1.as_deref().map(|s| s.split('#').next().unwrap()),
        Some(run.registry_did.as_str())
    );
    assert!(
        run.surfaced
            .iter()
            .all(|(doc, _)| doc["threadId"] == CANARY_THREAD),
        "the forged reply must not surface from the link at all: {:?}",
        run.surfaced
    );
}
