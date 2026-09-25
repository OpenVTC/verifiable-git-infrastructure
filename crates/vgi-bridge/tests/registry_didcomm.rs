//! The bridge-posted check's registry query over DIDComm, end to end: the
//! bridge's real `DidcommLink` on an in-process mediator, as the bridge's own
//! DID, against a fake registry on the same mediator. What is under test is
//! that an honest answer arrives through `RegistryReplies::route`, and that a
//! reply sealed with another DID's key but naming the registry's key in its
//! party info never does — the messaging SDK refuses it before it reaches the
//! bridge (the fix this path depends on), and the query times out.

#![cfg(feature = "forge-github")]
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use affinidi_messaging_test_mediator::{
    AccessListModeType, MediatorACLSet, TestEnvironment, TestMediator, TestUser,
};
use affinidi_tdk::affinidi_crypto::jose::{aes_kw, content_encryption, ecdh, key_agreement::*};
use affinidi_tdk::did_common::document::DocumentExt;
use futures_util::StreamExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
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

/// The fake registry: answers each query to `registry` — honestly, or with
/// an envelope Mallory seals with her own key while naming the registry's
/// key as the party the key agreement is for.
fn serve(
    env: Arc<TestEnvironment>,
    registry: TestUser,
    mallory: TestUser,
    forged: bool,
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
            let id = uuid::Uuid::new_v4().to_string();
            let msg = Message::build(id.clone(), DIDCOMM_ENVELOPE.to_string(), reply)
                .from(registry.did.clone())
                .to(sender.clone())
                .thid(message.body["id"].as_str().unwrap().to_string())
                .finalize();
            let (packed, via) = if forged {
                let (rkid, rpub) = ka(&tdk, &sender).await;
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
                    .pack_encrypted(&msg, &sender, Some(&registry.did), Some(&registry.did))
                    .await
                    .unwrap();
                (p, &registry)
            };
            let _ = env
                .atm
                .forward_and_send_message(
                    &via.profile,
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

async fn run(forged: bool) -> Result<bool, TrqlError> {
    let env = open_mediator().await;
    let registry = env.add_user("Registry").await.unwrap();
    let mallory = env.add_user("Mallory").await.unwrap();
    for u in [&registry, &mallory] {
        env.atm.profile_enable_websocket(&u.profile).await.unwrap();
    }
    let server = serve(env.clone(), registry.clone(), mallory, forged);

    // The bridge: a did:peer routed through this mediator, on its real link.
    let (identity, _) = BridgeIdentity::generate_did_peer(env.mediator.did()).unwrap();
    let (link, mut inbound) = DidcommLink::connect(&identity, env.mediator.did())
        .await
        .unwrap();
    let link = Arc::new(link);
    let replies = Arc::new(RegistryReplies::new(registry.did.clone()));
    // The bridge's inbound loop, reduced to the registry-reply hook.
    let pump = {
        let replies = Arc::clone(&replies);
        tokio::spawn(async move {
            while let Some(doc) = inbound.next().await {
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
    result
}

#[tokio::test]
async fn the_bridge_queries_the_registry_over_didcomm_as_its_own_did() {
    assert!(run(false).await.unwrap(), "the honest answer is authorized");
}

#[tokio::test]
async fn a_reply_whose_key_agreement_names_another_key_never_reaches_the_bridge() {
    let result = run(true).await;
    assert!(
        matches!(result, Err(TrqlError::Timeout { .. })),
        "a forged reply must not answer the bridge's query: {result:?}"
    );
}
