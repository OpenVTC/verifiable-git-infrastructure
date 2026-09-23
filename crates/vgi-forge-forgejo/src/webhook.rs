//! Webhook verification and translation (§5.6).
//!
//! Forgejo signs the raw body with HMAC-SHA256 under the hook's secret and
//! sends the tag as bare hex in `X-Forgejo-Signature` (and, for Gitea
//! compatibility, the same tag in `X-Gitea-Signature`). The tag is checked
//! in constant time over the exact bytes received, before a byte is parsed.
//! When `X-Forgejo-Signature` is present it is the one checked — a bad one
//! is not rescued by a good `X-Gitea-Signature`.
//!
//! The org webhook subscribes to `repository` only (created, deleted): that
//! is the one drift Forgejo announces. It sends no event for collaborator,
//! branch-protection, rename or archive changes, so those are found by the
//! scheduled `inspect` sweep — which is why the adapter reports
//! `webhooks: false`.
//!
//! As on GitHub, the signature covers no timestamp: a captured delivery
//! replays. [`ForgeEvent::delivery_id`] carries `X-Forgejo-Delivery` for the
//! core to drop repeats, and every event is a prompt to `inspect`.

use aws_lc_rs::hmac;
use http::HeaderMap;
use serde_json::Value;
use vgi_forge::{ForgeError, ForgeEvent, ForgeEventKind, Resource, Result};

use crate::secret::Secret;

/// The events the org webhook subscribes to.
pub const HOOK_EVENTS: [&str; 1] = ["repository"];

/// Verify `X-Forgejo-Signature` (or, failing that header, `X-Gitea-Signature`)
/// over `body`.
pub fn verify_signature(secret: &Secret, headers: &HeaderMap, body: &[u8]) -> Result<()> {
    let (name, value) = ["x-forgejo-signature", "x-gitea-signature"]
        .into_iter()
        .find_map(|n| headers.get(n).map(|v| (n, v)))
        .ok_or_else(|| {
            ForgeError::Webhook("missing X-Forgejo-Signature (or X-Gitea-Signature)".into())
        })?;
    let text = value
        .to_str()
        .map_err(|_| ForgeError::Webhook(format!("{name} is not ASCII")))?;
    let tag =
        hex::decode(text.trim()).map_err(|_| ForgeError::Webhook(format!("{name} is not hex")))?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());
    // `hmac::verify` recomputes the tag and compares in constant time.
    hmac::verify(&key, body, &tag)
        .map_err(|_| ForgeError::Webhook("signature does not match the body".into()))
}

/// The signature header value Forgejo would send. For tests and for
/// replaying captured deliveries against a local bridge.
pub fn sign_body(secret: &Secret, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());
    hex::encode(hmac::sign(&key, body).as_ref())
}

/// Verify, then translate. `host` is the forge host resources are built on.
pub fn parse(
    secret: &Secret,
    host: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<ForgeEvent>> {
    verify_signature(secret, headers, body)?;

    let event = header_str(headers, "x-forgejo-event")?
        .or(header_str(headers, "x-gitea-event")?)
        .ok_or_else(|| ForgeError::Webhook("missing X-Forgejo-Event".into()))?;
    let delivery = header_str(headers, "x-forgejo-delivery")?
        .or(header_str(headers, "x-gitea-delivery")?)
        .map(str::to_string);
    let payload: Value = serde_json::from_slice(body)
        .map_err(|e| ForgeError::Webhook(format!("body is not JSON: {e}")))?;
    let action = payload.get("action").and_then(Value::as_str).unwrap_or("");

    let kind = match (event, action) {
        ("repository", "created") => {
            let (repo, forge_id) = repository(host, &payload)?;
            Some(ForgeEventKind::RepoCreated { repo, forge_id })
        }
        ("repository", "deleted") => {
            let (repo, forge_id) = repository(host, &payload)?;
            Some(ForgeEventKind::RepoDeleted { repo, forge_id })
        }
        _ => None,
    };
    Ok(kind.map(|k| ForgeEvent::new(delivery, k)))
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> Result<Option<&'a str>> {
    headers
        .get(name)
        .map(|v| {
            v.to_str()
                .map_err(|_| ForgeError::Webhook(format!("{name} is not ASCII")))
        })
        .transpose()
}

fn repository(host: &str, payload: &Value) -> Result<(Resource, u64)> {
    let repo = &payload["repository"];
    let full_name = repo
        .get("full_name")
        .and_then(Value::as_str)
        .ok_or_else(|| ForgeError::Webhook("payload is missing `repository.full_name`".into()))?;
    let resource = Resource::parse_owner_repo(&format!("{host}/{full_name}"))?;
    resource
        .require_owner_repo()
        .map_err(|_| ForgeError::Webhook(format!("`{full_name}` is not an owner/repo name")))?;
    let id = repo
        .get("id")
        .and_then(Value::as_u64)
        .ok_or_else(|| ForgeError::Webhook("payload is missing numeric `repository.id`".into()))?;
    Ok((resource, id))
}
