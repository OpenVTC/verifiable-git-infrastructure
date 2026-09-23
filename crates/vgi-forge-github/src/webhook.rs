//! Webhook verification and translation (§5.6).
//!
//! Every delivery is authenticated before a byte of it is parsed: GitHub
//! signs the raw body with HMAC-SHA256 under the App's webhook secret and
//! sends the tag in `X-Hub-Signature-256`. The tag is checked in constant
//! time, over the exact bytes received — never over re-serialised JSON.
//!
//! What this cannot check is freshness: the signature covers no timestamp,
//! so a captured delivery replays cleanly. [`ForgeEvent::delivery_id`] is
//! carried through so the core can drop repeats, and every event here is a
//! prompt to `inspect`, not a statement of state to apply — a replayed
//! "ruleset edited" costs one read.

use aws_lc_rs::hmac;
use http::HeaderMap;
use serde_json::Value;
use vgi_forge::{
    ForgeAccount, ForgeError, ForgeEvent, ForgeEventKind, InstallationChange, MemberChange,
    Resource, Result, Visibility,
};

use crate::secret::Secret;

/// Verify `X-Hub-Signature-256` over `body`.
pub fn verify_signature(secret: &Secret, headers: &HeaderMap, body: &[u8]) -> Result<()> {
    let header = headers
        .get("x-hub-signature-256")
        .ok_or_else(|| ForgeError::Webhook("missing X-Hub-Signature-256".into()))?
        .to_str()
        .map_err(|_| ForgeError::Webhook("X-Hub-Signature-256 is not ASCII".into()))?;
    let hex_tag = header
        .strip_prefix("sha256=")
        .ok_or_else(|| ForgeError::Webhook("X-Hub-Signature-256 is not `sha256=<hex>`".into()))?;
    let tag = hex::decode(hex_tag)
        .map_err(|_| ForgeError::Webhook("X-Hub-Signature-256 is not hex".into()))?;
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());
    // `hmac::verify` recomputes the tag and compares in constant time.
    hmac::verify(&key, body, &tag)
        .map_err(|_| ForgeError::Webhook("signature does not match the body".into()))
}

/// Compute the `X-Hub-Signature-256` value GitHub would send. For tests and
/// for replaying captured deliveries against a local bridge.
pub fn sign_body(secret: &Secret, body: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.expose().as_bytes());
    format!("sha256={}", hex::encode(hmac::sign(&key, body).as_ref()))
}

/// Verify, then translate. `host` is the forge host resources are built on.
pub fn parse(
    secret: &Secret,
    host: &str,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<Option<ForgeEvent>> {
    verify_signature(secret, headers, body)?;

    let event = header_str(headers, "x-github-event")?
        .ok_or_else(|| ForgeError::Webhook("missing X-GitHub-Event".into()))?;
    let delivery = header_str(headers, "x-github-delivery")?.map(str::to_string);
    let payload: Value = serde_json::from_slice(body)
        .map_err(|e| ForgeError::Webhook(format!("body is not JSON: {e}")))?;
    let action = payload.get("action").and_then(Value::as_str).unwrap_or("");

    let kind = match event {
        "repository" => repository_event(host, action, &payload)?,
        "member" => {
            let change = match action {
                "added" => MemberChange::Added,
                "removed" => MemberChange::Removed,
                "edited" => MemberChange::Edited,
                _ => return Ok(None),
            };
            let (repo, forge_id) = repository(host, &payload)?;
            Some(ForgeEventKind::CollaboratorChanged {
                repo,
                forge_id,
                account: account(&payload["member"])?,
                change,
            })
        }
        // `membership` is *team* membership; `organization` carries joining
        // and leaving the org itself.
        "membership" => {
            let change = match action {
                "added" => MemberChange::Added,
                "removed" => MemberChange::Removed,
                _ => return Ok(None),
            };
            Some(ForgeEventKind::TeamMembershipChanged {
                namespace: namespace(host, &payload["organization"])?,
                team: str_at(payload.get("team").unwrap_or(&Value::Null), &["slug"])?.to_string(),
                account: account(&payload["member"])?,
                change,
            })
        }
        "organization" => {
            let change = match action {
                "member_added" => MemberChange::Added,
                "member_removed" => MemberChange::Removed,
                _ => return Ok(None),
            };
            Some(ForgeEventKind::OrgMembershipChanged {
                namespace: namespace(host, &payload["organization"])?,
                account: account(&payload["membership"]["user"])?,
                change,
            })
        }
        "repository_ruleset" | "branch_protection_rule" => {
            let repo = match payload.get("repository") {
                Some(r) if !r.is_null() => Some(repository(host, &payload)?.0),
                _ => None,
            };
            let namespace = match &repo {
                Some(r) => r.namespace(),
                None => namespace(host, &payload["organization"])?,
            };
            Some(ForgeEventKind::ProtectionChanged {
                repo,
                namespace,
                action: action.to_string(),
            })
        }
        "installation" => {
            let change = match action {
                "created" => InstallationChange::Created,
                "deleted" => InstallationChange::Deleted,
                "suspend" => InstallationChange::Suspended,
                "unsuspend" => InstallationChange::Unsuspended,
                "new_permissions_accepted" => InstallationChange::PermissionsAccepted,
                _ => return Ok(None),
            };
            let installation = &payload["installation"];
            Some(ForgeEventKind::InstallationChanged {
                namespace: namespace(host, &installation["account"])?,
                installation_id: u64_field(installation, "id")?,
                change,
            })
        }
        _ => None,
    };
    Ok(kind.map(|k| ForgeEvent::new(delivery, k)))
}

fn repository_event(host: &str, action: &str, payload: &Value) -> Result<Option<ForgeEventKind>> {
    let (repo, forge_id) = repository(host, payload)?;
    Ok(Some(match action {
        "created" => ForgeEventKind::RepoCreated { repo, forge_id },
        "deleted" => ForgeEventKind::RepoDeleted { repo, forge_id },
        "archived" | "unarchived" => ForgeEventKind::RepoArchived {
            repo,
            forge_id,
            archived: action == "archived",
        },
        "publicized" | "privatized" => ForgeEventKind::RepoVisibilityChanged {
            repo,
            forge_id,
            visibility: if action == "publicized" {
                Visibility::Public
            } else {
                Visibility::Private
            },
        },
        "renamed" => {
            let old = str_at(payload, &["changes", "repository", "name", "from"])?;
            let from = repo.namespace().join(old)?;
            ForgeEventKind::RepoRenamed {
                forge_id,
                from,
                to: repo,
            }
        }
        "transferred" => {
            let owner = &payload["changes"]["owner"]["from"];
            let from_account = if owner["organization"].is_object() {
                &owner["organization"]
            } else {
                &owner["user"]
            };
            ForgeEventKind::RepoTransferred {
                forge_id,
                from_namespace: namespace(host, from_account).ok(),
                to: repo,
            }
        }
        _ => return Ok(None),
    }))
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
    let full_name = str_at(repo, &["full_name"])?;
    let resource = Resource::parse_owner_repo(&format!("{host}/{full_name}"))?;
    Ok((resource, u64_field(repo, "id")?))
}

fn namespace(host: &str, account: &Value) -> Result<Resource> {
    Resource::namespace_of(host, str_at(account, &["login"])?)
}

fn account(v: &Value) -> Result<ForgeAccount> {
    Ok(ForgeAccount::new(
        u64_field(v, "id")?,
        str_at(v, &["login"])?,
    ))
}

fn u64_field(v: &Value, key: &str) -> Result<u64> {
    v.get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| ForgeError::Webhook(format!("payload is missing numeric `{key}`")))
}

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Result<&'a str> {
    path.iter()
        .try_fold(v, |v, k| v.get(k))
        .and_then(Value::as_str)
        .ok_or_else(|| ForgeError::Webhook(format!("payload is missing `{}`", path.join("."))))
}
