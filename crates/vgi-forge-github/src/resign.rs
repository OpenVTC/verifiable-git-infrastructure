//! The GitHub half of the Dependabot re-sign (§9, "Dependabot re-sign bot").
//!
//! verify-trust exempts a `web-flow`-signed commit only when it is a clean
//! merge, so Dependabot's single-parent commits fail the check: nothing in
//! a commit binds it to Dependabot (any writer can have GitHub write and
//! sign a commit with any `author` through the Contents API). The bridge
//! re-signs them with its own DID instead — but only on **provenance from
//! signed `push` webhooks**, never on authorship: every push to the branch
//! since its creation must have come from Dependabot, or be the bridge's own
//! re-sign.
//!
//! This module is what the bridge needs from GitHub for that:
//!
//! - [`GitHubForge::parse_push`]: verify a delivery (signature first) and,
//!   if it is a `push`, the fields the provenance ledger records — who
//!   pushed (login and numeric id), the branch, `before` / `after`, and the
//!   `created` / `deleted` / `forced` flags. The sender is GitHub's
//!   statement of the authenticated actor; nothing in the pushed commits is
//!   read.
//! - [`GitHubForge::contents_write_token`]: a token that can push to one
//!   repository, for the one force-push of the re-signed commits.
//!
//! Who opened the pull request, and where its head is, come from
//! [`GitHubForge::pull_request`].

use http::HeaderMap;
use serde_json::Value;
use vgi_forge::{ForgeError, Resource, Result};

use crate::forge::GitHubForge;
use crate::secret::Secret;
use crate::webhook;

/// Pushing the re-signed commits: Contents (write) on the one repository.
const PERMS_PUSH: &[(&str, &str)] = &[("contents", "write"), ("metadata", "read")];

/// The all-zero object id GitHub reports as `before` for a created branch
/// and as `after` for a deleted one.
pub const ZERO_SHA: &str = "0000000000000000000000000000000000000000";

/// One verified `push` delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PushEvent {
    /// The repository pushed to.
    pub repo: Resource,
    /// Its forge id.
    pub repo_id: u64,
    /// The full ref (`refs/heads/dependabot/cargo/foo-1.2.3`).
    pub git_ref: String,
    /// The ref's value before the push ([`ZERO_SHA`] when it was created).
    pub before: String,
    /// Its value after ([`ZERO_SHA`] when it was deleted).
    pub after: String,
    /// The push created the ref.
    pub created: bool,
    /// The push deleted the ref.
    pub deleted: bool,
    /// The push was not a fast-forward.
    pub forced: bool,
    /// The login of the account GitHub says pushed.
    pub sender_login: String,
    /// That account's numeric id.
    pub sender_id: u64,
    /// GitHub's delivery id.
    pub delivery_id: Option<String>,
}

impl PushEvent {
    /// The branch, if the ref is one (`refs/heads/<branch>`).
    pub fn branch(&self) -> Option<&str> {
        self.git_ref.strip_prefix("refs/heads/")
    }
}

/// A 40- or 64-hex object id, or the all-zero id.
fn object_id(v: &Value, key: &str) -> Result<String> {
    let s = v
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| ForgeError::Webhook(format!("push is missing `{key}`")))?;
    crate::checks::check_sha(s)
        .map_err(|_| ForgeError::Webhook(format!("push `{key}` is not an object id")))?;
    Ok(s.to_string())
}

impl GitHubForge {
    /// Verify a webhook and, if it is a `push`, read it. `Ok(None)` for a
    /// verified delivery of any other event; `Err` for one that failed
    /// verification or is malformed, which must not be acted on.
    pub fn parse_push(&self, headers: &HeaderMap, body: &[u8]) -> Result<Option<PushEvent>> {
        webhook::verify_signature(self.webhook_secret(), headers, body)?;
        let event = headers
            .get("x-github-event")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ForgeError::Webhook("missing X-GitHub-Event".into()))?;
        if event != "push" {
            return Ok(None);
        }
        let delivery_id = headers
            .get("x-github-delivery")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        let p: Value = serde_json::from_slice(body)
            .map_err(|e| ForgeError::Webhook(format!("body is not JSON: {e}")))?;
        let full_name = p
            .pointer("/repository/full_name")
            .and_then(Value::as_str)
            .ok_or_else(|| ForgeError::Webhook("push is missing `repository.full_name`".into()))?;
        let repo = Resource::parse_owner_repo(&format!("{}/{full_name}", self.config().host))?;
        let repo_id = p
            .pointer("/repository/id")
            .and_then(Value::as_u64)
            .ok_or_else(|| ForgeError::Webhook("push is missing `repository.id`".into()))?;
        let git_ref = p
            .get("ref")
            .and_then(Value::as_str)
            .filter(|r| !r.is_empty())
            .ok_or_else(|| ForgeError::Webhook("push is missing `ref`".into()))?
            .to_string();
        let flag = |k: &str| p.get(k).and_then(Value::as_bool).unwrap_or(false);
        let sender_login = p
            .pointer("/sender/login")
            .and_then(Value::as_str)
            .filter(|l| !l.is_empty())
            .ok_or_else(|| ForgeError::Webhook("push is missing `sender.login`".into()))?
            .to_string();
        let sender_id = p
            .pointer("/sender/id")
            .and_then(Value::as_u64)
            .ok_or_else(|| ForgeError::Webhook("push is missing `sender.id`".into()))?;
        Ok(Some(PushEvent {
            repo,
            repo_id,
            git_ref,
            before: object_id(&p, "before")?,
            after: object_id(&p, "after")?,
            created: flag("created"),
            deleted: flag("deleted"),
            forced: flag("forced"),
            sender_login,
            sender_id,
            delivery_id,
        }))
    }

    /// A token that can push to `repo` and nothing else, for one push of
    /// re-signed commits. The caller holds it for that push only.
    pub async fn contents_write_token(&self, repo: &Resource) -> Result<Secret> {
        Ok(self.repo_token_for(repo, PERMS_PUSH).await?.0)
    }
}
