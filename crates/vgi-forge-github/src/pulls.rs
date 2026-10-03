//! The pull-request gate on GitHub (`git-ns/bridge/job` 0.5
//! `closePullRequest`): read a pull request, find the bridge's own comment,
//! comment, close.
//!
//! Every token is minted for the one repository and dropped on return.
//! Reading needs `pull_requests: read`, which the App has held since the
//! bridge-posted check; commenting on a pull request and closing it need
//! `pull_requests: write` (GitHub files a pull request's conversation
//! comments under Issues *or* Pull requests, and closing one under Pull
//! requests only, so `pull_requests: write` is the one permission that
//! covers both). An installation that has not approved it gets a token
//! refused for that permission, reported as [`ForgeError::Forbidden`] — the
//! job's `forbidden` — and the namespace's `missingPermissions` lists it.
//!
//! The bridge's own account is the App's bot user: a comment or reopen
//! counts as its own when GitHub says the App performed it
//! (`performed_via_github_app.id`) or when it is by `<slug>[bot]`, a login
//! no person can register.

use reqwest::Method;
use serde::Deserialize;
use serde_json::json;
use vgi_forge::{
    ForgeAccount, ForgeError, PullRequest, PullRequestState, Reopen, Resource, Result,
};

use crate::api::Auth;
use crate::forge::GitHubForge;

/// Reading a pull request, its events and its comments.
const PERMS_PULL_READ: &[(&str, &str)] = &[("metadata", "read"), ("pull_requests", "read")];
/// Commenting on and closing a pull request.
const PERMS_PULL_WRITE: &[(&str, &str)] = &[("metadata", "read"), ("pull_requests", "write")];

#[derive(Deserialize)]
struct PullJson {
    state: String,
    #[serde(default)]
    merged: Option<bool>,
    #[serde(default)]
    merged_at: Option<String>,
}

#[derive(Deserialize)]
struct UserJson {
    id: u64,
    login: String,
}

#[derive(Deserialize)]
struct AppRef {
    id: u64,
}

#[derive(Deserialize)]
struct IssueEventJson {
    event: String,
    #[serde(default)]
    actor: Option<UserJson>,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    performed_via_github_app: Option<AppRef>,
}

#[derive(Deserialize)]
struct CommentJson {
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    user: Option<UserJson>,
    #[serde(default)]
    performed_via_github_app: Option<AppRef>,
}

/// RFC 3339 (`2026-10-07T15:12:02Z`) → Unix seconds.
fn unix_seconds(s: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| t.timestamp())
}

impl GitHubForge {
    /// Whether `user` / `app` is this App's own bot.
    fn is_own(&self, user: Option<&UserJson>, app: Option<&AppRef>) -> bool {
        if app.is_some_and(|a| a.id == self.config().app_id) {
            return true;
        }
        let own_bot = format!("{}[bot]", self.config().app_slug);
        user.is_some_and(|u| u.login.eq_ignore_ascii_case(&own_bot))
    }

    fn not_found(repo: &Resource, number: u64) -> ForgeError {
        ForgeError::NotFound {
            what: format!("pull request #{number} in {repo}"),
        }
    }

    /// See [`vgi_forge::Forge::pull_request`].
    pub(crate) async fn read_pull_request(
        &self,
        repo: &Resource,
        number: u64,
    ) -> Result<PullRequest> {
        let (token, owner, name) = self.repo_token_for(repo, PERMS_PULL_READ).await?;
        let n = number.to_string();
        let pr: PullJson = self
            .api()
            .json(
                Method::GET,
                self.api().url(&["repos", &owner, &name, "pulls", &n]),
                Auth::Bearer(&token),
                None,
                "pull request",
            )
            .await
            .map_err(|e| match e {
                ForgeError::NotFound { .. } => Self::not_found(repo, number),
                e => e,
            })?;
        let merged = pr.merged == Some(true) || pr.merged_at.is_some();
        let state = match (pr.state.as_str(), merged) {
            (_, true) => PullRequestState::Merged,
            ("open", false) => PullRequestState::Open,
            _ => PullRequestState::Closed,
        };
        let mut out = PullRequest::new(state);
        if state != PullRequestState::Open {
            // A closed pull request is left alone whoever reopened it before.
            return Ok(out);
        }
        // Who reopened it, from GitHub's own record of the action — the
        // most recent reopen by anyone but this App.
        let events: Vec<IssueEventJson> = self
            .api()
            .get_all(
                self.api()
                    .url(&["repos", &owner, &name, "issues", &n, "events"]),
                Auth::Bearer(&token),
                "pull request events",
            )
            .await?;
        let last = events
            .iter()
            .filter(|e| e.event == "reopened")
            .filter(|e| !self.is_own(e.actor.as_ref(), e.performed_via_github_app.as_ref()))
            .filter_map(|e| {
                let at = unix_seconds(e.created_at.as_deref()?)?;
                let by = e.actor.as_ref().map_or_else(
                    || ForgeAccount::new(0, "ghost"),
                    |a| ForgeAccount::new(a.id, a.login.clone()),
                );
                Some(Reopen::new(by, at))
            })
            .max_by_key(|r| r.at);
        if let Some(r) = last {
            out = out.with_reopen(r);
        }
        Ok(out)
    }

    /// See [`vgi_forge::Forge::has_own_comment`].
    pub(crate) async fn find_own_comment(
        &self,
        repo: &Resource,
        number: u64,
        marker: &str,
    ) -> Result<bool> {
        let (token, owner, name) = self.repo_token_for(repo, PERMS_PULL_READ).await?;
        let n = number.to_string();
        let comments: Vec<CommentJson> = self
            .api()
            .get_all(
                self.api()
                    .url(&["repos", &owner, &name, "issues", &n, "comments"]),
                Auth::Bearer(&token),
                "pull request comments",
            )
            .await
            .map_err(|e| match e {
                ForgeError::NotFound { .. } => Self::not_found(repo, number),
                e => e,
            })?;
        Ok(comments.iter().any(|c| {
            self.is_own(c.user.as_ref(), c.performed_via_github_app.as_ref())
                && c.body.as_deref().is_some_and(|b| b.contains(marker))
        }))
    }

    /// See [`vgi_forge::Forge::comment_on_pull_request`].
    pub(crate) async fn post_pull_request_comment(
        &self,
        repo: &Resource,
        number: u64,
        body: &str,
    ) -> Result<()> {
        let (token, owner, name) = self.repo_token_for(repo, PERMS_PULL_WRITE).await?;
        let n = number.to_string();
        self.api()
            .send(
                Method::POST,
                self.api()
                    .url(&["repos", &owner, &name, "issues", &n, "comments"]),
                Auth::Bearer(&token),
                Some(&json!({ "body": body })),
                "pull request comment",
            )
            .await
            .map_err(|e| match e {
                ForgeError::NotFound { .. } => Self::not_found(repo, number),
                e => e,
            })?;
        Ok(())
    }

    /// See [`vgi_forge::Forge::close_pull_request`].
    pub(crate) async fn patch_pull_request_closed(
        &self,
        repo: &Resource,
        number: u64,
    ) -> Result<()> {
        let (token, owner, name) = self.repo_token_for(repo, PERMS_PULL_WRITE).await?;
        let n = number.to_string();
        self.api()
            .send(
                Method::PATCH,
                self.api().url(&["repos", &owner, &name, "pulls", &n]),
                Auth::Bearer(&token),
                Some(&json!({ "state": "closed" })),
                "close pull request",
            )
            .await
            .map_err(|e| match e {
                ForgeError::NotFound { .. } => Self::not_found(repo, number),
                e => e,
            })?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_timestamps_parse() {
        assert_eq!(unix_seconds("1970-01-01T00:01:00Z"), Some(60));
        assert_eq!(unix_seconds("not a time"), None);
    }
}
