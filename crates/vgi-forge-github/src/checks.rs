//! The check the bridge posts itself (§9, "forged check runs").
//!
//! Where no org required workflow is available, a check pinned to the GitHub
//! Actions App is forgeable: any writer can run a workflow on another branch
//! that posts a passing "Verify commit trust" run onto someone else's pull
//! request. So the bridge runs verify-trust itself and posts the check as
//! the community's App, and the ruleset requires the check from that App
//! ([`crate::GitHubConfig::bridge_checks`]).
//!
//! This module is the GitHub half of that: recognising the deliveries that
//! call for a check ([`GitHubForge::parse_check_trigger`], signature first),
//! listing the commits under test ([`GitHubForge::compare_commits`]), a
//! read-only token for fetching them ([`GitHubForge::contents_read_token`]),
//! and the check run itself ([`GitHubForge::start_check_run`],
//! [`GitHubForge::finish_check_run`]). Running verify-trust is the bridge's.
//!
//! Every token here is minted for the one repository and the one permission
//! the call needs, and dropped on return — except the contents token, which
//! the caller holds for exactly one fetch.

use http::HeaderMap;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use vgi_forge::{ForgeError, Resource, Result};

use crate::api::Auth;
use crate::forge::GitHubForge;
use crate::secret::Secret;
use crate::webhook;

/// Posting and updating check runs.
const PERMS_CHECKS: &[(&str, &str)] = &[("checks", "write"), ("metadata", "read")];
/// Listing and fetching the commits under test. Read-only: the bridge never
/// writes to a repository while checking it.
const PERMS_READ: &[(&str, &str)] = &[("contents", "read"), ("metadata", "read")];

/// GitHub caps a check run's `output.summary` at 65 535 characters.
const MAX_SUMMARY: usize = 65_000;

/// Why a check is due.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckTriggerKind {
    /// A pull request was opened, pushed to, or reopened.
    PullRequest {
        /// Its number.
        number: u64,
        /// Commits GitHub counts on it, when the delivery says.
        commits: Option<u64>,
    },
    /// A merge queue asked for checks on a merge group.
    MergeGroup,
}

/// A verified delivery that calls for the check on `head_sha`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckTrigger {
    /// The repository the check is posted on (the pull request's base).
    pub repo: Resource,
    /// Its forge id.
    pub repo_id: u64,
    /// The commit the check is for.
    pub head_sha: String,
    /// The base it is compared against.
    pub base_sha: String,
    /// Pull request or merge group.
    pub kind: CheckTriggerKind,
    /// GitHub's delivery id, for de-duplication.
    pub delivery_id: Option<String>,
}

/// How a check run ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckConclusion {
    /// Every commit passed.
    Success,
    /// At least one commit did not, or the check could not be completed —
    /// fail closed, the same as verify-trust's exit code.
    Failure,
}

impl CheckConclusion {
    fn as_str(self) -> &'static str {
        match self {
            CheckConclusion::Success => "success",
            CheckConclusion::Failure => "failure",
        }
    }
}

/// The commits between a base and a head, as GitHub lists them.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Comparison {
    /// The commits in `base...head` (reachable from head, not from the merge
    /// base), oldest first. GitHub lists at most 250.
    pub commits: Vec<String>,
    /// How many there are in all. More than `commits.len()` means the list
    /// was truncated and the range cannot be checked from it.
    pub total: u64,
    /// The merge base.
    pub merge_base: String,
}

impl GitHubForge {
    /// Verify a webhook and, if it calls for the bridge-posted check, say on
    /// what. `Ok(None)` for a verified delivery that does not (another event,
    /// a closed pull request). `Err` for one that failed verification, which
    /// must not be acted on.
    ///
    /// Triggers: `pull_request` `opened` / `synchronize` / `reopened`, and
    /// `merge_group` `checks_requested`. The repository is the delivery's
    /// `repository` — the base the check is posted on — never the fork a
    /// pull request came from.
    pub fn parse_check_trigger(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Option<CheckTrigger>> {
        webhook::verify_signature(self.webhook_secret(), headers, body)?;
        let event = headers
            .get("x-github-event")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ForgeError::Webhook("missing X-GitHub-Event".into()))?;
        let delivery_id = headers
            .get("x-github-delivery")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if event != "pull_request" && event != "merge_group" {
            return Ok(None);
        }
        let payload: Value = serde_json::from_slice(body)
            .map_err(|e| ForgeError::Webhook(format!("body is not JSON: {e}")))?;
        let action = payload.get("action").and_then(Value::as_str).unwrap_or("");
        let repo_json = &payload["repository"];
        let full_name = repo_json
            .get("full_name")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ForgeError::Webhook("payload is missing `repository.full_name`".into())
            })?;
        let repo = Resource::parse_owner_repo(&format!("{}/{full_name}", self.config().host))?;
        let repo_id = repo_json
            .get("id")
            .and_then(Value::as_u64)
            .ok_or_else(|| ForgeError::Webhook("payload is missing `repository.id`".into()))?;

        let (head_sha, base_sha, kind) = match (event, action) {
            ("pull_request", "opened" | "synchronize" | "reopened") => {
                let pr = &payload["pull_request"];
                let number = pr
                    .get("number")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| ForgeError::Webhook("pull request has no number".into()))?;
                (
                    sha_at(pr, &["head", "sha"])?,
                    sha_at(pr, &["base", "sha"])?,
                    CheckTriggerKind::PullRequest {
                        number,
                        commits: pr.get("commits").and_then(Value::as_u64),
                    },
                )
            }
            ("merge_group", "checks_requested") => {
                let group = &payload["merge_group"];
                (
                    sha_at(group, &["head_sha"])?,
                    sha_at(group, &["base_sha"])?,
                    CheckTriggerKind::MergeGroup,
                )
            }
            _ => return Ok(None),
        };
        Ok(Some(CheckTrigger {
            repo,
            repo_id,
            head_sha,
            base_sha,
            kind,
            delivery_id,
        }))
    }

    /// The commits in `base...head` on `repo`, oldest first
    /// (`GET /repos/{o}/{r}/compare/{base}...{head}`).
    pub async fn compare_commits(
        &self,
        repo: &Resource,
        base: &str,
        head: &str,
    ) -> Result<Comparison> {
        check_sha(base)?;
        check_sha(head)?;
        let (token, owner, name) = self.repo_token_for(repo, PERMS_READ).await?;
        #[derive(Deserialize)]
        struct Sha {
            sha: String,
        }
        #[derive(Deserialize)]
        struct Compare {
            total_commits: u64,
            merge_base_commit: Sha,
            #[serde(default)]
            commits: Vec<Sha>,
        }
        let range = format!("{base}...{head}");
        let mut url = self.api().url(&["repos", &owner, &name, "compare", &range]);
        url.query_pairs_mut().append_pair("per_page", "100");
        let c: Compare = self
            .api()
            .json(
                Method::GET,
                url,
                Auth::Bearer(&token),
                None,
                "commit comparison",
            )
            .await?;
        let commits = c.commits.into_iter().map(|s| s.sha).collect::<Vec<_>>();
        for sha in &commits {
            check_sha(sha)?;
        }
        Ok(Comparison {
            commits,
            total: c.total_commits,
            merge_base: c.merge_base_commit.sha,
        })
    }

    /// A token that can read (fetch) `repo` and nothing else, for one fetch
    /// of the commits under test. The caller holds it for that fetch only
    /// and drops it; it lapses on its own within the hour either way.
    pub async fn contents_read_token(&self, repo: &Resource) -> Result<Secret> {
        Ok(self.repo_token_for(repo, PERMS_READ).await?.0)
    }

    /// The HTTPS clone URL of `repo` on this GitHub (`<web>/<owner>/<repo>.git`).
    pub fn clone_url(&self, repo: &Resource) -> Result<Url> {
        repo.require_owner_repo()?;
        let name = repo.repo_name().ok_or_else(|| ForgeError::WrongResource {
            resource: repo.to_string(),
            expected: "a repository".into(),
        })?;
        Ok(self.api().web_url(&[repo.owner(), &format!("{name}.git")]))
    }

    /// Post the check on `head_sha` as in progress, and return its id.
    pub async fn start_check_run(
        &self,
        repo: &Resource,
        head_sha: &str,
        name: &str,
        external_id: &str,
    ) -> Result<u64> {
        check_sha(head_sha)?;
        let (token, owner, repo_name) = self.repo_token_for(repo, PERMS_CHECKS).await?;
        #[derive(Deserialize)]
        struct Created {
            id: u64,
        }
        let body = json!({
            "name": name,
            "head_sha": head_sha,
            "status": "in_progress",
            "external_id": external_id,
            "output": {
                "title": "Checking commit signatures",
                "summary": "The community's bridge is verifying every commit against the Trust Registry.",
            },
        });
        let created: Created = self
            .api()
            .json(
                Method::POST,
                self.api().url(&["repos", &owner, &repo_name, "check-runs"]),
                Auth::Bearer(&token),
                Some(&body),
                "check run",
            )
            .await?;
        Ok(created.id)
    }

    /// Complete check run `id` with `conclusion`, a one-line `title` and a
    /// Markdown `summary` (truncated to what GitHub accepts).
    pub async fn finish_check_run(
        &self,
        repo: &Resource,
        id: u64,
        conclusion: CheckConclusion,
        title: &str,
        summary: &str,
    ) -> Result<()> {
        let (token, owner, repo_name) = self.repo_token_for(repo, PERMS_CHECKS).await?;
        let body = json!({
            "status": "completed",
            "conclusion": conclusion.as_str(),
            "output": { "title": title, "summary": truncate(summary, MAX_SUMMARY) },
        });
        self.api()
            .send(
                Method::PATCH,
                self.api()
                    .url(&["repos", &owner, &repo_name, "check-runs", &id.to_string()]),
                Auth::Bearer(&token),
                Some(&body),
                "check run",
            )
            .await?;
        Ok(())
    }
}

/// A git object id: 40 (SHA-1) or 64 (SHA-256) lowercase hex. Checked before
/// it goes into a URL or a git command line.
pub fn check_sha(sha: &str) -> Result<()> {
    let ok = (sha.len() == 40 || sha.len() == 64)
        && sha
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if ok {
        Ok(())
    } else {
        Err(ForgeError::Protocol(format!("`{sha}` is not a commit id")))
    }
}

fn sha_at(v: &Value, path: &[&str]) -> Result<String> {
    let s = path
        .iter()
        .try_fold(v, |v, k| v.get(k))
        .and_then(Value::as_str)
        .ok_or_else(|| ForgeError::Webhook(format!("payload is missing `{}`", path.join("."))))?;
    check_sha(s)
        .map_err(|_| ForgeError::Webhook(format!("`{}` is not a commit id", path.join("."))))?;
    Ok(s.to_string())
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n\n… (truncated)", &s[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shas_are_hex_of_the_right_length() {
        assert!(check_sha(&"a".repeat(40)).is_ok());
        assert!(check_sha(&"0".repeat(64)).is_ok());
        for bad in [
            "",
            "abc",
            &"A".repeat(40),
            &"g".repeat(40),
            "--upload-pack=x",
        ] {
            assert!(check_sha(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn long_summaries_are_cut_on_a_char_boundary() {
        let s = "é".repeat(40_000);
        let t = truncate(&s, MAX_SUMMARY);
        assert!(t.len() < s.len());
        assert!(t.ends_with("(truncated)"));
    }
}
