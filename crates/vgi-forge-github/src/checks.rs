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
/// Reading a pull request's current head and base.
const PERMS_PULLS: &[(&str, &str)] = &[("metadata", "read"), ("pull_requests", "read")];
/// The repository's metadata (its default branch).
const PERMS_METADATA: &[(&str, &str)] = &[("metadata", "read")];
/// GitHub lists a comparison's commits 100 to a page, 250 in all.
const COMPARE_PER_PAGE: usize = 100;
const COMPARE_PAGES: usize = 3;

/// GitHub caps a check run's `output.summary` at 65 535 characters.
const MAX_SUMMARY: usize = 65_000;

/// Why a check is due.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckTriggerKind {
    /// A pull request was opened, pushed to, reopened, or had its base
    /// branch changed.
    PullRequest {
        /// Its number.
        number: u64,
    },
    /// A merge queue asked for checks on a merge group.
    MergeGroup,
    /// Someone asked for the check again (`check_run` / `check_suite`
    /// `rerequested`) on a pull request.
    Rerequested {
        /// The pull request.
        number: u64,
    },
}

/// A verified delivery that calls for the check on `head_sha`, against the
/// base branch `base_ref`.
///
/// A check run attaches to a *commit*, not to a pull request: a success on
/// `head_sha` satisfies every pull request whose head is that commit. So a
/// check is only meaningful — and must only be posted — against a base the
/// required check protects; the caller decides that from `base_ref`, never
/// from anything else in the delivery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CheckTrigger {
    /// The repository the check is posted on (the pull request's base).
    pub repo: Resource,
    /// Its forge id.
    pub repo_id: u64,
    /// The commit the check is for.
    pub head_sha: String,
    /// The base branch's tip the delivery named (a pull request's may be
    /// stale; the caller re-reads it).
    pub base_sha: String,
    /// The base branch, without `refs/heads/`.
    pub base_ref: String,
    /// Pull request, merge group or rerequest.
    pub kind: CheckTriggerKind,
    /// GitHub's delivery id, for de-duplication.
    pub delivery_id: Option<String>,
    /// For a pull request delivery: its head branch, as the delivery says —
    /// a hint for the Dependabot re-sign, which re-reads it from GitHub.
    pub head_ref: Option<String>,
    /// For a pull request delivery: who opened it, as the delivery says (a
    /// hint only, like `head_ref`).
    pub author_login: Option<String>,
}

/// A pull request as GitHub reports it now.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PullRequestInfo {
    /// Its head commit.
    pub head_sha: String,
    /// Its base branch, without `refs/heads/`.
    pub base_ref: String,
    /// The base branch's tip.
    pub base_sha: String,
    /// Open (a closed or merged one gets no new check).
    pub open: bool,
    /// Its head branch, without `refs/heads/`.
    pub head_ref: String,
    /// The repository its head branch is in; `None` when GitHub reports
    /// none (a deleted fork).
    pub head_repo_id: Option<u64>,
    /// The repository it merges into.
    pub base_repo_id: Option<u64>,
    /// The login of the account that opened it.
    pub author_login: Option<String>,
    /// That account's numeric id.
    pub author_id: Option<u64>,
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

/// A branch name from a ref (`refs/heads/main` → `main`); a name that is
/// already bare is returned as it is.
fn branch_of(r: &str) -> &str {
    r.strip_prefix("refs/heads/").unwrap_or(r)
}

/// The `pull_requests` entries of a `check_run` / `check_suite` payload, as
/// rerequest triggers.
fn rerequests(
    repo: &Resource,
    repo_id: u64,
    head_sha: &str,
    prs: Option<&Value>,
    delivery_id: &Option<String>,
) -> Vec<CheckTrigger> {
    let mut out = Vec::new();
    for pr in prs.and_then(Value::as_array).into_iter().flatten() {
        let Some(number) = pr.get("number").and_then(Value::as_u64) else {
            continue;
        };
        let base_ref = pr
            .pointer("/base/ref")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let base_sha = pr
            .pointer("/base/sha")
            .and_then(Value::as_str)
            .unwrap_or_default();
        if base_ref.is_empty() || check_sha(base_sha).is_err() {
            continue;
        }
        out.push(CheckTrigger {
            repo: repo.clone(),
            repo_id,
            head_sha: head_sha.to_string(),
            base_sha: base_sha.to_string(),
            base_ref: branch_of(base_ref).to_string(),
            kind: CheckTriggerKind::Rerequested { number },
            delivery_id: delivery_id.clone(),
            head_ref: None,
            author_login: None,
        });
    }
    out
}

impl GitHubForge {
    /// Verify a webhook and, if it calls for the bridge-posted check, say on
    /// what. Empty for a verified delivery that does not (another event, a
    /// closed pull request, a title edit). `Err` for one that failed
    /// verification, which must not be acted on.
    ///
    /// Triggers: `pull_request` `opened` / `synchronize` / `reopened`, and
    /// `edited` when the base branch changed; `merge_group`
    /// `checks_requested`; this App's `check_run` / `check_suite`
    /// `rerequested` (one trigger per pull request the delivery names). The
    /// repository is the delivery's `repository` — the base the check is
    /// posted on — never the fork a pull request came from.
    pub fn parse_check_trigger(
        &self,
        headers: &HeaderMap,
        body: &[u8],
    ) -> Result<Vec<CheckTrigger>> {
        webhook::verify_signature(self.webhook_secret(), headers, body)?;
        let event = headers
            .get("x-github-event")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| ForgeError::Webhook("missing X-GitHub-Event".into()))?;
        let delivery_id = headers
            .get("x-github-delivery")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string);
        if !matches!(
            event,
            "pull_request" | "merge_group" | "check_run" | "check_suite"
        ) {
            return Ok(Vec::new());
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

        let one = |head_sha: String, base_sha: String, base_ref: &str, kind| {
            vec![CheckTrigger {
                repo: repo.clone(),
                repo_id,
                head_sha,
                base_sha,
                base_ref: branch_of(base_ref).to_string(),
                kind,
                delivery_id: delivery_id.clone(),
                head_ref: None,
                author_login: None,
            }]
        };
        let app_id = self.config().app_id;
        Ok(match (event, action) {
            ("pull_request", "opened" | "synchronize" | "reopened" | "edited") => {
                // An edit matters only when it moved the base: a title edit
                // changes nothing the check depends on.
                if action == "edited" && payload.pointer("/changes/base").is_none() {
                    return Ok(Vec::new());
                }
                let pr = &payload["pull_request"];
                let number = pr
                    .get("number")
                    .and_then(Value::as_u64)
                    .ok_or_else(|| ForgeError::Webhook("pull request has no number".into()))?;
                let mut t = one(
                    sha_at(pr, &["head", "sha"])?,
                    sha_at(pr, &["base", "sha"])?,
                    str_at(pr, &["base", "ref"])?,
                    CheckTriggerKind::PullRequest { number },
                );
                t[0].head_ref = str_at(pr, &["head", "ref"])
                    .ok()
                    .map(|r| branch_of(r).to_string());
                t[0].author_login = str_at(pr, &["user", "login"]).ok().map(str::to_string);
                t
            }
            ("merge_group", "checks_requested") => {
                let group = &payload["merge_group"];
                one(
                    sha_at(group, &["head_sha"])?,
                    sha_at(group, &["base_sha"])?,
                    str_at(group, &["base_ref"])?,
                    CheckTriggerKind::MergeGroup,
                )
            }
            ("check_run", "rerequested") | ("check_suite", "rerequested") => {
                let obj = &payload[event];
                // Only this App's own runs: another App's rerequest is not
                // ours to answer.
                if obj.pointer("/app/id").and_then(Value::as_u64) != Some(app_id) {
                    return Ok(Vec::new());
                }
                let head = sha_at(obj, &["head_sha"])?;
                rerequests(
                    &repo,
                    repo_id,
                    &head,
                    obj.get("pull_requests"),
                    &delivery_id,
                )
            }
            _ => Vec::new(),
        })
    }

    /// The repository's default branch — the one branch the managed
    /// ruleset protects (`~DEFAULT_BRANCH`), read from GitHub now rather
    /// than from a delivery.
    pub async fn default_branch(&self, repo: &Resource) -> Result<String> {
        let (token, owner, name) = self.repo_token_for(repo, PERMS_METADATA).await?;
        #[derive(Deserialize)]
        struct R {
            default_branch: Option<String>,
        }
        let r: R = self
            .api()
            .json(
                Method::GET,
                self.api().url(&["repos", &owner, &name]),
                Auth::Bearer(&token),
                None,
                repo.as_str(),
            )
            .await?;
        r.default_branch
            .ok_or_else(|| ForgeError::Protocol(format!("`{repo}` has no default branch")))
    }

    /// Pull request `number` on `repo`, as GitHub reports it now.
    pub async fn pull_request(&self, repo: &Resource, number: u64) -> Result<PullRequestInfo> {
        let (token, owner, name) = self.repo_token_for(repo, PERMS_PULLS).await?;
        let pr: Value = self
            .api()
            .json(
                Method::GET,
                self.api()
                    .url(&["repos", &owner, &name, "pulls", &number.to_string()]),
                Auth::Bearer(&token),
                None,
                "pull request",
            )
            .await?;
        Ok(PullRequestInfo {
            head_sha: sha_at(&pr, &["head", "sha"])?,
            base_ref: branch_of(str_at(&pr, &["base", "ref"])?).to_string(),
            base_sha: sha_at(&pr, &["base", "sha"])?,
            open: pr.get("state").and_then(Value::as_str) == Some("open"),
            head_ref: pr
                .pointer("/head/ref")
                .and_then(Value::as_str)
                .map(|r| branch_of(r).to_string())
                .unwrap_or_default(),
            head_repo_id: pr.pointer("/head/repo/id").and_then(Value::as_u64),
            base_repo_id: pr.pointer("/base/repo/id").and_then(Value::as_u64),
            author_login: pr
                .pointer("/user/login")
                .and_then(Value::as_str)
                .map(str::to_string),
            author_id: pr.pointer("/user/id").and_then(Value::as_u64),
        })
    }

    /// The commits in `base...head` on `repo`, oldest first
    /// (`GET /repos/{o}/{r}/compare/{base}...{head}`, every page: GitHub
    /// lists 100 per page and 250 in all).
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
        let mut commits = Vec::new();
        let mut total = 0;
        let mut merge_base = String::new();
        for page in 1..=COMPARE_PAGES {
            let mut url = self.api().url(&["repos", &owner, &name, "compare", &range]);
            url.query_pairs_mut()
                .append_pair("per_page", &COMPARE_PER_PAGE.to_string())
                .append_pair("page", &page.to_string());
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
            total = c.total_commits;
            merge_base = c.merge_base_commit.sha;
            let n = c.commits.len();
            commits.extend(c.commits.into_iter().map(|s| s.sha));
            if n < COMPARE_PER_PAGE || commits.len() as u64 >= total {
                break;
            }
        }
        for sha in &commits {
            check_sha(sha)?;
        }
        Ok(Comparison {
            commits,
            total,
            merge_base,
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

fn str_at<'a>(v: &'a Value, path: &[&str]) -> Result<&'a str> {
    path.iter()
        .try_fold(v, |v, k| v.get(k))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ForgeError::Webhook(format!("payload is missing `{}`", path.join("."))))
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
