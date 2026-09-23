//! The check the bridge posts itself (GitHub fallback mode, §9 "forged check
//! runs").
//!
//! On a `pull_request` or `merge_group` delivery for a namespace where the
//! bridge posts the check ([`vgi_forge::Capabilities::bridge_posted_check`]),
//! the bridge:
//!
//! 1. posts "Verify commit trust" as **in progress** under its App;
//! 2. lists the commits in `base...head` (GitHub's comparison), refusing
//!    more than `checks.max_commits`;
//! 3. fetches exactly those commit objects into a throwaway bare repository,
//!    with a read-only token for that one repository (see [`GitFetcher`]);
//! 4. runs verify-trust **as a library** against them — the qualified
//!    resource (`github.com/acme/widgets`) with the namespace
//!    (`github.com/acme`) as the fallback resource, where `git.ns.admin`'s
//!    implied `git.commit.sign` is published — bounded by
//!    `checks.max_signers` distinct signer DIDs;
//! 5. completes the check with **success** or **failure** and a per-commit
//!    summary.
//!
//! **Nothing from the pull request is ever executed.** The bridge reads
//! commit objects; it never checks out a tree, runs hooks, reads a config
//! from the repository or follows a submodule. Any error along the way
//! completes the check as a failure (fail closed), as verify-trust itself
//! would.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::process::Command;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;
use vgi_forge::Resource;
use vgi_forge_github::checks::check_sha;
use vgi_forge_github::{CheckConclusion, CheckTrigger, CheckTriggerKind};
use zeroize::Zeroizing;

use crate::bridge::Bridge;
use crate::config::{BridgeConfig, CheckConfig};
use crate::jobs::Ctx;
use crate::store::{NamespaceRecord, NamespaceState, Table};

/// One commit's verdict, for the summary.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct CommitLine {
    /// The commit.
    pub sha: String,
    /// Whether it passes.
    pub passes: bool,
    /// What verify-trust said, one line.
    pub verdict: String,
}

impl CommitLine {
    /// A line.
    pub fn new(sha: impl Into<String>, passes: bool, verdict: impl Into<String>) -> Self {
        CommitLine {
            sha: sha.into(),
            passes,
            verdict: verdict.into(),
        }
    }
}

/// Verifies commit objects already in a local repository.
#[async_trait]
pub trait CommitVerifier: Send + Sync {
    /// Verify `commits` (oldest first) in `repo_dir` against the registry
    /// for `resource`, falling back to `fallback`.
    async fn verify(
        &self,
        repo_dir: &Path,
        commits: &[String],
        resource: &str,
        fallback: &str,
    ) -> Result<Vec<CommitLine>>;
}

/// The real verifier: verify-trust's library, with the registry endpoint
/// discovered from the registry's DID document and signer DIDs resolved
/// under verify-trust's public-hosts-only policy.
pub struct VerifyTrustVerifier {
    registry_did: String,
    vtc_did: String,
    max_signers: usize,
    /// Per GitHub host, the configured `web-flow` keyring.
    keyrings: std::collections::BTreeMap<String, PathBuf>,
    tdk: OnceCell<Arc<affinidi_tdk::TDK>>,
    registry_url: OnceCell<String>,
}

impl VerifyTrustVerifier {
    /// From the bridge config. The exempt keyring for web-UI merge commits
    /// is the configured `web-flow` key, not a file from the repository
    /// under test.
    pub fn new(cfg: &BridgeConfig) -> Self {
        VerifyTrustVerifier {
            registry_did: cfg.trust_registry_did.clone(),
            vtc_did: cfg.vtc_did.clone(),
            max_signers: cfg.checks.max_signers,
            keyrings: cfg
                .github
                .iter()
                .map(|g| (g.host.clone(), g.platform_keyring_file.clone()))
                .collect(),
            tdk: OnceCell::new(),
            registry_url: OnceCell::new(),
        }
    }
}

#[async_trait]
impl CommitVerifier for VerifyTrustVerifier {
    async fn verify(
        &self,
        repo_dir: &Path,
        commits: &[String],
        resource: &str,
        fallback: &str,
    ) -> Result<Vec<CommitLine>> {
        let range: Vec<verify_trust::RangeCommit> = commits
            .iter()
            .map(|sha| {
                Ok(verify_trust::RangeCommit {
                    sha: sha.clone(),
                    raw: verify_trust::read_commit_raw(repo_dir, sha)?,
                })
            })
            .collect::<Result<_>>()?;
        let claimed = verify_trust::claimed_signer_dids(&range, self.max_signers)?;
        let tdk = self
            .tdk
            .get_or_try_init(|| async { verify_trust::build_resolver(false).await.map(Arc::new) })
            .await?;
        let registry_url = self
            .registry_url
            .get_or_try_init(|| verify_trust::resolve_registry_endpoint(tdk, &self.registry_did))
            .await?
            .clone();
        let signers = verify_trust::resolve_signer_keys(tdk, &claimed).await?;
        let host = resource.split('/').next().unwrap_or_default();
        let exempt = match self.keyrings.get(host) {
            Some(p) => Some(verify_trust::pgp_exempt::ExemptKeyring::load(p)?),
            None => None,
        };
        let args = verify_trust::VerifyTrustArgs {
            repo_dir: repo_dir.to_path_buf(),
            range: String::new(),
            max_signers: self.max_signers,
            registry_url: Some(registry_url),
            registry_did: self.registry_did.clone(),
            vtc_did: self.vtc_did.clone(),
            action: "git.commit.sign".into(),
            resource: resource.into(),
            fallback_resource: Some(fallback.into()),
            exempt_keyring: None,
            resolve_agent_names: false,
            json: false,
        };
        let report =
            verify_trust::verify_prepared(&args, &range, &signers, exempt.as_ref()).await?;
        Ok(report
            .commits
            .into_iter()
            .map(|c| {
                let verdict = serde_json::to_value(&c.status)
                    .ok()
                    .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_string))
                    .unwrap_or_else(|| format!("{:?}", c.status));
                CommitLine::new(c.sha, c.status.passes(), verdict)
            })
            .collect())
    }
}

/// Fetches commit objects without ever running anything from them.
///
/// `git` runs with no system or global config, no terminal prompt, hooks
/// pointed at nothing, redirects refused, and only the `https` protocol
/// allowed (so a URL can never become `ext::` or `file://`); the token
/// travels in an `http.extraHeader` set through the environment, never on
/// the command line. The repository is bare and is deleted afterwards.
#[derive(Debug, Clone)]
pub struct GitFetcher {
    git: PathBuf,
    timeout: Duration,
    allow_file: bool,
    remote_override: Option<Url>,
}

impl GitFetcher {
    /// From the check config.
    pub fn new(cfg: &CheckConfig) -> Self {
        GitFetcher {
            git: cfg.git.clone(),
            timeout: Duration::from_secs(cfg.fetch_timeout_secs),
            allow_file: false,
            remote_override: None,
        }
    }

    /// Fetch from a local repository instead of the forge — for tests only:
    /// it also allows the `file` protocol.
    #[doc(hidden)]
    pub fn with_local_remote(mut self, remote: Url) -> Self {
        self.allow_file = true;
        self.remote_override = Some(remote);
        self
    }

    async fn git(&self, dir: &Path, args: &[&str], token: Option<&str>) -> Result<Vec<u8>> {
        let mut cmd = Command::new(&self.git);
        cmd.arg("-C").arg(dir);
        // Hardening that must precede the subcommand.
        for c in [
            "core.hooksPath=/dev/null",
            "http.followRedirects=false",
            "protocol.allow=never",
            "core.fsmonitor=false",
            "submodule.recurse=false",
            "fetch.recurseSubmodules=false",
            "transfer.fsckObjects=true",
        ] {
            cmd.arg("-c").arg(c);
        }
        cmd.arg("-c").arg("protocol.https.allow=always");
        if self.allow_file {
            cmd.arg("-c").arg("protocol.file.allow=always");
        }
        cmd.args(args)
            .env_clear()
            .env("PATH", std::env::var_os("PATH").unwrap_or_default())
            .env("HOME", dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", "/bin/false")
            .env("GIT_PROTOCOL_FROM_USER", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let header;
        if let Some(t) = token {
            header = Zeroizing::new(format!(
                "Authorization: Basic {}",
                STANDARD.encode(format!("x-access-token:{t}"))
            ));
            cmd.env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "http.extraHeader")
                .env("GIT_CONFIG_VALUE_0", header.as_str());
        }
        let out = tokio::time::timeout(self.timeout, cmd.output())
            .await
            .context("git timed out")?
            .context("running git")?;
        if !out.status.success() {
            // The token is in the environment, not in anything git echoes;
            // stderr is still trimmed before it reaches a check summary.
            let err = String::from_utf8_lossy(&out.stderr);
            bail!(
                "git {}: {}",
                args[0],
                err.lines().last().unwrap_or("failed")
            );
        }
        Ok(out.stdout)
    }

    /// Fetch `head` with enough history to hold every commit in `commits`,
    /// into a fresh bare repository. Returns the directory (deleted on drop).
    pub async fn fetch(
        &self,
        remote: &Url,
        token: Option<&str>,
        head: &str,
        commits: &[String],
    ) -> Result<tempfile::TempDir> {
        check_sha(head).map_err(|e| anyhow!("{e}"))?;
        for c in commits {
            check_sha(c).map_err(|e| anyhow!("{e}"))?;
        }
        let remote = self.remote_override.as_ref().unwrap_or(remote);
        match remote.scheme() {
            "https" => {}
            "file" if self.allow_file => {}
            s => bail!("refusing to fetch over `{s}`"),
        }
        let dir = tempfile::tempdir()?;
        self.git(dir.path(), &["init", "--quiet", "--bare"], None)
            .await?;
        // Depth = the number of commits under test: every one of them is
        // within that many generations of the head.
        let depth = format!("--depth={}", commits.len().max(1));
        self.git(
            dir.path(),
            &[
                "fetch",
                "--quiet",
                "--no-tags",
                "--no-write-fetch-head",
                "--no-recurse-submodules",
                &depth,
                remote.as_str(),
                head,
            ],
            token,
        )
        .await?;
        for sha in commits {
            let t = self
                .git(dir.path(), &["cat-file", "-t", sha], None)
                .await
                .with_context(|| format!("commit {sha} did not arrive"))?;
            if String::from_utf8_lossy(&t).trim() != "commit" {
                bail!("{sha} is not a commit");
            }
        }
        Ok(dir)
    }
}

/// Runs checks, a bounded number at a time, each (repository, head) once.
pub struct CheckRunner {
    verifier: Arc<dyn CommitVerifier>,
    fetcher: GitFetcher,
    max_commits: usize,
    permits: Semaphore,
    in_flight: Mutex<BTreeSet<(String, String)>>,
}

impl CheckRunner {
    /// A runner.
    pub fn new(cfg: &CheckConfig, verifier: Arc<dyn CommitVerifier>, fetcher: GitFetcher) -> Self {
        CheckRunner {
            verifier,
            fetcher,
            max_commits: cfg.max_commits,
            permits: Semaphore::new(cfg.concurrency.max(1)),
            in_flight: Mutex::new(BTreeSet::new()),
        }
    }
}

/// Run the check for `trigger` in the background.
pub(crate) fn spawn(bridge: &Arc<Bridge>, trigger: CheckTrigger) {
    let bridge = Arc::clone(bridge);
    tokio::spawn(async move {
        let key = (trigger.repo.to_string(), trigger.head_sha.clone());
        if !bridge
            .checks
            .in_flight
            .lock()
            .expect("lock")
            .insert(key.clone())
        {
            return;
        }
        if let Err(e) = run(&bridge, &trigger).await {
            tracing::warn!(repo = %trigger.repo, head = %trigger.head_sha, error = %e, "check not posted");
        }
        bridge.checks.in_flight.lock().expect("lock").remove(&key);
    });
}

/// The namespace the check is for, if the bridge posts checks there.
fn check_namespace(bridge: &Bridge, repo: &Resource) -> Option<Ctx> {
    let ns = bridge
        .store
        .list::<NamespaceRecord>(Table::Namespaces)
        .ok()?
        .into_iter()
        .map(|(_, n)| n)
        .find(|n| n.state == NamespaceState::Bound && n.resource.contains(repo))?;
    let ctx = Ctx::load(bridge, &ns.id).ok()?;
    ctx.adapter
        .forge()
        .capabilities(&ctx.namespace)
        .bridge_posted_check
        .then_some(ctx)
}

pub(crate) async fn run(bridge: &Bridge, trigger: &CheckTrigger) -> Result<()> {
    let Some(ctx) = check_namespace(bridge, &trigger.repo) else {
        // A required-workflow namespace (Actions runs the check), manual
        // mode, or a repository outside every bound namespace.
        return Ok(());
    };
    let g = ctx
        .adapter
        .github()
        .context("bridge checks are GitHub's")?
        .clone();
    let check_name = bridge
        .adapters
        .vgi(ctx.ns.resource.host())
        .map(|v| v.required_check)
        .unwrap_or_else(|| vgi_forge::DEFAULT_REQUIRED_CHECK.into());
    let _permit = bridge.checks.permits.acquire().await?;
    let external = trigger
        .delivery_id
        .clone()
        .unwrap_or_else(|| trigger.head_sha.clone());
    let id = g
        .start_check_run(&trigger.repo, &trigger.head_sha, &check_name, &external)
        .await?;
    let (conclusion, title, summary) = match verify(bridge, &g, &ctx, trigger).await {
        Ok(lines) => summarise(&lines),
        Err(e) => (
            CheckConclusion::Failure,
            "The commits could not be verified".to_string(),
            format!(
                "The bridge could not complete the check, so it fails closed.\n\n`{}`",
                e.to_string().replace('`', "'")
            ),
        ),
    };
    g.finish_check_run(&trigger.repo, id, conclusion, &title, &summary)
        .await?;
    Ok(())
}

async fn verify(
    bridge: &Bridge,
    g: &vgi_forge_github::GitHubForge,
    ctx: &Ctx,
    trigger: &CheckTrigger,
) -> Result<Vec<CommitLine>> {
    let cmp = g
        .compare_commits(&trigger.repo, &trigger.base_sha, &trigger.head_sha)
        .await?;
    let max = bridge.checks.max_commits;
    if cmp.total as usize > max || (cmp.commits.len() as u64) < cmp.total {
        bail!(
            "{} commits are more than this bridge checks at once ({max}); split the change",
            cmp.total
        );
    }
    if let CheckTriggerKind::PullRequest {
        commits: Some(n), ..
    } = trigger.kind
        && n != cmp.total
    {
        tracing::debug!(
            said = n,
            listed = cmp.total,
            "the delivery and the comparison disagree on the commit count; the comparison is used"
        );
    }
    if cmp.commits.is_empty() {
        return Ok(Vec::new());
    }
    let token = g.contents_read_token(&trigger.repo).await?;
    let remote = g.clone_url(&trigger.repo)?;
    let dir = bridge
        .checks
        .fetcher
        .fetch(
            &remote,
            Some(token.expose()),
            &trigger.head_sha,
            &cmp.commits,
        )
        .await?;
    drop(token);
    let resource = trigger.repo.as_str();
    // Spec PR #623: `git.ns.admin`'s implied `git.commit.sign` is published
    // on the namespace resource, so the namespace is the fallback.
    let fallback = ctx.ns.resource.as_str();
    bridge
        .checks
        .verifier
        .verify(dir.path(), &cmp.commits, resource, fallback)
        .await
}

fn summarise(lines: &[CommitLine]) -> (CheckConclusion, String, String) {
    let failed = lines.iter().filter(|l| !l.passes).count();
    let conclusion = if failed == 0 {
        CheckConclusion::Success
    } else {
        CheckConclusion::Failure
    };
    let title = if lines.is_empty() {
        "No new commits to verify".to_string()
    } else if failed == 0 {
        format!("All {} commits are signed by trusted DIDs", lines.len())
    } else {
        format!("{failed} of {} commits are not trusted", lines.len())
    };
    let mut summary = String::from(
        "Checked by the community's bridge against its Trust Registry.\n\n| Commit | Verdict |\n|---|---|\n",
    );
    for l in lines {
        summary.push_str(&format!(
            "| `{}` | {} {} |\n",
            &l.sha[..l.sha.len().min(12)],
            if l.passes { "✅" } else { "❌" },
            l.verdict.replace('|', "/")
        ));
    }
    (conclusion, title, summary)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_fails_on_any_untrusted_commit() {
        let (c, t, s) = summarise(&[
            CommitLine::new("a".repeat(40), true, "trusted"),
            CommitLine::new("b".repeat(40), false, "unauthorized"),
        ]);
        assert_eq!(c, CheckConclusion::Failure);
        assert_eq!(t, "1 of 2 commits are not trusted");
        assert!(s.contains("unauthorized"));
        let (c, _, _) = summarise(&[CommitLine::new("a".repeat(40), true, "trusted")]);
        assert_eq!(c, CheckConclusion::Success);
    }

    #[tokio::test]
    async fn the_fetcher_refuses_anything_but_https_and_commit_ids() {
        let f = GitFetcher::new(&CheckConfig::default());
        let head = "a".repeat(40);
        for bad in [
            "file:///tmp/x",
            "ext::sh -c touch% /tmp/pwned",
            "http://example.org/r",
        ] {
            let Ok(u) = Url::parse(bad) else { continue };
            assert!(f.fetch(&u, None, &head, &[]).await.is_err(), "{bad}");
        }
        let u = Url::parse("https://example.org/r.git").unwrap();
        assert!(f.fetch(&u, None, "--upload-pack=x", &[]).await.is_err());
    }
}
