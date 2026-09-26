//! The check the bridge posts itself (GitHub fallback mode, §9 "forged check
//! runs").
//!
//! **A check run attaches to a commit, not to a pull request.** A success on
//! commit `H` satisfies the required check for *every* pull request whose
//! head is `H`. So the bridge posts only when the base it verified against is
//! a branch the managed ruleset protects — the repository's default branch
//! (the ruleset targets `~DEFAULT_BRANCH`), read from GitHub at check time —
//! and for any other base it posts **nothing**. Otherwise a writer could
//! open `b → a` where `a...H` is empty or all-trusted, collect a success on
//! `H`, and have it count for `b → main`. For the same reason:
//!
//! - a pull request's base is re-read from GitHub (the delivery may be
//!   stale), and a base change (`pull_request` `edited`) is checked again
//!   against the new base — or, if the new base is unprotected, not at all;
//! - de-duplication and the run's `external_id` are keyed by
//!   (repository, head, base branch), never by head alone;
//! - an **empty** comparison against the protected base is a success only
//!   when the head *is* the base tip; a head strictly inside the base has
//!   nothing to merge and gets a failure, never a success that could be
//!   reused.
//!
//! For a qualifying delivery the bridge:
//!
//! 1. posts "Verify commit trust" as **in progress** under its App;
//! 2. lists the commits in `base...head` (GitHub's comparison, every page),
//!    refusing more than `checks.max_commits` or a truncated list;
//! 3. fetches exactly those commit objects — no trees, no blobs
//!    (`--filter=tree:0`) — into a throwaway bare repository, with a
//!    read-only token for that one repository and a bound on the bytes
//!    fetched (see [`GitFetcher`]);
//! 4. runs verify-trust **as a library** against them — the qualified
//!    resource (`github.com/acme/widgets`) with the namespace
//!    (`github.com/acme`) as the fallback resource, where `git.ns.admin`'s
//!    implied `git.commit.sign` is published (spec PR #623) — bounded by
//!    `checks.max_signers` distinct signer DIDs;
//! 5. completes the check with **success** or **failure** and a per-commit
//!    summary.
//!
//! **Nothing from the pull request is ever executed.** The bridge reads
//! commit objects with a hardened git; it never checks out a tree, runs
//! hooks, reads a config from the repository or follows a submodule. Any
//! error along the way completes the check as a failure (fail closed).

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::{OnceCell, Semaphore};
use url::Url;
use verify_trust::RangeCommit;
use vgi_forge::Resource;
use vgi_forge_github::checks::check_sha;
use vgi_forge_github::{CheckConclusion, CheckTrigger, CheckTriggerKind};
use zeroize::Zeroizing;

use crate::bridge::Bridge;
use crate::config::{BridgeConfig, CheckConfig};
use crate::jobs::Ctx;
use crate::store::{LastCheck, NamespaceRecord, NamespaceState, RepoRecord, Table, repo_key};

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

/// Verifies commit objects (their raw bytes, as the fetcher read them).
#[async_trait]
pub trait CommitVerifier: Send + Sync {
    /// Verify `commits` (oldest first) against the registry for
    /// `resource`, falling back to `fallback`.
    async fn verify(
        &self,
        commits: &[RangeCommit],
        resource: &str,
        fallback: &str,
    ) -> Result<Vec<CommitLine>>;

    /// Whether the registry grants `did` `git.commit.sign` on `resource`
    /// right now. `Ok(None)`: this verifier cannot say (the default). Used
    /// only to warn an operator whose bridge DID lacks the grant the
    /// Dependabot re-sign needs; never to decide anything.
    async fn commit_sign_granted(&self, _did: &str, _resource: &str) -> Result<Option<bool>> {
        Ok(None)
    }
}

/// The real verifier: verify-trust's library, with the registry binding
/// discovered from the registry's DID document and signer DIDs resolved
/// under verify-trust's public-hosts-only policy.
///
/// With a channel ([`VerifyTrustVerifier::with_channel`], which the bridge
/// always sets), a registry advertising DIDComm is queried over it — as the
/// bridge's own DID, on the bridge's mediator session — in preference to
/// HTTPS, and a registry with no REST interface is reachable at all. TSP is
/// never used: the bridge's session to its mediator is DIDComm.
/// `[verify_trust] transport` chooses: `auto` (DIDComm, then HTTPS, no
/// fallback), `didcomm` or `https`.
pub struct VerifyTrustVerifier {
    registry_did: String,
    vtc_did: String,
    max_signers: usize,
    /// Per GitHub host, the configured `web-flow` keyring, where one is.
    keyrings: BTreeMap<String, PathBuf>,
    tdk: OnceCell<Arc<affinidi_tdk::TDK>>,
    /// How long a resolved DID document (and the binding read from the
    /// registry's) is kept.
    ttl: std::time::Duration,
    /// The discovered binding, and when. Dropped whenever the registry could
    /// not be consulted and once it is older than `ttl`, so the next check
    /// discovers it again (a registry that moved is found without a
    /// restart).
    registry_route: tokio::sync::Mutex<Option<(trql_client::TransportChoice, std::time::Instant)>>,
    /// Signer DIDs resolved again after an unknown key, and when.
    re_resolved: tokio::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
    /// A fixed HTTPS endpoint (tests; a registry that publishes none).
    registry_override: Option<String>,
    /// `[verify_trust] transport`, for the bridge's own queries.
    transport: verify_trust::TransportSelector,
    /// The bridge's own channel to the registry, for the DIDComm binding.
    channel: Option<Arc<dyn verify_trust::RegistryChannel>>,
}

impl VerifyTrustVerifier {
    /// From the bridge config. The exempt keyring for web-UI merge commits
    /// is the configured `web-flow` key, not a file from the repository
    /// under test; with none configured, platform-signed commits fail.
    pub fn new(cfg: &BridgeConfig) -> Self {
        VerifyTrustVerifier {
            registry_did: cfg.trust_registry_did.clone(),
            vtc_did: cfg.vtc_did.clone(),
            max_signers: cfg.checks.max_signers,
            keyrings: cfg
                .github
                .iter()
                .filter_map(|g| g.platform_keyring_file.clone().map(|k| (g.host.clone(), k)))
                .collect(),
            tdk: OnceCell::new(),
            ttl: std::time::Duration::from_secs(cfg.did_cache_ttl_secs),
            registry_route: tokio::sync::Mutex::new(None),
            re_resolved: Default::default(),
            registry_override: None,
            transport: bridge_transport(cfg.verify_trust.transport),
            channel: None,
        }
    }

    /// Use `url` as the registry's HTTPS endpoint instead of discovering a
    /// binding.
    pub fn with_registry_url(mut self, url: impl Into<String>) -> Self {
        self.registry_override = Some(url.into());
        self
    }

    /// Use `route` instead of discovering one from the registry's DID
    /// document (tests: a registry whose document is not resolvable here).
    #[doc(hidden)]
    pub fn with_route(self, route: trql_client::TransportChoice) -> Self {
        *self.registry_route.try_lock().expect("not yet shared") =
            Some((route, std::time::Instant::now()));
        self
    }

    /// Query over `channel` (the bridge's own DID and session) when the
    /// registry advertises its binding.
    pub fn with_channel(mut self, channel: Arc<dyn verify_trust::RegistryChannel>) -> Self {
        self.channel = Some(channel);
        self
    }

    /// The bindings this verifier can use, in preference order.
    fn supported(&self) -> Vec<trql_client::TransportKind> {
        let mut kinds: Vec<_> = self.channel.iter().map(|c| c.kind()).collect();
        kinds.push(trql_client::TransportKind::Https);
        kinds
    }

    /// The client for this check: the override, or the discovered binding.
    async fn registry(&self, tdk: &affinidi_tdk::TDK) -> Result<verify_trust::Registry> {
        if let Some(u) = &self.registry_override {
            return verify_trust::Registry::https(u, &self.registry_did);
        }
        let mut cached = self.registry_route.lock().await;
        let route = match cached.as_ref() {
            Some((r, at)) if at.elapsed() < self.ttl => r.clone(),
            _ => {
                let r = verify_trust::registry::discover_registry_route(
                    tdk,
                    &self.registry_did,
                    self.transport,
                    &self.supported(),
                )
                .await?;
                tracing::info!(binding = %r.kind, "querying the Trust Registry");
                *cached = Some((r.clone(), std::time::Instant::now()));
                r
            }
        };
        match (&route.kind, &self.channel) {
            (trql_client::TransportKind::Https, _) => {
                verify_trust::Registry::https(&route.endpoint, &self.registry_did)
            }
            (kind, Some(channel)) if *kind == channel.kind() => Ok(
                verify_trust::Registry::over_channel(Arc::clone(channel), &self.registry_did),
            ),
            (kind, _) => bail!("the bridge cannot query the registry over {kind}"),
        }
    }

    async fn resolver(&self) -> Result<&Arc<affinidi_tdk::TDK>> {
        let ttl = u32::try_from(self.ttl.as_secs()).unwrap_or(u32::MAX);
        self.tdk
            .get_or_try_init(|| async {
                verify_trust::build_resolver_with_cache_ttl(false, ttl)
                    .await
                    .map(Arc::new)
            })
            .await
    }

    async fn forget_endpoint(&self) {
        *self.registry_route.lock().await = None;
    }
}

/// `[verify_trust] transport` for the bridge's own queries: `auto` is DIDComm
/// then HTTPS (the bridge never speaks TSP — `tsp` is refused when the config
/// is loaded).
fn bridge_transport(t: vgi_forge::VerifyTransport) -> verify_trust::TransportSelector {
    match t {
        vgi_forge::VerifyTransport::Didcomm => verify_trust::TransportSelector::Didcomm,
        vgi_forge::VerifyTransport::Https => verify_trust::TransportSelector::Https,
        vgi_forge::VerifyTransport::Tsp => verify_trust::TransportSelector::Tsp,
        _ => verify_trust::TransportSelector::Auto,
    }
}

#[async_trait]
impl CommitVerifier for VerifyTrustVerifier {
    async fn verify(
        &self,
        range: &[RangeCommit],
        resource: &str,
        fallback: &str,
    ) -> Result<Vec<CommitLine>> {
        let claimed = verify_trust::claimed_signer_dids(range, self.max_signers)?;
        let tdk = self.resolver().await?;
        let lines = self
            .verify_once(tdk, range, resource, fallback, &claimed)
            .await?;
        // A signer that rotated its key since its document was cached shows
        // up as an unknown key (or an unresolved DID): resolve those DIDs
        // afresh and check once more before failing the commits (closed).
        let stale: Vec<String> = lines
            .1
            .iter()
            .filter_map(|s| match s {
                verify_trust::CommitStatus::UnknownKey { did, .. }
                | verify_trust::CommitStatus::UnresolvedSigner { did, .. } => Some(did.clone()),
                _ => None,
            })
            .collect();
        if stale.is_empty() {
            return Ok(lines.0);
        }
        // At most once per DID per interval (a signer DID is attacker-chosen
        // on a fork PR: it must not steer the bridge into re-fetching at will).
        let stale: Vec<String> = {
            let mut last = self.re_resolved.lock().await;
            let now = std::time::Instant::now();
            last.retain(|_, t| now.duration_since(*t) < crate::wire::RE_RESOLVE_EVERY);
            stale
                .into_iter()
                .filter(|d| last.insert(d.clone(), now).is_none())
                .collect()
        };
        if stale.is_empty() {
            return Ok(lines.0);
        }
        for did in &stale {
            let _ = tdk.did_resolver().remove(did).await;
        }
        tracing::info!(signers = ?stale, "re-resolving signer DIDs after an unknown key");
        Ok(self
            .verify_once(tdk, range, resource, fallback, &claimed)
            .await?
            .0)
    }

    async fn commit_sign_granted(&self, did: &str, resource: &str) -> Result<Option<bool>> {
        use trql_client::TrqpQuery;
        let tdk = self.resolver().await?;
        let registry = self.registry(tdk).await?;
        let query = TrqpQuery::new(did, &self.vtc_did, "git.commit.sign", resource);
        match registry.client().authorization(query).await {
            Ok(r) => Ok(Some(r.authorized)),
            // The registry answered and refused the tuple: a denial.
            Err(trql_client::TrqlError::Rejected { .. }) => Ok(Some(false)),
            Err(e) => Err(e.into()),
        }
    }
}

impl VerifyTrustVerifier {
    /// One verification of `range`: the lines, and each commit's status.
    async fn verify_once(
        &self,
        tdk: &affinidi_tdk::TDK,
        range: &[RangeCommit],
        resource: &str,
        fallback: &str,
        claimed: &[String],
    ) -> Result<(Vec<CommitLine>, Vec<verify_trust::CommitStatus>)> {
        let registry = self.registry(tdk).await?;
        let signers = verify_trust::resolve_signer_keys(tdk, claimed).await?;
        let host = resource.split('/').next().unwrap_or_default();
        let exempt = match self.keyrings.get(host) {
            Some(p) => Some(verify_trust::pgp_exempt::ExemptKeyring::load(p)?),
            None => None,
        };
        let args = verify_trust::VerifyTrustArgs {
            repo_dir: PathBuf::new(),
            range: String::new(),
            max_signers: self.max_signers,
            registry_url: None,
            transport: self.transport,
            registry_did: self.registry_did.clone(),
            vtc_did: self.vtc_did.clone(),
            action: "git.commit.sign".into(),
            resource: resource.into(),
            fallback_resource: Some(fallback.into()),
            exempt_keyring: None,
            resolve_agent_names: false,
            json: false,
        };
        let report = match verify_trust::verify_prepared_with(
            &args,
            range,
            &signers,
            exempt.as_ref(),
            &registry,
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                self.forget_endpoint().await;
                return Err(e);
            }
        };
        if report.commits.iter().any(|c| {
            matches!(
                c.status,
                verify_trust::CommitStatus::RegistryUnavailable { .. }
            )
        }) {
            self.forget_endpoint().await;
        }
        let statuses = report.commits.iter().map(|c| c.status.clone()).collect();
        let lines = report
            .commits
            .into_iter()
            .map(|c| {
                let verdict = serde_json::to_value(&c.status)
                    .ok()
                    .and_then(|v| v.get("status").and_then(|s| s.as_str()).map(str::to_string))
                    .unwrap_or_else(|| format!("{:?}", c.status));
                CommitLine::new(c.sha, c.status.passes(), verdict)
            })
            .collect();
        Ok((lines, statuses))
    }
}

/// Most objects one re-sign push fetches by id (see
/// [`GitFetcher::complete_for_push`]).
const MAX_MISSING_OBJECTS: usize = 2_000;

/// Fetches commit objects without ever running anything from them.
///
/// `git` runs with a cleared environment, no system or global config, no
/// terminal prompt, hooks pointed at nothing, redirects refused, lazy
/// fetching off, and only the `https` protocol allowed (so a URL can never
/// become `ext::` or `file://`); the token travels in an `http.extraHeader`
/// set through the environment, never on the command line. The repository
/// is bare, a partial clone that asks for commits only (`tree:0`, falling
/// back to `blob:none`), watched against `checks.max_fetch_bytes` while the
/// fetch runs, and deleted afterwards.
#[derive(Debug, Clone)]
pub struct GitFetcher {
    git: PathBuf,
    timeout: Duration,
    max_bytes: u64,
    allow_file: bool,
    remote_override: Option<Url>,
}

/// What a fetch produced: the commits, and the repository they came from
/// (kept only as long as this value).
#[derive(Debug)]
#[non_exhaustive]
pub struct Fetched {
    /// The commits under test, oldest first, as raw objects.
    pub commits: Vec<RangeCommit>,
    /// The throwaway repository.
    pub dir: tempfile::TempDir,
}

impl GitFetcher {
    /// From the check config.
    pub fn new(cfg: &CheckConfig) -> Self {
        GitFetcher {
            git: cfg.git.clone(),
            timeout: Duration::from_secs(cfg.fetch_timeout_secs),
            max_bytes: cfg.max_fetch_bytes,
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

    fn command(&self, dir: &Path, args: &[&str], token: Option<&str>) -> Command {
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
            "protocol.https.allow=always",
        ] {
            cmd.arg("-c").arg(c);
        }
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
            // Never reach back to the remote for an object a command wants.
            .env("GIT_NO_LAZY_FETCH", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(t) = token {
            let header = Zeroizing::new(format!(
                "Authorization: Basic {}",
                STANDARD.encode(format!("x-access-token:{t}"))
            ));
            cmd.env("GIT_CONFIG_COUNT", "1")
                .env("GIT_CONFIG_KEY_0", "http.extraHeader")
                .env("GIT_CONFIG_VALUE_0", header.as_str());
        }
        cmd
    }

    /// Run git in `dir`; with `watch`, kill it if `dir` grows past the
    /// byte bound while it runs.
    async fn git(
        &self,
        dir: &Path,
        args: &[&str],
        token: Option<&str>,
        watch: bool,
    ) -> Result<Vec<u8>> {
        let mut child = self
            .command(dir, args, token)
            .spawn()
            .context("running git")?;
        let mut stdout = child.stdout.take().expect("piped");
        let mut stderr = child.stderr.take().expect("piped");
        let out_task = tokio::spawn(async move {
            let mut b = Vec::new();
            let _ = stdout.read_to_end(&mut b).await;
            b
        });
        let err_task = tokio::spawn(async move {
            let mut b = Vec::new();
            let _ = stderr.read_to_end(&mut b).await;
            b
        });
        let deadline = tokio::time::Instant::now() + self.timeout;
        let mut tick = tokio::time::interval(Duration::from_millis(100));
        let status = loop {
            tokio::select! {
                s = child.wait() => break s.context("waiting for git")?,
                _ = tick.tick() => {
                    if tokio::time::Instant::now() > deadline {
                        let _ = child.kill().await;
                        bail!("git {} timed out", args[0]);
                    }
                    if watch && dir_size(dir) > self.max_bytes {
                        let _ = child.kill().await;
                        bail!(
                            "the fetch passed {} bytes; refusing a change this large",
                            self.max_bytes
                        );
                    }
                }
            }
        };
        let out = out_task.await.unwrap_or_default();
        let err = err_task.await.unwrap_or_default();
        if watch && dir_size(dir) > self.max_bytes {
            bail!(
                "the fetch passed {} bytes; refusing a change this large",
                self.max_bytes
            );
        }
        if !status.success() {
            // The token is in the environment, not in anything git echoes;
            // stderr is still trimmed before it reaches a check summary.
            let err = String::from_utf8_lossy(&err);
            // A push says why a ref was refused on its own line (a lease
            // that no longer holds is `[rejected] … (stale info)`).
            let line = err
                .lines()
                .find(|l| l.contains("rejected]"))
                .or_else(|| err.lines().last())
                .unwrap_or("failed");
            bail!("git {}: {}", args[0], line.trim());
        }
        Ok(out)
    }

    /// Before pushing commits that reuse trees of the commits they replace:
    /// fetch the objects git will want to send that the partial clone left
    /// out. git sends the trees of `new_head` that no commit on the
    /// remote's side of the push marks as present, with their blobs that
    /// differ from the base's — in practice the files the change touched —
    /// so those blobs are fetched (by id, bounded like every fetch).
    pub(crate) async fn complete_for_push(
        &self,
        dir: &Path,
        token: Option<&str>,
        new_head: &str,
        old_head: &str,
    ) -> Result<()> {
        check_sha(new_head).map_err(|e| anyhow!("{e}"))?;
        check_sha(old_head).map_err(|e| anyhow!("{e}"))?;
        let not_old = format!("^{old_head}");
        let listed = self
            .git(
                dir,
                &[
                    "rev-list",
                    "--objects",
                    "--missing=print",
                    new_head,
                    &not_old,
                ],
                None,
                false,
            )
            .await?;
        let missing: Vec<String> = String::from_utf8_lossy(&listed)
            .lines()
            .filter_map(|l| l.strip_prefix('?'))
            .map(|l| l.trim().to_string())
            .collect();
        if missing.is_empty() {
            return Ok(());
        }
        if missing.len() > MAX_MISSING_OBJECTS {
            bail!(
                "the change touches {} files; more than the bridge re-signs ({MAX_MISSING_OBJECTS})",
                missing.len()
            );
        }
        for m in &missing {
            check_sha(m).map_err(|e| anyhow!("{e}"))?;
        }
        let mut args = vec![
            "fetch",
            "--quiet",
            "--no-tags",
            "--no-write-fetch-head",
            "--no-recurse-submodules",
            "--filter=blob:none",
            "origin",
        ];
        args.extend(missing.iter().map(String::as_str));
        self.git(dir, &args, token, true).await?;
        Ok(())
    }

    /// Run git in `dir` with `input` on its standard input (for
    /// `hash-object --stdin` and `interpret-trailers`), under the same
    /// hardening and timeout as every other call. Never given a token.
    pub(crate) async fn git_with_input(
        &self,
        dir: &Path,
        args: &[&str],
        input: &[u8],
    ) -> Result<Vec<u8>> {
        use tokio::io::AsyncWriteExt;
        let mut cmd = self.command(dir, args, None);
        cmd.stdin(Stdio::piped());
        let mut child = cmd.spawn().context("running git")?;
        let mut stdin = child.stdin.take().expect("piped");
        let input = input.to_vec();
        let writer = tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            drop(stdin);
        });
        let out = tokio::time::timeout(self.timeout, child.wait_with_output())
            .await
            .map_err(|_| anyhow!("git {} timed out", args[0]))?
            .context("waiting for git")?;
        let _ = writer.await;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!(
                "git {}: {}",
                args[0],
                err.lines().last().unwrap_or("failed")
            );
        }
        Ok(out.stdout)
    }

    /// Where `refs/heads/<branch>` of the repository a [`Fetched`] came
    /// from points now (`None`: no such branch) — read from the remote
    /// itself, never from the forge's API, which can lag a push.
    pub(crate) async fn branch_head(
        &self,
        dir: &Path,
        token: Option<&str>,
        branch: &str,
    ) -> Result<Option<String>> {
        crate::resign::check_branch_name(branch)?;
        let refname = format!("refs/heads/{branch}");
        let out = self
            .git(dir, &["ls-remote", "origin", &refname], token, false)
            .await?;
        let out = String::from_utf8_lossy(&out);
        for line in out.lines() {
            if let Some((sha, name)) = line.split_once('\t')
                && name.trim() == refname
            {
                check_sha(sha).map_err(|e| anyhow!("{e}"))?;
                return Ok(Some(sha.to_string()));
            }
        }
        Ok(None)
    }

    /// Push `new_head` to `refs/heads/<branch>` of the repository a
    /// [`Fetched`] came from, only if the branch still points at `lease`
    /// (`--force-with-lease` with an explicit expected value: the remote
    /// compares and swaps, so a push that lands in between is never
    /// overwritten). `dir` is the fetch's repository, where the new commits
    /// were written.
    pub(crate) async fn push(
        &self,
        dir: &Path,
        token: Option<&str>,
        new_head: &str,
        branch: &str,
        lease: &str,
    ) -> Result<()> {
        check_sha(new_head).map_err(|e| anyhow!("{e}"))?;
        check_sha(lease).map_err(|e| anyhow!("{e}"))?;
        crate::resign::check_branch_name(branch)?;
        let lease = format!("--force-with-lease=refs/heads/{branch}:{lease}");
        let refspec = format!("{new_head}:refs/heads/{branch}");
        self.git(
            dir,
            &[
                "push",
                "--quiet",
                "--no-verify",
                // A thin pack would name blobs the partial clone does not
                // hold as delta bases.
                "--no-thin",
                "--no-recurse-submodules",
                &lease,
                "origin",
                &refspec,
            ],
            token,
            false,
        )
        .await
        .map(|_| ())
    }

    /// Fetch `head` with enough history to hold every commit in `commits`
    /// (commit objects only), and read each of them.
    pub async fn fetch(
        &self,
        remote: &Url,
        token: Option<&str>,
        head: &str,
        commits: &[String],
    ) -> Result<Fetched> {
        self.fetch_with(remote, token, head, commits, &["tree:0", "blob:none"], 0)
            .await
    }

    /// Fetch for a rewrite: the commits, their trees (no blobs) and one
    /// generation more — the parent the first rewritten commit keeps — so
    /// that commits reusing those trees can be pushed back from this
    /// repository. (git cannot push from a `tree:0` clone: it walks the
    /// trees it must not send.) Trees are small and the byte bound still
    /// applies.
    pub(crate) async fn fetch_for_rewrite(
        &self,
        remote: &Url,
        token: Option<&str>,
        head: &str,
        commits: &[String],
    ) -> Result<Fetched> {
        self.fetch_with(remote, token, head, commits, &["blob:none"], 1)
            .await
    }

    async fn fetch_with(
        &self,
        remote: &Url,
        token: Option<&str>,
        head: &str,
        commits: &[String],
        filters: &[&str],
        extra_depth: usize,
    ) -> Result<Fetched> {
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
        let d = dir.path();
        self.git(d, &["init", "--quiet", "--bare"], None, false)
            .await?;
        // A partial clone of `origin`: git fetches with a filter only from
        // its promisor remote.
        for (k, v) in [
            ("core.repositoryformatversion", "1"),
            ("extensions.partialClone", "origin"),
            ("remote.origin.url", remote.as_str()),
            ("remote.origin.promisor", "true"),
        ] {
            self.git(d, &["config", k, v], None, false).await?;
        }
        // Depth = the number of commits under test: every one of them is
        // within that many generations of the head.
        let depth = format!("--depth={}", commits.len().max(1) + extra_depth);
        let mut last_err = None;
        for &filter in filters {
            self.git(
                d,
                &["config", "remote.origin.partialclonefilter", filter],
                None,
                false,
            )
            .await?;
            let f = format!("--filter={filter}");
            match self
                .git(
                    d,
                    &[
                        "fetch",
                        "--quiet",
                        "--no-tags",
                        "--no-write-fetch-head",
                        "--no-recurse-submodules",
                        &f,
                        &depth,
                        "origin",
                        head,
                    ],
                    token,
                    true,
                )
                .await
            {
                Ok(_) => {
                    last_err = None;
                    break;
                }
                // The byte bound is not something another filter fixes.
                Err(e) if e.to_string().contains("bytes") => return Err(e),
                Err(e) => last_err = Some(e),
            }
        }
        if let Some(e) = last_err {
            return Err(e);
        }
        let mut out = Vec::with_capacity(commits.len());
        for sha in commits {
            let raw = self
                .git(d, &["cat-file", "commit", sha], None, false)
                .await
                .with_context(|| format!("commit {sha} did not arrive"))?;
            out.push(RangeCommit {
                sha: sha.clone(),
                raw,
            });
        }
        Ok(Fetched { commits: out, dir })
    }
}

/// Bytes under `dir` (best effort; unreadable entries count as nothing).
fn dir_size(dir: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![dir.to_path_buf()];
    while let Some(p) = stack.pop() {
        let Ok(rd) = std::fs::read_dir(&p) else {
            continue;
        };
        for e in rd.flatten() {
            match e.metadata() {
                Ok(m) if m.is_dir() => stack.push(e.path()),
                Ok(m) => total += m.len(),
                Err(_) => {}
            }
        }
    }
    total
}

/// Runs checks, a bounded number at a time, each (repository, head, base
/// branch) once at a time.
pub struct CheckRunner {
    pub(crate) verifier: Arc<dyn CommitVerifier>,
    pub(crate) fetcher: GitFetcher,
    max_commits: usize,
    permits: Semaphore,
    in_flight: Mutex<BTreeSet<(String, String, String)>>,
    /// Per repository (store key): when its last check was last reported to
    /// the VTC, and whether a report is waiting to go.
    reports: Mutex<BTreeMap<String, ReportSlot>>,
}

/// The post-check report of one repository, throttled.
#[derive(Debug, Default)]
struct ReportSlot {
    last: Option<Instant>,
    pending: bool,
}

/// At most one post-check report per repository in this long: each is an
/// inspection of the repository, and a busy repository posts many checks.
/// A report that waits carries the latest check when it goes.
const REPORT_INTERVAL: Duration = Duration::from_secs(60);

impl CheckRunner {
    /// A runner.
    pub fn new(cfg: &CheckConfig, verifier: Arc<dyn CommitVerifier>, fetcher: GitFetcher) -> Self {
        CheckRunner {
            verifier,
            fetcher,
            max_commits: cfg.max_commits,
            permits: Semaphore::new(cfg.concurrency.max(1)),
            in_flight: Mutex::new(BTreeSet::new()),
            reports: Mutex::new(BTreeMap::new()),
        }
    }
}

/// What one trigger came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CheckOutcome {
    /// A check run was completed.
    Posted(CheckConclusion),
    /// Nothing to post: not a bridge-check namespace, an unprotected base,
    /// a closed or moved-on pull request, or the same check already running.
    Skipped(&'static str),
}

/// Run the checks a delivery called for, in the background. `on_done` runs
/// only if every one of them completed (posted or deliberately skipped) —
/// the caller records the delivery as handled there, so a redelivery after
/// a failure is processed again.
pub(crate) fn spawn(
    bridge: &Arc<Bridge>,
    triggers: Vec<CheckTrigger>,
    on_done: impl FnOnce(&Bridge) + Send + 'static,
) {
    let bridge = Arc::clone(bridge);
    tokio::spawn(async move {
        let mut all_ok = true;
        for t in &triggers {
            match run(&bridge, t).await {
                Ok(o) => {
                    tracing::info!(repo = %t.repo, head = %t.head_sha, outcome = ?o, "check");
                    if matches!(o, CheckOutcome::Posted(_)) {
                        report_check(&bridge, t);
                    }
                }
                Err(e) => {
                    all_ok = false;
                    tracing::warn!(repo = %t.repo, head = %t.head_sha, error = %e, "check not posted");
                }
            }
        }
        if all_ok {
            on_done(&bridge);
        }
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

/// Removes an in-flight key when the check ends, however it ends.
struct InFlight<'a> {
    set: &'a Mutex<BTreeSet<(String, String, String)>>,
    key: (String, String, String),
}

impl Drop for InFlight<'_> {
    fn drop(&mut self) {
        self.set.lock().expect("lock").remove(&self.key);
    }
}

/// Run one trigger: resolve its base, post nothing unless that base is
/// protected, then check and post.
pub async fn run(bridge: &Bridge, trigger: &CheckTrigger) -> Result<CheckOutcome> {
    let Some(ctx) = check_namespace(bridge, &trigger.repo) else {
        // A required-workflow namespace (Actions runs the check), manual
        // mode, an installation without the check's permissions, or a
        // repository outside every bound namespace.
        return Ok(CheckOutcome::Skipped("not a bridge-check namespace"));
    };
    let g = ctx
        .adapter
        .github()
        .context("bridge checks are GitHub's")?
        .clone();

    // The base, from GitHub rather than the delivery wherever GitHub can say.
    let (base_ref, base_sha, pr_info) = match trigger.kind {
        CheckTriggerKind::PullRequest { number } | CheckTriggerKind::Rerequested { number } => {
            let pr = g.pull_request(&trigger.repo, number).await?;
            if !pr.open {
                return Ok(CheckOutcome::Skipped("the pull request is closed"));
            }
            if pr.head_sha != trigger.head_sha {
                // Pushed to since: the delivery for the new head checks it.
                return Ok(CheckOutcome::Skipped("the pull request has moved on"));
            }
            (pr.base_ref.clone(), pr.base_sha.clone(), Some(pr))
        }
        _ => (trigger.base_ref.clone(), trigger.base_sha.clone(), None),
    };
    check_sha(&base_sha).map_err(|e| anyhow!("{e}"))?;
    let protected = g.default_branch(&trigger.repo).await?;
    if base_ref != protected {
        // A success here would carry over to any pull request into the
        // protected branch with the same head: post nothing at all.
        return Ok(CheckOutcome::Skipped("the base branch is not protected"));
    }

    let key = (
        trigger.repo.to_string(),
        trigger.head_sha.clone(),
        base_ref.clone(),
    );
    if !bridge
        .checks
        .in_flight
        .lock()
        .expect("lock")
        .insert(key.clone())
    {
        return Ok(CheckOutcome::Skipped("the same check is already running"));
    }
    let _in_flight = InFlight {
        set: &bridge.checks.in_flight,
        key,
    };

    let check_name = bridge
        .adapters
        .vgi_for(&ctx.ns.resource)
        .map(|v| v.required_check)
        .unwrap_or_else(|| vgi_forge::DEFAULT_REQUIRED_CHECK.into());
    let _permit = bridge.checks.permits.acquire().await?;
    let external = format!("{base_ref}@{}", trigger.head_sha);
    let id = g
        .start_check_run(&trigger.repo, &trigger.head_sha, &check_name, &external)
        .await?;
    let (conclusion, title, mut summary) =
        match verify(bridge, &g, &ctx, trigger, &base_ref, &base_sha).await {
            Ok(v) => v,
            Err(e) => (
                CheckConclusion::Failure,
                "The commits could not be verified".to_string(),
                format!(
                    "The bridge could not complete the check, so it fails closed.\n\n`{}`",
                    e.to_string().replace('`', "'")
                ),
            ),
        };
    if conclusion == CheckConclusion::Failure
        && let Some(pr) = &pr_info
        && let Some(hint) = crate::resign::check_hint(bridge, &ctx, trigger, pr, &protected)
    {
        summary.push_str(&hint);
    }
    g.finish_check_run(&trigger.repo, id, conclusion, &title, &summary)
        .await?;
    // For the VTC's status report: the last check on a managed repository.
    let conclusion_word = match conclusion {
        CheckConclusion::Success => "success",
        _ => "failure",
    };
    let _ = bridge.store.update::<RepoRecord, _>(
        Table::Repos,
        &repo_key(trigger.repo.host(), trigger.repo_id),
        |r| {
            Ok((
                r.map(|mut r| {
                    r.last_check = Some(LastCheck::new(
                        trigger.head_sha.clone(),
                        conclusion_word,
                        crate::bridge::now(),
                    ));
                    r
                }),
                (),
            ))
        },
    );
    Ok(CheckOutcome::Posted(conclusion))
}

/// Tell the VTC about the check just posted on a managed repository: an
/// inspection, whose `protectionChanged` carries the complete drift the
/// event requires and, in `ext`, the last check. Throttled per repository
/// ([`REPORT_INTERVAL`]); a report already waiting picks up this check.
fn report_check(bridge: &Arc<Bridge>, t: &CheckTrigger) {
    let key = repo_key(t.repo.host(), t.repo_id);
    if !matches!(
        bridge.store.get::<RepoRecord>(Table::Repos, &key),
        Ok(Some(_))
    ) {
        return;
    }
    let delay = {
        let mut slots = bridge.checks.reports.lock().expect("lock");
        let slot = slots.entry(key.clone()).or_default();
        if slot.pending {
            return;
        }
        slot.pending = true;
        slot.last
            .map(|l| (l + REPORT_INTERVAL).saturating_duration_since(Instant::now()))
            .unwrap_or_default()
    };
    // Weak: a waiting report must not keep a stopped bridge (and its
    // store's lock) alive.
    let weak = Arc::downgrade(bridge);
    tokio::spawn(async move {
        tokio::time::sleep(delay).await;
        let Some(bridge) = weak.upgrade() else {
            return;
        };
        {
            let mut slots = bridge.checks.reports.lock().expect("lock");
            let slot = slots.entry(key.clone()).or_default();
            slot.pending = false;
            slot.last = Some(Instant::now());
        }
        let Ok(Some(rec)) = bridge.store.get::<RepoRecord>(Table::Repos, &key) else {
            return;
        };
        let Ok(ctx) = Ctx::load(&bridge, &rec.namespace) else {
            return;
        };
        let lock = bridge.ns_lock(&rec.namespace);
        let _g = lock.lock().await;
        if let Err(e) = crate::jobs::inspect_repo(&bridge, &ctx, &rec.resource, true, None).await {
            tracing::warn!(repo = %rec.resource, error = %e, "could not report a posted check");
        }
    });
}

async fn verify(
    bridge: &Bridge,
    g: &vgi_forge_github::GitHubForge,
    ctx: &Ctx,
    trigger: &CheckTrigger,
    base_ref: &str,
    base_sha: &str,
) -> Result<(CheckConclusion, String, String)> {
    let cmp = g
        .compare_commits(&trigger.repo, base_sha, &trigger.head_sha)
        .await?;
    let max = bridge.checks.max_commits;
    if cmp.total as usize > max {
        bail!(
            "{} commits are more than this bridge checks at once ({max}); split the change",
            cmp.total
        );
    }
    if (cmp.commits.len() as u64) < cmp.total {
        bail!(
            "GitHub listed {} of the {} commits; the range cannot be checked from a partial list",
            cmp.commits.len(),
            cmp.total
        );
    }
    if cmp.commits.is_empty() {
        // Nothing in `base...head`: the head is already in the base. Only
        // the base tip itself is a success; anything strictly inside the
        // base has nothing to merge, and a success on it would be one more
        // green commit for someone to reuse.
        return Ok(if trigger.head_sha == base_sha {
            (
                CheckConclusion::Success,
                format!("The head is the tip of `{base_ref}`; nothing to verify"),
                "Every commit here is already part of the protected branch.".into(),
            )
        } else {
            (
                CheckConclusion::Failure,
                format!("The head is already part of `{base_ref}`"),
                "There is nothing to merge: the head commit is already contained in the \
                 protected branch."
                    .into(),
            )
        });
    }
    let token = g.contents_read_token(&trigger.repo).await?;
    let remote = g.clone_url(&trigger.repo)?;
    let fetched = bridge
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
    let lines = bridge
        .checks
        .verifier
        .verify(&fetched.commits, resource, fallback)
        .await?;
    Ok(summarise(&lines, base_ref))
}

fn summarise(lines: &[CommitLine], base_ref: &str) -> (CheckConclusion, String, String) {
    let failed = lines.iter().filter(|l| !l.passes).count();
    let conclusion = if failed == 0 && !lines.is_empty() {
        CheckConclusion::Success
    } else {
        CheckConclusion::Failure
    };
    let title = if lines.is_empty() {
        "No commits were verified".to_string()
    } else if failed == 0 {
        format!("All {} commits are signed by trusted DIDs", lines.len())
    } else {
        format!("{failed} of {} commits are not trusted", lines.len())
    };
    let mut summary = format!(
        "Checked by the community's bridge against its Trust Registry, for merging into \
         `{base_ref}`.\n\n| Commit | Verdict |\n|---|---|\n"
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
    fn the_summary_fails_on_any_untrusted_commit_and_on_none() {
        let (c, t, s) = summarise(
            &[
                CommitLine::new("a".repeat(40), true, "trusted"),
                CommitLine::new("b".repeat(40), false, "unauthorized"),
            ],
            "main",
        );
        assert_eq!(c, CheckConclusion::Failure);
        assert_eq!(t, "1 of 2 commits are not trusted");
        assert!(s.contains("unauthorized") && s.contains("`main`"));
        let (c, _, _) = summarise(&[CommitLine::new("a".repeat(40), true, "trusted")], "main");
        assert_eq!(c, CheckConclusion::Success);
        let (c, _, _) = summarise(&[], "main");
        assert_eq!(
            c,
            CheckConclusion::Failure,
            "a verifier that saw nothing passes nothing"
        );
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
