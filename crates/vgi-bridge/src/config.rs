//! The operator's configuration: a TOML file, with a few environment
//! overrides for container deployments.
//!
//! Nothing secret goes in this file. Keys, tokens and passwords live in the
//! sealed store ([`crate::seal`]); the file names only where the master key
//! comes from. Unknown keys are refused, so a typo in a security-relevant
//! setting fails the start instead of silently falling back to a default.
//!
//! Environment overrides (applied after the file):
//! `VGI_BRIDGE_LISTEN`, `VGI_BRIDGE_DATA_DIR`, `VGI_BRIDGE_PUBLIC_URL`,
//! `VGI_BRIDGE_MASTER_KEY_FILE`, `VGI_BRIDGE_VTA_CREDENTIAL_FILE` (with a
//! `[vta]` section).

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use url::Url;
use vgi_forge::{DEFAULT_REQUIRED_CHECK, ForgeRole, Resource, RoleMap, VerifyTransport};

/// The whole file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct BridgeConfig {
    /// The one VTC this bridge serves. Jobs signed by any other DID are
    /// refused (spec: `permissionDenied`), whatever their proof.
    pub vtc_did: String,
    /// The `git-ns/bridge/event` version the bridge sends that VTC: `"0.3"`
    /// (the default), or `"0.2"` / `"0.1"` for a VTC that does not
    /// understand the newer one yet. All three are wire-identical for every
    /// forge event; 0.2 changes what the VTC does with a transfer (it
    /// detaches the repository and never moves its rights), and 0.3 adds
    /// `roleMapReported`, the role map the bridge projects rights with —
    /// which is never sent under 0.1 or 0.2, so such a VTC keeps assuming
    /// the default map. The bridge's own handling is the same either way.
    #[serde(default)]
    pub event_version: EventVersion,
    /// The community's Trust Registry, for the bootstrap plan and the
    /// bridge-posted check.
    pub trust_registry_did: String,
    /// The DIDComm mediator the bridge's DID is reachable through.
    pub mediator_did: String,
    /// The URL the forges reach the bridge at (behind the TLS proxy), e.g.
    /// `https://bridge.acme.example/`. Callback and webhook URLs are built
    /// from it.
    pub public_url: Url,
    /// Where the HTTP server listens. TLS is terminated in front of it.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Directory for the state store.
    #[serde(default = "default_data_dir")]
    pub data_dir: PathBuf,
    /// File holding the base64 master key (owner-only).
    #[serde(default)]
    pub master_key_file: Option<PathBuf>,
    /// Environment variable holding the base64 master key, when there is no
    /// file.
    #[serde(default)]
    pub master_key_env: Option<String>,
    /// VTA mode: the bridge's identity, secrets and state live in its own
    /// trust context of the VTC's VTA, and this host holds only a
    /// context-scoped credential. No master key is needed then. `None`: the
    /// self-contained mode (sealed store, local identity).
    #[serde(default)]
    pub vta: Option<VtaConfig>,
    /// Oldest `issuedAt` a job is accepted with, in seconds (plus a minute of
    /// clock skew). A stale job replayed after later ones would push the
    /// forge back to an old desired state.
    #[serde(default = "default_max_age")]
    pub max_job_age_secs: u64,
    /// Largest request body the HTTP server reads, in bytes.
    #[serde(default = "default_body_limit")]
    pub max_body_bytes: usize,
    /// How often forges without webhooks are swept for drift, in seconds.
    #[serde(default = "default_sweep")]
    pub drift_sweep_secs: u64,
    /// How often unacknowledged results and events are sent again, in
    /// seconds.
    #[serde(default = "default_resend")]
    pub resend_secs: u64,
    /// How long a resolved DID document is trusted before it is resolved
    /// again, in seconds (10–3600): the VTC's (job proofs), the registry's,
    /// and commit signers' (the bridge-posted check). It bounds how long a
    /// key its owner rotated out can still be accepted. A proof or commit
    /// that fails against a cached document is checked once more against a
    /// fresh resolution before it is refused.
    #[serde(default = "default_did_cache_ttl")]
    pub did_cache_ttl_secs: u64,
    /// How long a bind or link waits for the person, in seconds.
    #[serde(default = "default_flow_ttl")]
    pub flow_ttl_secs: u64,
    /// What the bootstrap plan writes.
    pub verify_trust: VerifyTrustConfig,
    /// The bridge-posted check.
    #[serde(default)]
    pub checks: CheckConfig,
    /// The Dependabot re-sign (§9): the committer the re-signed commits
    /// carry.
    #[serde(default)]
    pub resign: ResignConfig,
    /// Which forge role each repository right gets, for every forge this
    /// bridge serves. Each `[[github]]` / `[[forgejo]]` entry, namespace and
    /// repository can override it (see [`RoleMapConfig`]).
    #[serde(default)]
    pub role_map: RoleMapConfig,
    /// GitHub (github.com or GHES): one private App per organisation (or
    /// account), keyed by `(host, app_owner)`. GitHub installs a private App
    /// only on the account that owns it, so a community binding several
    /// organisations on one host registers one App for each; the VTC still
    /// maps the host to this one bridge.
    #[serde(default)]
    pub github: Vec<GitHubForgeConfig>,
    /// Forgejo instances, one bot each.
    #[serde(default)]
    pub forgejo: Vec<ForgejoForgeConfig>,
}

/// VTA mode (design §5.7, "The bridge works off the VTC's VTA"): where the
/// bridge's trust context is and how it authenticates to it.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VtaConfig {
    /// The context's id in the VTA (`vgi-bridge`).
    pub context: String,
    /// File holding the context credential bundle the VTA issued (JSON:
    /// `did`, `privateKeyMultibase`, `vtaDid`, optional `vtaUrl`; or the
    /// same base64-encoded). Owner-only.
    #[serde(default)]
    pub credential_file: Option<PathBuf>,
    /// Environment variable holding the bundle, when there is no file. The
    /// bridge clears it once read.
    #[serde(default)]
    pub credential_env: Option<String>,
    /// The mediator the VTA is reached through, over DIDComm. Default: the
    /// bridge's own `mediator_did`. Always DIDComm: the VTA releases a
    /// private key only over a channel confidential end to end (never over
    /// REST, where the key would exist wherever TLS terminates).
    #[serde(default)]
    pub mediator_did: Option<String>,
    /// The VTA's REST URL, when the bundle carries none: used only as the
    /// DIDComm client's fallback for unauthenticated calls.
    #[serde(default)]
    pub url: Option<Url>,
    /// The bridge's DID. `None`: the context's DID.
    #[serde(default)]
    pub did: Option<String>,
    /// Seconds start-up keeps retrying an unreachable VTA before it gives
    /// up (the bridge cannot run without its keys).
    #[serde(default = "default_vta_start_timeout")]
    pub start_timeout_secs: u64,
    /// How often the bridge asks the VTA whether its keys were rotated, in
    /// seconds (at least 30; SIGHUP asks at once). A rotation puts the new
    /// keys in service and drops the old ones.
    #[serde(default = "default_key_refresh")]
    pub key_refresh_secs: u64,
    /// Seconds a newly listed signing key must have been in the bridge's
    /// DID document before the bridge signs with it (every verifier's cached
    /// copy has it by then). Default 86400, the proposed verifier cache cap;
    /// at least `did_cache_ttl_secs`.
    #[serde(default = "default_signing_switch_after")]
    pub signing_switch_after_secs: u64,
}

fn default_signing_switch_after() -> u64 {
    86_400
}

fn default_key_refresh() -> u64 {
    60
}

fn default_vta_start_timeout() -> u64 {
    300
}

/// A `git-ns/bridge/event` version the bridge can send.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Deserialize)]
#[non_exhaustive]
pub enum EventVersion {
    /// `git-ns/bridge/event` 0.1, for a VTC that has not moved to 0.2.
    #[serde(rename = "0.1")]
    V0_1,
    /// `git-ns/bridge/event` 0.2, for a VTC that has not moved to 0.3: no
    /// role-map report.
    #[serde(rename = "0.2")]
    V0_2,
    /// `git-ns/bridge/event` 0.3: adds `roleMapReported`.
    #[default]
    #[serde(rename = "0.3")]
    V0_3,
}

impl EventVersion {
    /// Whether the VTC takes `roleMapReported` (event 0.3 and later).
    pub fn reports_role_map(self) -> bool {
        self >= EventVersion::V0_3
    }
}

/// Inputs to every bootstrap plan.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct VerifyTrustConfig {
    /// The verify-trust action reference, pinned to a commit.
    pub action: String,
    /// The release the action downloads (`v0.5.0`).
    pub version: String,
    /// SHA-256 of the release tarball (required by the Forgejo plan).
    #[serde(default)]
    pub sha256: Option<String>,
    /// The required check's name.
    #[serde(default = "default_check")]
    pub required_check: String,
    /// The Trust Registry binding: for the written workflows (the action's
    /// `transport` input) `auto` (default — TSP, then DIDComm, then HTTPS,
    /// no fallback), `tsp`, `didcomm` or `https`; for the check the bridge
    /// posts itself `auto` is DIDComm (as the bridge's own DID, over its
    /// mediator session), then HTTPS. `tsp` is refused while a GitHub forge
    /// has `bridge_checks` on: the bridge never speaks TSP. Set `https` while
    /// the registry's mediator does not admit a CI run's throwaway DID.
    #[serde(default)]
    pub transport: VerifyTransport,
}

/// Bounds on the check the bridge runs itself.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct CheckConfig {
    /// Most commits one check verifies; more fails the check (GitHub's
    /// comparison lists 250 at most anyway).
    #[serde(default = "default_max_commits")]
    pub max_commits: usize,
    /// Most distinct signer DIDs one check resolves (verify-trust's bound).
    #[serde(default = "default_max_signers")]
    pub max_signers: usize,
    /// The `git` binary used to fetch commits (never to run anything from
    /// them).
    #[serde(default = "default_git")]
    pub git: PathBuf,
    /// Seconds a fetch may take.
    #[serde(default = "default_fetch_timeout")]
    pub fetch_timeout_secs: u64,
    /// Bytes one fetch may write before it is stopped. The fetch asks for
    /// commit objects only, so this is generous for any honest range.
    #[serde(default = "default_max_fetch_bytes")]
    pub max_fetch_bytes: u64,
    /// Checks run at once; more wait.
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
}

impl Default for CheckConfig {
    fn default() -> Self {
        CheckConfig {
            max_commits: default_max_commits(),
            max_signers: default_max_signers(),
            git: default_git(),
            fetch_timeout_secs: default_fetch_timeout(),
            max_fetch_bytes: default_max_fetch_bytes(),
            concurrency: default_concurrency(),
        }
    }
}

/// The Dependabot re-sign's committer identity. The signature is the
/// bridge's DID (the `Signed-by-DID:` trailer names it); this is only the
/// name and address git and GitHub display as the committer.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ResignConfig {
    /// The committer name.
    #[serde(default = "default_committer_name")]
    pub committer_name: String,
    /// The committer email. Not a DID: the DID claim is the trailer.
    #[serde(default = "default_committer_email")]
    pub committer_email: String,
}

impl Default for ResignConfig {
    fn default() -> Self {
        ResignConfig {
            committer_name: default_committer_name(),
            committer_email: default_committer_email(),
        }
    }
}

/// Which forge role a repository right asks for (§5.8 layer 3, the
/// `role_map` community hook), as one layer of overrides.
///
/// Layers apply field by field, the most specific winning: a repository's
/// (`[<forge>.namespaces.<owner>.repos.<name>.role_map]`), then its
/// namespace's (`[<forge>.namespaces.<owner>.role_map]`), then its forge
/// entry's (`[<forge>.role_map]`), then the bridge's (`[role_map]`), then
/// the built-in default — `own = "admin"`, `maintain = "maintain"`,
/// `commit = "none"`. Each value is `none`, `read`, `triage`, `write`,
/// `maintain` or `admin`; a forge without a level rounds it down (Forgejo's
/// `maintain` is `write` plus the default branch's merge allow-list; a
/// GitHub personal account has only `write`).
///
/// Every map a layer can produce must be ordered (`own ≥ maintain ≥
/// commit`), give `admin` to nobody but `own` and keep `commit` at most
/// `write`, or the start fails: `maintain` and `commit` are rights their
/// holder may grant themselves, so neither may make them a forge admin.
///
/// **There is deliberately no key for `git.ns.admin`**: a namespace admin
/// gets no forge role (decided 2026-09-25), so none can be configured — an
/// unknown key such as `ns_admin` fails the start.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RoleMapConfig {
    /// Role for `git.repo.own`.
    #[serde(default)]
    pub own: Option<ForgeRole>,
    /// Role for `git.repo.maintain`.
    #[serde(default)]
    pub maintain: Option<ForgeRole>,
    /// Role for `git.commit.sign` (`write` opts committers in to
    /// branch-based contribution; `none`, the default, is fork PRs).
    #[serde(default)]
    pub commit: Option<ForgeRole>,
}

impl RoleMapConfig {
    /// `self` over `base`: each field `self` sets wins.
    fn over(self, base: RoleMapConfig) -> RoleMapConfig {
        RoleMapConfig {
            own: self.own.or(base.own),
            maintain: self.maintain.or(base.maintain),
            commit: self.commit.or(base.commit),
        }
    }

    /// The map these layers make, over the built-in default.
    fn resolve(layers: &[Option<RoleMapConfig>]) -> Result<RoleMap> {
        let merged = layers
            .iter()
            .flatten()
            .fold(RoleMapConfig::default(), |acc, l| l.over(acc));
        let d = RoleMap::default();
        RoleMap::new(
            merged.own.unwrap_or(d.own()),
            merged.maintain.unwrap_or(d.maintain()),
            merged.commit.unwrap_or(d.commit()),
        )
        .map_err(|e| anyhow::anyhow!(e))
    }
}

/// Per-repository settings, under
/// `[<forge>.namespaces.<owner>.repos.<name>]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct RepoConfig {
    /// This repository's role-map overrides.
    #[serde(default)]
    pub role_map: Option<RoleMapConfig>,
}

/// Per-namespace GitHub settings, under `[github.namespaces.<owner>]`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GitHubNamespaceConfig {
    /// Re-sign Dependabot pull requests in this namespace (§9). On unless
    /// turned off.
    #[serde(default = "yes")]
    pub resign_dependabot: bool,
    /// This namespace's role-map overrides.
    #[serde(default)]
    pub role_map: Option<RoleMapConfig>,
    /// Per-repository settings, keyed by the repository's name (lowercase).
    #[serde(default)]
    pub repos: BTreeMap<String, RepoConfig>,
}

impl Default for GitHubNamespaceConfig {
    fn default() -> Self {
        GitHubNamespaceConfig {
            resign_dependabot: true,
            role_map: None,
            repos: BTreeMap::new(),
        }
    }
}

/// Per-namespace Forgejo settings, under `[forgejo.namespaces.<owner>]`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ForgejoNamespaceConfig {
    /// This namespace's role-map overrides.
    #[serde(default)]
    pub role_map: Option<RoleMapConfig>,
    /// Per-repository settings, keyed by the repository's name (lowercase).
    #[serde(default)]
    pub repos: BTreeMap<String, RepoConfig>,
}

/// One GitHub App the bridge holds: its host, and the organisation (or
/// account) that owns it and whose namespaces it serves.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GitHubForgeConfig {
    /// `github.com` or the GHES host.
    #[serde(default = "default_github_host")]
    pub host: String,
    /// The App's name for the manifest (`acme-vgi-bridge`). GitHub App names
    /// are unique per GitHub instance, so every entry on a host names its
    /// own.
    pub app_name: String,
    /// The organisation (or, with `app_owner_is_user`, the personal account)
    /// the App is registered under and owned by. The manifest exchange
    /// refuses an App registered anywhere else.
    pub app_owner: String,
    /// `app_owner` is a personal account, not an organisation.
    #[serde(default)]
    pub app_owner_is_user: bool,
    /// The `web-flow` public key, armored — the exempt keyring for commits
    /// GitHub signs (web-UI merges, merge queues)
    /// (https://github.com/web-flow.gpg). Optional: the bridge-posted check
    /// needs it only to pass such commits, and the in-repo workflow and
    /// required-workflow plans refuse to plan without it. `None`: platform
    /// signed commits fail the check.
    #[serde(default)]
    pub platform_keyring_file: Option<PathBuf>,
    /// Post the check from the bridge where there is no org required
    /// workflow (§9). On by default: without it a writer can forge the check.
    #[serde(default = "yes")]
    pub bridge_checks: bool,
    /// The login GitHub reports for Dependabot, as the `sender` of its pushes
    /// and the `user` of its pull requests.
    #[serde(default = "default_dependabot_login")]
    pub dependabot_login: String,
    /// Dependabot's numeric account id, checked together with the login.
    /// `49699333` on github.com (`GET /users/dependabot[bot]`); a GHES
    /// instance has its own — look it up there.
    #[serde(default = "default_dependabot_id")]
    pub dependabot_id: u64,
    /// Role-map overrides for every namespace on this host.
    #[serde(default)]
    pub role_map: Option<RoleMapConfig>,
    /// Per-namespace settings, keyed by the owner's login (lowercase).
    #[serde(default)]
    pub namespaces: BTreeMap<String, GitHubNamespaceConfig>,
    /// Override the API base (tests, proxies).
    #[serde(default)]
    pub api_base: Option<Url>,
    /// Override the web base (tests, proxies).
    #[serde(default)]
    pub web_base: Option<Url>,
}

/// One Forgejo instance the bridge serves as one bot.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct ForgejoForgeConfig {
    /// The instance's root URL (`https://codeberg.org/`).
    pub base_url: Url,
    /// The bot user's login.
    pub bot_login: String,
    /// The bridge's OAuth2 application on the instance.
    pub oauth_client_id: String,
    /// Rotate the bot token every this many days (needs the bot password in
    /// the sealed store). `None`: rotation is the operator's.
    #[serde(default)]
    pub rotate_token_days: Option<u64>,
    /// Allow instance-signed merge commits where fast-forward-only merges
    /// are unavailable (see the adapter's `MergeFallback`).
    #[serde(default)]
    pub instance_signing_key_fallback: bool,
    /// Require this status context instead of the derived one.
    #[serde(default)]
    pub status_check_context: Option<String>,
    /// The runner label (`runs-on:`) of the workflow the bootstrap writes.
    /// `None`: the adapter's default, `docker`. Whatever label the
    /// instance's runners register; the job image needs glibc 2.39+.
    #[serde(default)]
    pub runs_on: Option<String>,
    /// Role-map overrides for every namespace on this instance.
    #[serde(default)]
    pub role_map: Option<RoleMapConfig>,
    /// Per-namespace settings, keyed by the owner's login (lowercase).
    #[serde(default)]
    pub namespaces: BTreeMap<String, ForgejoNamespaceConfig>,
}

impl ForgejoForgeConfig {
    /// The forge host resources name.
    pub fn host(&self) -> Result<String> {
        Ok(self
            .base_url
            .host_str()
            .context("Forgejo base_url has no host")?
            .to_ascii_lowercase())
    }
}

fn default_listen() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("static")
}
fn default_data_dir() -> PathBuf {
    PathBuf::from("/var/lib/vgi-bridge")
}
fn default_max_age() -> u64 {
    300
}
fn default_body_limit() -> usize {
    2 * 1024 * 1024
}
fn default_sweep() -> u64 {
    3600
}
fn default_resend() -> u64 {
    60
}
fn default_did_cache_ttl() -> u64 {
    60
}
fn default_flow_ttl() -> u64 {
    900
}
fn default_check() -> String {
    DEFAULT_REQUIRED_CHECK.into()
}
fn default_max_commits() -> usize {
    250
}
fn default_max_signers() -> usize {
    16
}
fn default_git() -> PathBuf {
    PathBuf::from("git")
}
fn default_max_fetch_bytes() -> u64 {
    64 * 1024 * 1024
}
fn default_fetch_timeout() -> u64 {
    120
}
fn default_concurrency() -> usize {
    4
}
fn default_github_host() -> String {
    "github.com".into()
}
fn default_dependabot_login() -> String {
    "dependabot[bot]".into()
}
fn default_dependabot_id() -> u64 {
    49_699_333
}
fn default_committer_name() -> String {
    "VGI bridge".into()
}
fn default_committer_email() -> String {
    "vgi-bridge@noreply.invalid".into()
}

/// A GitHub login is letters, digits and single hyphens: what is safe in a
/// route segment and a secret's name.
fn url_segment_ok(login: &str) -> bool {
    !login.is_empty()
        && login.len() <= 39
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !login.starts_with('-')
}

impl GitHubForgeConfig {
    /// The owner as the bridge keys the App by (logins are case-insensitive).
    pub fn owner_key(&self) -> String {
        self.app_owner.to_ascii_lowercase()
    }

    /// Whether the Dependabot re-sign is on for the namespace owned by
    /// `owner` (on unless `[github.namespaces.<owner>]` turns it off).
    pub fn resign_dependabot(&self, owner: &str) -> bool {
        self.namespaces
            .get(&owner.to_ascii_lowercase())
            .is_none_or(|n| n.resign_dependabot)
    }
}

/// The role-map layers for a namespace and repository: `(namespace, repos)`.
type NsLayers<'a> = (Option<RoleMapConfig>, &'a BTreeMap<String, RepoConfig>);

impl BridgeConfig {
    /// The `[[github]]` entry that serves `owner`'s namespaces on `host`: the
    /// App `owner` owns, and no other. GitHub installs a private App only on
    /// its owner, so an owner without an entry of its own has no App here.
    pub fn github_for(&self, host: &str, owner: &str) -> Option<&GitHubForgeConfig> {
        self.github
            .iter()
            .find(|g| g.host == host && g.app_owner.eq_ignore_ascii_case(owner))
    }

    /// Every `[[github]]` entry on `host`.
    pub fn github_on(&self, host: &str) -> impl Iterator<Item = &GitHubForgeConfig> {
        self.github.iter().filter(move |g| g.host == host)
    }

    /// The role map for `repo` (`host/owner/name`): its repository's,
    /// namespace's, forge entry's and the bridge's overrides over the
    /// default. A resource on a host this bridge has no entry for gets the
    /// bridge-wide map.
    pub fn role_map(&self, repo: &Resource) -> RoleMap {
        let host = repo.host();
        let owner = repo.owner().to_ascii_lowercase();
        let name = repo.repo_name().map(str::to_ascii_lowercase);
        let (forge, ns): (Option<RoleMapConfig>, Option<NsLayers<'_>>) =
            if let Some(g) = self.github_for(host, &owner) {
                (
                    g.role_map,
                    g.namespaces.get(&owner).map(|n| (n.role_map, &n.repos)),
                )
            } else if let Some(f) = self
                .forgejo
                .iter()
                .find(|f| f.host().is_ok_and(|h| h == host))
            {
                (
                    f.role_map,
                    f.namespaces.get(&owner).map(|n| (n.role_map, &n.repos)),
                )
            } else {
                (None, None)
            };
        let ns_layer = ns.and_then(|(l, _)| l);
        let repo_layer = ns
            .zip(name)
            .and_then(|((_, repos), n)| repos.get(&n))
            .and_then(|r| r.role_map);
        // Every chain was checked by `validate`, so this cannot fail on a
        // loaded config; the default is the safe answer if it ever did.
        RoleMapConfig::resolve(&[Some(self.role_map), forge, ns_layer, repo_layer])
            .unwrap_or_default()
    }

    /// The repositories with a `role_map` layer of their own in the
    /// namespace `ns` (`host/owner`), as resources (the config keys them by
    /// lowercase name). Empty on a host this bridge has no entry for.
    pub fn role_map_repos(&self, ns: &Resource) -> Vec<Resource> {
        let host = ns.host();
        let owner = ns.owner().to_ascii_lowercase();
        let repos: Option<&BTreeMap<String, RepoConfig>> =
            if let Some(g) = self.github_for(host, &owner) {
                g.namespaces.get(&owner).map(|n| &n.repos)
            } else if let Some(f) = self
                .forgejo
                .iter()
                .find(|f| f.host().is_ok_and(|h| h == host))
            {
                f.namespaces.get(&owner).map(|n| &n.repos)
            } else {
                None
            };
        repos
            .into_iter()
            .flatten()
            .filter(|(_, r)| r.role_map.is_some())
            .filter_map(|(name, _)| ns.namespace().join(name).ok())
            .collect()
    }

    /// Check every role map the layers can produce, and the keys.
    fn validate_role_maps(&self) -> Result<()> {
        let base = Some(self.role_map);
        RoleMapConfig::resolve(&[base]).context("`role_map`")?;
        let check = |what: String,
                     forge: Option<RoleMapConfig>,
                     namespaces: Vec<(&String, NsLayers<'_>)>|
         -> Result<()> {
            RoleMapConfig::resolve(&[base, forge]).with_context(|| format!("`{what}.role_map`"))?;
            for (owner, (ns, repos)) in namespaces {
                if *owner != owner.to_ascii_lowercase() {
                    bail!("`{what}.namespaces` keys are lowercase owner logins; got `{owner}`");
                }
                RoleMapConfig::resolve(&[base, forge, ns])
                    .with_context(|| format!("`{what}.namespaces.{owner}.role_map`"))?;
                for (name, repo) in repos {
                    if *name != name.to_ascii_lowercase() {
                        bail!(
                            "`{what}.namespaces.{owner}.repos` keys are lowercase repository \
                             names; got `{name}`"
                        );
                    }
                    RoleMapConfig::resolve(&[base, forge, ns, repo.role_map]).with_context(
                        || format!("`{what}.namespaces.{owner}.repos.{name}.role_map`"),
                    )?;
                }
            }
            Ok(())
        };
        for g in &self.github {
            check(
                format!("github ({}, {})", g.host, g.app_owner),
                g.role_map,
                g.namespaces
                    .iter()
                    .map(|(k, n)| (k, (n.role_map, &n.repos)))
                    .collect(),
            )?;
        }
        for f in &self.forgejo {
            check(
                format!("forgejo ({})", f.host()?),
                f.role_map,
                f.namespaces
                    .iter()
                    .map(|(k, n)| (k, (n.role_map, &n.repos)))
                    .collect(),
            )?;
        }
        Ok(())
    }
}

/// A Forgejo runner label, checked as the adapter will check it.
fn check_runs_on(label: &str) -> Result<()> {
    #[cfg(feature = "forge-forgejo")]
    vgi_forge_forgejo::plan::check_runs_on(label)?;
    #[cfg(not(feature = "forge-forgejo"))]
    let _ = label;
    Ok(())
}

/// A name or address that can go into a git `committer` header as it is.
fn check_ident(what: &str, v: &str) -> Result<()> {
    if v.trim().is_empty()
        || v.chars()
            .any(|c| matches!(c, '<' | '>' | '\n' | '\r' | '\0'))
    {
        bail!("`{what}` must be non-empty and hold no `<`, `>` or line break; got `{v}`");
    }
    Ok(())
}
fn yes() -> bool {
    true
}

impl BridgeConfig {
    /// Parse `text` and check it.
    pub fn parse(text: &str) -> Result<Self> {
        let mut cfg: BridgeConfig = toml::from_str(text).context("parsing the bridge config")?;
        cfg.fill_defaults();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Read `path`, apply the environment overrides, and check the result.
    pub fn load(path: &Path) -> Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: BridgeConfig =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.apply_env()?;
        cfg.fill_defaults();
        cfg.validate()?;
        Ok(cfg)
    }

    /// Defaults that depend on other settings.
    fn fill_defaults(&mut self) {
        if let Some(v) = self.vta.as_mut()
            && v.mediator_did.is_none()
        {
            v.mediator_did = Some(self.mediator_did.clone());
        }
    }

    fn apply_env(&mut self) -> Result<()> {
        if let Ok(v) = std::env::var("VGI_BRIDGE_LISTEN") {
            self.listen = v.parse().context("VGI_BRIDGE_LISTEN")?;
        }
        if let Ok(v) = std::env::var("VGI_BRIDGE_DATA_DIR") {
            self.data_dir = v.into();
        }
        if let Ok(v) = std::env::var("VGI_BRIDGE_PUBLIC_URL") {
            self.public_url = v.parse().context("VGI_BRIDGE_PUBLIC_URL")?;
        }
        if let Ok(v) = std::env::var("VGI_BRIDGE_MASTER_KEY_FILE") {
            self.master_key_file = Some(v.into());
        }
        if let Ok(v) = std::env::var("VGI_BRIDGE_VTA_CREDENTIAL_FILE")
            && let Some(vta) = self.vta.as_mut()
        {
            vta.credential_file = Some(v.into());
        }
        Ok(())
    }

    /// The checks a bad value would otherwise fail late on.
    pub fn validate(&self) -> Result<()> {
        for (what, did) in [
            ("vtc_did", &self.vtc_did),
            ("trust_registry_did", &self.trust_registry_did),
            ("mediator_did", &self.mediator_did),
        ] {
            if !did.starts_with("did:") || did.chars().any(char::is_whitespace) {
                bail!("`{what}` must be a DID, got `{did}`");
            }
        }
        match self.public_url.scheme() {
            "https" => {}
            "http"
                if matches!(
                    self.public_url.host_str(),
                    Some("localhost" | "127.0.0.1" | "[::1]")
                ) => {}
            s => bail!(
                "`public_url` must be https (the forges send secrets-bearing redirects and \
                 webhooks to it); got `{s}`"
            ),
        }
        if let Some(v) = &self.vta {
            if self.master_key_file.is_some() || self.master_key_env.is_some() {
                bail!(
                    "`[vta]` and a master key are both set: in VTA mode nothing is sealed into the \
                     local store (secrets live in the VTA), so remove `master_key_file` / \
                     `master_key_env`"
                );
            }
            if v.signing_switch_after_secs < self.did_cache_ttl_secs {
                bail!(
                    "`vta.signing_switch_after_secs` ({}) must be at least `did_cache_ttl_secs` \
                     ({}): a verifier's cached DID document must have the new key before the \
                     bridge signs with it",
                    v.signing_switch_after_secs,
                    self.did_cache_ttl_secs
                );
            }
            if v.context.trim().is_empty() {
                bail!("`vta.context` must name the bridge's context in the VTA");
            }
            if v.credential_file.is_none() && v.credential_env.is_none() {
                bail!("`[vta]` needs `credential_file` or `credential_env`");
            }
            for (what, did) in [("vta.mediator_did", &v.mediator_did), ("vta.did", &v.did)] {
                if let Some(did) = did
                    && (!did.starts_with("did:") || did.chars().any(char::is_whitespace))
                {
                    bail!("`{what}` must be a DID, got `{did}`");
                }
            }
            if let Some(u) = &v.url
                && u.scheme() != "https"
                && !matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"))
            {
                bail!("`vta.url` must be https (the credential handshake travels over it)");
            }
        }
        if !(10..=3600).contains(&self.did_cache_ttl_secs) {
            bail!("`did_cache_ttl_secs` must be between 10 and 3600");
        }
        if self.max_body_bytes < 64 * 1024 {
            bail!("`max_body_bytes` below 64 KiB would refuse ordinary webhooks");
        }
        if self.checks.max_commits == 0 || self.checks.max_signers == 0 {
            bail!("`checks.max_commits` and `checks.max_signers` must be at least 1");
        }
        if self.verify_trust.transport == VerifyTransport::Tsp
            && self.github.iter().any(|g| g.bridge_checks)
        {
            bail!(
                "`verify_trust.transport = \"tsp\"`: the check this bridge posts itself queries \
                 the registry over the bridge's DIDComm session or HTTPS, never TSP. Use `auto` \
                 (TSP > DIDComm > HTTPS in the written workflows; DIDComm > HTTPS for the \
                 bridge's own check), `didcomm` or `https` — or turn `bridge_checks` off"
            );
        }

        check_ident("resign.committer_name", &self.resign.committer_name)?;
        check_ident("resign.committer_email", &self.resign.committer_email)?;
        if self.resign.committer_email.starts_with("did:") {
            bail!(
                "`resign.committer_email` must not be a DID: the re-signed commits claim the \
                 bridge's DID in their `Signed-by-DID:` trailer"
            );
        }
        let mut apps = std::collections::BTreeSet::new();
        let mut names = std::collections::BTreeSet::new();
        for g in &self.github {
            Resource::namespace_of(&g.host, &g.app_owner).map_err(|e| {
                anyhow::anyhow!("github `{}` / app_owner `{}`: {e}", g.host, g.app_owner)
            })?;
            if !apps.insert((g.host.clone(), g.owner_key())) {
                bail!(
                    "two `[[github]]` entries for `{}` on `{}`: one App per organisation (or \
                     account), each its own entry",
                    g.app_owner,
                    g.host
                );
            }
            if !names.insert((g.host.clone(), g.app_name.to_ascii_lowercase())) {
                bail!(
                    "two `[[github]]` entries on `{}` name the App `{}`: GitHub App names are unique \
                     per instance, so give each organisation's App its own `app_name`",
                    g.host,
                    g.app_name
                );
            }
            if !url_segment_ok(&g.app_owner) {
                bail!("`app_owner` `{}` is not a GitHub login", g.app_owner);
            }
            if g.dependabot_login.is_empty() || g.dependabot_id == 0 {
                bail!("`dependabot_login` and `dependabot_id` must be set");
            }
        }
        let github_hosts: std::collections::BTreeSet<&str> =
            self.github.iter().map(|g| g.host.as_str()).collect();
        let mut hosts = std::collections::BTreeSet::new();
        for f in &self.forgejo {
            let host = f.host()?;
            if github_hosts.contains(host.as_str()) || !hosts.insert(host.clone()) {
                bail!("forge host `{host}` is configured twice");
            }
            if let Some(label) = &f.runs_on {
                check_runs_on(label).with_context(|| format!("forgejo ({host}) `runs_on`"))?;
            }
        }
        self.validate_role_maps()
    }

    /// A URL under `public_url`.
    pub fn url(&self, path: &str) -> Url {
        let mut base = self.public_url.clone();
        if !base.path().ends_with('/') {
            let p = format!("{}/", base.path());
            base.set_path(&p);
        }
        base.join(path.trim_start_matches('/'))
            .expect("relative path joins")
    }

    /// The flow lifetime.
    pub fn flow_ttl(&self) -> Duration {
        Duration::from_secs(self.flow_ttl_secs)
    }

    /// The state store's path.
    pub fn store_path(&self) -> PathBuf {
        self.data_dir.join("state.redb")
    }
}

/// The test config without a master key (VTA-mode tests elsewhere).
#[cfg(test)]
pub(crate) fn tests_example() -> String {
    tests::EXAMPLE.replace(
        "master_key_file = \"/run/secrets/vgi-bridge-master-key\"\n",
        "",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) const EXAMPLE: &str = r#"
vtc_did = "did:webvh:QmVtc:acme-vtc.example"
trust_registry_did = "did:webvh:QmReg:registry.acme.example"
mediator_did = "did:web:mediator.acme.example"
public_url = "https://bridge.acme.example/"
master_key_file = "/run/secrets/vgi-bridge-master-key"

[verify_trust]
action = "OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@0123456789abcdef0123456789abcdef01234567"
version = "v0.5.0"

[[github]]
app_name = "acme-vgi-bridge"
app_owner = "acme"
platform_keyring_file = "/etc/vgi-bridge/web-flow.asc"

[[forgejo]]
base_url = "https://codeberg.org/"
bot_login = "acme-vgi-bot"
oauth_client_id = "0b6e3a0c"
"#;

    #[test]
    fn the_example_parses_with_defaults() {
        let c = BridgeConfig::parse(EXAMPLE).unwrap();
        assert_eq!(c.github[0].host, "github.com");
        assert!(c.github[0].bridge_checks, "on unless turned off");
        assert_eq!(c.forgejo[0].host().unwrap(), "codeberg.org");
        assert_eq!(c.verify_trust.required_check, "Verify commit trust");
        assert_eq!(
            c.url("github/github.com/webhook").as_str(),
            "https://bridge.acme.example/github/github.com/webhook"
        );
        assert_eq!(c.checks.max_commits, 250);
        assert_eq!(c.event_version, EventVersion::V0_3, "0.3 unless set");
    }

    #[test]
    fn the_workflow_transport_defaults_to_auto_and_is_carried_into_the_plan() {
        let c = BridgeConfig::parse(EXAMPLE).unwrap();
        assert_eq!(c.verify_trust.transport, VerifyTransport::Auto);

        let pinned = EXAMPLE.replace(
            "version = \"v0.5.0\"\n",
            "version = \"v0.5.0\"\ntransport = \"https\"\n",
        );
        let c = BridgeConfig::parse(&pinned).unwrap();
        assert_eq!(c.verify_trust.transport, VerifyTransport::Https);
        assert_eq!(
            crate::registry::vgi_config(&c, None).verify_trust_transport,
            VerifyTransport::Https,
            "the written workflows carry the pin"
        );

        let bogus = EXAMPLE.replace(
            "version = \"v0.5.0\"\n",
            "version = \"v0.5.0\"\ntransport = \"carrier-pigeon\"\n",
        );
        assert!(BridgeConfig::parse(&bogus).is_err());
        // The bridge-posted check has no transport option: it is HTTPS.
        let check = EXAMPLE.replace(
            "version = \"v0.5.0\"\n",
            "version = \"v0.5.0\"\n\n[checks]\ntransport = \"didcomm\"\n",
        );
        assert!(BridgeConfig::parse(&check).is_err());
    }

    #[test]
    fn tsp_is_refused_while_the_bridge_posts_checks() {
        let tsp = EXAMPLE.replace(
            "version = \"v0.5.0\"\n",
            "version = \"v0.5.0\"\ntransport = \"tsp\"\n",
        );
        let e = BridgeConfig::parse(&tsp).unwrap_err().to_string();
        assert!(e.contains("never TSP"), "{e}");
        // With the bridge not posting checks, only the workflows use it.
        let off = tsp.replace(
            "platform_keyring_file",
            "bridge_checks = false\nplatform_keyring_file",
        );
        let c = BridgeConfig::parse(&off).unwrap();
        assert_eq!(c.verify_trust.transport, VerifyTransport::Tsp);
    }

    #[test]
    fn the_event_version_is_0_1_0_2_or_0_3() {
        let with = |v: &str| {
            BridgeConfig::parse(&EXAMPLE.replacen(
                "public_url",
                &format!("event_version = \"{v}\"\npublic_url"),
                1,
            ))
        };
        assert_eq!(with("0.1").unwrap().event_version, EventVersion::V0_1);
        assert_eq!(with("0.2").unwrap().event_version, EventVersion::V0_2);
        assert_eq!(with("0.3").unwrap().event_version, EventVersion::V0_3);
        assert!(!EventVersion::V0_2.reports_role_map());
        assert!(EventVersion::V0_3.reports_role_map());
        for bad in ["0.4", "1.0", "", "v0.2"] {
            assert!(with(bad).is_err(), "`{bad}` is refused");
        }
    }

    #[test]
    fn the_app_owner_is_required_and_the_keyring_is_not() {
        let no_owner = EXAMPLE.replace("app_owner = \"acme\"\n", "");
        assert!(BridgeConfig::parse(&no_owner).is_err());
        let no_keyring = EXAMPLE.replace(
            "platform_keyring_file = \"/etc/vgi-bridge/web-flow.asc\"\n",
            "",
        );
        let c = BridgeConfig::parse(&no_keyring).unwrap();
        assert!(c.github[0].platform_keyring_file.is_none());
    }

    #[test]
    fn vta_mode_parses_and_refuses_a_master_key_beside_it() {
        let base = EXAMPLE.replace(
            "master_key_file = \"/run/secrets/vgi-bridge-master-key\"\n",
            "",
        );
        let with = |vta: &str| BridgeConfig::parse(&format!("{base}\n[vta]\n{vta}"));
        let c = with("context = \"vgi-bridge\"\ncredential_file = \"/run/secrets/c\"").unwrap();
        let v = c.vta.clone().unwrap();
        assert_eq!(v.context, "vgi-bridge");
        assert_eq!(v.key_refresh_secs, 60);
        assert_eq!(c.did_cache_ttl_secs, 60);
        assert_eq!(
            v.mediator_did.as_deref(),
            Some("did:web:mediator.acme.example"),
            "the VTA is reached over DIDComm, through the bridge's mediator by default"
        );
        assert!(
            with("context = \"vgi-bridge\"").is_err(),
            "a credential source is required"
        );
        assert!(with("context = \"\"\ncredential_env = \"X\"").is_err());
        assert!(
            with("context = \"b\"\ncredential_env = \"X\"\nurl = \"http://vta.example\"").is_err(),
            "cleartext only to loopback"
        );
        assert!(
            with("context = \"b\"\ncredential_env = \"X\"\nmediator_did = \"mediator\"").is_err()
        );
        let err = BridgeConfig::parse(&format!(
            "{EXAMPLE}\n[vta]\ncontext = \"b\"\ncredential_env = \"X\""
        ))
        .unwrap_err();
        assert!(err.to_string().contains("master key"), "{err}");
        assert!(BridgeConfig::parse(&format!("did_cache_ttl_secs = 5\n{EXAMPLE}")).is_err());
    }

    #[test]
    fn several_apps_on_one_host_are_keyed_by_owner() {
        let second = |owner: &str, name: &str| {
            format!("{EXAMPLE}\n[[github]]\napp_name = \"{name}\"\napp_owner = \"{owner}\"\n")
        };
        let c = BridgeConfig::parse(&second("globex", "globex-vgi-bridge")).unwrap();
        assert_eq!(
            c.github_for("github.com", "ACME").unwrap().app_owner,
            "acme"
        );
        assert_eq!(
            c.github_for("github.com", "globex").unwrap().app_name,
            "globex-vgi-bridge"
        );
        assert!(
            c.github_for("github.com", "initech").is_none(),
            "no fallback with several"
        );
        assert!(c.github_for("ghe.example", "acme").is_none());
        // One App per organisation, and GitHub App names are unique.
        assert!(BridgeConfig::parse(&second("Acme", "other-name")).is_err());
        assert!(BridgeConfig::parse(&second("globex", "ACME-vgi-bridge")).is_err());
        assert!(BridgeConfig::parse(&second("glo/bex", "x")).is_err());
        // A lone App serves only its own owner.
        let one = BridgeConfig::parse(EXAMPLE).unwrap();
        assert!(one.github_for("github.com", "initech").is_none());
    }

    #[test]
    fn role_map_repos_are_the_owners_own() {
        // Two Apps on github.com, one configured repository map under the
        // second: only that organisation's report lists it.
        let text = format!(
            "{EXAMPLE}\n[[github]]\napp_name = \"globex-vgi-bridge\"\napp_owner = \"globex\"\n\n\
             [github.namespaces.globex.repos.w.role_map]\ncommit = \"write\"\n"
        );
        let c = BridgeConfig::parse(&text).unwrap();
        let listed = |ns: &str| -> Vec<String> {
            c.role_map_repos(&res(ns))
                .into_iter()
                .map(|r| r.to_string())
                .collect()
        };
        assert_eq!(listed("github.com/globex"), vec!["github.com/globex/w"]);
        assert!(listed("github.com/acme").is_empty());
    }

    #[test]
    fn the_shipped_example_parses() {
        let c = BridgeConfig::parse(include_str!("../bridge.example.toml")).unwrap();
        assert_eq!(c.github.len(), 1);
        assert!(c.forgejo.is_empty());
    }

    #[test]
    fn the_dependabot_resign_is_on_by_default_and_off_per_namespace() {
        let c = BridgeConfig::parse(EXAMPLE).unwrap();
        let g = &c.github[0];
        assert_eq!(g.dependabot_login, "dependabot[bot]");
        assert_eq!(g.dependabot_id, 49_699_333);
        assert!(g.resign_dependabot("acme"));
        assert_eq!(c.resign.committer_name, "VGI bridge");
        let off = EXAMPLE.replace(
            "[[forgejo]]",
            "[github.namespaces.acme]\nresign_dependabot = false\n\n[[forgejo]]",
        );
        let c = BridgeConfig::parse(&off).unwrap();
        assert!(!c.github[0].resign_dependabot("Acme"));
        assert!(c.github[0].resign_dependabot("other"));
        let upper = off.replace("namespaces.acme]", "namespaces.Acme]");
        assert!(BridgeConfig::parse(&upper).is_err());
        for bad in ["\"a<b\"", "\"did:key:z6Mk\"", "\"\""] {
            let t = format!("{EXAMPLE}\n[resign]\ncommitter_email = {bad}\n");
            assert!(BridgeConfig::parse(&t).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_forgejo_runner_label_defaults_and_is_checked() {
        let c = BridgeConfig::parse(EXAMPLE).unwrap();
        assert_eq!(c.forgejo[0].runs_on, None, "the adapter's default");
        let with = |label: &str| {
            BridgeConfig::parse(&EXAMPLE.replace(
                "oauth_client_id = \"0b6e3a0c\"",
                &format!("oauth_client_id = \"0b6e3a0c\"\nruns_on = {label}"),
            ))
        };
        assert_eq!(
            with("\"ubuntu-24.04\"").unwrap().forgejo[0]
                .runs_on
                .as_deref(),
            Some("ubuntu-24.04")
        );
        for bad in ["\"\"", "\"a b\"", "\"x\\nevil: 1\""] {
            assert!(with(bad).is_err(), "{bad}");
        }
    }

    fn res(s: &str) -> Resource {
        Resource::parse(s).unwrap()
    }

    #[test]
    fn the_role_map_defaults_to_the_design_projection() {
        let c = BridgeConfig::parse(EXAMPLE).unwrap();
        for r in [
            "github.com/acme/widgets",
            "codeberg.org/acme/w",
            "elsewhere.org/x/y",
        ] {
            assert_eq!(c.role_map(&res(r)), RoleMap::default(), "{r}");
        }
    }

    #[test]
    fn role_map_layers_apply_most_specific_first() {
        let text = format!(
            "{}\n{}",
            EXAMPLE.replace("[[github]]", "[role_map]\ncommit = \"read\"\n\n[[github]]"),
            r#"
[forgejo.role_map]
maintain = "write"

[forgejo.namespaces.acme.role_map]
maintain = "maintain"

[forgejo.namespaces.acme.repos.widgets.role_map]
commit = "write"
"#
        );
        let c = BridgeConfig::parse(&text).unwrap();
        use ForgeRole::*;
        let got = |r| {
            let m = c.role_map(&res(r));
            (m.own(), m.maintain(), m.commit())
        };
        // Bridge-wide only.
        assert_eq!(got("github.com/acme/widgets"), (Admin, Maintain, Read));
        // Forge entry over the bridge.
        assert_eq!(got("codeberg.org/other/widgets"), (Admin, Write, Read));
        // Namespace over the forge entry.
        assert_eq!(got("codeberg.org/acme/gadgets"), (Admin, Maintain, Read));
        // Repository over the namespace; names match case-insensitively.
        assert_eq!(got("codeberg.org/Acme/Widgets"), (Admin, Maintain, Write));
        // The repositories with a layer of their own, for the report.
        assert_eq!(
            c.role_map_repos(&res("codeberg.org/acme")),
            vec![res("codeberg.org/acme/widgets")]
        );
        assert!(c.role_map_repos(&res("codeberg.org/other")).is_empty());
        assert!(c.role_map_repos(&res("github.com/acme")).is_empty());
    }

    #[test]
    fn a_role_map_cannot_name_a_namespace_admin_or_be_out_of_order() {
        let with = |extra: &str| BridgeConfig::parse(&format!("{EXAMPLE}\n{extra}"));
        for bad in [
            // No key for `git.ns.admin`, under any spelling.
            "[role_map]\nns_admin = \"admin\"",
            "[role_map]\nadmin = \"admin\"",
            "[forgejo.namespaces.acme.role_map]\nnsAdmin = \"admin\"",
            // Out of order, or a committer above `write`.
            "[role_map]\nown = \"write\"",
            "[role_map]\ncommit = \"maintain\"",
            // Checked through every layer, not only on its own.
            "[forgejo.role_map]\nown = \"write\"\n\
             [forgejo.namespaces.acme.role_map]\nmaintain = \"maintain\"",
            "[forgejo.namespaces.acme.repos.w.role_map]\ncommit = \"triage\"\nmaintain = \"read\"",
            // Keys are lowercase.
            "[forgejo.namespaces.Acme.role_map]\nmaintain = \"write\"",
            "[forgejo.namespaces.acme.repos.W.role_map]\ncommit = \"write\"",
            "[role_map]\nmaintain = \"superuser\"",
        ] {
            assert!(with(bad).is_err(), "{bad}");
        }
        assert!(with("[role_map]\nmaintain = \"write\"\ncommit = \"write\"").is_ok());
    }

    #[test]
    fn only_an_owner_may_map_to_admin_at_any_layer() {
        let with = |extra: &str| BridgeConfig::parse(&format!("{EXAMPLE}\n{extra}"));
        for (bad, layer) in [
            ("[role_map]\nmaintain = \"admin\"", "`role_map`"),
            (
                "[role_map]\nmaintain = \"admin\"\ncommit = \"write\"",
                "`role_map`",
            ),
            ("[forgejo.role_map]\nmaintain = \"admin\"", "forgejo"),
            ("[forgejo.role_map]\ncommit = \"admin\"", "forgejo"),
            (
                "[forgejo.namespaces.acme.role_map]\nmaintain = \"admin\"",
                "acme",
            ),
            (
                "[forgejo.namespaces.acme.repos.w.role_map]\nmaintain = \"admin\"",
                "acme",
            ),
        ] {
            let err = format!("{:#}", with(bad).unwrap_err());
            assert!(err.contains("only an owner"), "{bad}: {err}");
            assert!(err.contains(layer), "{bad} names its layer: {err}");
        }
        // An owner at admin is the default, and a narrower owner is allowed.
        assert!(with("[role_map]\nown = \"admin\"").is_ok());
        assert!(with("[role_map]\nown = \"write\"\nmaintain = \"write\"").is_ok());
    }

    #[test]
    fn typos_and_unsafe_values_fail_the_start() {
        let typo = EXAMPLE.replace("mediator_did", "mediatr_did");
        assert!(BridgeConfig::parse(&typo).is_err());
        let http = EXAMPLE.replace("https://bridge", "http://bridge");
        assert!(BridgeConfig::parse(&http).is_err());
        let not_did = EXAMPLE.replace("did:webvh:QmVtc:acme-vtc.example", "acme");
        assert!(BridgeConfig::parse(&not_did).is_err());
        let twice = format!("{EXAMPLE}\n[[github]]\napp_name = \"x\"\napp_owner = \"acme\"\n");
        assert!(BridgeConfig::parse(&twice).is_err());
    }
}
