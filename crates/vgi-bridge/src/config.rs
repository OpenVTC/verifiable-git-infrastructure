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
//! `VGI_BRIDGE_MASTER_KEY_FILE`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use serde::Deserialize;
use url::Url;
use vgi_forge::{DEFAULT_REQUIRED_CHECK, Resource};

/// The whole file.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct BridgeConfig {
    /// The one VTC this bridge serves. Jobs signed by any other DID are
    /// refused (spec: `permissionDenied`), whatever their proof.
    pub vtc_did: String,
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
    /// How long a bind or link waits for the person, in seconds.
    #[serde(default = "default_flow_ttl")]
    pub flow_ttl_secs: u64,
    /// What the bootstrap plan writes.
    pub verify_trust: VerifyTrustConfig,
    /// The bridge-posted check.
    #[serde(default)]
    pub checks: CheckConfig,
    /// GitHub (github.com or GHES), one App each.
    #[serde(default)]
    pub github: Vec<GitHubForgeConfig>,
    /// Forgejo instances, one bot each.
    #[serde(default)]
    pub forgejo: Vec<ForgejoForgeConfig>,
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
            concurrency: default_concurrency(),
        }
    }
}

/// One GitHub the bridge serves as one App.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GitHubForgeConfig {
    /// `github.com` or the GHES host.
    #[serde(default = "default_github_host")]
    pub host: String,
    /// The App's name for the manifest (`acme-vgi-bridge`).
    pub app_name: String,
    /// The org to register the App under (it is then owned by the org);
    /// `None` registers it under whoever does it.
    #[serde(default)]
    pub app_owner: Option<String>,
    /// The `web-flow` public key, armored — the exempt keyring for web-UI
    /// merge commits (https://github.com/web-flow.gpg).
    pub platform_keyring_file: PathBuf,
    /// Post the check from the bridge where there is no org required
    /// workflow (§9). On by default: without it a writer can forge the check.
    #[serde(default = "yes")]
    pub bridge_checks: bool,
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
fn default_fetch_timeout() -> u64 {
    120
}
fn default_concurrency() -> usize {
    4
}
fn default_github_host() -> String {
    "github.com".into()
}
fn yes() -> bool {
    true
}

impl BridgeConfig {
    /// Parse `text` and check it.
    pub fn parse(text: &str) -> Result<Self> {
        let cfg: BridgeConfig = toml::from_str(text).context("parsing the bridge config")?;
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
        cfg.validate()?;
        Ok(cfg)
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
        if self.max_body_bytes < 64 * 1024 {
            bail!("`max_body_bytes` below 64 KiB would refuse ordinary webhooks");
        }
        if self.checks.max_commits == 0 || self.checks.max_signers == 0 {
            bail!("`checks.max_commits` and `checks.max_signers` must be at least 1");
        }
        let mut hosts = std::collections::BTreeSet::new();
        for g in &self.github {
            Resource::namespace_of(&g.host, "x")
                .map_err(|e| anyhow::anyhow!("github host `{}`: {e}", g.host))?;
            if !hosts.insert(g.host.clone()) {
                bail!("forge host `{}` is configured twice", g.host);
            }
        }
        for f in &self.forgejo {
            let host = f.host()?;
            if !hosts.insert(host.clone()) {
                bail!("forge host `{host}` is configured twice");
            }
        }
        Ok(())
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
    }

    #[test]
    fn the_shipped_example_parses() {
        let c = BridgeConfig::parse(include_str!("../bridge.example.toml")).unwrap();
        assert_eq!(c.github.len(), 1);
        assert!(c.forgejo.is_empty());
    }

    #[test]
    fn typos_and_unsafe_values_fail_the_start() {
        let typo = EXAMPLE.replace("mediator_did", "mediatr_did");
        assert!(BridgeConfig::parse(&typo).is_err());
        let http = EXAMPLE.replace("https://bridge", "http://bridge");
        assert!(BridgeConfig::parse(&http).is_err());
        let not_did = EXAMPLE.replace("did:webvh:QmVtc:acme-vtc.example", "acme");
        assert!(BridgeConfig::parse(&not_did).is_err());
        let twice =
            format!("{EXAMPLE}\n[[github]]\napp_name = \"x\"\nplatform_keyring_file = \"/k\"\n");
        assert!(BridgeConfig::parse(&twice).is_err());
    }
}
