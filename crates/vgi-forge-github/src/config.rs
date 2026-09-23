//! Adapter configuration.

use std::time::Duration;

use url::Url;
use vgi_forge::{ForgeError, Result};

/// `actions/checkout` pinned to a commit (v7.0.1), the same pin this
/// repository's own workflows use. The generated workflow references
/// actions by SHA only, like every workflow here (SEC-4045).
pub const DEFAULT_CHECKOUT_ACTION: &str =
    "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";

/// What the App JWT's `iss` claim carries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum JwtIssuer {
    /// The client id — GitHub's recommendation on github.com.
    #[default]
    ClientId,
    /// The numeric App id — for GitHub Enterprise Server releases that do
    /// not accept a client id as issuer.
    AppId,
}

/// How to reach one GitHub (github.com or a GHES instance) as one App.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct GitHubConfig {
    /// Forge host resources on this GitHub start with: `github.com`, or the
    /// GHES host.
    pub host: String,
    /// REST API base: `https://api.github.com`, `https://<ghes>/api/v3`.
    pub api_base: Url,
    /// Web base, for install pages and the OAuth device flow:
    /// `https://github.com`, `https://<ghes>`.
    pub web_base: Url,
    /// The App's numeric id.
    pub app_id: u64,
    /// The App's client id (`Iv1.…` / `Iv23…`): the JWT issuer and the
    /// device-flow client.
    pub client_id: String,
    /// The App's URL slug, for its install page.
    pub app_slug: String,
    /// Which identifier the App JWT is issued under.
    pub jwt_issuer: JwtIssuer,
    /// `uses:` reference for checkout in the generated workflow; must be
    /// pinned to a 40-hex commit.
    pub checkout_action: String,
    /// The GitHub Actions App's id, which the required status check is pinned
    /// to. `None` looks it up (`GET /apps/github-actions`) when first needed.
    /// Pinning matters: an unpinned required check is satisfied by a status
    /// *anyone with write access* posts under that name.
    pub actions_integration_id: Option<u64>,
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// One second of device-flow polling interval, as the adapter waits it.
    /// Always one second outside tests.
    pub device_poll_unit: Duration,
    /// Where no org required workflow is available (personal accounts,
    /// organisations without org rulesets), the bridge posts the check
    /// itself and the ruleset requires it from **this App** rather than
    /// from GitHub Actions (§9, "forged check runs"): a workflow on another
    /// branch can post a "Verify commit trust" run as the Actions App, but
    /// not as the community's App. The plan then commits no workflow. Off by
    /// default, so a caller with no check poster keeps the Actions workflow;
    /// the bridge turns it on.
    pub bridge_checks: bool,
}

impl GitHubConfig {
    /// github.com.
    pub fn github_com(
        app_id: u64,
        client_id: impl Into<String>,
        app_slug: impl Into<String>,
    ) -> Self {
        GitHubConfig {
            host: "github.com".into(),
            api_base: Url::parse("https://api.github.com").expect("static URL"),
            web_base: Url::parse("https://github.com").expect("static URL"),
            app_id,
            client_id: client_id.into(),
            app_slug: app_slug.into(),
            jwt_issuer: JwtIssuer::ClientId,
            checkout_action: DEFAULT_CHECKOUT_ACTION.into(),
            actions_integration_id: None,
            request_timeout: Duration::from_secs(30),
            device_poll_unit: Duration::from_secs(1),
            bridge_checks: false,
        }
    }

    /// A GitHub Enterprise Server instance at `host`.
    pub fn enterprise(
        host: &str,
        app_id: u64,
        client_id: impl Into<String>,
        app_slug: impl Into<String>,
    ) -> Result<Self> {
        let host = host.to_ascii_lowercase();
        let web_base = Url::parse(&format!("https://{host}"))
            .map_err(|e| ForgeError::Config(format!("GHES host `{host}`: {e}")))?;
        let api_base = web_base
            .join("api/v3")
            .map_err(|e| ForgeError::Config(e.to_string()))?;
        let mut cfg = GitHubConfig::github_com(app_id, client_id, app_slug);
        cfg.host = host;
        cfg.api_base = api_base;
        cfg.web_base = web_base;
        Ok(cfg)
    }

    /// Point the API and web bases elsewhere (a proxy, a test server). The
    /// host that resources must name is unchanged.
    pub fn with_endpoints(mut self, api_base: Url, web_base: Url) -> Self {
        self.api_base = api_base;
        self.web_base = web_base;
        self
    }

    /// Issue App JWTs under the numeric App id instead of the client id.
    pub fn with_app_id_issuer(mut self) -> Self {
        self.jwt_issuer = JwtIssuer::AppId;
        self
    }

    /// Pin the Actions App id instead of looking it up.
    pub fn with_actions_integration_id(mut self, id: u64) -> Self {
        self.actions_integration_id = Some(id);
        self
    }

    /// Have the bridge post the check itself where there is no org required
    /// workflow (see [`GitHubConfig::bridge_checks`]).
    pub fn with_bridge_checks(mut self) -> Self {
        self.bridge_checks = true;
        self
    }
}
