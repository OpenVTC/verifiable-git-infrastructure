//! Adapter configuration and credentials.

use std::fmt;
use std::time::Duration;

use url::Url;
use vgi_forge::{ForgeError, Result};

use crate::secret::Secret;

/// `actions/checkout` v4.4.0, by full URL and commit. Full URL because a
/// Forgejo runner resolves a bare `owner/repo` against the instance's own
/// default actions host; v4 because it runs on `node20`, which every
/// forgejo-runner supports (v5+ needs `node24`).
pub const DEFAULT_CHECKOUT_ACTION: &str =
    "https://github.com/actions/checkout@11d5960a326750d5838078e36cf38b85af677262";

/// Where a bare `owner/repo[/path]@sha` action reference is resolved: the
/// verify-trust action lives on GitHub.
pub const DEFAULT_ACTIONS_BASE: &str = "https://github.com";

/// The runner label the verify-trust job asks for.
pub const DEFAULT_RUNS_ON: &str = "docker";

/// The organisation team the bot is put in at bind.
pub const DEFAULT_TEAM: &str = "vgi-bridge";

/// What to do when the instance cannot restrict merges to fast-forward only
/// (Forgejo before 7, Gitea before 1.22).
///
/// Fast-forward-only merges land the PR's own DID-signed commits unchanged,
/// so no platform key is needed. Without it, every web merge makes a new
/// commit that the check never saw, and the only way that commit passes a
/// later verification is if the instance signs it and its key is exempted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum MergeFallback {
    /// Refuse: the merge-settings step fails with instructions to upgrade.
    #[default]
    Fail,
    /// Allow instance-made merge commits only, commit the instance's signing
    /// key (`GET /api/v1/signing-key.gpg`, fetched when the adapter probes
    /// the instance) as the exempt keyring, and pass `exempt-keyring` to the
    /// action. The instance must sign merges (`[repository.signing]`).
    InstanceSigningKey,
}

/// How to reach one Forgejo (or Gitea) instance as one bot user.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ForgejoConfig {
    /// Forge host resources on this instance start with: `codeberg.org`,
    /// `git.example.org`. Derived from `base_url`; override it only when
    /// the bridge reaches the instance through another name.
    pub host: String,
    /// The instance's root URL, e.g. `https://codeberg.org/` (or
    /// `https://example.org/git/` under a sub-path). The API is
    /// `<base_url>/api/v1`; OAuth lives under `<base_url>/login/oauth`.
    pub base_url: Url,
    /// The bot user's login (`acme-vgi-bot`). The token must belong to it.
    pub bot_login: String,
    /// The bridge's OAuth2 application on this instance (confidential).
    pub oauth_client_id: String,
    /// Redirect URI for namespace binds (registered on the OAuth app).
    pub bind_redirect_uri: Url,
    /// Redirect URI for account links (registered on the OAuth app).
    pub link_redirect_uri: Url,
    /// OAuth `scope` to request, when the instance grants scoped OAuth
    /// tokens (`[oauth2] ENABLE_ADDITIONAL_GRANT_SCOPES`). `None` asks for
    /// no scope: such a token has the admin's (or member's) full access, so
    /// the adapter uses it for a handful of calls and wipes it.
    pub oauth_scope: Option<String>,
    /// Where the instance delivers the org webhook (the bridge). `None`
    /// creates no webhook; drift is then found by the scheduled sweep only.
    pub webhook_url: Option<Url>,
    /// The org team the bot is put in.
    pub team_name: String,
    /// `uses:` for checkout in the generated workflow: a full URL pinned to
    /// a 40-hex commit.
    pub checkout_action: String,
    /// Base URL for a bare `owner/repo[/path]@sha` verify-trust reference.
    pub actions_base: Url,
    /// The runner label (`runs-on:`). The job image needs glibc 2.39+
    /// (Ubuntu 24.04, Debian 13) for the verify-trust Linux binary.
    pub runs_on: String,
    /// The status-check context branch protection requires. Forgejo names a
    /// job's status `<workflow name> / <job name> (<event>)`; `None` derives
    /// it from the check name the plan gives both, i.e. `Verify commit trust
    /// / Verify commit trust (pull_request)`. Set it when a completed run
    /// reports something else.
    pub status_check_context: Option<String>,
    /// What to do on an instance without fast-forward-only merges.
    pub merge_fallback: MergeFallback,
    /// Deliver `TRUST_REGISTRY_DID` / `VTC_DID` as Actions variables rather
    /// than writing them into the workflow. Off by default, for two reasons:
    /// Forgejo lets only a repository *owner* (the org's Owners team) manage
    /// variables, which the bot — an admin through its team — is not; and a
    /// value in the workflow can only change through a pull request, which
    /// the protected paths refuse, while an owner can re-point a variable at
    /// another registry without one. Turn it on only if the bot is an owner.
    pub use_actions_variables: bool,
    /// Per-request timeout.
    pub request_timeout: Duration,
    /// How long an account-link `state` stays valid.
    pub link_state_ttl: Duration,
}

impl ForgejoConfig {
    /// An instance at `base_url`, with the bot and OAuth app named.
    ///
    /// Plain `http` is refused except on a loopback host: the bot token is
    /// long-lived and travels on every request.
    pub fn new(
        base_url: Url,
        bot_login: impl Into<String>,
        oauth_client_id: impl Into<String>,
        bind_redirect_uri: Url,
        link_redirect_uri: Url,
    ) -> Result<Self> {
        let host = base_url
            .host_str()
            .ok_or_else(|| ForgeError::Config(format!("instance URL `{base_url}` has no host")))?
            .to_ascii_lowercase();
        let loopback = matches!(host.as_str(), "localhost" | "127.0.0.1" | "[::1]");
        match base_url.scheme() {
            "https" => {}
            "http" if loopback => {}
            s => {
                return Err(ForgeError::Config(format!(
                    "instance URL `{base_url}`: `{s}` is not allowed (https, or http on loopback)"
                )));
            }
        }
        let mut base_url = base_url;
        if !base_url.path().ends_with('/') {
            let path = format!("{}/", base_url.path());
            base_url.set_path(&path);
        }
        base_url.set_query(None);
        base_url.set_fragment(None);
        let bot_login = bot_login.into();
        check_login(&bot_login)?;
        Ok(ForgejoConfig {
            host: host.trim_start_matches('[').trim_end_matches(']').into(),
            base_url,
            bot_login,
            oauth_client_id: oauth_client_id.into(),
            bind_redirect_uri,
            link_redirect_uri,
            oauth_scope: None,
            webhook_url: None,
            team_name: DEFAULT_TEAM.into(),
            checkout_action: DEFAULT_CHECKOUT_ACTION.into(),
            actions_base: Url::parse(DEFAULT_ACTIONS_BASE).expect("static URL"),
            runs_on: DEFAULT_RUNS_ON.into(),
            status_check_context: None,
            merge_fallback: MergeFallback::Fail,
            use_actions_variables: false,
            request_timeout: Duration::from_secs(30),
            link_state_ttl: Duration::from_secs(15 * 60),
        })
    }

    /// Name resources on this instance with `host` instead of the URL's.
    pub fn with_host(mut self, host: impl Into<String>) -> Self {
        self.host = host.into().to_ascii_lowercase();
        self
    }

    /// Have the bind create (or update) an org webhook to `url`.
    pub fn with_webhook_url(mut self, url: Url) -> Self {
        self.webhook_url = Some(url);
        self
    }

    /// Require this status-check context instead of the derived one.
    pub fn with_status_check_context(mut self, context: impl Into<String>) -> Self {
        self.status_check_context = Some(context.into());
        self
    }

    /// Choose the fallback for instances without fast-forward-only merges.
    pub fn with_merge_fallback(mut self, fallback: MergeFallback) -> Self {
        self.merge_fallback = fallback;
        self
    }

    /// Deliver the DIDs as Actions variables (see
    /// [`ForgejoConfig::use_actions_variables`]: needs the bot to be an owner).
    pub fn with_actions_variables(mut self) -> Self {
        self.use_actions_variables = true;
        self
    }

    /// The API root, `<base_url>/api/v1`.
    pub(crate) fn api_base(&self) -> Url {
        self.base_url.join("api/v1").expect("relative join")
    }

    /// The status context for a job named `check` in a workflow of the same
    /// name, triggered by `pull_request`.
    pub fn status_context(&self, check: &str) -> String {
        self.status_check_context
            .clone()
            .unwrap_or_else(|| format!("{check} / {check} (pull_request)"))
    }
}

/// How the bot token is rotated — an explicit choice, because Forgejo only
/// mints and deletes access tokens under **basic** authentication (the
/// `/users/{name}/tokens` endpoints refuse token auth), so rotation without a
/// human means the bridge holds the bot's password too.
#[non_exhaustive]
pub enum TokenRotation {
    /// The bridge holds only the token. Rotating is an operator's job: mint a
    /// new token for the bot with [`crate::BOT_TOKEN_SCOPES`] and hand it to
    /// [`crate::ForgejoForge::replace_token`], which verifies it before use.
    Manual,
    /// The bridge also holds the bot's password (sealed like the App key on
    /// GitHub) and rotates on its own with
    /// [`crate::ForgejoForge::mint_token`] and
    /// [`crate::ForgejoForge::retire_token`]. The bot must not have 2FA
    /// enabled, which Forgejo requires for basic auth.
    WithPassword(Secret),
}

impl fmt::Debug for TokenRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenRotation::Manual => f.write_str("Manual"),
            TokenRotation::WithPassword(_) => f.write_str("WithPassword(<redacted>)"),
        }
    }
}

/// Everything secret the adapter holds. Every field zeroizes on drop and
/// prints as `<redacted>`.
#[non_exhaustive]
pub struct Credentials {
    /// The bot's access token.
    pub bot_token: Secret,
    /// How it is rotated.
    pub rotation: TokenRotation,
    /// The OAuth application's client secret.
    pub oauth_client_secret: Secret,
    /// The org webhook's HMAC secret.
    pub webhook_secret: Secret,
}

impl Credentials {
    /// Credentials with manual token rotation.
    pub fn new(bot_token: Secret, oauth_client_secret: Secret, webhook_secret: Secret) -> Self {
        Credentials {
            bot_token,
            rotation: TokenRotation::Manual,
            oauth_client_secret,
            webhook_secret,
        }
    }

    /// Let the adapter rotate the token itself with the bot's password.
    pub fn with_bot_password(mut self, password: Secret) -> Self {
        self.rotation = TokenRotation::WithPassword(password);
        self
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("bot_token", &self.bot_token)
            .field("rotation", &self.rotation)
            .field("oauth_client_secret", &self.oauth_client_secret)
            .field("webhook_secret", &self.webhook_secret)
            .finish()
    }
}

/// A Forgejo login: what the instance allows in a user or org name. Checked
/// before a login goes into a URL path segment or a protection allow-list.
pub(crate) fn check_login(login: &str) -> Result<()> {
    let ok = !login.is_empty()
        && login.len() <= 40
        && login
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
        && !login.starts_with('.')
        && login != "..";
    if ok {
        Ok(())
    } else {
        Err(ForgeError::Protocol(format!(
            "`{login}` is not a valid Forgejo login"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn host_and_api_come_from_the_base_url() {
        let c = ForgejoConfig::new(
            url("https://Git.Example.org/forgejo"),
            "acme-vgi-bot",
            "cid",
            url("https://bridge/bind"),
            url("https://bridge/link"),
        )
        .unwrap();
        assert_eq!(c.host, "git.example.org");
        assert_eq!(
            c.api_base().as_str(),
            "https://git.example.org/forgejo/api/v1"
        );
        assert_eq!(
            c.status_context("Verify commit trust"),
            "Verify commit trust / Verify commit trust (pull_request)"
        );
    }

    #[test]
    fn plain_http_only_on_loopback() {
        let new =
            |u| ForgejoConfig::new(url(u), "bot", "cid", url("https://b/1"), url("https://b/2"));
        assert!(new("http://git.example.org").is_err());
        assert!(new("http://127.0.0.1:3000").is_ok());
        assert!(new("http://localhost:3000").is_ok());
        assert!(new("ftp://git.example.org").is_err());
    }

    #[test]
    fn credentials_never_print() {
        let c = Credentials::new(Secret::new("t0k"), Secret::new("cs"), Secret::new("wh"))
            .with_bot_password(Secret::new("pw"));
        let shown = format!("{c:?}");
        for s in ["t0k", "cs", "wh", "pw"] {
            assert!(!shown.contains(s), "{shown}");
        }
    }
}
