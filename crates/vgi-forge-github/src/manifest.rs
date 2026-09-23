//! Registering the community's GitHub App through the manifest flow (§5.7).
//!
//! The bridge builds a manifest; the admin's browser POSTs it to GitHub (a
//! form whose `manifest` field is the JSON below) at the URL from
//! [`registration_url`]; the admin approves; GitHub redirects to
//! `redirect_url` with a one-time `code`; [`exchange_code`] trades it for
//! the App's id, private key and webhook secret. Nobody copies a key by hand.
//!
//! The permission set is fixed here, not a parameter, so every community's
//! App asks for the same reviewed set. The manifest travels through the
//! admin's browser, where it could be altered, so [`exchange_code`] checks
//! that the App GitHub actually registered holds nothing beyond these
//! permissions and refuses the credentials otherwise.
//!
//! GitHub's manifest format cannot enable the OAuth device flow; the admin
//! ticks "Enable Device Flow" on the App's settings page once, or account
//! linking reports `device_flow_disabled`.

use std::collections::BTreeMap;
use std::fmt;

use reqwest::Method;
use serde::Deserialize;
use serde_json::{Value, json};
use url::Url;
use vgi_forge::{ForgeError, Result};

use crate::api::{Api, Auth};
use crate::secret::Secret;

/// The App's permissions: repository Administration (write), Contents
/// (write, for the bootstrap commit and for pushing re-signed Dependabot
/// commits, §9), Variables (write), Metadata (read);
/// organisation Members (read) and Administration (write). No secrets,
/// Actions logs, code scanning or packages.
///
/// Organisation Administration (`organization_administration`) is for one
/// thing: the org ruleset that runs verify-trust as a **required workflow**
/// from the bridge-managed `<org>/.vgi` repository at a pinned commit (§9).
/// A `pull_request` workflow committed to the repository itself runs from
/// the pull request's own files, so a writer could edit it to pass; the
/// org ruleset takes what runs out of the pull request's reach. GitHub files
/// every `/orgs/{org}/rulesets` endpoint under this permission, at write
/// even for reads. It is always requested — the manifest is fixed per App,
/// and organisations are the recommended topology — and it also lets the
/// App edit other org settings, which is why the bind screen has to say
/// why it is there. On a personal account it grants nothing. An owner who
/// declines it gets the owner-review fallback (`missing_permissions` lists
/// it).
///
/// Checks (`checks`, write), Pull requests (`pull_requests`, read) and Merge
/// queues (`merge_queues`, read) are for one thing too: where there is no org
/// required workflow, the **bridge posts the "Verify commit trust" check
/// itself** (§9, "forged check runs"), and the repository ruleset requires
/// that check from this App's own integration id. A workflow on another
/// branch can post a check run under the GitHub Actions App — the reason a
/// check pinned to Actions is forgeable by any writer — but nothing but
/// this App's key can post one under this App. The two read permissions are
/// what GitHub requires for the `pull_request` and `merge_group` events
/// that tell the bridge when to check, and for reading a pull request's
/// current base. None of them reaches code: checks only posts check runs,
/// and the reads see pull request and queue metadata. Tokens for them are
/// minted per pull request, for that one repository.
pub const APP_PERMISSIONS: [(&str, &str); 9] = [
    ("actions_variables", "write"),
    ("administration", "write"),
    ("checks", "write"),
    ("contents", "write"),
    ("members", "read"),
    ("merge_queues", "read"),
    ("metadata", "read"),
    ("organization_administration", "write"),
    ("pull_requests", "read"),
];

/// What the bridge-posted check needs on an installation: the permissions
/// and the event subscriptions. An App registered before these were in the
/// manifest has neither until its settings are changed and each
/// installation's owner approves the change — until then the namespace
/// keeps the in-repo Actions workflow.
pub const CHECK_PERMISSIONS: [(&str, &str); 3] = [
    ("checks", "write"),
    ("merge_queues", "read"),
    ("pull_requests", "read"),
];

/// The events the bridge-posted check is triggered by (see
/// [`CHECK_PERMISSIONS`]).
pub const CHECK_EVENTS: [&str; 2] = ["merge_group", "pull_request"];

/// The events the Dependabot re-sign needs (§9, "Dependabot re-sign bot"):
/// `push`, the signed record of who moved each `dependabot/*` branch, from
/// which the bridge decides whether a branch is Dependabot's alone. GitHub
/// delivers it under Contents, which the App already holds (write, for the
/// bootstrap commit and the re-signed push). An App registered before `push`
/// was in the manifest sees no pushes, so no branch is ever clean and nothing
/// is re-signed until the owner subscribes it — failing safe.
pub const RESIGN_EVENTS: [&str; 1] = ["push"];

/// Webhook events for drift (§5.6), plus `organization` for members joining
/// and leaving the org, `pull_request` / `merge_group` / `check_run` /
/// `check_suite` so the bridge can post (and re-post, on a rerequest) the
/// check where it runs it itself, and `push` for the Dependabot re-sign's
/// provenance ledger ([`RESIGN_EVENTS`]). `installation` events are always
/// delivered to an App and need no subscription. Sorted.
pub const APP_EVENTS: [&str; 11] = [
    "branch_protection_rule",
    "check_run",
    "check_suite",
    "member",
    "membership",
    "merge_group",
    "organization",
    "pull_request",
    "push",
    "repository",
    "repository_ruleset",
];

/// Inputs to the manifest.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ManifestParams {
    /// App name, unique on GitHub (e.g. `acme-vgi-bridge`).
    pub name: String,
    /// Homepage shown on the App's page.
    pub url: String,
    /// Where GitHub delivers webhooks (the bridge).
    pub webhook_url: String,
    /// Where GitHub sends the admin after registration, with `code`.
    pub redirect_url: String,
    /// OAuth callback URLs (device flow needs none, but GitHub wants one).
    pub callback_urls: Vec<String>,
    /// Where GitHub sends the admin after an install, with
    /// `installation_id` and the bind `state` (§4.1 step 3).
    pub setup_url: Option<String>,
    /// Optional description.
    pub description: Option<String>,
}

impl ManifestParams {
    /// Parameters with one callback URL and no setup URL or description.
    pub fn new(
        name: impl Into<String>,
        url: impl Into<String>,
        webhook_url: impl Into<String>,
        redirect_url: impl Into<String>,
    ) -> Self {
        let redirect_url = redirect_url.into();
        ManifestParams {
            name: name.into(),
            url: url.into(),
            webhook_url: webhook_url.into(),
            callback_urls: vec![redirect_url.clone()],
            redirect_url,
            setup_url: None,
            description: None,
        }
    }

    /// Set the post-install setup URL.
    pub fn with_setup_url(mut self, url: impl Into<String>) -> Self {
        self.setup_url = Some(url.into());
        self
    }
}

/// The manifest JSON.
pub fn app_manifest(p: &ManifestParams) -> Value {
    let permissions: BTreeMap<_, _> = APP_PERMISSIONS.into_iter().collect();
    let mut m = json!({
        "name": p.name,
        "url": p.url,
        "hook_attributes": { "url": p.webhook_url, "active": true },
        "redirect_url": p.redirect_url,
        "callback_urls": p.callback_urls,
        // Private: only the registering org or account can install it.
        "public": false,
        "default_permissions": permissions,
        "default_events": APP_EVENTS,
        "request_oauth_on_install": false,
    });
    if let Some(setup) = &p.setup_url {
        m["setup_url"] = json!(setup);
        // Bring the admin back through the bind callback on permission
        // updates too, so an upgrade is seen rather than inferred.
        m["setup_on_update"] = json!(true);
    }
    if let Some(d) = &p.description {
        m["description"] = json!(d);
    }
    m
}

/// Where the admin's browser POSTs the manifest form: the org's settings
/// when `org` is given (the App is then owned by the org), the admin's own
/// otherwise. `state` comes back on the redirect; check it there.
pub fn registration_url(web_base: &Url, org: Option<&str>, state: &str) -> Url {
    let mut url = web_base.clone();
    {
        let mut path = url.path_segments_mut().expect("http(s) base");
        path.pop_if_empty();
        match org {
            Some(org) => path.extend(["organizations", org, "settings", "apps", "new"]),
            None => path.extend(["settings", "apps", "new"]),
        };
    }
    url.query_pairs_mut().append_pair("state", state);
    url
}

/// What registering the App produced. Holds the App private key and the
/// webhook and client secrets: zeroized on drop, never `Debug`-printed.
pub struct AppCredentials {
    /// Numeric App id.
    pub app_id: u64,
    /// URL slug (for the install page).
    pub slug: String,
    /// OAuth client id (JWT issuer, device-flow client).
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: Secret,
    /// Webhook HMAC secret.
    pub webhook_secret: Secret,
    /// The App private key, PEM. Hand it to the sealed store and drop this.
    pub pem: Secret,
    /// The account that owns the App.
    pub owner_login: Option<String>,
}

impl fmt::Debug for AppCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AppCredentials")
            .field("app_id", &self.app_id)
            .field("slug", &self.slug)
            .field("client_id", &self.client_id)
            .field("client_secret", &"<redacted>")
            .field("webhook_secret", &"<redacted>")
            .field("pem", &"<redacted>")
            .field("owner_login", &self.owner_login)
            .finish()
    }
}

#[derive(Deserialize)]
struct Conversion {
    id: u64,
    slug: String,
    client_id: String,
    client_secret: String,
    webhook_secret: Option<String>,
    pem: String,
    // Required, not defaulted: a response without these cannot be checked
    // against what the admin approved, and must not pass as "no excess".
    owner: Owner,
    permissions: BTreeMap<String, String>,
    events: Vec<String>,
    /// Not part of GitHub's documented conversion response today; checked
    /// when present so a public App is never accepted silently.
    #[serde(default)]
    public: Option<bool>,
}

/// Rank of a GitHub permission level; unknown levels rank highest so they
/// count as excess.
pub(crate) fn level_rank(level: &str) -> u8 {
    match level {
        "read" => 1,
        "write" => 2,
        _ => 3,
    }
}

/// Permissions in `granted` that the reviewed set does not allow, as
/// `name:level`.
pub(crate) fn excess_permissions(granted: &BTreeMap<String, String>) -> Vec<String> {
    granted
        .iter()
        .filter(|(name, level)| {
            APP_PERMISSIONS
                .iter()
                .find(|(n, _)| n == name)
                .is_none_or(|(_, allowed)| level_rank(level) > level_rank(allowed))
        })
        .map(|(name, level)| format!("{name}:{level}"))
        .collect()
}

/// Whether an installation with `granted` permissions and `events`
/// subscriptions can carry the bridge-posted check.
pub fn check_ready(granted: &BTreeMap<String, String>, events: &[String]) -> bool {
    CHECK_PERMISSIONS.iter().all(|(name, level)| {
        granted
            .get(*name)
            .is_some_and(|have| level_rank(have) >= level_rank(level))
    }) && CHECK_EVENTS.iter().all(|e| events.iter().any(|x| x == e))
}

/// Reviewed permissions that `granted` lacks or holds at a lower level, as
/// `name:level`.
pub(crate) fn missing_permissions(granted: &BTreeMap<String, String>) -> Vec<String> {
    APP_PERMISSIONS
        .iter()
        .filter(|(name, level)| {
            granted
                .get(*name)
                .is_none_or(|have| level_rank(have) < level_rank(level))
        })
        .map(|(name, level)| format!("{name}:{level}"))
        .collect()
}

#[derive(Deserialize)]
struct Owner {
    login: String,
}

/// Exchange the redirect's `code` for the App's credentials
/// (`POST /app-manifests/{code}/conversions`). The code is single-use and
/// expires after an hour.
///
/// `expected_owner` is the org (or user) the admin set out to register the
/// App under — the one passed to [`registration_url`]. An App registered
/// anywhere else is refused: its key would act for the wrong account.
pub async fn exchange_code(
    api_base: &Url,
    code: &str,
    expected_owner: &str,
) -> Result<AppCredentials> {
    if code.is_empty() || !code.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return Err(ForgeError::Config(
            "manifest code is not alphanumeric".into(),
        ));
    }
    let api = Api::new(
        api_base.clone(),
        api_base.clone(),
        std::time::Duration::from_secs(30),
    )?;
    let url = api.url(&["app-manifests", code, "conversions"]);
    let c: Conversion = api
        .json(Method::POST, url, Auth::None, None, "manifest conversion")
        .await?;
    // Move the secrets into zeroizing storage before anything can fail.
    let creds = AppCredentials {
        app_id: c.id,
        slug: c.slug,
        client_id: c.client_id,
        client_secret: Secret::new(c.client_secret),
        webhook_secret: Secret::new(c.webhook_secret.unwrap_or_default()),
        pem: Secret::new(c.pem),
        owner_login: Some(c.owner.login),
    };
    let refuse = |why: String| {
        Err(ForgeError::Config(format!(
            "{why}; delete App `{}` on GitHub and register again",
            creds.slug
        )))
    };

    let owner = creds.owner_login.as_deref().unwrap_or_default();
    if !owner.eq_ignore_ascii_case(expected_owner) {
        return refuse(format!(
            "the App was registered under `{owner}`, not `{expected_owner}`"
        ));
    }
    if c.public == Some(true) {
        return refuse("the registered App is public; the manifest asks for a private one".into());
    }
    let mut events = c.events;
    events.sort();
    events.dedup();
    if events != APP_EVENTS {
        return refuse(format!(
            "the registered App's events {events:?} differ from the reviewed manifest {APP_EVENTS:?}"
        ));
    }

    // Fewer permissions than reviewed is harmless (the adapter reports what
    // it cannot do); any permission beyond the set, or at a higher level, is
    // not what the admin was shown.
    let excess = excess_permissions(&c.permissions);
    if !excess.is_empty() {
        return refuse(format!(
            "the registered App has permissions beyond the reviewed manifest ({})",
            excess.join(", ")
        ));
    }
    if creds.webhook_secret.expose().is_empty() {
        return Err(ForgeError::Config(
            "GitHub returned no webhook secret; webhooks could not be verified".into(),
        ));
    }
    Ok(creds)
}
