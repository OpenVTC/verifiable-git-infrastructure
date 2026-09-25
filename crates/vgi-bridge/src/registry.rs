//! The adapter registry: one [`Forge`] per Forgejo host, and one per GitHub
//! App — `(host, owner)`, since a private App serves only the account that
//! owns it.
//!
//! The core dispatches on a resource's host (and, on GitHub, its owner:
//! [`Adapters::for_resource`]) and talks to every adapter
//! through the forge-neutral [`Forge`] and [`ForgeHooks`] traits. The few
//! adapter-specific calls — GitHub's managed set, pins and check runs,
//! Forgejo's token rotation — go through [`Adapter`], so they stay in one
//! place.
//!
//! Adapters are built from the config plus the sealed store, and a GitHub
//! adapter can appear at run time (the App is registered through the
//! manifest flow while the bridge is up).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use vgi_forge::{Forge, ForgeHooks, Resource, VgiConfig};
use zeroize::Zeroizing;

use crate::config::BridgeConfig;
#[cfg(feature = "forge-forgejo")]
use crate::config::ForgejoForgeConfig;
#[cfg(feature = "forge-github")]
use crate::config::GitHubForgeConfig;
use crate::store::{NamespaceRecord, NamespaceState, Store};

/// One adapter, with its concrete type kept for the calls the trait does
/// not have.
#[derive(Clone)]
#[non_exhaustive]
pub enum Adapter {
    /// GitHub (github.com or GHES) as the community's App.
    #[cfg(feature = "forge-github")]
    GitHub(Arc<vgi_forge_github::GitHubForge>),
    /// A Forgejo instance as the community's bot.
    #[cfg(feature = "forge-forgejo")]
    Forgejo(Arc<vgi_forge_forgejo::ForgejoForge>),
}

impl std::fmt::Debug for Adapter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Adapter({})", self.forge().host())
    }
}

impl Adapter {
    /// The forge-neutral view.
    pub fn forge(&self) -> &dyn Forge {
        match self {
            #[cfg(feature = "forge-github")]
            Adapter::GitHub(g) => g.as_ref(),
            #[cfg(feature = "forge-forgejo")]
            Adapter::Forgejo(f) => f.as_ref(),
        }
    }

    /// The adapter's lifecycle hooks.
    pub fn hooks(&self) -> &dyn ForgeHooks {
        match self {
            #[cfg(feature = "forge-github")]
            Adapter::GitHub(g) => g.as_ref(),
            #[cfg(feature = "forge-forgejo")]
            Adapter::Forgejo(f) => f.as_ref(),
        }
    }

    /// The GitHub adapter, if this is one.
    #[cfg(feature = "forge-github")]
    pub fn github(&self) -> Option<&Arc<vgi_forge_github::GitHubForge>> {
        match self {
            Adapter::GitHub(g) => Some(g),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// The Forgejo adapter, if this is one.
    #[cfg(feature = "forge-forgejo")]
    pub fn forgejo(&self) -> Option<&Arc<vgi_forge_forgejo::ForgejoForge>> {
        match self {
            Adapter::Forgejo(f) => Some(f),
            #[allow(unreachable_patterns)]
            _ => None,
        }
    }

    /// Hand a stored namespace back to the adapter after a restart: the
    /// binding, and on GitHub the required-workflow availability, managed
    /// set and pin — without which its org-mode steps refuse to run.
    pub fn restore(&self, record: &NamespaceRecord) -> Result<()> {
        if record.state != NamespaceState::Bound {
            return Ok(());
        }
        let Some(binding) = &record.binding else {
            return Ok(());
        };
        match self {
            #[cfg(feature = "forge-github")]
            Adapter::GitHub(g) => {
                g.register_namespace(binding.namespace.clone())?;
                let rw = record
                    .required_workflow
                    .or(record.capabilities.as_ref().map(|c| c.required_workflow));
                if let Some(rw) = rw {
                    g.set_required_workflow(&record.resource, rw);
                }
                g.set_managed_repositories(&record.resource, record.managed.iter().copied());
                if let Some(ready) = record.bridge_checks {
                    g.set_bridge_checks_ready(&record.resource, ready);
                }
                if let Some(pin) = &record.pin {
                    g.set_required_workflow_pin(
                        &record.resource,
                        vgi_forge_github::RequiredWorkflowPin::new(
                            pin.repository_id,
                            pin.sha.clone(),
                            pin.check.clone(),
                        ),
                    );
                }
            }
            #[cfg(feature = "forge-forgejo")]
            Adapter::Forgejo(f) => {
                f.register_namespace(binding.namespace.clone())?;
            }
        }
        Ok(())
    }
}

/// What the manifest exchange produced, as sealed at
/// `github/<host>/<owner>/app`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredApp {
    /// Numeric App id.
    pub app_id: u64,
    /// The account that owns the App (lowercase), as GitHub reported it at
    /// registration. Absent in records written before several Apps per host
    /// were supported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner: Option<String>,
    /// URL slug.
    pub slug: String,
    /// OAuth client id.
    pub client_id: String,
    /// OAuth client secret.
    pub client_secret: String,
    /// Webhook HMAC secret.
    pub webhook_secret: String,
    /// The App private key, PEM.
    pub pem: String,
}

impl Drop for StoredApp {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_secret.zeroize();
        self.webhook_secret.zeroize();
        self.pem.zeroize();
    }
}

/// The sealed-secret name of the GitHub App `owner` owns on `host`.
pub fn github_app_secret(host: &str, owner: &str) -> String {
    format!("github/{host}/{}/app", owner.to_ascii_lowercase())
}

/// Where a single-App release kept its App: `github/<host>/app`.
pub fn legacy_github_app_secret(host: &str) -> String {
    format!("github/{host}/app")
}

/// The URL slug GitHub derives from an App name (lowercase, runs of anything
/// but letters and digits become one hyphen).
fn slug_of(name: &str) -> String {
    let mut out = String::new();
    for c in name.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    out.trim_matches('-').to_string()
}

/// Move a single-App release's `github/<host>/app` to the entry it belongs
/// to (`github/<host>/<owner>/app`): the only entry on the host, or the one
/// whose `app_name` is the App's (its slug). Refuses, naming the fix, when
/// it cannot tell. Idempotent; a no-op once moved.
pub fn migrate_legacy_github_secrets(cfg: &BridgeConfig, store: &Store) -> Result<()> {
    let hosts: std::collections::BTreeSet<&str> =
        cfg.github.iter().map(|g| g.host.as_str()).collect();
    for host in hosts {
        let legacy = legacy_github_app_secret(host);
        let Some(bytes) = store.get_secret(&legacy)? else {
            continue;
        };
        let app: StoredApp = serde_json::from_slice(&bytes).context("decoding the sealed App")?;
        let entries: Vec<_> = cfg.github_on(host).collect();
        let owner = if entries.len() == 1 {
            entries[0].owner_key()
        } else {
            let matching: Vec<_> = entries
                .iter()
                .filter(|g| slug_of(&g.app_name) == app.slug.to_ascii_lowercase())
                .collect();
            match matching.as_slice() {
                [g] => g.owner_key(),
                _ => anyhow::bail!(
                    "`{legacy}` holds the App `{}` from a single-App config, and none (or more than \
                     one) of the `[[github]]` entries on `{host}` has that `app_name`: set the \
                     entry of the organisation that owns it to `app_name = \"{}\"`",
                    app.slug,
                    app.slug
                ),
            }
        };
        let target = github_app_secret(host, &owner);
        if store.get_secret(&target)?.is_some() {
            anyhow::bail!(
                "both `{legacy}` and `{target}` are stored: the old single-App record is stale; \
                 remove it once you have checked `{target}` is the App in use"
            );
        }
        let mut moved = app;
        moved.owner = Some(owner.clone());
        let json = Zeroizing::new(serde_json::to_vec(&moved)?);
        store.put_secret(&target, &json)?;
        store.delete_secret(&legacy)?;
        tracing::info!(%host, %owner, "moved the GitHub App's credentials to `{target}`");
    }
    Ok(())
}

/// The sealed-secret names of a Forgejo bot's credentials.
pub fn forgejo_secret(host: &str, what: &str) -> String {
    format!("forgejo/{host}/{what}")
}

/// What an adapter is filed under: its host, and for a GitHub App the owner
/// (lowercase).
type Key = (String, Option<String>);

/// Every adapter the bridge has — one per Forgejo host, one per GitHub App —
/// with each one's bootstrap inputs.
#[derive(Default)]
pub struct Adapters {
    map: RwLock<BTreeMap<Key, Adapter>>,
    vgi: RwLock<BTreeMap<Key, VgiConfig>>,
}

impl std::fmt::Debug for Adapters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let keys: Vec<String> = self
            .map
            .read()
            .expect("lock")
            .keys()
            .map(|(h, o)| match o {
                Some(o) => format!("{h}/{o}"),
                None => h.clone(),
            })
            .collect();
        f.debug_struct("Adapters").field("adapters", &keys).finish()
    }
}

impl Adapters {
    /// No adapters.
    pub fn new() -> Self {
        Adapters::default()
    }

    /// Put `adapter` in service, with the bootstrap inputs `vgi`: a GitHub
    /// App under `owner` (the account that owns it), a Forgejo bot under its
    /// host (`owner` is `None`).
    pub fn insert(&self, adapter: Adapter, owner: Option<&str>, vgi: VgiConfig) {
        let key = (
            adapter.forge().host().to_string(),
            owner.map(str::to_ascii_lowercase),
        );
        self.vgi.write().expect("lock").insert(key.clone(), vgi);
        self.map.write().expect("lock").insert(key, adapter);
    }

    /// The key of the adapter serving `owner` on `host`: the host's (Forgejo),
    /// the App `owner` owns, or a host's only App.
    fn key_for(&self, host: &str, owner: Option<&str>) -> Option<Key> {
        let map = self.map.read().expect("lock");
        let host_key = (host.to_string(), None);
        if map.contains_key(&host_key) {
            return Some(host_key);
        }
        if let Some(o) = owner {
            let k = (host.to_string(), Some(o.to_ascii_lowercase()));
            if map.contains_key(&k) {
                return Some(k);
            }
        }
        // A host with one App keeps serving every owner there, as before
        // several Apps per host were supported (GitHub installs a private App
        // only on the account that owns it anyway).
        let mut on_host = map.keys().filter(|(h, _)| h == host);
        match (on_host.next(), on_host.next()) {
            (Some(only), None) => Some(only.clone()),
            _ => None,
        }
    }

    /// The adapter for `host` when there is exactly one there (a Forgejo
    /// host, or a GitHub host with a single App).
    pub fn get(&self, host: &str) -> Option<Adapter> {
        let k = self.key_for(host, None)?;
        self.map.read().expect("lock").get(&k).cloned()
    }

    /// The GitHub App `owner` owns on `host` (or the host's only App).
    pub fn get_github(&self, host: &str, owner: &str) -> Option<Adapter> {
        let k = self.key_for(host, Some(owner))?;
        self.map.read().expect("lock").get(&k).cloned()
    }

    /// Exactly the GitHub App `owner` owns on `host` (no single-App
    /// fallback): what a route naming the owner reaches.
    pub fn github_exact(&self, host: &str, owner: &str) -> Option<Adapter> {
        self.map
            .read()
            .expect("lock")
            .get(&(host.to_string(), Some(owner.to_ascii_lowercase())))
            .cloned()
    }

    /// The GitHub App on `host` whose numeric id is `app_id`.
    #[cfg(feature = "forge-github")]
    pub fn github_by_app_id(&self, host: &str, app_id: u64) -> Option<Adapter> {
        self.map
            .read()
            .expect("lock")
            .iter()
            .find(|((h, o), a)| {
                h == host && o.is_some() && a.github().is_some_and(|g| g.config().app_id == app_id)
            })
            .map(|(_, a)| a.clone())
    }

    /// How many adapters serve `host`.
    pub fn count_on(&self, host: &str) -> usize {
        self.map
            .read()
            .expect("lock")
            .keys()
            .filter(|(h, _)| h == host)
            .count()
    }

    /// The adapter for a resource: its host's, and on GitHub the App its
    /// owner owns.
    pub fn for_resource(&self, r: &Resource) -> Option<Adapter> {
        self.get_github(r.host(), r.owner())
    }

    /// The bootstrap inputs of the adapter serving `r`.
    pub fn vgi_for(&self, r: &Resource) -> Option<VgiConfig> {
        let k = self.key_for(r.host(), Some(r.owner()))?;
        self.vgi.read().expect("lock").get(&k).cloned()
    }

    /// Every adapter.
    pub fn all(&self) -> Vec<Adapter> {
        self.map.read().expect("lock").values().cloned().collect()
    }
}

/// The forge-neutral bootstrap inputs from the config, plus a platform
/// keyring when the forge needs one.
pub fn vgi_config(cfg: &BridgeConfig, keyring: Option<Vec<u8>>) -> VgiConfig {
    let v = &cfg.verify_trust;
    let mut out = VgiConfig::new(
        cfg.trust_registry_did.clone(),
        cfg.vtc_did.clone(),
        v.action.clone(),
        v.version.clone(),
    );
    out.required_check = v.required_check.clone();
    out = out.with_verify_trust_transport(v.transport);
    if let Some(sha) = &v.sha256 {
        out = out.with_verify_trust_sha256(sha.clone());
    }
    if let Some(k) = keyring {
        out = out.with_platform_keyring(k);
    }
    out
}

/// Read an armored keyring file.
pub fn read_keyring(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading the platform keyring {}", path.display()))
}

/// Build the GitHub adapter for `g` from its sealed App credentials, or
/// `None` if the App has not been registered yet. An App recorded as owned
/// by another account than `g.app_owner` is refused.
#[cfg(feature = "forge-github")]
pub fn build_github(
    store: &Store,
    g: &GitHubForgeConfig,
) -> Result<Option<Arc<vgi_forge_github::GitHubForge>>> {
    use vgi_forge_github::{GitHubConfig, GitHubForge, InProcessKey, Secret};
    let Some(bytes) = store.get_secret(&github_app_secret(&g.host, &g.app_owner))? else {
        return Ok(None);
    };
    let app: StoredApp = serde_json::from_slice(&bytes).context("decoding the sealed App")?;
    if let Some(owner) = &app.owner
        && !owner.eq_ignore_ascii_case(&g.app_owner)
    {
        anyhow::bail!(
            "the App stored for `{}` on `{}` is owned by `{owner}`: refusing it",
            g.app_owner,
            g.host
        );
    }
    let mut cfg = if g.host == "github.com" {
        GitHubConfig::github_com(app.app_id, app.client_id.clone(), app.slug.clone())
    } else {
        GitHubConfig::enterprise(&g.host, app.app_id, app.client_id.clone(), app.slug.clone())?
    };
    if let (Some(api), Some(web)) = (&g.api_base, &g.web_base) {
        cfg = cfg.with_endpoints(api.clone(), web.clone());
    }
    if g.bridge_checks {
        cfg = cfg.with_bridge_checks();
    }
    // The key stays in process memory from here on (the enclave signer of
    // §5.7 is the `AppKeySigner` seam when a deployment has one).
    let pem = Zeroizing::new(app.pem.clone());
    let signer = Arc::new(InProcessKey::from_pem(&pem)?);
    let forge = GitHubForge::new(cfg, signer, Secret::new(app.webhook_secret.clone()))?
        .with_client_secret(Secret::new(app.client_secret.clone()));
    Ok(Some(Arc::new(forge)))
}

/// Connect the Forgejo adapter for `f` with its sealed bot credentials.
/// `None` if the bot token is not stored yet.
#[cfg(feature = "forge-forgejo")]
pub async fn build_forgejo(
    cfg: &BridgeConfig,
    store: &Store,
    f: &ForgejoForgeConfig,
) -> Result<Option<Arc<vgi_forge_forgejo::ForgejoForge>>> {
    use vgi_forge_forgejo::{Credentials, ForgejoConfig, ForgejoForge, MergeFallback, Secret};
    let host = f.host()?;
    let secret = |what: &str| -> Result<Option<Secret>> {
        Ok(store
            .get_secret_string(&forgejo_secret(&host, what))?
            .map(|s| Secret::new(s.as_str())))
    };
    let Some(token) = secret("bot-token")? else {
        return Ok(None);
    };
    let oauth = secret("oauth-client-secret")?
        .context("the Forgejo OAuth client secret is not stored (`vgi-bridge secret set`)")?;
    let webhook = secret("webhook-secret")?
        .context("the Forgejo webhook secret is not stored (`vgi-bridge secret set`)")?;
    let mut fc = ForgejoConfig::new(
        f.base_url.clone(),
        f.bot_login.clone(),
        f.oauth_client_id.clone(),
        cfg.url(&format!("forgejo/{host}/bind")),
        cfg.url(&format!("forgejo/{host}/link")),
    )?
    .with_webhook_url(cfg.url(&format!("forgejo/{host}/webhook")));
    if f.instance_signing_key_fallback {
        fc = fc.with_merge_fallback(MergeFallback::InstanceSigningKey);
    }
    if let Some(ctx) = &f.status_check_context {
        fc = fc.with_status_check_context(ctx.clone());
    }
    if let Some(label) = &f.runs_on {
        fc = fc.with_runs_on(label.clone())?;
    }
    let mut creds = Credentials::new(token, oauth, webhook);
    if let Some(pw) = secret("bot-password")? {
        creds = creds.with_bot_password(pw);
    }
    Ok(Some(Arc::new(ForgejoForge::connect(fc, creds).await?)))
}
