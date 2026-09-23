//! The adapter registry: one [`Forge`] per forge host.
//!
//! The core dispatches on a resource's host and talks to every adapter
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
/// `github/<host>/app`.
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StoredApp {
    /// Numeric App id.
    pub app_id: u64,
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

/// The sealed-secret name of a GitHub App's credentials.
pub fn github_app_secret(host: &str) -> String {
    format!("github/{host}/app")
}

/// The sealed-secret names of a Forgejo bot's credentials.
pub fn forgejo_secret(host: &str, what: &str) -> String {
    format!("forgejo/{host}/{what}")
}

/// Every adapter the bridge has, by host, with each host's bootstrap
/// inputs.
#[derive(Default)]
pub struct Adapters {
    map: RwLock<BTreeMap<String, Adapter>>,
    vgi: RwLock<BTreeMap<String, VgiConfig>>,
}

impl std::fmt::Debug for Adapters {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hosts: Vec<String> = self.map.read().expect("lock").keys().cloned().collect();
        f.debug_struct("Adapters").field("hosts", &hosts).finish()
    }
}

impl Adapters {
    /// No adapters.
    pub fn new() -> Self {
        Adapters::default()
    }

    /// Put `adapter` in service for its host, with the bootstrap inputs
    /// `vgi`.
    pub fn insert(&self, adapter: Adapter, vgi: VgiConfig) {
        let host = adapter.forge().host().to_string();
        self.vgi.write().expect("lock").insert(host.clone(), vgi);
        self.map.write().expect("lock").insert(host, adapter);
    }

    /// The adapter for `host`.
    pub fn get(&self, host: &str) -> Option<Adapter> {
        self.map.read().expect("lock").get(host).cloned()
    }

    /// The adapter for a resource's host.
    pub fn for_resource(&self, r: &Resource) -> Option<Adapter> {
        self.get(r.host())
    }

    /// The bootstrap inputs for `host`.
    pub fn vgi(&self, host: &str) -> Option<VgiConfig> {
        self.vgi.read().expect("lock").get(host).cloned()
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
/// `None` if the App has not been registered yet.
#[cfg(feature = "forge-github")]
pub fn build_github(
    store: &Store,
    g: &GitHubForgeConfig,
) -> Result<Option<Arc<vgi_forge_github::GitHubForge>>> {
    use vgi_forge_github::{GitHubConfig, GitHubForge, InProcessKey, Secret};
    let Some(bytes) = store.get_secret(&github_app_secret(&g.host))? else {
        return Ok(None);
    };
    let app: StoredApp = serde_json::from_slice(&bytes).context("decoding the sealed App")?;
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
    let mut creds = Credentials::new(token, oauth, webhook);
    if let Some(pw) = secret("bot-password")? {
        creds = creds.with_bot_password(pw);
    }
    Ok(Some(Arc::new(ForgejoForge::connect(fc, creds).await?)))
}
