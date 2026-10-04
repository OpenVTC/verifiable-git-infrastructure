//! `vgi-bridge setup`: one folder holding everything a bridge needs to run,
//! written without root.
//!
//! The command finds what it can — the VTC's Trust Registry and mediator
//! from the VTC's DID document, the verify-trust commit for this release
//! from GitHub, GitHub's `web-flow` key — asks for what it cannot (the
//! public URL, the organisation), provisions the bridge's VTA credential the
//! way `did-git-sign init` does, and writes:
//!
//! ```text
//! <dir>/bridge.toml          the config, every path in it absolute
//! <dir>/vta-credential.json  the context-scoped VTA credential (0600)
//! <dir>/web-flow.asc         GitHub's web-flow key (GitHub only)
//! <dir>/data/                the state store (0700)
//! <dir>/vgi-bridge.service   or org.openvtc.vgi-bridge.plist, or compose.yml
//! ```
//!
//! This module holds the pieces that can be checked without a VTA or a
//! network — rendering, discovery from a document, the URL rule, file
//! writing — and the network steps (resolution, the GitHub lookups, the VTA
//! provisioning and the DID minting) as separate functions. `main` strings
//! them together.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use url::Url;
use vta_sdk::credentials::CredentialBundle;
use zeroize::Zeroizing;

use crate::vta::Session;

/// The VTA context the bridge's DID, keys and state live in by default.
pub const DEFAULT_CONTEXT: &str = "vgi-bridge";
/// The default listener: loopback, behind a TLS proxy or tunnel on the same
/// host.
pub const DEFAULT_LISTEN: &str = "127.0.0.1:8080";
/// Where the verify-trust action and its releases live.
pub const VGI_REPO: &str = "OpenVTC/verifiable-git-infrastructure";
/// The action's path inside [`VGI_REPO`].
pub const ACTION_PATH: &str = ".github/actions/verify-trust";
/// GitHub's REST API.
pub const GITHUB_API: &str = "https://api.github.com";
/// GitHub's `web-flow` signing key.
pub const WEB_FLOW_URL: &str = "https://github.com/web-flow.gpg";
/// The launchd label (and the plist's file name, with `.plist`).
pub const LAUNCHD_LABEL: &str = "org.openvtc.vgi-bridge";
/// The container image `compose.yml` names (built from
/// `crates/vgi-bridge/Dockerfile`).
pub const IMAGE: &str = "vgi-bridge";

/// The release tag this binary is: the verify-trust release its bootstrap
/// writes into repositories.
pub fn release_tag() -> String {
    format!("v{}", env!("CARGO_PKG_VERSION"))
}

/// Which service manager runs the bridge.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ServiceKind {
    /// A systemd `--user` unit (Linux).
    Systemd,
    /// A launchd agent (macOS).
    Launchd,
    /// A Compose file for the container image.
    Docker,
    /// Nothing: print the command to run.
    None,
}

impl ServiceKind {
    /// The usual manager on this OS: launchd on macOS, systemd on Linux,
    /// none elsewhere.
    pub fn for_this_os() -> Self {
        if cfg!(target_os = "macos") {
            ServiceKind::Launchd
        } else if cfg!(target_os = "linux") {
            ServiceKind::Systemd
        } else {
            ServiceKind::None
        }
    }
}

/// Which forge the first entry is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ForgeChoice {
    /// GitHub (github.com or GHES): a `[[github]]` entry.
    Github,
    /// A Forgejo instance: a `[[forgejo]]` entry.
    Forgejo,
}

/// The files of a setup folder.
#[derive(Debug, Clone)]
pub struct Layout {
    dir: PathBuf,
}

impl Layout {
    /// The folder `dir`, which must be absolute.
    pub fn new(dir: impl Into<PathBuf>) -> Result<Self> {
        let dir = dir.into();
        if !dir.is_absolute() {
            bail!(
                "the setup folder must be an absolute path, got {}",
                dir.display()
            );
        }
        check_path_chars(&dir)?;
        Ok(Layout { dir })
    }
    /// The folder.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
    /// `bridge.toml`.
    pub fn config(&self) -> PathBuf {
        self.dir.join("bridge.toml")
    }
    /// The state store's directory.
    pub fn data(&self) -> PathBuf {
        self.dir.join("data")
    }
    /// The VTA credential (VTA mode).
    pub fn credential(&self) -> PathBuf {
        self.dir.join("vta-credential.json")
    }
    /// The master key (self-contained mode).
    pub fn master_key(&self) -> PathBuf {
        self.dir.join("master-key")
    }
    /// GitHub's web-flow key.
    pub fn web_flow(&self) -> PathBuf {
        self.dir.join("web-flow.asc")
    }
    /// The log the service manager appends to.
    pub fn log(&self) -> PathBuf {
        self.dir.join("bridge.log")
    }
    /// The service file `kind` writes, if any.
    pub fn service_file(&self, kind: ServiceKind) -> Option<PathBuf> {
        match kind {
            ServiceKind::Systemd => Some(self.dir.join("vgi-bridge.service")),
            ServiceKind::Launchd => Some(self.dir.join(format!("{LAUNCHD_LABEL}.plist"))),
            ServiceKind::Docker => Some(self.dir.join("compose.yml")),
            ServiceKind::None => None,
        }
    }
}

/// Refuse a path the service files cannot carry as it is: whitespace,
/// quotes, `\`, `$`, `%` (a systemd specifier), `` ` ``, or a control
/// character. Pick another folder rather than have a unit that runs
/// something else.
fn check_path_chars(p: &Path) -> Result<()> {
    let s = p
        .to_str()
        .with_context(|| format!("{} is not UTF-8", p.display()))?;
    if let Some(c) = s.chars().find(|c| {
        c.is_whitespace() || c.is_control() || matches!(c, '"' | '\'' | '\\' | '$' | '%' | '`')
    }) {
        bail!(
            "the setup folder `{s}` holds `{}`, which the service files cannot carry safely; \
             choose a folder without spaces, quotes, `\\`, `$`, `%` or backticks",
            c.escape_default()
        );
    }
    Ok(())
}

/// Create `dir` (owner-only when it is new) and return it absolute and
/// canonical.
pub fn prepare_dir(dir: &Path) -> Result<Layout> {
    let abs = if dir.is_absolute() {
        dir.to_path_buf()
    } else {
        std::env::current_dir()?.join(dir)
    };
    if !abs.exists() {
        create_private_dir(&abs)?;
    }
    let canon = abs
        .canonicalize()
        .with_context(|| format!("resolving {}", abs.display()))?;
    if !canon.is_dir() {
        bail!("{} is not a directory", canon.display());
    }
    Layout::new(canon)
}

/// `create_dir_all`, the last component owner-only.
pub fn create_private_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| format!("restricting {}", dir.display()))?;
    }
    Ok(())
}

/// Write `bytes` to `path` with `mode`. Without `overwrite`, an existing
/// file is refused. The bytes go to a temporary file in the same folder
/// first, so a failure never leaves a half-written file at `path`.
pub fn write_file(path: &Path, bytes: &[u8], mode: u32, overwrite: bool) -> Result<()> {
    use std::io::Write;
    let parent = path.parent().context("a file needs a parent folder")?;
    let mut tmp = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("creating a temporary file in {}", parent.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    let _ = mode;
    tmp.write_all(bytes)
        .and_then(|()| tmp.as_file().sync_all())
        .with_context(|| format!("writing {}", path.display()))?;
    if overwrite {
        tmp.persist(path)
            .map_err(|e| anyhow!("writing {}: {}", path.display(), e.error))?;
    } else {
        tmp.persist_noclobber(path).map_err(|e| {
            anyhow!(
                "{} already exists ({}); pass --force to replace it",
                path.display(),
                e.error
            )
        })?;
    }
    Ok(())
}

/// Write the VTA credential, owner-only (`0600`), in the form the bridge's
/// `credential_file` reads (the bundle's JSON).
pub fn write_credential(path: &Path, cred: &CredentialBundle, overwrite: bool) -> Result<()> {
    let json = Zeroizing::new(serde_json::to_vec_pretty(cred)?);
    write_file(path, &json, 0o600, overwrite)
}

/// A public URL the bridge accepts: https, or plain http to loopback only
/// (the same rule the config enforces).
pub fn check_public_url(s: &str) -> Result<Url> {
    let url: Url = s
        .trim()
        .parse()
        .with_context(|| format!("`{s}` is not a URL"))?;
    if url.host_str().is_none_or(str::is_empty) {
        bail!("`{s}` names no host");
    }
    match url.scheme() {
        "https" => {}
        "http" if matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) => {}
        other => bail!(
            "the public URL must be https (GitHub sends secrets-bearing redirects and webhooks to \
             it; plain http only for localhost), got `{other}`"
        ),
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("the public URL must not carry a query or fragment: `{s}`");
    }
    Ok(url)
}

/// What a VTC's DID document says about the community.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Discovered {
    /// The `TrustRegistry` referral.
    pub registry: Option<String>,
    /// The mediator of its `TSPTransport` (else `DIDCommMessaging`) service.
    pub mediator: Option<String>,
}

/// Read the registry and mediator from a VTC's DID document.
pub fn discover(doc: &Value) -> Discovered {
    Discovered {
        registry: vgi_core::registry_referral(doc),
        mediator: vgi_core::messaging_mediator(doc),
    }
}

/// Resolve `did` to its current document.
pub async fn resolve_document(did: &str) -> Result<Value> {
    use affinidi_tdk::did_resolver::DIDCacheClient;
    use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;
    let resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .context("building the DID resolver")?;
    let r = resolver
        .resolve(did)
        .await
        .map_err(|e| anyhow!("resolving `{did}`: {e}"))?;
    Ok(serde_json::to_value(&r.doc)?)
}

fn http_client(https_only: bool) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("vgi-bridge/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        .https_only(https_only)
        .build()
        .context("HTTP client")
}

async fn fetch_text(url: &str, accept: &str) -> Result<String> {
    let resp = http_client(url.starts_with("https://"))?
        .get(url)
        .header("Accept", accept)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("fetching {url}: HTTP {status}");
    }
    resp.text().await.with_context(|| format!("reading {url}"))
}

/// The `object` a git ref or annotated tag points at: its type and sha.
fn git_object(v: &Value) -> Result<(String, String)> {
    let obj = v.get("object").context("no `object` in GitHub's reply")?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .context("no object type in GitHub's reply")?;
    let sha = obj
        .get("sha")
        .and_then(Value::as_str)
        .context("no object sha in GitHub's reply")?;
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("`{sha}` is not a commit sha");
    }
    Ok((kind.to_string(), sha.to_ascii_lowercase()))
}

/// The commit the tag `tag` of [`VGI_REPO`] names, through the GitHub API at
/// `api_base` (unauthenticated): the tag ref, an annotated tag dereferenced.
pub async fn resolve_tag_commit(api_base: &str, tag: &str) -> Result<String> {
    if tag.is_empty()
        || !tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        bail!("`{tag}` is not a release tag");
    }
    let api = format!("{}/repos/{VGI_REPO}/git", api_base.trim_end_matches('/'));
    let json = |url: String| async move {
        let text = fetch_text(&url, "application/vnd.github+json").await?;
        serde_json::from_str::<Value>(&text).with_context(|| format!("{url} is not JSON"))
    };
    let mut obj = git_object(&json(format!("{api}/ref/tags/{tag}")).await?)?;
    // A tag of a tag of …, followed a few levels.
    for _ in 0..5 {
        if obj.0 != "tag" {
            break;
        }
        obj = git_object(&json(format!("{api}/tags/{}", obj.1)).await?)?;
    }
    match obj {
        (kind, sha) if kind == "commit" => Ok(sha),
        (kind, _) => bail!("the tag {tag} names a {kind}, not a commit"),
    }
}

/// The action reference pinned to `sha`.
pub fn action_ref(sha: &str) -> String {
    format!("{VGI_REPO}/{ACTION_PATH}@{sha}")
}

/// GitHub's web-flow key (armored), from `url`.
pub async fn fetch_web_flow(url: &str) -> Result<String> {
    let text = fetch_text(url, "*/*").await?;
    if !text.contains("BEGIN PGP PUBLIC KEY BLOCK") {
        bail!("{url} did not return an armored PGP public key");
    }
    Ok(text)
}

/// How the bridge holds its identity and secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mode {
    /// VTA mode: its own context in the VTC's VTA, a credential on disk.
    Vta {
        /// The context id.
        context: String,
        /// The mediator the VTA is reached through, when it is not the
        /// bridge's own.
        vta_mediator: Option<String>,
    },
    /// A sealed store and a local identity, under a master key on disk.
    SelfContained,
}

/// The forge entry the config starts with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForgeEntry {
    /// One GitHub App.
    GitHub {
        /// `github.com` or the GHES host.
        host: String,
        /// The organisation (or account) owning the App.
        owner: String,
        /// The App's name.
        app_name: String,
        /// `owner` is a personal account.
        owner_is_user: bool,
        /// Whether `web-flow.asc` was written (else the line is left
        /// commented, with how to fill it).
        keyring: bool,
    },
    /// One Forgejo bot.
    Forgejo {
        /// The instance's root URL.
        base_url: Url,
        /// The bot's login.
        bot_login: String,
        /// The bridge's OAuth2 application on the instance.
        oauth_client_id: String,
    },
}

impl ForgeEntry {
    /// The forge host the VTC's `[git_ns] bridges` keys this bridge by.
    pub fn host(&self) -> String {
        match self {
            ForgeEntry::GitHub { host, .. } => host.clone(),
            ForgeEntry::Forgejo { base_url, .. } => {
                base_url.host_str().unwrap_or_default().to_ascii_lowercase()
            }
        }
    }
}

/// The default App name for `owner`.
pub fn default_app_name(owner: &str) -> String {
    format!("{}-vgi-bridge", owner.to_ascii_lowercase())
}

/// Everything `bridge.toml` is rendered from.
#[derive(Debug, Clone)]
pub struct ConfigInputs {
    /// The folder.
    pub layout: Layout,
    /// The VTC served.
    pub vtc_did: String,
    /// The community's Trust Registry.
    pub trust_registry_did: String,
    /// The mediator the bridge is reachable through.
    pub mediator_did: String,
    /// Where the forges reach the bridge.
    pub public_url: Url,
    /// The plain-HTTP listener.
    pub listen: SocketAddr,
    /// VTA or self-contained.
    pub mode: Mode,
    /// The verify-trust release.
    pub verify_trust_version: String,
    /// The pinned action, when GitHub answered.
    pub verify_trust_action: Option<String>,
    /// The first forge entry.
    pub forge: ForgeEntry,
}

/// A TOML string literal.
fn q(s: &str) -> String {
    toml::Value::String(s.to_string()).to_string()
}

fn qp(p: &Path) -> String {
    q(&p.to_string_lossy())
}

/// Render `bridge.toml`. Every path is absolute, under the setup folder.
pub fn render_config(i: &ConfigInputs) -> String {
    let l = &i.layout;
    let mut out = String::new();
    let mut line = |s: &str| {
        out.push_str(s);
        out.push('\n');
    };
    line(&format!(
        "# VGI bridge configuration, written by `vgi-bridge setup` ({}).",
        release_tag()
    ));
    line("# Re-run setup with --force to regenerate it, or edit it by hand: every key");
    line("# is described in crates/vgi-bridge/bridge.example.toml and docs/BRIDGE.md.");
    line("# Nothing secret is in this file.");
    line("");
    line("# The one VTC this bridge serves (jobs signed by any other DID are refused).");
    line(&format!("vtc_did = {}", q(&i.vtc_did)));
    line("# The community's Trust Registry (the VTC's TrustRegistry referral).");
    line(&format!(
        "trust_registry_did = {}",
        q(&i.trust_registry_did)
    ));
    line("# The mediator the bridge's DID is reachable through (the VTC's).");
    line(&format!("mediator_did = {}", q(&i.mediator_did)));
    line("");
    line("# Where the forges reach the bridge: must be HTTPS (a TLS proxy or tunnel in");
    line("# front of `listen`).");
    line(&format!("public_url = {}", q(i.public_url.as_str())));
    line("# Plain HTTP: only the proxy or tunnel on this host may reach it.");
    line(&format!("listen = {}", q(&i.listen.to_string())));
    line(&format!("data_dir = {}", qp(&l.data())));
    line("");
    match &i.mode {
        Mode::SelfContained => {
            line("# Self-contained mode: the master key that seals every secret in the store.");
            line("# Back it up apart from data_dir.");
            line(&format!("master_key_file = {}", qp(&l.master_key())));
            line("");
        }
        Mode::Vta { .. } => {}
    }
    line("[verify_trust]");
    line("# What the bootstrap writes into repositories: this release's verify-trust");
    line("# action, pinned to the release tag's commit.");
    match &i.verify_trust_action {
        Some(a) => line(&format!("action = {}", q(a))),
        None => {
            line(&format!(
                "# TODO: pin the action to the commit of {} — fill in the 40-hex sha from",
                i.verify_trust_version
            ));
            line(&format!(
                "#   gh api repos/{VGI_REPO}/commits/{} --jq .sha",
                i.verify_trust_version
            ));
            line(&format!(
                "action = {}",
                q(&format!("{VGI_REPO}/{ACTION_PATH}@<40-hex commit>"))
            ));
        }
    }
    line(&format!("version = {}", q(&i.verify_trust_version)));
    line("");
    if let Mode::Vta {
        context,
        vta_mediator,
    } = &i.mode
    {
        line("# VTA mode (BRIDGE.md §2a): the bridge's DID, keys, secrets and state live in");
        line("# its own context of the VTC's VTA; this folder holds only the credential.");
        line("[vta]");
        line(&format!("context = {}", q(context)));
        line(&format!("credential_file = {}", qp(&l.credential())));
        if let Some(m) = vta_mediator {
            line("# The VTA's own mediator (it is not the bridge's).");
            line(&format!("mediator_did = {}", q(m)));
        }
        line("");
    }
    match &i.forge {
        ForgeEntry::GitHub {
            host,
            owner,
            app_name,
            owner_is_user,
            keyring,
        } => {
            line("# The GitHub App this bridge registers for the organisation (or account).");
            line("# Another organisation: copy the entry with its own app_owner and app_name.");
            line("[[github]]");
            line(&format!("host = {}", q(host)));
            line(&format!("app_name = {}", q(app_name)));
            line(&format!("app_owner = {}", q(owner)));
            if *owner_is_user {
                line("app_owner_is_user = true");
            }
            line("# GitHub's web-flow key: the exempt keyring for commits GitHub signs.");
            if *keyring {
                line(&format!("platform_keyring_file = {}", qp(&l.web_flow())));
            } else {
                line(&format!(
                    "# TODO: curl -fsSL {WEB_FLOW_URL} > {}",
                    l.web_flow().display()
                ));
                line(&format!("# platform_keyring_file = {}", qp(&l.web_flow())));
            }
        }
        ForgeEntry::Forgejo {
            base_url,
            bot_login,
            oauth_client_id,
        } => {
            line("# The Forgejo instance this bridge serves as one bot (BRIDGE.md §4).");
            line("[[forgejo]]");
            line(&format!("base_url = {}", q(base_url.as_str())));
            line(&format!("bot_login = {}", q(bot_login)));
            line(&format!("oauth_client_id = {}", q(oauth_client_id)));
        }
    }
    out
}

/// The command that runs the bridge on this folder.
pub fn run_command(exe: &Path, layout: &Layout) -> String {
    format!(
        "{} --config {} run",
        exe.display(),
        layout.config().display()
    )
}

/// A systemd `--user` unit.
pub fn render_systemd(exe: &Path, layout: &Layout) -> String {
    let log = layout.log();
    format!(
        "# Written by `vgi-bridge setup`. Install and start it with:\n\
         #   systemctl --user enable --now {unit}\n\
         [Unit]\n\
         Description=VGI bridge ({dir})\n\
         Wants=network-online.target\n\
         After=network-online.target\n\
         \n\
         [Service]\n\
         ExecStart=\"{exe}\" --config {config} run\n\
         # SIGHUP: ask the VTA at once whether the bridge's keys were rotated.\n\
         ExecReload=/bin/kill -HUP $MAINPID\n\
         WorkingDirectory={dir}\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         UMask=0077\n\
         NoNewPrivileges=yes\n\
         StandardOutput=append:{log}\n\
         StandardError=append:{log}\n\
         \n\
         [Install]\n\
         WantedBy=default.target\n",
        unit = layout
            .service_file(ServiceKind::Systemd)
            .expect("systemd writes a file")
            .display(),
        dir = layout.dir().display(),
        exe = exe.display(),
        config = layout.config().display(),
        log = log.display(),
    )
}

/// XML text escaping.
fn xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// A launchd agent.
pub fn render_launchd(exe: &Path, layout: &Layout) -> String {
    let e = |p: &Path| xml(&p.to_string_lossy());
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- Written by `vgi-bridge setup`. -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{LAUNCHD_LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exe}</string>
    <string>--config</string>
    <string>{config}</string>
    <string>run</string>
  </array>
  <key>WorkingDirectory</key>
  <string>{dir}</string>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <dict>
    <key>SuccessfulExit</key>
    <false/>
  </dict>
  <key>ThrottleInterval</key>
  <integer>10</integer>
  <key>Umask</key>
  <integer>63</integer>
  <key>StandardOutPath</key>
  <string>{log}</string>
  <key>StandardErrorPath</key>
  <string>{log}</string>
</dict>
</plist>
"#,
        exe = e(exe),
        config = e(&layout.config()),
        dir = e(layout.dir()),
        log = e(&layout.log()),
    )
}

/// A Compose file for the container image. The folder is mounted at the same
/// path inside the container, so `bridge.toml`'s absolute paths hold there
/// too: read-only, with `data/` writable.
pub fn render_compose(layout: &Layout, listen: SocketAddr, uid: u32, gid: u32) -> String {
    let dir = layout.dir().display();
    let data = layout.data();
    let port = listen.port();
    format!(
        "# Written by `vgi-bridge setup`. Build the image from a checkout of\n\
         # {VGI_REPO}:\n\
         #   docker build -f crates/vgi-bridge/Dockerfile -t {IMAGE} .\n\
         # then start it from this folder:\n\
         #   docker compose up -d\n\
         # Logs: `docker compose logs -f`.\n\
         services:\n\
         \x20 vgi-bridge:\n\
         \x20   image: {IMAGE}\n\
         \x20   restart: unless-stopped\n\
         \x20   # Runs as you, so it can read this folder's owner-only files. The image's\n\
         \x20   # own user is uid 10001: to run as that instead (Linux), drop this line and\n\
         \x20   #   sudo chown -R 10001:10001 {dir}\n\
         \x20   user: \"{uid}:{gid}\"\n\
         \x20   command: [\"--config\", \"{config}\", \"run\"]\n\
         \x20   environment:\n\
         \x20     VGI_BRIDGE_CONFIG: \"{config}\"\n\
         \x20     # Inside the container the bridge listens on every interface; the\n\
         \x20     # port is published on this host's loopback only.\n\
         \x20     VGI_BRIDGE_LISTEN: \"0.0.0.0:{port}\"\n\
         \x20   volumes:\n\
         \x20     - \"{dir}:{dir}:ro\"\n\
         \x20     - \"{data}:{data}\"\n\
         \x20   ports:\n\
         \x20     - \"127.0.0.1:{port}:{port}\"\n",
        config = layout.config().display(),
        data = data.display(),
    )
}

/// The commands that install and start the service `kind` wrote.
pub fn service_steps(kind: ServiceKind, exe: &Path, layout: &Layout) -> Vec<String> {
    match kind {
        ServiceKind::Systemd => {
            let unit = layout.service_file(kind).expect("a file");
            vec![
                format!("systemctl --user enable --now {}", unit.display()),
                "loginctl enable-linger \"$USER\"   # keep it running while you are logged out"
                    .into(),
                format!("tail -f {}", layout.log().display()),
            ]
        }
        ServiceKind::Launchd => {
            let plist = layout.service_file(kind).expect("a file");
            let agent = format!("~/Library/LaunchAgents/{LAUNCHD_LABEL}.plist");
            vec![
                format!("cp {} {agent}", plist.display()),
                format!("launchctl bootstrap gui/$(id -u) {agent}"),
                format!("tail -f {}", layout.log().display()),
            ]
        }
        ServiceKind::Docker => vec![
            format!("docker build -f crates/vgi-bridge/Dockerfile -t {IMAGE} .   # in a checkout"),
            format!("cd {} && docker compose up -d", layout.dir().display()),
            "docker compose logs -f".into(),
        ],
        ServiceKind::None => vec![format!(
            "{} 2>>{}",
            run_command(exe, layout),
            layout.log().display()
        )],
    }
}

/// The two `pnm` commands that authorise the setup DID in the VTA: one for a
/// new context, one for an existing one. The hand-off is required: the setup
/// DID is rolled over to a long-term admin (`ProvisionAsk::vta_admin_rotated`),
/// which the VTA allows only for a grant made with it.
pub fn pnm_grant_commands(context: &str, setup_did: &str) -> String {
    format!(
        "  If the context `{context}` does not exist yet:\n    \
         pnm contexts create --id {context} --name \"vgi-bridge\" \\\n        \
         --admin-did {setup_did} --admin-expires 1h --admin-handoff\n\n  \
         If it already exists:\n    \
         pnm acl create --did {setup_did} --role admin --contexts {context} \\\n        \
         --expires 1h --handoff"
    )
}

/// Provision the bridge's context credential: authenticate as `setup_key`
/// (which the operator has granted with [`pnm_grant_commands`]) over TSP or
/// DIDComm and have the VTA roll it over to a long-term admin scoped to
/// `context`. Progress is printed as it happens.
pub async fn provision_credential(
    vta_did: &str,
    context: &str,
    setup_key: &vta_sdk::provision_client::EphemeralSetupKey,
) -> Result<CredentialBundle> {
    use vta_sdk::provision_client::{
        AdminCredentialReply, DiagStatus, ProvisionAsk, VtaEvent, VtaIntent, VtaReply,
        run_connection_test,
    };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VtaEvent>();
    let ask = ProvisionAsk::vta_admin_rotated(context.to_string()).with_label("vgi-bridge");
    let setup_did = setup_key.did.clone();
    let setup_priv = setup_key.private_key_multibase().to_string();
    let runner_vta = vta_did.to_string();
    tokio::spawn(async move {
        run_connection_test(
            VtaIntent::AdminRotated,
            runner_vta,
            setup_did,
            setup_priv,
            ask,
            None,
            tx,
        )
        .await;
    });
    let mut admin: Option<AdminCredentialReply> = None;
    let mut failure = None;
    while let Some(ev) = rx.recv().await {
        match ev {
            VtaEvent::CheckStart(c) => println!("  · {}…", c.label()),
            VtaEvent::CheckDone(c, status) => match status {
                DiagStatus::Ok(d) => println!("  ok {} — {d}", c.label()),
                DiagStatus::Skipped(d) => println!("  -- {} (skipped: {d})", c.label()),
                DiagStatus::Failed(d) => println!("  !! {} — {d}", c.label()),
                DiagStatus::Pending | DiagStatus::Running => {}
            },
            VtaEvent::Connected {
                reply: VtaReply::AdminOnly(a),
                ..
            } => admin = Some(a),
            VtaEvent::Failed(reason) => failure = Some(reason),
            _ => {}
        }
    }
    if let Some(reason) = failure {
        bail!("provisioning the bridge's VTA credential failed: {reason}");
    }
    let a = admin.context("provisioning ended without a credential")?;
    Ok(CredentialBundle::new(
        a.admin_did,
        a.admin_private_key_mb,
        vta_did,
    ))
}

/// The bridge's DID in its context: the context's DID if it has one, else a
/// `did:webvh` minted into it now — on the VTA's did:webvh hosting server
/// (`webvh_server`, or the only one the VTA has), with a `DIDCommMessaging`
/// and a `TSPTransport` service naming the VTA's mediator. `(did, minted)`.
pub async fn ensure_bridge_did(
    session: &Session,
    webvh_server: Option<&str>,
) -> Result<(String, bool)> {
    if let Some(did) = session.context_did().await? {
        return Ok((did, false));
    }
    let client = session.client();
    let server_id = match webvh_server {
        Some(s) => s.to_string(),
        None => {
            let servers = client
                .list_webvh_servers()
                .await
                .map_err(|e| {
                    anyhow!(
                        "listing the VTA's did:webvh hosting servers: {e}; pass --webvh-server \
                         <id> (`pnm webvh servers list` on the VTA)"
                    )
                })?
                .servers;
            match servers.as_slice() {
                [one] => one.id.clone(),
                [] => bail!(
                    "the context `{}` has no DID and the VTA has no did:webvh hosting server to \
                     mint one on: register one, or provision the bridge's DID into the context \
                     by hand (BRIDGE.md, \"Manual configuration\")",
                    session.context()
                ),
                many => bail!(
                    "the VTA has several did:webvh hosting servers ({}); pass --webvh-server <id>",
                    many.iter()
                        .map(|s| s.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            }
        }
    };
    let req = vta_sdk::client::CreateDidWebvhRequest {
        context_id: session.context().to_string(),
        server_id: Some(server_id),
        url: None,
        path: None,
        path_mode: None,
        domain: None,
        label: Some("vgi-bridge".into()),
        portable: false,
        add_mediator_service: true,
        add_tsp_service: true,
        additional_services: None,
        pre_rotation_count: 0,
        did_document: None,
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template: None,
        template_context: None,
        template_vars: Default::default(),
    };
    let created = client.create_did_webvh(req).await.map_err(|e| {
        anyhow!(
            "minting the bridge's did:webvh in `{}`: {e}",
            session.context()
        )
    })?;
    Ok((created.did, true))
}

/// What to print at the end: the DID, the VTC line, how to start, the URL
/// rule and the App registration.
pub fn summary(
    bridge_did: &str,
    forge: &ForgeEntry,
    public_url: &Url,
    listen: SocketAddr,
    start: &[String],
    config: &Path,
) -> String {
    let host = forge.host();
    let mut s = String::new();
    s.push_str(&format!("\nThe bridge's DID:\n  {bridge_did}\n\n"));
    s.push_str("Next:\n\n");
    s.push_str("1. Start the bridge:\n");
    for c in start {
        s.push_str(&format!("     {c}\n"));
    }
    s.push_str(&format!(
        "\n2. On the VTC host, add this to the VTC's config, then restart the VTC:\n\n     \
         [git_ns]\n     bridges = {{ {} = {} }}\n\n",
        q(&host),
        q(bridge_did)
    ));
    s.push_str(&format!(
        "3. Make {public_url} reach this host's {listen} over HTTPS: a TLS proxy, or a tunnel \
         such as cloudflared, ngrok or Tailscale Funnel. Prefer a stable hostname: GitHub's \
         callback and webhook URLs are built from it, and changing it means re-registering.\n\n"
    ));
    match forge {
        ForgeEntry::GitHub { owner, .. } => {
            let register = Url::parse(public_url.as_str())
                .ok()
                .and_then(|u| {
                    let base = if u.path().ends_with('/') {
                        u
                    } else {
                        let mut u = u;
                        let p = format!("{}/", u.path());
                        u.set_path(&p);
                        u
                    };
                    base.join(&format!("github/{host}/{owner}/register")).ok()
                })
                .map(|u| u.to_string())
                .unwrap_or_default();
            s.push_str(&format!(
                "4. Register the GitHub App: once the bridge runs, its log shows a one-time link\n     \
                 {register}?state=…\n   which an owner of `{owner}` opens (SETUP-GITHUB-VTC.md §3).\n"
            ));
        }
        ForgeEntry::Forgejo { .. } => {
            s.push_str(&format!(
                "4. Give the bridge its Forgejo bot's token (BRIDGE.md §4):\n     \
                 vgi-bridge --config {} secret set forgejo/{host}/bot-token < token.txt\n",
                config.display()
            ));
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BridgeConfig;
    use serde_json::json;

    fn layout() -> Layout {
        Layout::new("/home/ops/vgi-bridge").unwrap()
    }

    fn github(keyring: bool) -> ForgeEntry {
        ForgeEntry::GitHub {
            host: "github.com".into(),
            owner: "acme".into(),
            app_name: default_app_name("Acme"),
            owner_is_user: false,
            keyring,
        }
    }

    fn inputs(mode: Mode, forge: ForgeEntry) -> ConfigInputs {
        ConfigInputs {
            layout: layout(),
            vtc_did: "did:webvh:QmVtc:acme-vtc.example".into(),
            trust_registry_did: "did:webvh:QmReg:registry.acme.example".into(),
            mediator_did: "did:web:mediator.acme.example".into(),
            public_url: check_public_url("https://bridge.acme.example/").unwrap(),
            listen: DEFAULT_LISTEN.parse().unwrap(),
            mode,
            verify_trust_version: "v0.15.1".into(),
            verify_trust_action: Some(action_ref(&"a".repeat(40))),
            forge,
        }
    }

    fn vta_mode() -> Mode {
        Mode::Vta {
            context: DEFAULT_CONTEXT.into(),
            vta_mediator: None,
        }
    }

    #[test]
    fn the_vta_mode_config_parses_with_absolute_paths() {
        let text = render_config(&inputs(vta_mode(), github(true)));
        let c = BridgeConfig::parse(&text).unwrap();
        assert_eq!(c.data_dir, PathBuf::from("/home/ops/vgi-bridge/data"));
        assert!(c.listen.ip().is_loopback());
        assert!(c.master_key_file.is_none());
        let v = c.vta.as_ref().unwrap();
        assert_eq!(v.context, "vgi-bridge");
        assert_eq!(
            v.credential_file.as_deref(),
            Some(Path::new("/home/ops/vgi-bridge/vta-credential.json"))
        );
        assert_eq!(
            v.mediator_did.as_deref(),
            Some("did:web:mediator.acme.example"),
            "the bridge's own mediator by default"
        );
        let g = &c.github[0];
        assert_eq!(g.app_name, "acme-vgi-bridge");
        assert_eq!(g.app_owner, "acme");
        assert_eq!(
            g.platform_keyring_file.as_deref(),
            Some(Path::new("/home/ops/vgi-bridge/web-flow.asc"))
        );
        assert_eq!(c.verify_trust.version, "v0.15.1");
        assert!(c.verify_trust.action.ends_with(&"a".repeat(40)));
        for path in [
            c.data_dir.clone(),
            v.credential_file.clone().unwrap(),
            g.platform_keyring_file.clone().unwrap(),
        ] {
            assert!(path.is_absolute(), "{}", path.display());
        }
        assert!(!text.contains("/etc/") && !text.contains("/var/") && !text.contains("/run/"));
    }

    #[test]
    fn a_separate_vta_mediator_and_a_personal_account_are_written() {
        let mut forge = github(false);
        if let ForgeEntry::GitHub { owner_is_user, .. } = &mut forge {
            *owner_is_user = true;
        }
        let mode = Mode::Vta {
            context: "bridge".into(),
            vta_mediator: Some("did:web:vta-mediator.example".into()),
        };
        let mut i = inputs(mode, forge);
        i.verify_trust_action = None;
        let text = render_config(&i);
        assert!(text.contains("TODO: pin the action"), "{text}");
        assert!(text.contains("TODO: curl -fsSL"), "{text}");
        let c = BridgeConfig::parse(&text).unwrap();
        assert_eq!(
            c.vta.unwrap().mediator_did.as_deref(),
            Some("did:web:vta-mediator.example")
        );
        assert!(c.github[0].app_owner_is_user);
        assert!(c.github[0].platform_keyring_file.is_none());
    }

    #[test]
    fn the_self_contained_config_names_a_master_key_in_the_folder() {
        let text = render_config(&inputs(Mode::SelfContained, github(true)));
        let c = BridgeConfig::parse(&text).unwrap();
        assert!(c.vta.is_none());
        assert_eq!(
            c.master_key_file.as_deref(),
            Some(Path::new("/home/ops/vgi-bridge/master-key"))
        );
    }

    #[test]
    fn a_forgejo_entry_parses() {
        let forge = ForgeEntry::Forgejo {
            base_url: "https://codeberg.org/".parse().unwrap(),
            bot_login: "acme-vgi-bot".into(),
            oauth_client_id: "0b6e3a0c".into(),
        };
        assert_eq!(forge.host(), "codeberg.org");
        let c = BridgeConfig::parse(&render_config(&inputs(vta_mode(), forge))).unwrap();
        assert_eq!(c.forgejo[0].bot_login, "acme-vgi-bot");
        assert!(c.github.is_empty());
    }

    #[test]
    fn strings_are_escaped_not_spliced() {
        let mut i = inputs(vta_mode(), github(true));
        i.vtc_did = "did:web:x\"\nmaster_key_env = \"X".into();
        let text = render_config(&i);
        // The value stays one string: the config refuses it as a DID rather
        // than reading a second key out of it.
        let err = BridgeConfig::parse(&text).unwrap_err();
        assert!(format!("{err:#}").contains("vtc_did"), "{err:#}");
    }

    #[test]
    fn the_public_url_must_be_https_unless_loopback() {
        assert!(check_public_url("https://bridge.example/").is_ok());
        assert!(check_public_url("http://localhost:8080/").is_ok());
        assert!(check_public_url("http://127.0.0.1:8080").is_ok());
        for bad in [
            "http://bridge.example/",
            "ftp://bridge.example/",
            "bridge.example",
            "https://bridge.example/?x=1",
            "https://bridge.example/#f",
            "http://127.0.0.2/",
        ] {
            assert!(check_public_url(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn folders_the_service_files_cannot_carry_are_refused() {
        assert!(Layout::new("relative/dir").is_err());
        for bad in [
            "/home/o ps/b",
            "/home/ops/b$x",
            "/home/ops/%h",
            "/home/ops/\"b",
            "/home/ops/b\nx",
        ] {
            assert!(Layout::new(bad).is_err(), "{bad:?}");
        }
        assert!(Layout::new("/Users/ops/vgi-bridge.acme_1").is_ok());
    }

    #[test]
    fn discovery_reads_the_registry_and_the_mediator() {
        let doc = json!({
            "id": "did:webvh:QmVtc:acme-vtc.example",
            "service": [
                { "id": "#didcomm", "type": "DIDCommMessaging",
                  "serviceEndpoint": [{ "uri": "did:web:mediator.acme.example", "accept": ["didcomm/v2"] }] },
                { "id": "#tsp", "type": "TSPTransport", "serviceEndpoint": "did:web:mediator.acme.example" },
                { "id": "#registry", "type": "TrustRegistry",
                  "serviceEndpoint": { "uri": "did:webvh:QmReg:registry.acme.example" } }
            ]
        });
        assert_eq!(
            discover(&doc),
            Discovered {
                registry: Some("did:webvh:QmReg:registry.acme.example".into()),
                mediator: Some("did:web:mediator.acme.example".into()),
            }
        );
        let bare = json!({ "id": "did:web:vtc.example", "service": [
            { "type": "DIDCommMessaging", "serviceEndpoint": "https://vtc.example/didcomm" }
        ]});
        assert_eq!(discover(&bare), Discovered::default());
    }

    #[test]
    fn the_systemd_unit_runs_the_folder() {
        let unit = render_systemd(Path::new("/home/ops/.cargo/bin/vgi-bridge"), &layout());
        assert!(unit.contains(
            "ExecStart=\"/home/ops/.cargo/bin/vgi-bridge\" --config /home/ops/vgi-bridge/bridge.toml run"
        ));
        assert!(unit.contains("StandardError=append:/home/ops/vgi-bridge/bridge.log"));
        assert!(unit.contains("WantedBy=default.target"), "a user unit");
        assert!(!unit.contains("User="), "no root, no user switch");
        let steps = service_steps(ServiceKind::Systemd, Path::new("/x"), &layout());
        assert!(steps[0].starts_with("systemctl --user enable --now /home/ops/vgi-bridge/"));
    }

    #[test]
    fn the_launchd_agent_runs_the_folder() {
        let plist = render_launchd(Path::new("/opt/homebrew/bin/vgi-bridge"), &layout());
        assert!(plist.contains("<string>org.openvtc.vgi-bridge</string>"));
        assert!(plist.contains("<string>/home/ops/vgi-bridge/bridge.toml</string>"));
        assert!(plist.contains(
            "<key>StandardErrorPath</key>\n  <string>/home/ops/vgi-bridge/bridge.log</string>"
        ));
        assert_eq!(xml("a&<b>\""), "a&amp;&lt;b&gt;&quot;");
        let steps = service_steps(ServiceKind::Launchd, Path::new("/x"), &layout());
        assert!(
            steps
                .iter()
                .any(|s| s.starts_with("launchctl bootstrap gui/$(id -u) "))
        );
    }

    #[test]
    fn the_compose_file_mounts_the_folder_at_its_own_path() {
        let c = render_compose(&layout(), DEFAULT_LISTEN.parse().unwrap(), 1000, 1000);
        assert!(
            c.contains("- \"/home/ops/vgi-bridge:/home/ops/vgi-bridge:ro\""),
            "{c}"
        );
        assert!(c.contains("- \"/home/ops/vgi-bridge/data:/home/ops/vgi-bridge/data\""));
        assert!(c.contains("- \"127.0.0.1:8080:8080\""));
        assert!(c.contains("user: \"1000:1000\""));
        assert!(
            c.contains("10001"),
            "says how to run as the image's own user"
        );
        assert!(c.contains("VGI_BRIDGE_LISTEN: \"0.0.0.0:8080\""));
    }

    #[test]
    fn no_service_prints_the_run_command() {
        let steps = service_steps(
            ServiceKind::None,
            Path::new("/usr/local/bin/vgi-bridge"),
            &layout(),
        );
        assert_eq!(
            steps,
            vec![
                "/usr/local/bin/vgi-bridge --config /home/ops/vgi-bridge/bridge.toml run \
                 2>>/home/ops/vgi-bridge/bridge.log"
                    .to_string()
            ]
        );
        assert!(layout().service_file(ServiceKind::None).is_none());
    }

    #[test]
    fn an_existing_file_is_not_overwritten_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bridge.toml");
        write_file(&p, b"one", 0o644, false).unwrap();
        let err = write_file(&p, b"two", 0o644, false).unwrap_err();
        assert!(err.to_string().contains("--force"), "{err}");
        assert_eq!(std::fs::read(&p).unwrap(), b"one");
        write_file(&p, b"two", 0o644, true).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
    }

    #[cfg(unix)]
    #[test]
    fn the_credential_is_owner_only_and_reads_back() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("vta-credential.json");
        let cred = CredentialBundle::new(
            "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp",
            "z3u2en7t5LR2WtQH5PfsqMWHmSVq4ETRoX6Z3fC6ArUmJvLG",
            "did:webvh:QmVta:vta.acme.example",
        );
        write_credential(&p, &cred, false).unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        crate::seal::check_owner_only(&p).unwrap();
        let back = crate::vta::parse_credential(&std::fs::read_to_string(&p).unwrap()).unwrap();
        assert_eq!(back.did, cred.did);
        assert_eq!(back.vta_did, cred.vta_did);
        assert!(
            write_credential(&p, &cred, false).is_err(),
            "never replaced silently"
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_new_folder_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let l = prepare_dir(&dir.path().join("bridge")).unwrap();
        assert!(l.dir().is_absolute());
        let mode = std::fs::metadata(l.dir()).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
    }

    #[test]
    fn the_grant_commands_carry_the_hand_off() {
        let s = pnm_grant_commands("vgi-bridge", "did:key:z6MkSetup");
        assert!(s.contains("--admin-did did:key:z6MkSetup --admin-expires 1h --admin-handoff"));
        assert!(
            s.contains("pnm acl create --did did:key:z6MkSetup --role admin --contexts vgi-bridge")
        );
        assert!(s.contains("--expires 1h --handoff"));
    }

    #[test]
    fn the_summary_names_the_vtc_line_and_the_registration_link() {
        let s = summary(
            "did:webvh:QmBridge:bridge.acme.example",
            &github(true),
            &"https://bridge.acme.example/base".parse().unwrap(),
            DEFAULT_LISTEN.parse().unwrap(),
            &["systemctl --user enable --now /x".into()],
            Path::new("/home/ops/vgi-bridge/bridge.toml"),
        );
        assert!(
            s.contains("bridges = { \"github.com\" = \"did:webvh:QmBridge:bridge.acme.example\" }"),
            "{s}"
        );
        assert!(s.contains("restart the VTC"));
        assert!(
            s.contains("https://bridge.acme.example/base/github/github.com/acme/register?state=")
        );
        assert!(s.contains("cloudflared"));
    }

    #[tokio::test]
    async fn the_tag_resolves_to_its_commit_through_an_annotated_tag() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        let tag_sha = "b".repeat(40);
        let commit = "c".repeat(40);
        Mock::given(method("GET"))
            .and(path(format!("/repos/{VGI_REPO}/git/ref/tags/v0.15.1")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "ref": "refs/tags/v0.15.1", "object": { "type": "tag", "sha": tag_sha } }),
            ))
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path(format!("/repos/{VGI_REPO}/git/tags/{tag_sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(
                json!({ "object": { "type": "commit", "sha": commit.to_uppercase() } }),
            ))
            .mount(&server)
            .await;
        let sha = resolve_tag_commit(&server.uri(), "v0.15.1").await.unwrap();
        assert_eq!(sha, commit);
        assert_eq!(
            action_ref(&sha),
            format!("OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@{commit}")
        );
        assert!(
            resolve_tag_commit(&server.uri(), "v9.9.9").await.is_err(),
            "404"
        );
        assert!(resolve_tag_commit(&server.uri(), "v1/../x").await.is_err());
    }

    #[tokio::test]
    async fn the_web_flow_key_must_be_a_pgp_key() {
        use wiremock::matchers::method;
        use wiremock::{Mock, MockServer, ResponseTemplate};
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string(
                "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxsBN\n-----END PGP PUBLIC KEY BLOCK-----\n",
            ))
            .mount(&server)
            .await;
        assert!(fetch_web_flow(&server.uri()).await.is_ok());
        let html = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
            .mount(&html)
            .await;
        assert!(fetch_web_flow(&html.uri()).await.is_err());
    }
}
