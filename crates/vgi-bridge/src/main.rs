//! `vgi-bridge`: run the bridge, or set up its identity and secrets.
//!
//! The admin commands open the state store directly, which takes redb's
//! exclusive lock: stop the bridge first (`run` refuses to start on a store
//! another process holds, and so do they).

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use vgi_bridge::identity::check_reachable;
use vgi_bridge::seal::{MasterKey, write_key_file};
use vgi_bridge::{BridgeConfig, BridgeIdentity, Store};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(
    name = "vgi-bridge",
    version,
    about = "The per-community VGI forge bridge"
)]
struct Cli {
    /// The config file. Default: `$VGI_BRIDGE_CONFIG`, else
    /// `/etc/vgi-bridge/bridge.toml`. Not read by `setup`, which writes one.
    #[arg(long, short)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Write a complete, runnable bridge folder: the config, the VTA
    /// credential (provisioned here) and a service file. No root needed.
    Setup(Box<SetupArgs>),
    /// Serve: TSP or DIDComm to the VTC, HTTP for the forges.
    Run,
    /// First start: create the master key file (if the config names one and
    /// it does not exist) and mint a `did:peer` identity naming the
    /// configured mediator (if there is none).
    Init,
    /// The bridge's identity.
    Identity {
        #[command(subcommand)]
        command: IdentityCmd,
    },
    /// Sealed secrets (in VTA mode: the context's app-state).
    Secret {
        #[command(subcommand)]
        command: SecretCmd,
    },
    /// VTA mode: the bridge's trust context in the VTC's VTA.
    Vta {
        #[command(subcommand)]
        command: VtaCmd,
    },
    /// Exit 0 when the running bridge's `GET /healthz` answers 200 (for a
    /// container HEALTHCHECK: the image has no curl). Opens no store.
    Healthcheck,
}

#[derive(Subcommand)]
enum VtaCmd {
    /// Check the context is ready and the credential can do what the bridge
    /// needs (fetch its DID's keys, use app-state) and nothing wider, and
    /// print the DID to register at the VTC.
    Setup,
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Print the bridge's DID (register it at the VTC as this bridge).
    Show,
    /// Replace the identity with a secrets bundle — a VTA-provisioned DID's,
    /// or one `identity export` wrote (JSON: `{ "did": …, "secrets": [ … ] }`).
    ///
    /// Replacing an identity with a different DID takes the same guards as
    /// `mint --replace`.
    Import {
        /// The bundle file. Delete it once imported.
        bundle: PathBuf,
        #[command(flatten)]
        replace: ReplaceArgs,
    },
    /// Write the identity's secrets bundle to a new file (0600), for a
    /// backup kept apart from the store: importing it into a fresh store
    /// brings back the same DID. Key material.
    Export {
        /// The file to create. Never overwritten.
        out: PathBuf,
    },
    /// Mint a new `did:peer` identity naming the configured mediator.
    ///
    /// Replacing an identity is not a key rotation: the new DID is a
    /// different bridge. The VTC's `[git_ns] bridges` must name the new DID;
    /// the VTC accepts results and events for a namespace only from the DID
    /// it bound, so namespaces bound to the old one are not served; the
    /// registry's `git.commit.sign` service grant is held by the old DID, so
    /// Dependabot commits the new one re-signs fail the check; and with no
    /// re-attach today, binding those namespaces again needs an unbind,
    /// which revokes every right in them.
    Mint {
        /// Replace an identity the store already holds.
        #[arg(long)]
        replace: bool,
        #[command(flatten)]
        guard: ReplaceArgs,
    },
}

/// The guards on replacing the bridge's identity with another DID.
#[derive(clap::Args)]
struct ReplaceArgs {
    /// Where to write the current identity's secrets bundle (0600, never
    /// over an existing file) before it is replaced. Required whenever there
    /// is one to replace.
    #[arg(long, value_name = "FILE")]
    backup: Option<PathBuf>,
    /// Replace the identity although the store holds namespaces bound (or
    /// being bound) to it, or it is a DID this bridge did not mint (a
    /// VTA-provisioned `did:webvh`). Those namespaces stop being served.
    #[arg(long)]
    abandon_current_did: bool,
}

#[derive(Subcommand)]
enum SecretCmd {
    /// Store a secret read from standard input, e.g.
    /// `forgejo/codeberg.org/bot-token`, `…/bot-password`,
    /// `…/oauth-client-secret`, `…/webhook-secret`.
    Set {
        /// The secret's name.
        name: String,
    },
    /// List the stored secrets' names (never their values).
    List,
}

/// Names an operator may set by hand. The GitHub App's credentials and the
/// identity arrive through their own flows.
fn settable(name: &str) -> bool {
    let parts: Vec<&str> = name.split('/').collect();
    matches!(
        parts.as_slice(),
        ["forgejo", host, "bot-token" | "bot-password" | "oauth-client-secret" | "webhook-secret"]
            if !host.is_empty()
    )
}

/// Load the VTA credential (VTA mode), and clear the environment variable
/// it came from, as [`load_key`] does for the master key.
fn load_credential(cfg: &BridgeConfig) -> Result<vta_sdk::credentials::CredentialBundle> {
    let v = cfg.vta.as_ref().context("no `[vta]` section")?;
    let cred = vgi_bridge::vta::load_credential(v)?;
    if v.credential_file.is_none()
        && let Some(var) = v.credential_env.as_deref()
    {
        // SAFETY: as in `load_key` — called before any thread is started.
        unsafe { std::env::remove_var(var) };
    }
    Ok(cred)
}

/// Refuse a command that only makes sense for a locally held identity.
fn not_in_vta_mode(cfg: &BridgeConfig, what: &str) -> Result<()> {
    if cfg.vta.is_some() {
        bail!(
            "{what} is for a bridge that holds its own identity; in VTA mode the identity is the \
             DID in the VTA context (`vgi-bridge vta setup` checks it)"
        );
    }
    Ok(())
}

/// Connect to the VTA (VTA mode's admin commands).
async fn vta_session(
    cfg: &BridgeConfig,
    cred: vta_sdk::credentials::CredentialBundle,
) -> Result<vgi_bridge::vta::Session> {
    let v = cfg.vta.as_ref().context("no `[vta]` section")?;
    let mut cred = cred;
    let s = vgi_bridge::vta::Session::connect(v, &cred).await;
    zeroize::Zeroize::zeroize(&mut cred.private_key_multibase);
    s
}

/// VTA mode's admin commands, over one session.
fn vta_command(cfg: &BridgeConfig, command: Cmd) -> Result<()> {
    use vgi_bridge::appstate::{AppState as _, secret_key};
    let cred = load_credential(cfg)?;
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let session = vta_session(cfg, cred).await?;
        let v = cfg.vta.as_ref().context("no `[vta]` section")?;
        let out = async {
            match command {
                Cmd::Vta { command: VtaCmd::Setup } | Cmd::Init => {
                    let report = vgi_bridge::vta::setup(
                        &session,
                        v,
                        &cfg.mediator_did,
                        &vgi_bridge::vta::Resolver::new().await?,
                    )
                    .await;
                    for l in &report.lines {
                        eprintln!("{l}");
                    }
                    if report.failed {
                        bail!("the VTA context is not ready for the bridge (see above)");
                    }
                    println!("{}", report.did);
                    eprintln!("register this DID at the VTC as the bridge serving its namespaces");
                }
                Cmd::Identity { command: IdentityCmd::Show } => {
                    let did = session
                        .context_did()
                        .await?
                        .context("the VTA context has no DID yet")?;
                    println!("{did}");
                }
                Cmd::Secret { command } => {
                    let remote = vgi_bridge::vta::VtaAppState::new(&session);
                    match command {
                        SecretCmd::Set { name } => {
                            let value = read_secret(&name)?;
                            let key = secret_key(&name);
                            let seal = session.sealing_key(true).await?;
                            // Under the lease, like the running bridge's own
                            // writes: sealed once, never left unopenable.
                            let mut lease = vgi_bridge::appstate::Lease::acquire(
                                &remote,
                                &format!("secret-set-{}", vgi_bridge::wire::new_id()),
                                std::time::Duration::from_secs(60),
                            )
                            .await?;
                            let written = async {
                                let current = remote.get(&key).await?.map(|r| r.version);
                                vgi_bridge::appstate::put_sealed(
                                    &remote,
                                    &seal,
                                    &name,
                                    value.as_bytes(),
                                    current,
                                    &mut lease,
                                )
                                .await
                                .map_err(|e| anyhow::anyhow!("{e}"))
                            }
                            .await;
                            lease.release(&remote).await;
                            written?;
                            eprintln!(
                                "stored `{name}` in the VTA context `{}`; restart the bridge to use it",
                                session.context()
                            );
                        }
                        SecretCmd::List => {
                            for r in remote.list().await?.records {
                                if !r.deleted
                                    && let Some(n) = r.key.strip_prefix("secret/")
                                {
                                    println!("{n}");
                                }
                            }
                        }
                    }
                }
                _ => bail!("not a VTA-mode command"),
            }
            Ok(())
        }
        .await;
        session.shutdown().await;
        out
    })
}

/// Read a hand-set secret from standard input.
fn read_secret(name: &str) -> Result<Zeroizing<String>> {
    if !settable(name) {
        bail!(
            "`{name}` is not a secret set by hand (forgejo/<host>/bot-token, \
             bot-password, oauth-client-secret or webhook-secret)"
        );
    }
    let mut value = Zeroizing::new(String::new());
    std::io::stdin().read_to_string(&mut value)?;
    let trimmed = value.trim_end_matches(['\r', '\n']);
    if trimmed.is_empty() {
        bail!("empty secret on standard input");
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

/// Load the master key, and clear the environment variable it came from so
/// no child process (git, for the check) or crash dump inherits it. Called
/// from `main` before any thread is started: `remove_var` is only sound
/// while the process is single-threaded.
fn load_key(cfg: &BridgeConfig) -> Result<MasterKey> {
    let key = MasterKey::load(
        cfg.master_key_file.as_deref(),
        cfg.master_key_env.as_deref(),
    )?;
    if cfg.master_key_file.is_none()
        && let Some(var) = cfg.master_key_env.as_deref()
    {
        // SAFETY: `main` calls this before building the tokio runtime or
        // spawning any thread, so nothing reads the environment concurrently.
        unsafe { std::env::remove_var(var) };
    }
    Ok(key)
}

fn open_store(cfg: &BridgeConfig) -> Result<Store> {
    let key = load_key(cfg)?;
    std::fs::create_dir_all(&cfg.data_dir)
        .with_context(|| format!("creating {}", cfg.data_dir.display()))?;
    Store::open(&cfg.store_path(), key)
}

fn init(cfg: &BridgeConfig) -> Result<String> {
    if let Some(path) = cfg.master_key_file.as_deref()
        && !Path::new(path).exists()
    {
        write_key_file(path, &MasterKey::generate()?)?;
        eprintln!(
            "created the master key at {} — back it up somewhere other than the state store",
            path.display()
        );
    }
    let store = open_store(cfg)?;
    let identity = match BridgeIdentity::load(&store)? {
        Some(id) => id,
        None => mint(cfg, &store)?,
    };
    println!("{}", identity.did());
    if let Some(warning) = check_reachable(identity.did(), &cfg.mediator_did)? {
        eprintln!("warning: {warning}");
    }
    eprintln!("register this DID at the VTC as the bridge serving its namespaces");
    Ok(identity.did().to_string())
}

/// Mint and seal a `did:peer` that names the configured mediator.
fn mint(cfg: &BridgeConfig, store: &Store) -> Result<BridgeIdentity> {
    let (_, bundle) = BridgeIdentity::generate_did_peer(&cfg.mediator_did)?;
    BridgeIdentity::store_bundle(store, bundle)
}

/// What replacing the identity breaks, printed whenever it happens.
const REPLACE_CONSEQUENCES: &str = "\
a new DID is a different bridge, not a rotated key:
  - the VTC's `[git_ns] bridges` must name the new DID;
  - the VTC accepts results and events for a namespace only from the DID it bound,
    so namespaces bound to the old DID are no longer served;
  - the registry's `git.commit.sign` service grant is held by the old DID, so
    Dependabot commits the new DID re-signs fail the check;
  - there is no re-attach yet: binding those namespaces again needs
    `cnm git namespace unbind` first, which revokes every right in them.";

/// Check that the identity in `store` may be replaced by `new_did`, and back
/// it up to `args.backup` first. Nothing to do when the store holds no
/// identity, or already holds `new_did`.
fn guard_replace(store: &Store, new_did: Option<&str>, args: &ReplaceArgs) -> Result<()> {
    use vgi_bridge::store::{NamespaceRecord, Table};
    let Some(old) = BridgeIdentity::load(store)? else {
        return Ok(());
    };
    if new_did == Some(old.did()) {
        return Ok(());
    }
    let namespaces = store.list::<NamespaceRecord>(Table::Namespaces)?;
    let minted_here = old.did().starts_with("did:peer:") || old.did().starts_with("did:key:");
    if (!namespaces.is_empty() || !minted_here) && !args.abandon_current_did {
        let mut why = Vec::new();
        if !namespaces.is_empty() {
            why.push(format!(
                "it serves {} namespace(s):\n{}",
                namespaces.len(),
                namespaces
                    .iter()
                    .map(|(id, ns)| format!("    {id}  {}  ({:?})", ns.resource, ns.state))
                    .collect::<Vec<_>>()
                    .join("\n")
            ));
        }
        if !minted_here {
            why.push(
                "it is a DID this bridge did not mint (a VTA-provisioned DID), which may be \
                 moved to another mediator without changing it"
                    .to_string(),
            );
        }
        bail!(
            "refusing to replace the bridge's identity `{}`: {}\n{REPLACE_CONSEQUENCES}\n\
             If a did:peer names the wrong mediator, set `mediator_did` back instead. To \
             replace it anyway, pass --abandon-current-did (and --backup <file>).",
            old.did(),
            why.join("; ")
        );
    }
    let Some(backup) = args.backup.as_deref() else {
        bail!(
            "the store holds the identity `{}`; pass --backup <file> to keep a copy of it \
             before it is replaced\n{REPLACE_CONSEQUENCES}",
            old.did()
        );
    };
    let bundle = BridgeIdentity::stored_bundle(store)?.context("the identity vanished")?;
    write_new_private(backup, &Zeroizing::new(serde_json::to_vec_pretty(&bundle)?))?;
    eprintln!(
        "replacing the identity `{}`; its secrets bundle is in {} (`identity import` \
         restores it)\n{REPLACE_CONSEQUENCES}",
        old.did(),
        backup.display()
    );
    Ok(())
}

/// Create `path` owner-only and write `bytes`; refuse an existing file or a
/// symlink (`O_EXCL`). A failed write removes the partial file, so a retry
/// is not refused over it.
fn write_new_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .with_context(|| format!("creating {} (it must not exist)", path.display()))?;
    if let Err(e) = f.write_all(bytes).and_then(|()| f.sync_all()) {
        drop(f);
        let _ = std::fs::remove_file(path);
        return Err(e).with_context(|| format!("writing {}", path.display()));
    }
    Ok(())
}

/// Ask the bridge listening at `listen` for `GET /healthz`; `Ok` on a 200.
///
/// Plain HTTP over a std socket, so the image needs no HTTP client. An
/// unspecified listen address (`0.0.0.0`, `[::]`) is probed on loopback.
fn healthcheck(listen: std::net::SocketAddr) -> Result<()> {
    use std::io::Write;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
    use std::time::Duration;

    const TIMEOUT: Duration = Duration::from_secs(5);
    let target = match listen.ip() {
        IpAddr::V4(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), listen.port())
        }
        IpAddr::V6(ip) if ip.is_unspecified() => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), listen.port())
        }
        _ => listen,
    };
    let mut stream = TcpStream::connect_timeout(&target, TIMEOUT)
        .with_context(|| format!("connecting to the bridge at {target}"))?;
    stream.set_read_timeout(Some(TIMEOUT))?;
    stream.set_write_timeout(Some(TIMEOUT))?;
    let request = format!("GET /healthz HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n");
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    // The status line is all that is needed; bound the read regardless.
    stream.take(4096).read_to_end(&mut response)?;
    let status_line = String::from_utf8_lossy(&response);
    let status_line = status_line.lines().next().unwrap_or_default();
    match status_line.split_whitespace().nth(1) {
        Some("200") => Ok(()),
        _ => bail!("the bridge at {target} is not healthy: `{status_line}`"),
    }
}

/// `vgi-bridge setup`.
#[derive(clap::Args)]
struct SetupArgs {
    /// The VTC this bridge serves. Its DID document names the Trust Registry
    /// and the mediator.
    #[arg(long, value_name = "DID")]
    vtc: String,
    /// The folder to write: the config, the credential, the state store and
    /// the service file. Created owner-only if missing.
    #[arg(long, value_name = "FOLDER")]
    dir: PathBuf,
    /// Where the forges reach the bridge: https (a TLS proxy or tunnel in
    /// front of `--listen`). Asked for when not given.
    #[arg(long, value_name = "URL")]
    public_url: Option<String>,
    /// The forge of the first entry.
    #[arg(long, value_enum, default_value_t = vgi_bridge::setup::ForgeChoice::Github)]
    forge: vgi_bridge::setup::ForgeChoice,
    /// GitHub: the organisation (or, with --user-account, the personal
    /// account) the App is registered under. Asked for when not given.
    #[arg(long, value_name = "LOGIN")]
    owner: Option<String>,
    /// GitHub: --owner is a personal account, not an organisation.
    #[arg(long)]
    user_account: bool,
    /// GitHub: the App's name (unique on the GitHub instance). Default
    /// `<owner>-vgi-bridge`.
    #[arg(long, value_name = "NAME")]
    app_name: Option<String>,
    /// GitHub: the host (a GHES instance's, for GitHub Enterprise Server).
    #[arg(long, value_name = "HOST", default_value = "github.com")]
    github_host: String,
    /// Forgejo: the instance's root URL (`https://codeberg.org/`).
    #[arg(long, value_name = "URL")]
    forgejo_url: Option<String>,
    /// Forgejo: the bot user's login.
    #[arg(long, value_name = "LOGIN")]
    bot_login: Option<String>,
    /// Forgejo: the bridge's OAuth2 application's client id.
    #[arg(long, value_name = "ID")]
    oauth_client_id: Option<String>,
    /// How the bridge is started. Default: launchd on macOS, systemd
    /// elsewhere on Linux, otherwise none.
    #[arg(long, value_enum)]
    service: Option<vgi_bridge::setup::ServiceKind>,
    /// The Trust Registry's DID, instead of the VTC document's referral.
    #[arg(long, value_name = "DID")]
    registry: Option<String>,
    /// The mediator's DID, instead of the VTC document's.
    #[arg(long, value_name = "DID")]
    mediator: Option<String>,
    /// The VTC's VTA, where the bridge's context lives. Required unless
    /// --credential names a credential that carries it.
    #[arg(long, value_name = "DID")]
    vta: Option<String>,
    /// The bridge's context in the VTA.
    #[arg(long, value_name = "ID", default_value = vgi_bridge::setup::DEFAULT_CONTEXT)]
    context: String,
    /// Use this context credential (JSON, or base64 JSON) instead of
    /// provisioning one. It is copied into the folder owner-only.
    #[arg(long, value_name = "FILE")]
    credential: Option<PathBuf>,
    /// The VTA's did:webvh hosting server to mint the bridge's DID on, when
    /// the context has no DID and the VTA has several.
    #[arg(long, value_name = "ID")]
    webvh_server: Option<String>,
    /// Where the bridge listens (plain HTTP, for the proxy or tunnel).
    #[arg(long, value_name = "ADDR", default_value = vgi_bridge::setup::DEFAULT_LISTEN)]
    listen: std::net::SocketAddr,
    /// Self-contained mode instead of VTA mode: a master key in the folder
    /// and a locally minted did:peer. For development and testing.
    #[arg(long, conflicts_with_all = ["vta", "credential", "webvh_server"])]
    self_contained: bool,
    /// Ask nothing: fail on a missing value instead, and do not wait after
    /// printing the `pnm` grant.
    #[arg(long)]
    yes: bool,
    /// Replace an existing bridge.toml and service file.
    #[arg(long)]
    force: bool,
}

/// Ask on the terminal for a value not given as `flag`; with `--yes`, fail.
fn ask(yes: bool, flag: &str, question: &str) -> Result<String> {
    use std::io::Write;
    if yes {
        bail!("{flag} is required with --yes");
    }
    print!("{question}: ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin()
        .read_line(&mut line)
        .context("reading from the terminal")?;
    let v = line.trim().to_string();
    if v.is_empty() {
        bail!("no answer; pass {flag}");
    }
    Ok(v)
}

fn require_did(what: &str, did: &str) -> Result<()> {
    if !did.starts_with("did:") || did.chars().any(char::is_whitespace) {
        bail!("{what} must be a DID, got `{did}`");
    }
    Ok(())
}

fn cmd_setup(args: SetupArgs) -> Result<()> {
    use vgi_bridge::setup::{self, ForgeChoice, ForgeEntry, Mode, ServiceKind};

    require_did("--vtc", &args.vtc)?;
    let layout = setup::prepare_dir(&args.dir)?;
    if layout.config().exists() && !args.force {
        bail!(
            "{} already exists; pass --force to replace it (the credential, the master key and \
             the state store are kept either way)",
            layout.config().display()
        );
    }
    if !args.self_contained
        && args.vta.is_none()
        && args.credential.is_none()
        && !layout.credential().exists()
    {
        bail!(
            "pass --vta <DID>: the VTC's VTA, where the bridge's context lives (a VTC's DID \
             document does not name its VTA); or --credential <file> for a credential you \
             already have; or --self-contained for a bridge without a VTA"
        );
    }
    let service = args.service.unwrap_or_else(ServiceKind::for_this_os);
    let exe = std::env::current_exe()
        .and_then(|p| p.canonicalize())
        .context("finding this binary's path (for the service file)")?;
    println!("Setting up a VGI bridge in {}", layout.dir().display());

    let rt = tokio::runtime::Runtime::new()?;
    let (inputs, cred) = rt.block_on(async {
        // 1. The community, from the VTC's DID document.
        let mut found = setup::Discovered::default();
        if args.registry.is_none() || args.mediator.is_none() {
            println!("Resolving the VTC {} …", args.vtc);
            let doc = setup::resolve_document(&args.vtc).await?;
            found = setup::discover(&doc);
        }
        let registry = match (&args.registry, &found.registry) {
            (Some(r), _) => r.clone(),
            (None, Some(r)) => {
                println!(
                    "  registry  {r}  (the VTC's TrustRegistry referral; --registry overrides)"
                );
                r.clone()
            }
            (None, None) => bail!(
                "the VTC's DID document names no TrustRegistry; pass --registry <DID> (the \
                 community's Trust Registry)"
            ),
        };
        let mediator = match (&args.mediator, &found.mediator) {
            (Some(m), _) => m.clone(),
            (None, Some(m)) => {
                println!("  mediator  {m}  (the VTC's messaging service; --mediator overrides)");
                m.clone()
            }
            (None, None) => bail!(
                "the VTC's DID document names no mediator (no TSPTransport or DIDCommMessaging \
                 service with a DID endpoint); pass --mediator <DID>"
            ),
        };
        require_did("the registry", &registry)?;
        require_did("the mediator", &mediator)?;

        // 2. Where the forges reach it.
        let public_url = match &args.public_url {
            Some(u) => u.clone(),
            None => ask(
                args.yes,
                "--public-url",
                "The bridge's public HTTPS URL (e.g. https://bridge.example.org/)",
            )?,
        };
        let public_url = setup::check_public_url(&public_url)?;

        // 3. The forge entry.
        let forge = match args.forge {
            ForgeChoice::Github => {
                let owner = match &args.owner {
                    Some(o) => o.clone(),
                    None => ask(
                        args.yes,
                        "--owner",
                        "The GitHub organisation (or account) the App is registered under",
                    )?,
                };
                println!("Fetching GitHub's web-flow key …");
                let keyring = match setup::fetch_web_flow(setup::WEB_FLOW_URL).await {
                    Ok(key) => {
                        setup::write_file(&layout.web_flow(), key.as_bytes(), 0o644, true)?;
                        println!("  wrote {}", layout.web_flow().display());
                        true
                    }
                    Err(e) => {
                        println!(
                            "  warning: {e:#}; bridge.toml leaves `platform_keyring_file` \
                             commented with how to fetch it"
                        );
                        false
                    }
                };
                ForgeEntry::GitHub {
                    host: args.github_host.to_ascii_lowercase(),
                    app_name: args
                        .app_name
                        .clone()
                        .unwrap_or_else(|| setup::default_app_name(&owner)),
                    owner,
                    owner_is_user: args.user_account,
                    keyring,
                }
            }
            ForgeChoice::Forgejo => {
                let base = match &args.forgejo_url {
                    Some(u) => u.clone(),
                    None => ask(args.yes, "--forgejo-url", "The Forgejo instance's URL")?,
                };
                let base_url: url::Url = base
                    .parse()
                    .with_context(|| format!("`{base}` is not a URL"))?;
                ForgeEntry::Forgejo {
                    base_url,
                    bot_login: match &args.bot_login {
                        Some(b) => b.clone(),
                        None => ask(args.yes, "--bot-login", "The bot user's login")?,
                    },
                    oauth_client_id: match &args.oauth_client_id {
                        Some(c) => c.clone(),
                        None => ask(
                            args.yes,
                            "--oauth-client-id",
                            "The bridge's OAuth2 application's client id",
                        )?,
                    },
                }
            }
        };

        // 4. This release's verify-trust, pinned to its commit.
        let version = setup::release_tag();
        println!("Pinning verify-trust {version} …");
        let action = match setup::resolve_tag_commit(setup::GITHUB_API, &version).await {
            Ok(sha) => {
                println!("  {version} is commit {sha}");
                Some(setup::action_ref(&sha))
            }
            Err(e) => {
                println!(
                    "  warning: {e:#}; bridge.toml carries a TODO for the action's commit — fill \
                     it in before binding a namespace"
                );
                None
            }
        };

        // 5. The identity: a context credential in the VTC's VTA.
        let (mode, cred) = if args.self_contained {
            (Mode::SelfContained, None)
        } else {
            let cred = obtain_credential(&args, &layout).await?;
            let vta_mediator = match vta_sdk::session::resolve_mediator_did(&cred.vta_did).await {
                Ok(Some(m)) if m != mediator => {
                    println!("  the VTA is reached through its own mediator {m}");
                    Some(m)
                }
                Ok(_) => None,
                Err(e) => {
                    println!(
                        "  warning: could not read the VTA's mediator ({e}); reaching it through \
                         {mediator}"
                    );
                    None
                }
            };
            (
                Mode::Vta {
                    context: args.context.clone(),
                    vta_mediator,
                },
                Some(cred),
            )
        };
        anyhow::Ok((
            setup::ConfigInputs {
                layout: layout.clone(),
                vtc_did: args.vtc.clone(),
                trust_registry_did: registry,
                mediator_did: mediator,
                public_url,
                listen: args.listen,
                mode,
                verify_trust_version: version,
                verify_trust_action: action,
                forge,
            },
            cred,
        ))
    })?;

    // 6. The config, checked by the bridge's own parser before and after it
    //    is written.
    let text = setup::render_config(&inputs);
    BridgeConfig::parse(&text).context("the rendered config does not load (a bug in setup)")?;
    setup::write_file(&layout.config(), text.as_bytes(), 0o644, args.force)?;
    setup::create_private_dir(&layout.data())?;
    let cfg = BridgeConfig::load(&layout.config())?;
    println!("Wrote {}", layout.config().display());

    // 7. The service file.
    match service {
        ServiceKind::Systemd => write_service(
            &layout,
            service,
            &setup::render_systemd(&exe, &layout),
            args.force,
        )?,
        ServiceKind::Launchd => write_service(
            &layout,
            service,
            &setup::render_launchd(&exe, &layout),
            args.force,
        )?,
        ServiceKind::Docker => {
            let (uid, gid) = owner_ids(layout.dir())?;
            write_service(
                &layout,
                service,
                &setup::render_compose(&layout, args.listen, uid, gid),
                args.force,
            )?
        }
        ServiceKind::None => {}
    }

    // 8. The bridge's DID.
    let did = match cred {
        None => init(&cfg)?,
        Some(cred) => rt.block_on(vta_did_ready(&cfg, cred, args.webvh_server.as_deref()))?,
    };

    let start = setup::service_steps(service, &exe, &layout);
    println!(
        "{}",
        setup::summary(
            &did,
            &inputs.forge,
            &inputs.public_url,
            args.listen,
            &start,
            &layout.config()
        )
    );
    Ok(())
}

fn write_service(
    layout: &vgi_bridge::setup::Layout,
    kind: vgi_bridge::setup::ServiceKind,
    text: &str,
    force: bool,
) -> Result<()> {
    let path = layout.service_file(kind).context("no service file")?;
    vgi_bridge::setup::write_file(&path, text.as_bytes(), 0o644, force)?;
    println!("Wrote {}", path.display());
    Ok(())
}

/// The owner of `dir`, for the container's `user:`.
#[cfg(unix)]
fn owner_ids(dir: &Path) -> Result<(u32, u32)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(dir)?;
    Ok((m.uid(), m.gid()))
}

#[cfg(not(unix))]
fn owner_ids(_dir: &Path) -> Result<(u32, u32)> {
    Ok((10001, 10001))
}

/// The context credential: `--credential`, else the folder's own from an
/// earlier run, else provisioned now the way `did-git-sign init` does.
async fn obtain_credential(
    args: &SetupArgs,
    layout: &vgi_bridge::setup::Layout,
) -> Result<vta_sdk::credentials::CredentialBundle> {
    use vgi_bridge::setup;
    let path = layout.credential();
    let check_vta = |cred: &vta_sdk::credentials::CredentialBundle| -> Result<()> {
        if let Some(vta) = &args.vta
            && *vta != cred.vta_did
        {
            bail!(
                "the credential is for the VTA `{}`, not --vta `{vta}`",
                cred.vta_did
            );
        }
        Ok(())
    };
    if let Some(file) = &args.credential {
        let text = Zeroizing::new(
            std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?,
        );
        let cred = vgi_bridge::vta::parse_credential(&text)?;
        check_vta(&cred)?;
        if file.canonicalize().ok() != path.canonicalize().ok() {
            setup::write_credential(&path, &cred, args.force)?;
        }
        println!("Using the credential {} (VTA {})", cred.did, cred.vta_did);
        return Ok(cred);
    }
    if path.exists() {
        vgi_bridge::seal::check_owner_only(&path)?;
        let text = Zeroizing::new(std::fs::read_to_string(&path)?);
        let cred = vgi_bridge::vta::parse_credential(&text)?;
        check_vta(&cred)?;
        println!(
            "Using the credential already in {} ({}, VTA {})",
            path.display(),
            cred.did,
            cred.vta_did
        );
        return Ok(cred);
    }
    let vta_did = args.vta.clone().context(
        "pass --vta <DID>: the VTC's VTA, where the bridge's context lives (a VTC's DID \
         document does not name its VTA), or --credential <file> for a credential you already have",
    )?;
    require_did("--vta", &vta_did)?;
    let setup_key = vta_sdk::provision_client::EphemeralSetupKey::generate()
        .map_err(|e| anyhow::anyhow!("generating the setup did:key: {e}"))?;
    println!();
    println!("A temporary admin DID for this setup (held in memory only):");
    println!("  {}", setup_key.did);
    println!();
    println!(
        "Authorise it on the VTA {vta_did} with your Personal Network Manager (an admin of the VTA):"
    );
    println!();
    println!(
        "{}",
        setup::pnm_grant_commands(&args.context, &setup_key.did)
    );
    println!();
    if !args.yes {
        use std::io::Write;
        println!(
            "The grant lasts an hour and hands off once, to the bridge's long-term credential."
        );
        print!("Press Enter once one of them has run (Ctrl+C to stop)… ");
        std::io::stdout().flush().ok();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("reading from the terminal")?;
    }
    println!(
        "Provisioning the bridge's credential in `{}` …",
        args.context
    );
    let cred = setup::provision_credential(&vta_did, &args.context, &setup_key).await?;
    setup::write_credential(&path, &cred, false)?;
    println!("  wrote {} (0600): {}", path.display(), cred.did);
    Ok(cred)
}

/// VTA mode: connect with the new credential, mint the bridge's DID if the
/// context has none, and run `vta setup`'s checks.
async fn vta_did_ready(
    cfg: &BridgeConfig,
    cred: vta_sdk::credentials::CredentialBundle,
    webvh_server: Option<&str>,
) -> Result<String> {
    let v = cfg.vta.as_ref().context("no `[vta]` section")?;
    println!("Connecting to the VTA {} …", cred.vta_did);
    let session = vta_session(cfg, cred).await?;
    let out = async {
        let (did, minted) = vgi_bridge::setup::ensure_bridge_did(&session, webvh_server).await?;
        if minted {
            println!("  minted the bridge's DID {did}");
        }
        let resolver = vgi_bridge::vta::Resolver::new().await?;
        let report = vgi_bridge::vta::setup(&session, v, &cfg.mediator_did, &resolver).await;
        for l in &report.lines {
            println!("  {l}");
        }
        if report.failed {
            bail!(
                "the VTA context is not ready for the bridge (see above); fix it and check again \
                 with `vgi-bridge --config {} vta setup` — the folder is otherwise complete",
                cfg_path_hint(cfg)
            );
        }
        // The VTA's mediator is what a DID it mints advertises: say so if
        // that is not the one the bridge listens at.
        if let Ok(doc) = vgi_bridge::vta::DidDocuments::current(&resolver, &report.did).await
            && let Some(m) = vgi_core::messaging_mediator(&doc)
            && m != cfg.mediator_did
        {
            println!(
                "  warning: the bridge's DID advertises the mediator {m}, but bridge.toml listens \
                 at {}; set `mediator_did = \"{m}\"` so the VTC's jobs arrive where the bridge is",
                cfg.mediator_did
            );
        }
        anyhow::Ok(report.did)
    }
    .await;
    session.shutdown().await;
    out
}

/// The config's folder, for messages (the data directory's parent).
fn cfg_path_hint(cfg: &BridgeConfig) -> String {
    cfg.data_dir
        .parent()
        .map(|d| d.join("bridge.toml").display().to_string())
        .unwrap_or_else(|| "bridge.toml".into())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    if let Cmd::Setup(args) = cli.command {
        return cmd_setup(*args);
    }
    let path = cli
        .config
        .or_else(|| std::env::var_os("VGI_BRIDGE_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/vgi-bridge/bridge.toml"));
    let cfg = BridgeConfig::load(&path)?;
    if matches!(cli.command, Cmd::Healthcheck) {
        return healthcheck(cfg.listen);
    }
    if cfg.vta.is_some() {
        return match cli.command {
            Cmd::Run => {
                let cred = load_credential(&cfg)?;
                tokio::runtime::Runtime::new()?
                    .block_on(vgi_bridge::run(cfg, vgi_bridge::Keys::Vta(cred)))
            }
            Cmd::Identity {
                command: IdentityCmd::Import { .. },
            } => not_in_vta_mode(&cfg, "`identity import`"),
            Cmd::Identity {
                command: IdentityCmd::Export { .. },
            } => not_in_vta_mode(&cfg, "`identity export`"),
            Cmd::Identity {
                command: IdentityCmd::Mint { .. },
            } => not_in_vta_mode(&cfg, "`identity mint`"),
            other => vta_command(&cfg, other),
        };
    }
    match cli.command {
        Cmd::Run => {
            let key = load_key(&cfg)?;
            tokio::runtime::Runtime::new()?
                .block_on(vgi_bridge::run(cfg, vgi_bridge::Keys::Sealed(key)))
        }
        Cmd::Init => init(&cfg).map(drop),
        Cmd::Setup(_) => unreachable!("answered before the config is read"),
        Cmd::Vta { .. } => bail!("the config has no `[vta]` section (VTA mode is off)"),
        Cmd::Healthcheck => unreachable!("answered before the mode is chosen"),
        Cmd::Identity { command } => {
            let store = open_store(&cfg)?;
            match command {
                IdentityCmd::Show => {
                    let id = BridgeIdentity::load(&store)?.context("no identity: run `init`")?;
                    println!("{}", id.did());
                }
                IdentityCmd::Import { bundle, replace } => {
                    let text = Zeroizing::new(
                        std::fs::read_to_string(&bundle)
                            .with_context(|| format!("reading {}", bundle.display()))?,
                    );
                    let bundle: vta_sdk::did_secrets::DidSecretsBundle =
                        serde_json::from_str(&text).context("parsing the bundle")?;
                    // Refused before it replaces anything: a did:peer that
                    // names another mediator would have the VTC deliver
                    // jobs where this bridge does not listen.
                    let warning = check_reachable(&bundle.did, &cfg.mediator_did)?;
                    // Checked before it is sealed, so a bundle that does not
                    // load replaces nothing.
                    BridgeIdentity::from_bundle(&bundle)?;
                    guard_replace(&store, Some(&bundle.did), &replace)?;
                    let id = BridgeIdentity::store_bundle(&store, bundle)?;
                    println!("{}", id.did());
                    if let Some(warning) = warning {
                        eprintln!("warning: {warning}");
                    }
                }
                IdentityCmd::Export { out } => {
                    // As stored: every key an imported bundle carries.
                    let bundle = BridgeIdentity::stored_bundle(&store)?
                        .context("no identity: run `init`")?;
                    let json = Zeroizing::new(serde_json::to_vec_pretty(&bundle)?);
                    write_new_private(&out, &json)?;
                    println!("{}", bundle.did);
                    eprintln!(
                        "wrote the identity's private keys to {} — keep it apart from the store \
                         and the master key; `identity import` restores it",
                        out.display()
                    );
                }
                IdentityCmd::Mint { replace, guard } => {
                    if let Some(old) = BridgeIdentity::load(&store)?
                        && !replace
                    {
                        bail!(
                            "the store already holds `{}`; pass --replace --backup <file> to \
                             mint a new identity in its place\n{REPLACE_CONSEQUENCES}",
                            old.did()
                        );
                    }
                    guard_replace(&store, None, &guard)?;
                    let id = mint(&cfg, &store)?;
                    println!("{}", id.did());
                    eprintln!("register this DID at the VTC as the bridge serving its namespaces");
                }
            }
            Ok(())
        }
        Cmd::Secret { command } => {
            let store = open_store(&cfg)?;
            match command {
                SecretCmd::Set { name } => {
                    let value = read_secret(&name)?;
                    store.put_secret(&name, value.as_bytes())?;
                    eprintln!("stored `{name}`");
                }
                SecretCmd::List => {
                    for n in store.secret_names()? {
                        println!("{n}");
                    }
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A one-shot HTTP server answering `status_line`; returns its address.
    fn answer_once(status_line: &'static str) -> std::net::SocketAddr {
        use std::io::Write;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Read the whole request: closing with some of it unread resets
            // the connection before the client sees the answer.
            let mut request = Vec::new();
            let mut chunk = [0u8; 256];
            while !request.ends_with(b"\r\n\r\n") {
                match stream.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                }
            }
            let _ = write!(
                stream,
                "HTTP/1.1 {status_line}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
            );
        });
        addr
    }

    #[test]
    fn healthcheck_passes_on_200_only() {
        assert!(healthcheck(answer_once("200 OK")).is_ok());
        let err = healthcheck(answer_once("503 Service Unavailable")).unwrap_err();
        assert!(err.to_string().contains("503"), "{err}");
    }

    #[test]
    fn healthcheck_probes_an_unspecified_listener_on_loopback() {
        let served = answer_once("200 OK");
        let listen: std::net::SocketAddr = format!("0.0.0.0:{}", served.port()).parse().unwrap();
        assert!(healthcheck(listen).is_ok());
    }

    #[test]
    fn healthcheck_fails_when_nothing_listens() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        assert!(healthcheck(format!("127.0.0.1:{port}").parse().unwrap()).is_err());
    }

    #[test]
    fn only_forgejo_bot_secrets_are_set_by_hand() {
        assert!(settable("forgejo/codeberg.org/bot-token"));
        assert!(!settable("identity"));
        assert!(!settable("github/github.com/app"));
        assert!(!settable("forgejo//bot-token"));
    }
}
