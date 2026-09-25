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
    /// `/etc/vgi-bridge/bridge.toml`.
    #[arg(long, short)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve: DIDComm to the VTC, HTTP for the forges.
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
    /// Sealed secrets.
    Secret {
        #[command(subcommand)]
        command: SecretCmd,
    },
}

#[derive(Subcommand)]
enum IdentityCmd {
    /// Print the bridge's DID (register it at the VTC as this bridge).
    Show,
    /// Replace the identity with a secrets bundle — a VTA-provisioned DID's,
    /// or one `identity export` wrote (JSON: `{ "did": …, "secrets": [ … ] }`).
    Import {
        /// The bundle file. Delete it once imported.
        bundle: PathBuf,
    },
    /// Write the identity's secrets bundle to a new file (0600), for a
    /// backup kept apart from the store: importing it into a fresh store
    /// brings back the same DID. Key material.
    Export {
        /// The file to create. Never overwritten.
        out: PathBuf,
    },
    /// Mint a new `did:peer` identity naming the configured mediator. The
    /// new DID must be registered at the VTC; namespaces bound to the old
    /// one are not served by it.
    Mint {
        /// Replace an identity the store already holds.
        #[arg(long)]
        replace: bool,
    },
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

fn init(cfg: &BridgeConfig) -> Result<()> {
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
    Ok(())
}

/// Mint and seal a `did:peer` that names the configured mediator.
fn mint(cfg: &BridgeConfig, store: &Store) -> Result<BridgeIdentity> {
    let (_, bundle) = BridgeIdentity::generate_did_peer(&cfg.mediator_did)?;
    BridgeIdentity::store_bundle(store, bundle)
}

/// Create `path` owner-only and write `bytes`; refuse an existing file.
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
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let path = cli
        .config
        .or_else(|| std::env::var_os("VGI_BRIDGE_CONFIG").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/etc/vgi-bridge/bridge.toml"));
    let cfg = BridgeConfig::load(&path)?;
    match cli.command {
        Cmd::Run => {
            let key = load_key(&cfg)?;
            tokio::runtime::Runtime::new()?.block_on(vgi_bridge::run(cfg, key))
        }
        Cmd::Init => init(&cfg),
        Cmd::Identity { command } => {
            let store = open_store(&cfg)?;
            match command {
                IdentityCmd::Show => {
                    let id = BridgeIdentity::load(&store)?.context("no identity: run `init`")?;
                    println!("{}", id.did());
                }
                IdentityCmd::Import { bundle } => {
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
                    let id = BridgeIdentity::store_bundle(&store, bundle)?;
                    println!("{}", id.did());
                    if let Some(warning) = warning {
                        eprintln!("warning: {warning}");
                    }
                }
                IdentityCmd::Export { out } => {
                    let id = BridgeIdentity::load(&store)?.context("no identity: run `init`")?;
                    let json = Zeroizing::new(serde_json::to_vec_pretty(&id.to_bundle()?)?);
                    write_new_private(&out, &json)?;
                    println!("{}", id.did());
                    eprintln!(
                        "wrote the identity's private keys to {} — keep it apart from the store \
                         and the master key; `identity import` restores it",
                        out.display()
                    );
                }
                IdentityCmd::Mint { replace } => {
                    if let Some(old) = BridgeIdentity::load(&store)?
                        && !replace
                    {
                        bail!(
                            "the store already holds `{}`; pass --replace to mint a new \
                             identity in its place (namespaces bound to it are then not served)",
                            old.did()
                        );
                    }
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
                    if !settable(&name) {
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
                    store.put_secret(&name, trimmed.as_bytes())?;
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

    #[test]
    fn only_forgejo_bot_secrets_are_set_by_hand() {
        assert!(settable("forgejo/codeberg.org/bot-token"));
        assert!(!settable("identity"));
        assert!(!settable("github/github.com/app"));
        assert!(!settable("forgejo//bot-token"));
    }
}
