//! `vgi-bridge`: run the bridge, or set up its identity and secrets.
//!
//! The admin commands open the state store directly, which takes redb's
//! exclusive lock: stop the bridge first (`run` refuses to start on a store
//! another process holds, and so do they).

use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
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
    /// it does not exist) and mint a `did:key` identity (if there is none).
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
    /// Replace the identity with a VTA-provisioned DID's secrets bundle
    /// (JSON: `{ "did": …, "secrets": [ … ] }`).
    Import {
        /// The bundle file. Delete it once imported.
        bundle: PathBuf,
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

fn open_store(cfg: &BridgeConfig) -> Result<Store> {
    let key = MasterKey::load(
        cfg.master_key_file.as_deref(),
        cfg.master_key_env.as_deref(),
    )?;
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
        None => {
            let (_, seed) = BridgeIdentity::generate_did_key()?;
            BridgeIdentity::store_did_key(&store, &seed)?
        }
    };
    println!("{}", identity.did());
    eprintln!("register this DID at the VTC as the bridge serving its namespaces");
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
        Cmd::Run => tokio::runtime::Runtime::new()?.block_on(vgi_bridge::run(cfg)),
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
                    let bundle = serde_json::from_str(&text).context("parsing the bundle")?;
                    let id = BridgeIdentity::store_bundle(&store, bundle)?;
                    println!("{}", id.did());
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
