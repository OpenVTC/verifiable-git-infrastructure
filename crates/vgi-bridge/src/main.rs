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
        Cmd::Init => init(&cfg),
        Cmd::Vta { .. } => bail!("the config has no `[vta]` section (VTA mode is off)"),
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

    #[test]
    fn only_forgejo_bot_secrets_are_set_by_hand() {
        assert!(settable("forgejo/codeberg.org/bot-token"));
        assert!(!settable("identity"));
        assert!(!settable("github/github.com/app"));
        assert!(!settable("forgejo//bot-token"));
    }
}
