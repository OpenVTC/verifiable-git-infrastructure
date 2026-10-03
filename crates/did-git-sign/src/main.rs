use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use dialoguer::{Confirm, Select, theme::ColorfulTheme};
use did_git_sign::{config, enable, init, names, profiles, sign, vta};
use ed25519_dalek::SigningKey;
use std::path::PathBuf;

use config::SigningConfig;

/// Run `provision_client::run_connection_test` against the VTA with the
/// given setup did:key, drain its `VtaEvent` stream to stdout, and return
/// the issued admin credential. Errors out if provisioning fails or
/// completes without an admin VC.
async fn run_provision(
    vta_did: &str,
    context: &str,
    setup_key: &vta_sdk::provision_client::EphemeralSetupKey,
) -> Result<vta_sdk::provision_client::AdminCredentialReply> {
    use vta_sdk::provision_client::{
        AdminCredentialReply, DiagStatus, ProvisionAsk, VtaEvent, VtaIntent, VtaReply,
        run_connection_test,
    };

    println!("Bootstrapping with the VTA…");

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<VtaEvent>();
    // AdminRotated rolls the ephemeral setup did:key over to a fresh
    // long-term admin DID server-side, so the credential we persist
    // doesn't carry the setup key's `--admin-expires 1h` lifetime. The VTA only
    // allows that rollover for a setup entry created with `--admin-handoff`
    // (VTI-ACL-054), so the command we print must carry it.
    let ask = ProvisionAsk::vta_admin_rotated(context.to_string()).with_label("did-git-sign");
    let setup_did = setup_key.did.clone();
    let setup_priv = setup_key.private_key_multibase().to_string();
    let runner_vta_did = vta_did.to_string();
    tokio::spawn(async move {
        run_connection_test(
            VtaIntent::AdminRotated,
            runner_vta_did,
            setup_did,
            setup_priv,
            ask,
            None,
            tx,
        )
        .await;
    });

    let mut admin_reply: Option<AdminCredentialReply> = None;
    let mut failure: Option<String> = None;
    while let Some(ev) = rx.recv().await {
        match ev {
            VtaEvent::CheckStart(check) => {
                println!("  · {}…", check.label());
            }
            VtaEvent::CheckDone(check, status) => match status {
                DiagStatus::Ok(detail) => println!("  ✓ {} — {detail}", check.label()),
                DiagStatus::Skipped(detail) => {
                    println!("  · {} (skipped: {detail})", check.label())
                }
                DiagStatus::Failed(detail) => println!("  ✗ {} — {detail}", check.label()),
                DiagStatus::Pending | DiagStatus::Running => {}
            },
            VtaEvent::Resolved(_)
            | VtaEvent::AttemptCompleted { .. }
            | VtaEvent::PreflightDone { .. } => {}
            VtaEvent::Connected { reply, .. } => {
                if let VtaReply::AdminOnly(adm) = reply {
                    admin_reply = Some(adm);
                }
            }
            VtaEvent::Failed(reason) => {
                failure = Some(reason);
            }
        }
    }

    if let Some(reason) = failure {
        bail!("provisioning failed: {reason}");
    }
    admin_reply.context("provisioning ended without an admin credential")
}

/// Register the platform-specific keyring-core credential store as the
/// process default. Must run before any `keyring_core::Entry::new` call.
fn init_default_keyring_store() -> Result<()> {
    #[cfg(target_os = "macos")]
    let store = apple_native_keyring_store::keychain::Store::new()
        .map_err(|e| anyhow::anyhow!("init macOS keychain store: {e}"))?;
    #[cfg(target_os = "linux")]
    let store = linux_keyutils_keyring_store::Store::new()
        .map_err(|e| anyhow::anyhow!("init linux keyutils store: {e}"))?;
    #[cfg(target_os = "windows")]
    let store = windows_native_keyring_store::Store::new()
        .map_err(|e| anyhow::anyhow!("init Windows credential manager store: {e}"))?;
    keyring_core::set_default_store(store);
    Ok(())
}

#[derive(Parser)]
#[command(
    name = "did-git-sign",
    about = "Git commit signing using DID Ed25519 keys via VTA",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// SSH-keygen compatibility: operation flag (e.g., -Y sign)
    #[arg(short = 'Y', hide = true)]
    operation: Option<String>,

    /// SSH-keygen compatibility: key/config file path
    #[arg(short = 'f', hide = true)]
    key_file: Option<PathBuf>,

    /// SSH-keygen compatibility: namespace
    #[arg(short = 'n', hide = true)]
    namespace: Option<String>,

    /// SSH-keygen compatibility: file to sign (positional, passed by git)
    #[arg(hide = true)]
    sign_file: Option<PathBuf>,

    /// SSH-keygen compatibility: signature file (-s <file>, used by -Y verify)
    #[arg(short = 's', hide = true)]
    sig_file: Option<PathBuf>,

    /// SSH-keygen compatibility: signer identity (-I <principal>, used by -Y verify)
    #[arg(short = 'I', hide = true)]
    identity: Option<String>,

    /// SSH-keygen compatibility: signature option (-O <option>, used by -Y verify, repeatable)
    #[arg(short = 'O', hide = true, action = clap::ArgAction::Append)]
    sig_option: Vec<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Set up a signing identity. Writes no git configuration: a repository
    /// signs with it only after `did-git-sign enable`.
    Init {
        /// Refused since 0.14: init no longer writes global git config. Use
        /// `did-git-sign enable --dir <path>` to sign in every repository
        /// under a directory.
        #[arg(long, hide = true)]
        global: bool,

        /// VTA DID. The service URL is discovered from the DID document
        /// (overridable with `--vta-url`). did-git-sign mints a temporary
        /// admin did:key for this setup session and prints a `pnm contexts
        /// create` command for you to run before bootstrapping.
        #[arg(long)]
        vta_did: String,

        /// Context id to provision into. Pass the same value to
        /// `pnm contexts create --id <ctx>`.
        #[arg(long, default_value = "did-git-sign")]
        context: String,

        /// Git user.name to set
        #[arg(long)]
        name: Option<String>,

        /// VTA URL (overrides DID document discovery)
        #[arg(long)]
        vta_url: Option<String>,

        /// VTA key ID for the signing key (skip interactive selection)
        #[arg(long)]
        key_id: Option<String>,

        /// DID#key-id to use as signing identity (skip interactive selection)
        #[arg(long)]
        did_key_id: Option<String>,

        /// Skip the "press Enter once authorised" prompt — assume the PNM
        /// ACL grant has already been registered. Useful for scripted
        /// setups.
        #[arg(long)]
        yes: bool,

        /// Show the agent name each DID claims, having resolved that name
        /// back to the DID claiming it. Costs a DID resolution plus an
        /// outbound fetch per claimed name, so it is asked for rather than
        /// paid for by accident.
        #[arg(long)]
        resolve_agent_names: bool,

        /// Save this identity as a named profile. If did-git-sign is already
        /// set up here (or globally, with --global), the identity is added
        /// beside the default instead of replacing it; switch to it with
        /// `did-git-sign use <name>`.
        #[arg(long)]
        profile: Option<String>,

        /// With --profile: also make this identity the default, replacing
        /// the current one.
        #[arg(long = "default", requires = "profile")]
        make_default: bool,
    },

    /// List the named profiles, marking the default and the one this
    /// repository signs as.
    Profiles,

    /// Sign as a named profile in this repository: `enable --profile <name>`.
    Use {
        /// The profile's name (`did-git-sign profiles` lists them).
        name: String,

        /// Refused: use `did-git-sign enable --dir <path> --profile <name>`.
        #[arg(long, hide = true)]
        global: bool,
    },

    /// Sign with did-git-sign in this repository, or in every repository
    /// under a directory. Adds one include line and changes nothing else.
    Enable {
        /// The profile to sign as (default: the identity `init` set up
        /// without --profile, or the only profile).
        #[arg(long)]
        profile: Option<String>,

        /// Instead of this repository, every repository under this directory:
        /// one `includeIf "gitdir:<dir>/"` line in the global git config.
        #[arg(long)]
        dir: Option<String>,
    },

    /// Stop signing with did-git-sign in this repository (or, with --dir,
    /// under a directory). Removes only the line `enable` added.
    Disable {
        /// The directory given to `enable --dir`.
        #[arg(long)]
        dir: Option<String>,
    },

    /// Verify the signing setup by performing a test sign operation
    Verify,

    /// Check configuration, VTA connectivity, and show signing public key
    Health {
        /// Show the signing identity's agent name, having resolved that name
        /// back to the DID claiming it. See `init --resolve-agent-names`.
        #[arg(long)]
        resolve_agent_names: bool,
        /// Path to a did.jsonl file to verify the signing key against.
        #[arg(long)]
        did_jsonl: Option<std::path::PathBuf>,
        /// Check this named profile instead of the default identity.
        #[arg(long)]
        profile: Option<String>,
    },

    /// Remove this host's did-git-sign install: deletes the JSON config,
    /// drops the keyring entries, strips the matching allowed_signers
    /// line, and unsets the relevant git config keys. Idempotent — safe
    /// to run on a partial / already-clean install.
    Uninstall {
        /// Tear down the global install (`~/.config/did-git-sign/`).
        /// Mutually exclusive with `--local`; when neither is given, the
        /// command auto-detects whichever install exists at the current
        /// working directory and falls back to global.
        #[arg(long)]
        global: bool,

        /// Tear down the repo-local install (`.did-git-sign.json`).
        #[arg(long, conflicts_with = "global")]
        local: bool,

        /// Override the principal to remove. By default the value is read
        /// from the SigningConfig file. Only set this when the file is
        /// missing but you still need to clear keyring entries.
        #[arg(long)]
        did_key_id: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    // Register the platform's keyring-core credential store before any
    // Entry::new call. Same backend choice as openvtc so credential
    // namespaces line up across both binaries.
    init_default_keyring_store()?;

    let cli = Cli::parse();

    // Handle SSH-keygen-compatible invocation:
    // git calls: did-git-sign -Y sign -f <config> -n <namespace> <file_to_sign>
    if let Some(op) = &cli.operation {
        match op.as_str() {
            "sign" => {
                let config_path = cli
                    .key_file
                    .as_ref()
                    .context("missing -f <config_path> argument")?;
                let namespace = cli.namespace.as_deref().unwrap_or("git");
                return sign::handle_sign(config_path, namespace, cli.sign_file.as_deref()).await;
            }
            _ => {
                // All other -Y operations (verify, find-principals, check-novalidate,
                // and any future operations git may introduce) are forwarded verbatim
                // to ssh-keygen. did-git-sign only intercepts signing — everything else
                // requires no VTA authentication and is handled natively by ssh-keygen.
                let code = delegate_to_ssh_keygen(op, &cli)?;
                // NOTE: process::exit skips tokio runtime shutdown AND any
                // `Drop` impls on stack-resident values. Safe here because:
                //   1. no async work happens in this branch after delegation;
                //   2. inherited stdio (stdout/stderr) doesn't buffer
                //      in-process — bytes have already crossed the syscall
                //      boundary by the time we reach this line, so there's
                //      nothing to flush.
                // If a future edit introduces `println!`/`eprintln!` between
                // the delegation and this exit, point (2) no longer holds —
                // switch to a clean `return Ok(())` from main and propagate
                // the exit code via the `Result` instead.
                std::process::exit(code);
            }
        }
    }

    match cli.command {
        Some(Commands::Init {
            global,
            vta_did,
            context,
            name,
            vta_url,
            key_id,
            did_key_id,
            yes,
            resolve_agent_names,
            profile,
            make_default,
        }) => {
            cmd_init(
                global,
                vta_did,
                context,
                name,
                vta_url,
                key_id,
                did_key_id,
                yes,
                resolve_agent_names,
                profile,
                make_default,
            )
            .await
        }
        Some(Commands::Profiles) => cmd_profiles(),
        Some(Commands::Use { name, global }) => cmd_use(&name, global),
        Some(Commands::Enable { profile, dir }) => cmd_enable(profile.as_deref(), dir.as_deref()),
        Some(Commands::Disable { dir }) => cmd_disable(dir.as_deref()),
        Some(Commands::Verify) => cmd_verify().await,
        Some(Commands::Health {
            resolve_agent_names,
            did_jsonl,
            profile,
        }) => {
            cmd_health(
                resolve_agent_names,
                did_jsonl.as_deref(),
                profile.as_deref(),
            )
            .await
        }
        Some(Commands::Uninstall {
            global,
            local,
            did_key_id,
        }) => cmd_uninstall(global, local, did_key_id),
        None => {
            // `sign_file` is only legitimate when `-Y sign` is set (git signing
            // invocation), which is handled in the early-return block above. If
            // we reach this arm with `sign_file` populated, the user typed an
            // unrecognised subcommand — without this guard, typos like
            // `did-git-sign verfy` silently fall through to help.
            //
            // (No nested `cli.operation.is_none()` check: the early-return
            // block consumes any `-Y` operation before we get here, so it's
            // always `None` in this arm.)
            if let Some(f) = &cli.sign_file {
                anyhow::bail!(
                    "unrecognised subcommand {:?}\n\nUsage: did-git-sign [COMMAND]\n\nRun 'did-git-sign --help' for available commands.",
                    f.display()
                );
            }
            use clap::CommandFactory;
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}

/// The `pnm` command that authorises the setup session's temporary admin DID.
///
/// `--admin-handoff` is required, not decoration: `init` rolls the setup DID
/// over to a long-term admin (`ProvisionAsk::vta_admin_rotated`), and the VTA
/// refuses that rollover for an entry created without the one-time hand-off
/// (VTI-ACL-053, VTI-ACL-054). It in turn requires `--admin-expires`.
fn pnm_grant_command(context: &str, setup_did: &str) -> String {
    format!(
        "    pnm contexts create --id {context} --name \"did-git-sign\" \\\n        \
         --admin-did {setup_did} --admin-expires 1h --admin-handoff"
    )
}

#[allow(clippy::too_many_arguments)]
async fn cmd_init(
    global: bool,
    vta_did: String,
    context: String,
    user_name: Option<String>,
    vta_url_override: Option<String>,
    key_id_override: Option<String>,
    did_key_id_override: Option<String>,
    yes: bool,
    resolve_agent_names: bool,
    profile: Option<String>,
    make_default: bool,
) -> Result<()> {
    // A bad profile name is refused before anything is provisioned.
    if let Some(name) = &profile {
        profiles::validate_name(name)?;
    }
    // A profile is added beside an existing install rather than replacing its
    // default; the first install, or --default, sets the default as before.
    if global {
        bail!(
            "`init --global` no longer writes your global git config, so it cannot replace an \
             existing signing setup. Run `did-git-sign init …` without --global, then sign where \
             you choose:\n  did-git-sign enable                 # this repository\n  \
             did-git-sign enable --dir ~/code/   # every repository under a directory"
        );
    }
    let target_config = SigningConfig::default_global_path()?;
    let add_beside_default = profile.is_some() && !make_default && target_config.exists();

    // 1. Resolve the VTA service URL (or take the override).
    let vta_url = if let Some(url) = vta_url_override {
        url
    } else {
        println!("Resolving VTA service endpoint from {vta_did}…");
        vta_sdk::session::resolve_vta_url(&vta_did)
            .await
            .map_err(|e| anyhow::anyhow!("could not resolve VTA URL from {vta_did}: {e}"))?
    };
    // The resolved URL has passed the SDK's endpoint guard; an operator's
    // `--vta-url` has not. Hold both to the rule every later use of the
    // stored URL is held to, before the challenge-response sends anything.
    if !vta::vta_url_is_secure(&vta_url) {
        return Err(vta::insecure_vta_url(&vta_url));
    }
    println!("VTA URL: {vta_url}");

    // The VTA's DIDComm mediator, if it advertises one. With it, `init` and
    // every later signing reach the VTA over DIDComm, which is the only way in
    // to a VTA that publishes no REST service. Without one, REST as before.
    let mediator_did = vta_sdk::session::resolve_mediator_did(&vta_did)
        .await
        .map_err(|e| anyhow::anyhow!("could not resolve the VTA's mediator from {vta_did}: {e}"))?;
    match &mediator_did {
        Some(m) => println!("VTA mediator: {m}"),
        None => println!("VTA mediator: none advertised; using REST"),
    }

    // 2. Mint a fresh ephemeral did:key as the admin identity for this
    //    setup session. Held in memory only — if did-git-sign is rerun the
    //    operator must re-grant the ACL for the new DID.
    let setup_key = vta_sdk::provision_client::EphemeralSetupKey::generate()
        .map_err(|e| anyhow::anyhow!("failed to generate setup did:key: {e}"))?;

    // 3. Show the operator the matching `pnm contexts create` command and
    //    wait for them to confirm it has run (skippable with --yes).
    println!();
    println!("did-git-sign has minted a temporary admin DID for this setup session:");
    println!("  {}", setup_key.did);
    println!();
    println!("Authorise it on the VTA via your Personal Network Manager (PNM):");
    println!();
    println!("{}", pnm_grant_command(&context, &setup_key.did));
    println!();
    if !yes {
        println!("The admin grant is short-lived (1h) and can hand off once to a long-term");
        println!("admin DID (--admin-handoff). Once the command above has run,");
        print!("press Enter to continue (or Ctrl+C to abort)... ");
        use std::io::Write;
        std::io::stdout().flush().ok();
        let mut buf = String::new();
        std::io::stdin()
            .read_line(&mut buf)
            .context("failed to read confirmation from stdin")?;
    }

    // 4. Bootstrap with the VTA. provision_client handles the resolve →
    //    enumerate → authenticate → issue-admin-VC pipeline; we drain its
    //    event stream into stdout so the operator can see progress.
    let admin = run_provision(&vta_did, &context, &setup_key).await?;

    // 5. Authenticate as the issued admin DID and proceed with the existing
    //    interactive context / DID / key picker.
    println!();
    println!("Authenticating as {}…", admin.admin_did);
    let connected = vta::connect_with_retry_auto(vta_sdk::client::AutoConnect {
        vta_url: &vta_url,
        vta_did: &vta_did,
        credential_did: &admin.admin_did,
        private_key_multibase: &admin.admin_private_key_mb,
        mediator_did: mediator_did.as_deref(),
    })
    .await
    .map_err(|e| anyhow::anyhow!("VTA authentication failed: {e}"))?;
    let client = connected.client;
    // Only a REST handshake issues a bearer token; a DIDComm session is its
    // own authenticator.
    let token = connected.rest_token;
    println!("Authenticated.");
    println!();

    // A DIDComm session owns a live mediator connection that only `shutdown`
    // closes, so everything that uses it runs in one block and the session is
    // closed whether the block succeeds or fails.
    let outcome: Result<()> = async {
        // Names for the pickers and the closing summary. ACL labels and context
        // names ride along on listings we fetch anyway; agent names cost network
        // and are opt-in.
        let mut book = names::book_from_vta(&client).await;

        let (key_id, did_key_id) =
            if let (Some(kid), Some(dkid)) = (key_id_override, did_key_id_override) {
                // Non-interactive: use provided values directly
                (kid, dkid)
            } else {
                // Interactive: select context, DID, and signing key
                interactive_select(&client, &mut book, resolve_agent_names, yes).await?
            };
        names::resolve_agent_names_into(&mut book, [did_key_id.as_str()], resolve_agent_names)
            .await;

        // Fetch the persona signing key so we know its public bytes for the
        // allowed_signers entry. Uses the freshly-issued admin token.
        let seed = vta::get_signing_key(&client, &key_id).await?;
        let signing_key = SigningKey::from_bytes(seed.as_bytes());
        let verifying_key = signing_key.verifying_key();

        // Cache the REST token we already have so the very next sign operation
        // doesn't have to re-auth. A DIDComm session has none to cache.
        if let Some(token) = &token {
            let _ = config::cache_token(&did_key_id, &token.access_token, token.access_expires_at);
        }

        let include_name = profile.as_deref().unwrap_or(enable::DEFAULT_NAME);
        let install_args = init::InstallArgs {
            global: false,
            did_key_id: did_key_id.clone(),
            vta_key_id: key_id,
            credential_did: admin.admin_did.clone(),
            credential_private_key_mb: admin.admin_private_key_mb.clone(),
            vta_did: vta_did.clone(),
            vta_url,
            // Stored so signing connects the way setup just did: over DIDComm
            // when the VTA advertises a mediator, REST otherwise.
            mediator_did: mediator_did.clone(),
            user_name,
            verifying_key: verifying_key.as_bytes(),
        };

        if add_beside_default {
            let name = profile.as_deref().unwrap_or_default();
            let ssh_public_key = init::add_identity(install_args)?;
            save_profile(name, &did_key_id, &vta_did, &context)?;
            let include = enable::write_include(include_name, &did_key_id)?;
            println!("VTA credentials stored in OS keyring");
            println!("Signing settings: {}", include.display());
            println!("No git configuration was changed.");
            println!();
            println!("Profile '{name}' saved. It does not replace the default identity;");
            println!("sign as it in a repository with:");
            println!("  did-git-sign enable --profile {name}");
            println!();
            if let Some(n) = names::name_line(&book, &did_key_id) {
                println!("  Name: {n}");
            }
            println!("  DID: {did_key_id}");
            println!("  Key: {ssh_public_key}");
            return Ok(());
        }

        let result = init::install(install_args)?;
        if let Some(name) = &profile {
            save_profile(name, &did_key_id, &vta_did, &context)?;
            println!("Profile '{name}' saved (the default identity)");
        }
        let include = enable::write_include(include_name, &did_key_id)?;

        println!("Config saved to: {}", result.config_path.display());
        println!("VTA credentials stored in OS keyring");
        println!("Signing settings: {}", include.display());
        println!("No git configuration was changed.");
        println!();
        println!("Setup complete. This identity signs where you enable it:");
        // The DID stays whole here — this is the identity the operator has to be
        // able to recognise later, and abbreviating it is exactly what a summary
        // must not do. The name goes above it, never in place of it.
        if let Some(name) = names::name_line(&book, &did_key_id) {
            println!("  Name: {name}");
        }
        println!("  DID: {did_key_id}");
        println!("  Key: {}", result.ssh_public_key);
        println!();
        println!("IMPORTANT — to make signatures show as 'Verified':");
        println!("  1. Copy the SSH public key above.");
        println!("  2. Add it to your account:");
        println!("       User Settings → SSH Keys → Add new key");
        println!("       Set Usage type to 'Signing' (or 'Authentication & Signing').");
        println!("  3. Ensure git user.email matches your account email:");
        println!("       git config user.email");
        println!();
        match &profile {
            Some(name) => {
                println!("Enable it in a repository:   did-git-sign enable --profile {name}");
                println!("or for a directory of them:  did-git-sign enable --profile {name} --dir ~/code/");
            }
            None => {
                println!("Enable it in a repository:   did-git-sign enable");
                println!("or for a directory of them:  did-git-sign enable --dir ~/code/");
            }
        }
        println!("Stop at any time with `did-git-sign disable`; nothing else is changed.");

        Ok(())
    }
    .await;
    client.shutdown().await;
    outcome
}

/// Interactive flow: select context → DID → signing key.
/// Returns (vta_key_id, did_key_id).
async fn interactive_select(
    client: &vta_sdk::client::VtaClient,
    book: &mut vta_sdk::display_name::NameBook,
    resolve_agent_names: bool,
    yes: bool,
) -> Result<(String, String)> {
    // 1. List and select context
    let contexts = client
        .list_contexts()
        .await
        .map_err(|e| anyhow::anyhow!("failed to list contexts: {e}"))?;

    if contexts.contexts.is_empty() {
        bail!("no contexts found in VTA — create a context first");
    }

    let context_labels: Vec<String> = contexts
        .contexts
        .iter()
        .map(|c| {
            let did_info = c
                .did
                .as_deref()
                .map_or_else(|| "no DID".to_string(), |d| names::inline(book, d));
            format!("{} — {} ({})", c.id, c.name, did_info)
        })
        .collect();

    let ctx_idx = if contexts.contexts.len() == 1 {
        println!("Using context: {}", context_labels[0]);
        0
    } else {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a context")
            .items(&context_labels)
            .default(0)
            .interact()?
    };
    let context = &contexts.contexts[ctx_idx];
    println!();

    // 2. List and select DID in this context
    let dids = client
        .list_dids_webvh(Some(&context.id), None)
        .await
        .map_err(|e| anyhow::anyhow!("failed to list DIDs: {e}"))?;

    // A context `init` just created (`pnm contexts create`) holds no DID yet.
    // Create one there rather than send the operator away to do it.
    let dids = if dids.dids.is_empty() {
        create_context_did(client, &context.id, yes).await?;
        client
            .list_dids_webvh(Some(&context.id), None)
            .await
            .map_err(|e| anyhow::anyhow!("failed to list DIDs: {e}"))?
    } else {
        dids
    };

    // A DID is what the operator is choosing between here, so this is the
    // picker that most needs a name. `list_dids_webvh` carries no label of
    // its own, so the names come from the book: an ACL label if the VTA has
    // one, otherwise an agent name when asked for.
    names::resolve_agent_names_into(
        book,
        dids.dids.iter().map(|d| d.did.as_str()),
        resolve_agent_names,
    )
    .await;

    let did_labels: Vec<String> = dids
        .dids
        .iter()
        .map(|d| names::inline(book, &d.did))
        .collect();

    let did_idx = if dids.dids.len() == 1 {
        println!("Using DID: {}", did_labels[0]);
        0
    } else {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a DID")
            .items(&did_labels)
            .default(0)
            .interact()?
    };
    let selected_did = &dids.dids[did_idx].did;
    println!();

    // 3. List Ed25519 keys in this context
    let keys = client
        .list_keys(0, 100, Some("active"), Some(&context.id))
        .await
        .map_err(|e| anyhow::anyhow!("failed to list keys: {e}"))?;

    let ed25519_keys: Vec<_> = keys
        .keys
        .iter()
        .filter(|k| k.key_type == vta_sdk::keys::KeyType::Ed25519)
        .collect();

    if ed25519_keys.is_empty() {
        bail!(
            "no active Ed25519 keys found in context '{}' — create signing keys first",
            context.id
        );
    }

    let key_labels: Vec<String> = ed25519_keys
        .iter()
        .map(|k| {
            let label = k.label.as_deref().unwrap_or("unlabeled");
            format!("{} ({})", label, k.key_id)
        })
        .collect();

    let key_idx = if ed25519_keys.len() == 1 {
        println!("Using key: {}", key_labels[0]);
        0
    } else {
        Select::with_theme(&ColorfulTheme::default())
            .with_prompt("Select a signing key")
            .items(&key_labels)
            .default(0)
            .interact()?
    };
    let selected_key = ed25519_keys[key_idx];
    println!();

    // 4. Determine the DID#key-id by matching the key's public key against
    //    the DID document's verification methods
    let did_key_id = resolve_did_key_fragment(client, selected_did, selected_key).await?;

    println!("Signing identity: {did_key_id}");
    println!();

    Ok((selected_key.key_id.clone(), did_key_id))
}

/// Create a `did:webvh` for `context`, on a DID-hosting server the VTA has
/// registered, and return it.
///
/// The request is the one `pnm contexts provision --server` makes: portable,
/// no pre-rotation keys, set as the context's primary DID, the VTA choosing
/// the path and domain. With one server it is used; with several the operator
/// picks (or, under `--yes`, is told to create the DID themselves); with none
/// there is nowhere to publish the DID, and the error says how to make one.
async fn create_context_did(
    client: &vta_sdk::client::VtaClient,
    context: &str,
    yes: bool,
) -> Result<String> {
    let servers = client
        .list_webvh_servers()
        .await
        .map_err(|e| anyhow::anyhow!("failed to list DID-hosting servers: {e}"))?
        .servers;
    let label = |s: &vta_sdk::webvh::WebvhServerRecord| match &s.label {
        Some(l) => format!("{l} ({})", s.id),
        None => s.id.clone(),
    };
    let server = match servers.len() {
        0 => bail!(
            "context '{context}' has no DID, and the VTA has no DID-hosting server to \
             create one on.\n\nRegister one (`pnm did-mgmt servers add …`), or create the \
             DID yourself:\n  pnm did-mgmt dids create --context {context} --did-url <url>\n\
             then run `did-git-sign init` again."
        ),
        1 => &servers[0],
        n if yes => bail!(
            "context '{context}' has no DID, and the VTA has {n} DID-hosting servers to \
             create one on. Run without --yes to choose, or create it yourself:\n  \
             pnm did-mgmt dids create --context {context} --server <id>"
        ),
        _ => {
            let labels: Vec<String> = servers.iter().map(label).collect();
            let idx = Select::with_theme(&ColorfulTheme::default())
                .with_prompt(format!(
                    "Context '{context}' has no DID. Create one on which server?"
                ))
                .items(&labels)
                .default(0)
                .interact()?;
            &servers[idx]
        }
    };

    if !yes
        && servers.len() == 1
        && !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Context '{context}' has no DID. Create a did:webvh for it on {}?",
                label(server)
            ))
            .default(true)
            .interact()?
    {
        bail!(
            "no DID to sign with. Create one with\n  pnm did-mgmt dids create --context \
             {context} --server {}\nand run `did-git-sign init` again.",
            server.id
        );
    }

    println!(
        "Creating a did:webvh in context '{context}' on {}…",
        label(server)
    );
    let req = vta_sdk::client::CreateDidWebvhRequest {
        context_id: context.to_string(),
        server_id: Some(server.id.clone()),
        url: None,
        path: None,
        path_mode: None,
        domain: None,
        label: Some(context.to_string()),
        portable: true,
        add_mediator_service: false,
        add_tsp_service: false,
        additional_services: None,
        pre_rotation_count: 0,
        did_document: None,
        did_log: None,
        set_primary: true,
        signing_key_id: None,
        ka_key_id: None,
        template: None,
        template_context: None,
        template_vars: std::collections::HashMap::new(),
    };
    let created = client
        .create_did_webvh(req)
        .await
        .map_err(|e| anyhow::anyhow!("failed to create a DID in context '{context}': {e}"))?;
    println!(
        "Created {} (signing key {})",
        created.did, created.signing_key_id
    );
    println!();
    Ok(created.did)
}

/// Match a VTA key's public key against a DID document's verification methods
/// to find the corresponding DID#key-N fragment.
async fn resolve_did_key_fragment(
    client: &vta_sdk::client::VtaClient,
    did: &str,
    key: &vta_sdk::keys::KeyRecord,
) -> Result<String> {
    // Try to get the DID document from VTA
    let _did_record = client
        .get_did_webvh(did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get DID record: {e}"))?;

    // Try to get the DID log to extract the document
    let log_resp = client
        .get_did_webvh_log(did)
        .await
        .map_err(|e| anyhow::anyhow!("failed to get DID log: {e}"))?;

    if let Some(log) = &log_resp.log
        && let Some(last_line) = log.lines().last()
        && let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line)
        && let Some(state) = entry.get("state")
        && let Some(vms) = state.get("verificationMethod")
        && let Some(vms_arr) = vms.as_array()
    {
        for vm in vms_arr {
            if let Some(pub_key_mb) = vm.get("publicKeyMultibase")
                && pub_key_mb.as_str() == Some(&key.public_key)
                && let Some(id) = vm.get("id").and_then(|v| v.as_str())
            {
                return Ok(id.to_string());
            }
        }
    }

    // Fallback: if we can't match, use the DID + #key-0 convention
    // (the first signing key is typically #key-0 for VTA-created DIDs)
    eprintln!("Warning: could not match key against DID document, using default fragment #key-0");
    Ok(format!("{did}#key-0"))
}

/// Find and load the signing config (repo-local first, then global).
fn load_config() -> Result<(PathBuf, SigningConfig)> {
    let config_path = if SigningConfig::repo_local_path().exists() {
        SigningConfig::repo_local_path()
    } else {
        SigningConfig::default_global_path()?
    };

    if !config_path.exists() {
        anyhow::bail!("No did-git-sign configuration found. Run `did-git-sign init` first.");
    }

    let cfg = SigningConfig::load(&config_path)?;
    Ok((config_path, cfg))
}

async fn cmd_verify() -> Result<()> {
    let (config_path, cfg) = load_config()?;
    println!("Config:     {}", config_path.display());
    println!("DID:        {}", cfg.did_key_id);

    // Check keyring
    print!("Keyring:    ");
    let creds = config::load_vta_credentials(&cfg.did_key_id)
        .context("VTA credentials not found in keyring")?;
    println!("OK (VTA: {})", creds.vta_url);

    // Authenticate with VTA
    print!("VTA auth:   ");
    let (client, creds) = vta::authenticate(&cfg).await?;
    println!("OK");

    // Fetch signing key
    print!("Fetch key:  ");
    let seed = vta::get_signing_key(&client, &creds.key_id).await?;
    println!("OK");

    // Test sign
    print!("Test sign:  ");
    let signing_key = SigningKey::from_bytes(seed.as_bytes());
    let verifying_key = signing_key.verifying_key();
    let test_data = b"did-git-sign verification test";
    sign::test_sign(&signing_key, &verifying_key, test_data)?;
    println!("OK");

    println!();
    println!("All checks passed. Signing is operational.");
    Ok(())
}

/// Report the commit-msg hook that writes the `Signed-by-DID:` trailer.
///
/// `init` writes the hook once; upgrading the binary does not touch it. A
/// hook from an older release keeps its old behaviour — version 1 put the
/// trailer above a `---` line, where verify-trust does not read it — until
/// `init` is re-run, so health says so.
fn print_commit_msg_hook_status() {
    use init::CommitMsgHookStatus as Hook;
    print!("Commit-msg hook: ");
    match init::commit_msg_hook_status() {
        Ok(Hook::Current { path }) => println!(
            "OK (v{}, {})",
            init::COMMIT_MSG_HOOK_VERSION,
            path.display()
        ),
        Ok(Hook::Outdated {
            path,
            installed,
            current,
        }) => {
            println!(
                "OUTDATED (v{installed}, current v{current}, {})",
                path.display()
            );
            println!(
                "  Re-run `did-git-sign init` to replace it. Hooks before v2 put the \
                 Signed-by-DID trailer above any `---` line in a commit message, where \
                 verify-trust does not read it, and those commits fail as noSignerDid."
            );
        }
        Ok(Hook::Newer {
            path,
            installed,
            current,
        }) => {
            println!(
                "NEWER (v{installed}, this binary writes v{current}, {})",
                path.display()
            );
            println!("  Installed by a newer did-git-sign; upgrade this binary.");
        }
        Ok(Hook::Foreign { path }) => {
            println!("NOT did-git-sign ({})", path.display());
            println!(
                "  Nothing is known to write the Signed-by-DID trailer; commits will be \
                 refused at signing time. Re-run `did-git-sign init`."
            );
        }
        Ok(Hook::Missing { path }) => {
            println!("MISSING ({})", path.display());
            println!("  Re-run `did-git-sign init` to install it.");
        }
        Ok(Hook::Unknown) => {
            println!("not checked (not in a repository and no global core.hooksPath)");
        }
        Err(e) => println!("could not check: {e}"),
    }
    println!();
}

/// Record `name` as the profile for this identity.
fn save_profile(name: &str, did_key_id: &str, vta_did: &str, context: &str) -> Result<()> {
    let mut all = profiles::Profiles::load()?;
    if let Some(old) = all.profiles.get(name)
        && old.did_key_id != did_key_id
    {
        println!(
            "Profile '{name}' now names {did_key_id} (was {}).",
            old.did_key_id
        );
    }
    all.profiles.insert(
        name.to_string(),
        profiles::Profile {
            did_key_id: did_key_id.to_string(),
            vta_did: vta_did.to_string(),
            context: Some(context.to_string()),
        },
    );
    all.save()
}

/// `git config --get <key>` in the current directory, if set.
fn git_config_get(key: &str) -> Option<String> {
    let out = std::process::Command::new("git")
        .args(["config", "--get", key])
        .output()
        .ok()?;
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// `did-git-sign profiles`: every profile, which one is the default, which
/// one this repository signs as, and whether its credentials are present.
fn cmd_profiles() -> Result<()> {
    let all = profiles::Profiles::load()?;
    if all.profiles.is_empty() {
        println!("No profiles yet. Create one with:");
        println!("  did-git-sign init --profile <name> --vta-did <VTA DID>");
        return Ok(());
    }
    // The default is the config file's identity: this repository's own
    // install if it has one, otherwise the global one.
    let default = [
        Some(SigningConfig::repo_local_path()),
        SigningConfig::default_global_path().ok(),
    ]
    .into_iter()
    .flatten()
    .find(|p| p.exists())
    .and_then(|p| SigningConfig::load(&p).ok())
    .map(|c| c.did_key_id);
    let here = git_config_get(sign::SIGNING_KEY_GIT_CONFIG);

    for (name, p) in &all.profiles {
        let mut marks = Vec::new();
        if default.as_deref() == Some(p.did_key_id.as_str()) {
            marks.push("default");
        }
        if here.as_deref() == Some(p.did_key_id.as_str()) {
            marks.push("signs here");
        }
        let marks = if marks.is_empty() {
            String::new()
        } else {
            format!("  [{}]", marks.join(", "))
        };
        println!("{name}{marks}");
        println!("  DID:      {}", p.did_key_id);
        println!("  VTA:      {}", p.vta_did);
        if let Some(ctx) = &p.context {
            println!("  Context:  {ctx}");
        }
        if config::load_vta_credentials(&p.did_key_id).is_err() {
            println!(
                "  Credentials: MISSING from the keyring; run `did-git-sign init --profile {name} …` again"
            );
        }
    }
    if let Some(sel) = &here
        && all.name_of(sel).is_none()
    {
        println!();
        println!("This repository signs as {sel}, which is not a profile.");
    }
    Ok(())
}

/// `did-git-sign use <name>`: make this repository (or, with `--global`,
/// every repository) sign as the named profile.
fn cmd_use(name: &str, global: bool) -> Result<()> {
    if global {
        bail!(
            "`use --global` is gone: did-git-sign no longer writes your global git config. \
             Sign as '{name}' in every repository under a directory with\n  \
             did-git-sign enable --profile {name} --dir <directory>"
        );
    }
    cmd_enable(Some(name), None)
}

/// Resolve which include file `enable` means: a named profile's, else the
/// default identity's, else the only profile's.
fn include_for(profile: Option<&str>) -> Result<(String, PathBuf)> {
    let all = profiles::Profiles::load()?;
    let name = match profile {
        Some(n) => {
            all.get(n)?;
            n.to_string()
        }
        None if enable::include_path(enable::DEFAULT_NAME)?.exists() => {
            enable::DEFAULT_NAME.to_string()
        }
        None if all.profiles.len() == 1 => all.profiles.keys().next().cloned().unwrap_or_default(),
        None if all.profiles.is_empty() => {
            bail!("no identity is set up yet; run `did-git-sign init --vta-did <VTA DID>` first")
        }
        None => {
            let names: Vec<&str> = all.profiles.keys().map(String::as_str).collect();
            bail!(
                "more than one profile; choose one with --profile ({})",
                names.join(", ")
            )
        }
    };
    let path = enable::include_path(&name)?;
    if !path.exists() {
        bail!(
            "no signing settings for '{name}' at {}; run `did-git-sign init --profile {name} …` \
             again (installs before 0.14 did not write them)",
            path.display()
        );
    }
    if let Some(did) = enable::include_identity(&path)
        && config::load_vta_credentials(&did).is_err()
    {
        bail!(
            "'{name}' ({did}) has no credentials in the keyring; run \
             `did-git-sign init --profile {name} …` again"
        );
    }
    Ok((name, path))
}

/// `did-git-sign enable`: one include line in this repository's config, or one
/// `includeIf` line in the global config with `--dir`.
fn cmd_enable(profile: Option<&str>, dir: Option<&str>) -> Result<()> {
    let (name, include) = include_for(profile)?;
    let did = enable::include_identity(&include).unwrap_or_default();
    match dir {
        Some(dir) => {
            let key = enable::enable_dir(dir, &include)?;
            println!("Every repository under {dir} now signs as '{name}':");
            println!("  {did}");
            println!(
                "Added to your global git config: {key} = {}",
                include.display()
            );
            println!("Undo with: did-git-sign disable --dir {dir}");
        }
        None => {
            enable::enable_repo(&include)?;
            println!("This repository now signs as '{name}':");
            println!("  {did}");
            println!("Added to .git/config: include.path = {}", include.display());
            println!("Undo with: did-git-sign disable");
        }
    }
    Ok(())
}

/// `did-git-sign disable`: remove the line `enable` added, and nothing else.
fn cmd_disable(dir: Option<&str>) -> Result<()> {
    let removed = match dir {
        Some(dir) => enable::disable_dir(dir)?,
        None => enable::disable_repo()?,
    };
    match (removed, dir) {
        (true, Some(dir)) => println!("Repositories under {dir} no longer sign with did-git-sign."),
        (true, None) => println!("This repository no longer signs with did-git-sign."),
        (false, Some(dir)) => println!("did-git-sign was not enabled for {dir}; nothing changed."),
        (false, None) => {
            println!("did-git-sign was not enabled in this repository; nothing changed.")
        }
    }
    Ok(())
}

async fn cmd_health(
    resolve_agent_names: bool,
    did_jsonl: Option<&std::path::Path>,
    profile: Option<&str>,
) -> Result<()> {
    let (config_path, mut cfg) = load_config()?;
    // A named profile is checked in place of the default identity.
    if let Some(name) = profile {
        cfg.did_key_id = profiles::Profiles::load()?.get(name)?.did_key_id.clone();
    }

    println!("did-git-sign health check");
    println!("=========================");
    println!();

    // Keyring — read before the identity block so every DID this install
    // holds can be named in one pass.
    let creds = config::load_vta_credentials(&cfg.did_key_id)
        .context("VTA credentials not found in keyring — run `did-git-sign init` first")?;

    // Health is a diagnostic: it prints every DID in full and puts the name
    // above, never in place of it. Nothing here talks to the VTA yet, so the
    // only source that can name these is an agent name, which is opt-in.
    let mut book = vta_sdk::display_name::NameBook::new();
    names::resolve_agent_names_into(
        &mut book,
        [
            cfg.did_key_id.as_str(),
            creds.vta_did.as_str(),
            creds.credential_did.as_str(),
        ],
        resolve_agent_names,
    )
    .await;
    let named = |label: &str, did: &str| {
        if let Some(name) = names::name_line(&book, did) {
            println!("{label:<16} {name}");
        }
    };

    // Config
    println!("Config:          {}", config_path.display());
    if let Some(name) = profile {
        println!("Profile:         {name}");
    }
    named("Signing name:", &cfg.did_key_id);
    println!("DID:             {}", cfg.did_key_id);
    if let Some(name) = &cfg.user_name {
        println!("User:            {name}");
    }
    println!();

    println!("VTA URL:         {}", creds.vta_url);
    named("VTA name:", &creds.vta_did);
    println!("VTA DID:         {}", creds.vta_did);
    named("Credential name:", &creds.credential_did);
    println!("Credential DID:  {}", creds.credential_did);
    println!("Signing Key ID:  {}", creds.key_id);

    // A VTA reached through its mediator (DIDComm or TSP) is asked over the
    // authenticated session; one reached over REST over HTTPS. The stored URL
    // of a mediator-only VTA is only its DID's host, which may well answer
    // `/health` itself (a DID-hosting daemon does), so asking it there reports
    // the wrong service as healthy.
    let over_session = creds.mediator_did.is_some();

    // Token cache: only a REST handshake issues a token to cache.
    if over_session {
        println!("Token cache:     not used (a mediator session authenticates itself)");
    } else {
        match config::load_cached_token(&cfg.did_key_id) {
            Some(_) => println!("Token cache:     valid"),
            None => println!("Token cache:     empty or expired"),
        }
    }
    println!();

    // Whether this repository signs with did-git-sign at all, and as whom.
    match enable::repo_include() {
        Some(inc) => println!(
            "This repository: enabled ({}) → {}",
            inc.file_stem()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default(),
            enable::include_identity(&inc).unwrap_or_else(|| "unreadable include".into())
        ),
        None => match git_config_get("gpg.ssh.program").as_deref() {
            Some("did-git-sign") => {
                println!("This repository: signs with did-git-sign (not via `enable`)")
            }
            _ => println!("This repository: not enabled (`did-git-sign enable` to sign here)"),
        },
    }
    print_commit_msg_hook_status();

    // VTA connectivity, REST: the VTA's public `/health`, which carries its
    // version.
    if !over_session {
        print!("VTA health:      ");
        let vta_client = vta_sdk::client::VtaClient::new(&creds.vta_url);
        match vta_client.health().await {
            Ok(health) => {
                println!("OK (v{})", health.version.as_deref().unwrap_or("unknown"));
                if let Some(mediator_did) = &health.mediator_did {
                    println!("  Mediator DID:  {mediator_did}");
                }
            }
            Err(e) => {
                println!("FAILED");
                println!("  Error: {e}");
            }
        }
    }

    // Authentication
    print!("VTA auth:        ");
    match vta::authenticate(&cfg).await {
        Ok((client, creds)) => {
            println!("OK");
            if over_session {
                print_session_health(&client).await;
            }

            // Fetch signing key and show public key
            print!("Signing key:     ");
            match vta::get_signing_key(&client, &creds.key_id).await {
                Ok(seed) => {
                    let signing_key = SigningKey::from_bytes(seed.as_bytes());
                    let verifying_key = signing_key.verifying_key();
                    println!("OK");
                    println!();
                    println!("SSH Public Key (for signature verification):");
                    println!(
                        "  {}",
                        init::ssh_public_key_string(verifying_key.as_bytes())
                    );
                    println!();
                    println!("Allowed Signers Entry:");
                    println!(
                        "  {}",
                        init::allowed_signers_entry(&cfg, verifying_key.as_bytes())
                    );

                    // Verify the local did.jsonl publishes this key (if provided).
                    if let Some(path) = did_jsonl {
                        println!();
                        print!("DID doc check:   ");
                        match check_key_in_did_log(path, verifying_key.as_bytes()) {
                            Ok(true) => {
                                println!("OK (key found in {})", path.display());
                                let local_mb = multibase::encode(
                                    multibase::Base::Base58Btc,
                                    [
                                        vgi_core::ED25519_MULTICODEC_PREFIX.as_slice(),
                                        verifying_key.as_bytes(),
                                    ]
                                    .concat(),
                                );
                                println!("  publicKeyMultibase: {local_mb}");
                            }
                            Ok(false) => {
                                println!("MISMATCH");
                                println!("  {} does not contain the signing key.", path.display());
                                let local_mb = multibase::encode(
                                    multibase::Base::Base58Btc,
                                    [
                                        vgi_core::ED25519_MULTICODEC_PREFIX.as_slice(),
                                        verifying_key.as_bytes(),
                                    ]
                                    .concat(),
                                );
                                println!("  Local key (multibase): {local_mb}");
                                println!("  Re-export or re-run onboarding.");
                            }
                            Err(e) => println!("FAILED ({e})"),
                        }
                    }
                }
                Err(e) => {
                    println!("FAILED");
                    println!("  Error: {e}");
                }
            }
            // A mediator session stays open until it is shut down.
            client.shutdown().await;
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {e}");
            if over_session {
                println!("VTA health:      not checked (no session to ask it over)");
            }
        }
    }

    Ok(())
}

/// The VTA's own health, asked over the authenticated mediator session
/// (`vta/health/details/0.1`, a signed answer verified against the VTA's DID).
///
/// It carries no software version: the VTA answers this for any caller and
/// keeps its version to `vta/restore/status`, which only administrators of the
/// whole VTA may read, and `did-git-sign`'s credential administers one context.
async fn print_session_health(client: &vta_sdk::client::VtaClient) {
    print!("VTA health:      ");
    match client.health_details().await {
        Ok(h) => {
            println!(
                "OK ({}, asked over the mediator; a VTA does not publish its version)",
                h.status
            );
            if let Some(m) = &h.mediator_did {
                println!("  Mediator DID:  {}", m.as_str());
            }
            println!(
                "  TSP:           {}",
                if h.tsp_enabled {
                    "advertised"
                } else {
                    "not advertised"
                }
            );
            println!("  Sealed:        {}", if h.sealed { "yes" } else { "no" });
            println!(
                "  Key storage:   {}",
                if h.storage_encrypted {
                    "encrypted at rest"
                } else {
                    "not encrypted at rest"
                }
            );
        }
        Err(e) => {
            println!("FAILED");
            println!("  Error: {e}");
        }
    }
}

/// Check whether a local did.jsonl file publishes the given Ed25519 key.
fn check_key_in_did_log(path: &std::path::Path, local_key: &[u8; 32]) -> Result<bool> {
    use vgi_core::ed25519_signing_keys_from_doc;

    let content =
        std::fs::read_to_string(path).with_context(|| format!("cannot read {}", path.display()))?;

    // did.jsonl is JSONL — the DID document state is in the first line's "state" field.
    let first_line = content.lines().next().context("empty did.jsonl")?;
    let entry: serde_json::Value =
        serde_json::from_str(first_line).context("invalid JSON in did.jsonl")?;
    let state = entry
        .get("state")
        .context("no 'state' field in did.jsonl entry")?;

    let published_keys = ed25519_signing_keys_from_doc(state);
    if published_keys.is_empty() {
        anyhow::bail!("DID document lists no Ed25519 key under assertionMethod");
    }

    Ok(published_keys.iter().any(|k| k == local_key))
}

fn cmd_uninstall(
    global_flag: bool,
    local_flag: bool,
    did_key_id_override: Option<String>,
) -> Result<()> {
    // Decide which install scope to tear down. `--global` / `--local`
    // pin the choice; otherwise auto-detect: prefer the repo-local
    // install when one is present at the CWD, falling back to global.
    let global = if global_flag {
        true
    } else {
        !(local_flag || SigningConfig::repo_local_path().exists())
    };

    // Discover did_key_id: explicit override, or read from the
    // SigningConfig file at this scope. The keyring entries are keyed
    // by it, so we need it to clear them.
    let config_path = if global {
        SigningConfig::default_global_path()?
    } else {
        SigningConfig::repo_local_path()
    };
    let did_key_id = match did_key_id_override {
        Some(id) => id,
        None => match SigningConfig::load(&config_path) {
            Ok(cfg) => cfg.did_key_id,
            Err(e) => {
                bail!(
                    "could not read {} to discover the principal — pass --did-key-id explicitly: {e}",
                    config_path.display()
                );
            }
        },
    };

    let summary = init::uninstall(global, &did_key_id)?;

    if let Some(path) = &summary.removed_config_file {
        println!("Removed config: {}", path.display());
    } else {
        println!("Config file already absent");
    }
    if !summary.removed_keyring_entries.is_empty() {
        for key in &summary.removed_keyring_entries {
            println!("Removed keyring entry: {key}");
        }
    } else {
        println!("Keyring entries already absent");
    }
    if summary.allowed_signers_entry_removed {
        println!("Removed allowed_signers entry for {did_key_id}");
    }
    for path in &summary.removed_include_files {
        println!("Removed signing settings: {}", path.display());
    }
    if summary.removed_include_lines > 0 {
        println!(
            "Removed {} include line(s) that enabled it",
            summary.removed_include_lines
        );
    }
    if !summary.git_config_keys_unset.is_empty() {
        let scope = if global { "--global" } else { "--local" };
        for key in &summary.git_config_keys_unset {
            println!("Unset git config {scope} {key} (left by an install before 0.14)");
        }
    }
    for w in &summary.warnings {
        eprintln!("warning: {w}");
    }
    println!();
    println!("did-git-sign install removed.");
    Ok(())
}

/// Delegate a verification operation to the system ssh-keygen binary.
///
/// did-git-sign only adds value during signing (VTA authentication to retrieve the key).
/// Verification is stateless and only requires the public key from the allowed_signers file,
/// which ssh-keygen handles natively. Rebuilding that logic here would duplicate it for no gain.
///
/// Git calls: `did-git-sign -Y verify -f <allowed_signers> -I <principal> -n git -s <sig_file>`
/// We forward this verbatim to: `ssh-keygen -Y verify ...`
fn delegate_to_ssh_keygen(op: &str, cli: &Cli) -> Result<i32> {
    // Allow the ssh-keygen binary path to be overridden via environment variable.
    // This is useful when did-git-sign is invoked by git in a stripped-down
    // environment (GUI clients, minimal CI containers) where ssh-keygen may not
    // be on the inherited $PATH.
    let ssh_keygen =
        std::env::var("DID_GIT_SIGN_SSH_KEYGEN").unwrap_or_else(|_| "ssh-keygen".to_string());

    let mut cmd = std::process::Command::new(&ssh_keygen);
    cmd.arg("-Y").arg(op);

    if let Some(f) = &cli.key_file {
        cmd.arg("-f").arg(f);
    }
    if let Some(i) = &cli.identity {
        cmd.arg("-I").arg(i);
    }
    if let Some(n) = &cli.namespace {
        cmd.arg("-n").arg(n);
    }
    if let Some(s) = &cli.sig_file {
        cmd.arg("-s").arg(s);
    }
    for opt in &cli.sig_option {
        cmd.arg("-O").arg(opt);
    }

    let status = cmd
        .stdin(std::process::Stdio::inherit())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .status()
        .context(format!(
            "failed to invoke ssh-keygen at {:?} — is ssh-keygen installed? \
             Set DID_GIT_SIGN_SSH_KEYGEN to override the path.",
            ssh_keygen
        ))?;

    // status.code() returns None when ssh-keygen was terminated by a signal rather
    // than exiting normally. We collapse that to exit code 1 (generic failure).
    // Re-raising the signal would be more faithful but requires platform-specific
    // libc calls and provides no practical benefit here — git treats both cases
    // identically (verification failed). The unwrap_or(1) is intentional.
    Ok(status.code().unwrap_or(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn grant_command_carries_the_one_time_handoff() {
        let cmd = pnm_grant_command("did-git-sign", "did:key:z6MkExample");
        assert_eq!(
            cmd,
            "    pnm contexts create --id did-git-sign --name \"did-git-sign\" \\\n        \
             --admin-did did:key:z6MkExample --admin-expires 1h --admin-handoff"
        );
        // The VTA refuses the rollover without the hand-off, which needs the expiry.
        assert!(cmd.contains("--admin-handoff"));
        assert!(cmd.contains("--admin-expires"));
    }

    /// Sets an env var on construction, removes it on drop (panic-safe).
    /// Requires `#[serial_test::serial]` — `set_var`/`remove_var` are `unsafe`
    /// in edition 2024 and safe only when no other thread reads the var
    /// concurrently. **Any future test reading `DID_GIT_SIGN_SSH_KEYGEN` or
    /// `DID_GIT_SIGN_TEST_MOCK_OUT` without `#[serial]` will race.**
    struct EnvVarGuard(&'static str);

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            // SAFETY: see struct-level doc comment above.
            unsafe { std::env::remove_var(self.0) };
        }
    }

    fn set_test_env(key: &'static str, value: &str) -> EnvVarGuard {
        // SAFETY: see EnvVarGuard struct-level doc comment.
        unsafe { std::env::set_var(key, value) };
        EnvVarGuard(key)
    }

    /// Verifies that delegate_to_ssh_keygen forwards every flag in the Cli struct
    /// to the underlying ssh-keygen binary in the correct order, and that the
    /// DID_GIT_SIGN_SSH_KEYGEN env var is honoured for path override.
    ///
    /// The real ssh-keygen is replaced by a small shell script that writes each
    /// received argument on its own line to a temp file.  The test then asserts
    /// that every expected flag and value appears in that file.
    #[test]
    #[serial_test::serial]
    // The mock ssh-keygen is a POSIX shell script, which Windows cannot
    // execute (os error 193). The behavior under test — argv forwarding —
    // is platform-independent, so non-Windows coverage suffices.
    #[cfg(not(windows))]
    fn delegate_forwards_all_flags_to_ssh_keygen() {
        // Copy the mock script into a private temp dir and operate on the COPY —
        // never mutate the shared, checked-in fixture. Previously this test
        // chmod'd the fixture in-place, which raced under full-workspace parallel
        // test runs (the shared file's metadata read could fail mid-mutation),
        // producing a flaky failure. Each run now owns its own executable copy,
        // and `tmp_dir` is held for the test's lifetime so it isn't reaped early.
        let src =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/mock_ssh_keygen.sh");
        let tmp_dir = tempfile::tempdir().unwrap();
        let mock_path = tmp_dir.path().join("mock_ssh_keygen.sh");
        std::fs::copy(&src, &mock_path).unwrap();

        // Ensure the mock script is executable regardless of git checkout settings.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&mock_path).unwrap().permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&mock_path, perms).unwrap();
        }

        let out_file = tempfile::NamedTempFile::new().unwrap();
        let _ssh_guard = set_test_env("DID_GIT_SIGN_SSH_KEYGEN", mock_path.to_str().unwrap());
        let _out_guard = set_test_env(
            "DID_GIT_SIGN_TEST_MOCK_OUT",
            out_file.path().to_str().unwrap(),
        );

        // Build a Cli that mirrors what git passes for -Y verify:
        //   did-git-sign -Y verify -f allowed_signers -I <principal> -n git -s <sig> -O hashalg=sha512
        let cli = Cli::try_parse_from([
            "did-git-sign",
            "-Y",
            "verify",
            "-f",
            "allowed_signers",
            "-I",
            "did:webvh:test#key-0",
            "-n",
            "git",
            "-s",
            "buffer.diff.sig",
            "-O",
            "hashalg=sha512",
        ])
        .expect("clap should parse these flags without error");

        let code = delegate_to_ssh_keygen("verify", &cli).unwrap();
        assert_eq!(code, 0, "mock ssh-keygen must exit 0");

        // Each arg is written on its own line by the mock script.
        let content = std::fs::read_to_string(out_file.path()).unwrap();
        let lines: Vec<&str> = content.lines().collect();

        assert!(lines.contains(&"-Y"), "missing -Y flag");
        assert!(lines.contains(&"verify"), "missing operation");
        assert!(lines.contains(&"-f"), "missing -f flag");
        assert!(lines.contains(&"allowed_signers"), "missing key_file value");
        assert!(lines.contains(&"-I"), "missing -I flag");
        assert!(lines.contains(&"did:webvh:test#key-0"), "missing identity");
        assert!(lines.contains(&"-n"), "missing -n flag");
        assert!(lines.contains(&"git"), "missing namespace");
        assert!(lines.contains(&"-s"), "missing -s flag");
        assert!(lines.contains(&"buffer.diff.sig"), "missing sig_file");
        assert!(lines.contains(&"-O"), "missing -O flag");
        assert!(lines.contains(&"hashalg=sha512"), "missing sig_option");
    }
}
