//! `verify-trust`: the VGI CI verifier.
//!
//! Verifies every commit in a range against the DID document of the signer the
//! commit itself names, then checks that DID against the VTC Trust Registry.
//! Exits 0 only when every commit in the range is signed by a
//! registry-authorized DID (or is an exempt platform commit). Designed for CI
//! (GitHub PR checks).

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use verify_trust::{VerifyTrustArgs, handle_verify_trust};

#[derive(Parser)]
#[command(
    name = "verify-trust",
    about = "Verify a git commit range against a VTC Trust Registry",
    version
)]
struct Cli {
    /// Commit range in `git rev-list` syntax, e.g. `origin/main..HEAD`.
    #[arg(long)]
    range: String,

    /// Maximum number of distinct signer DIDs a range may claim. Each costs
    /// one DID resolution, to a host the commit's author chose, so the set a
    /// pull request can make CI resolve is bounded.
    #[arg(long, default_value_t = 32)]
    max_signers: usize,

    /// Base URL of the Trust Registry (queries POST to `<url>/trust-tasks`).
    #[arg(long)]
    registry_url: String,

    /// DID of the Trust Registry (the recipient of every query).
    #[arg(long)]
    registry_did: String,

    /// DID of the authority the trust tuple is evaluated under.
    #[arg(long)]
    authority: String,

    /// TRQP action of the trust tuple.
    #[arg(long, default_value = "git.commit.sign")]
    action: String,

    /// TRQP resource of the trust tuple (e.g. the `org/repo` slug). Defaults
    /// to $GITHUB_REPOSITORY when unset.
    ///
    /// Security-relevant: this is the only thing scoping a signer to this
    /// repository, so widening it widens who may sign.
    #[arg(long)]
    resource: Option<String>,

    /// Broader resource to also accept a grant under when the primary resource
    /// does not authorize (e.g. the org for org-wide grants). Grant semantics
    /// are OR — a repo-level record cannot veto an org-level grant. Omitted:
    /// only the primary resource is queried.
    #[arg(long)]
    fallback_resource: Option<String>,

    /// Armored PGP keyring of exempt platform keys (e.g. GitHub's web-flow
    /// key, https://github.com/web-flow.gpg) committed to the repo. PGP-signed
    /// commits (web-UI merges, Dependabot) pass only if their signature
    /// verifies against a key in this file. Omitted: no exemptions.
    #[arg(long)]
    exempt_keyring: Option<PathBuf>,

    /// Repository to verify. Defaults to the current directory.
    #[arg(long)]
    repo_dir: Option<PathBuf>,

    /// Verify the agent names the signers' DID documents claim, by resolving
    /// each name back to the DID that claims it. Without this, a claimed name
    /// still shows but is tagged `[unverified]` — `alsoKnownAs` is
    /// self-asserted, so an unchecked name is only what a DID says about
    /// itself. Costs one outbound HTTPS fetch per claimed name.
    #[arg(long)]
    resolve_agent_names: bool,

    /// Emit a machine-readable JSON report on stdout.
    #[arg(long)]
    json: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let resource = cli
        .resource
        .or_else(|| std::env::var("GITHUB_REPOSITORY").ok())
        .context("--resource is required (or set GITHUB_REPOSITORY)")?;
    let repo_dir = match cli.repo_dir {
        Some(dir) => dir,
        None => std::env::current_dir().context("cannot determine current directory")?,
    };

    let code = handle_verify_trust(VerifyTrustArgs {
        repo_dir,
        range: cli.range,
        max_signers: cli.max_signers,
        registry_url: cli.registry_url,
        registry_did: cli.registry_did,
        authority_did: cli.authority,
        action: cli.action,
        resource,
        fallback_resource: cli.fallback_resource,
        exempt_keyring: cli.exempt_keyring,
        resolve_agent_names: cli.resolve_agent_names,
        json: cli.json,
    })
    .await?;
    std::process::exit(code);
}
