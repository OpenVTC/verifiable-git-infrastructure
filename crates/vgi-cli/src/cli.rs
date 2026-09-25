//! Command-line arguments.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};
use url::Url;
use vgi_forge::DEFAULT_REQUIRED_CHECK;

/// `vgi`: VGI tools for the people who hold a repository.
#[derive(Debug, Parser)]
#[command(name = "vgi", version, about, long_about = None)]
pub struct Cli {
    /// What to do.
    #[command(subcommand)]
    pub command: Command,
}

/// Top-level commands.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Repository commands.
    #[command(subcommand)]
    Repo(RepoCommand),
}

/// `vgi repo …`.
#[derive(Debug, Subcommand)]
pub enum RepoCommand {
    /// Turn VGI commit trust on for a repository, as its admin.
    Init(InitArgs),
}

/// Which forge API to talk to.
/// `--verify-trust-transport`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum TransportChoice {
    /// TSP, then DIDComm, then HTTPS.
    Auto,
    /// TSP only.
    Tsp,
    /// DIDComm only.
    Didcomm,
    /// HTTPS only.
    Https,
}

impl From<TransportChoice> for vgi_forge::VerifyTransport {
    fn from(c: TransportChoice) -> Self {
        match c {
            TransportChoice::Auto => vgi_forge::VerifyTransport::Auto,
            TransportChoice::Tsp => vgi_forge::VerifyTransport::Tsp,
            TransportChoice::Didcomm => vgi_forge::VerifyTransport::Didcomm,
            TransportChoice::Https => vgi_forge::VerifyTransport::Https,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ForgeChoice {
    /// GitHub for `github.com/…`; any other host is taken for Forgejo once
    /// it answers, without the token, as Forgejo or Gitea.
    Auto,
    /// GitHub or GitHub Enterprise Server, through `gh`.
    Github,
    /// Forgejo or Gitea, with `FORGEJO_TOKEN`.
    Forgejo,
}

const INIT_ABOUT: &str = "\
Turn VGI commit trust on for a repository in a manual or personal-account git \
namespace: the same bootstrap the community's bridge runs, done as you.

On GitHub it acts through your own `gh` login (`gh auth login`; you need admin \
on the repository). It commits `.github/workflows/verify-trust.yml` with the \
registry and VTC DIDs written in as literals, and the exempt web-flow keyring; \
removes stale TRUST_REGISTRY_DID / VTC_DID repository variables; and converges \
the \"VGI commit trust\" ruleset on the default branch: pull request required, \
\"Verify commit trust\" required and pinned to GitHub Actions, no force-push, no \
deletion, no bypass actors. The owners are the person running this (on a \
personal repository, the account holder) plus each --code-owner, counted once \
each. With two or more owners it also writes a managed `.github/CODEOWNERS` \
block and the ruleset requires a code owner's review, so no pull request can \
change the check it is judged by without another owner's approval. With one \
owner, only the check is required. On an organisation repository that is \
refused unless you pass --solo: anyone else in the organisation with write \
access could edit the workflow in the very pull request it judges.

These are per-repository guards. They are not the organisation's required \
workflow, which only the community's bridge sets.

On Forgejo it acts with FORGEJO_TOKEN (a token of yours with write:repository \
and read:user), sent only to the repository's own host and only after \
GET /api/v1/version, asked without it, answers as Forgejo or Gitea. It \
allows fast-forward-only merges, commits \
`.forgejo/workflows/verify-trust.yml` with the DIDs written in, and \
converges the default branch's protection: no pushes, the check's status \
context required, the workflow directories protected, applying to admins.

Every step is check-then-apply: a re-run changes nothing, and --dry-run \
prints each change (with the file or request body) without making it.

It does not tell the VTC the repository exists. That is `git-ns/repo/adopt`, \
a Trust Task signed with a VTA session, which this tool does not hold; it \
prints the `cnm git adopt` command to run instead.";

/// `vgi repo init`.
#[derive(Debug, Args)]
#[command(long_about = INIT_ABOUT)]
pub struct InitArgs {
    /// The DID of the community's VTC — the only authority the check trusts.
    #[arg(long, value_name = "DID")]
    pub vtc: String,

    /// The repository, forge-qualified: `github.com/acme/widgets`. Default:
    /// the `origin` remote of the clone this runs in.
    #[arg(long, value_name = "HOST/OWNER/REPO")]
    pub resource: Option<String>,

    /// The Trust Registry's DID. Default: the `TrustRegistry` referral in
    /// the VTC's DID document.
    #[arg(long, value_name = "DID")]
    pub registry: Option<String>,

    /// A repository owner's DID, for the `cnm git adopt` command printed at
    /// the end. Repeat for several.
    #[arg(long = "owner", value_name = "DID")]
    pub owners: Vec<String>,

    /// Which forge API to use.
    #[arg(long, value_enum, default_value_t = ForgeChoice::Auto)]
    pub forge: ForgeChoice,

    /// GitHub: another owner's login, who may approve workflow changes.
    /// Repeat for several. The owners are you (the account holder, on a
    /// personal repository) plus these, counted once each; with two or more,
    /// workflow changes need a code owner's review.
    #[arg(long = "code-owner", value_name = "LOGIN")]
    pub code_owners: Vec<String>,

    /// GitHub: accept a single owner on an organisation repository. Only
    /// the check is required then, and no one has to review workflow
    /// changes: other members with write access could edit the workflow in
    /// the pull request it judges. Name a second owner with --code-owner
    /// instead where you can.
    #[arg(long, conflicts_with = "code_owners")]
    pub solo: bool,

    /// GitHub: the armored `web-flow` key for the exempt keyring. Default:
    /// downloaded from `https://github.com/web-flow.gpg` (github.com only).
    #[arg(long, value_name = "FILE")]
    pub platform_keyring: Option<PathBuf>,

    /// The verify-trust action, pinned to a commit
    /// (`OpenVTC/verifiable-git-infrastructure/.github/actions/verify-trust@<sha>`).
    /// Default: the commit of the --verify-trust-version tag.
    #[arg(long, value_name = "REF")]
    pub verify_trust_action: Option<String>,

    /// The VGI release the check downloads.
    #[arg(long, value_name = "TAG", default_value = concat!("v", env!("CARGO_PKG_VERSION")))]
    pub verify_trust_version: String,

    /// Forgejo: SHA-256 of `verify-trust-x86_64-unknown-linux-gnu.tar.gz` in
    /// that release, pinned in the workflow. Default: the checksum the
    /// release publishes (trust on first use; say so to reviewers).
    #[arg(long, value_name = "HEX")]
    pub verify_trust_sha256: Option<String>,

    /// The Trust Registry binding the written workflow uses (the action's
    /// `transport` input). `auto` (default: TSP, then DIDComm, then HTTPS,
    /// no fallback) writes no input; use `https` while the registry's
    /// mediator does not admit a CI run's throwaway DID.
    #[arg(long, value_enum, value_name = "BINDING", default_value_t = TransportChoice::Auto)]
    pub verify_trust_transport: TransportChoice,

    /// The required check's name (the verify-trust job's name).
    #[arg(long, value_name = "NAME", default_value = DEFAULT_REQUIRED_CHECK)]
    pub required_check: String,

    /// Forgejo: the instance's root URL. Default: `https://<host>/`.
    #[arg(long, value_name = "URL")]
    pub forgejo_url: Option<Url>,

    /// Forgejo: the runner label the job asks for.
    #[arg(long, value_name = "LABEL", default_value = vgi_forge_forgejo::DEFAULT_RUNS_ON)]
    pub runs_on: String,

    /// Print every change, with its contents, and make none.
    #[arg(long)]
    pub dry_run: bool,
}
