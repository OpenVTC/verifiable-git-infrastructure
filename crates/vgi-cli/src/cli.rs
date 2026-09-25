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
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ForgeChoice {
    /// GitHub for `github.com/…`, Forgejo for any other host.
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
deletion, no bypass actors. With two or more owners (the account holder of a \
personal repository counts, plus each --code-owner) it also writes a managed \
`.github/CODEOWNERS` block and the ruleset requires a code owner's review, so \
no pull request can change the check it is judged by without another owner's \
approval. With one owner, only the check is required.

On Forgejo it acts with FORGEJO_TOKEN (a token of yours with write:repository \
and read:user). It allows fast-forward-only merges, commits \
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
    /// With two or more owners, workflow changes need a code owner's review.
    #[arg(long = "code-owner", value_name = "LOGIN")]
    pub code_owners: Vec<String>,

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
