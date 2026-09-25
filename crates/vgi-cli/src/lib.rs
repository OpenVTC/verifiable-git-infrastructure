//! `vgi`: VGI tools for the people who hold a repository.
//!
//! `vgi repo init` is the manual-mode half of the git-namespaces design
//! (§7.3, §8): where no community bridge can act on a repository — a
//! namespace bound in manual mode, or a personal account the community's
//! App is not installed on — the account holder runs the bridge's own
//! bootstrap plan themselves, with their own credentials. The plan, the
//! files and the request bodies come from the adapters (`vgi-forge-github`,
//! `vgi-forge-forgejo`), so what lands is byte-for-byte what the bridge
//! would have written.
//!
//! It stops short of `git-ns/repo/adopt`: that is a Trust Task signed with a
//! VTA session, which this tool does not hold. It prints the `cnm git
//! adopt` command instead.

pub mod cli;
pub mod forgejo;
pub mod github;
pub mod inputs;
pub mod report;
pub mod shell;

use std::io::Write;

use anyhow::{Context, Result, bail};
use vgi_forge::{RepoSpec, Resource, VgiConfig};
use vgi_forge_github::plan::CheckGuard;

use crate::cli::{Cli, Command, ForgeChoice, InitArgs, RepoCommand};
use crate::report::Report;

/// Run a parsed command line, writing the report to `out`.
pub async fn run(cli: Cli, out: &mut dyn Write) -> Result<()> {
    match cli.command {
        Command::Repo(RepoCommand::Init(args)) => repo_init(args, out).await,
    }
}

/// Which forge `resource` is on. `Auto` off github.com stays `Auto`, and is
/// taken for Forgejo only once the instance answers the unauthenticated
/// probe ([`forgejo::Client::connect`]).
fn forge_for(choice: ForgeChoice, resource: &Resource) -> ForgeChoice {
    match choice {
        ForgeChoice::Auto if resource.host() == "github.com" => ForgeChoice::Github,
        c => c,
    }
}

/// The command the namespace admin (or the reservation's owner) runs next.
pub fn adopt_command(resource: &Resource, owners: &[String]) -> String {
    let mut argv = vec![
        "cnm".to_string(),
        "git".into(),
        "adopt".into(),
        resource.to_string(),
    ];
    if owners.is_empty() {
        return format!("{} --owner <owner-did>", shell::command_line(&argv));
    }
    for o in owners {
        argv.push("--owner".into());
        argv.push(o.clone());
    }
    shell::command_line(&argv)
}

async fn repo_init(args: InitArgs, out: &mut dyn Write) -> Result<()> {
    shell::check_did("--vtc", &args.vtc)?;
    for o in &args.owners {
        shell::check_did("--owner", o)?;
    }
    let resource = match &args.resource {
        Some(r) => {
            let r = Resource::parse_owner_repo(r)?;
            r.require_owner_repo()?;
            r
        }
        None => inputs::resource_from_origin(&std::env::current_dir()?)?,
    };
    let forge = forge_for(args.forge, &resource);
    if forge != ForgeChoice::Github && (!args.code_owners.is_empty() || args.solo) {
        bail!(
            "--code-owner and --solo choose GitHub's owner-review guard; Forgejo protects the \
             workflow paths instead"
        );
    }
    let (registry, registry_from_referral) = match &args.registry {
        Some(r) => (r.clone(), false),
        None => (inputs::resolve_registry(&args.vtc).await?, true),
    };
    shell::check_did("--registry", &registry)?;
    let (action, action_resolved) = match &args.verify_trust_action {
        Some(a) => (a.clone(), false),
        None => (
            inputs::resolve_action(&args.verify_trust_version).await?,
            true,
        ),
    };
    let mut cfg = VgiConfig::new(
        registry.clone(),
        args.vtc.clone(),
        action,
        args.verify_trust_version.clone(),
    );
    cfg.required_check = args.required_check.clone();

    let owner = resource.owner().to_string();
    let name = resource
        .repo_name()
        .expect("checked to be owner/repo")
        .to_string();
    let spec = RepoSpec::new(resource.clone());
    let mut report = Report::new(out, args.dry_run);
    report.line(format!(
        "vgi repo init {resource}{}",
        if args.dry_run {
            " (dry run: nothing is changed)"
        } else {
            ""
        }
    ));
    report.line(format!("  VTC       {}", args.vtc));
    if registry_from_referral {
        report.line(format!(
            "  registry  {registry} (the TrustRegistry referral in the VTC's DID document; pass \
             --registry to name one yourself)"
        ));
    } else {
        report.line(format!("  registry  {registry}"));
    }
    if action_resolved {
        report.line(format!(
            "  action    {} (the commit {} named when this ran; trust on first use — pass \
             --verify-trust-action to pin one you verified)",
            cfg.verify_trust_action, cfg.verify_trust_version
        ));
    } else {
        report.line(format!("  action    {}", cfg.verify_trust_action));
    }
    report.line(format!("  release   {}", cfg.verify_trust_version));

    match forge {
        ForgeChoice::Github => {
            let keyring = match &args.platform_keyring {
                Some(p) => std::fs::read(p)
                    .with_context(|| format!("reading the platform keyring {}", p.display()))?,
                None if resource.host() == "github.com" => {
                    report.line("  keyring   web-flow key from https://github.com/web-flow.gpg");
                    inputs::web_flow_key().await?
                }
                None => bail!(
                    "on GitHub Enterprise Server pass --platform-keyring <file> (the instance's \
                     web-flow key, <https://host>/web-flow.gpg)"
                ),
            };
            cfg = cfg.with_platform_keyring(keyring);
            let gh = github::Gh::new(resource.host());
            let facts = github::repo_facts(&gh, &owner, &name)?;
            let owners = github::owners(&gh, &facts, &args.code_owners, args.solo)?;
            let guard = CheckGuard::for_owners(&owners);
            let steps = github::plan(&spec, &cfg, &guard)?;
            report.line(format!(
                "  guard     {}",
                github::describe(&guard, facts.personal)
            ));
            report.line("");
            github::apply(&gh, &facts, &steps, &mut report)?;
        }
        ForgeChoice::Forgejo | ForgeChoice::Auto => {
            let token = std::env::var(forgejo::TOKEN_ENV).map_err(|_| {
                anyhow::anyhow!(
                    "set {} to a token of yours with write:repository and read:user",
                    forgejo::TOKEN_ENV
                )
            })?;
            let base = forgejo::base_url(resource.host(), args.forgejo_url.as_ref())?;
            // The token goes only to an instance that has answered, without
            // it, as Forgejo or Gitea.
            let (client, info) =
                forgejo::Client::connect(&base, token, forge == ForgeChoice::Auto).await?;
            let sha = match &args.verify_trust_sha256 {
                Some(s) => s.to_ascii_lowercase(),
                None => {
                    let s = inputs::release_sha256(&args.verify_trust_version).await?;
                    report.line(format!(
                        "  sha256    {s} (published with {}; trust on first use — pass \
                         --verify-trust-sha256 to pin one you verified)",
                        args.verify_trust_version
                    ));
                    s
                }
            };
            cfg = cfg.with_verify_trust_sha256(sha);
            let steps = forgejo::plan(&spec, &cfg, &args.runs_on)?;
            let me = forgejo::whoami(&client).await?;
            report.line(format!("  instance  {base} ({}), as {me}", info.version));
            report.line("");
            forgejo::apply(&client, &owner, &name, &me, &info, &steps, &mut report).await?;
        }
    }

    report.line("");
    if report.dry_run() {
        report.line(format!(
            "{} change(s) would be made. Run again without --dry-run to make them.",
            report.changes()
        ));
    } else if report.changes() == 0 {
        report.line("Nothing to change: commit trust is already on.");
    } else {
        report.line(format!("{} change(s) made.", report.changes()));
    }
    report.line("");
    report.line(
        "Next, tell the VTC the repository exists. vgi cannot: git-ns/repo/adopt is a Trust \
         Task signed with a VTA session, which this tool does not hold. A namespace admin (or \
         the owner of the reservation `git-ns/repo/create` made) runs:",
    );
    report.line("");
    report.line(format!("  {}", adopt_command(&resource, &args.owners)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_adopt_command_is_quoted() {
        let r = Resource::parse("github.com/Acme/Widgets").unwrap();
        assert_eq!(
            adopt_command(
                &r,
                &[
                    "did:web:a.example".into(),
                    "did:webvh:Qm:b.example%3A80".into()
                ]
            ),
            "cnm git adopt github.com/acme/widgets --owner did:web:a.example --owner \
             did:webvh:Qm:b.example%3A80"
        );
        assert_eq!(
            adopt_command(&r, &[]),
            "cnm git adopt github.com/acme/widgets --owner <owner-did>"
        );
    }
}
