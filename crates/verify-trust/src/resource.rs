//! The TRQP resource a run is checked under, and the form it is written in.
//!
//! Resources are moving from the bare `owner/repo` slug (`legacy`) to a
//! forge-qualified name (`qualified`):
//!
//! ```text
//! resource   = forge-host "/" owner [ "/" repo ]
//! forge-host = the forge's lowercased host: github.com, a GHES host,
//!              codeberg.org, git.example.org
//! ```
//!
//! `acme/widgets` alone names no forge, so it cannot tell `github.com/acme`
//! from `codeberg.org/acme` — which may belong to different people. The
//! qualified form makes the forge explicit, never assumed.
//!
//! The grammar itself is [`vgi_core::normalize_resource`], shared with the
//! VTC's registry projection and the forge adapters, so the resource this
//! run queries is byte-for-byte the one a grant was written under. This
//! module adds only what is verify-trust's own: the flag names in messages
//! and a fix suggested from the CI environment.
//!
//! The change is staged so nothing deployed moves under an operator's feet:
//! `legacy` is the default and behaves exactly as before; the default flips to
//! `qualified` in a later release, and `legacy` is then removed. Registry
//! grants must be written in the form the run uses.
//!
//! [`CiEnv`] is the seam that knows how each CI system names the repository
//! under test. Anything it cannot detect falls back to an explicit
//! `--resource`.

use anyhow::{Context, Result, bail};
use vgi_core::{ResourceErrorKind, normalize_resource, resource_contains};

/// Which form the TRQP resource is written in.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, clap::ValueEnum)]
pub enum ResourceFormat {
    /// `owner/repo`, taken as given — the pre-qualification behaviour.
    #[default]
    Legacy,
    /// `<forge-host>/owner/repo`, validated and lowercased.
    Qualified,
}

/// What the CI environment says about the repository under test.
///
/// A snapshot of the variables rather than live reads, so the derivation can
/// be tested without touching the process environment.
#[derive(Debug, Clone, Default)]
pub struct CiEnv {
    /// `FORGEJO_SERVER_URL`: the instance's base URL on Forgejo Actions.
    pub forgejo_server_url: Option<String>,
    /// `FORGEJO_REPOSITORY`: `owner/repo` on Forgejo Actions.
    pub forgejo_repository: Option<String>,
    /// `GITHUB_SERVER_URL`: `https://github.com`, or a GHES host. Forgejo
    /// Actions sets it too, to the instance's URL.
    pub github_server_url: Option<String>,
    /// `GITHUB_REPOSITORY`: `owner/repo`.
    pub github_repository: Option<String>,
}

impl CiEnv {
    /// Read the variables from the process environment.
    pub fn from_env() -> Self {
        Self::from_lookup(|name| std::env::var(name).ok())
    }

    /// Read the variables through `lookup` (a name → value function).
    pub fn from_lookup(lookup: impl Fn(&str) -> Option<String>) -> Self {
        Self {
            forgejo_server_url: lookup("FORGEJO_SERVER_URL"),
            forgejo_repository: lookup("FORGEJO_REPOSITORY"),
            github_server_url: lookup("GITHUB_SERVER_URL"),
            github_repository: lookup("GITHUB_REPOSITORY"),
        }
    }

    /// The server URL / repository pair to derive from: Forgejo's names when
    /// both are set, else GitHub's. A pair is never mixed across systems.
    fn detected(&self) -> Option<(&'static str, &str, &str)> {
        fn pair<'a>(
            url: &'a Option<String>,
            repo: &'a Option<String>,
        ) -> Option<(&'a str, &'a str)> {
            let url = url.as_deref().filter(|v| !v.is_empty())?;
            let repo = repo.as_deref().filter(|v| !v.is_empty())?;
            Some((url, repo))
        }
        pair(&self.forgejo_server_url, &self.forgejo_repository)
            .map(|(url, repo)| ("FORGEJO_SERVER_URL + FORGEJO_REPOSITORY", url, repo))
            .or_else(|| {
                pair(&self.github_server_url, &self.github_repository)
                    .map(|(url, repo)| ("GITHUB_SERVER_URL + GITHUB_REPOSITORY", url, repo))
            })
    }

    /// The forge host this run is on, when the environment names one. Used to
    /// suggest a fix for an unqualified `--resource`.
    pub fn forge_host(&self) -> Option<String> {
        [&self.forgejo_server_url, &self.github_server_url]
            .into_iter()
            .flatten()
            .find_map(|url| forge_host_of(url))
    }

    /// The qualified resource for the repository under test, or `None` when
    /// this is not a CI system we recognise.
    pub fn qualified_resource(&self) -> Result<Option<String>> {
        let Some((source, url, repo)) = self.detected() else {
            return Ok(None);
        };
        let host = forge_host_of(url)
            .with_context(|| format!("cannot read a forge host from {source} (`{url}`)"))?;
        normalize_qualified(
            &format!("resource derived from {source}"),
            &format!("{host}/{repo}"),
            self,
        )
        .map(Some)
    }
}

/// The lowercased host of a forge's base URL: scheme, credentials, port and
/// path dropped.
///
/// The port is dropped on purpose. A resource names a forge, not a socket, and
/// `:` has no place in the grammar; an instance served on a non-default port is
/// still identified by its host. Two forges on one host differing only by port
/// would share resources — an unusual deployment that should pass `--resource`
/// explicitly.
pub fn forge_host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map_or(url, |(_, rest)| rest);
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host_port = authority
        .rsplit_once('@')
        .map_or(authority, |(_, host)| host);
    let host = host_port.split(':').next().unwrap_or_default();
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Validate a qualified resource and return it normalised (lowercased).
///
/// `what` names the value in errors (`--resource`, `--fallback-resource`, or
/// where a derived one came from). Every rejection says how to fix it; an
/// unqualified `owner/repo` gets the forge host this run is on suggested.
pub fn normalize_qualified(what: &str, value: &str, ci: &CiEnv) -> Result<String> {
    match normalize_resource(value) {
        Ok(canonical) => Ok(canonical),
        Err(e) if *e.kind() == ResourceErrorKind::MissingForgeHost => {
            let bare = value.trim_matches('/').to_ascii_lowercase();
            let fix = match ci.forge_host() {
                Some(detected) => format!("did you mean `{detected}/{bare}`?"),
                None => format!("prefix the forge host, e.g. `github.com/{bare}`"),
            };
            bail!(
                "{what} `{value}` is not forge-qualified (--resource-format qualified expects \
                 `<forge-host>/<owner>[/<repo>]`); {fix}"
            )
        }
        Err(e) => bail!("{}", e.describe(what)),
    }
}

/// The primary and fallback resources a run queries, in the chosen form.
///
/// `legacy` is the pre-qualification behaviour: values pass through
/// untouched, and the primary defaults to `$GITHUB_REPOSITORY`; only a
/// forge-qualified fallback is refused, since it would mix the two forms in
/// one run. `qualified` validates and lowercases explicit values, derives the
/// default from [`CiEnv`], and requires the fallback to **contain** the
/// primary — the namespace it sits in (`github.com/acme` for
/// `github.com/acme/widgets`), or the primary itself. A fallback naming
/// another owner or another forge is refused, so a grant there can never
/// authorize this repository.
pub fn select_resources(
    format: ResourceFormat,
    resource: Option<String>,
    fallback_resource: Option<String>,
    ci: &CiEnv,
) -> Result<(String, Option<String>)> {
    // One form per run, never both. Querying `github.com/acme/widgets` and
    // then `acme/widgets` would accept a grant under either, so during the
    // migration window — when the VTC writes both — a stale or hand-issued
    // legacy grant would silently widen who may sign.
    match format {
        ResourceFormat::Legacy => {
            let resource = resource
                .or_else(|| ci.github_repository.clone())
                .context("--resource is required (or set GITHUB_REPOSITORY)")?;
            if let Some(fallback) = &fallback_resource
                && let Ok(qualified) = normalize_resource(fallback)
            {
                bail!(
                    "--fallback-resource `{fallback}` is forge-qualified (`{qualified}`) but \
                     --resource-format is legacy; one run uses one form: pass \
                     --resource-format qualified, or the bare owner"
                );
            }
            Ok((resource, fallback_resource))
        }
        ResourceFormat::Qualified => {
            let resource = match resource {
                Some(value) => normalize_qualified("--resource", &value, ci)?,
                None => ci.qualified_resource()?.context(
                    "--resource is required: no CI environment detected to derive it from \
                     (FORGEJO_SERVER_URL + FORGEJO_REPOSITORY, or GITHUB_SERVER_URL + \
                     GITHUB_REPOSITORY); pass e.g. `--resource github.com/acme/widgets`",
                )?,
            };
            let fallback = fallback_resource
                .map(|value| normalize_qualified("--fallback-resource", &value, ci))
                .transpose()?;
            if let Some(fallback) = &fallback
                && !resource_contains(fallback, &resource)
            {
                bail!(
                    "--fallback-resource `{fallback}` does not contain --resource `{resource}`: \
                     the fallback must be the namespace the repository sits in (e.g. `{}`), \
                     never another owner's or another forge's",
                    namespace_of(&resource)
                );
            }
            Ok((resource, fallback))
        }
    }
}

/// `host/owner` of a normalised qualified resource (itself when it is one).
fn namespace_of(resource: &str) -> String {
    resource
        .splitn(3, '/')
        .take(2)
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    fn ci(vars: &[(&str, &str)]) -> CiEnv {
        CiEnv::from_lookup(|name| {
            vars.iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_string())
        })
    }

    fn github() -> CiEnv {
        ci(&[
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_REPOSITORY", "Acme/Widgets"),
        ])
    }

    fn err(what: &str, value: &str, ci: &CiEnv) -> String {
        normalize_qualified(what, value, ci)
            .unwrap_err()
            .to_string()
    }

    // --- CiEnv derivation ----------------------------------------------------

    #[test]
    fn github_actions_yields_the_lowercased_github_resource() {
        assert_eq!(
            github().qualified_resource().unwrap().as_deref(),
            Some("github.com/acme/widgets")
        );
    }

    #[test]
    fn an_enterprise_server_gets_its_own_host() {
        let env = ci(&[
            ("GITHUB_SERVER_URL", "https://GHE.Example.com/"),
            ("GITHUB_REPOSITORY", "acme/widgets"),
        ]);
        assert_eq!(
            env.qualified_resource().unwrap().as_deref(),
            Some("ghe.example.com/acme/widgets")
        );
    }

    #[test]
    fn forgejo_names_take_precedence_over_the_github_ones() {
        let env = ci(&[
            ("FORGEJO_SERVER_URL", "https://codeberg.org"),
            ("FORGEJO_REPOSITORY", "acme/widgets"),
            ("GITHUB_SERVER_URL", "https://github.com"),
            ("GITHUB_REPOSITORY", "other/thing"),
        ]);
        assert_eq!(
            env.qualified_resource().unwrap().as_deref(),
            Some("codeberg.org/acme/widgets")
        );
    }

    #[test]
    fn a_half_set_forgejo_pair_falls_back_to_github_names() {
        let env = ci(&[
            ("FORGEJO_SERVER_URL", "https://git.example.org"),
            ("GITHUB_SERVER_URL", "https://git.example.org"),
            ("GITHUB_REPOSITORY", "acme/widgets"),
        ]);
        assert_eq!(
            env.qualified_resource().unwrap().as_deref(),
            Some("git.example.org/acme/widgets")
        );
    }

    #[test]
    fn a_port_is_not_part_of_the_forge_host() {
        let env = ci(&[
            (
                "FORGEJO_SERVER_URL",
                "http://user@git.example.org:3000/forgejo",
            ),
            ("FORGEJO_REPOSITORY", "acme/widgets"),
        ]);
        assert_eq!(
            env.qualified_resource().unwrap().as_deref(),
            Some("git.example.org/acme/widgets")
        );
        assert_eq!(
            forge_host_of("http://localhost:3000").as_deref(),
            Some("localhost")
        );
    }

    #[test]
    fn no_ci_environment_derives_nothing() {
        assert_eq!(CiEnv::default().qualified_resource().unwrap(), None);
        // A repository with no server URL is not enough to name the forge.
        let env = ci(&[("GITHUB_REPOSITORY", "acme/widgets")]);
        assert_eq!(env.qualified_resource().unwrap(), None);
        let env = ci(&[
            ("GITHUB_SERVER_URL", ""),
            ("GITHUB_REPOSITORY", "acme/widgets"),
        ]);
        assert_eq!(env.qualified_resource().unwrap(), None);
    }

    // --- validation and normalisation ----------------------------------------

    #[test]
    fn qualified_values_are_accepted_and_lowercased() {
        let none = CiEnv::default();
        for (value, expected) in [
            ("GitHub.com/Acme/Widgets", "github.com/acme/widgets"),
            ("github.com/acme", "github.com/acme"),
            ("codeberg.org/acme/widgets", "codeberg.org/acme/widgets"),
            ("localhost/acme/widgets", "localhost/acme/widgets"),
            (
                "gitlab.example.org/group/sub/project",
                "gitlab.example.org/group/sub/project",
            ),
        ] {
            assert_eq!(
                normalize_qualified("--resource", value, &none).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn an_unqualified_value_suggests_the_detected_forge() {
        let message = err("--resource", "Acme/Widgets", &github());
        assert!(message.contains("not forge-qualified"), "{message}");
        assert!(
            message.contains("did you mean `github.com/acme/widgets`?"),
            "{message}"
        );

        let message = err("--fallback-resource", "acme", &github());
        assert!(
            message.starts_with("--fallback-resource `acme`"),
            "{message}"
        );
        assert!(
            message.contains("did you mean `github.com/acme`?"),
            "{message}"
        );
    }

    #[test]
    fn an_unqualified_value_outside_ci_suggests_a_prefix() {
        let message = err("--resource", "acme/widgets", &CiEnv::default());
        assert!(
            message.contains("prefix the forge host, e.g. `github.com/acme/widgets`"),
            "{message}"
        );
    }

    #[test]
    fn malformed_values_are_rejected_with_a_fix() {
        let none = CiEnv::default();
        let cases = [
            ("", "is empty"),
            ("github.com/acme widgets", "whitespace"),
            (
                "https://github.com/acme/widgets.git",
                "did you mean `github.com/acme/widgets`?",
            ),
            (
                "/github.com/acme/widgets",
                "did you mean `github.com/acme/widgets`?",
            ),
            (
                "github.com/acme/widgets/",
                "did you mean `github.com/acme/widgets`?",
            ),
            ("github.com//widgets", "empty path segment"),
            ("github.com/acme/../other", "`.` or `..` segment"),
            ("github.com/./acme", "`.` or `..` segment"),
            (
                "git.example.org:3000/acme",
                "did you mean `git.example.org/acme`?",
            ),
            ("github.com", "names a forge but no owner"),
            ("github..com/acme", "invalid forge host"),
            ("github.com/acme@x", "may only contain"),
        ];
        for (value, expected) in cases {
            let message = err("--resource", value, &none);
            assert!(message.contains(expected), "{value:?}: {message}");
        }
    }

    // --- mode selection --------------------------------------------------------

    #[test]
    fn legacy_is_the_default_and_passes_values_through_untouched() {
        assert_eq!(ResourceFormat::default(), ResourceFormat::Legacy);
        // Derived: $GITHUB_REPOSITORY verbatim — no host, no lowercasing.
        assert_eq!(
            select_resources(ResourceFormat::Legacy, None, None, &github()).unwrap(),
            ("Acme/Widgets".to_string(), None)
        );
        // Explicit: whatever was given, qualified-looking or not.
        assert_eq!(
            select_resources(
                ResourceFormat::Legacy,
                Some("Acme/Widgets".into()),
                Some("Acme".into()),
                &github()
            )
            .unwrap(),
            ("Acme/Widgets".to_string(), Some("Acme".to_string()))
        );
        // Forgejo's names are not consulted in legacy mode.
        let env = ci(&[
            ("FORGEJO_SERVER_URL", "https://codeberg.org"),
            ("FORGEJO_REPOSITORY", "acme/widgets"),
        ]);
        let message = select_resources(ResourceFormat::Legacy, None, None, &env)
            .unwrap_err()
            .to_string();
        assert_eq!(message, "--resource is required (or set GITHUB_REPOSITORY)");
    }

    #[test]
    fn qualified_mode_derives_and_validates_both_resources() {
        assert_eq!(
            select_resources(
                ResourceFormat::Qualified,
                None,
                Some("GitHub.com/Acme".into()),
                &github()
            )
            .unwrap(),
            (
                "github.com/acme/widgets".to_string(),
                Some("github.com/acme".to_string())
            )
        );
        let message = select_resources(
            ResourceFormat::Qualified,
            None,
            Some("acme".into()),
            &github(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            message.contains("did you mean `github.com/acme`?"),
            "{message}"
        );
    }

    #[test]
    fn a_qualified_fallback_must_be_the_repositorys_own_namespace() {
        let select = |fallback: &str| {
            select_resources(
                ResourceFormat::Qualified,
                None,
                Some(fallback.into()),
                &github(),
            )
        };
        // The namespace, however it is cased, and the repository itself.
        for ok in [
            "github.com/acme",
            "GitHub.com/Acme",
            "github.com/acme/widgets",
        ] {
            assert!(select(ok).is_ok(), "{ok}");
        }
        // Another owner, a byte-prefix owner, another forge, a sibling
        // repository, a deeper path: never.
        for other in [
            "github.com/other",
            "github.com/acm",
            "github.com/acme-labs",
            "codeberg.org/acme",
            "ghe.example.com/acme",
            "github.com/acme/other",
            "github.com/acme/widgets/sub",
        ] {
            let message = select(other).unwrap_err().to_string();
            assert!(
                message.contains("does not contain --resource `github.com/acme/widgets`")
                    && message.contains("`github.com/acme`"),
                "{other}: {message}"
            );
        }
        // The same holds for an explicit primary.
        let message = select_resources(
            ResourceFormat::Qualified,
            Some("github.com/acme/widgets".into()),
            Some("github.com/evil".into()),
            &CiEnv::default(),
        )
        .unwrap_err()
        .to_string();
        assert!(message.contains("does not contain"), "{message}");
    }

    #[test]
    fn legacy_mode_refuses_a_qualified_fallback() {
        let message = select_resources(
            ResourceFormat::Legacy,
            None,
            Some("github.com/acme".into()),
            &github(),
        )
        .unwrap_err()
        .to_string();
        assert!(
            message.contains("is forge-qualified") && message.contains("legacy"),
            "{message}"
        );
        // A dotted first segment reads as a host: `john.doe/repo` is refused
        // too, while the bare dotted owner `john.doe` (no owner segment
        // after it, so not qualified) still passes.
        assert!(
            select_resources(
                ResourceFormat::Legacy,
                None,
                Some("john.doe/repo".into()),
                &github()
            )
            .is_err()
        );
        assert!(
            select_resources(
                ResourceFormat::Legacy,
                None,
                Some("john.doe".into()),
                &github()
            )
            .is_ok()
        );
        // A bare owner is still passed through untouched.
        assert_eq!(
            select_resources(ResourceFormat::Legacy, None, Some("Acme".into()), &github())
                .unwrap()
                .1
                .as_deref(),
            Some("Acme")
        );
    }

    #[test]
    fn qualified_mode_outside_ci_requires_an_explicit_resource() {
        let message = select_resources(ResourceFormat::Qualified, None, None, &CiEnv::default())
            .unwrap_err()
            .to_string();
        assert!(message.contains("--resource is required"), "{message}");
        assert!(message.contains("github.com/acme/widgets"), "{message}");
    }
}
