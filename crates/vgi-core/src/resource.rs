//! Forge-qualified trust-tuple resources.
//!
//! A resource names the forge first, then the path on it:
//!
//! ```text
//! resource   = forge-host "/" segment *( "/" segment )
//! forge-host = lowercased DNS host of the forge: github.com, a GHES host,
//!              codeberg.org, a self-hosted git.example.org, or localhost
//! segment    = lowercased [a-z0-9._-]+, never "." or ".."
//! ```
//!
//! `github.com/acme` and `github.com/acme/widgets` are resources;
//! `acme/widgets` is not. The forge is explicit because `github.com/acme` and
//! `codeberg.org/acme` may belong to different people, and a grant that
//! silently assumed one of them would be a grant to whoever holds the other.
//!
//! Normalisation is deliberately narrow: ASCII case is folded (GitHub and
//! Forgejo owners and repo names are case-insensitive, so `Acme/Widgets` and
//! `acme/widgets` are one repository and must be one resource), and nothing
//! else is repaired. A scheme, a trailing slash, a `.git` suffix or an empty
//! segment is refused with a message that says what to write instead, rather
//! than quietly rewritten — `resource` is what scopes a signer, and an input
//! that needed guessing at is one to show back to the operator.
//!
//! How many path segments a forge allows is the forge's rule, not the
//! grammar's: GitHub and Forgejo have exactly an owner and optionally a repo,
//! while a forge with nested groups keeps its full path. Callers that know
//! their forge pass that bound to [`normalize_resource_with_depth`].

use std::fmt;

/// Longest resource accepted, in bytes. Far above any real forge path
/// (GitHub: 39-byte owners, 100-byte repo names) while keeping a hostile
/// input from turning into an unbounded registry key.
pub const MAX_RESOURCE_LEN: usize = 512;

/// Most path segments (after the host) [`normalize_resource`] accepts when the
/// caller states no forge-specific bound. GitLab allows 20 levels of subgroup
/// under a top-level group, so this is that plus the project.
pub const MAX_PATH_SEGMENTS: usize = 21;

/// Why a string is not a valid forge-qualified resource.
///
/// The `Display` form names the offending input and suggests the fix, so it
/// can be shown to an operator as-is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceError {
    input: String,
    kind: ResourceErrorKind,
}

/// The specific rule a resource broke.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResourceErrorKind {
    /// Nothing but whitespace, or nothing at all.
    Empty,
    /// Longer than [`MAX_RESOURCE_LEN`].
    TooLong,
    /// Contains whitespace or a control character.
    Whitespace,
    /// Contains a non-ASCII character (hosts must be given in punycode).
    NonAscii,
    /// Starts with a URL scheme such as `https://`.
    HasScheme,
    /// The first segment is not a forge host — the `owner/repo` form.
    MissingForgeHost,
    /// The first segment looks like a host but is not a valid one.
    InvalidHost,
    /// A host with a `:port`. Resources name a forge by host alone.
    HasPort,
    /// Only a host, with no owner after it.
    MissingOwner,
    /// Two slashes in a row, or a leading/trailing slash.
    EmptySegment,
    /// A `.` or `..` segment.
    DotSegment,
    /// A character outside `[a-z0-9._-]` in a path segment.
    InvalidCharacter(char),
    /// More path segments than the forge allows.
    TooManySegments {
        /// The bound that was exceeded.
        max: usize,
    },
}

impl ResourceError {
    fn new(input: &str, kind: ResourceErrorKind) -> Self {
        // Keep enough of a hostile input to be recognisable in a message, not
        // the whole of it.
        let input = if input.len() > 80 {
            let mut end = 80;
            while !input.is_char_boundary(end) {
                end -= 1;
            }
            format!("{}…", &input[..end])
        } else {
            input.to_string()
        };
        Self { input, kind }
    }

    /// The rule that was broken.
    pub fn kind(&self) -> &ResourceErrorKind {
        &self.kind
    }

    /// The input that was rejected (truncated if it was long).
    pub fn input(&self) -> &str {
        &self.input
    }

    /// The message, naming the value `what` (`--resource`, `resource
    /// derived from GITHUB_REPOSITORY`, …). [`fmt::Display`] is
    /// `describe("resource")`.
    pub fn describe(&self, what: &str) -> String {
        let v = &self.input;
        let e = "`<forge-host>/<owner>[/<repo>]`";
        match &self.kind {
            ResourceErrorKind::Empty => {
                format!("{what} is empty; expected {e}, e.g. `github.com/acme/widgets`")
            }
            ResourceErrorKind::TooLong => {
                format!("{what} `{v}` is longer than {MAX_RESOURCE_LEN} bytes")
            }
            ResourceErrorKind::Whitespace => format!(
                "{what} `{v}` contains whitespace or a control character; a resource is {e} \
                 with no spaces"
            ),
            ResourceErrorKind::NonAscii => format!(
                "{what} `{v}` contains a non-ASCII character; forge hosts are written in \
                 punycode and owner/repo names are ASCII"
            ),
            ResourceErrorKind::HasScheme => format!(
                "{what} `{v}` is a URL, not a resource; did you mean `{}`?",
                suggest_without_scheme(v)
            ),
            ResourceErrorKind::MissingForgeHost => {
                let bare = v.trim_matches('/').to_ascii_lowercase();
                format!(
                    "{what} `{v}` is not forge-qualified (expected {e}); prefix the forge host, \
                     e.g. `github.com/{bare}` or `codeberg.org/{bare}`"
                )
            }
            ResourceErrorKind::InvalidHost => format!(
                "{what} `{v}` starts with an invalid forge host; a host is dot-separated labels \
                 of [a-z0-9-] (e.g. `github.com`, `git.example.org`) or `localhost`"
            ),
            ResourceErrorKind::HasPort => format!(
                "{what} `{v}` carries a port; a resource names the forge by host alone — did you \
                 mean `{}`?",
                suggest_without_port(v)
            ),
            ResourceErrorKind::MissingOwner => {
                let host = v.trim_end_matches('/').to_ascii_lowercase();
                format!(
                    "{what} `{v}` names a forge but no owner; e.g. `{host}/acme` or \
                     `{host}/acme/widgets`"
                )
            }
            ResourceErrorKind::EmptySegment => format!(
                "{what} `{v}` has an empty path segment (a doubled, leading or trailing `/`); \
                 did you mean `{}`?",
                suggest_collapsed(v)
            ),
            ResourceErrorKind::DotSegment => {
                format!("{what} `{v}` has a `.` or `..` segment; name the owner and repo directly")
            }
            ResourceErrorKind::InvalidCharacter(c) => format!(
                "{what} `{v}` contains `{}`; owner and repo segments may only contain letters, \
                 digits, `.`, `_` and `-`",
                c.escape_default()
            ),
            ResourceErrorKind::TooManySegments { max } => format!(
                "{what} `{v}` has too many segments for this forge: at most {max} after the host \
                 (`<forge-host>/<owner>/<repo>`)"
            ),
        }
    }
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.describe("resource"))
    }
}

impl std::error::Error for ResourceError {}

/// Normalise a forge-qualified resource, allowing up to
/// [`MAX_PATH_SEGMENTS`] path segments after the host.
///
/// Returns the canonical, lowercased form. See the module docs for the
/// grammar and why only case is folded.
pub fn normalize_resource(raw: &str) -> Result<String, ResourceError> {
    normalize_resource_with_depth(raw, MAX_PATH_SEGMENTS)
}

/// Normalise a forge-qualified resource with at most `max_path_segments`
/// segments after the host — `2` for GitHub and Forgejo (`owner/repo`).
pub fn normalize_resource_with_depth(
    raw: &str,
    max_path_segments: usize,
) -> Result<String, ResourceError> {
    let err = |kind| ResourceError::new(raw, kind);

    if raw.trim().is_empty() {
        return Err(err(ResourceErrorKind::Empty));
    }
    if raw.len() > MAX_RESOURCE_LEN {
        return Err(err(ResourceErrorKind::TooLong));
    }
    if raw.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(err(ResourceErrorKind::Whitespace));
    }
    if !raw.is_ascii() {
        return Err(err(ResourceErrorKind::NonAscii));
    }
    if raw.contains("://") {
        return Err(err(ResourceErrorKind::HasScheme));
    }

    let lowered = raw.to_ascii_lowercase();
    let segments: Vec<&str> = lowered.split('/').collect();
    let host = segments[0];

    // The host decides whether this is the legacy `owner/repo` form, so check
    // it before complaining about anything after it.
    if host.is_empty() {
        // A leading slash: in front of a host it is just an empty segment,
        // in front of `acme/widgets` it is the legacy slug.
        return Err(err(match segments.get(1) {
            Some(next) if !next.is_empty() && !looks_like_host(next) => {
                ResourceErrorKind::MissingForgeHost
            }
            _ => ResourceErrorKind::EmptySegment,
        }));
    }
    if let Some((name, _port)) = host.split_once(':') {
        if looks_like_host(name) {
            return Err(err(ResourceErrorKind::HasPort));
        }
        return Err(err(ResourceErrorKind::InvalidHost));
    }
    if !looks_like_host(host) {
        return Err(err(if host.is_empty() {
            ResourceErrorKind::EmptySegment
        } else {
            ResourceErrorKind::MissingForgeHost
        }));
    }
    if !is_valid_host(host) {
        return Err(err(ResourceErrorKind::InvalidHost));
    }

    let path = &segments[1..];
    if path.is_empty() || (path.len() == 1 && path[0].is_empty()) {
        return Err(err(ResourceErrorKind::MissingOwner));
    }
    if path.iter().any(|s| s.is_empty()) {
        return Err(err(ResourceErrorKind::EmptySegment));
    }
    if path.iter().any(|s| *s == "." || *s == "..") {
        return Err(err(ResourceErrorKind::DotSegment));
    }
    if let Some(c) = path
        .iter()
        .flat_map(|s| s.chars())
        .find(|c| !is_segment_char(*c))
    {
        return Err(err(ResourceErrorKind::InvalidCharacter(c)));
    }
    if path.len() > max_path_segments {
        return Err(err(ResourceErrorKind::TooManySegments {
            max: max_path_segments,
        }));
    }

    Ok(lowered)
}

/// Segment-prefix containment of two normalised resources: `scope` contains
/// `resource` when it is equal to it or a whole-segment prefix of it.
///
/// `github.com/acme` contains `github.com/acme/widgets`; it does not contain
/// `github.com/acme-labs/x` (a byte prefix, not a segment prefix) or
/// `codeberg.org/acme/widgets` (another forge). Both arguments must already be
/// normalised — this compares bytes and does not fold case.
pub fn resource_contains(scope: &str, resource: &str) -> bool {
    match resource.strip_prefix(scope) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

/// Whether a first segment is meant as a host: a dotted name or `localhost`.
/// `acme` in `acme/widgets` is not, which is how the legacy form is caught.
fn looks_like_host(segment: &str) -> bool {
    segment.contains('.') || segment == "localhost"
}

/// RFC 1123 host: dot-separated labels of `[a-z0-9-]`, 1–63 bytes each, not
/// starting or ending with `-`.
fn is_valid_host(host: &str) -> bool {
    host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn is_segment_char(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-')
}

fn suggest_without_scheme(input: &str) -> String {
    let rest = input.split_once("://").map_or(input, |(_, rest)| rest);
    let rest = rest.trim_end_matches('/');
    rest.strip_suffix(".git")
        .unwrap_or(rest)
        .to_ascii_lowercase()
}

fn suggest_without_port(input: &str) -> String {
    let lowered = input.to_ascii_lowercase();
    match lowered.split_once('/') {
        Some((host, rest)) => {
            let host = host.split_once(':').map_or(host, |(h, _)| h);
            format!("{host}/{rest}")
        }
        None => lowered,
    }
}

fn suggest_collapsed(input: &str) -> String {
    input
        .to_ascii_lowercase()
        .split('/')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(raw: &str) -> ResourceErrorKind {
        normalize_resource_with_depth(raw, 2)
            .expect_err(raw)
            .kind()
            .clone()
    }

    #[test]
    fn canonical_resources_pass_through() {
        for ok in [
            "github.com/acme",
            "github.com/acme/widgets",
            "codeberg.org/acme/widgets",
            "git.example.org/acme/.github",
            "ghe.corp.example/team-a/repo_1.x",
            "localhost/acme/widgets",
        ] {
            assert_eq!(normalize_resource_with_depth(ok, 2).as_deref(), Ok(ok));
        }
    }

    #[test]
    fn case_is_folded_and_nothing_else() {
        assert_eq!(
            normalize_resource("GitHub.com/Acme/Widgets").as_deref(),
            Ok("github.com/acme/widgets")
        );
    }

    #[test]
    fn the_legacy_owner_repo_form_is_refused_with_a_suggestion() {
        let err = normalize_resource_with_depth("Acme/Widgets", 2).unwrap_err();
        assert_eq!(err.kind(), &ResourceErrorKind::MissingForgeHost);
        assert!(err.to_string().contains("github.com/acme/widgets"), "{err}");
        assert_eq!(kind("acme"), ResourceErrorKind::MissingForgeHost);
        assert_eq!(kind("/acme/widgets"), ResourceErrorKind::MissingForgeHost);
    }

    #[test]
    fn urls_are_refused_with_the_bare_form_suggested() {
        let err =
            normalize_resource_with_depth("https://github.com/Acme/widgets.git", 2).unwrap_err();
        assert_eq!(err.kind(), &ResourceErrorKind::HasScheme);
        assert!(
            err.to_string().contains("`github.com/acme/widgets`"),
            "{err}"
        );
    }

    #[test]
    fn empty_and_dot_segments_are_refused() {
        assert_eq!(kind("github.com//widgets"), ResourceErrorKind::EmptySegment);
        assert_eq!(kind("github.com/acme/"), ResourceErrorKind::EmptySegment);
        assert_eq!(kind("/github.com/acme"), ResourceErrorKind::EmptySegment);
        assert_eq!(kind("github.com/acme/.."), ResourceErrorKind::DotSegment);
        assert_eq!(kind("github.com/./acme"), ResourceErrorKind::DotSegment);
        let err = normalize_resource_with_depth("github.com//acme//x", 2).unwrap_err();
        assert!(err.to_string().contains("`github.com/acme/x`"), "{err}");
    }

    #[test]
    fn a_host_alone_asks_for_an_owner() {
        assert_eq!(kind("github.com"), ResourceErrorKind::MissingOwner);
        assert_eq!(kind("github.com/"), ResourceErrorKind::MissingOwner);
    }

    #[test]
    fn hosts_are_checked() {
        assert_eq!(kind("github.com:443/acme"), ResourceErrorKind::HasPort);
        assert_eq!(kind("-bad.example/acme"), ResourceErrorKind::InvalidHost);
        assert_eq!(kind("bad..example/acme"), ResourceErrorKind::InvalidHost);
        assert_eq!(kind("git_hub.com/acme"), ResourceErrorKind::InvalidHost);
        let err = normalize_resource_with_depth("GitHub.com:8443/acme/x", 2).unwrap_err();
        assert!(err.to_string().contains("`github.com/acme/x`"), "{err}");
    }

    #[test]
    fn odd_characters_are_refused() {
        assert_eq!(kind("github.com/ac me"), ResourceErrorKind::Whitespace);
        assert_eq!(kind(" github.com/acme"), ResourceErrorKind::Whitespace);
        assert_eq!(kind("github.com/acmé"), ResourceErrorKind::NonAscii);
        assert_eq!(
            kind("github.com/acme/w%2e"),
            ResourceErrorKind::InvalidCharacter('%')
        );
        assert_eq!(
            kind("github.com/acme@x"),
            ResourceErrorKind::InvalidCharacter('@')
        );
        assert_eq!(kind(""), ResourceErrorKind::Empty);
        assert_eq!(
            kind(&format!("github.com/{}", "a".repeat(600))),
            ResourceErrorKind::TooLong
        );
    }

    #[test]
    fn depth_is_the_callers_bound() {
        assert_eq!(
            kind("gitlab.com/group/sub/project"),
            ResourceErrorKind::TooManySegments { max: 2 }
        );
        assert_eq!(
            normalize_resource("gitlab.com/Group/Sub/Project").as_deref(),
            Ok("gitlab.com/group/sub/project")
        );
    }

    #[test]
    fn containment_is_by_whole_segment_and_never_crosses_forges() {
        assert!(resource_contains("github.com/acme", "github.com/acme"));
        assert!(resource_contains(
            "github.com/acme",
            "github.com/acme/widgets"
        ));
        assert!(!resource_contains(
            "github.com/acme",
            "github.com/acme-labs/x"
        ));
        assert!(!resource_contains(
            "github.com/acme",
            "codeberg.org/acme/widgets"
        ));
        assert!(!resource_contains(
            "github.com/acme/widgets",
            "github.com/acme"
        ));
    }

    #[test]
    fn long_hostile_inputs_are_truncated_in_errors() {
        let err = normalize_resource(&"é".repeat(400)).unwrap_err();
        assert!(err.input().len() < 100);
    }
}
