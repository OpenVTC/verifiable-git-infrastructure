//! The plan's inputs that `vgi repo init` finds for itself when they are
//! not given: the repository, the registry, the pinned action and — for
//! Forgejo — the release checksum and the web-flow key.

use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;
use vgi_forge::Resource;

/// Where the verify-trust action and its releases live.
pub const VGI_REPO: &str = "OpenVTC/verifiable-git-infrastructure";
/// The action's path inside [`VGI_REPO`].
pub const ACTION_PATH: &str = ".github/actions/verify-trust";
/// The release tarball a Forgejo runner (Linux x86-64) downloads.
pub const LINUX_ASSET: &str = "verify-trust-x86_64-unknown-linux-gnu.tar.gz";

/// The repository `origin` names in the clone at `dir`, as a resource.
pub fn resource_from_origin(dir: &Path) -> Result<Resource> {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(["remote", "get-url", "origin"])
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "no --resource given and this is not a clone with an `origin` remote; pass \
             --resource <host>/<owner>/<repo>"
        );
    }
    let url = String::from_utf8(out.stdout).context("origin URL is not UTF-8")?;
    resource_from_remote(url.trim())
}

/// `https://github.com/Acme/Widgets.git`, `git@github.com:Acme/Widgets.git`
/// or `ssh://git@host:2222/acme/widgets` → `github.com/acme/widgets`.
pub fn resource_from_remote(url: &str) -> Result<Resource> {
    let unsupported =
        || anyhow!("cannot read a repository from the remote URL `{url}`; pass --resource");
    let (host, path) = if let Some(rest) = url.split_once("://").map(|(_, r)| r) {
        let (authority, path) = rest.split_once('/').ok_or_else(unsupported)?;
        let host = authority.rsplit('@').next().unwrap_or(authority);
        let host = host.split(':').next().unwrap_or(host);
        (host.to_string(), path.to_string())
    } else if let Some((userhost, path)) = url.split_once(':') {
        // scp-like: [user@]host:owner/repo
        let host = userhost.rsplit('@').next().unwrap_or(userhost);
        (host.to_string(), path.to_string())
    } else {
        return Err(unsupported());
    };
    let path = path.trim_end_matches('/');
    let path = path.strip_suffix(".git").unwrap_or(path);
    let r = Resource::parse_owner_repo(&format!("{host}/{path}"))?;
    r.require_owner_repo()?;
    Ok(r)
}

/// The registry DID a DID document refers to: a service whose `type` is (or
/// includes) `TrustRegistry` and whose endpoint `uri` is a DID.
pub fn registry_referral(doc: &Value) -> Option<String> {
    let services = doc.get("service")?.as_array()?;
    services.iter().find_map(|s| {
        let is_registry = match s.get("type")? {
            Value::String(t) => t == "TrustRegistry",
            Value::Array(ts) => ts.iter().any(|t| t == "TrustRegistry"),
            _ => false,
        };
        if !is_registry {
            return None;
        }
        let uri = match s.get("serviceEndpoint")? {
            Value::String(u) => u.as_str(),
            Value::Object(o) => o.get("uri")?.as_str()?,
            _ => return None,
        };
        uri.starts_with("did:").then(|| uri.to_string())
    })
}

/// Resolve `vtc_did` and take its `TrustRegistry` referral.
pub async fn resolve_registry(vtc_did: &str) -> Result<String> {
    let tdk = verify_trust::build_resolver(false).await?;
    let resolved = tdk
        .did_resolver()
        .resolve(vtc_did)
        .await
        .map_err(|e| anyhow!("could not resolve the VTC DID {vtc_did}: {e}"))?;
    let doc = serde_json::to_value(&resolved.doc).context("the VTC's DID document")?;
    registry_referral(&doc).ok_or_else(|| {
        anyhow!(
            "the VTC's DID document names no TrustRegistry; pass --registry <did> (the \
             community's Trust Registry DID)"
        )
    })
}

fn check_tag(tag: &str) -> Result<()> {
    let ok = !tag.is_empty()
        && tag
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if !ok {
        bail!("`{tag}` is not a release tag");
    }
    Ok(())
}

fn http() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .user_agent(concat!("vgi/", env!("CARGO_PKG_VERSION")))
        .timeout(std::time::Duration::from_secs(30))
        // Every URL here is https; a redirect must not downgrade it.
        .https_only(true)
        .build()
        .context("HTTP client")
}

async fn fetch_text(url: &str, accept: &str) -> Result<String> {
    let resp = http()?
        .get(url)
        .header("Accept", accept)
        .send()
        .await
        .with_context(|| format!("fetching {url}"))?;
    let status = resp.status();
    if !status.is_success() {
        bail!("fetching {url}: HTTP {status}");
    }
    resp.text().await.with_context(|| format!("reading {url}"))
}

/// Annotated tags followed before giving up (a tag of a tag of …).
const MAX_TAG_DEPTH: usize = 5;

/// The `object` a git ref or annotated tag points at: its type and sha.
fn git_object(v: &Value) -> Result<(String, String)> {
    let obj = v
        .get("object")
        .ok_or_else(|| anyhow!("no `object` in GitHub's reply"))?;
    let kind = obj
        .get("type")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no object type in GitHub's reply"))?;
    let sha = obj
        .get("sha")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("no object sha in GitHub's reply"))?;
    if sha.len() != 40 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("`{sha}` is not a commit sha");
    }
    Ok((kind.to_string(), sha.to_ascii_lowercase()))
}

async fn fetch_json(url: &str) -> Result<Value> {
    let text = fetch_text(url, "application/vnd.github+json").await?;
    serde_json::from_str(&text).with_context(|| format!("{url} is not JSON"))
}

/// The action pinned to the commit `tag` names: the tag ref
/// (`git/ref/tags/<tag>` — only a tag, never a branch of that name), with
/// an annotated tag dereferenced to its commit.
pub async fn resolve_action(tag: &str) -> Result<String> {
    check_tag(tag)?;
    let api = format!("https://api.github.com/repos/{VGI_REPO}/git");
    let fail = |e: anyhow::Error| {
        anyhow!("could not resolve the tag {tag} of {VGI_REPO} ({e:#}); pass --verify-trust-action")
    };
    let mut obj = git_object(
        &fetch_json(&format!("{api}/ref/tags/{tag}"))
            .await
            .map_err(fail)?,
    )
    .map_err(fail)?;
    for _ in 0..MAX_TAG_DEPTH {
        if obj.0 != "tag" {
            break;
        }
        obj = git_object(
            &fetch_json(&format!("{api}/tags/{}", obj.1))
                .await
                .map_err(fail)?,
        )
        .map_err(fail)?;
    }
    match obj {
        (kind, sha) if kind == "commit" => Ok(format!("{VGI_REPO}/{ACTION_PATH}@{sha}")),
        (kind, _) => Err(fail(anyhow!("the tag names a {kind}, not a commit"))),
    }
}

/// The SHA-256 the release publishes next to its Linux x86-64 tarball.
pub async fn release_sha256(tag: &str) -> Result<String> {
    check_tag(tag)?;
    let url = format!("https://github.com/{VGI_REPO}/releases/download/{tag}/{LINUX_ASSET}.sha256");
    let text = fetch_text(&url, "text/plain").await?;
    let hex = text
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        bail!("{url} is not a SHA-256; pass --verify-trust-sha256");
    }
    Ok(hex)
}

/// GitHub's `web-flow` key, from `https://github.com/web-flow.gpg`.
pub async fn web_flow_key() -> Result<Vec<u8>> {
    let text = fetch_text("https://github.com/web-flow.gpg", "*/*").await?;
    Ok(text.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn remotes_become_resources() {
        for (url, want) in [
            (
                "https://github.com/Acme/Widgets.git",
                "github.com/acme/widgets",
            ),
            ("https://github.com/acme/widgets", "github.com/acme/widgets"),
            ("git@github.com:Acme/Widgets.git", "github.com/acme/widgets"),
            (
                "ssh://git@codeberg.org:2222/alice/tool.git",
                "codeberg.org/alice/tool",
            ),
            (
                "https://user:pw@git.example.org/team/repo/",
                "git.example.org/team/repo",
            ),
        ] {
            assert_eq!(resource_from_remote(url).unwrap().as_str(), want, "{url}");
        }
        for bad in ["/tmp/repo", "https://github.com/acme", "file:///x/y"] {
            assert!(resource_from_remote(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_registry_referral_is_read_from_the_document() {
        let doc = json!({
            "id": "did:webvh:Qm:vtc.example",
            "service": [
                { "id": "#didcomm", "type": "DIDCommMessaging", "serviceEndpoint": "did:web:m" },
                {
                    "id": "did:webvh:Qm:vtc.example#trust-registry",
                    "type": "TrustRegistry",
                    "serviceEndpoint": {
                        "uri": "did:webvh:QmReg:registry.example",
                        "profile": "https://trustoverip.org/profiles/trqp/v2"
                    }
                }
            ]
        });
        assert_eq!(
            registry_referral(&doc).as_deref(),
            Some("did:webvh:QmReg:registry.example")
        );
        // An https endpoint is a registry *serving* TRQP, not a referral.
        let doc = json!({ "service": [
            { "type": ["TRQPRest", "TrustRegistry"], "serviceEndpoint": "https://r.example" }
        ]});
        assert_eq!(registry_referral(&doc), None);
        assert_eq!(registry_referral(&json!({})), None);
    }

    #[test]
    fn git_objects_are_read_from_refs_and_annotated_tags() {
        let sha = "0123456789ABCDEF0123456789abcdef01234567";
        let r = json!({ "ref": "refs/tags/v1", "object": { "type": "tag", "sha": sha } });
        assert_eq!(
            git_object(&r).unwrap(),
            ("tag".into(), sha.to_ascii_lowercase())
        );
        let t = json!({ "tag": "v1", "object": { "type": "commit", "sha": sha } });
        assert_eq!(git_object(&t).unwrap().0, "commit");
        assert!(git_object(&json!({ "object": { "type": "commit", "sha": "abc" } })).is_err());
        // A list of refs (what `git/refs` answers) is not one ref.
        assert!(git_object(&json!([{ "object": { "type": "commit", "sha": sha } }])).is_err());
    }

    #[test]
    fn tags_are_checked_before_they_reach_a_url() {
        assert!(check_tag("v0.4.14").is_ok());
        for bad in ["", "v1/../x", "v1?x", "v 1"] {
            assert!(check_tag(bad).is_err(), "{bad}");
        }
    }
}
