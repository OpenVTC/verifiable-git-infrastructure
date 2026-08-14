//! Git commit-object handling for signature verification.
//!
//! Git signs the commit object with its `gpgsig` header removed;
//! [`split_signed_commit`] reconstructs the exact signed bytes and recovers the
//! armored signature. [`normalize_sshsig_armor`] re-wraps an sshsig body to the
//! 70-column width strict PEM parsers require. [`committer_did`] reads the
//! signer identity a commit claims on its `committer` header.

use anyhow::{Context, Result, bail};

/// Re-wrap an sshsig armor's base64 body at 70 columns.
///
/// OpenSSH's own base64 reader accepts any line width, but the strict PEM
/// parser underneath `SshSig::from_pem` requires exactly the 70-column
/// wrapping ssh-keygen emits. Signatures created by did-git-sign before it
/// matched ssh-keygen's width (76 columns) live on in git history, so the
/// armor is normalized rather than trusted to be canonical.
pub fn normalize_sshsig_armor(pem: &str) -> String {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .map(str::trim)
        .collect();
    let mut normalized = String::from("-----BEGIN SSH SIGNATURE-----\n");
    for chunk in body.as_bytes().chunks(70) {
        // Chunks of an ASCII base64 string are always valid UTF-8.
        normalized.push_str(&String::from_utf8_lossy(chunk));
        normalized.push('\n');
    }
    normalized.push_str("-----END SSH SIGNATURE-----\n");
    normalized
}

/// Split a raw commit object into (payload-as-signed, armored signature).
///
/// Git signs the commit object with the `gpgsig` header removed; the header's
/// value spans continuation lines (each prefixed with one space). Returns
/// `Ok(None)` for an unsigned commit.
pub fn split_signed_commit(raw: &[u8]) -> Result<Option<(Vec<u8>, String)>> {
    let text = std::str::from_utf8(raw).context("commit object is not UTF-8")?;
    let Some((headers, body)) = text.split_once("\n\n") else {
        bail!("malformed commit object: no header/body separator");
    };

    let mut kept_headers: Vec<&str> = Vec::new();
    let mut signature_lines: Vec<&str> = Vec::new();
    let mut in_gpgsig = false;
    for line in headers.split('\n') {
        if let Some(first) = line.strip_prefix("gpgsig ") {
            in_gpgsig = true;
            signature_lines.push(first);
        } else if in_gpgsig && let Some(continuation) = line.strip_prefix(' ') {
            signature_lines.push(continuation);
        } else {
            in_gpgsig = false;
            kept_headers.push(line);
        }
    }

    if signature_lines.is_empty() {
        return Ok(None);
    }

    let mut payload = kept_headers.join("\n").into_bytes();
    payload.extend_from_slice(b"\n\n");
    payload.extend_from_slice(body.as_bytes());

    let mut pem = signature_lines.join("\n");
    pem.push('\n');
    Ok(Some((payload, pem)))
}

/// The committer identity: the `<…>` field of the `committer` header.
///
/// Read from the header block only, so a body line that happens to begin with
/// `committer ` cannot be mistaken for the header. Returns `None` for a commit
/// with no committer header or no angle-bracketed identity.
#[must_use]
pub fn committer_identity(commit: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(commit).ok()?;
    let headers = text.split_once("\n\n").map_or(text, |(headers, _)| headers);
    let line = headers
        .split('\n')
        .find_map(|line| line.strip_prefix("committer "))?;
    // `rfind` so a display name containing '<' cannot truncate the identity.
    let open = line.rfind('<')?;
    let close = line[open..].find('>')? + open;
    Some(line[open + 1..close].to_string())
}

/// The signer DID a commit claims: its committer identity when that is a DID,
/// reduced to the bare DID.
///
/// `did-git-sign` sets `user.email` to the verification-method id it signs
/// with (`did:webvh:…#key-0`); the fragment names *which* key, while the DID
/// is the identity to resolve and to ask the registry about, so any
/// fragment, path or query is stripped.
///
/// This is a **claim**, not an authenticated fact — the committer header is
/// author-controlled text. It is safe to use only as a lookup hint whose
/// answer is then checked: the DID must publish the key that actually signed,
/// and the signature must verify over a payload that includes this very
/// header. A commit claiming a DID it cannot sign for fails both checks.
#[must_use]
pub fn committer_did(commit: &[u8]) -> Option<String> {
    let identity = committer_identity(commit)?;
    if !identity.starts_with("did:") {
        return None;
    }
    let did = identity
        .split(['#', '?', '/'])
        .next()
        .unwrap_or(identity.as_str());
    if did.is_empty() {
        return None;
    }
    Some(did.to_string())
}

/// The signer DID a commit claims, checking the `Signed-by-DID:` trailer
/// first, then falling back to the committer email for legacy commits.
///
/// The trailer is the canonical location for new commits (it lets
/// `user.email` be a normal email for git-host attribution). Old commits
/// that carried the DID in the committer email still verify via the
/// fallback.
#[must_use]
pub fn signer_did(commit: &[u8]) -> Option<String> {
    trailer_did(commit).or_else(|| committer_did(commit))
}

/// Return both explicit identity claims when the final `Signed-by-DID:`
/// trailer and legacy DID committer identity disagree.
#[must_use]
pub fn conflicting_signer_dids(commit: &[u8]) -> Option<(String, String)> {
    let trailer = trailer_did(commit)?;
    let committer = committer_did(commit)?;
    (trailer != committer).then_some((trailer, committer))
}

/// Extract a bare DID from a `Signed-by-DID:` trailer in the commit body's
/// final trailer block.
fn trailer_did(commit: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(commit).ok()?;
    let (_, body) = text.split_once("\n\n")?;

    let mut lines: Vec<&str> = body.lines().collect();
    while lines.last().is_some_and(|line| line.trim().is_empty()) {
        lines.pop();
    }

    let mut trailer_start = lines.len();
    while trailer_start > 0 && is_trailer_line(lines[trailer_start - 1]) {
        trailer_start -= 1;
    }
    if trailer_start == lines.len() {
        return None;
    }

    for line in lines[trailer_start..].iter().rev() {
        if let Some(value) = line.strip_prefix("Signed-by-DID:") {
            let value = value.trim();
            if value.starts_with("did:") {
                return Some(
                    value
                        .split(['#', '?', '/'])
                        .next()
                        .unwrap_or(value)
                        .to_string(),
                );
            }
        }
    }
    None
}

fn is_trailer_line(line: &str) -> bool {
    let Some((key, _)) = line.split_once(':') else {
        return false;
    };
    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    fn commit_with_committer(committer: &str) -> String {
        format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer {committer} 1700000000 +0000\n\
             \n\
             a message\n"
        )
    }

    #[test]
    fn a_did_committer_yields_the_bare_did() {
        let commit = commit_with_committer("Alice <did:webvh:QmAbc:example.com#key-0>");
        assert_eq!(
            committer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmAbc:example.com",
            "the fragment names the key, not the identity the registry knows"
        );
    }

    #[test]
    fn a_did_without_a_fragment_survives_intact() {
        let commit = commit_with_committer("Alice <did:webvh:QmAbc:example.com>");
        assert_eq!(
            committer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmAbc:example.com"
        );
    }

    #[test]
    fn a_plain_email_committer_claims_no_did() {
        let commit = commit_with_committer("Alice <alice@example.com>");
        assert!(committer_did(commit.as_bytes()).is_none());
        assert_eq!(
            committer_identity(commit.as_bytes()).unwrap(),
            "alice@example.com",
            "the identity is still reported, so the failure can name it"
        );
    }

    #[test]
    fn a_body_line_cannot_impersonate_the_committer_header() {
        // The header block ends at the first blank line; everything after it
        // is the message, where an author controls every byte.
        let commit = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer A U Thor <alice@example.com> 1700000000 +0000\n\
             \n\
             committer Evil <did:webvh:QmEvil:attacker.example> 1700000000 +0000\n";
        assert!(
            committer_did(commit.as_bytes()).is_none(),
            "a DID in the message body must not be read as the committer"
        );
    }

    #[test]
    fn a_display_name_containing_an_angle_bracket_does_not_truncate() {
        let commit = commit_with_committer("A <script> Thor <did:webvh:QmAbc:example.com#key-1>");
        assert_eq!(
            committer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmAbc:example.com"
        );
    }

    #[test]
    fn a_signed_commits_payload_still_exposes_the_committer() {
        // The committer header is a kept header, so it survives the gpgsig
        // strip and is covered by the signature.
        let commit = commit_with_committer("Alice <did:webvh:QmAbc:example.com#key-0>");
        let (headers, body) = commit.split_once("\n\n").unwrap();
        let signed = format!(
            "{headers}\ngpgsig -----BEGIN SSH SIGNATURE-----\n \
             AAAA\n -----END SSH SIGNATURE-----\n\n{body}"
        );
        let (payload, _) = split_signed_commit(signed.as_bytes()).unwrap().unwrap();
        assert_eq!(
            committer_did(&payload).unwrap(),
            "did:webvh:QmAbc:example.com"
        );
    }

    fn commit_with_trailer(committer: &str, trailer: &str) -> String {
        format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer {committer} 1700000000 +0000\n\
             \n\
             a message\n\
             \n\
             {trailer}\n"
        )
    }

    #[test]
    fn signer_did_prefers_trailer_over_committer() {
        let commit = commit_with_trailer(
            "Alice <did:webvh:QmOld:old.example#key-0>",
            "Signed-by-DID: did:webvh:QmNew:new.example#key-0",
        );
        assert_eq!(
            signer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmNew:new.example",
            "trailer must take precedence over committer email"
        );
    }

    #[test]
    fn signer_did_falls_back_to_committer_for_legacy_commits() {
        let commit = commit_with_committer("Alice <did:webvh:QmAbc:example.com#key-0>");
        assert_eq!(
            signer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmAbc:example.com",
            "legacy commits with DID in committer email must still work"
        );
    }

    #[test]
    fn signer_did_reads_trailer_with_normal_email_committer() {
        let commit = commit_with_trailer(
            "Alice <alice@example.com>",
            "Signed-by-DID: did:webvh:QmAbc:example.com#key-0",
        );
        assert_eq!(
            signer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmAbc:example.com",
        );
    }

    #[test]
    fn signer_did_returns_none_without_did_anywhere() {
        let commit = commit_with_committer("Alice <alice@example.com>");
        assert!(signer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn trailer_strips_fragment() {
        let commit = commit_with_trailer(
            "Alice <alice@example.com>",
            "Signed-by-DID: did:webvh:QmAbc:example.com#key-1",
        );
        assert_eq!(
            signer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmAbc:example.com",
        );
    }

    #[test]
    fn trailer_ignores_non_did_values() {
        let commit = commit_with_trailer("Alice <alice@example.com>", "Signed-by-DID: not-a-did");
        assert!(signer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn signer_did_ignores_body_line_outside_final_trailer_block() {
        let commit = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer Alice <alice@example.com> 1700000000 +0000\n\
             \n\
             This line only discusses a trailer.\n\
             Signed-by-DID: did:webvh:QmBody:example.com#key-0\n\
             \n\
             final prose, not a trailer block\n";
        assert!(signer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn signer_did_reads_final_trailer_block_only() {
        let commit = "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer Alice <alice@example.com> 1700000000 +0000\n\
             \n\
             Signed-by-DID: did:webvh:QmBody:ignored.example#key-0\n\
             \n\
             body text\n\
             \n\
             Signed-off-by: Alice <alice@example.com>\n\
             Signed-by-DID: did:webvh:QmTrailer:example.com#key-0\n";
        assert_eq!(
            signer_did(commit.as_bytes()).unwrap(),
            "did:webvh:QmTrailer:example.com"
        );
    }

    #[test]
    fn conflicting_signer_dids_reports_trailer_and_committer_disagreement() {
        let commit = commit_with_trailer(
            "Alice <did:webvh:QmCommitter:example.com#key-0>",
            "Signed-by-DID: did:webvh:QmTrailer:example.com#key-0",
        );
        assert_eq!(
            conflicting_signer_dids(commit.as_bytes()).unwrap(),
            (
                "did:webvh:QmTrailer:example.com".to_string(),
                "did:webvh:QmCommitter:example.com".to_string(),
            )
        );
    }
}
