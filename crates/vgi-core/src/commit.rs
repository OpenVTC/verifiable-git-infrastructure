//! Git commit-object handling for signature verification.
//!
//! Git signs the commit object with its `gpgsig` header removed;
//! [`split_signed_commit`] reconstructs the exact signed bytes and recovers the
//! armored signature. [`normalize_sshsig_armor`] re-wraps an sshsig body to the
//! 70-column width strict PEM parsers require. [`committer_did`] reads the
//! signer identity a commit claims on its `committer` header.
//!
//! [`signer_did`] prefers the claim in the commit message's `Signed-by-DID:`
//! trailer. That trailer block is located with git's own rules, ported from
//! `find_trailer_block_start` in git's `trailer.c`, so that the DID which gets
//! verified is the one `git log --format='%(trailers:…)'`, `git
//! interpret-trailers --parse` and git-based review UIs show. The port is held
//! to real git by `tests/trailer_differential.rs`.

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

/// The trailer key that carries the signer DID.
const SIGNER_DID_KEY: &str = "Signed-by-DID";

/// Git's default comment prefix (`core.commentChar`).
///
/// This code reads no git configuration, so a repository that sets a
/// different comment character can have git see a trailer block where this
/// does not. That direction only loses a DID claim, and a lost claim fails
/// closed.
const COMMENT_PREFIX: char = '#';

/// The prefixes git treats as its own generated trailers
/// (`git_generated_prefixes` in git's `trailer.c`).
///
/// A line starting with one of these counts as a trailer line *and* unlocks
/// the 25%-non-trailer allowance in [`trailer_block_start`], whether or not
/// the line has a separator — which is why `(cherry picked from commit …)`,
/// with no `:` in it at all, can turn a mixed paragraph into a trailer block.
const GIT_GENERATED_PREFIXES: [&str; 2] = ["Signed-off-by: ", "(cherry picked from commit "];

/// Extract a bare DID from the `Signed-by-DID:` trailer of the commit
/// message's trailer block.
///
/// The trailer block is located with git's own rules rather than an
/// approximation of them, because the risk here is a *display* differential:
/// a reviewer reads the DID that `git log --format='%(trailers:…)'`, `git
/// interpret-trailers --parse` and every git-based UI report, so the DID that
/// verify-trust checks has to be that same one. Where the two disagree the
/// commit either claims a DID no reviewer is shown, or shows a DID nobody
/// checked. `crates/vgi-core/tests/trailer_differential.rs` holds git to this
/// by running both git commands over generated messages.
///
/// The claim is the *last* `Signed-by-DID` trailer git reports, and it is a
/// claim only when that trailer's value is a DID. An earlier trailer is never
/// promoted when a later one is not a DID: the last trailer is what a reader
/// scanning to the bottom of the block sees, so preferring an earlier one
/// would hide the checked DID behind it.
fn trailer_did(commit: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(commit).ok()?;
    let (_, message) = text.split_once("\n\n")?;
    let value = last_trailer_value(message, SIGNER_DID_KEY)?;
    let value = value.trim_ascii();
    if !value.starts_with("did:") {
        return None;
    }
    // The fragment names which key signed; the DID is the identity to resolve
    // and to ask the registry about.
    Some(
        value
            .split(['#', '?', '/'])
            .next()
            .unwrap_or(value)
            .to_string(),
    )
}

/// The value of the last trailer named `key` in `message`'s trailer block,
/// unfolded as git unfolds a continuation line.
///
/// Mirrors git's `trailer_block_get`: the block is split into entries, a line
/// whose first character is whitespace continues the entry before it (but
/// only when that entry had a separator), and every other line starts a new
/// entry. Key matching is case-insensitive, as it is for git's
/// `%(trailers:key=…)`.
fn last_trailer_value(message: &str, key: &str) -> Option<String> {
    let mut lines: Vec<&str> = message.split('\n').collect();
    // A message ending in a newline has no empty final line in git's view.
    if lines.last().is_some_and(|line| line.is_empty()) {
        lines.pop();
    }
    // git presents a commit's message from its subject onward: pretty.c's
    // `parse_commit_message` runs `skip_blank_lines` before recording where the
    // subject starts, and `%(trailers:…)` reads from there. So blank lines at
    // the very start of a message are not part of it. Keeping them would make
    // the subject look like a second paragraph, and turn a trailer-shaped
    // subject line — which `git log` and GitHub both display as the subject —
    // into a trailer nobody is shown.
    let before_subject = lines.iter().take_while(|line| is_blank(line)).count();
    let lines = &lines[before_subject..];

    let start = trailer_block_start(lines)?;

    let mut value: Option<String> = None;
    // Whether an entry is open for continuation lines, and whether that entry
    // is the one being looked for. A line without a separator (a comment or a
    // non-trailer line inside the block) opens nothing, so a continuation
    // after it is not folded into the trailer before it.
    let mut open: Option<bool> = None;
    for line in &lines[start..] {
        if open.is_some() && line.starts_with(|c: char| c.is_ascii_whitespace()) {
            if open == Some(true)
                && let Some(value) = value.as_mut()
            {
                // Keep the raw text, newline and all: git concatenates the
                // continuation onto the value and unfolds once, at the end.
                value.push('\n');
                value.push_str(line);
            }
            continue;
        }
        match separator_pos(line) {
            Some(position) => {
                let matched = line[..position].trim_ascii().eq_ignore_ascii_case(key);
                if matched {
                    value = Some(line[position + 1..].to_string());
                }
                open = Some(matched);
            }
            None => open = None,
        }
    }
    // git trims the assembled value, then unfolds it.
    value.map(|value| unfold(value.trim_ascii()))
}

/// Collapse every newline and the whitespace that follows it down to a single
/// space, as git's `unfold_value` does, then trim.
///
/// Whitespace *before* a newline is left alone, so a trailer value with
/// trailing spaces and a continuation line under it keeps those spaces and
/// gains one more for the fold — which is the text git reports, and is why the
/// value cannot be trimmed line by line as it is assembled.
fn unfold(value: &str) -> String {
    let mut unfolded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(newline) = rest.find('\n') {
        unfolded.push_str(&rest[..newline]);
        unfolded.push(' ');
        rest = rest[newline + 1..].trim_ascii_start();
    }
    unfolded.push_str(rest);
    unfolded.trim_ascii().to_string()
}

/// The index of the first line of the message's trailer block, following
/// git's `find_trailer_block_start` (`trailer.c`). `None` when git would see
/// no trailer block at all.
///
/// Only the final paragraph can be a trailer block, it cannot be the title
/// paragraph, and it qualifies when either every line in it is a trailer, or
/// it holds one of git's own generated trailers and is at least 25% trailer
/// lines.
fn trailer_block_start(lines: &[&str]) -> Option<usize> {
    // The first paragraph is the title and cannot hold trailers, so the scan
    // below stops at the blank line ending it. With no blank line anywhere
    // the message is all title, and so has no trailer block.
    let end_of_title = lines
        .iter()
        .position(|line| !line.starts_with(COMMENT_PREFIX) && is_blank(line))?;

    let mut recognized_prefix = false;
    let mut trailer_lines = 0_usize;
    let mut non_trailer_lines = 0_usize;
    // Lines that are continuations if a trailer turns up above them, and
    // non-trailers if a non-trailer does.
    let mut possible_continuation_lines = 0_usize;
    let mut only_spaces = true;

    for index in (end_of_title..lines.len()).rev() {
        let line = lines[index];
        if line.starts_with(COMMENT_PREFIX) {
            non_trailer_lines += possible_continuation_lines;
            possible_continuation_lines = 0;
            continue;
        }
        if is_blank(line) {
            if only_spaces {
                continue;
            }
            non_trailer_lines += possible_continuation_lines;
            if recognized_prefix && trailer_lines * 3 >= non_trailer_lines {
                return Some(index + 1);
            }
            if trailer_lines > 0 && non_trailer_lines == 0 {
                return Some(index + 1);
            }
            return None;
        }
        only_spaces = false;

        if GIT_GENERATED_PREFIXES
            .iter()
            .any(|prefix| line.starts_with(prefix))
        {
            trailer_lines += 1;
            possible_continuation_lines = 0;
            recognized_prefix = true;
        } else if separator_pos(line).is_some() {
            trailer_lines += 1;
            possible_continuation_lines = 0;
            // git also sets `recognized_prefix` here for a key named in
            // `trailer.<token>.key` configuration. This reads no git config,
            // so only git's own prefixes above unlock the 25% allowance; a
            // repository that configures more of them can have git see a
            // block this does not, which loses a claim and fails closed.
        } else if line.starts_with(|c: char| c.is_ascii_whitespace()) {
            possible_continuation_lines += 1;
        } else {
            non_trailer_lines += 1 + possible_continuation_lines;
            possible_continuation_lines = 0;
        }
    }
    None
}

/// The offset of the `:` that ends a trailer key, following git's
/// `find_separator` for its default separator set.
///
/// The key is alphanumerics and `-`, optionally followed by spaces or tabs
/// before the colon, and the colon may not be the first character. A line
/// starting with whitespace never has one, which is what makes it a
/// continuation line rather than a trailer.
fn separator_pos(line: &str) -> Option<usize> {
    let mut whitespace_found = false;
    for (offset, c) in line.char_indices() {
        if c == ':' {
            return (offset >= 1).then_some(offset);
        }
        if !whitespace_found && (c.is_ascii_alphanumeric() || c == '-') {
            continue;
        }
        if offset != 0 && (c == ' ' || c == '\t') {
            whitespace_found = true;
            continue;
        }
        return None;
    }
    None
}

/// Whether a line is blank in git's sense: empty, or only whitespace.
fn is_blank(line: &str) -> bool {
    line.trim_ascii().is_empty()
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

    // Git's trailer-block rules, as fast assertions that do not need `git` on
    // PATH. Every one of them is also checked against real git, over
    // generated messages, by `tests/trailer_differential.rs`.

    /// A commit whose committer is a plain email, so a DID claim can only come
    /// from the trailer.
    fn commit_with_body(body: &str) -> String {
        format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer Alice <alice@example.com> 1700000000 +0000\n\
             \n\
             {body}"
        )
    }

    const DID: &str = "did:webvh:QmA:example.com";

    #[test]
    fn a_trailer_in_a_mixed_paragraph_is_not_a_claim() {
        // git accepts the final paragraph as trailers only when every line is
        // a trailer, or when one of git's own trailers is in it. A
        // `Signed-by-DID` line appended to a prose paragraph is not a trailer
        // to git, so it must not be a claim here: it would be a DID that no
        // reviewer's tooling shows as one.
        let commit = commit_with_body(&format!(
            "subject\n\nprose about the change\nSigned-by-DID: {DID}\n"
        ));
        assert!(trailer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn a_trailer_in_the_title_paragraph_is_not_a_claim() {
        // The first paragraph is the title, and git never reads trailers from
        // it — not when it is the whole message, and not when the trailer is
        // the line under the subject with no blank line between.
        let commit = commit_with_body(&format!("Signed-by-DID: {DID}\n"));
        assert!(trailer_did(commit.as_bytes()).is_none());
        let commit = commit_with_body(&format!("subject\nSigned-by-DID: {DID}\n"));
        assert!(trailer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn whitespace_before_the_colon_still_names_the_trailer() {
        // git's key scan allows spaces and tabs between the key and the
        // colon, and trims them, so these are all the same trailer to it.
        for gap in ["", " ", "  ", "\t", " \t"] {
            let commit = commit_with_body(&format!("subject\n\nSigned-by-DID{gap}: {DID}#key-0\n"));
            assert_eq!(
                trailer_did(commit.as_bytes()).as_deref(),
                Some(DID),
                "gap {gap:?} must not hide the claim"
            );
        }
    }

    #[test]
    fn the_trailer_key_is_matched_case_insensitively() {
        // As `%(trailers:key=…)` matches it.
        for key in [
            "Signed-by-DID",
            "signed-by-did",
            "SIGNED-BY-DID",
            "Signed-By-Did",
        ] {
            let commit = commit_with_body(&format!("subject\n\n{key}: {DID}#key-0\n"));
            assert_eq!(
                trailer_did(commit.as_bytes()).as_deref(),
                Some(DID),
                "key {key:?} must be recognized"
            );
        }
    }

    #[test]
    fn a_folded_trailer_value_is_unfolded_like_git() {
        // git folds a continuation line into the value with a single space and
        // displays it that way. The result is not a resolvable DID, so the
        // commit fails closed — but it fails on the same text git shows,
        // rather than on a truncated prefix of it.
        let commit = commit_with_body(&format!("subject\n\nSigned-by-DID: {DID}\n  and more\n"));
        assert_eq!(
            trailer_did(commit.as_bytes()).as_deref(),
            Some("did:webvh:QmA:example.com and more")
        );
        // Only the whitespace *after* the newline collapses. The three spaces
        // before it are part of the value, so git reports them and the fold's
        // single space — four in all. Trimming the first line as it is read
        // would report one.
        let commit = commit_with_body(&format!("subject\n\nSigned-by-DID: {DID}   \n continued\n"));
        assert_eq!(
            trailer_did(commit.as_bytes()).as_deref(),
            Some("did:webvh:QmA:example.com    continued")
        );
    }

    #[test]
    fn a_git_generated_trailer_unlocks_the_25_percent_allowance() {
        // With a `Signed-off-by:` in the block, git tolerates non-trailer
        // lines while trailers are at least a quarter of it…
        let commit = commit_with_body(&format!(
            "subject\n\nn1\nn2\nn3\nSigned-off-by: A U Thor <a@example.com>\nSigned-by-DID: {DID}\n"
        ));
        assert_eq!(trailer_did(commit.as_bytes()).as_deref(), Some(DID));
        // …and past that boundary sees no trailer block at all.
        let commit = commit_with_body(&format!(
            "subject\n\nn1\nn2\nn3\nn4\nn5\nn6\nn7\n\
             Signed-off-by: A U Thor <a@example.com>\nSigned-by-DID: {DID}\n"
        ));
        assert!(trailer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn a_cherry_pick_line_unlocks_the_allowance_without_a_separator() {
        // `(cherry picked from commit …)` holds no colon, so it is not a
        // trailer line by the separator rule, yet git counts it as one of its
        // own and lets the block through.
        let commit = commit_with_body(&format!(
            "subject\n\nprose\n\
             (cherry picked from commit 0123456789abcdef0123456789abcdef01234567)\n\
             Signed-by-DID: {DID}\n"
        ));
        assert_eq!(trailer_did(commit.as_bytes()).as_deref(), Some(DID));
    }

    #[test]
    fn a_line_whose_colon_comes_first_defeats_the_block() {
        // A separator at offset 0 is not a trailer to git, so the paragraph is
        // neither all trailers nor git-generated, and holds no claim.
        let commit = commit_with_body(&format!(
            "subject\n\n: did:webvh:QmEvil:attacker.example\nSigned-by-DID: {DID}\n"
        ));
        assert!(trailer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn the_last_trailer_wins_even_when_its_value_is_not_a_did() {
        // git reports both trailers, and the last one is what a reader
        // scanning to the bottom of the block sees, so an earlier DID is not
        // promoted over it.
        let commit = commit_with_body(
            "subject\n\nSigned-by-DID: did:webvh:QmFirst:example.com\nSigned-by-DID: see below\n",
        );
        assert!(trailer_did(commit.as_bytes()).is_none());
    }

    #[test]
    fn blank_lines_before_the_subject_are_skipped_like_git() {
        // git shows a commit's message from its subject onward, skipping blank
        // lines before it. So in each of these the `Signed-by-DID` line *is*
        // the subject, with no trailer block under it, and reading a claim
        // here would verify a DID that `git log` and GitHub display as the
        // commit's subject line.
        for prefix in ["\n", "   \n", "\t\n", "\n\n"] {
            let commit = commit_with_body(&format!("{prefix}Signed-by-DID: {DID}\n"));
            assert!(
                trailer_did(commit.as_bytes()).is_none(),
                "with prefix {prefix:?} the trailer line is the subject git shows"
            );
        }
        // The skip must not cost a real trailer block further down.
        let commit = commit_with_body(&format!("\nsubject\n\nSigned-by-DID: {DID}\n"));
        assert_eq!(trailer_did(commit.as_bytes()).as_deref(), Some(DID));
    }

    #[test]
    fn comment_lines_do_not_count_against_the_block() {
        // git skips them when deciding what the block is.
        let commit = commit_with_body(&format!("subject\n\n# a comment\nSigned-by-DID: {DID}\n"));
        assert_eq!(trailer_did(commit.as_bytes()).as_deref(), Some(DID));
    }
}
