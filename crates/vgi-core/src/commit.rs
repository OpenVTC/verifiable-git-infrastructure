//! Git commit-object handling for signature verification.
//!
//! Git signs the commit object with its `gpgsig` header removed;
//! [`split_signed_commit`] reconstructs the exact signed bytes and recovers the
//! armored signature. [`normalize_sshsig_armor`] re-wraps an sshsig body to the
//! 70-column width strict PEM parsers require.

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
