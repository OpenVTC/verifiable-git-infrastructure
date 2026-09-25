//! DID syntax and shell quoting for the command `vgi repo init` prints.
//!
//! The printed `cnm git adopt …` line is meant to be copied into a shell, so
//! every argument in it is either DID-core-validated or a normalised
//! resource, and is quoted anyway: a value that needs no quoting is printed
//! bare, anything else in single quotes.

use anyhow::{Result, bail};

/// Check `did` against the DID-core `did` production (a DID, not a DID URL):
///
/// ```text
/// did                = "did:" method-name ":" method-specific-id
/// method-name        = 1*method-char          ; %x61-7A / DIGIT
/// method-specific-id = *( *idchar ":" ) 1*idchar
/// idchar             = ALPHA / DIGIT / "." / "-" / "_" / pct-encoded
/// ```
pub fn check_did(field: &str, did: &str) -> Result<()> {
    let bad = || -> Result<()> {
        bail!(
            "{field} `{}` is not a DID (expected `did:<method>:<method-specific-id>`, \
             DID-core syntax, no path, query or fragment)",
            did.escape_debug()
        )
    };
    let Some(rest) = did.strip_prefix("did:") else {
        return bad();
    };
    let Some((method, id)) = rest.split_once(':') else {
        return bad();
    };
    if method.is_empty()
        || !method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
    {
        return bad();
    }
    // The last segment must be non-empty; earlier ones may be empty.
    if id.is_empty() || id.ends_with(':') || did.len() > 2048 {
        return bad();
    }
    let bytes = id.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = |j: usize| bytes.get(j).is_some_and(u8::is_ascii_hexdigit);
                if !(hex(i + 1) && hex(i + 2)) {
                    return bad();
                }
                i += 3;
            }
            b if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b':') => i += 1,
            _ => return bad(),
        }
    }
    Ok(())
}

/// Quote `arg` for a POSIX shell: bare when every character is one no shell
/// treats specially, otherwise in single quotes (a `'` inside becoming
/// `'\''`).
pub fn quote(arg: &str) -> String {
    let safe = !arg.is_empty()
        && arg.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'_' | b'@' | b'%' | b'+' | b'=' | b':' | b',' | b'.' | b'/' | b'-'
                )
        });
    if safe {
        arg.to_string()
    } else {
        format!("'{}'", arg.replace('\'', r"'\''"))
    }
}

/// `argv` as one line a POSIX shell reads back as the same arguments.
pub fn command_line<S: AsRef<str>>(argv: &[S]) -> String {
    argv.iter()
        .map(|a| quote(a.as_ref()))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dids_follow_did_core() {
        for ok in [
            "did:web:example.com",
            "did:webvh:QmScid:example.com%3A8443:alice",
            "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
            "did:example::a",
        ] {
            assert!(check_did("owner", ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "did:",
            "did:web",
            "did:Web:example.com",
            "did:web:",
            "did:web:a:",
            "did:web:a b",
            "did:web:a;rm -rf ~",
            "did:web:a'b",
            "did:web:a#frag",
            "did:web:a/path",
            "did:web:a?q",
            "did:web:%zz",
            "did:web:%4",
            "web:example.com",
            "did:web:$(id)",
            "did:web:a\nb",
        ] {
            assert!(check_did("owner", bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn quoting_round_trips_through_a_shell() {
        assert_eq!(quote("github.com/acme/widgets"), "github.com/acme/widgets");
        assert_eq!(
            quote("did:webvh:Qm:x.example%3A80"),
            "did:webvh:Qm:x.example%3A80"
        );
        assert_eq!(quote(""), "''");
        assert_eq!(quote("a b"), "'a b'");
        assert_eq!(quote("it's"), r"'it'\''s'");
        assert_eq!(quote("$(id)"), "'$(id)'");
        assert_eq!(quote("`id`;x"), "'`id`;x'");
        assert_eq!(quote("--owner"), "--owner");
    }

    #[cfg(unix)]
    #[test]
    fn a_quoted_line_is_read_back_unchanged() {
        let args = [
            "cnm",
            "git",
            "adopt",
            "github.com/acme/widgets",
            "--owner",
            "did:web:a.example",
            "it's $(x) `y` \"z\" \\ ;&|<>*?[]{}~#!",
        ];
        let line = command_line(&args);
        let out = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("printf '%s\\n' {line}"))
            .output()
            .unwrap();
        let back: Vec<&str> = std::str::from_utf8(&out.stdout).unwrap().lines().collect();
        assert_eq!(back, args);
    }
}
