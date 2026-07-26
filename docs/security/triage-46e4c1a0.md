# Security scan triage — scan `46e4c1a0`

Disposition of the 28 findings in the AI validation report dated 2026-07-26,
each checked against the code rather than against the report's own verdict.
Recorded so a re-scan does not re-litigate the same set.

The report's buckets are not carried over. Several findings it "confirmed" are
design intent; several it escalated to HIGH are contradicted by evidence it
itself accepted elsewhere; one that it rated HIGH pointed at a real bug it did
not describe.

Every finding was in `did-git-sign`. None in `verify-trust` or `vgi-core` —
which, given the verifier decides whether commits are trusted, reads as uneven
coverage rather than a clean verifier.

## Fixed

| Finding | Location | What was actually wrong |
|---|---|---|
| VTA URL validation | `vta.rs:75,89` | Not the reported issue. `starts_with("http://localhost")` matched the *URL prefix*, so `http://localhost.evil.com` and `http://localhostevil.com` satisfied the HTTPS requirement — cleartext credential exchange to an attacker-chosen host. Now parses the host. The IPv6 arm had the same flaw (`[::1].evil.com`) and is fixed with it. |
| Parent-process allow-list | `policy.rs:69` | Reported as CRITICAL "arbitrary code execution"; it is neither critical nor RCE, but `token.starts_with("git")` did admit `gitleaks`, `github-desktop`, `gitfoo`. An attacker's build script only had to be named well. Now matched whole, with `git-*` for git's subcommand binaries and `.exe` stripped for Windows. |

Both remain defence in depth. As `policy.rs`'s module doc already says, an
attacker who can execute code as the user can spawn real `git` and satisfy any
parent check. Tightening removes the free pass, not the attack.

## Accepted risk — design intent, documented

| Finding | Why no action |
|---|---|
| Private keys / VTA credentials / tokens in OS keyring "without additional encryption" (×3) | The OS keyring **is** the trust boundary, per the README security model. Encrypting its contents needs a key that must itself live somewhere; on the same machine that is circular. |
| Cleartext HTTP allowed for VTA URL in development | Deliberate, documented, and now correctly scoped to genuine loopback. |
| Session fixation via cached token reuse | Tokens are validated with a 30-second safety margin before reuse. |
| Unvalidated agent name from `alsoKnownAs` | This describes the mitigation, not a gap: claims render tagged `[unverified]` unless `--resolve-agent-names` round-trips them back to the claiming DID. |
| SHA-256 of signing buffer in audit log | The hash is the point — it records *which* buffer was signed without recording its contents. |
| Global committer email without per-repo warning | **Already fixed** in #16; the scan predates it. |

## Rejected

| Finding | Why |
|---|---|
| Git config injection (HIGH) · Path traversal in `SigningConfig::load` (HIGH) | `Command::new("git").arg(...)` never invokes a shell; values are data. The report reached exactly this conclusion when dismissing the identical "Command Injection via Unsanitized DID Key ID" claim as a false positive, then kept these. |
| Committer identity check bypassable via non-commit payloads (MEDIUM) | Tags legitimately carry `tagger`, not `committer`; `verify-trust` only inspects commits; and the check is a misconfiguration guard, not an attacker-facing control — an attacker who controls the payload is the policy gate's problem, not this one's. The report dismissed a duplicate of this as a false positive while retaining it. |
| Unvalidated namespace allows signature confusion (MEDIUM) | PROTOCOL.sshsig binds the namespace into the signed blob, so a signature made under one namespace cannot be replayed as another. Cross-protocol confusion is prevented by construction. |
| Missing rate limiting on VTA authentication retry (MEDIUM) | A local CLI retrying against its own VTA. No attacker gains anything from it. |
| Race condition in token caching / stale token use (MEDIUM ×2) | The 30-second validity margin is the mitigation. |
| TOCTOU in audit log append without file locking (LOW) | The log opens `O_APPEND`; appends below `PIPE_BUF` are atomic on POSIX. (The *visibility* of a failed append was a real gap — fixed, below.) |
| Missing authorization check on signing key selection override (HIGH) | The check exists. `handle_sign` refuses when an override names a persona with no stored credentials, rather than silently falling back to the config file's — the keyring is the authorization, and R-G-2 is exactly this rule. |
| Sensitive key material not zeroized in all code paths (MEDIUM) | Both paths zeroize. `SeedMaterial` wipes on drop (test pins it), and `ed25519_dalek::SigningKey` carries an unconditional `Drop` that zeroizes its secret plus `ZeroizeOnDrop`. |
| Sensitive credential material logged in VTA connection errors (MEDIUM) | The retry path formats the SDK's error value, never the credential struct, and `VtaCredentials`' `Debug` redacts `private_key_multibase` regardless. What a third-party SDK puts in its own error text is outside this crate, and worth watching if `vta-sdk` changes. |

## Deferred, then resolved

All three were taken up in the follow-up PR. Two were real; one was not, and
this record was wrong about it.

- **`allowed_signers` write is not atomic** (`init.rs`). **Fixed.** Both the
  install and uninstall paths used `std::fs::write`, which truncates before
  writing — a concurrent `git verify-commit` could read an empty file and
  report a good signature as unverified. Now written to a sibling temp file
  and renamed over the target. The read-modify-write against a *concurrent
  `init`* remains; it needs locking, and losing one of two simultaneously
  provisioned personas is a lesser fault than the truncation window.
- **Audit-write failure is silent** (`policy.rs`). **Fixed**, and worse than
  this record first claimed. The subscriber is built with
  `EnvFilter::from_default_env()`, which defaults to `ERROR` when `RUST_LOG` is
  unset — so the `warn!` was not merely easy to miss, it was filtered out and
  reached nobody. Now reported on stderr, which git shows.
- **~~Uninstall does not revoke VTA tokens~~** (`init.rs:167`). **Not a
  finding — this record was wrong.** `uninstall` iterates `[":vta", ":token"]`
  and deletes both keyring entries, so the cached token does not survive it.
  What is not attempted is *server-side* revocation at the VTA, which the
  finding did not claim and which is not warranted for tokens carrying a
  30-second validity margin.

## Noted elsewhere

`validate_public_url` in `affinidi-trust-registry-rs` parses the host correctly
for `localhost`/`127.0.0.1` — and is what this fix was modelled on — but its
IPv6 arm still uses `rest.starts_with("[::1]")`, so `http://[::1].evil.com`
passes it. Same class as the bug fixed here, in the sibling implementation.
