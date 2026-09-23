//! OAuth2 authorisation code + PKCE against the instance (RFC 6749, 7636).
//!
//! Two flows use it: an admin binding a namespace and a member linking an
//! account. Both need the PKCE `code_verifier` again when the callback
//! lands, and the adapter keeps no per-flow state — a bridge restart, or a
//! second bridge replica, must still finish the flow. So the verifier is
//! *derived*: an HMAC, under a key derived from the OAuth client secret, of
//! the flow's purpose and `state`. The state travels through the browser,
//! the key never does, and redeeming a code needs the client secret anyway —
//! so a party that intercepts the code and the state still cannot compute
//! the verifier.
//!
//! A bind's `state` is the caller's nonce (it stores and expires it, like the
//! GitHub adapter). A link has no caller-side store, so its state is
//! self-authenticating: a random nonce and an issue time, MACed, checked for
//! age on the way back.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::{constant_time, digest, hmac};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use vgi_forge::{ForgeError, Result};

use crate::secret::Secret;

/// Why a PKCE verifier is derived, so a bind state can never unlock a link.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Purpose {
    Bind,
    Link,
}

impl Purpose {
    fn label(self) -> &'static [u8] {
        match self {
            Purpose::Bind => b"bind",
            Purpose::Link => b"link",
        }
    }
}

/// Keys derived from the OAuth client secret.
pub(crate) struct OAuthKeys {
    verifier: hmac::Key,
    state: hmac::Key,
}

impl std::fmt::Debug for OAuthKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuthKeys(<redacted>)")
    }
}

const LINK_NONCE: usize = 16;
const LINK_TAG: usize = 16;

impl OAuthKeys {
    pub(crate) fn new(client_secret: &Secret) -> Self {
        let root = hmac::Key::new(hmac::HMAC_SHA256, client_secret.expose().as_bytes());
        let derive =
            |label: &[u8]| hmac::Key::new(hmac::HMAC_SHA256, hmac::sign(&root, label).as_ref());
        OAuthKeys {
            verifier: derive(b"vgi-forge-forgejo/pkce-verifier/v1"),
            state: derive(b"vgi-forge-forgejo/link-state/v1"),
        }
    }

    /// The PKCE `code_verifier` for a flow: 43 base64url characters
    /// (256 bits), within RFC 7636's 43–128.
    pub(crate) fn verifier(&self, purpose: Purpose, state: &str) -> Secret {
        let mut ctx = hmac::Context::with_key(&self.verifier);
        ctx.update(purpose.label());
        ctx.update(b"\0");
        ctx.update(state.as_bytes());
        Secret::new(URL_SAFE_NO_PAD.encode(ctx.sign().as_ref()))
    }

    /// `S256` challenge for a verifier.
    pub(crate) fn challenge(verifier: &Secret) -> String {
        URL_SAFE_NO_PAD.encode(digest::digest(
            &digest::SHA256,
            verifier.expose().as_bytes(),
        ))
    }

    /// A fresh link state issued at `now` (seconds since the epoch).
    pub(crate) fn issue_link_state(&self, now: u64) -> Result<String> {
        let mut nonce = [0u8; LINK_NONCE];
        aws_lc_rs::rand::fill(&mut nonce)
            .map_err(|_| ForgeError::Config("system RNG unavailable".into()))?;
        let mut raw = Vec::with_capacity(LINK_NONCE + 8 + LINK_TAG);
        raw.extend_from_slice(&nonce);
        raw.extend_from_slice(&now.to_be_bytes());
        let tag = hmac::sign(&self.state, &raw);
        raw.extend_from_slice(&tag.as_ref()[..LINK_TAG]);
        Ok(URL_SAFE_NO_PAD.encode(raw))
    }

    /// Check a link state: ours (MAC, in constant time), and issued no more
    /// than `ttl` before `now`.
    pub(crate) fn check_link_state(&self, state: &str, now: u64, ttl: Duration) -> Result<()> {
        let bad = || ForgeError::LinkFailed("the `state` is not one this bridge issued".into());
        let raw = URL_SAFE_NO_PAD.decode(state).map_err(|_| bad())?;
        if raw.len() != LINK_NONCE + 8 + LINK_TAG {
            return Err(bad());
        }
        let (body, tag) = raw.split_at(LINK_NONCE + 8);
        let expected = hmac::sign(&self.state, body);
        constant_time::verify_slices_are_equal(tag, &expected.as_ref()[..LINK_TAG])
            .map_err(|_| bad())?;
        let issued = u64::from_be_bytes(body[LINK_NONCE..].try_into().expect("8 bytes"));
        if issued > now.saturating_add(60) || now.saturating_sub(issued) > ttl.as_secs() {
            return Err(ForgeError::LinkFailed(
                "the link expired before it was completed; start again".into(),
            ));
        }
        Ok(())
    }
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The token endpoint's answer. Only the access token is kept; a refresh
/// token, if the instance sends one, is never deserialised.
#[derive(Deserialize, Default)]
pub(crate) struct TokenJson {
    pub(crate) access_token: Option<String>,
    pub(crate) error: Option<String>,
    pub(crate) error_description: Option<String>,
}

impl TokenJson {
    /// The access token, or the instance's error as `fail`.
    pub(crate) fn into_token(mut self, fail: impl Fn(String) -> ForgeError) -> Result<Secret> {
        match (self.access_token.take(), self.error.take()) {
            (Some(t), None) if !t.is_empty() => Ok(Secret::new(t)),
            (_, Some(err)) => Err(fail(format!(
                "{err}: {}",
                self.error_description.as_deref().unwrap_or("")
            ))),
            _ => Err(ForgeError::Protocol(
                "token response has neither a token nor an error".into(),
            )),
        }
    }
}

impl Drop for TokenJson {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(t) = self.access_token.as_mut() {
            t.zeroize();
        }
    }
}

impl std::fmt::Debug for TokenJson {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenJson")
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "<redacted>"),
            )
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn keys() -> OAuthKeys {
        OAuthKeys::new(&Secret::new("client-secret"))
    }

    #[test]
    fn verifiers_are_stable_per_purpose_and_state() {
        let k = keys();
        let a = k.verifier(Purpose::Bind, "s1");
        assert_eq!(a.expose().len(), 43);
        assert_eq!(a.expose(), k.verifier(Purpose::Bind, "s1").expose());
        assert_ne!(a.expose(), k.verifier(Purpose::Link, "s1").expose());
        assert_ne!(a.expose(), k.verifier(Purpose::Bind, "s2").expose());
        let other = OAuthKeys::new(&Secret::new("another-secret"));
        assert_ne!(a.expose(), other.verifier(Purpose::Bind, "s1").expose());
        assert_eq!(format!("{a:?}"), "Secret(<redacted>)");
    }

    #[test]
    fn pkce_challenge_matches_rfc7636_appendix_b() {
        let v = Secret::new("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk");
        assert_eq!(
            OAuthKeys::challenge(&v),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }

    #[test]
    fn link_states_verify_and_expire() {
        let k = keys();
        let ttl = Duration::from_secs(900);
        let s = k.issue_link_state(1_000).unwrap();
        k.check_link_state(&s, 1_000, ttl).unwrap();
        k.check_link_state(&s, 1_900, ttl).unwrap();
        assert!(k.check_link_state(&s, 1_901, ttl).is_err(), "expired");
        assert!(k.check_link_state(&s, 800, ttl).is_err(), "from the future");
        assert!(keys().check_link_state(&s, 1_000, ttl).is_ok());
        let other = OAuthKeys::new(&Secret::new("x"));
        assert!(other.check_link_state(&s, 1_000, ttl).is_err(), "not ours");
        let mut raw = URL_SAFE_NO_PAD.decode(&s).unwrap();
        raw[20] ^= 1;
        let forged = URL_SAFE_NO_PAD.encode(raw);
        assert!(k.check_link_state(&forged, 1_000, ttl).is_err(), "tampered");
        assert!(k.check_link_state("short", 1_000, ttl).is_err());
    }

    #[test]
    fn token_responses_never_print_the_token() {
        let mut t = TokenJson::default();
        t.access_token = Some("gto_secret".into());
        assert!(!format!("{t:?}").contains("gto_secret"));
        let token = t.into_token(ForgeError::LinkFailed).unwrap();
        assert_eq!(token.expose(), "gto_secret");
        let mut denied = TokenJson::default();
        denied.error = Some("invalid_grant".into());
        assert!(matches!(
            denied.into_token(ForgeError::LinkFailed),
            Err(ForgeError::LinkFailed(m)) if m.starts_with("invalid_grant")
        ));
    }
}
