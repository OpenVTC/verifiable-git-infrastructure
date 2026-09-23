//! GitHub App authentication: the RS256 App JWT.
//!
//! The App's private key signs a short JWT; the JWT buys an installation
//! access token; the installation token does the work. Only the first step
//! touches the key, and it goes through [`AppKeySigner`] so the key can live
//! in an enclave signer that will sign (and log) but never export it (§5.7).
//! [`InProcessKey`] is the in-memory implementation for deployments without
//! one.

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{RSA_PKCS1_SHA256, RsaKeyPair};
use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use vgi_forge::async_trait;
use vgi_forge::{ForgeError, Result};
use zeroize::Zeroizing;

use crate::secret::Secret;

/// How far `iat` is backdated. GitHub's documented allowance for clock
/// drift between the bridge and GitHub.
pub const JWT_BACKDATE_SECS: u64 = 60;

/// How long an App JWT is valid from now. GitHub refuses more than ten
/// minutes; nine leaves room for our clock running slightly slow.
pub const JWT_LIFETIME_SECS: u64 = 9 * 60;

/// Signs App JWTs with the App's private key (RSASSA-PKCS1-v1_5, SHA-256).
///
/// Async because a real deployment's signer is another process — the
/// enclave — and signing is a round-trip to it.
#[async_trait]
pub trait AppKeySigner: Send + Sync {
    /// RS256 signature over `message`.
    async fn sign_rs256(&self, message: &[u8]) -> Result<Vec<u8>>;
}

/// The App private key held in this process.
pub struct InProcessKey {
    key: RsaKeyPair,
}

impl InProcessKey {
    /// Load the PEM GitHub issues (`-----BEGIN RSA PRIVATE KEY-----`, PKCS#1)
    /// or a PKCS#8 `-----BEGIN PRIVATE KEY-----`. Encrypted keys are refused.
    pub fn from_pem(pem: &str) -> Result<Self> {
        let (label, der) = decode_pem(pem)?;
        let key = match label.as_str() {
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(&der),
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(&der),
            other => {
                return Err(ForgeError::Config(format!(
                    "expected an RSA private key PEM (`RSA PRIVATE KEY` or `PRIVATE KEY`), got \
                     `{other}`"
                )));
            }
        }
        .map_err(|e| ForgeError::Config(format!("the App private key was rejected: {e}")))?;
        Ok(InProcessKey { key })
    }

    /// Load from a [`Secret`] holding the PEM.
    pub fn from_secret(pem: &Secret) -> Result<Self> {
        Self::from_pem(pem.expose())
    }
}

impl fmt::Debug for InProcessKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("InProcessKey(<redacted>)")
    }
}

#[async_trait]
impl AppKeySigner for InProcessKey {
    async fn sign_rs256(&self, message: &[u8]) -> Result<Vec<u8>> {
        let mut sig = vec![0u8; self.key.public_modulus_len()];
        self.key
            .sign(&RSA_PKCS1_SHA256, &SystemRandom::new(), message, &mut sig)
            .map_err(|_| ForgeError::Config("RS256 signing failed".into()))?;
        Ok(sig)
    }
}

/// The JWT claims, for tests and logs. `iss` is the App's client id — GitHub
/// accepts the numeric App id too, but recommends the client id.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AppClaims {
    /// Issued-at, backdated by [`JWT_BACKDATE_SECS`].
    pub iat: u64,
    /// Expiry, [`JWT_LIFETIME_SECS`] from now.
    pub exp: u64,
    /// The App's client id.
    pub iss: String,
}

impl AppClaims {
    /// Claims for a JWT minted at `now` (Unix seconds).
    pub fn at(now: u64, issuer: &str) -> Self {
        AppClaims {
            iat: now.saturating_sub(JWT_BACKDATE_SECS),
            exp: now + JWT_LIFETIME_SECS,
            iss: issuer.to_string(),
        }
    }
}

/// Mint an App JWT for `issuer` at `now`.
pub async fn app_jwt_at(signer: &dyn AppKeySigner, issuer: &str, now: u64) -> Result<Secret> {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let claims = serde_json::to_vec(&AppClaims::at(now, issuer))
        .map_err(|e| ForgeError::Protocol(e.to_string()))?;
    let signing_input = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims));
    let signature = signer.sign_rs256(signing_input.as_bytes()).await?;
    Ok(Secret::new(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    )))
}

/// Mint an App JWT now.
pub async fn app_jwt(signer: &dyn AppKeySigner, issuer: &str) -> Result<Secret> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ForgeError::Config("system clock is before 1970".into()))?
        .as_secs();
    app_jwt_at(signer, issuer, now).await
}

/// Decode one PEM block into its label and DER bytes (zeroized on drop).
fn decode_pem(pem: &str) -> Result<(String, Zeroizing<Vec<u8>>)> {
    let bad = |m: &str| ForgeError::Config(format!("App private key: {m}"));
    let pem = pem.trim();
    let first = pem.lines().next().unwrap_or_default().trim();
    let label = first
        .strip_prefix("-----BEGIN ")
        .and_then(|l| l.strip_suffix("-----"))
        .ok_or_else(|| bad("not a PEM block"))?
        .to_string();
    if pem.contains("ENCRYPTED") || pem.contains("Proc-Type:") {
        return Err(bad(
            "encrypted keys are not supported; supply the key GitHub issued",
        ));
    }
    let end = format!("-----END {label}-----");
    let body: Zeroizing<String> = Zeroizing::new(
        pem.lines()
            .skip(1)
            .take_while(|l| l.trim() != end)
            .map(str::trim)
            .collect(),
    );
    if !pem.lines().any(|l| l.trim() == end) {
        return Err(bad("missing the END line"));
    }
    let der = Zeroizing::new(
        STANDARD
            .decode(body.as_bytes())
            .map_err(|_| bad("the PEM body is not valid base64"))?,
    );
    Ok((label, der))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn claims_backdate_iat_and_stay_under_ten_minutes() {
        let c = AppClaims::at(1_000_000, "Iv1.abc");
        assert_eq!(c.iat, 1_000_000 - 60);
        assert_eq!(c.exp, 1_000_000 + 540);
        assert!(c.exp - 1_000_000 <= 600);
        assert_eq!(c.iss, "Iv1.abc");
    }

    #[test]
    fn pem_errors_are_specific() {
        let e = InProcessKey::from_pem("not a key").unwrap_err();
        assert!(e.to_string().contains("not a PEM block"), "{e}");
        let e =
            InProcessKey::from_pem("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----")
                .unwrap_err();
        assert!(e.to_string().contains("CERTIFICATE"), "{e}");
        let e = InProcessKey::from_pem(
            "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----",
        )
        .unwrap_err();
        assert!(e.to_string().contains("encrypted"), "{e}");
        let e = InProcessKey::from_pem("-----BEGIN RSA PRIVATE KEY-----\nAAAA\n").unwrap_err();
        assert!(e.to_string().contains("END"), "{e}");
    }
}
