use anyhow::{Context, Result, bail};
use vta_sdk::client::{AutoConnect, ClientIdentity, ConnectedVta, VtaClient};
use zeroize::Zeroize;

use crate::config::{self, SigningConfig, VtaCredentials};

/// Maximum number of authentication retry attempts.
const MAX_AUTH_RETRIES: u32 = 2;

/// The pause before retry `n` is `n` times this.
const RETRY_BACKOFF: std::time::Duration = std::time::Duration::from_millis(500);

/// Authenticate with VTA, using whichever transport the install captured.
/// Returns an authenticated `VtaClient` and the loaded VTA credentials.
///
/// - **DIDComm transport** (`mediator_did` is `Some`) — opens a fresh
///   DIDComm session as the credential DID against the advertised
///   mediator. The session itself is the authenticator; there is no
///   bearer token to cache, so the keyring token cache is bypassed on
///   this path.
/// - **REST transport** (`mediator_did` is `None`) — original behaviour:
///   try cached token first, fall back to challenge-response auth with
///   retry, cache the new token for next time.
pub async fn authenticate(cfg: &SigningConfig) -> Result<(VtaClient, VtaCredentials)> {
    let creds = config::load_vta_credentials(&cfg.did_key_id)?;
    validate_credentials(&creds)?;

    // REST transport with a cached bearer token: short-circuit the handshake.
    // Token caching stays caller-side — the SDK deliberately leaves it to us.
    if creds.mediator_did.is_none()
        && let Some(token) = config::load_cached_token(&cfg.did_key_id)
    {
        let client = client_with_identity(
            &creds.vta_url,
            &creds.credential_did,
            &creds.private_key_multibase,
            &creds.vta_did,
        );
        client.set_token(token);
        return Ok((client, creds));
    }

    // Let the SDK pick the transport and run the handshake. `connect_auto`
    // encapsulates the DIDComm-vs-REST branch, the `rest_fallback` derivation,
    // and the empty-URL rule we used to hand-roll here and in openvtc-core —
    // that logic is SDK-level knowledge, so it lives there now (R22). We keep
    // the transient-failure retry and (REST) token caching, both of which are
    // application policy.
    let connected = connect_with_retry(&creds).await?;

    // DIDComm sessions carry no bearer token (`rest_token` is `None`); a REST
    // handshake issues one, which we cache for the next invocation.
    if let Some(token) = &connected.rest_token {
        let _ = config::cache_token(
            &cfg.did_key_id,
            &token.access_token,
            token.access_expires_at,
        );
    }

    Ok((connected.client, creds))
}

/// Is this a URL we may carry VTA credentials over?
///
/// `https://`, or cleartext `http://` to a loopback host for local
/// development — decided by **parsing the URL**, with the SDK's own rule
/// (`vta_sdk::protocol::matching::is_https_or_loopback`), never by matching
/// text. Hand-parsing got this wrong twice: `starts_with("http://localhost")`
/// admitted `http://localhost.evil.com`, and the host-splitting parser that
/// replaced it read `http://localhost:80@evil.com` as `localhost` — the part
/// before `@` is userinfo, and the request, carrying the credential exchange,
/// goes in the clear to `evil.com` (SEC-4045 / VGI-07).
///
/// Userinfo is refused outright, as the SDK's `guard_vta_endpoint` does: a
/// VTA URL has no use for it, and it is what that bypass was built from.
pub fn vta_url_is_secure(url: &str) -> bool {
    let Ok(parsed) = url::Url::parse(url) else {
        return false;
    };
    parsed.username().is_empty()
        && parsed.password().is_none()
        && vta_sdk::protocol::matching::is_https_or_loopback(url)
}

/// The error for a VTA URL that fails [`vta_url_is_secure`]. Any userinfo is
/// cut from the URL it echoes, so a password never lands in a terminal or log.
pub fn insecure_vta_url(url: &str) -> anyhow::Error {
    let shown = match url::Url::parse(url) {
        Ok(mut parsed) if !parsed.username().is_empty() || parsed.password().is_some() => {
            let _ = parsed.set_username("");
            let _ = parsed.set_password(None);
            format!("{parsed} with a user:password@ part")
        }
        _ => url.to_string(),
    };
    anyhow::anyhow!(
        "VTA URL must use HTTPS, with no user:password@ part (got: {shown}). Cleartext \
         http:// is allowed only to loopback (localhost, 127.0.0.0/8, [::1]) for local \
         development."
    )
}

/// Validate VTA credentials before use.
///
/// REST transport requires a non-empty HTTPS URL. DIDComm transport
/// (`mediator_did` set) treats `vta_url` as optional — an empty value is
/// fine for VTAs that publish no `#vta-rest` service at all.
fn validate_credentials(creds: &VtaCredentials) -> Result<()> {
    if creds.credential_did.is_empty() {
        bail!("credential DID is empty");
    }
    if creds.key_id.is_empty() {
        bail!("signing key ID is empty");
    }

    if creds.mediator_did.is_some() {
        // DIDComm transport — the URL is optional. If it *is* set, hold
        // it to the same HTTPS rule (it'll be passed through as a /health
        // fallback so we don't want to risk leaking creds over plain HTTP).
        if !creds.vta_url.is_empty() && !vta_url_is_secure(&creds.vta_url) {
            return Err(insecure_vta_url(&creds.vta_url));
        }
        return Ok(());
    }

    // REST transport — URL is required.
    if creds.vta_url.is_empty() {
        bail!("VTA URL is empty");
    }
    if !vta_url_is_secure(&creds.vta_url) {
        return Err(insecure_vta_url(&creds.vta_url));
    }
    Ok(())
}

/// Connect via [`VtaClient::connect_auto`] with retry on transient failures.
///
/// The transport (DIDComm vs REST) is chosen by the SDK from `creds`. Retry
/// covers both paths uniformly — a transient mediator or network hiccup is
/// worth a second attempt regardless of transport.
async fn connect_with_retry(creds: &VtaCredentials) -> Result<ConnectedVta> {
    connect_with_retry_auto(AutoConnect {
        vta_url: &creds.vta_url,
        vta_did: &creds.vta_did,
        credential_did: &creds.credential_did,
        private_key_multibase: &creds.private_key_multibase,
        mediator_did: creds.mediator_did.as_deref(),
    })
    .await
}

/// [`connect_with_retry`] for a caller that has not stored credentials yet:
/// `init`, right after it provisioned the admin DID. The same transport
/// choice and the same retry, so setup and signing cannot reach the VTA
/// differently — setup used to hardcode a REST handshake, which a VTA that
/// publishes no REST service answers with something that is not JSON.
pub async fn connect_with_retry_auto(input: AutoConnect<'_>) -> Result<ConnectedVta> {
    let mut last_err = None;
    for attempt in 1..=MAX_AUTH_RETRIES {
        let result = VtaClient::connect_auto(input.clone()).await;
        match result {
            Ok(connected) => {
                // A REST handshake must yield a non-empty bearer token; DIDComm
                // carries none (`rest_token` is `None`), so this skips it.
                if let Some(token) = &connected.rest_token
                    && token.access_token.is_empty()
                {
                    bail!("VTA returned an empty access token");
                }
                return Ok(connected);
            }
            Err(e) => {
                let err_msg = format!("{e}");
                if attempt < MAX_AUTH_RETRIES {
                    eprintln!(
                        "VTA connect attempt {attempt}/{MAX_AUTH_RETRIES} failed: {err_msg}, retrying..."
                    );
                    // A pause, not a hammer: a VTA that just refused or timed
                    // out gets a moment before the next handshake.
                    tokio::time::sleep(RETRY_BACKOFF * attempt).await;
                }
                last_err = Some(err_msg);
            }
        }
    }
    bail!(
        "VTA connection failed after {MAX_AUTH_RETRIES} attempts: {}",
        last_err.unwrap_or_else(|| "unknown error".to_string())
    )
}

/// A client speaking as `client_did`, with the token left to the caller.
///
/// The identity is not optional. `keys/export-secret` — like every
/// proof-bearing trust task — names an in-band recipient and signs the
/// request, and the SDK refuses to build that document from an identity-less
/// client before any I/O happens. `init` shipped exactly that regression
/// once: a `VtaClient::new` + `set_token` client whose first
/// [`get_signing_key`] failed with "carries no ClientIdentity".
///
/// What the client may *do* is the VTA's ACL's business, not this
/// function's: `init` passes its freshly provisioned admin credential, but
/// nothing here checks or confers a role.
pub fn client_with_identity(
    vta_url: &str,
    client_did: &str,
    private_key_mb: &str,
    vta_did: &str,
) -> VtaClient {
    let identity = ClientIdentity::did_key(client_did, private_key_mb, vta_did);
    VtaClient::new(vta_url).with_identity(identity)
}

/// Fetch the Ed25519 signing key seed from VTA. Returns 32-byte seed.
/// The seed is zeroized on drop via the returned wrapper.
pub async fn get_signing_key(client: &VtaClient, key_id: &str) -> Result<SeedMaterial> {
    let resp = client
        .get_key_secret(key_id)
        .await
        .map_err(|e| anyhow::anyhow!("failed to fetch key secret: {e}"))?;

    if resp.key_type != vta_sdk::keys::KeyType::Ed25519 {
        bail!(
            "signing key {key_id} is {:?}, expected Ed25519",
            resp.key_type
        );
    }

    let seed = vta_sdk::did_key::decode_private_key_multibase(&resp.private_key_multibase)
        .context("failed to decode signing key")?;

    Ok(SeedMaterial(seed))
}

/// Wrapper around a 32-byte Ed25519 seed that zeroizes on drop.
pub struct SeedMaterial([u8; 32]);

impl SeedMaterial {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for SeedMaterial {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_creds() -> VtaCredentials {
        VtaCredentials {
            vta_url: "https://vta.example.com".to_string(),
            vta_did: "did:example:vta".to_string(),
            credential_did: "did:key:z6Mk123".to_string(),
            private_key_multibase: "z...".to_string(),
            key_id: "key-1".to_string(),
            mediator_did: None,
        }
    }

    /// The SDK refuses `keys/export-secret` from an identity-less client
    /// before any I/O — the control for the regression test below. The URL is
    /// unreachable on purpose: nothing here may touch the network.
    #[tokio::test]
    async fn test_get_signing_key_without_identity_refused_before_io() {
        let bare = VtaClient::new("http://127.0.0.1:1");
        bare.set_token("test-token".to_string());
        let err = match get_signing_key(&bare, "key-1").await {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("an identity-less client must not fetch a key secret"),
        };
        assert!(
            err.contains("ClientIdentity"),
            "expected the SDK's identity refusal, got: {err}"
        );
    }

    /// The client `init` builds must get past the identity gate: whatever
    /// fails afterwards (here: an undecodable key, still with no I/O), it must
    /// not be the "carries no ClientIdentity" refusal `init` once shipped.
    #[tokio::test]
    async fn test_client_with_identity_passes_identity_gate() {
        let client = client_with_identity(
            "http://127.0.0.1:1",
            "did:key:z6Mk123",
            "zNotARealKey",
            "did:example:vta",
        );
        client.set_token("test-token".to_string());
        let err = match get_signing_key(&client, "key-1").await {
            Err(e) => format!("{e:#}"),
            Ok(_) => panic!("a garbage key against an unreachable VTA must not succeed"),
        };
        assert!(
            !err.contains("ClientIdentity"),
            "the init client lost its identity again: {err}"
        );
    }

    #[test]
    fn test_validate_rejects_empty_url() {
        let mut creds = test_creds();
        creds.vta_url = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_rejects_http() {
        let mut creds = test_creds();
        creds.vta_url = "http://example.com".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_allows_https() {
        assert!(validate_credentials(&test_creds()).is_ok());
    }

    #[test]
    fn test_validate_allows_localhost() {
        let mut creds = test_creds();
        creds.vta_url = "http://localhost:3000".to_string();
        assert!(validate_credentials(&creds).is_ok());
    }

    /// Every loopback form the dev affordance is meant to cover.
    #[test]
    fn cleartext_is_allowed_to_every_loopback_form() {
        for url in [
            "http://localhost",
            "http://localhost:3000",
            "http://localhost/path",
            "http://127.0.0.1:8100",
            "http://[::1]:8100",
        ] {
            let mut creds = test_creds();
            creds.vta_url = url.to_string();
            assert!(
                validate_credentials(&creds).is_ok(),
                "loopback must stay usable for local dev: {url}"
            );
        }
    }

    /// The bug this replaces: `starts_with("http://localhost")` matched any
    /// host merely *beginning* with those characters, so the HTTPS
    /// requirement could be sidestepped by registering a lookalike domain.
    /// The credential exchange would then cross the network in cleartext to
    /// a host the attacker controls.
    #[test]
    fn cleartext_is_rejected_to_hosts_that_only_look_like_loopback() {
        for url in [
            "http://localhost.evil.com",
            "http://localhost.evil.com/vta",
            "http://localhostevil.com",
            "http://127.0.0.1.evil.com",
            "http://[::1].evil.com",
        ] {
            let mut creds = test_creds();
            creds.vta_url = url.to_string();
            assert!(
                validate_credentials(&creds).is_err(),
                "a lookalike host must not pass the HTTPS requirement: {url}"
            );
        }
    }

    /// VGI-07: the part before `@` is userinfo, so each of these sends the
    /// credential exchange in the clear to `evil.com`. The hand-rolled parser
    /// this replaced read the host as `localhost` and let them through.
    #[test]
    fn userinfo_cannot_disguise_a_remote_host_as_loopback() {
        for url in [
            "http://localhost:80@evil.com",
            "http://localhost@evil.com/vta",
            "http://127.0.0.1:8100@evil.com",
            "http://[::1]:80@evil.com",
        ] {
            let mut creds = test_creds();
            creds.vta_url = url.to_string();
            assert!(
                validate_credentials(&creds).is_err(),
                "userinfo must not pass as a loopback host: {url}"
            );
        }
    }

    /// A VTA URL has no use for credentials, and refusing them costs nothing
    /// — but the refusal must not print them.
    #[test]
    fn userinfo_is_refused_even_over_https_and_never_echoed() {
        let mut creds = test_creds();
        creds.vta_url = "https://alice:s3cret@vta.example.com".to_string();
        let err = validate_credentials(&creds).unwrap_err().to_string();
        assert!(!err.contains("s3cret"), "{err}");
        assert!(!err.contains("alice"), "{err}");
        assert!(err.contains("vta.example.com"), "{err}");
    }

    #[test]
    fn the_whole_loopback_range_and_trailing_dot_stay_usable() {
        for url in ["http://127.0.0.2:8100", "http://localhost.:3000"] {
            assert!(vta_url_is_secure(url), "{url}");
        }
        for url in ["ftp://vta.example.com", "not a url", "https://"] {
            assert!(!vta_url_is_secure(url), "{url}");
        }
    }

    /// The DIDComm branch treats the URL as optional but holds a present one
    /// to the same rule — it is passed through as a `/health` fallback, so a
    /// lookalike there leaks just the same.
    #[test]
    fn the_didcomm_branch_applies_the_same_host_rule() {
        let mut creds = test_creds();
        creds.mediator_did = Some("did:web:mediator.example".to_string());

        creds.vta_url = String::new();
        assert!(validate_credentials(&creds).is_ok(), "empty stays allowed");

        creds.vta_url = "http://localhost:3000".to_string();
        assert!(validate_credentials(&creds).is_ok());

        creds.vta_url = "http://localhost.evil.com".to_string();
        assert!(
            validate_credentials(&creds).is_err(),
            "the lookalike must fail on the DIDComm path too"
        );
    }

    #[test]
    fn test_validate_rejects_empty_key_id() {
        let mut creds = test_creds();
        creds.key_id = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_rejects_empty_credential_did() {
        let mut creds = test_creds();
        creds.credential_did = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_seed_material_zeroizes_on_drop() {
        let seed = SeedMaterial([0xAB; 32]);
        assert_eq!(seed.as_bytes(), &[0xAB; 32]);
        drop(seed);
    }

    #[test]
    fn test_validate_didcomm_only_accepts_empty_url() {
        let mut creds = test_creds();
        creds.vta_url = "".to_string();
        creds.mediator_did = Some("did:peer:0z6Mkmediator".to_string());
        assert!(validate_credentials(&creds).is_ok());
    }

    #[test]
    fn test_validate_didcomm_with_url_still_requires_https() {
        let mut creds = test_creds();
        creds.vta_url = "http://example.com".to_string();
        creds.mediator_did = Some("did:peer:0z6Mkmediator".to_string());
        assert!(validate_credentials(&creds).is_err());
    }

    #[test]
    fn test_validate_didcomm_still_rejects_empty_credential_did() {
        let mut creds = test_creds();
        creds.vta_url = "".to_string();
        creds.mediator_did = Some("did:peer:0z6Mkmediator".to_string());
        creds.credential_did = "".to_string();
        assert!(validate_credentials(&creds).is_err());
    }
}
