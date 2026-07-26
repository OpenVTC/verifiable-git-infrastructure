//! `verify-trust`: verify a git commit range against the VTC Trust Registry.
//!
//! For every commit in a range this module answers two questions, in order:
//!
//! 1. **Who signed it, cryptographically?** The commit names a DID on its
//!    `committer` header; that DID is resolved, its document must publish the
//!    Ed25519 key embedded in the commit's sshsig, and the signature must
//!    verify over the exact bytes git signed.
//! 2. **Is that DID trusted, right now?** The signer DID is checked against
//!    the Trust Registry with a TRQP authorization query
//!    (`{entity: signer, authority, action, resource}`) via `trql-client`,
//!    where `authority` is the **VTC's** DID — the community the tuple is
//!    evaluated under.
//!
//! The registry's endpoint is discovered from its DID document rather than
//! configured alongside it: [`resolve_registry_endpoint`] picks the
//! highest-preference transport both sides support (TSP, then DIDComm, then
//! HTTPS). Over the HTTPS binding the registry's answer carries no signature —
//! the registry DID is only stamped on the *outgoing* request as `recipient` —
//! so the endpoint is what the answer's trustworthiness rests on, and deriving
//! it from the DID document keeps it bound to an identifier with integrity
//! behind it.
//!
//! The signer set is **derived from the commits themselves** — there is no
//! per-repository allowlist. The committer header is author-controlled text,
//! so it is treated strictly as a lookup hint: the claim is only ever as good
//! as the two checks that follow it. A commit claiming a DID it cannot sign
//! for fails step 1 (the DID does not publish the signing key, or the
//! signature does not verify over a payload that includes the claim itself);
//! a commit signed by a DID nobody enrolled fails step 2.
//!
//! That places every question of *who may sign here* in the registry, where
//! enrolment, rotation and revocation already live. `--resource` is
//! consequently the only thing scoping a signer to this repository, and is
//! security-relevant input: widening it, or widening `--fallback-resource`,
//! widens who may sign, with nothing in the repository to contradict it.
//!
//! Failure is closed at every layer: an unsigned commit, a committer naming no
//! DID, a DID that will not resolve, a signature by a key that DID does not
//! publish, a cryptographically invalid signature, an unauthorized DID, and an
//! unreachable registry all fail the check — each with its own status so an
//! operator can tell which remediation applies.
//!
//! Signers are reported by **agent name** where one is available
//! (`example.com/@alice`) rather than by raw DID. Names come out of the DID
//! documents this crate already resolves, and render through
//! [`vta_sdk::display_name`] — the same seam the PNM, CNM and VTC operator
//! surfaces use, so a DID is abbreviated identically wherever it appears.

pub mod pgp_exempt;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use ssh_key::{SshSig, public::KeyData};
use trql_client::{
    HttpsTransport, HttpsTransportConfig, ServiceCapabilities, TransportKind, TrqlClient,
    TrqlError, TrqpQuery,
};
use vgi_core::{
    GIT_SSHSIG_NAMESPACE, committer_did, committer_identity, ed25519_keys_from_doc,
    normalize_sshsig_armor, split_signed_commit,
};
use vta_sdk::display_name::{DisplayName, NameBook, NameSource};

use crate::pgp_exempt::ExemptKeyring;

/// Everything `verify-trust` needs for one run.
#[derive(Debug, Clone)]
pub struct VerifyTrustArgs {
    /// Repository to verify (a working tree with `git` available).
    pub repo_dir: PathBuf,
    /// Commit range in `git rev-list` syntax, e.g. `origin/main..HEAD`.
    pub range: String,
    /// Ceiling on the number of *distinct* DIDs a range may claim, each of
    /// which costs one resolution.
    ///
    /// The signer set is derived from the commits, so a pull request chooses
    /// which identifiers CI resolves — and for the network-resolved methods
    /// (`did:web`, `did:webvh`) that means an outbound fetch to a host the
    /// author picked. Distinct DIDs are deduplicated first; this bounds what
    /// remains. Exceeding it fails the run rather than resolving anyway.
    pub max_signers: usize,
    /// Base URL of the Trust Registry (`POST <url>/trust-tasks`).
    ///
    /// `None` until discovery fills it in from `registry_did`'s DID document;
    /// set explicitly to override discovery (a local or dev registry that
    /// publishes no service endpoint). [`verify_prepared`] requires it
    /// resolved — [`handle_verify_trust`] does that before calling.
    ///
    /// Prefer discovery. Over the HTTPS binding the registry's answer is not
    /// signed — `registry_did` is only stamped on the outgoing request as
    /// `recipient` — so trust in "is this DID authorized" rests on reaching
    /// the right host. Deriving the URL from the DID document makes the
    /// endpoint inherit that DID's integrity instead of being a second,
    /// independently mutable value that nothing cross-checks.
    pub registry_url: Option<String>,
    /// DID of the registry (the `recipient` on every query document, and what
    /// the endpoint is discovered from).
    pub registry_did: String,
    /// DID of the **VTC** — the community whose authority the trust tuple is
    /// evaluated under, sent as TRQP's `authority_id`.
    pub vtc_did: String,
    /// TRQP action, e.g. `git.commit.sign`.
    pub action: String,
    /// TRQP resource, e.g. the `org/repo` slug.
    ///
    /// With no committed signer index, this is the **only** thing scoping a
    /// signer to this repository: a grant is accepted exactly when the
    /// registry authorizes the tuple under this resource (or the fallback).
    /// Treat it as security-relevant configuration.
    pub resource: String,
    /// Broader resource to try when the primary one does not authorize
    /// (e.g. the org for an org-wide grant). Grant semantics are
    /// `resource OR fallback`: the registry's wire contract cannot
    /// distinguish "no record" from an explicit `authorized: false`, so a
    /// repo-level record cannot veto an org-level grant.
    pub fallback_resource: Option<String>,
    /// Optional armored PGP keyring of exempt platform keys (e.g. GitHub's
    /// web-flow key); relative paths resolve against `repo_dir`. Absent means
    /// no exemptions: every PGP-signed commit fails.
    pub exempt_keyring: Option<PathBuf>,
    /// Round-trip the agent names the signers' DID documents claim, so a
    /// verified name renders unqualified instead of tagged `[unverified]`.
    ///
    /// Costs one outbound HTTPS fetch per claimed name, to a host the
    /// *document's author* chose, so it is opt-in — the same rule the PNM and
    /// CNM CLIs apply to their `--resolve-agent-names` flag. With it off the
    /// claims still show (they come free with the documents this crate must
    /// resolve anyway), but as the self-assertions they are.
    pub resolve_agent_names: bool,
    /// Emit machine-readable JSON on stdout instead of human lines.
    pub json: bool,
}

/// Outcome for one commit. Ordered worst-first so a report can sort on it.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", tag = "status", content = "detail")]
pub enum CommitStatus {
    /// No `gpgsig` header on the commit.
    Unsigned,
    /// The signature did not parse as an Ed25519 sshsig.
    Malformed(String),
    /// Signed, but the `committer` header names no DID, so the commit asserts
    /// no identity to resolve or authorize.
    NoSignerDid { committer: String },
    /// The claimed DID could not be resolved, so its published keys are
    /// unknown. Fails closed: an unresolvable signer is not a trusted one.
    UnresolvedSigner { did: String, error: String },
    /// The claimed DID resolved, but publishes no verification method holding
    /// the key that signed this commit.
    UnknownKey { did: String, fingerprint: String },
    /// The DID publishes the key, but the signature does not verify.
    BadSignature { signer_did: String },
    /// Valid signature, but the registry did not authorize the signer.
    Unauthorized { signer_did: String },
    /// Valid signature, but the registry could not be consulted. Fails the
    /// run (closed), distinctly from a denial.
    RegistryUnavailable { signer_did: String, error: String },
    /// PGP-signed (a platform commit), but the signature verifies against no
    /// key in the exempt keyring — or no keyring is configured.
    PgpRejected { detail: String },
    /// PGP-signed by a key in the committed exempt keyring (e.g. a GitHub
    /// web-UI merge commit). Passes, reported distinctly from `Trusted`.
    Exempt { fingerprint: String },
    /// Valid signature by a registry-authorized signer. `resource` is the
    /// tuple resource the grant was found under (the primary one or the
    /// fallback).
    Trusted {
        signer_did: String,
        resource: String,
    },
}

impl CommitStatus {
    /// Signed by a registry-authorized DID.
    pub fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted { .. })
    }

    /// Whether the commit passes the check: DID-trusted or keyring-exempt.
    pub fn passes(&self) -> bool {
        matches!(self, Self::Trusted { .. } | Self::Exempt { .. })
    }
}

/// One commit's verdict, as reported.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CommitVerdict {
    pub sha: String,
    #[serde(flatten)]
    pub status: CommitStatus,
}

/// The full report for a range.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustReport {
    pub ok: bool,
    pub commits: Vec<CommitVerdict>,
    /// Claimed DIDs whose resolution failed, each with the reason. Their
    /// commits already carry `unresolvedSigner`; this aggregates the set for
    /// a consumer that wants it without walking every commit.
    pub unresolved_signers: BTreeMap<String, String>,
    /// Display name per named signer DID, with its provenance. Only DIDs that
    /// have a name appear. The commit entries keep full DIDs, so a consumer
    /// that does not care about names is unaffected.
    pub signer_names: BTreeMap<String, DisplayName>,
}

/// The DIDs a range claimed, resolved: the keys each publishes, why any of
/// them could not be resolved, and what to call them.
///
/// Produced by [`resolve_signer_keys`] and consumed by [`verify_with_keys`],
/// which tests construct directly via [`ResolvedSigners::from_keys`].
#[derive(Debug, Default)]
pub struct ResolvedSigners {
    /// DID → the Ed25519 keys its document publishes. Keyed by DID rather
    /// than by key so a commit is checked against *the identity it claims*,
    /// not against whatever identity happens to publish the signing key.
    pub keys: BTreeMap<String, Vec<[u8; 32]>>,
    /// Claimed DID → why it did not resolve.
    pub unresolved: BTreeMap<String, String>,
    /// DID → display name, for every signer whose document names it.
    pub names: NameBook,
}

impl ResolvedSigners {
    /// A signer set with keys but no names — the shape a test wants when it
    /// supplies keys directly instead of resolving DID documents.
    #[must_use]
    pub fn from_keys<I, D>(keys: I) -> Self
    where
        I: IntoIterator<Item = (D, Vec<[u8; 32]>)>,
        D: Into<String>,
    {
        Self {
            keys: keys.into_iter().map(|(did, k)| (did.into(), k)).collect(),
            ..Self::default()
        }
    }

    /// The keys `did` publishes, or `None` if it never resolved.
    fn published(&self, did: &str) -> Option<&[[u8; 32]]> {
        self.keys.get(did).map(Vec::as_slice)
    }
}

/// Run the check end to end: discover the registry endpoint, collect the DIDs
/// the range claims, resolve them, then verify. Returns the process exit code
/// (0 = every commit passes).
pub async fn handle_verify_trust(mut args: VerifyTrustArgs) -> Result<i32> {
    let exempt = load_exempt_keyring(&args)?;
    let commits = read_range(&args.repo_dir, &args.range)?;
    let claimed = claimed_signer_dids(&commits, args.max_signers)?;

    // One resolver for both lookups: the registry's endpoint and the signers'
    // keys come from the same cache.
    let tdk = build_resolver(args.resolve_agent_names).await?;
    if args.registry_url.is_none() {
        args.registry_url = Some(resolve_registry_endpoint(&tdk, &args.registry_did).await?);
    }
    let signers = resolve_signer_keys(&tdk, &claimed).await?;

    let report = verify_prepared(&args, &commits, &signers, exempt.as_ref()).await?;
    print_report(&args, &report)?;
    Ok(if report.ok { 0 } else { 1 })
}

/// One commit of the range, read once so the object is not fetched again for
/// the claim pass and the verification pass.
#[derive(Debug, Clone)]
pub struct RangeCommit {
    pub sha: String,
    pub raw: Vec<u8>,
}

/// Read every commit object in the range, oldest first.
pub fn read_range(repo_dir: &Path, range: &str) -> Result<Vec<RangeCommit>> {
    list_commits(repo_dir, range)?
        .into_iter()
        .map(|sha| {
            let raw = read_commit_raw(repo_dir, &sha)?;
            Ok(RangeCommit { sha, raw })
        })
        .collect()
}

/// The distinct DIDs the range's commits claim on their committer headers.
///
/// Deduplicated, then bounded by `max_signers`: the set is chosen by whoever
/// wrote the commits, and each entry costs a resolution. Commits claiming no
/// DID contribute nothing here — they fail later, individually, with a status
/// that says so.
pub fn claimed_signer_dids(commits: &[RangeCommit], max_signers: usize) -> Result<Vec<String>> {
    let dids: BTreeSet<String> = commits
        .iter()
        .filter_map(|commit| committer_did(&commit.raw))
        .collect();
    if dids.len() > max_signers {
        bail!(
            "range claims {} distinct signer DIDs, over the limit of {max_signers}; \
             each costs a resolution to a host the commit's author chose. Raise \
             --max-signers only if this range is legitimately that wide.",
            dids.len()
        );
    }
    Ok(dids.into_iter().collect())
}

/// Verify commits already read and resolved. Split from
/// [`handle_verify_trust`] so tests can supply keys without a live resolver.
pub async fn verify_prepared(
    args: &VerifyTrustArgs,
    commits: &[RangeCommit],
    signers: &ResolvedSigners,
    exempt: Option<&ExemptKeyring>,
) -> Result<TrustReport> {
    // Pass 1: cryptographic verification, collecting the DIDs that signed.
    let mut checked = Vec::with_capacity(commits.len());
    let mut signer_dids = BTreeSet::new();
    for commit in commits {
        let signature = check_commit_signature(&commit.raw, signers, exempt);
        if let SignatureCheck::Valid { signer_did } = &signature {
            signer_dids.insert(signer_did.clone());
        }
        checked.push((commit.sha.clone(), signature));
    }

    // Pass 2: one registry query per distinct signer DID.
    let decisions = query_registry(args, &signer_dids).await?;

    let commits: Vec<CommitVerdict> = checked
        .into_iter()
        .map(|(sha, signature)| CommitVerdict {
            sha,
            status: status_of(signature, &decisions),
        })
        .collect();

    // Names are reported for the signers that actually signed something here
    // — a name for a DID absent from the range is noise.
    let signer_names = signer_dids
        .iter()
        .filter_map(|did| {
            signers
                .names
                .get(did)
                .map(|name| (did.clone(), name.clone()))
        })
        .collect();

    // An empty range passes vacuously (nothing new to verify).
    let ok = commits.iter().all(|c| c.status.passes());
    Ok(TrustReport {
        ok,
        commits,
        unresolved_signers: signers.unresolved.clone(),
        signer_names,
    })
}

// --- signature layer ---------------------------------------------------------

/// Result of the cryptographic check for one commit.
#[derive(Debug, Clone, PartialEq)]
pub enum SignatureCheck {
    Unsigned,
    Malformed(String),
    NoSignerDid { committer: String },
    UnresolvedSigner { did: String, error: String },
    UnknownKey { did: String, fingerprint: String },
    BadSignature { signer_did: String },
    PgpRejected { detail: String },
    Exempt { fingerprint: String },
    Valid { signer_did: String },
}

/// Verify one raw commit object against the resolved signers.
///
/// The identity comes from the commit's own `committer` header, and is checked
/// against itself: the DID it claims must publish the key that signed, and the
/// signature must verify over a payload that includes that very header. The
/// claim is therefore never trusted — it only selects which document to check
/// the key against, and a commit naming a DID it cannot sign for fails here.
pub fn check_commit_signature(
    raw: &[u8],
    signers: &ResolvedSigners,
    exempt: Option<&ExemptKeyring>,
) -> SignatureCheck {
    let (payload, pem) = match split_signed_commit(raw) {
        Ok(Some(parts)) => parts,
        Ok(None) => return SignatureCheck::Unsigned,
        Err(e) => return SignatureCheck::Malformed(e.to_string()),
    };
    // Platform commits (GitHub web-UI merges, Dependabot) are PGP-signed;
    // they pass only via the explicitly committed exempt keyring.
    if pem.starts_with("-----BEGIN PGP SIGNATURE-----") {
        let Some(keyring) = exempt else {
            return SignatureCheck::PgpRejected {
                detail: "PGP-signed commit, but no exempt keyring is configured".to_string(),
            };
        };
        return match keyring.verify(&pem, &payload) {
            Ok(fingerprint) => SignatureCheck::Exempt { fingerprint },
            Err(detail) => SignatureCheck::PgpRejected { detail },
        };
    }
    let sig = match SshSig::from_pem(normalize_sshsig_armor(&pem).as_bytes()) {
        Ok(sig) => sig,
        Err(e) => return SignatureCheck::Malformed(format!("sshsig did not parse: {e}")),
    };
    let KeyData::Ed25519(embedded) = sig.public_key() else {
        return SignatureCheck::Malformed(format!(
            "unsupported signature algorithm: {}",
            sig.algorithm()
        ));
    };
    let key_bytes: [u8; 32] = embedded.0;

    // The identity is read from the payload — the bytes the signature covers —
    // so a claim that survives verification is one the signer committed to.
    let Some(claimed) = committer_did(&payload) else {
        return SignatureCheck::NoSignerDid {
            committer: committer_identity(&payload).unwrap_or_else(|| "(absent)".to_string()),
        };
    };
    let Some(published) = signers.published(&claimed) else {
        let error = signers
            .unresolved
            .get(&claimed)
            .cloned()
            .unwrap_or_else(|| "not resolved".to_string());
        return SignatureCheck::UnresolvedSigner {
            did: claimed,
            error,
        };
    };
    if !published.contains(&key_bytes) {
        return SignatureCheck::UnknownKey {
            did: claimed,
            fingerprint: hex::encode(key_bytes),
        };
    }
    let public_key = ssh_key::PublicKey::from(sig.public_key().clone());
    match public_key.verify(GIT_SSHSIG_NAMESPACE, &payload, &sig) {
        Ok(()) => SignatureCheck::Valid {
            signer_did: claimed,
        },
        Err(_) => SignatureCheck::BadSignature {
            signer_did: claimed,
        },
    }
}

/// Load the exempt keyring named by the args, resolving relative to the repo.
fn load_exempt_keyring(args: &VerifyTrustArgs) -> Result<Option<ExemptKeyring>> {
    let Some(path) = &args.exempt_keyring else {
        return Ok(None);
    };
    let path = if path.is_absolute() {
        path.clone()
    } else {
        args.repo_dir.join(path)
    };
    Ok(Some(ExemptKeyring::load(&path)?))
}

// --- DID resolution ----------------------------------------------------------

/// Build the DID resolver used for both the registry endpoint and the signers.
///
/// `resolve_agent_names` turns on the resolver's shortcut derivation, which
/// round-trips each claimed name before it is treated as its DID's — see
/// [`VerifyTrustArgs::resolve_agent_names`].
pub async fn build_resolver(resolve_agent_names: bool) -> Result<affinidi_tdk::TDK> {
    use affinidi_tdk::TDK;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;

    // `with_resolve_shortcuts` exists because `vta-sdk/agent-names` turns on
    // `affinidi-did-resolver-cache-sdk/agent-names`, which cargo unifies onto
    // the resolver the TDK builds here.
    TDK::new(
        TDKConfig::builder()
            .with_load_environment(false)
            .with_did_resolver_config(
                DIDCacheConfigBuilder::default()
                    .with_resolve_shortcuts(resolve_agent_names)
                    .build(),
            )
            .build()
            .context("TDK config")?,
        None,
    )
    .await
    .context("TDK init")
}

/// Discover the Trust Registry's endpoint from its DID document.
///
/// The document advertises one service entry per binding it serves;
/// [`ServiceCapabilities::select`] takes the highest-preference transport
/// present in **both** the document and this build — TSP, then DIDComm, then
/// HTTPS. `TransportKind::compiled()` is what this binary can actually
/// construct, so a registry offering only bindings we were not built with
/// fails with both sides listed rather than silently downgrading.
///
/// There is deliberately **no fallback to guessing a URL from the DID's
/// domain**. `vta-sdk` does that for a VTA, where a wrong host merely fails
/// authentication; here a wrong host is one whose authorization answers we
/// would believe. A registry that advertises nothing is an error, and
/// [`VerifyTrustArgs::registry_url`] is the explicit override.
pub async fn resolve_registry_endpoint(
    tdk: &affinidi_tdk::TDK,
    registry_did: &str,
) -> Result<String> {
    let response = tdk
        .did_resolver()
        .resolve(registry_did)
        .await
        .map_err(|e| anyhow::anyhow!("could not resolve registry DID {registry_did}: {e}"))?;
    let doc = serde_json::to_value(&response.doc)
        .with_context(|| format!("DID document for {registry_did} did not serialize"))?;

    let capabilities = ServiceCapabilities::from_document(&doc);
    let choice = capabilities
        .select(&TransportKind::compiled())
        .with_context(|| format!("no usable Trust Registry transport on {registry_did}"))?;

    match choice.kind {
        TransportKind::Https => {
            tracing::debug!(endpoint = %choice.endpoint, "discovered registry REST endpoint");
            Ok(choice.endpoint)
        }
        // Unreachable while `compiled()` is HTTPS-only, but the TSP and DIDComm
        // endpoints are *mediator DIDs*, not URLs — handing one to an HTTPS
        // transport would be a category error, so refuse explicitly.
        kind => bail!(
            "registry {registry_did} was selected for the {kind} binding, whose endpoint \
             ({}) is a mediator DID rather than a URL; verify-trust can only query over \
             HTTPS. Set --registry-url to a REST endpoint.",
            choice.endpoint
        ),
    }
}

/// Resolve every DID the range claimed: collect the Ed25519 keys their
/// documents publish, and name each signer from the same document. A DID that
/// fails to resolve is recorded (its commits fail as `unresolvedSigner`)
/// without blocking the others.
pub async fn resolve_signer_keys(
    tdk: &affinidi_tdk::TDK,
    dids: &[String],
) -> Result<ResolvedSigners> {
    let mut signers = ResolvedSigners::default();
    for did in dids {
        match tdk.did_resolver().resolve(did).await {
            Ok(response) => {
                // A shortcut is only ever set after the resolver checked the
                // claimed name resolves back to this DID; anything else the
                // document claims is a bare self-assertion.
                let name = signer_display_name(
                    response.shortcut.as_ref().map(|s| s.label()),
                    &vta_sdk::display_name::agent_name::claimed_names(&response.doc),
                );
                if let Some(name) = name {
                    signers.names.insert(did.clone(), name);
                }

                let doc = serde_json::to_value(&response.doc)
                    .with_context(|| format!("DID document for {did} did not serialize"))?;
                let published = ed25519_keys_from_doc(&doc);
                if published.is_empty() {
                    // Left out of `keys` deliberately: a document with no
                    // Ed25519 method can verify nothing, and recording it as
                    // resolved-but-empty would report its commits as an
                    // unknown key rather than as this, the actual cause.
                    signers.unresolved.insert(
                        did.clone(),
                        "DID document publishes no Ed25519 verification keys".to_string(),
                    );
                } else {
                    signers.keys.insert(did.clone(), published);
                }
            }
            Err(e) => {
                signers
                    .unresolved
                    .insert(did.clone(), format!("resolution failed: {e}"));
            }
        }
    }
    Ok(signers)
}

/// Pick what to call a signer, given the name its resolution verified (if any)
/// and the names its document claims.
///
/// A verified shortcut wins outright. Otherwise the first claim is reported
/// **unverified**: `alsoKnownAs` is self-asserted, so a hostile DID can claim
/// `mybank.com/@treasury` and a verifier that printed that bare would have
/// told the reviewer, in an authoritative voice, that the bank signed this
/// commit. The claim still surfaces — a DID *attempting* to present as
/// someone else is exactly what a reviewer should see — but tagged, and
/// ranked below every trusted source. See [`vta_sdk::display_name`].
fn signer_display_name(verified: Option<&str>, claimed: &[String]) -> Option<DisplayName> {
    if let Some(name) = verified {
        return Some(DisplayName::new(
            name,
            NameSource::AgentName { verified: true },
        ));
    }
    claimed
        .first()
        .map(|name| DisplayName::new(name, NameSource::AgentName { verified: false }))
}

// --- registry layer -----------------------------------------------------------

/// Per-DID registry decision: `Ok(Some(resource))` = authorized under that
/// tuple resource, `Ok(None)` = denied everywhere queried, `Err` =
/// registry unavailable.
type RegistryDecisions = BTreeMap<String, Result<Option<String>, String>>;

/// One TRQP authorization query per distinct signer DID.
async fn query_registry(
    args: &VerifyTrustArgs,
    signer_dids: &BTreeSet<String>,
) -> Result<RegistryDecisions> {
    let mut decisions = RegistryDecisions::new();
    if signer_dids.is_empty() {
        return Ok(decisions);
    }
    // Resolved by `handle_verify_trust` (discovered from `registry_did`, or
    // taken from the explicit override) before this point.
    let registry_url = args.registry_url.as_deref().context(
        "registry URL not resolved: discover it from --registry-did or pass --registry-url",
    )?;
    let transport = HttpsTransport::new(HttpsTransportConfig::new(registry_url))?;
    let client = TrqlClient::new(Arc::new(transport), &args.registry_did);
    // The primary resource, then the broader fallback if it did not grant.
    let mut resources = vec![args.resource.clone()];
    if let Some(fallback) = &args.fallback_resource
        && fallback != &args.resource
    {
        resources.push(fallback.clone());
    }
    for did in signer_dids {
        let mut decision: Result<Option<String>, String> = Ok(None);
        for resource in &resources {
            // The VTC's DID is TRQP's `authority_id`.
            let query = TrqpQuery::new(did, &args.vtc_did, &args.action, resource);
            match client.authorization(query).await {
                Ok(response) if response.authorized => {
                    decision = Ok(Some(resource.clone()));
                    break;
                }
                Ok(_) => {}
                Err(e @ TrqlError::Rejected { .. }) => {
                    // The registry answered and said no (e.g. unknown tuple
                    // rejected rather than answered false) — a denial, not
                    // an availability problem; the fallback may still grant.
                    tracing::debug!("registry rejected the query for {did}: {e}");
                }
                Err(e) => {
                    // Fail closed: with any scope undeterminable, "denied"
                    // cannot be distinguished from "unreachable".
                    decision = Err(e.to_string());
                    break;
                }
            }
        }
        decisions.insert(did.clone(), decision);
    }
    Ok(decisions)
}

/// Combine the signature check with the registry decision.
fn status_of(signature: SignatureCheck, decisions: &RegistryDecisions) -> CommitStatus {
    match signature {
        SignatureCheck::Unsigned => CommitStatus::Unsigned,
        SignatureCheck::Malformed(detail) => CommitStatus::Malformed(detail),
        SignatureCheck::NoSignerDid { committer } => CommitStatus::NoSignerDid { committer },
        SignatureCheck::UnresolvedSigner { did, error } => {
            CommitStatus::UnresolvedSigner { did, error }
        }
        SignatureCheck::UnknownKey { did, fingerprint } => {
            CommitStatus::UnknownKey { did, fingerprint }
        }
        SignatureCheck::BadSignature { signer_did } => CommitStatus::BadSignature { signer_did },
        SignatureCheck::PgpRejected { detail } => CommitStatus::PgpRejected { detail },
        SignatureCheck::Exempt { fingerprint } => CommitStatus::Exempt { fingerprint },
        SignatureCheck::Valid { signer_did } => match decisions.get(&signer_did) {
            Some(Ok(Some(resource))) => CommitStatus::Trusted {
                signer_did,
                resource: resource.clone(),
            },
            Some(Ok(None)) => CommitStatus::Unauthorized { signer_did },
            Some(Err(error)) => CommitStatus::RegistryUnavailable {
                signer_did,
                error: error.clone(),
            },
            None => CommitStatus::RegistryUnavailable {
                signer_did,
                error: "no registry decision recorded".to_string(),
            },
        },
    }
}

// --- git plumbing --------------------------------------------------------------

/// List the commits in `range`, oldest first.
pub fn list_commits(repo_dir: &Path, range: &str) -> Result<Vec<String>> {
    let output = git(repo_dir, &["rev-list", "--reverse", range])?;
    Ok(output.lines().map(str::to_string).collect())
}

/// Read one raw commit object.
pub fn read_commit_raw(repo_dir: &Path, sha: &str) -> Result<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(["cat-file", "commit", sha])
        .output()
        .context("running git cat-file")?;
    if !output.status.success() {
        bail!(
            "git cat-file commit {sha} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn git(repo_dir: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_dir)
        .args(args)
        .output()
        .with_context(|| format!("running git {}", args.join(" ")))?;
    if !output.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(String::from_utf8(output.stdout)?.trim_end().to_string())
}

// --- reporting ------------------------------------------------------------------

fn print_report(args: &VerifyTrustArgs, report: &TrustReport) -> Result<()> {
    if args.json {
        println!("{}", serde_json::to_string_pretty(report)?);
        return Ok(());
    }

    // Per-commit lines name the signer and abbreviate its DID; the signer
    // block below carries every DID in full, so nothing a reviewer has to
    // check against the registry is lost to the abbreviation.
    let signer = |did: &str| render_signer(report, did);

    for commit in &report.commits {
        let short = &commit.sha[..commit.sha.len().min(12)];
        match &commit.status {
            CommitStatus::Trusted {
                signer_did,
                resource,
            } => {
                println!(
                    "TRUSTED      {short}  {} (via {resource})",
                    signer(signer_did)
                );
            }
            CommitStatus::Exempt { fingerprint } => {
                println!("EXEMPT       {short}  PGP-signed by exempt platform key {fingerprint}");
            }
            CommitStatus::PgpRejected { detail } => {
                println!("PGP-REJECTED {short}  {detail}");
            }
            CommitStatus::Unauthorized { signer_did } => {
                println!(
                    "UNAUTHORIZED {short}  {} is not authorized by the registry",
                    signer(signer_did)
                );
            }
            CommitStatus::RegistryUnavailable { signer_did, error } => {
                println!(
                    "UNAVAILABLE  {short}  signed by {}; registry check failed: {error}",
                    signer(signer_did)
                );
            }
            CommitStatus::BadSignature { signer_did } => {
                println!(
                    "BAD-SIG      {short}  signature by {} does not verify",
                    signer(signer_did)
                );
            }
            CommitStatus::UnknownKey { did, fingerprint } => {
                println!(
                    "UNKNOWN-KEY  {short}  {} publishes no key {fingerprint}",
                    signer(did)
                );
            }
            CommitStatus::UnresolvedSigner { did, error } => {
                println!("UNRESOLVED   {short}  claimed signer {did} did not resolve: {error}");
            }
            CommitStatus::NoSignerDid { committer } => {
                println!("NO-SIGNER    {short}  committer <{committer}> is not a DID");
            }
            CommitStatus::Malformed(detail) => {
                println!("MALFORMED    {short}  {detail}");
            }
            CommitStatus::Unsigned => {
                println!("UNSIGNED     {short}  commit carries no signature");
            }
        }
    }

    print_signer_block(args, report);

    let passing = report.commits.iter().filter(|c| c.status.passes()).count();
    println!(
        "{}: {passing}/{} commits pass",
        if report.ok { "PASS" } else { "FAIL" },
        report.commits.len()
    );
    Ok(())
}

/// A signer for one commit line: `name (did:webvh:QmXk…:example.com)`, or the
/// abbreviated DID alone when nothing names it. Unverified names carry the
/// `[unverified]` tag `NameBook` appends — surfaces must not strip it.
fn render_signer(report: &TrustReport, did: &str) -> String {
    match report.signer_names.get(did) {
        Some(name) if name.is_trusted() => {
            format!(
                "{} ({})",
                name.name,
                vta_sdk::display_name::shorten_did(did)
            )
        }
        Some(name) => format!(
            "{}{} ({})",
            name.name,
            vta_sdk::display_name::UNVERIFIED_SUFFIX,
            vta_sdk::display_name::shorten_did(did)
        ),
        None => vta_sdk::display_name::shorten_did(did),
    }
}

/// The signers that signed this range, each with its full DID.
///
/// Emitted only when something was named — on a repo whose signers claim no
/// agent names this would be a list of DIDs already on every line above.
fn print_signer_block(args: &VerifyTrustArgs, report: &TrustReport) {
    if report.signer_names.is_empty() {
        return;
    }
    println!();
    println!("Signers:");
    for (did, name) in &report.signer_names {
        let tag = if name.is_trusted() {
            String::new()
        } else {
            format!(" {}", vta_sdk::display_name::UNVERIFIED_SUFFIX.trim())
        };
        println!("  {}{tag}", name.name);
        println!("    {did}");
    }
    if !args.resolve_agent_names && report.signer_names.values().any(|n| !n.is_trusted()) {
        println!();
        println!(
            "  Names above are claimed by the DID and were not checked. Pass \
             --resolve-agent-names to resolve each claim back to its DID."
        );
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use ed25519_dalek::SigningKey;
    use vgi_core::create_ssh_signature;

    fn test_key() -> (SigningKey, [u8; 32]) {
        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let public = signing.verifying_key().to_bytes();
        (signing, public)
    }

    const SIGNER: &str = "did:webvh:QmSigner:example.com";

    /// An unsigned commit whose committer claims `SIGNER`, as `did-git-sign`
    /// writes it: `user.email` is the verification-method id.
    fn unsigned_commit() -> String {
        commit_committed_by(&format!("{SIGNER}#key-0"))
    }

    fn commit_committed_by(committer: &str) -> String {
        format!(
            "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
             author A U Thor <a@example.com> 1700000000 +0000\n\
             committer A U Thor <{committer}> 1700000000 +0000\n\
             \n\
             a message\n"
        )
    }

    /// A signer set in which `SIGNER` publishes `public`.
    fn signers_publishing(public: [u8; 32]) -> ResolvedSigners {
        ResolvedSigners::from_keys([(SIGNER, vec![public])])
    }

    /// Insert a gpgsig header before the blank line, continuation-indented,
    /// exactly as git stores it.
    fn signed_commit(payload: &str, armored: &str) -> String {
        let (headers, body) = payload.split_once("\n\n").unwrap();
        let mut sig_header = String::from("gpgsig ");
        let mut lines = armored.trim_end().split('\n');
        sig_header.push_str(lines.next().unwrap());
        for line in lines {
            sig_header.push('\n');
            sig_header.push(' ');
            sig_header.push_str(line);
        }
        format!("{headers}\n{sig_header}\n\n{body}")
    }

    fn sign_commit(payload: &str, key: &SigningKey) -> String {
        let armored = create_ssh_signature(
            key,
            &key.verifying_key(),
            GIT_SSHSIG_NAMESPACE,
            payload.as_bytes(),
        )
        .unwrap();
        signed_commit(payload, &armored)
    }

    #[test]
    fn split_returns_none_for_unsigned_commit() {
        assert!(
            split_signed_commit(unsigned_commit().as_bytes())
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn split_recovers_exact_payload_and_signature() {
        let payload = unsigned_commit();
        let (key, _) = test_key();
        let commit = sign_commit(&payload, &key);

        let (recovered_payload, pem) = split_signed_commit(commit.as_bytes()).unwrap().unwrap();
        assert_eq!(recovered_payload, payload.as_bytes());
        assert!(pem.starts_with("-----BEGIN SSH SIGNATURE-----"));
        assert!(pem.trim_end().ends_with("-----END SSH SIGNATURE-----"));
    }

    #[test]
    fn our_encoder_and_the_decoder_agree() {
        // Cross-check: a signature produced by sign.rs verifies through the
        // ssh-key crate's independent implementation.
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key);

        let check = check_commit_signature(commit.as_bytes(), &signers_publishing(public), None);
        assert_eq!(
            check,
            SignatureCheck::Valid {
                signer_did: SIGNER.to_string()
            }
        );
    }

    #[test]
    fn the_signer_is_the_did_the_commit_claims() {
        // The identity is not configuration: it comes off the commit's own
        // committer header, with the fragment stripped.
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key);

        let SignatureCheck::Valid { signer_did } =
            check_commit_signature(commit.as_bytes(), &signers_publishing(public), None)
        else {
            panic!("expected a valid signature");
        };
        assert_eq!(signer_did, SIGNER, "the bare DID, not the key id");
    }

    #[test]
    fn claiming_a_did_that_does_not_publish_the_signing_key_fails() {
        // The spoof the committer header invites: sign with your own key while
        // naming someone else's DID. The claim selects whose document to
        // check, and that document does not publish this key.
        let payload = commit_committed_by("did:webvh:QmVictim:example.com#key-0");
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key);

        let signers = ResolvedSigners::from_keys([
            (SIGNER, vec![public]),
            ("did:webvh:QmVictim:example.com", vec![[0u8; 32]]),
        ]);
        assert_eq!(
            check_commit_signature(commit.as_bytes(), &signers, None),
            SignatureCheck::UnknownKey {
                did: "did:webvh:QmVictim:example.com".to_string(),
                fingerprint: hex::encode(public),
            },
            "a key published by another DID must not authenticate this claim"
        );
    }

    #[test]
    fn a_committer_that_is_not_a_did_has_no_identity_to_check() {
        let payload = commit_committed_by("alice@example.com");
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key);

        assert_eq!(
            check_commit_signature(commit.as_bytes(), &signers_publishing(public), None),
            SignatureCheck::NoSignerDid {
                committer: "alice@example.com".to_string()
            }
        );
    }

    #[test]
    fn a_claimed_did_that_did_not_resolve_fails_closed() {
        let payload = unsigned_commit();
        let (key, _) = test_key();
        let commit = sign_commit(&payload, &key);

        let mut signers = ResolvedSigners::default();
        signers
            .unresolved
            .insert(SIGNER.to_string(), "resolution failed: no such host".into());

        assert_eq!(
            check_commit_signature(commit.as_bytes(), &signers, None),
            SignatureCheck::UnresolvedSigner {
                did: SIGNER.to_string(),
                error: "resolution failed: no such host".to_string(),
            },
            "an unresolvable signer is not a trusted one"
        );
    }

    #[test]
    fn the_claim_is_read_from_the_bytes_the_signature_covers() {
        // Rewriting the committer after signing invalidates the signature, so
        // a surviving claim is one the signer committed to.
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key).replace(
            &format!("{SIGNER}#key-0"),
            "did:webvh:QmOther:example.com#key-0",
        );

        let signers = ResolvedSigners::from_keys([
            (SIGNER, vec![public]),
            ("did:webvh:QmOther:example.com", vec![public]),
        ]);
        assert_eq!(
            check_commit_signature(commit.as_bytes(), &signers, None),
            SignatureCheck::BadSignature {
                signer_did: "did:webvh:QmOther:example.com".to_string()
            },
            "tampering with the claimed identity breaks the signature over it"
        );
    }

    #[test]
    fn distinct_claimed_dids_are_deduplicated_and_bounded() {
        let (key, _) = test_key();
        let commits: Vec<RangeCommit> = ["QmA", "QmB", "QmA"]
            .iter()
            .enumerate()
            .map(|(i, scid)| RangeCommit {
                sha: format!("{i:040}"),
                raw: sign_commit(
                    &commit_committed_by(&format!("did:webvh:{scid}:example.com#key-0")),
                    &key,
                )
                .into_bytes(),
            })
            .collect();

        let claimed = claimed_signer_dids(&commits, 32).unwrap();
        assert_eq!(
            claimed,
            vec![
                "did:webvh:QmA:example.com".to_string(),
                "did:webvh:QmB:example.com".to_string(),
            ],
            "three commits, two identities, two resolutions"
        );
        assert!(
            claimed_signer_dids(&commits, 1).is_err(),
            "a range may not make CI resolve more hosts than the cap allows"
        );
    }

    #[test]
    fn legacy_76_column_armor_still_verifies() {
        // Signatures created before sign.rs matched ssh-keygen's 70-column
        // wrapping are permanent in git history and must keep verifying.
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let armored = create_ssh_signature(
            &key,
            &key.verifying_key(),
            GIT_SSHSIG_NAMESPACE,
            payload.as_bytes(),
        )
        .unwrap();
        let body: String = armored
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect();
        let mut legacy = String::from("-----BEGIN SSH SIGNATURE-----\n");
        for chunk in body.as_bytes().chunks(76) {
            legacy.push_str(std::str::from_utf8(chunk).unwrap());
            legacy.push('\n');
        }
        legacy.push_str("-----END SSH SIGNATURE-----\n");

        let commit = signed_commit(&payload, &legacy);
        assert_eq!(
            check_commit_signature(commit.as_bytes(), &signers_publishing(public), None),
            SignatureCheck::Valid {
                signer_did: SIGNER.to_string()
            }
        );
    }

    #[test]
    fn a_key_the_claimed_did_does_not_publish_is_reported_with_its_fingerprint() {
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key);

        // The DID resolved, but publishes a different key.
        let signers = ResolvedSigners::from_keys([(SIGNER, vec![[3u8; 32]])]);
        assert_eq!(
            check_commit_signature(commit.as_bytes(), &signers, None),
            SignatureCheck::UnknownKey {
                did: SIGNER.to_string(),
                fingerprint: hex::encode(public),
            }
        );
    }

    #[test]
    fn tampered_payload_is_a_bad_signature() {
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key).replace("a message", "b message");

        let check = check_commit_signature(commit.as_bytes(), &signers_publishing(public), None);
        assert_eq!(
            check,
            SignatureCheck::BadSignature {
                signer_did: SIGNER.to_string()
            }
        );
    }

    #[test]
    fn unsigned_commit_is_unsigned() {
        let check = check_commit_signature(
            unsigned_commit().as_bytes(),
            &ResolvedSigners::default(),
            None,
        );
        assert_eq!(check, SignatureCheck::Unsigned);
    }

    // --- registry endpoint discovery ---

    /// The `service` block from the Trust Registry DID document in the
    /// workspace's DID_SERVICE_DISCOVERY design note: one entry per binding,
    /// `#rest` carrying both types via the set form, TSP/DIDComm endpoints
    /// being mediator DIDs rather than URLs.
    fn registry_document() -> serde_json::Value {
        serde_json::json!({
            "id": "did:webvh:QmRegistryScid:registry.example",
            "service": [
                {
                    "id": "did:webvh:QmRegistryScid:registry.example#rest",
                    "type": ["TRQPRest", "TrustRegistry"],
                    "serviceEndpoint": {
                        "uri": "https://registry.example",
                        "profile": "https://trustoverip.org/profiles/trqp/v2"
                    }
                },
                {
                    "id": "did:webvh:QmRegistryScid:registry.example#didcomm",
                    "type": "DIDCommMessaging",
                    "serviceEndpoint": {
                        "uri": "did:web:mediator.example",
                        "accept": ["didcomm/v2"],
                        "routingKeys": []
                    }
                },
                {
                    "id": "did:webvh:QmRegistryScid:registry.example#tsp",
                    "type": "TSPTransport",
                    "serviceEndpoint": "did:web:mediator.example"
                }
            ]
        })
    }

    #[test]
    fn all_three_bindings_are_parsed_from_the_registry_document() {
        let caps = ServiceCapabilities::from_document(&registry_document());
        assert_eq!(caps.https.as_deref(), Some("https://registry.example"));
        assert_eq!(caps.tsp.as_deref(), Some("did:web:mediator.example"));
        assert_eq!(caps.didcomm.as_deref(), Some("did:web:mediator.example"));
        assert_eq!(
            caps.advertised(),
            vec![
                TransportKind::Tsp,
                TransportKind::Didcomm,
                TransportKind::Https
            ],
            "advertised order is the preference order: TSP, DIDComm, HTTPS"
        );
    }

    #[test]
    fn selection_prefers_tsp_then_didcomm_then_https() {
        let caps = ServiceCapabilities::from_document(&registry_document());
        // Against a client that speaks everything, TSP wins outright.
        assert_eq!(
            caps.select(&[
                TransportKind::Tsp,
                TransportKind::Didcomm,
                TransportKind::Https
            ])
            .unwrap()
            .kind,
            TransportKind::Tsp
        );
        // Drop TSP and DIDComm is next, ahead of the HTTPS floor.
        assert_eq!(
            caps.select(&[TransportKind::Didcomm, TransportKind::Https])
                .unwrap()
                .kind,
            TransportKind::Didcomm
        );
    }

    #[test]
    fn this_build_selects_https_because_that_is_what_it_can_construct() {
        // `compiled()` is feature-gated, and verify-trust takes trql-client's
        // default features (https only): the preference order is honoured, we
        // simply cannot construct the two above it. Selecting against what we
        // advertise rather than a hard-coded list is what stops us choosing a
        // transport and then failing to build it.
        let compiled = TransportKind::compiled();
        assert_eq!(compiled, vec![TransportKind::Https]);

        let choice = ServiceCapabilities::from_document(&registry_document())
            .select(&compiled)
            .unwrap();
        assert_eq!(choice.kind, TransportKind::Https);
        assert_eq!(choice.endpoint, "https://registry.example");
    }

    #[test]
    fn a_registry_offering_no_binding_we_speak_fails_with_both_sides_named() {
        // TSP and DIDComm only. Failing loudly beats guessing a URL: the error
        // carries what each side offers so the mismatch is diagnosable.
        let doc = serde_json::json!({
            "id": "did:webvh:QmRegistryScid:registry.example",
            "service": [{
                "id": "did:webvh:QmRegistryScid:registry.example#tsp",
                "type": "TSPTransport",
                "serviceEndpoint": "did:web:mediator.example"
            }]
        });
        let error = ServiceCapabilities::from_document(&doc)
            .select(&[TransportKind::Https])
            .unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains("https") && rendered.contains("tsp"),
            "the error must name both sides' transports: {rendered}"
        );
    }

    #[test]
    fn a_document_advertising_nothing_yields_no_endpoint() {
        // No service block at all: there is nothing to discover, and no
        // domain-guessing fallback exists to paper over it.
        let caps = ServiceCapabilities::from_document(&serde_json::json!({
            "id": "did:webvh:QmRegistryScid:registry.example"
        }));
        assert_eq!(caps, ServiceCapabilities::default());
        assert!(caps.select(&TransportKind::compiled()).is_err());
    }

    #[test]
    fn statuses_compose_signature_and_registry_decisions() {
        let did = "did:example:signer".to_string();
        let mut decisions = RegistryDecisions::new();
        decisions.insert(did.clone(), Ok(Some("example/repo".to_string())));
        assert!(
            status_of(
                SignatureCheck::Valid {
                    signer_did: did.clone()
                },
                &decisions
            )
            .is_trusted()
        );

        decisions.insert(did.clone(), Ok(None));
        assert_eq!(
            status_of(
                SignatureCheck::Valid {
                    signer_did: did.clone()
                },
                &decisions
            ),
            CommitStatus::Unauthorized {
                signer_did: did.clone()
            }
        );

        decisions.insert(did.clone(), Err("connect refused".to_string()));
        assert!(matches!(
            status_of(SignatureCheck::Valid { signer_did: did }, &decisions),
            CommitStatus::RegistryUnavailable { .. }
        ));
    }

    // --- signer naming ---

    #[test]
    fn a_verified_shortcut_is_the_name() {
        let name = signer_display_name(
            Some("example.com/@alice"),
            &["https://example.com/@alice".to_string()],
        )
        .unwrap();
        assert_eq!(name.name, "example.com/@alice");
        assert!(name.is_trusted());
    }

    #[test]
    fn an_unchecked_claim_is_never_trusted() {
        // The spoof this exists for: a signer's document claims the bank's
        // name. Nothing resolved it back, so it must not render as the bank.
        let name =
            signer_display_name(None, &["https://mybank.com/@treasury".to_string()]).unwrap();
        assert_eq!(name.source, NameSource::AgentName { verified: false });
        assert!(!name.is_trusted());
    }

    #[test]
    fn a_signer_claiming_nothing_has_no_name() {
        assert!(signer_display_name(None, &[]).is_none());
    }

    #[test]
    fn an_unverified_name_renders_tagged_beside_its_did() {
        let did = "did:webvh:QmScidAbCdEfGhIj:example.com:ops";
        let report = TrustReport {
            ok: true,
            commits: Vec::new(),
            unresolved_signers: BTreeMap::new(),
            signer_names: BTreeMap::from([(
                did.to_string(),
                DisplayName::new(
                    "mybank.com/@treasury",
                    NameSource::AgentName { verified: false },
                ),
            )]),
        };
        let rendered = render_signer(&report, did);
        assert!(
            rendered.contains("unverified"),
            "an unchecked claim must never render as a plain name: {rendered}"
        );
        assert!(
            rendered.contains("example.com"),
            "the DID must stay visible beside the name: {rendered}"
        );
    }

    #[test]
    fn an_unnamed_signer_falls_back_to_its_did() {
        let did = "did:webvh:QmScidAbCdEfGhIj:example.com:ops";
        let report = TrustReport {
            ok: true,
            commits: Vec::new(),
            unresolved_signers: BTreeMap::new(),
            signer_names: BTreeMap::new(),
        };
        assert_eq!(
            render_signer(&report, did),
            vta_sdk::display_name::shorten_did(did)
        );
    }
}
