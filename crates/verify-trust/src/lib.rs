//! `verify-trust`: verify a git commit range against the VTC Trust Registry.
//!
//! For every commit in a range this module answers two questions, in order:
//!
//! 1. **Who signed it, cryptographically?** The commit's `gpgsig` header is
//!    parsed as a PROTOCOL.sshsig blob; the Ed25519 public key embedded in it
//!    is matched against the keys published in the DID documents of the
//!    repository's declared signers, and the signature is verified over the
//!    exact bytes git signed.
//! 2. **Is that DID trusted, right now?** The signer DID is checked against
//!    the Trust Registry with a TRQP authorization query
//!    (`{entity: signer, authority, action, resource}`) via `trql-client`.
//!
//! The signer set comes from a committed index file (default `.did-signers`,
//! one DID per line) that lists *identities, not keys* — keys are resolved
//! from each DID document at verification time, so key rotation never
//! requires touching the repository, and revoking a signer is a registry
//! operation that takes effect on the next run.
//!
//! Failure is closed at every layer: an unsigned commit, a signature by an
//! unpublished key, a cryptographically invalid signature, an unauthorized
//! DID, and an unreachable registry all fail the check — each with its own
//! status so an operator can tell which remediation applies.
//!
//! Signers are reported by **agent name** where one is available
//! (`example.com/@alice`) rather than by raw DID. Names come out of the DID
//! documents this crate already resolves, and render through
//! [`vta_sdk::display_name`] — the same seam the PNM, CNM and VTC operator
//! surfaces use, so a DID is abbreviated identically wherever it appears.

pub mod pgp_exempt;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use serde::Serialize;
use ssh_key::{SshSig, public::KeyData};
use trql_client::{HttpsTransport, HttpsTransportConfig, TrqlClient, TrqlError, TrqpQuery};
use vgi_core::{
    GIT_SSHSIG_NAMESPACE, ed25519_keys_from_doc, normalize_sshsig_armor, split_signed_commit,
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
    /// Signer index file; relative paths resolve against `repo_dir`.
    pub signers_file: PathBuf,
    /// Base URL of the Trust Registry (`POST <url>/trust-tasks`).
    pub registry_url: String,
    /// DID of the registry (the `recipient` on every query document).
    pub registry_did: String,
    /// DID of the authority the tuple is evaluated under.
    pub authority_did: String,
    /// TRQP action, e.g. `git.commit.sign`.
    pub action: String,
    /// TRQP resource, e.g. the `org/repo` slug.
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
    /// The embedded key is published by none of the declared signers.
    UnknownKey { fingerprint: String },
    /// The key maps to a signer, but the signature does not verify.
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
    /// Signer DIDs whose resolution failed (their commits show as
    /// `unknownKey`); surfaced so the cause is visible.
    pub unresolved_signers: BTreeMap<String, String>,
    /// Display name per named signer DID, with its provenance. Only DIDs that
    /// have a name appear. The commit entries keep full DIDs, so a consumer
    /// that does not care about names is unaffected.
    pub signer_names: BTreeMap<String, DisplayName>,
}

/// The declared signers, resolved: their published keys, why any of them
/// could not be resolved, and what to call them.
///
/// Produced by [`resolve_signer_keys`] and consumed by [`verify_with_keys`],
/// which tests construct directly via [`ResolvedSigners::from_keys`].
#[derive(Debug, Default)]
pub struct ResolvedSigners {
    /// Published Ed25519 key → the DID that publishes it.
    pub keys: HashMap<[u8; 32], String>,
    /// Declared DID → why it did not resolve.
    pub unresolved: BTreeMap<String, String>,
    /// DID → display name, for every signer whose document names it.
    pub names: NameBook,
}

impl ResolvedSigners {
    /// A signer set with keys but no names — the shape a test wants when it
    /// supplies keys directly instead of resolving DID documents.
    #[must_use]
    pub fn from_keys(keys: HashMap<[u8; 32], String>) -> Self {
        Self {
            keys,
            ..Self::default()
        }
    }
}

/// Run the check end to end: resolve the declared signers' keys, then verify
/// the range. Returns the process exit code (0 = every commit trusted).
pub async fn handle_verify_trust(args: VerifyTrustArgs) -> Result<i32> {
    let signer_dids = load_signers(&args.repo_dir, &args.signers_file)?;
    let exempt = load_exempt_keyring(&args)?;
    let signers = resolve_signer_keys(&signer_dids, args.resolve_agent_names).await?;
    let report = verify_with_keys(&args, &signers, exempt.as_ref()).await?;
    print_report(&args, &report)?;
    Ok(if report.ok { 0 } else { 1 })
}

/// Verify the range against an already-resolved signer set. Split from
/// [`handle_verify_trust`] so tests can supply keys without a live resolver.
pub async fn verify_with_keys(
    args: &VerifyTrustArgs,
    signers: &ResolvedSigners,
    exempt: Option<&ExemptKeyring>,
) -> Result<TrustReport> {
    let shas = list_commits(&args.repo_dir, &args.range)?;

    // Pass 1: cryptographic verification, collecting the DIDs that signed.
    let mut checked = Vec::with_capacity(shas.len());
    let mut signer_dids = BTreeSet::new();
    for sha in shas {
        let raw = read_commit_raw(&args.repo_dir, &sha)?;
        let signature = check_commit_signature(&raw, &signers.keys, exempt);
        if let SignatureCheck::Valid { signer_did } = &signature {
            signer_dids.insert(signer_did.clone());
        }
        checked.push((sha, signature));
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

    // Names are reported for the declared signers that actually signed
    // something here — a name for a DID absent from the range is noise.
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
    UnknownKey { fingerprint: String },
    BadSignature { signer_did: String },
    PgpRejected { detail: String },
    Exempt { fingerprint: String },
    Valid { signer_did: String },
}

/// Verify one raw commit object against the signer key map.
pub fn check_commit_signature(
    raw: &[u8],
    signer_keys: &HashMap<[u8; 32], String>,
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
    let Some(signer_did) = signer_keys.get(&key_bytes) else {
        return SignatureCheck::UnknownKey {
            fingerprint: hex::encode(key_bytes),
        };
    };
    let public_key = ssh_key::PublicKey::from(sig.public_key().clone());
    match public_key.verify(GIT_SSHSIG_NAMESPACE, &payload, &sig) {
        Ok(()) => SignatureCheck::Valid {
            signer_did: signer_did.clone(),
        },
        Err(_) => SignatureCheck::BadSignature {
            signer_did: signer_did.clone(),
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

// --- signer index & DID resolution -------------------------------------------

/// Read and parse the signer index: one DID per line, `#` comments allowed.
/// A missing or malformed file is a hard error — with no declared signers
/// there is nothing to verify against, and the check must not silently pass.
pub fn load_signers(repo_dir: &Path, signers_file: &Path) -> Result<Vec<String>> {
    let path = if signers_file.is_absolute() {
        signers_file.to_path_buf()
    } else {
        repo_dir.join(signers_file)
    };
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read signer index {}", path.display()))?;
    let dids = parse_signers(&text)?;
    if dids.is_empty() {
        bail!("signer index {} declares no DIDs", path.display());
    }
    Ok(dids)
}

/// Parse signer-index text. Rejects non-DID entries outright rather than
/// skipping them: a typo must fail loudly, not silently drop a signer.
pub fn parse_signers(text: &str) -> Result<Vec<String>> {
    let mut dids = Vec::new();
    for (number, line) in text.lines().enumerate() {
        let entry = line.trim();
        if entry.is_empty() || entry.starts_with('#') {
            continue;
        }
        if !entry.starts_with("did:") {
            bail!("signer index line {}: not a DID: {entry}", number + 1);
        }
        dids.push(entry.to_string());
    }
    Ok(dids)
}

/// Resolve every declared signer DID: collect the Ed25519 keys their DID
/// documents publish, and name each signer from the same document. A DID that
/// fails to resolve is recorded (its commits will fail as `unknownKey`)
/// without blocking the other signers.
///
/// `resolve_agent_names` turns on the resolver's shortcut derivation, which
/// round-trips each claimed name before it is treated as this DID's — see
/// [`VerifyTrustArgs::resolve_agent_names`]. Unverified claims are picked up
/// either way, since they arrive with documents that must be resolved anyway.
pub async fn resolve_signer_keys(
    dids: &[String],
    resolve_agent_names: bool,
) -> Result<ResolvedSigners> {
    use affinidi_tdk::TDK;
    use affinidi_tdk::common::config::TDKConfig;
    use affinidi_tdk::did_resolver::config::DIDCacheConfigBuilder;

    // `with_resolve_shortcuts` exists because `vta-sdk/agent-names` turns on
    // `affinidi-did-resolver-cache-sdk/agent-names`, which cargo unifies onto
    // the resolver the TDK builds here.
    let tdk = TDK::new(
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
    .context("TDK init")?;

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
                    signers.unresolved.insert(
                        did.clone(),
                        "DID document publishes no Ed25519 verification keys".to_string(),
                    );
                }
                for key in published {
                    signers.keys.insert(key, did.clone());
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
    let transport = HttpsTransport::new(HttpsTransportConfig::new(&args.registry_url))?;
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
            let query = TrqpQuery::new(did, &args.authority_did, &args.action, resource);
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
        SignatureCheck::UnknownKey { fingerprint } => CommitStatus::UnknownKey { fingerprint },
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
    // block below carries every DID in full, so nothing that has to be
    // cross-checked against `.did-signers` is lost to the abbreviation.
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
            CommitStatus::UnknownKey { fingerprint } => {
                println!(
                    "UNKNOWN-KEY  {short}  key {fingerprint} is published by no declared signer"
                );
            }
            CommitStatus::Malformed(detail) => {
                println!("MALFORMED    {short}  {detail}");
            }
            CommitStatus::Unsigned => {
                println!("UNSIGNED     {short}  commit carries no signature");
            }
        }
    }
    for (did, reason) in &report.unresolved_signers {
        println!("WARNING      declared signer {did}: {reason}");
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

    fn unsigned_commit() -> String {
        "tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904\n\
         author A U Thor <a@example.com> 1700000000 +0000\n\
         committer A U Thor <a@example.com> 1700000000 +0000\n\
         \n\
         a message\n"
            .to_string()
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
        let keys = HashMap::from([(public, "did:example:signer".to_string())]);

        let check = check_commit_signature(commit.as_bytes(), &keys, None);
        assert_eq!(
            check,
            SignatureCheck::Valid {
                signer_did: "did:example:signer".to_string()
            }
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
        let keys = HashMap::from([(public, "did:example:signer".to_string())]);
        assert_eq!(
            check_commit_signature(commit.as_bytes(), &keys, None),
            SignatureCheck::Valid {
                signer_did: "did:example:signer".to_string()
            }
        );
    }

    #[test]
    fn unknown_key_is_reported_with_fingerprint() {
        let payload = unsigned_commit();
        let (key, _) = test_key();
        let commit = sign_commit(&payload, &key);

        let check = check_commit_signature(commit.as_bytes(), &HashMap::new(), None);
        assert!(matches!(check, SignatureCheck::UnknownKey { .. }));
    }

    #[test]
    fn tampered_payload_is_a_bad_signature() {
        let payload = unsigned_commit();
        let (key, public) = test_key();
        let commit = sign_commit(&payload, &key).replace("a message", "b message");
        let keys = HashMap::from([(public, "did:example:signer".to_string())]);

        let check = check_commit_signature(commit.as_bytes(), &keys, None);
        assert_eq!(
            check,
            SignatureCheck::BadSignature {
                signer_did: "did:example:signer".to_string()
            }
        );
    }

    #[test]
    fn unsigned_commit_is_unsigned() {
        let check = check_commit_signature(unsigned_commit().as_bytes(), &HashMap::new(), None);
        assert_eq!(check, SignatureCheck::Unsigned);
    }

    #[test]
    fn signers_index_parses_and_rejects_non_dids() {
        let parsed =
            parse_signers("# team\n did:webvh:abc:example.com \n\ndid:webvh:def:example.com\n")
                .unwrap();
        assert_eq!(parsed.len(), 2);
        assert!(parse_signers("not-a-did\n").is_err());
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
