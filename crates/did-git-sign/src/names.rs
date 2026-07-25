//! DID → human name for the operator-facing surfaces.
//!
//! Setup and diagnostics show DIDs constantly, and operators can't read them.
//! The naming logic itself lives in [`vta_sdk::display_name`] — the same seam
//! the PNM, CNM and VTC operator CLIs render through, so a DID is abbreviated
//! identically wherever it appears. This module is the thin layer on top: it
//! knows about the two shapes local to `did-git-sign`.
//!
//! **Principals carry a fragment.** The signing identity is a
//! `did:webvh:…#key-0`, but a name is bound to the DID, not to one of its
//! keys — so a lookup has to strip the fragment first. [`principal_did`] is
//! that one line, in one place, rather than at every call site.
//!
//! **Names cost network here.** `did-git-sign` holds no local label store: a
//! context names its own DID and nothing else, so the only source that can
//! name a *signing* identity is an agent name, and reading one back is a DID
//! resolution plus an outbound fetch per claimed name. That is opt-in per
//! invocation (`--resolve-agent-names`), matching the PNM and CNM CLIs.

use vta_sdk::client::VtaClient;
use vta_sdk::display_name::{DisplayName, NameBook, NameSource, shorten_did};

/// The DID a principal belongs to: everything before the `#fragment`.
///
/// `did:webvh:QmScid:example.com#key-0` → `did:webvh:QmScid:example.com`.
/// A name binds to the identity, so `#key-0` and `#key-1` are the same
/// subject and must resolve to the same name.
#[must_use]
pub fn principal_did(principal: &str) -> &str {
    principal.split('#').next().unwrap_or(principal)
}

/// Name each context's own DID from the context's name — free, it rides on a
/// listing the caller already has.
pub fn book_from_contexts(book: &mut NameBook, contexts: &[vta_sdk::client::ContextResponse]) {
    for ctx in contexts {
        if let Some(did) = &ctx.did {
            book.insert(did, DisplayName::new(&ctx.name, NameSource::ContextName));
        }
    }
}

/// Name every DID the VTA has a label for: ACL subject labels and context
/// names. Both fetches are swallowed on failure — naming is decoration, and a
/// caller who may read their own DIDs but not the ACL must still get output.
pub async fn book_from_vta(client: &VtaClient) -> NameBook {
    let mut book = NameBook::new();
    if let Ok(acl) = client.list_acl(None).await {
        for entry in &acl.entries {
            book.insert_opt(&entry.did, entry.label.as_deref(), NameSource::AclLabel);
        }
    }
    if let Ok(contexts) = client.list_contexts().await {
        book_from_contexts(&mut book, &contexts.contexts);
    }
    book
}

/// Add verified agent names to `book` for each principal in `principals`.
///
/// No-op unless the operator asked for it. Each claimed name is round-tripped
/// before it is trusted: a claim that does not lead back to its own DID still
/// lands in the book, but as `AgentName { verified: false }`, which ranks
/// below every local label and renders tagged. Failures are swallowed per DID
/// — an unreachable name server degrades a line to its DID rather than
/// failing the command.
pub async fn resolve_agent_names_into<'a>(
    book: &mut NameBook,
    principals: impl IntoIterator<Item = &'a str>,
    enabled: bool,
) {
    if !enabled {
        return;
    }
    let dids: Vec<&str> = principals.into_iter().map(principal_did).collect();
    vta_sdk::display_name::agent_name::fill_book(book, dids).await;
}

/// One-line rendering for prose and pickers:
/// `example.com/@alice (did:webvh:QmXk…:example.com)`.
///
/// Falls back to the shortened DID alone when nothing names it — the DID is
/// always present, because a name an operator cannot cross-check against an
/// identifier is a name they cannot audit. An unverified claim keeps the
/// `[unverified]` tag `NameBook` appends; do not strip it.
#[must_use]
pub fn inline(book: &NameBook, principal: &str) -> String {
    match book.name_of(principal_did(principal)) {
        Some(name) => format!("{name} ({})", shorten_did(principal)),
        None => shorten_did(principal),
    }
}

/// The `Name:` line for a detail block, or `None` when nothing names the
/// principal.
///
/// Detail blocks print the DID in full on their own line — abbreviating it is
/// the one thing they exist to avoid — so this returns the name alone.
#[must_use]
pub fn name_line(book: &NameBook, principal: &str) -> Option<String> {
    book.name_of(principal_did(principal))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    const DID: &str = "did:webvh:QmScidAbCdEfGhIj:example.com:ops";

    #[test]
    fn a_fragment_is_not_part_of_the_subject() {
        assert_eq!(principal_did(&format!("{DID}#key-0")), DID);
        assert_eq!(principal_did(DID), DID);
    }

    #[test]
    fn a_key_is_named_by_the_did_that_publishes_it() {
        // The book is keyed by DID; a principal names the same subject
        // whichever of its keys is signing.
        let mut book = NameBook::new();
        book.insert(DID, DisplayName::new("ops", NameSource::ContextName));
        assert_eq!(name_line(&book, &format!("{DID}#key-0")).unwrap(), "ops");
        assert_eq!(name_line(&book, &format!("{DID}#key-7")).unwrap(), "ops");
    }

    #[test]
    fn inline_keeps_the_did_beside_the_name() {
        let mut book = NameBook::new();
        book.insert(DID, DisplayName::new("ops", NameSource::ContextName));
        let out = inline(&book, DID);
        assert!(out.starts_with("ops ("));
        assert!(out.contains("example.com"));
    }

    #[test]
    fn inline_falls_back_to_the_shortened_did() {
        assert_eq!(inline(&NameBook::new(), DID), shorten_did(DID));
    }

    #[test]
    fn an_unchecked_claim_stays_tagged() {
        let mut book = NameBook::new();
        book.insert(
            DID,
            DisplayName::new(
                "mybank.com/@treasury",
                NameSource::AgentName { verified: false },
            ),
        );
        assert!(
            inline(&book, DID).contains("unverified"),
            "a self-asserted name must never render as a plain one"
        );
    }

    #[test]
    fn a_context_names_its_own_did_only() {
        let mut book = NameBook::new();
        book_from_contexts(
            &mut book,
            &[serde_json::from_value(serde_json::json!({
                "id": "ctx-1",
                "name": "did-git-sign",
                "did": DID,
                "description": null,
                "base_path": "/",
                "created_at": "2026-01-01T00:00:00Z",
                "updated_at": "2026-01-01T00:00:00Z",
            }))
            .unwrap()],
        );
        assert_eq!(name_line(&book, DID).unwrap(), "did-git-sign");
    }
}
