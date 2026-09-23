//! Forgejo adapter for VGI git namespaces.
//!
//! Implements [`vgi_forge::Forge`] for a Forgejo instance (and Gitea, best
//! effort), acting as **one community's bot user** on it (§5.9 of the
//! design). Forgejo has no GitHub-App equivalent, so the differences are
//! about identity, merges and self-hosting:
//!
//! - **Identity.** A dedicated bot user with an access token scoped to
//!   [`BOT_TOKEN_SCOPES`]. It is long-lived, so it is held as a [`Secret`]
//!   (zeroized, never printed), swappable in place, and rotated by the
//!   bridge in two phases ([`ForgejoForge::mint_token`], then
//!   [`ForgejoForge::retire_token`] once the new one is persisted) — which needs the bot's
//!   password, because Forgejo mints tokens only under basic auth. Whether
//!   the bridge holds that password is an explicit choice
//!   ([`TokenRotation`]).
//! - **Capabilities by probing.** [`ForgejoForge::connect`] reads
//!   `/api/v1/version` and switches off what the instance lacks
//!   (fast-forward-only merges, the Actions variables API) before a plan is
//!   built, rather than failing half-way through one.
//! - **Binding.** The admin signs in through the bridge's OAuth2 app
//!   (authorisation code + PKCE). The bridge confirms they own the org,
//!   uses that one-time token to put the bot in a `vgi-bridge` team (admin,
//!   "create repositories") and to create the org webhook, then wipes it.
//! - **Roles.** Owner → `admin` collaborator; maintainer → `write` **and**
//!   the default branch's merge allow-list; committer → nothing (or `write`
//!   by opt-in). Logins are looked up fresh by numeric id before each change.
//! - **Bootstrap.** Fast-forward-only merges, the workflow at
//!   `.forgejo/workflows/verify-trust.yml` (action by full URL, pinned by
//!   SHA, `version` and `sha256` pinned), the variables, and a branch
//!   protection that lets nobody push, applies to admins, requires the
//!   check's status context, restricts merging to the allow-list, and
//!   protects the workflow paths so no PR can rewrite its own check.
//! - **Webhooks.** `X-Forgejo-Signature` (or `X-Gitea-Signature`), hex
//!   HMAC-SHA256 of the raw body, checked in constant time before parsing.
//!
//! The HTTP layer is a thin reqwest client, like the GitHub adapter's:
//! redirects off, a configurable base URL, and the credential named on
//! every request.

mod api;
mod config;
mod forge;
mod oauth;
pub mod plan;
mod secret;
pub mod version;
pub mod webhook;

pub use config::{
    Credentials, DEFAULT_ACTIONS_BASE, DEFAULT_CHECKOUT_ACTION, DEFAULT_RUNS_ON, DEFAULT_TEAM,
    ForgejoConfig, MergeFallback, TokenRotation,
};
pub use forge::{
    BOT_TOKEN_SCOPES, ForgejoForge, MintedToken, RefreshReport, TOKEN_NAME_PREFIX, TokenRef,
};
pub use secret::Secret;
pub use version::{Features, Flavor, InstanceInfo};
