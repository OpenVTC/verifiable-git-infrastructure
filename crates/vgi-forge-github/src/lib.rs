//! GitHub adapter for VGI git namespaces.
//!
//! Implements [`vgi_forge::Forge`] for github.com and GitHub Enterprise
//! Server, acting as **one community's own GitHub App** (§5.7 of the design:
//! no shared operator, one App and one bridge per community).
//!
//! - **Auth.** The App key signs a nine-minute RS256 JWT
//!   ([`jwt::app_jwt`]) through an [`AppKeySigner`] — in-process
//!   ([`InProcessKey`]) or an enclave. Every operation then mints its own
//!   installation token, scoped to the one repository and the permissions
//!   that operation needs, and drops it on return. Nothing long-lived is
//!   cached.
//! - **Registration.** [`manifest`] builds the App manifest with the fixed,
//!   reviewed permission set and exchanges GitHub's code for the App's
//!   credentials ([`manifest::AppCredentials`], zeroized, never printed).
//! - **Binding.** [`vgi_forge::Forge::begin_bind`] sends the admin to the
//!   App's install page with a `state` nonce; `complete_bind` checks it in
//!   constant time and confirms the installation is this App's, on the
//!   expected owner.
//! - **Accounts.** Members link through the OAuth device flow; the bridge
//!   keeps the numeric id and login and discards the user token.
//! - **Repos.** Create (organisations only — a personal account reports
//!   `bot_can_create_repos: false`, §8), inspect, archive, converge roles,
//!   and the §5.3 bootstrap with a ruleset that has no bypass actors. So that
//!   a pull request cannot satisfy its own check (§9), an organisation with
//!   org rulesets runs verify-trust as a **required workflow** from the
//!   bridge-managed `<org>/.vgi` at a pinned commit; elsewhere the workflow
//!   is committed to the repository and, with two or more owners, guarded
//!   by `CODEOWNERS` plus code-owner review; a solo repository gets the
//!   check alone ([`plan::CheckGuard`]).
//! - **Webhooks.** `X-Hub-Signature-256` verified in constant time before
//!   parsing; repository, member, membership, ruleset and installation
//!   events become [`vgi_forge::ForgeEvent`]s.
//!
//! The HTTP layer is a thin reqwest client ([`api`]) rather than octocrab:
//! see the crate README for why.

mod api;
mod config;
mod forge;
pub mod jwt;
pub mod manifest;
pub mod plan;
mod secret;
pub mod webhook;

pub use api::API_VERSION;
pub use config::{DEFAULT_CHECKOUT_ACTION, GitHubConfig, JwtIssuer};
pub use forge::{GitHubForge, RequiredWorkflowPin};
pub use jwt::{AppKeySigner, InProcessKey};
pub use secret::Secret;
