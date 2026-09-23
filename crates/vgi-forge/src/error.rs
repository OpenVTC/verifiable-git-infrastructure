//! The one error type every adapter returns.
//!
//! Variants describe what the *core* has to decide — retry, give up, ask a
//! human, re-bind — rather than which HTTP status a forge happened to use, so
//! the projector can act on a Forgejo failure and a GitHub failure the same
//! way. Adapters keep the forge's own message in the payload for the audit log.

use std::fmt;

use vgi_core::ResourceError;

/// Shorthand for adapter results.
pub type Result<T, E = ForgeError> = std::result::Result<T, E>;

/// A failed forge operation.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ForgeError {
    /// The input is not a valid forge-qualified resource.
    InvalidResource(ResourceError),
    /// The resource is valid but not on this adapter's forge, or not the
    /// shape the operation needs (a namespace where a repo was expected).
    WrongResource {
        /// What was given.
        resource: String,
        /// What the operation expected, in words.
        expected: String,
    },
    /// No namespace binding covers this resource, so the adapter holds no
    /// credential for it.
    NotBound {
        /// The namespace (`host/owner`) that has no binding.
        namespace: String,
    },
    /// The forge (or this namespace on it) cannot do this — see
    /// [`crate::Capabilities`]. `hint` says what a human can do instead.
    Unsupported {
        /// The operation that was refused.
        operation: String,
        /// Why, and what to do instead.
        hint: String,
    },
    /// The resource does not exist, or the credential cannot see it (forges
    /// deliberately do not distinguish the two).
    NotFound {
        /// What was looked up.
        what: String,
    },
    /// Refused to create something that already exists. Carries the forge id
    /// so the core can tell its own earlier attempt from a squatter.
    AlreadyExists {
        /// The resource that exists.
        resource: String,
        /// The forge's numeric id for it, when known.
        forge_id: Option<u64>,
    },
    /// The forge answered with a redirect the adapter will not follow — a
    /// renamed or transferred repository, usually.
    Moved {
        /// What was requested.
        what: String,
        /// Where the forge pointed.
        location: String,
    },
    /// The forge rejected the adapter's credentials (expired, revoked, wrong
    /// key). Re-binding or rotating the key is the fix, not a retry.
    Unauthorized(String),
    /// Authenticated, but not permitted — usually a permission the owner has
    /// not approved on the installation.
    Forbidden(String),
    /// The forge refused the request as invalid or conflicting (a rule
    /// violation, a validation failure).
    Rejected {
        /// The forge's status code.
        status: u16,
        /// The forge's message.
        message: String,
    },
    /// Rate-limited. Retry after the given number of seconds, if the forge
    /// said.
    RateLimited {
        /// Seconds to wait, when the forge said.
        retry_after_secs: Option<u64>,
    },
    /// The forge could not be reached or failed (network, 5xx, timeout).
    Unavailable(String),
    /// A namespace bind callback did not match the bind that was started —
    /// wrong or stale `state`, or an installation on the wrong owner.
    BindRejected(String),
    /// Linking a member's forge account did not complete (expired, denied).
    LinkFailed(String),
    /// A webhook failed verification or could not be parsed. Always treat as
    /// hostile input: do not act on it.
    Webhook(String),
    /// The adapter or the bootstrap config is incomplete or invalid.
    Config(String),
    /// The forge answered with something the adapter does not understand.
    Protocol(String),
}

impl ForgeError {
    /// Whether retrying the same operation later can succeed without anyone
    /// changing anything. Rejections, auth failures and bad input are not.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ForgeError::RateLimited { .. } | ForgeError::Unavailable(_)
        )
    }
}

impl fmt::Display for ForgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ForgeError::InvalidResource(e) => write!(f, "{e}"),
            ForgeError::WrongResource { resource, expected } => {
                write!(f, "resource `{resource}`: expected {expected}")
            }
            ForgeError::NotBound { namespace } => write!(
                f,
                "namespace `{namespace}` is not bound to this bridge; bind it before managing \
                 its repositories"
            ),
            ForgeError::Unsupported { operation, hint } => {
                write!(f, "{operation} is not supported here: {hint}")
            }
            ForgeError::NotFound { what } => write!(f, "{what}: not found (or not visible)"),
            ForgeError::AlreadyExists { resource, forge_id } => match forge_id {
                Some(id) => write!(f, "`{resource}` already exists (forge id {id})"),
                None => write!(f, "`{resource}` already exists"),
            },
            ForgeError::Moved { what, location } => {
                write!(
                    f,
                    "{what} has moved to {location} (renamed or transferred?)"
                )
            }
            ForgeError::Unauthorized(m) => write!(f, "forge rejected the credentials: {m}"),
            ForgeError::Forbidden(m) => write!(f, "forge refused the operation: {m}"),
            ForgeError::Rejected { status, message } => {
                write!(f, "forge rejected the request ({status}): {message}")
            }
            ForgeError::RateLimited { retry_after_secs } => match retry_after_secs {
                Some(s) => write!(f, "rate-limited by the forge; retry in {s}s"),
                None => write!(f, "rate-limited by the forge"),
            },
            ForgeError::Unavailable(m) => write!(f, "forge unavailable: {m}"),
            ForgeError::BindRejected(m) => write!(f, "namespace bind rejected: {m}"),
            ForgeError::LinkFailed(m) => write!(f, "account link failed: {m}"),
            ForgeError::Webhook(m) => write!(f, "webhook rejected: {m}"),
            ForgeError::Config(m) => write!(f, "configuration error: {m}"),
            ForgeError::Protocol(m) => write!(f, "unexpected forge response: {m}"),
        }
    }
}

impl std::error::Error for ForgeError {}

impl From<ResourceError> for ForgeError {
    fn from(e: ResourceError) -> Self {
        ForgeError::InvalidResource(e)
    }
}
