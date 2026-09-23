//! Secret-bearing strings: zeroized on drop, never printed.

use std::fmt;

use zeroize::Zeroizing;

/// A secret string — a token, a key, a webhook secret.
///
/// Wiped from memory when dropped, and its `Debug` is a fixed placeholder so
/// a stray `{:?}` or `tracing::debug!(?x)` cannot write it to a log. There is
/// deliberately no `Display`, `Serialize` or `Clone`: getting the value out
/// takes an explicit [`Secret::expose`], which is easy to grep for.
pub struct Secret(Zeroizing<String>);

impl Secret {
    /// Wrap a secret.
    pub fn new(value: impl Into<String>) -> Self {
        Secret(Zeroizing::new(value.into()))
    }

    /// The secret value. Keep the borrow short.
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<String> for Secret {
    fn from(value: String) -> Self {
        Secret::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_never_shows_the_value() {
        let s = Secret::new("ghs_supersecret");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(s.expose(), "ghs_supersecret");
    }
}
