//! A credential that is unprintable by type (security model §5, ADR-0008).
//!
//! [`Secret`] has no `Display`, a `Debug` that prints only `Secret(<redacted>)`,
//! and zeroes its buffer on drop. The bytes come out through exactly one
//! accessor, [`Secret::expose`], whose single caller is the gateway header
//! injection in [`crate::gateway`].

use std::fmt;

use zeroize::Zeroizing;

/// A credential value: a byte string that never appears in logs, errors or
/// `Debug` output, and is wiped from memory when dropped.
///
/// There is deliberately no `Display`, so a secret cannot end up in a
/// formatted message by accident:
///
/// ```compile_fail
/// let s = ward_proxy::Secret::from("sk-live");
/// println!("{s}");
/// ```
///
/// ```compile_fail
/// let s = ward_proxy::Secret::from("sk-live");
/// let _ = s.to_string();
/// ```
#[derive(Clone)]
pub struct Secret(Zeroizing<Vec<u8>>);

impl Secret {
    /// Wrap `bytes`. The buffer is moved, not copied.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(Zeroizing::new(bytes.into()))
    }

    /// The raw bytes. The only caller is the gateway injection site; do not
    /// add others.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// `true` for an empty credential.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl From<String> for Secret {
    fn from(s: String) -> Self {
        Self::new(s.into_bytes())
    }
}

impl From<&str> for Secret {
    fn from(s: &str) -> Self {
        Self::new(s.as_bytes())
    }
}

impl From<Vec<u8>> for Secret {
    fn from(v: Vec<u8>) -> Self {
        Self::new(v)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_is_redacted_and_expose_is_verbatim() {
        let s = Secret::from("sk-ant-very-secret");
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert!(!format!("{s:#?}").contains("sk-ant"));
        assert_eq!(s.expose(), b"sk-ant-very-secret");
        assert_eq!(s.len(), 18);
        assert!(!s.is_empty());
        assert!(Secret::new(Vec::new()).is_empty());
        assert_eq!(s.clone().expose(), s.expose());
    }
}
