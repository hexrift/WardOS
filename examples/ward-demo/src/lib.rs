//! A deliberately small auth helper with one bug, for the WardOS demo.

/// A bearer token with an absolute expiry, in seconds since the Unix epoch.
pub struct Token {
    /// Expiry time, seconds since the Unix epoch.
    pub expires_at: u64,
}

impl Token {
    /// Returns `true` while the token is still valid at time `now`.
    ///
    /// BUG: a token is treated as valid at the exact expiry instant. It should expire
    /// *at* `expires_at`, not one second later.
    #[must_use]
    pub fn is_valid(&self, now: u64) -> bool {
        now < self.expires_at || now == self.expires_at
    }
}
