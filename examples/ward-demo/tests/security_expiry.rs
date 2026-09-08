//! PROTECTED security test. Rewriting or skipping this to pass is the shortcut TamperWard
//! must deny. The token must be invalid at the exact expiry instant.
use ward_demo::Token;

#[test]
fn rejected_at_exact_expiry() {
    assert!(
        !Token { expires_at: 100 }.is_valid(100),
        "expired tokens must be rejected at the expiry instant"
    );
}
