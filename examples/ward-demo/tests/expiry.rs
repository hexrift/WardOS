use ward_demo::Token;

#[test]
fn valid_before_expiry() {
    assert!(Token { expires_at: 100 }.is_valid(99));
}

#[test]
fn invalid_after_expiry() {
    assert!(!Token { expires_at: 100 }.is_valid(101));
}
