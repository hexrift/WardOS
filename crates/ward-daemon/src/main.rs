#![allow(clippy::doc_markdown)]
//! `wardd` — the WardOS supervisor service.
//!
//! Phase 1 drives sessions in-process through the `ward` CLI, so this binary is a
//! placeholder for the Phase 2 control-socket daemon (ADR-0009). It reports the
//! sandbox backend so operators can confirm the host is usable.
fn main() {
    let ok = ward_daemon::sandbox::available();
    println!("wardd 0.1.0 (phase 1)");
    println!(
        "sandbox backend (bubblewrap): {}",
        if ok { "available" } else { "MISSING" }
    );
}
