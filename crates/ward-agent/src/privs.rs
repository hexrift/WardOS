//! `PR_SET_NO_NEW_PRIVS` and capability dropping.

use caps::CapSet;
use nix::sys::prctl;

use crate::error::{AgentError, Result};

/// Set `PR_SET_NO_NEW_PRIVS` on the calling thread if it is not already set.
pub fn ensure_no_new_privs() -> Result<()> {
    if prctl::get_no_new_privs().map_err(AgentError::sys("PR_GET_NO_NEW_PRIVS"))? {
        return Ok(());
    }
    prctl::set_no_new_privs().map_err(AgentError::sys("PR_SET_NO_NEW_PRIVS"))
}

/// Drop every capability the calling thread still holds.
///
/// The bounding set is cleared first (it needs `CAP_SETPCAP`, which we may be
/// about to lose), then the ambient, effective, permitted and inheritable sets.
/// Returns whether the bounding set could be cleared; when it cannot (no
/// `CAP_SETPCAP`), the caller holds no capabilities and `no_new_privs` prevents
/// acquiring any via exec, so this is reported rather than fatal.
pub fn drop_capabilities() -> Result<bool> {
    let bounding_cleared = caps::clear(None, CapSet::Bounding).is_ok();
    for set in [
        CapSet::Ambient,
        CapSet::Effective,
        CapSet::Permitted,
        CapSet::Inheritable,
    ] {
        let held = caps::read(None, set).map_err(|e| AgentError::Caps(e.to_string()))?;
        if !held.is_empty() {
            caps::clear(None, set).map_err(|e| AgentError::Caps(format!("clear {set:?}: {e}")))?;
        }
    }
    Ok(bounding_cleared)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Both settings are per-thread, so exercising them here only affects the
    // test's own thread.
    #[test]
    fn no_new_privs_is_set_and_idempotent() {
        ensure_no_new_privs().unwrap();
        assert!(prctl::get_no_new_privs().unwrap());
        ensure_no_new_privs().unwrap();
    }

    #[test]
    fn capabilities_are_empty_after_drop() {
        drop_capabilities().unwrap();
        for set in [CapSet::Effective, CapSet::Permitted, CapSet::Inheritable] {
            assert!(
                caps::read(None, set).unwrap().is_empty(),
                "{set:?} not empty"
            );
        }
    }
}
