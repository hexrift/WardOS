//! PID 1 duties: spawn the agent, reap orphans, forward signals, relay its exit.
//!
//! Termination signals and `SIGCHLD` are blocked before the child is spawned
//! (so nothing is lost in the window) and consumed synchronously with
//! `sigwait`; `std::process::Command` resets the mask in the child.

use std::process::Command;

use nix::errno::Errno;
use nix::sys::signal::{SigSet, Signal, kill};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::Pid;

use crate::error::{AgentError, Result};

/// Signals relayed from PID 1 to the agent.
pub const FORWARDED: [Signal; 3] = [Signal::SIGTERM, Signal::SIGINT, Signal::SIGHUP];

/// Exit code reported for a child killed by `signal`, following the shell convention.
pub fn signal_exit_code(signal: Signal) -> i32 {
    128 + signal as i32
}

/// Run `command` as the supervised child and return the exit code to relay.
pub fn run(command: &mut Command) -> Result<i32> {
    let mut mask = SigSet::empty();
    for signal in FORWARDED.into_iter().chain([Signal::SIGCHLD]) {
        mask.add(signal);
    }
    mask.thread_block()
        .map_err(AgentError::sys("block signals"))?;

    let program = command.get_program().to_string_lossy().into_owned();
    let child = command
        .spawn()
        .map_err(|source| AgentError::Spawn { program, source })?;
    let child = i32::try_from(child.id())
        .map(Pid::from_raw)
        .map_err(|_| AgentError::Spawn {
            program: String::new(),
            source: std::io::Error::other("pid out of range"),
        })?;

    loop {
        match mask.wait().map_err(AgentError::sys("sigwait"))? {
            Signal::SIGCHLD => {
                if let Some(code) = reap(child)? {
                    return Ok(code);
                }
            }
            // ESRCH means the child already exited; SIGCHLD will follow.
            signal => match kill(child, signal) {
                Ok(()) | Err(Errno::ESRCH) => {}
                Err(e) => return Err(AgentError::sys("forward signal")(e)),
            },
        }
    }
}

/// Reap every exited child without blocking; return the main child's exit code
/// once it has been collected.
fn reap(child: Pid) -> Result<Option<i32>> {
    let mut exit = None;
    loop {
        match waitpid(None, Some(WaitPidFlag::WNOHANG)) {
            Ok(WaitStatus::Exited(pid, code)) if pid == child => exit = Some(code),
            Ok(WaitStatus::Signaled(pid, signal, _)) if pid == child => {
                exit = Some(signal_exit_code(signal));
            }
            Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => return Ok(exit),
            Ok(_) => {}
            Err(e) => return Err(AgentError::sys("waitpid")(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signalled_children_map_to_128_plus_signum() {
        assert_eq!(signal_exit_code(Signal::SIGTERM), 143);
        assert_eq!(signal_exit_code(Signal::SIGKILL), 137);
    }
}
