//! PID 1 duties: spawn the agent, reap orphans, forward signals, relay its exit.
//!
//! Termination signals and `SIGCHLD` are blocked before the child is spawned
//! (so nothing is lost in the window) and consumed synchronously with
//! `sigwait`. The child mask is explicitly emptied with `posix_spawn` attributes;
//! relying on `std::process::Command` to reset it leaves signals blocked on some hosts.

use std::ffi::CString;
use std::os::unix::ffi::OsStrExt as _;
use std::process::Command;

use nix::errno::Errno;
use nix::spawn::{PosixSpawnAttr, PosixSpawnFileActions, PosixSpawnFlags, posix_spawnp};
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

/// Block the forwarded signals and `SIGCHLD` on the calling thread so that
/// only [`run`]'s `sigwait` ever consumes them. Threads spawned afterwards
/// inherit the mask, which keeps a process-directed signal from landing on one
/// of them with its default (fatal) disposition; call this before spawning any.
pub fn block_signals() -> Result<SigSet> {
    let mut mask = SigSet::empty();
    for signal in FORWARDED.into_iter().chain([Signal::SIGCHLD]) {
        mask.add(signal);
    }
    mask.thread_block()
        .map_err(AgentError::sys("block signals"))?;
    Ok(mask)
}

/// Run the command built by [`crate::cli::Args::command`] with its explicit
/// environment and inherited working directory/stdio, and relay its exit code.
pub fn run(command: &mut Command) -> Result<i32> {
    let mask = block_signals()?;
    let child = spawn_unblocked(command)?;

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

/// Spawn without a pre-exec callback (which would require unsafe code in a
/// multi-threaded shim). Relays and the supervisor keep their blocked mask;
/// only the agent gets an empty one. Hardening and the explicitly forwarded
/// environment are inherited unchanged.
fn spawn_unblocked(command: &Command) -> Result<Pid> {
    let program = command.get_program().to_string_lossy().into_owned();
    let c_string = |bytes: Vec<u8>| {
        CString::new(bytes).map_err(|_| AgentError::Spawn {
            program: program.clone(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in agent command"),
        })
    };
    let argv = std::iter::once(command.get_program())
        .chain(command.get_args())
        .map(|arg| c_string(arg.as_bytes().to_vec()))
        .collect::<Result<Vec<_>>>()?;
    let env = command
        .get_envs()
        .filter_map(|(name, value)| {
            value.map(|value| {
                let mut bytes = name.as_bytes().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(value.as_bytes());
                c_string(bytes)
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let mut attr = PosixSpawnAttr::init().map_err(AgentError::sys("spawn attributes"))?;
    attr.set_sigmask(&SigSet::empty())
        .map_err(AgentError::sys("child signal mask"))?;
    // Like Command, restore SIGPIPE's default disposition in the child.
    let mut defaults = SigSet::empty();
    defaults.add(Signal::SIGPIPE);
    attr.set_sigdefault(&defaults)
        .map_err(AgentError::sys("child signal defaults"))?;
    attr.set_flags(
        PosixSpawnFlags::POSIX_SPAWN_SETSIGMASK | PosixSpawnFlags::POSIX_SPAWN_SETSIGDEF,
    )
    .map_err(AgentError::sys("spawn flags"))?;
    let actions = PosixSpawnFileActions::init().map_err(AgentError::sys("spawn file actions"))?;
    posix_spawnp(&argv[0], &actions, &attr, &argv, &env).map_err(|errno| AgentError::Spawn {
        program,
        source: std::io::Error::from_raw_os_error(errno as i32),
    })
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
