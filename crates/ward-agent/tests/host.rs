//! Runs the built `ward-agent` binary on the host (no container needed) and
//! checks that Landlock confines writes, that the seccomp/PID 1 path relays
//! exit codes, that termination signals reach the agent, and that `--relay`
//! forwards loopback TCP into a Unix socket without outliving the agent.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::ffi::OsStr;
use std::io::{IoSliceMut, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use nix::errno::Errno;
use nix::sys::signal::{Signal, kill};
use nix::sys::uio::{RemoteIoVec, process_vm_readv};
use nix::unistd::Pid;

const BIN: &str = env!("CARGO_BIN_EXE_ward-agent");

/// The shim with `rw` as its only writable tree and no Landlock opt-out.
fn bare(rw: &Path) -> Command {
    let mut command = Command::new(BIN);
    command
        .env("WARD_AGENT_QUIET", "1")
        .arg("--rw")
        .arg(rw)
        .stdin(Stdio::null())
        .stderr(Stdio::piped());
    command
}

/// The shim as the tests that do not depend on Landlock run it: opted out of
/// the Landlock requirement only where the kernel cannot provide it.
fn shim(rw: &Path) -> Command {
    let mut command = bare(rw);
    if !landlock_available() {
        command.arg("--allow-no-landlock");
    }
    command
}

fn landlock_available() -> bool {
    if ward_agent::landlock::is_available() {
        return true;
    }
    eprintln!("landlock unavailable on this kernel");
    false
}

#[test]
fn writes_outside_rw_fail_with_eacces_and_inside_succeed() {
    if !landlock_available() {
        eprintln!("skipping: needs landlock");
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    let other = tempfile::tempdir().unwrap();

    let denied = shim(rw.path())
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}/x", other.path().display()))
        .output()
        .unwrap();
    let stderr = String::from_utf8_lossy(&denied.stderr);
    assert!(
        !denied.status.success(),
        "touch outside rw succeeded: {stderr}"
    );
    assert!(
        stderr.contains("Permission denied"),
        "expected EACCES, got: {stderr}"
    );
    assert!(!other.path().join("x").exists());

    let allowed = shim(rw.path())
        .args(["--", "sh", "-c"])
        .arg(format!("touch {}/y", rw.path().display()))
        .output()
        .unwrap();
    assert!(
        allowed.status.success(),
        "touch inside rw failed: {}",
        String::from_utf8_lossy(&allowed.stderr)
    );
    assert!(rw.path().join("y").exists());
}

#[test]
fn refuses_to_exec_without_landlock_unless_allowed() {
    // Only observable on kernels without Landlock; elsewhere the flag is a no-op.
    if landlock_available() {
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    let refused = bare(rw.path()).args(["--", "true"]).output().unwrap();
    assert_eq!(refused.status.code(), Some(125));
    assert!(String::from_utf8_lossy(&refused.stderr).contains("landlock is unavailable"));
    let allowed = bare(rw.path())
        .args(["--allow-no-landlock", "--", "true"])
        .output()
        .unwrap();
    assert!(allowed.status.success());
}

#[test]
fn relays_the_agent_exit_code() {
    let rw = tempfile::tempdir().unwrap();
    let out = shim(rw.path())
        .args(["--", "sh", "-c", "exit 7"])
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Re-exec hook: when `WARD_AGENT_PROBE=vm_readv` is set, this test binary
/// issues `process_vm_readv` against its own memory — a syscall the baseline
/// profile denies with EPERM but which an unprivileged process can otherwise
/// make (self-access always passes the ptrace access check) — and exits with
/// the errno (0 on success).
///
/// `ptrace(PTRACE_TRACEME)` is deliberately not used: libtest runs each test on
/// a spawned thread, and a traced non-leader thread can only be reaped by its
/// tracer with `__WALL`, which the parent's `Command::output` never does, so the
/// unsandboxed control run would deadlock as a zombie.
#[test]
fn probe_vm_readv() {
    if std::env::var_os(PROBE_ENV).as_deref() != Some(OsStr::new("vm_readv")) {
        return;
    }
    let source = *b"ward-agent";
    let mut sink = [0u8; 10];
    let remote = [RemoteIoVec {
        base: source.as_ptr() as usize,
        len: source.len(),
    }];
    let result = process_vm_readv(
        nix::unistd::getpid(),
        &mut [IoSliceMut::new(&mut sink)],
        &remote,
    );
    println!("process_vm_readv={result:?} copied={}", sink == source);
    std::process::exit(match result {
        Ok(n) if n == source.len() && sink == source => 0,
        Ok(_) => 255,
        Err(e) => e as i32,
    });
}

const PROBE_ENV: &str = "WARD_AGENT_PROBE";

/// Run [`probe_vm_readv`] in a fresh copy of this test binary, optionally under the shim.
fn run_probe(under_shim: bool) -> std::process::Output {
    let exe = std::env::current_exe().unwrap();
    let rw = tempfile::tempdir().unwrap();
    let mut command = if under_shim {
        let mut command = shim(rw.path());
        // `--ro` replaces the defaults, so restate them plus the test binary's directory.
        for dir in ward_agent::landlock::DEFAULT_RO {
            command.arg("--ro").arg(dir);
        }
        command.arg("--ro").arg(exe.parent().unwrap());
        command.args(["--env", PROBE_ENV, "--"]);
        command
    } else {
        Command::new("env")
    };
    command
        .arg(&exe)
        .args(["probe_vm_readv", "--exact", "--nocapture"])
        .env(PROBE_ENV, "vm_readv")
        .output()
        .unwrap()
}

#[test]
fn denied_syscalls_fail_with_eperm() {
    // Without the shim the probe succeeds, so EPERM below can only come from seccomp.
    let plain = run_probe(false);
    assert_eq!(
        plain.status.code(),
        Some(0),
        "process_vm_readv should succeed unsandboxed: {}",
        String::from_utf8_lossy(&plain.stdout)
    );

    let filtered = run_probe(true);
    let stdout = String::from_utf8_lossy(&filtered.stdout);
    assert_eq!(
        filtered.status.code(),
        Some(Errno::EPERM as i32),
        "expected EPERM from process_vm_readv under the shim: {stdout} {}",
        String::from_utf8_lossy(&filtered.stderr)
    );
    assert!(stdout.contains("EPERM"), "{stdout}");
}

#[test]
fn mount_fails_with_eperm_as_root() {
    if !nix::unistd::geteuid().is_root() {
        eprintln!("skipping: mount(8) refuses to issue the syscall unless root");
        return;
    }
    let rw = tempfile::tempdir().unwrap();
    let out = shim(rw.path())
        .args([
            "--",
            "sh",
            "-c",
            "mount -t tmpfs none /mnt 2>&1; echo rc=$?",
        ])
        .stderr(Stdio::inherit())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("ermission denied") || stdout.contains("not permitted"),
        "expected EPERM from mount, got: {stdout}"
    );
}

#[test]
fn forwards_sigterm_to_the_agent() {
    let rw = tempfile::tempdir().unwrap();
    let mut child = shim(rw.path())
        .args([
            "--",
            "sh",
            "-c",
            "trap 'exit 42' TERM; while :; do sleep 0.05; done",
        ])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(42));
}

/// Echo one stream's bytes back to it until EOF, reporting what was received.
fn echo(mut stream: impl Read + Write, seen: &mpsc::Sender<Vec<u8>>) {
    let mut buf = [0u8; 1024];
    while let Ok(n) = stream.read(&mut buf) {
        if n == 0 || stream.write_all(&buf[..n]).is_err() {
            break;
        }
        let _ = seen.send(buf[..n].to_vec());
    }
}

/// A port that was free a moment ago; the shim binds it before the agent runs.
fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

/// A shell one-liner that sends `ping` to `port` and prints the reply line,
/// in the first runtime that works unsandboxed (bash's `/dev/tcp`, then
/// python3). `None` when the host offers neither.
fn tcp_client(port: u16) -> Option<[String; 3]> {
    let candidates = [
        [
            "bash".to_string(),
            "-c".to_string(),
            format!("exec 3<>/dev/tcp/127.0.0.1/{port}; echo ping >&3; read -r r <&3; echo \"$r\""),
        ],
        [
            "python3".to_string(),
            "-c".to_string(),
            format!(
                "import socket; s = socket.create_connection(('127.0.0.1', {port})); \
                 s.sendall(b'ping\\n'); print(s.makefile().readline().strip())"
            ),
        ],
    ];
    // Prove the candidate against a plain TCP echo before trusting it to test the relay.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let probe_port = listener.local_addr().unwrap().port();
    let (seen, _) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            echo(stream, &seen);
        }
    });
    candidates.into_iter().find(|[prog, flag, script]| {
        let script = script.replace(&port.to_string(), &probe_port.to_string());
        Command::new(prog)
            .args([flag, &script])
            .output()
            .is_ok_and(|out| out.status.success() && out.stdout.trim_ascii() == b"ping")
    })
}

/// `output()` with a deadline, so a shim that outlives its agent fails the
/// test instead of hanging it.
fn output_within(mut command: Command, timeout: Duration) -> Output {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || tx.send(command.output()));
    rx.recv_timeout(timeout)
        .expect("shim did not exit in time")
        .unwrap()
}

#[test]
fn relays_loopback_tcp_into_the_unix_socket() {
    let listen = free_port();
    let Some(client) = tcp_client(listen.port()) else {
        eprintln!("skipping: neither bash /dev/tcp nor python3 can open a TCP connection here");
        return;
    };
    let rw = tempfile::tempdir().unwrap();
    let socket = rw.path().join("proxy.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (seen, received) = mpsc::channel();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            echo(stream, &seen);
        }
    });

    let mut command = shim(rw.path());
    command
        .arg("--relay")
        .arg(format!("{listen}={}", socket.display()))
        .arg("--")
        .args(&client)
        .stdout(Stdio::piped());
    let out = output_within(command, Duration::from_secs(20));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{stderr}");
    assert_eq!(
        String::from_utf8_lossy(&out.stdout).trim(),
        "ping",
        "{stderr}"
    );
    assert_eq!(
        received.recv_timeout(Duration::from_secs(1)).unwrap(),
        b"ping\n",
        "the bytes did not pass through the Unix socket"
    );
}

#[test]
fn relay_threads_do_not_outlive_the_agent() {
    let rw = tempfile::tempdir().unwrap();
    let mut command = shim(rw.path());
    command
        .arg("--relay")
        .arg(format!(
            "{}={}",
            free_port(),
            rw.path().join("never.sock").display()
        ))
        .args(["--", "sh", "-c", "exit 7"]);
    let out = output_within(command, Duration::from_secs(20));
    assert_eq!(
        out.status.code(),
        Some(7),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

/// Relay threads inherit the supervisor's signal mask; without that a
/// process-directed SIGTERM could be delivered to one of them and kill the
/// shim outright instead of being forwarded.
#[test]
fn forwards_sigterm_to_the_agent_with_a_relay_running() {
    let rw = tempfile::tempdir().unwrap();
    let mut child = shim(rw.path())
        .arg("--relay")
        .arg(format!(
            "{}={}",
            free_port(),
            rw.path().join("never.sock").display()
        ))
        .args([
            "--",
            "sh",
            "-c",
            "trap 'exit 42' TERM; while :; do sleep 0.05; done",
        ])
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    kill(
        Pid::from_raw(i32::try_from(child.id()).unwrap()),
        Signal::SIGTERM,
    )
    .unwrap();
    let status = child.wait().unwrap();
    assert_eq!(status.code(), Some(42));
}

#[test]
fn relay_bind_failure_is_a_shim_failure() {
    let rw = tempfile::tempdir().unwrap();
    // Hold the port so the shim cannot bind it.
    let taken = TcpListener::bind("127.0.0.1:0").unwrap();
    let mut command = shim(rw.path());
    command
        .arg("--relay")
        .arg(format!(
            "{}={}",
            taken.local_addr().unwrap(),
            rw.path().join("never.sock").display()
        ))
        .args(["--", "true"]);
    let out = output_within(command, Duration::from_secs(20));
    assert_eq!(out.status.code(), Some(125));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("relay") && stderr.contains("bind"),
        "{stderr}"
    );
}
