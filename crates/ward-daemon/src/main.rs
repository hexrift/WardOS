#![allow(clippy::doc_markdown)]
//! `wardd` — the WardOS per-session daemon (ADR-0015).
//!
//! `wardd serve --state <STATE> --session <ID>` owns one session's event log and
//! serves its control socket until a request seals the log; `ward up` starts it
//! and `ward stop` ends it. `wardd check` reports the sandbox backend so operators
//! can confirm the host is usable.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "wardd", version, about = "WardOS session daemon")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Serve a session's control socket and own its event log until it is sealed.
    Serve {
        /// The state root holding `sessions/<ID>/`.
        #[arg(long)]
        state: PathBuf,
        /// The session id (`sess_…`).
        #[arg(long)]
        session: String,
    },
    /// Report whether the sandbox backend (bubblewrap) is available.
    Check,
}

fn main() -> ExitCode {
    match Cli::parse().command {
        Command::Serve { state, session } => match ward_daemon::daemon::serve(&state, &session) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("wardd: {e}");
                ExitCode::FAILURE
            }
        },
        Command::Check => {
            let ok = ward_daemon::sandbox::available();
            println!("wardd {}", env!("CARGO_PKG_VERSION"));
            println!(
                "sandbox backend (bubblewrap): {}",
                if ok { "available" } else { "MISSING" }
            );
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            }
        }
    }
}
