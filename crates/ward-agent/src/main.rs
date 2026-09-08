//! `ward-agent` binary: parse flags, harden, run the agent, relay its exit code.
//! `ward-agent hook` instead runs the Claude Code hook client ([`ward_agent::hook`]).

use std::process::ExitCode;

use clap::Parser;
use ward_agent::cli::{self, Args, SHIM_FAILURE};

fn main() -> ExitCode {
    if std::env::args_os().nth(1).is_some_and(|arg| arg == "hook") {
        ward_agent::hook::run(std::io::stdin().lock(), std::io::stdout().lock());
        return ExitCode::SUCCESS;
    }
    match cli::run(&Args::parse()) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX)),
        Err(error) => {
            eprintln!("ward-agent: {error}");
            ExitCode::from(SHIM_FAILURE)
        }
    }
}
