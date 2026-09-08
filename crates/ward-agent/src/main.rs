//! `ward-agent` binary: parse flags, harden, run the agent, relay its exit code.

use std::process::ExitCode;

use clap::Parser;
use ward_agent::cli::{self, Args, SHIM_FAILURE};

fn main() -> ExitCode {
    match cli::run(&Args::parse()) {
        Ok(code) => ExitCode::from(u8::try_from(code).unwrap_or(u8::MAX)),
        Err(error) => {
            eprintln!("ward-agent: {error}");
            ExitCode::from(SHIM_FAILURE)
        }
    }
}
