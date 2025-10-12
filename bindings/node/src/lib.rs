use std::iter;

use clap::{CommandFactory, Parser};
use napi::bindgen_prelude::*;
use napi_derive::napi;
use reauthfi_core::{ExecutionStatus, Options};

#[derive(Parser)]
#[command(name = "reauthfi")]
#[command(about = "macOS Captive Portal auto-detection and opener")]
#[command(version)]
struct CliArgs {
    #[arg(short, long, help = "Enable verbose output")]
    verbose: bool,

    #[arg(long, help = "Display portal URL without opening")]
    no_open: bool,

    #[arg(long, help = "Prioritize gateway direct check")]
    gateway: bool,

    #[arg(long, default_value_t = 10, help = "Request timeout in seconds")]
    timeout: u64,
}

#[napi]
pub fn run(args: Vec<String>) -> Result<()> {
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        CliArgs::command()
            .print_help()
            .map_err(|e| Error::from_reason(e.to_string()))?;
        println!();
        return Ok(());
    }

    if args.iter().any(|arg| arg == "--version" || arg == "-V") {
        if let Some(version) = CliArgs::command().get_version() {
            println!("{}", version);
        }
        return Ok(());
    }

    let parsed = CliArgs::try_parse_from(iter::once("reauthfi".to_string()).chain(args))
        .map_err(|err| Error::from_reason(err.to_string()))?;

    let options = Options {
        verbose: parsed.verbose,
        no_open: parsed.no_open,
        gateway: parsed.gateway,
        timeout: parsed.timeout,
    };

    match reauthfi_core::run(&options) {
        Ok(ExecutionStatus::Completed) | Ok(ExecutionStatus::NetworkNotReady) => Ok(()),
        Err(err) => Err(Error::from_reason(err.to_string())),
    }
}
