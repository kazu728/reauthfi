use std::process::ExitCode;

use clap::Parser;
use colored::Colorize;
use reauthfi_core::{run, ExecutionStatus, Options};

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

fn main() -> ExitCode {
    let args = CliArgs::parse();
    let options = Options {
        verbose: args.verbose,
        no_open: args.no_open,
        gateway: args.gateway,
        timeout: args.timeout,
    };

    match run(&options) {
        Ok(ExecutionStatus::Completed) | Ok(ExecutionStatus::NetworkNotReady) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("{} {}", "❌".red().bold(), err);
            ExitCode::FAILURE
        }
    }
}
