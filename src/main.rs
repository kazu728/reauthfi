use std::process::ExitCode;

use colored::Colorize;
use reauthfi::{run, ExecutionStatus, Options};

const HELP: &str = "\
reauthfi - macOS Captive Portal auto-detection and opener

Usage:
  reauthfi [--help] [--version]

Options:
  -h, --help     Show this help
  -V, --version  Show version
";

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let first = args.next();
    if args.next().is_some() {
        eprintln!("Too many arguments");
        eprintln!();
        eprintln!("{HELP}");
        return ExitCode::FAILURE;
    }
    if let Some(arg) = first {
        match arg.as_str() {
            "-h" | "--help" => {
                println!("{HELP}");
                return ExitCode::SUCCESS;
            }
            "-V" | "--version" => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                return ExitCode::SUCCESS;
            }
            _ => {
                eprintln!("Unknown argument: {arg}");
                eprintln!();
                eprintln!("{HELP}");
                return ExitCode::FAILURE;
            }
        }
    }
    let options = Options::default();

    match run(&options) {
        Ok(ExecutionStatus::Completed) => ExitCode::SUCCESS,
        Ok(ExecutionStatus::NetworkNotReady) => ExitCode::from(2),
        Err(err) => {
            eprintln!("{} {}", "❌".red().bold(), err);
            ExitCode::FAILURE
        }
    }
}
