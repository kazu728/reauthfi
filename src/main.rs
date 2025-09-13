use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use std::process::Command;
use std::result::Result;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use colored::*;
use regex::Regex;
use reqwest::blocking::Client;

#[derive(Debug)]
enum ReauthfiError {
    Network(reqwest::Error),
    Io(std::io::Error),
    NotFound,
}

#[derive(Debug)]
enum DetectionResult {
    PortalFound(String),
    NoPortalDetected,
    AllTimeout,
    NetworkError,
}

impl fmt::Display for ReauthfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReauthfiError::Network(e) => write!(f, "Network error: {}", e),
            ReauthfiError::Io(e) => write!(f, "IO error: {}", e),
            ReauthfiError::NotFound => write!(f, "Captive portal not found"),
        }
    }
}

impl Error for ReauthfiError {}

impl From<reqwest::Error> for ReauthfiError {
    fn from(err: reqwest::Error) -> Self {
        ReauthfiError::Network(err)
    }
}

impl From<std::io::Error> for ReauthfiError {
    fn from(err: std::io::Error) -> Self {
        ReauthfiError::Io(err)
    }
}

#[derive(Debug, Clone)]
enum Platform {
    MacOS,
}

impl Platform {
    fn detect() -> Self {
        #[cfg(target_os = "macos")]
        return Platform::MacOS;

        #[cfg(not(target_os = "macos"))]
        return Platform::MacOS; // macOS only
    }

    fn detection_endpoints(&self) -> &'static [DetectionEndpoint] {
        match self {
            Platform::MacOS => MACOS_DETECTION_ENDPOINTS,
        }
    }
}

#[derive(Debug, Clone)]
struct DetectionEndpoint {
    name: &'static str,
    url: &'static str,
    expected_status: Option<u16>,
}

const MACOS_DETECTION_ENDPOINTS: &[DetectionEndpoint] = &[
    DetectionEndpoint {
        name: "Apple",
        url: "http://captive.apple.com/hotspot-detect.html",
        expected_status: None,
    },
    DetectionEndpoint {
        name: "Google",
        url: "http://connectivitycheck.gstatic.com/generate_204",
        expected_status: Some(204),
    },
];

#[derive(Debug)]
struct PlatformConfig {
    gateway_command: &'static [&'static str],
    gateway_regex: &'static str,
    gateway_endpoints: &'static [&'static str],
}

const MACOS_GATEWAY_COMMAND: &[&str] = &["route", "-n", "get", "default"];
const MACOS_GATEWAY_REGEX: &str = r"gateway:\s+(\d+\.\d+\.\d+\.\d+)";
const MACOS_GATEWAY_ENDPOINTS: &[&str] = &["/"];

impl PlatformConfig {
    fn for_platform(_platform: &Platform) -> Self {
        PlatformConfig {
            gateway_command: MACOS_GATEWAY_COMMAND,
            gateway_regex: MACOS_GATEWAY_REGEX,
            gateway_endpoints: MACOS_GATEWAY_ENDPOINTS,
        }
    }
}

trait DetectionStrategy {
    fn detect(&self, platform: &Platform, config: &PlatformConfig, args: &Args) -> DetectionResult;
}

#[derive(Copy, Clone)]
enum StrategyKind {
    Gateway,
    StandardUrl,
}

const GATEWAY_PRIORITY: [StrategyKind; 2] = [StrategyKind::Gateway, StrategyKind::StandardUrl];
const STANDARD_PRIORITY: [StrategyKind; 2] = [StrategyKind::StandardUrl, StrategyKind::Gateway];

struct StandardUrlDetection;

impl DetectionStrategy for StandardUrlDetection {
    fn detect(
        &self,
        platform: &Platform,
        _config: &PlatformConfig,
        args: &Args,
    ) -> DetectionResult {
        let client = match build_client(args.timeout) {
            Ok(client) => client,
            Err(_) => return DetectionResult::NetworkError,
        };

        let endpoints = platform.detection_endpoints();
        let mut saw_any_error = false;

        for endpoint in endpoints {
            if args.verbose {
                println!(
                    "  {} Checking {} ({})",
                    "•".yellow(),
                    endpoint.name,
                    endpoint.url
                );
            }

            match check_with_progress(endpoint.url, &client, args.timeout) {
                Ok(response) => {
                    let status = response.status();

                    if let Some(expected) = endpoint.expected_status {
                        if status.as_u16() == expected {
                            if args.verbose {
                                println!("    {} Expected {} status", "✓".green(), expected);
                            }
                            continue; // move to next endpoint
                        }
                    }

                    if let Some(portal_url) = redirect_location_url(&response) {
                        if args.verbose {
                            println!("    {} {} Redirect", "✓".green(), status.as_u16());
                        }
                        return DetectionResult::PortalFound(portal_url);
                    }
                }
                Err(e) => {
                    saw_any_error = true;
                    if args.verbose {
                        if e.is_timeout() {
                            println!("    {} Timeout ({}s)", "⏱".yellow(), args.timeout);
                        } else if e.is_connect() {
                            println!("    {} Connection failed", "✗".red());
                        } else {
                            println!("    {} Failed: {}", "✗".red(), e);
                        }
                    }
                }
            }
        }

        // Determine result based on what happened
        if saw_any_error {
            DetectionResult::NetworkError
        } else {
            DetectionResult::NoPortalDetected
        }
    }
}

struct GatewayDetection;

impl DetectionStrategy for GatewayDetection {
    fn detect(
        &self,
        _platform: &Platform,
        config: &PlatformConfig,
        args: &Args,
    ) -> DetectionResult {
        let gateway_ip = match get_gateway_ip(config) {
            Ok(ip) => ip,
            Err(_) => return DetectionResult::NetworkError,
        };

        if args.verbose {
            println!("  {} Gateway IP: {}", "•".yellow(), gateway_ip);
        }

        let client = match build_client(args.timeout) {
            Ok(client) => client,
            Err(_) => return DetectionResult::NetworkError,
        };

        for endpoint in config.gateway_endpoints {
            let url = format!("http://{}{}", gateway_ip, endpoint);

            if args.verbose {
                println!("    {} Checking {}...", "•".yellow(), url);
            }

            match check_with_progress(&url, &client, args.timeout) {
                Ok(response) => {
                    let status = response.status();

                    if let Some(portal_url) = redirect_location_url(&response) {
                        if args.verbose {
                            println!("      {} {} Redirect", "✓".green(), status.as_u16());
                        }
                        return DetectionResult::PortalFound(portal_url);
                    }

                    if status.is_success() {
                        if let Ok(html) = response.text() {
                            if let Some(meta_url) = extract_meta_refresh(&html) {
                                if args.verbose {
                                    println!("      {} Found meta refresh", "✓".green());
                                }
                                return DetectionResult::PortalFound(meta_url);
                            }
                        }
                    }
                }
                Err(e) => {
                    if args.verbose {
                        if e.is_timeout() {
                            println!("      {} Timeout ({}s)", "⏱".yellow(), args.timeout);
                        } else {
                            println!("      {} Failed", "✗".red());
                        }
                    }
                }
            }
        }

        DetectionResult::NoPortalDetected
    }
}

struct PortalOpenerService;

impl PortalOpenerService {
    fn open(url: &str) -> Result<(), ReauthfiError> {
        #[cfg(target_os = "macos")]
        Command::new("open").arg(url).status()?;

        Ok(())
    }
}

fn build_client(timeout_secs: u64) -> Result<Client, ReauthfiError> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;
    Ok(client)
}

fn print_progress(message: &str, elapsed: u64, total: u64) {
    print!("\r  {} {} [", "•".yellow(), message);

    let progress = (elapsed * 20 / total).min(20);
    for i in 0..20 {
        if i < progress {
            print!("█");
        } else {
            print!("░");
        }
    }

    print!("] {}s/{}s", elapsed, total);
    io::stdout().flush().ok();
}

fn check_with_progress(
    url: &str,
    client: &Client,
    timeout: u64,
) -> Result<reqwest::blocking::Response, reqwest::Error> {
    let start = Instant::now();
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = done.clone();

    let url_clone = url.to_string();
    print_progress(&url_clone, 0, timeout);
    io::stdout().flush().ok();

    let handle = thread::spawn(move || {
        while !done_clone.load(Ordering::Relaxed) {
            let elapsed = start.elapsed().as_secs();
            if elapsed <= timeout {
                print_progress(&url_clone, elapsed, timeout);
            }
            thread::sleep(Duration::from_millis(500));
        }
        println!("");
        io::stdout().flush().ok();
    });

    let result = client.get(url).send();

    done.store(true, Ordering::Relaxed);
    handle.join().ok();

    result
}

fn get_gateway_ip(config: &PlatformConfig) -> Result<String, ReauthfiError> {
    let output = Command::new(config.gateway_command[0])
        .args(&config.gateway_command[1..])
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let re = Regex::new(config.gateway_regex).map_err(|_| ReauthfiError::NotFound)?;

    re.captures(&stdout)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or(ReauthfiError::NotFound)
}

fn extract_meta_refresh(html: &str) -> Option<String> {
    // Case-insensitive match for meta refresh with URL
    let re = Regex::new(r#"(?i)content\s*=\s*["']?\d+\s*;\s*url\s*=\s*([^"'\s>]+)"#).ok()?;
    re.captures(html)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str())
        .and_then(|url| {
            if url.starts_with("http") {
                Some(url.to_string())
            } else {
                None
            }
        })
}

fn redirect_location_url(response: &reqwest::blocking::Response) -> Option<String> {
    if response.status().is_redirection() {
        response
            .headers()
            .get("location")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else {
        None
    }
}

#[derive(Parser)]
#[command(name = "reauthfi")]
#[command(about = "macOS Captive Portal auto-detection and opener")]
#[command(version)]
struct Args {
    #[arg(short, long, help = "Enable verbose output")]
    verbose: bool,

    #[arg(long, help = "Display portal URL without opening")]
    no_open: bool,

    #[arg(long, help = "Prioritize gateway direct check")]
    gateway: bool,

    #[arg(long, default_value_t = 10, help = "Request timeout in seconds")]
    timeout: u64,
}

fn main() {
    let args = Args::parse();
    let platform = Platform::detect();
    let config = PlatformConfig::for_platform(&platform);

    println!("{}", "🔍 Detecting Captive Portal...".cyan().bold());

    let strategies: &[StrategyKind] = if args.gateway {
        &GATEWAY_PRIORITY
    } else {
        &STANDARD_PRIORITY
    };

    for &strategy in strategies {
        let detector: &dyn DetectionStrategy = match strategy {
            StrategyKind::Gateway => &GatewayDetection,
            StrategyKind::StandardUrl => &StandardUrlDetection,
        };

        match detector.detect(&platform, &config, &args) {
            DetectionResult::PortalFound(portal_url) => {
                if args.verbose {
                    println!("  {} Portal URL: {}", "→".green().bold(), portal_url);
                }

                if !args.no_open {
                    println!("{}", "📱 Opening in browser...".cyan().bold());
                    match PortalOpenerService::open(&portal_url) {
                        Ok(_) => println!("{}", "✅ Done!".green().bold()),
                        Err(e) => println!("{} Failed: {}", "❌".red().bold(), e),
                    }
                }
                return;
            }
            DetectionResult::AllTimeout => {
                println!(
                    "{} Network not ready - this may be a first-time Wi-Fi connection",
                    "❌".red().bold()
                );
                println!("  Close any macOS network popup windows and try again");
                println!("  Or wait a few seconds for the network to stabilize");
                return;
            }
            DetectionResult::NetworkError => {
                println!(
                    "{} Network not ready - this may be a first-time Wi-Fi connection",
                    "❌".red().bold()
                );
                println!("  Close any macOS network popup windows and try again");
                println!("  Or wait a few seconds for the network to stabilize");
                return;
            }
            DetectionResult::NoPortalDetected => continue,
        }
    }

    println!("{} No captive portal detected", "✅".green().bold());
}
