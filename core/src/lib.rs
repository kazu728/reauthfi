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

use colored::Colorize;
use regex::Regex;
use reqwest::blocking::Client;

#[cfg(not(target_os = "macos"))]
compile_error!("reauthfi currently supports only macOS");

#[derive(Debug)]
pub enum ReauthfiError {
    Network(reqwest::Error),
    Io(std::io::Error),
    NotFound,
    CommandFailed(String),
    #[cfg(not(target_os = "macos"))]
    UnsupportedPlatform,
}

#[derive(Debug)]
pub enum DetectionResult {
    PortalFound(String),
    NoPortalDetected,
    NetworkError,
}

impl fmt::Display for ReauthfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReauthfiError::Network(e) => write!(f, "Network error: {}", e),
            ReauthfiError::Io(e) => write!(f, "IO error: {}", e),
            ReauthfiError::NotFound => write!(f, "Captive portal not found"),
            ReauthfiError::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
            #[cfg(not(target_os = "macos"))]
            ReauthfiError::UnsupportedPlatform => write!(f, "Unsupported platform"),
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
pub enum Platform {
    MacOS,
}

impl Platform {
    pub fn detect() -> Self {
        Platform::MacOS
    }

    pub fn detection_endpoints(&self) -> &'static [DetectionEndpoint] {
        match self {
            Platform::MacOS => MACOS_DETECTION_ENDPOINTS,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DetectionEndpoint {
    pub name: &'static str,
    pub url: &'static str,
    pub expected_status: Option<u16>,
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
pub struct PlatformConfig {
    pub gateway_command: &'static [&'static str],
    pub gateway_regex: &'static str,
    pub gateway_endpoints: &'static [&'static str],
}

const MACOS_GATEWAY_COMMAND: &[&str] = &["route", "-n", "get", "default"];
const MACOS_GATEWAY_REGEX: &str = r"gateway:\s+(\d+\.\d+\.\d+\.\d+)";
const MACOS_GATEWAY_ENDPOINTS: &[&str] = &["/"];

impl PlatformConfig {
    pub fn for_platform(_platform: &Platform) -> Self {
        PlatformConfig {
            gateway_command: MACOS_GATEWAY_COMMAND,
            gateway_regex: MACOS_GATEWAY_REGEX,
            gateway_endpoints: MACOS_GATEWAY_ENDPOINTS,
        }
    }
}

pub trait DetectionStrategy {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult;
}

#[derive(Copy, Clone)]
pub enum StrategyKind {
    Gateway,
    StandardUrl,
}

pub const GATEWAY_PRIORITY: [StrategyKind; 2] = [StrategyKind::Gateway, StrategyKind::StandardUrl];
pub const STANDARD_PRIORITY: [StrategyKind; 2] = [StrategyKind::StandardUrl, StrategyKind::Gateway];

pub struct DetectionContext<'a> {
    pub platform: &'a Platform,
    pub config: &'a PlatformConfig,
    pub client: &'a Client,
    pub options: &'a Options,
}

pub struct StandardUrlDetection;

impl DetectionStrategy for StandardUrlDetection {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult {
        let endpoints = ctx.platform.detection_endpoints();
        let mut saw_any_error = false;

        for endpoint in endpoints {
            if ctx.options.verbose {
                println!(
                    "  {} Checking {} ({})",
                    "•".yellow(),
                    endpoint.name,
                    endpoint.url
                );
            }

            match check_with_progress(endpoint.url, ctx.client, ctx.options.timeout) {
                Ok(response) => {
                    let status = response.status();

                    if let Some(expected) = endpoint.expected_status {
                        if status.as_u16() == expected {
                            if ctx.options.verbose {
                                println!("    {} Expected {} status", "✓".green(), expected);
                            }
                            continue; // move to next endpoint
                        }
                    }

                    if let Some(portal_url) = redirect_location_url(&response) {
                        if ctx.options.verbose {
                            println!("    {} {} Redirect", "✓".green(), status.as_u16());
                        }
                        return DetectionResult::PortalFound(portal_url);
                    }
                }
                Err(e) => {
                    saw_any_error = true;
                    if ctx.options.verbose {
                        if e.is_timeout() {
                            println!("    {} Timeout ({}s)", "⏱".yellow(), ctx.options.timeout);
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

pub struct GatewayDetection;

impl DetectionStrategy for GatewayDetection {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult {
        let gateway_ip = match get_gateway_ip(ctx.config) {
            Ok(ip) => ip,
            Err(_) => return DetectionResult::NetworkError,
        };

        if ctx.options.verbose {
            println!("  {} Gateway IP: {}", "•".yellow(), gateway_ip);
        }

        for endpoint in ctx.config.gateway_endpoints {
            let url = format!("http://{}{}", gateway_ip, endpoint);

            if ctx.options.verbose {
                println!("    {} Checking {}...", "•".yellow(), url);
            }

            match check_with_progress(&url, ctx.client, ctx.options.timeout) {
                Ok(response) => {
                    let status = response.status();

                    if let Some(portal_url) = redirect_location_url(&response) {
                        if ctx.options.verbose {
                            println!("      {} {} Redirect", "✓".green(), status.as_u16());
                        }
                        return DetectionResult::PortalFound(portal_url);
                    }

                    if status.is_success() {
                        if let Ok(html) = response.text() {
                            if let Some(meta_url) = extract_meta_refresh(&html) {
                                if ctx.options.verbose {
                                    println!("      {} Found meta refresh", "✓".green());
                                }
                                return DetectionResult::PortalFound(meta_url);
                            }
                        }
                    }
                }
                Err(e) => {
                    if ctx.options.verbose {
                        if e.is_timeout() {
                            println!("      {} Timeout ({}s)", "⏱".yellow(), ctx.options.timeout);
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

pub struct PortalOpenerService;

impl PortalOpenerService {
    pub fn open(url: &str) -> Result<(), ReauthfiError> {
        #[cfg(target_os = "macos")]
        {
            let status = Command::new("open").arg(url).status()?;

            if status.success() {
                Ok(())
            } else {
                let detail = status
                    .code()
                    .map(|code| format!("exit code {}", code))
                    .unwrap_or_else(|| "terminated by signal".to_string());
                Err(ReauthfiError::CommandFailed(detail))
            }
        }

        #[cfg(not(target_os = "macos"))]
        {
            Err(ReauthfiError::UnsupportedPlatform)
        }
    }
}

pub fn build_client(timeout_secs: u64) -> Result<Client, ReauthfiError> {
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(timeout_secs))
        .build()?;
    Ok(client)
}

pub fn print_network_not_ready(verbose: bool, detail: Option<&dyn fmt::Display>) {
    println!(
        "{} Network not ready - this may be a first-time Wi-Fi connection",
        "❌".red().bold()
    );
    println!("  Close any macOS network popup windows and try again");
    println!("  Or wait a few seconds for the network to stabilize");

    if verbose {
        if let Some(detail) = detail {
            println!("  Detail: {}", detail);
        }
    }
}

fn print_progress(message: &str, elapsed: u64, total: u64) {
    print!("\r  {} {} [", "•".yellow(), message);

    let bar_slots = 20;
    let safe_total = total.max(1);
    let progress = (elapsed * bar_slots / safe_total).min(bar_slots);
    for i in 0..bar_slots {
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

#[derive(Debug, Clone)]
pub struct Options {
    pub verbose: bool,
    pub no_open: bool,
    pub gateway: bool,
    pub timeout: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            verbose: false,
            no_open: false,
            gateway: false,
            timeout: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Completed,
    NetworkNotReady,
}

pub fn run(options: &Options) -> Result<ExecutionStatus, ReauthfiError> {
    let platform = Platform::detect();
    let config = PlatformConfig::for_platform(&platform);

    let client = match build_client(options.timeout) {
        Ok(client) => client,
        Err(e) => {
            print_network_not_ready(options.verbose, Some(&e));
            return Ok(ExecutionStatus::NetworkNotReady);
        }
    };

    println!("{}", "🔍 Detecting Captive Portal...".cyan().bold());

    let strategies: &[StrategyKind] = if options.gateway {
        &GATEWAY_PRIORITY
    } else {
        &STANDARD_PRIORITY
    };

    let ctx = DetectionContext {
        platform: &platform,
        config: &config,
        client: &client,
        options,
    };

    for &strategy in strategies {
        let detector: &dyn DetectionStrategy = match strategy {
            StrategyKind::Gateway => &GatewayDetection,
            StrategyKind::StandardUrl => &StandardUrlDetection,
        };

        match detector.detect(&ctx) {
            DetectionResult::PortalFound(portal_url) => {
                if options.verbose {
                    println!("  {} Portal URL: {}", "→".green().bold(), portal_url);
                }

                if !options.no_open {
                    println!("{}", "📱 Opening in browser...".cyan().bold());
                    match PortalOpenerService::open(&portal_url) {
                        Ok(_) => println!("{}", "✅ Done!".green().bold()),
                        Err(e) => return Err(e),
                    }
                }
                return Ok(ExecutionStatus::Completed);
            }
            DetectionResult::NetworkError => {
                print_network_not_ready(options.verbose, None);
                return Ok(ExecutionStatus::NetworkNotReady);
            }
            DetectionResult::NoPortalDetected => continue,
        }
    }

    println!("{} No captive portal detected", "✅".green().bold());
    Ok(ExecutionStatus::Completed)
}
