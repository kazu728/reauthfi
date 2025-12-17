mod strategies;
mod wifi_reset;

use std::error::Error;
use std::fmt;
use std::process::Command;
use std::result::Result;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use colored::Colorize;
use regex::Regex;
use reqwest::blocking::{Client, Response};
use strategies::{DetectionContext, DetectionStrategy, GatewayDetection, StandardUrlDetection};
use wifi_reset::WifiController;

#[derive(Debug)]
pub enum ReauthfiError {
    Io(std::io::Error),
    NotFound,
    CommandFailed(String),
    UnsupportedPlatform,
    Setup(String),
}

#[derive(Debug)]
pub enum DetectionResult {
    PortalFound(String),
    NoPortalDetected,
    NetworkIssues(Vec<String>),
}

impl fmt::Display for ReauthfiError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ReauthfiError::Io(e) => write!(f, "IO error: {}", e),
            ReauthfiError::NotFound => write!(f, "Captive portal not found"),
            ReauthfiError::CommandFailed(msg) => write!(f, "Command failed: {}", msg),
            ReauthfiError::UnsupportedPlatform => write!(f, "Unsupported platform"),
            ReauthfiError::Setup(msg) => write!(f, "Setup error: {}", msg),
        }
    }
}

impl Error for ReauthfiError {}

impl From<std::io::Error> for ReauthfiError {
    fn from(err: std::io::Error) -> Self {
        ReauthfiError::Io(err)
    }
}

#[derive(Copy, Clone)]
pub enum StrategyKind {
    Gateway,
    StandardUrl,
}

pub const GATEWAY_PRIORITY: [StrategyKind; 2] = [StrategyKind::Gateway, StrategyKind::StandardUrl];
pub const STANDARD_PRIORITY: [StrategyKind; 2] = [StrategyKind::StandardUrl, StrategyKind::Gateway];

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
pub struct DetectionConfig {
    pub detection_endpoints: &'static [DetectionEndpoint],
    pub gateway_command: &'static [&'static str],
    pub gateway_regex: &'static str,
    pub gateway_endpoints: &'static [&'static str],
    pub supports_wifi_reset: bool,
}

const MACOS_GATEWAY_COMMAND: &[&str] = &["route", "-n", "get", "default"];
const MACOS_GATEWAY_REGEX: &str = r"gateway:\s+(\d+\.\d+\.\d+\.\d+)";
const MACOS_GATEWAY_ENDPOINTS: &[&str] = &["/"];

static MACOS_CONFIG: DetectionConfig = DetectionConfig {
    detection_endpoints: MACOS_DETECTION_ENDPOINTS,
    gateway_command: MACOS_GATEWAY_COMMAND,
    gateway_regex: MACOS_GATEWAY_REGEX,
    gateway_endpoints: MACOS_GATEWAY_ENDPOINTS,
    supports_wifi_reset: true,
};

fn detection_config() -> Result<&'static DetectionConfig, ReauthfiError> {
    #[cfg(target_os = "macos")]
    {
        Ok(&MACOS_CONFIG)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(ReauthfiError::UnsupportedPlatform)
    }
}

/// Shared cancellation flag checked by worker threads to allow Ctrl+C to abort quickly.
#[derive(Clone, Default)]
pub struct CancelFlag {
    inner: Arc<std::sync::atomic::AtomicBool>,
}

impl CancelFlag {
    pub fn is_set(&self) -> bool {
        self.inner.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn set(&self) {
        self.inner.store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

pub trait NetworkClient: Send + Sync {
    fn get(&self, url: &str, timeout: Duration) -> Result<Response, reqwest::Error>;
}

#[derive(Clone)]
pub struct HttpClient {
    inner: Client,
}

impl HttpClient {
    pub fn new(request_timeout_secs: u64) -> Result<Self, ReauthfiError> {
        let request_timeout = Duration::from_secs(request_timeout_secs);
        let connect_timeout = request_timeout.min(Duration::from_secs(2));
        let inner = Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(request_timeout)
            .connect_timeout(connect_timeout)
            .build()
            .map_err(|e| ReauthfiError::Setup(format!("failed to build http client: {}", e)))?;

        Ok(Self { inner })
    }
}

impl NetworkClient for HttpClient {
    fn get(&self, url: &str, timeout: Duration) -> Result<Response, reqwest::Error> {
        self.inner.get(url).timeout(timeout).send()
    }
}

pub trait CommandRunner: Send + Sync {
    fn run(&self, cmd: &[&str]) -> Result<String, std::io::Error>;
}

pub struct SystemCommandRunner;

impl CommandRunner for SystemCommandRunner {
    fn run(&self, cmd: &[&str]) -> Result<String, std::io::Error> {
        let output = std::process::Command::new(cmd[0])
            .args(&cmd[1..])
            .output()?;

        if !output.status.success() {
            let status_desc = output
                .status
                .code()
                .map(|code| format!("exit code {}", code))
                .unwrap_or_else(|| "terminated by signal".to_string());
            let stderr = String::from_utf8_lossy(&output.stderr);
            let detail = stderr.trim();
            let msg = if detail.is_empty() {
                status_desc
            } else {
                format!("{} ({})", status_desc, detail)
            };

            return Err(std::io::Error::new(std::io::ErrorKind::Other, msg));
        }

        Ok(String::from_utf8_lossy(&output.stdout).to_string())
    }
}

pub fn get_gateway_ip(
    config: &DetectionConfig,
    runner: &dyn CommandRunner,
) -> Result<String, ReauthfiError> {
    let stdout = runner.run(config.gateway_command)?;
    let re = Regex::new(config.gateway_regex).map_err(|_| ReauthfiError::NotFound)?;

    re.captures(&stdout)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
        .ok_or(ReauthfiError::NotFound)
}

pub fn extract_meta_refresh(html: &str) -> Option<String> {
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

pub fn redirect_location_url(response: &Response) -> Option<String> {
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
pub trait PortalOpener: Send + Sync {
    fn open(&self, url: &str) -> Result<(), ReauthfiError>;
}

pub struct MacPortalOpener;

impl PortalOpener for MacPortalOpener {
    fn open(&self, url: &str) -> Result<(), ReauthfiError> {
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
            let _ = url;
            Err(ReauthfiError::UnsupportedPlatform)
        }
    }
}

pub fn print_network_not_ready(verbose: bool, detail: Option<&dyn fmt::Display>) {
    println!(
        "{} Network not ready - this may be a first-time Wi-Fi connection",
        "❌".red().bold()
    );
    println!("  Close any macOS network popup windows and try again");
    println!("  Or wait a few seconds for the network to stabilize");

    if let Some(detail) = detail {
        println!("  Detail: {}", detail);
    } else if verbose {
        println!("  Detail: none");
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
            timeout: 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionStatus {
    Completed,
    NetworkNotReady,
}

struct Detector<'a> {
    config: &'a DetectionConfig,
    commands: &'a dyn CommandRunner,
    options: &'a Options,
    cancel_flag: &'a CancelFlag,
    opener: &'a dyn PortalOpener,
}

impl<'a> Detector<'a> {
    fn run(&self, strategies: &[StrategyKind]) -> Result<ExecutionStatus, ReauthfiError> {
        let (status, errors) = self.detect_once(strategies)?;
        match status {
            ExecutionStatus::Completed => Ok(ExecutionStatus::Completed),
            ExecutionStatus::NetworkNotReady => self.retry_with_wifi_reset(strategies, errors),
        }
    }

    fn detect_once(
        &self,
        strategies: &[StrategyKind],
    ) -> Result<(ExecutionStatus, Vec<String>), ReauthfiError> {
        let net = Arc::new(HttpClient::new(self.options.timeout)?);
        let ctx = DetectionContext {
            config: self.config,
            net: net.clone(),
            commands: self.commands,
            options: self.options,
            cancel_flag: self.cancel_flag,
        };
        Ok(detect_portal(strategies, &ctx, self.options, self.opener))
    }

    fn retry_with_wifi_reset(
        &self,
        strategies: &[StrategyKind],
        first_errors: Vec<String>,
    ) -> Result<ExecutionStatus, ReauthfiError> {
        #[cfg(target_os = "macos")]
        {
            if self.config.supports_wifi_reset {
                if let Ok(dev) = WifiController::wifi_device() {
                    println!(
                        "{} Resetting Wi-Fi on {} and retrying after reconnect...",
                        "↻".yellow(),
                        dev
                    );
                    if WifiController::reset_wifi(&dev).is_ok() {
                        // Allow the interface time to come back up after toggle.
                        println!(
                            "{} Waiting 10s for Wi-Fi to reconnect...",
                            "⏳".yellow()
                        );
                        thread::sleep(Duration::from_secs(10));
                    }
                    let (retry_status, retry_errors) = self.detect_once(strategies)?;
                    if retry_status == ExecutionStatus::Completed {
                        return Ok(ExecutionStatus::Completed);
                    }
                    if !retry_errors.is_empty() {
                        return finish_network_not_ready(self.options, &retry_errors);
                    }
                }
            }
        }

        if !first_errors.is_empty() {
            finish_network_not_ready(self.options, &first_errors)
        } else {
            finish_network_not_ready(self.options, &[])
        }
    }
}

pub fn run(options: &Options) -> Result<ExecutionStatus, ReauthfiError> {
    let config = detection_config()?;
    let cancel_flag = CancelFlag::default();
    let ctrlc_flag = cancel_flag.clone();
    ctrlc::set_handler(move || {
        ctrlc_flag.set();
    })
    .map_err(|e| ReauthfiError::CommandFailed(format!("failed to set Ctrl+C handler: {}", e)))?;

    let commands = SystemCommandRunner;
    let opener = MacPortalOpener;

    println!("{}", "🔍 Detecting Captive Portal...".cyan().bold());

    let strategies: &[StrategyKind] = if options.gateway {
        &GATEWAY_PRIORITY
    } else {
        &STANDARD_PRIORITY
    };

    let detector = Detector {
        config: &config,
        commands: &commands,
        options,
        cancel_flag: &cancel_flag,
        opener: &opener,
    };

    detector.run(strategies)
}

fn detect_portal(
    strategies: &[StrategyKind],
    ctx: &DetectionContext,
    options: &Options,
    opener: &dyn PortalOpener,
) -> (ExecutionStatus, Vec<String>) {
    let mut saw_error = false;
    let mut any_success = false;
    let mut all_errors: Vec<String> = Vec::new();

    for &strategy in strategies {
        let detector: &dyn DetectionStrategy = match strategy {
            StrategyKind::Gateway => &GatewayDetection,
            StrategyKind::StandardUrl => &StandardUrlDetection,
        };

        match detector.detect(ctx) {
            DetectionResult::PortalFound(portal_url) => {
                if !options.verbose {
                    println!("  {} Portal URL: {}", "→".green().bold(), portal_url);
                }

                if !options.no_open {
                    println!("{}", "📱 Opening in browser...".cyan().bold());
                    match opener.open(&portal_url) {
                        Ok(_) => println!("{}", "✅ Done!".green().bold()),
                        Err(e) => return (ExecutionStatus::NetworkNotReady, vec![e.to_string()]),
                    }
                }
                return (ExecutionStatus::Completed, Vec::new());
            }
            DetectionResult::NetworkIssues(errors) => {
                saw_error = true;
                all_errors.extend(errors);
                continue;
            }
            DetectionResult::NoPortalDetected => {
                any_success = true;
                continue;
            }
        }
    }

    if any_success {
        println!("{} No captive portal detected", "✅".green().bold());
        (ExecutionStatus::Completed, Vec::new())
    } else if saw_error {
        (ExecutionStatus::NetworkNotReady, all_errors)
    } else {
        println!("{} No captive portal detected", "✅".green().bold());
        (ExecutionStatus::Completed, Vec::new())
    }
}

fn finish_network_not_ready(
    options: &Options,
    errors: &[String],
) -> Result<ExecutionStatus, ReauthfiError> {
    if !errors.is_empty() {
        let detail = errors.join(", ");
        print_network_not_ready(options.verbose, Some(&detail));
    } else {
        print_network_not_ready(options.verbose, None);
    }
    Ok(ExecutionStatus::NetworkNotReady)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockRunner {
        output: String,
    }

    impl CommandRunner for MockRunner {
        fn run(&self, _cmd: &[&str]) -> Result<String, std::io::Error> {
            Ok(self.output.clone())
        }
    }

    fn dummy_config() -> DetectionConfig {
        DetectionConfig {
            detection_endpoints: &[],
            gateway_command: &["route"],
            gateway_regex: MACOS_GATEWAY_REGEX,
            gateway_endpoints: &[],
            supports_wifi_reset: true,
        }
    }

    #[test]
    fn gateway_ip_is_parsed_from_route_output() {
        let cfg = dummy_config();
        let runner = MockRunner {
            output: "route to default\n    gateway: 10.0.0.1\n".to_string(),
        };

        let ip = get_gateway_ip(&cfg, &runner).unwrap();
        assert_eq!(ip, "10.0.0.1");
    }

    #[test]
    fn gateway_ip_missing_returns_not_found() {
        let cfg = dummy_config();
        let runner = MockRunner {
            output: "no gateway present".to_string(),
        };

        let err = get_gateway_ip(&cfg, &runner).unwrap_err();
        assert!(matches!(err, ReauthfiError::NotFound));
    }
}
