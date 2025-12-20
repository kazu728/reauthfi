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

pub struct WifiController;

impl WifiController {
    pub fn wifi_device() -> Result<String, ReauthfiError> {
        let output = Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()
            .map_err(ReauthfiError::from)?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let re_block = Regex::new(r"(?s)Hardware Port:\s*(Wi-Fi|AirPort).*?Device:\s*([^\s]+)")
            .map_err(|_| ReauthfiError::NotFound)?;

        re_block
            .captures(&stdout)
            .and_then(|caps| caps.get(2).map(|m| m.as_str().to_string()))
            .ok_or(ReauthfiError::NotFound)
    }

    pub fn reset_wifi(device: &str) -> Result<(), ReauthfiError> {
        Command::new("networksetup")
            .args(["-setairportpower", device, "off"])
            .status()
            .map_err(ReauthfiError::from)
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(ReauthfiError::CommandFailed(format!(
                        "setairportpower off failed ({})",
                        status
                    )))
                }
            })?;

        std::thread::sleep(std::time::Duration::from_secs(2));

        Command::new("networksetup")
            .args(["-setairportpower", device, "on"])
            .status()
            .map_err(ReauthfiError::from)
            .and_then(|status| {
                if status.success() {
                    Ok(())
                } else {
                    Err(ReauthfiError::CommandFailed(format!(
                        "setairportpower on failed ({})",
                        status
                    )))
                }
            })?;

        Ok(())
    }
}

pub fn print_network_not_ready(detail: Option<&dyn fmt::Display>) {
    println!(
        "{} Network not ready - this may be a first-time Wi-Fi connection",
        "❌".red().bold()
    );
    println!("  Close any macOS network popup windows and try again");
    println!("  Or wait a few seconds for the network to stabilize");

    if let Some(detail) = detail {
        println!("  Detail: {}", detail);
    }
}

#[derive(Debug, Clone)]
pub struct Options {
    pub timeout: u64,
}

impl Default for Options {
    fn default() -> Self {
        Self { timeout: 5 }
    }
}

pub struct DetectionContext<'a> {
    pub config: &'a DetectionConfig,
    pub net: Arc<dyn NetworkClient>,
    pub commands: &'a dyn CommandRunner,
    pub options: &'a Options,
}

#[derive(Debug, Clone)]
struct DetectionTarget {
    name: String,
    url: String,
    expected_status: Option<u16>,
    allow_meta_refresh: bool,
}

#[derive(Debug, Clone)]
enum Outcome {
    Portal(String),
    ExpectedOk,
    Mismatch(u16),
    Issue(String),
}

fn classify_parts(
    target: &DetectionTarget,
    status_code: u16,
    location: Option<String>,
    body: Option<String>,
) -> Outcome {
    if let Some(portal_url) = location {
        return Outcome::Portal(portal_url);
    }

    if let Some(expected) = target.expected_status {
        if status_code == expected {
            return Outcome::ExpectedOk;
        }
    }

    if let Some(body) = body {
        if target.allow_meta_refresh {
            if let Some(url) = extract_meta_refresh(&body) {
                return Outcome::Portal(url);
            }
        }

        if target.expected_status.is_none() && body.to_ascii_lowercase().contains("success") {
            return Outcome::ExpectedOk;
        }
    }

    Outcome::Mismatch(status_code)
}

fn classify_response(target: &DetectionTarget, response: Response) -> Outcome {
    let location = redirect_location_url(&response);
    let status = response.status();
    let status_code = status.as_u16();
    let should_parse_body =
        status.is_success() && (target.allow_meta_refresh || target.expected_status.is_none());

    if should_parse_body {
        match response.text() {
            Ok(body) => classify_parts(target, status_code, location, Some(body)),
            Err(_) => Outcome::Issue(format!("{}: failed to read body", target.name)),
        }
    } else {
        classify_parts(target, status_code, location, None)
    }
}

fn error_reason(name: &str, err: &reqwest::Error, timeout: Duration) -> String {
    if err.is_timeout() {
        format!("{}: timeout ({}s)", name, timeout.as_secs())
    } else if err.is_connect() {
        format!("{}: connect error", name)
    } else {
        format!("{}: error {}", name, err)
    }
}

fn run_detection(targets: &[DetectionTarget], ctx: &DetectionContext) -> DetectionResult {
    let mut errors: Vec<String> = Vec::new();
    let mut saw_expected_ok = false;

    for target in targets {
        let request_timeout = Duration::from_secs(ctx.options.timeout);

        let outcome = match ctx.net.get(&target.url, request_timeout) {
            Ok(response) => classify_response(target, response),
            Err(e) => Outcome::Issue(error_reason(&target.name, &e, request_timeout)),
        };

        match outcome {
            Outcome::Portal(url) => {
                println!("    {} {} redirect detected", "✓".green(), target.name);
                return DetectionResult::PortalFound(url);
            }
            Outcome::Issue(msg) => {
                if target.allow_meta_refresh {
                    println!(
                        "    {} {} unreachable (ignored)",
                        "⚠️".yellow(),
                        target.name
                    );
                } else {
                    println!("    {} {} failed", "✗".red(), target.name);
                }
                errors.push(msg);
            }
            Outcome::Mismatch(status) => {
                errors.push(format!("{}: status {}", target.name, status));
            }
            Outcome::ExpectedOk => {
                saw_expected_ok = true;
            }
        }
    }

    if saw_expected_ok {
        DetectionResult::NoPortalDetected
    } else if !errors.is_empty() {
        DetectionResult::NetworkIssues(errors)
    } else {
        DetectionResult::NoPortalDetected
    }
}

pub fn detect_standard(ctx: &DetectionContext) -> DetectionResult {
    let endpoints = ctx.config.detection_endpoints;
    if endpoints.is_empty() {
        return DetectionResult::NoPortalDetected;
    }

    println!(
        "  {} Checking captive portal endpoints ({} total)...",
        "•".yellow(),
        endpoints.len()
    );

    let targets: Vec<DetectionTarget> = endpoints
        .iter()
        .map(|endpoint| DetectionTarget {
            name: endpoint.name.to_string(),
            url: endpoint.url.to_string(),
            expected_status: endpoint.expected_status,
            allow_meta_refresh: false,
        })
        .collect();

    run_detection(&targets, ctx)
}

pub fn detect_gateway(ctx: &DetectionContext) -> DetectionResult {
    let gateway_ip = match get_gateway_ip(ctx.config, ctx.commands) {
        Ok(ip) => ip,
        Err(_) => return DetectionResult::NetworkIssues(vec!["gateway_ip".to_string()]),
    };

    println!("  {} Checking gateway endpoints...", "•".yellow());

    let targets: Vec<DetectionTarget> = ctx
        .config
        .gateway_endpoints
        .iter()
        .map(|endpoint| DetectionTarget {
            name: format!("Gateway{}", endpoint),
            url: format!("http://{}{}", gateway_ip, endpoint),
            expected_status: None,
            allow_meta_refresh: true,
        })
        .collect();

    run_detection(&targets, ctx)
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
    opener: &'a dyn PortalOpener,
}

impl<'a> Detector<'a> {
    fn run(&self) -> Result<ExecutionStatus, ReauthfiError> {
        let (status, errors) = self.detect_once()?;
        match status {
            ExecutionStatus::Completed => Ok(ExecutionStatus::Completed),
            ExecutionStatus::NetworkNotReady => self.retry_with_wifi_reset(errors),
        }
    }

    fn detect_once(&self) -> Result<(ExecutionStatus, Vec<String>), ReauthfiError> {
        let net = Arc::new(HttpClient::new(self.options.timeout)?);
        let ctx = DetectionContext {
            config: self.config,
            net: net.clone(),
            commands: self.commands,
            options: self.options,
        };
        Ok(detect_portal(&ctx, self.opener))
    }

    fn retry_with_wifi_reset(
        &self,
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
                        println!("{} Waiting 10s for Wi-Fi to reconnect...", "⏳".yellow());
                        thread::sleep(Duration::from_secs(10));
                    }
                    let (retry_status, retry_errors) = self.detect_once()?;
                    if retry_status == ExecutionStatus::Completed {
                        return Ok(ExecutionStatus::Completed);
                    }
                    if !retry_errors.is_empty() {
                        return finish_network_not_ready(&retry_errors);
                    }
                }
            }
        }

        if !first_errors.is_empty() {
            finish_network_not_ready(&first_errors)
        } else {
            finish_network_not_ready(&[])
        }
    }
}

pub fn run(options: &Options) -> Result<ExecutionStatus, ReauthfiError> {
    let config = detection_config()?;

    let commands = SystemCommandRunner;
    let opener = MacPortalOpener;

    println!("{}", "🔍 Detecting Captive Portal...".cyan().bold());

    let detector = Detector {
        config: &config,
        commands: &commands,
        options,
        opener: &opener,
    };

    detector.run()
}

fn detect_portal(
    ctx: &DetectionContext,
    opener: &dyn PortalOpener,
) -> (ExecutionStatus, Vec<String>) {
    let mut saw_error = false;
    let mut any_success = false;
    let mut all_errors: Vec<String> = Vec::new();

    let detection_steps: [fn(&DetectionContext) -> DetectionResult; 2] =
        [detect_standard, detect_gateway];

    for detect in detection_steps {
        match detect(ctx) {
            DetectionResult::PortalFound(portal_url) => {
                println!("  {} Portal URL: {}", "→".green().bold(), portal_url);

                println!("{}", "📱 Opening in browser...".cyan().bold());
                match opener.open(&portal_url) {
                    Ok(_) => println!("{}", "✅ Done!".green().bold()),
                    Err(e) => return (ExecutionStatus::NetworkNotReady, vec![e.to_string()]),
                }
                return (ExecutionStatus::Completed, Vec::new());
            }
            DetectionResult::NetworkIssues(errors) => {
                saw_error = true;
                all_errors.extend(errors);
            }
            DetectionResult::NoPortalDetected => {
                any_success = true;
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

fn finish_network_not_ready(errors: &[String]) -> Result<ExecutionStatus, ReauthfiError> {
    if !errors.is_empty() {
        let detail = errors.join(", ");
        print_network_not_ready(Some(&detail));
    } else {
        print_network_not_ready(None);
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

    fn base_target() -> DetectionTarget {
        DetectionTarget {
            name: "Test".to_string(),
            url: "http://example.com".to_string(),
            expected_status: None,
            allow_meta_refresh: false,
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

    #[test]
    fn classify_prefers_redirect_location() {
        let target = base_target();
        let outcome = classify_parts(&target, 200, Some("http://portal".to_string()), None);
        assert!(matches!(outcome, Outcome::Portal(url) if url == "http://portal"));
    }

    #[test]
    fn classify_matches_expected_status() {
        let mut target = base_target();
        target.expected_status = Some(204);
        let outcome = classify_parts(&target, 204, None, None);
        assert!(matches!(outcome, Outcome::ExpectedOk));
    }

    #[test]
    fn classify_detects_meta_refresh() {
        let mut target = base_target();
        target.allow_meta_refresh = true;
        let body = r#"<html><meta http-equiv="refresh" content="0; url=http://portal"/></html>"#;
        let outcome = classify_parts(&target, 200, None, Some(body.to_string()));
        assert!(matches!(outcome, Outcome::Portal(url) if url == "http://portal"));
    }

    #[test]
    fn classify_accepts_success_body() {
        let target = base_target();
        let outcome = classify_parts(&target, 200, None, Some("Success".to_string()));
        assert!(matches!(outcome, Outcome::ExpectedOk));
    }
}
