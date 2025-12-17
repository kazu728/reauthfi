use std::sync::Arc;
use std::time::Duration;

use colored::Colorize;
use reqwest::blocking::Response;

use crate::{
    extract_meta_refresh, get_gateway_ip, redirect_location_url, CancelFlag, CommandRunner,
    DetectionConfig, DetectionResult, NetworkClient, Options,
};

pub struct DetectionContext<'a> {
    pub config: &'a DetectionConfig,
    pub net: Arc<dyn NetworkClient>,
    pub commands: &'a dyn CommandRunner,
    pub options: &'a Options,
    pub cancel_flag: &'a CancelFlag,
}

pub trait DetectionStrategy {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult;
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
        if ctx.cancel_flag.is_set() {
            return DetectionResult::NetworkIssues(vec!["canceled".to_string()]);
        }

        let request_timeout = Duration::from_secs(ctx.options.timeout);

        if ctx.options.verbose {
            println!(
                "  {} Checking {} ({})",
                "•".yellow(),
                target.name,
                target.url
            );
        }

        let outcome = match ctx.net.get(&target.url, request_timeout) {
            Ok(response) => classify_response(target, response),
            Err(e) => {
                if ctx.options.verbose {
                    if e.is_timeout() {
                        println!(
                            "    {} Timeout ({}s)",
                            "⏱".yellow(),
                            request_timeout.as_secs()
                        );
                    } else if e.is_connect() {
                        println!("    {} Connection failed", "✗".red());
                    } else {
                        println!("    {} Failed: {}", "✗".red(), e);
                    }
                }
                Outcome::Issue(error_reason(&target.name, &e, request_timeout))
            }
        };

        match outcome {
            Outcome::Portal(url) => {
                if ctx.options.verbose {
                    println!(
                        "    {} Portal detected via {} ({})",
                        "→".green().bold(),
                        target.name,
                        url
                    );
                } else {
                    println!("    {} {} redirect detected", "✓".green(), target.name);
                }
                return DetectionResult::PortalFound(url);
            }
            Outcome::Issue(msg) => {
                if !ctx.options.verbose {
                    if target.allow_meta_refresh {
                        println!(
                            "    {} {} unreachable (ignored)",
                            "⚠️".yellow(),
                            target.name
                        );
                    } else {
                        println!("    {} {} failed", "✗".red(), target.name);
                    }
                }
                errors.push(msg);
            }
            Outcome::Mismatch(status) => {
                if ctx.options.verbose {
                    println!(
                        "    {} {} unexpected status {}",
                        "•".yellow(),
                        target.name,
                        status
                    );
                }
                errors.push(format!("{}: status {}", target.name, status));
            }
            Outcome::ExpectedOk => {
                saw_expected_ok = true;
                if ctx.options.verbose {
                    println!("    {} Expected status", "✓".green());
                }
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

pub struct StandardUrlDetection;

impl DetectionStrategy for StandardUrlDetection {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult {
        let endpoints = ctx.config.detection_endpoints;
        if endpoints.is_empty() {
            return DetectionResult::NoPortalDetected;
        }

        if !ctx.options.verbose {
            println!(
                "  {} Checking captive portal endpoints ({} total)...",
                "•".yellow(),
                endpoints.len()
            );
        }

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
}

pub struct GatewayDetection;

impl DetectionStrategy for GatewayDetection {
    fn detect(&self, ctx: &DetectionContext) -> DetectionResult {
        if ctx.cancel_flag.is_set() {
            return DetectionResult::NetworkIssues(vec!["canceled".to_string()]);
        }

        let gateway_ip = match get_gateway_ip(ctx.config, ctx.commands) {
            Ok(ip) => ip,
            Err(_) => return DetectionResult::NetworkIssues(vec!["gateway_ip".to_string()]),
        };

        if ctx.options.verbose {
            println!("  {} Gateway IP: {}", "•".yellow(), gateway_ip);
        } else {
            println!("  {} Checking gateway endpoints...", "•".yellow());
        }

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
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_target() -> DetectionTarget {
        DetectionTarget {
            name: "Test".to_string(),
            url: "http://example.com".to_string(),
            expected_status: None,
            allow_meta_refresh: false,
        }
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
