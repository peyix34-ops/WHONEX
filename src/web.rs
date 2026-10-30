use reqwest::blocking::{Client, Response};
use reqwest::header::{HeaderMap, SET_COOKIE};
use reqwest::redirect::Policy;
use reqwest::Method;
use serde::Serialize;

use std::collections::HashSet;
use std::fs::OpenOptions;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use url::Url;

const MAX_REQUESTS: usize = 8;
const MAX_DISCOVERED_PAGES: usize = 4;
const MAX_ROOT_BODY_BYTES: usize = 512 * 1024;
const MAX_METADATA_BODY_BYTES: usize = 32 * 1024;
const MIN_REQUEST_INTERVAL_MS: u64 = 800;
const MAX_REQUEST_INTERVAL_MS: u64 = 3_000;
const REQUEST_TIMEOUT_SECS: u64 = 9;
const CONNECT_TIMEOUT_SECS: u64 = 4;

#[derive(Debug, Clone)]
struct Target {
    url: Url,
    host: String,
    port: u16,
}

#[derive(Debug)]
struct ResponseSnapshot {
    status: u16,
    headers: HeaderMap,
    body: Vec<u8>,
    body_truncated: bool,
    bytes_read: usize,
    duration_ms: u128,
}

#[derive(Debug)]
struct RequestLimiter {
    interval: Duration,
    last_started: Option<Instant>,
    quick_responses: u8,
}

impl RequestLimiter {
    fn new() -> Self {
        Self {
            interval: Duration::from_millis(MIN_REQUEST_INTERVAL_MS),
            last_started: None,
            quick_responses: 0,
        }
    }

    fn wait_turn(&mut self) {
        if let Some(last) = self.last_started {
            let elapsed = last.elapsed();
            if elapsed < self.interval {
                thread::sleep(self.interval - elapsed);
            }
        }
        self.last_started = Some(Instant::now());
    }

    fn observe(&mut self, duration: Duration, status: u16) {
        if status == 429 || status >= 500 || duration >= Duration::from_secs(2) {
            self.interval = (self.interval + Duration::from_millis(700))
                .min(Duration::from_millis(MAX_REQUEST_INTERVAL_MS));
            self.quick_responses = 0;
        } else if duration < Duration::from_millis(600) {
            self.quick_responses = self.quick_responses.saturating_add(1);
            if self.quick_responses >= 3 {
                self.interval = self
                    .interval
                    .saturating_sub(Duration::from_millis(100))
                    .max(Duration::from_millis(MIN_REQUEST_INTERVAL_MS));
                self.quick_responses = 0;
            }
        } else {
            self.quick_responses = 0;
        }
        // Enforce a quiet interval after the response completes.
        self.last_started = Some(Instant::now());
    }
}

#[derive(Serialize)]
struct WebReport {
    schema_version: String,
    tool: String,
    version: String,
    target: String,
    scope: String,
    authorization_self_attested: bool,
    started_at_unix: u64,
    completed_at_unix: u64,
    request_budget: usize,
    requests_attempted: usize,
    summary: ReportSummary,
    checks: Vec<String>,
    findings: Vec<WebFinding>,
    request_log: Vec<RequestRecord>,
    notes: Vec<String>,
    limitations: Vec<String>,
}

#[derive(Default, Serialize)]
struct ReportSummary {
    total_observations: usize,
    confirmed_vulnerabilities: usize,
    needs_manual_verification: usize,
    low: usize,
    informational: usize,
}

#[derive(Serialize)]
struct WebFinding {
    id: String,
    classification: String,
    severity: String,
    confidence: String,
    validation: String,
    title: String,
    affected_url: String,
    evidence: String,
    impact: String,
    recommendation: String,
}

#[derive(Serialize)]
struct RequestRecord {
    method: String,
    url: String,
    status: Option<u16>,
    duration_ms: Option<u128>,
    response_bytes_read: usize,
    purpose: String,
    outcome: String,
}

pub fn run_interactive(output: Option<PathBuf>) -> Result<(), String> {
    println!();
    println!("====================================================");
    println!("                 WHONEX WEB ANALYST");
    println!("       Evidence-based external assessment v0.3");
    println!("====================================================");
    println!("Low-impact assessment for explicitly authorized hosts.");
    println!("Methods: GET and HEAD only; no form submission.");
    println!("No exploit payloads, data changes or redirect following.");
    println!();

    let raw_url = ask("Website origin (https://example.com): ")?;
    let target = parse_target(&raw_url)?;

    println!();
    println!("Target: https://{}", target.host);
    println!("Port: {} (only standard HTTPS is supported)", target.port);
    println!("Scope: exact hostname only; subdomains excluded");
    println!("Redirects: not followed");
    println!("Discovered pages: same-host links only, HEAD requests only");
    println!();
    println!("This tool requires written permission covering this exact host.");

    let authorization = ask("Do you have written authorization? Type EVET: ")?;
    if authorization.trim() != "EVET" {
        return Err("Assessment cancelled: authorization was not confirmed.".into());
    }

    let confirmation = ask(&format!(
        "Type the hostname exactly to confirm the scope ({}): ",
        target.host
    ))?;
    if confirmation.trim() != target.host {
        return Err("Hostname confirmation failed. Assessment cancelled.".into());
    }

    println!();
    println!("AVAILABLE CHECKS");
    println!("----------------------------------------------------");
    println!("1. HTTPS response and security headers");
    println!("2. Cookie security attributes (cookie values are never saved)");
    println!("3. Public metadata (security.txt and robots.txt)");
    println!("4. Same-host page discovery (maximum 4 HEAD requests)");
    println!("----------------------------------------------------");
    println!("Enter 1,2,3,4 or press Enter for all checks.");

    let selection = ask("Selection: ")?;
    let selected = parse_selection(&selection)?;
    let checks = selected
        .iter()
        .map(|number| match number {
            1 => "HTTPS response and security headers".to_string(),
            2 => "Cookie security attributes".to_string(),
            3 => "Public metadata".to_string(),
            4 => "Same-host page discovery".to_string(),
            _ => unreachable!(),
        })
        .collect::<Vec<_>>();

    println!();
    println!("Starting bounded assessment...");
    println!("Maximum attempted requests: {}", MAX_REQUESTS);
    println!("Initial request interval: {} ms", MIN_REQUEST_INTERVAL_MS);
    println!("Request interval increases automatically on slow/error responses.");
    println!("Response body cap: {} KiB; body content is not saved in the report.", MAX_ROOT_BODY_BYTES / 1024);
    println!();

    let report = perform_scan(&target, selected, checks)?;
    print_report(&report);

    if let Some(path) = output {
        save_report(&report, &path)?;
        println!();
        println!("JSON report saved: {}", path.display());
    }

    Ok(())
}

fn ask(message: &str) -> Result<String, String> {
    print!("{message}");
    io::stdout()
        .flush()
        .map_err(|error| format!("Terminal output error: {error}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|error| format!("Input error: {error}"))?;
    Ok(input.trim().to_string())
}

fn parse_selection(input: &str) -> Result<Vec<u8>, String> {
    if input.trim().is_empty() {
        return Ok(vec![1, 2, 3, 4]);
    }

    let mut selected = Vec::new();
    for item in input.split(',') {
        let number = item
            .trim()
            .parse::<u8>()
            .map_err(|_| "Invalid menu selection. Use numbers 1, 2, 3 or 4.".to_string())?;
        if !(1..=4).contains(&number) {
            return Err("Only options 1, 2, 3 and 4 are available.".into());
        }
        if !selected.contains(&number) {
            selected.push(number);
        }
    }

    if selected.is_empty() {
        return Err("No checks selected.".into());
    }
    selected.sort_unstable();
    Ok(selected)
}

fn parse_target(input: &str) -> Result<Target, String> {
    let url = Url::parse(input.trim()).map_err(|_| "Invalid website URL.".to_string())?;

    if url.scheme() != "https" {
        return Err("Only HTTPS targets are supported.".into());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("URLs containing credentials are not allowed.".into());
    }
    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err("Enter the origin only, without a path, query or fragment.".into());
    }

    let host = url
        .host_str()
        .ok_or("The URL does not contain a hostname.")?
        .to_ascii_lowercase();

    if host.parse::<IpAddr>().is_ok() {
        return Err("Direct IP-address targets are not supported.".into());
    }
    if host == "localhost"
        || host.ends_with(".localhost")
        || host.ends_with(".local")
        || host.ends_with(".test")
        || host.ends_with(".invalid")
        || host.ends_with(".onion")
    {
        return Err("Local, reserved or non-public hostnames are not supported.".into());
    }

    let port = url.port_or_known_default().ok_or("Could not determine HTTPS port.")?;
    if port != 443 {
        return Err("For strict scope control, this version only supports HTTPS port 443.".into());
    }

    Ok(Target { url, host, port })
}

fn resolve_public_address(target: &Target) -> Result<SocketAddr, String> {
    let addresses = (target.host.as_str(), target.port)
        .to_socket_addrs()
        .map_err(|error| format!("DNS resolution failed: {error}"))?
        .collect::<Vec<_>>();

    if addresses.is_empty() {
        return Err("The hostname did not resolve to an IP address.".into());
    }

    // Reject the entire hostname if even one answer is private/reserved. The selected
    // public address is pinned in reqwest so a later DNS answer cannot silently change it.
    if addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(
            "DNS returned a private, local or reserved IP address. Assessment cancelled."
                .into(),
        );
    }

    addresses
        .first()
        .copied()
        .ok_or_else(|| "No usable DNS address was found.".to_string())
}

fn in_ipv4_range(ip: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    let value = u32::from(ip);
    let network_value = u32::from(network);
    let mask = if prefix == 0 { 0 } else { u32::MAX << (32 - prefix) };
    (value & mask) == (network_value & mask)
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let blocked = [
        (Ipv4Addr::new(0, 0, 0, 0), 8),
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(127, 0, 0, 0), 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(192, 31, 196, 0), 24),
        (Ipv4Addr::new(192, 52, 193, 0), 24),
        (Ipv4Addr::new(192, 88, 99, 0), 24),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
        (Ipv4Addr::new(192, 175, 48, 0), 24),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4),
    ];

    !blocked
        .iter()
        .any(|(network, prefix)| in_ipv4_range(ip, *network, *prefix))
}

fn in_ipv6_prefix(ip: std::net::Ipv6Addr, network: std::net::Ipv6Addr, prefix: u8) -> bool {
    let value = u128::from(ip);
    let network_value = u128::from(network);
    let mask = if prefix == 0 { 0 } else { u128::MAX << (128 - prefix) };
    (value & mask) == (network_value & mask)
}

fn is_public_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();

    // Treat IPv4-mapped IPv6 according to the embedded IPv4 address.
    if segments[0] == 0
        && segments[1] == 0
        && segments[2] == 0
        && segments[3] == 0
        && segments[4] == 0
        && segments[5] == 0xffff
    {
        let embedded = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return is_public_ipv4(embedded);
    }

    // Only global-unicast 2000::/3 is considered. Additional special-purpose
    // ranges inside that block are denied conservatively.
    if !in_ipv6_prefix(
        ip,
        std::net::Ipv6Addr::new(0x2000, 0, 0, 0, 0, 0, 0, 0),
        3,
    ) {
        return false;
    }

    let blocked = [
        (std::net::Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 23),
        (std::net::Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
        (std::net::Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16),
        (std::net::Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
        (std::net::Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
        (std::net::Ipv6Addr::new(0x0064, 0xff9b, 1, 0, 0, 0, 0, 0), 48),
        (std::net::Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64),
    ];

    !blocked
        .iter()
        .any(|(network, prefix)| in_ipv6_prefix(ip, *network, *prefix))
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn build_client(target: &Target, pinned_address: SocketAddr) -> Result<Client, String> {
    Client::builder()
        .timeout(Duration::from_secs(REQUEST_TIMEOUT_SECS))
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .redirect(Policy::none())
        .user_agent(concat!("WHONEX/", env!("CARGO_PKG_VERSION"), " authorized-assessment"))
        .resolve(&target.host, pinned_address)
        .build()
        .map_err(|error| format!("HTTP client initialization failed: {error}"))
}

fn issue_request(
    client: &Client,
    method: Method,
    url: &Url,
    body_limit: usize,
    limiter: &mut RequestLimiter,
) -> Result<ResponseSnapshot, String> {
    limiter.wait_turn();
    let started = Instant::now();

    let response = client
        .request(method.clone(), url.clone())
        .header("Accept", "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.5")
        .send()
        .map_err(|error| format!("Network/TLS request failed: {error}"))?;

    snapshot_response(response, body_limit, started, limiter)
}

fn snapshot_response(
    response: Response,
    body_limit: usize,
    started: Instant,
    limiter: &mut RequestLimiter,
) -> Result<ResponseSnapshot, String> {
    let status = response.status().as_u16();
    let headers = response.headers().clone();
    let mut body = Vec::new();
    let mut body_truncated = false;

    if body_limit > 0 {
        let mut limited = response.take((body_limit as u64).saturating_add(1));
        limited
            .read_to_end(&mut body)
            .map_err(|error| format!("Could not read the limited response body: {error}"))?;
        if body.len() > body_limit {
            body.truncate(body_limit);
            body_truncated = true;
        }
    }

    let duration = started.elapsed();
    limiter.observe(duration, status);

    Ok(ResponseSnapshot {
        status,
        headers,
        bytes_read: body.len(),
        body,
        body_truncated,
        duration_ms: duration.as_millis(),
    })
}

fn perform_scan(
    target: &Target,
    selected: Vec<u8>,
    checks: Vec<String>,
) -> Result<WebReport, String> {
    let pinned_address = resolve_public_address(target)?;
    let client = build_client(target, pinned_address)?;
    let started_at_unix = now_unix();

    let mut report = WebReport {
        schema_version: "1.0".to_string(),
        tool: "WHONEX".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        target: target.url.to_string(),
        scope: format!("{}:{} (exact hostname only)", target.host, target.port),
        authorization_self_attested: true,
        started_at_unix,
        completed_at_unix: started_at_unix,
        request_budget: MAX_REQUESTS,
        requests_attempted: 0,
        summary: ReportSummary::default(),
        checks,
        findings: Vec::new(),
        request_log: Vec::new(),
        notes: Vec::new(),
        limitations: vec![
            "This is an external, low-impact assessment, not a complete penetration test.".into(),
            "No authentication, account-role, IDOR, SQL injection, XSS or business-logic exploit tests are performed.".into(),
            "Forms are identified but never submitted. No records are created, changed or deleted.".into(),
            "Only the exact hostname on HTTPS port 443 is in scope; subdomains are excluded.".into(),
            "The root HTML response is read only up to a fixed byte limit for same-host link discovery; body contents are not stored in the report.".into(),
            "TLS certificate/hostname validation is enforced by the HTTP library; cipher-suite and protocol enumeration are not performed.".into(),
            "DNS/IP screening blocks common private and special-use ranges, but it is not a complete SSRF defense or an ownership verification system.".into(),
            "CSP directive quality, CORS behavior, API authorization and application business logic are not validated by this version.".into(),
            "A clean result does not prove that the website is secure or free of vulnerabilities.".into(),
        ],
    };

    report.notes.push(format!(
        "DNS resolved to {}; the selected address was pinned for the HTTP session.",
        pinned_address.ip()
    ));
    report.notes.push(
        "All HTTP requests use GET or HEAD. Redirects are not followed.".into(),
    );

    let mut limiter = RequestLimiter::new();
    let mut attempted_urls = HashSet::new();

    // The root request is the only request required for every run.
    report.requests_attempted += 1;
    attempted_urls.insert(target.url.as_str().to_string());
    let root_body_limit = if selected.contains(&4) {
        MAX_ROOT_BODY_BYTES
    } else {
        0
    };
    let root = match issue_request(
        &client,
        Method::GET,
        &target.url,
        root_body_limit,
        &mut limiter,
    ) {
        Ok(snapshot) => {
            report.request_log.push(request_record(
                "GET",
                &target.url,
                &snapshot,
                "Root page and response security configuration",
            ));
            snapshot
        }
        Err(error) => {
            report.request_log.push(RequestRecord {
                method: "GET".into(),
                url: target.url.to_string(),
                status: None,
                duration_ms: None,
                response_bytes_read: 0,
                purpose: "Root page and response security configuration".into(),
                outcome: error.clone(),
            });
            return Err(error);
        }
    };

    report.notes.push(format!("Root endpoint returned HTTP {}.", root.status));
    report.notes.push(format!(
        "TLS certificate and hostname validation succeeded for the HTTPS connection to {}.",
        target.host
    ));

    // Do not assess access-gateway or error responses as if they were the real app.
    if !(200..300).contains(&root.status) {
        match root.status {
            301..=399 => report.notes.push(
                "The root endpoint returned a redirect. WHONEX did not follow it; the redirect destination was not assessed.".into(),
            ),
            401 | 403 => report.notes.push(
                "The root endpoint returned an authorization/access-denied response. Security-header and cookie findings were intentionally suppressed because this may be an access gateway rather than the application response.".into(),
            ),
            429 => report.notes.push(
                "The server rate-limited the assessment (HTTP 429). No further requests were sent.".into(),
            ),
            500..=599 => report.notes.push(
                "The server returned an HTTP 5xx error. No further requests were sent to avoid adding load.".into(),
            ),
            _ => report.notes.push(
                "The root response was not a successful 2xx application response. Application-level checks were skipped.".into(),
            ),
        }
        finalize_report(&mut report);
        return Ok(report);
    }

    if selected.contains(&1) {
        analyze_security_headers(&root.headers, &target.url, "GET", &mut report);
    }
    if selected.contains(&2) {
        analyze_cookies(&root.headers, &target.url, &mut report);
    }

    let content_type = header_value(&root.headers, "content-type").unwrap_or_default();
    let is_html = content_type.to_ascii_lowercase().contains("text/html")
        || content_type.to_ascii_lowercase().contains("application/xhtml+xml");

    if is_html && !root.body.is_empty() {
        let html = String::from_utf8_lossy(&root.body);
        let form_count = count_case_insensitive(&html, "<form");
        if form_count > 0 {
            report.notes.push(format!(
                "The root HTML contains approximately {} form element(s). WHONEX did not submit forms or test credentials.",
                form_count
            ));
        }
        if root.body_truncated {
            report.notes.push(
                "The root HTML exceeded the configured read limit; link discovery used only the first bounded portion.".into(),
            );
        }
    } else if !is_html {
        report.notes.push(format!(
            "Root Content-Type was '{}'; HTML link discovery was skipped.",
            safe_compact(&content_type, 120)
        ));
    }

    let mut stop = false;

    // Public metadata is read-only. Bodies are capped and never written to disk.
    if selected.contains(&3) && report.requests_attempted < MAX_REQUESTS {
        let metadata_paths = [
            ("/.well-known/security.txt", "Public security contact metadata"),
            ("/security.txt", "Legacy public security contact metadata"),
            ("/robots.txt", "Public robots metadata"),
        ];

        for (path, purpose) in metadata_paths {
            if report.requests_attempted >= MAX_REQUESTS || stop {
                break;
            }
            let url = path_url(target, path)?;
            if !attempted_urls.insert(url.as_str().to_string()) {
                continue;
            }

            report.requests_attempted += 1;
            match issue_request(
                &client,
                Method::GET,
                &url,
                MAX_METADATA_BODY_BYTES,
                &mut limiter,
            ) {
                Ok(snapshot) => {
                    report.request_log.push(request_record("GET", &url, &snapshot, purpose));
                    match snapshot.status {
                        200..=299 => {
                            if path.ends_with("robots.txt") {
                                let body = String::from_utf8_lossy(&snapshot.body);
                                let directives = count_nonempty_robots_disallow(&body);
                                report.notes.push(format!(
                                    "robots.txt is publicly reachable (HTTP {}). It contains {} non-empty Disallow directive(s); these paths are not automatically treated as vulnerabilities.",
                                    snapshot.status, directives
                                ));
                            } else {
                                report.notes.push(format!(
                                    "{} is publicly reachable (HTTP {}). Its contents were not copied into the report.",
                                    path, snapshot.status
                                ));
                            }
                        }
                        401 | 403 => report.notes.push(format!(
                            "{} returned HTTP {}; access is restricted.", path, snapshot.status
                        )),
                        404 | 410 => report.notes.push(format!(
                            "{} was not found (HTTP {}).", path, snapshot.status
                        )),
                        429 | 500..=599 => {
                            report.notes.push(format!(
                                "{} returned HTTP {}; remaining requests were stopped.", path, snapshot.status
                            ));
                            stop = true;
                        }
                        300..=399 => report.notes.push(format!(
                            "{} returned a redirect; it was not followed.", path
                        )),
                        other => report.notes.push(format!(
                            "{} returned HTTP {}.", path, other
                        )),
                    }
                }
                Err(error) => {
                    report.request_log.push(failed_request_record("GET", &url, purpose, &error));
                    report.notes.push(format!("Metadata request stopped: {}", error));
                    stop = true;
                }
            }
        }
    }

    // Discover a few ordinary same-host navigation links, then issue HEAD only.
    // No forms, query strings, logout links or state-changing-looking routes are requested.
    if selected.contains(&4) && !stop && report.requests_attempted < MAX_REQUESTS {
        if is_html {
            let html = String::from_utf8_lossy(&root.body);
            let links = extract_safe_same_host_links(&html, &target.url, target);
            if links.is_empty() {
                report.notes.push("No eligible same-host navigation links were discovered in the bounded root HTML.".into());
            } else {
                report.notes.push(format!(
                    "Discovered {} eligible same-host navigation link(s); at most {} were checked using HEAD only.",
                    links.len(), MAX_DISCOVERED_PAGES
                ));
            }

            for url in links.into_iter().take(MAX_DISCOVERED_PAGES) {
                if report.requests_attempted >= MAX_REQUESTS || stop {
                    break;
                }
                if !attempted_urls.insert(url.as_str().to_string()) {
                    continue;
                }
                report.requests_attempted += 1;
                match issue_request(&client, Method::HEAD, &url, 0, &mut limiter) {
                    Ok(snapshot) => {
                        report.request_log.push(request_record(
                            "HEAD",
                            &url,
                            &snapshot,
                            "Same-host navigation endpoint response headers",
                        ));
                        match snapshot.status {
                            200..=299 => {
                                report.notes.push(format!(
                                    "Discovered page responded with HTTP {}: {}",
                                    snapshot.status,
                                    url.path()
                                ));
                                if selected.contains(&1) {
                                    report.notes.push(format!(
                                        "Security headers on {} were not scored from HEAD because some servers handle HEAD differently from GET.",
                                        url.path()
                                    ));
                                }
                            }
                            401 | 403 => report.notes.push(format!(
                                "Discovered page is access restricted (HTTP {}): {}",
                                snapshot.status,
                                url.path()
                            )),
                            429 | 500..=599 => {
                                report.notes.push(format!(
                                    "Discovered page returned HTTP {}; remaining requests were stopped.",
                                    snapshot.status
                                ));
                                stop = true;
                            }
                            300..=399 => report.notes.push(format!(
                                "Discovered page returned a redirect; it was not followed: {}",
                                url.path()
                            )),
                            other => report.notes.push(format!(
                                "Discovered page returned HTTP {}: {}",
                                other,
                                url.path()
                            )),
                        }
                    }
                    Err(error) => {
                        report.request_log.push(failed_request_record(
                            "HEAD",
                            &url,
                            "Same-host navigation endpoint response headers",
                            &error,
                        ));
                        report.notes.push(format!(
                            "Page discovery stopped after a network error: {}",
                            error
                        ));
                        stop = true;
                    }
                }
            }
        } else {
            report.notes.push("Same-host page discovery requires an HTML root response; skipped.".into());
        }
    }

    if report.requests_attempted >= MAX_REQUESTS {
        report.notes.push("The hard request budget was reached; no additional requests were sent.".into());
    }
    if report.findings.is_empty() {
        report.notes.push(
            "No observations matched the selected checks. This is not proof that the website is vulnerability-free.".into(),
        );
    }

    finalize_report(&mut report);
    Ok(report)
}

fn path_url(target: &Target, path: &str) -> Result<Url, String> {
    let mut url = target.url.clone();
    url.set_path(path);
    url.set_query(None);
    url.set_fragment(None);
    if url.host_str() != Some(target.host.as_str()) || url.port_or_known_default() != Some(443) {
        return Err("Internal scope validation failed while building a request URL.".into());
    }
    Ok(url)
}

fn request_record(method: &str, url: &Url, snapshot: &ResponseSnapshot, purpose: &str) -> RequestRecord {
    RequestRecord {
        method: method.to_string(),
        url: url.to_string(),
        status: Some(snapshot.status),
        duration_ms: Some(snapshot.duration_ms),
        response_bytes_read: snapshot.bytes_read,
        purpose: purpose.to_string(),
        outcome: if snapshot.body_truncated {
            "Response read reached the configured body limit.".into()
        } else {
            "Response received.".into()
        },
    }
}

fn failed_request_record(method: &str, url: &Url, purpose: &str, error: &str) -> RequestRecord {
    RequestRecord {
        method: method.to_string(),
        url: url.to_string(),
        status: None,
        duration_ms: None,
        response_bytes_read: 0,
        purpose: purpose.to_string(),
        outcome: safe_compact(error, 240),
    }
}

fn analyze_security_headers(headers: &HeaderMap, url: &Url, method: &str, report: &mut WebReport) {
    let affected = url.to_string();
    let evidence_prefix = format!("{} response for {}", method, url.path());

    match header_value(headers, "strict-transport-security") {
        None => add_finding(
            report,
            "WHX-WEB-001",
            "Hardening observation",
            "Informational",
            "High",
            "Observed directly",
            "HSTS header was not present",
            &affected,
            &format!("{} did not include Strict-Transport-Security.", evidence_prefix),
            "Browsers may not retain an explicit HSTS policy for future visits. This is a hardening recommendation, not proof of an exploitable vulnerability.",
            "After confirming HTTPS works across the intended host scope, configure an appropriate Strict-Transport-Security max-age policy.",
        ),
        Some(value) => {
            let max_age = value
                .split(';')
                .map(str::trim)
                .find_map(|part| {
                    let mut pair = part.splitn(2, '=');
                    let name = pair.next()?.trim();
                    let val = pair.next()?.trim();
                    if name.eq_ignore_ascii_case("max-age") {
                        val.parse::<u64>().ok()
                    } else {
                        None
                    }
                });
            if max_age == Some(0) || max_age.is_none() {
                add_finding(
                    report,
                    "WHX-WEB-001",
                    "Potential configuration weakness",
                    "Low",
                    "High",
                    "Observed directly",
                    "HSTS policy is ineffective or malformed",
                    &affected,
                    &format!("{} returned Strict-Transport-Security: {}", evidence_prefix, safe_compact(&value, 180)),
                    "The browser may not receive an effective instruction to enforce HTTPS on later visits.",
                    "Use a valid max-age value and verify the policy against the site's deployment and subdomain requirements.",
                );
            }
        }
    }

    let csp = header_value(headers, "content-security-policy");
    let csp_report_only = header_value(headers, "content-security-policy-report-only");
    if csp.as_deref().map(|value| value.trim().is_empty()).unwrap_or(true) {
        let evidence = if csp_report_only.is_some() {
            format!("{} had Content-Security-Policy-Report-Only but no enforcing Content-Security-Policy header.", evidence_prefix)
        } else {
            format!("{} did not include Content-Security-Policy.", evidence_prefix)
        };
        add_finding(
            report,
            "WHX-WEB-002",
            "Hardening observation",
            "Informational",
            "High",
            "Observed directly",
            "No enforcing Content Security Policy was observed",
            &affected,
            &evidence,
            "The browser may have fewer restrictions on which resources the page can load. Report-Only policies monitor violations but do not enforce them.",
            "Design and deploy a policy appropriate for the application's required scripts, styles, images, frames and API connections. Test it before enforcement.",
        );
    }

    let nosniff = header_value(headers, "x-content-type-options")
        .map(|value| value.trim().eq_ignore_ascii_case("nosniff"))
        .unwrap_or(false);
    if !nosniff {
        add_finding(
            report,
            "WHX-WEB-003",
            "Hardening observation",
            "Low",
            "High",
            "Observed directly",
            "X-Content-Type-Options nosniff was not observed",
            &affected,
            &format!("{} did not return X-Content-Type-Options: nosniff.", evidence_prefix),
            "Some browsers may perform MIME-type sniffing in circumstances where the declared content type should be respected.",
            "Set X-Content-Type-Options: nosniff on responses where appropriate, especially static and user-controlled content.",
        );
    }

    let referrer_valid = header_value(headers, "referrer-policy")
        .map(|value| {
            value.split(',').any(|item| {
                matches!(
                    item.trim().to_ascii_lowercase().as_str(),
                    "no-referrer"
                        | "no-referrer-when-downgrade"
                        | "origin"
                        | "origin-when-cross-origin"
                        | "same-origin"
                        | "strict-origin"
                        | "strict-origin-when-cross-origin"
                        | "unsafe-url"
                )
            })
        })
        .unwrap_or(false);
    if !referrer_valid {
        add_finding(
            report,
            "WHX-WEB-004",
            "Hardening observation",
            "Informational",
            "High",
            "Observed directly",
            "A recognized Referrer-Policy was not observed",
            &affected,
            &format!("{} did not return a recognized Referrer-Policy value.", evidence_prefix),
            "Browsers may send referrer information according to their defaults, which may not match the site's privacy expectations.",
            "Choose an explicit Referrer-Policy suitable for the application, commonly strict-origin-when-cross-origin or no-referrer.",
        );
    }

    if header_value(headers, "permissions-policy").is_none() {
        add_finding(
            report,
            "WHX-WEB-005",
            "Hardening observation",
            "Informational",
            "High",
            "Observed directly",
            "Permissions-Policy header was not observed",
            &affected,
            &format!("{} did not include Permissions-Policy.", evidence_prefix),
            "Browser features are not explicitly restricted by this response policy. The practical impact depends on which features the application uses.",
            "Define a least-privilege Permissions-Policy for browser features the application does not need.",
        );
    }

    let xfo = header_value(headers, "x-frame-options");
    let csp_has_frame_ancestors = csp
        .as_deref()
        .map(has_frame_ancestors)
        .unwrap_or(false);
    let xfo_valid = xfo
        .as_deref()
        .map(|value| {
            let token = value.trim().to_ascii_uppercase();
            token == "DENY" || token == "SAMEORIGIN"
        })
        .unwrap_or(false);

    if xfo.is_some() && !xfo_valid && !csp_has_frame_ancestors {
        add_finding(
            report,
            "WHX-WEB-006",
            "Potential configuration weakness",
            "Low",
            "High",
            "Observed directly",
            "X-Frame-Options value was not recognized",
            &affected,
            &format!("{} returned X-Frame-Options: {}", evidence_prefix, safe_compact(xfo.as_deref().unwrap_or_default(), 100)),
            "An unrecognized or obsolete frame policy may not provide the expected framing restriction.",
            "Use CSP frame-ancestors and, where needed for legacy compatibility, X-Frame-Options: DENY or SAMEORIGIN.",
        );
    } else if xfo.is_none() && !csp_has_frame_ancestors {
        add_finding(
            report,
            "WHX-WEB-006",
            "Hardening observation",
            "Informational",
            "High",
            "Observed directly",
            "No recognized frame protection policy was observed",
            &affected,
            &format!("{} had neither X-Frame-Options nor an enforcing CSP frame-ancestors directive.", evidence_prefix),
            "The response does not visibly restrict framing. Whether clickjacking is exploitable depends on the page's functionality and user interaction.",
            "Configure CSP frame-ancestors with the intended allowed origins. X-Frame-Options may be retained for compatibility.",
        );
    }

    if let Some(server) = header_value(headers, "server") {
        add_finding(
            report,
            "WHX-WEB-007",
            "Information disclosure observation",
            "Informational",
            "High",
            "Observed directly",
            "Server identification header is exposed",
            &affected,
            &format!("{} returned Server: {}", evidence_prefix, safe_compact(&server, 100)),
            "The header may reveal server software or version information. Exposure alone is not proof of a vulnerability.",
            "Consider minimizing unnecessary product and version details in public response headers.",
        );
    }

    if let Some(powered) = header_value(headers, "x-powered-by") {
        add_finding(
            report,
            "WHX-WEB-008",
            "Information disclosure observation",
            "Informational",
            "High",
            "Observed directly",
            "Technology identification header is exposed",
            &affected,
            &format!("{} returned X-Powered-By: {}", evidence_prefix, safe_compact(&powered, 100)),
            "The header may disclose implementation details that help fingerprint the application. Exposure alone is not proof of a vulnerability.",
            "Remove unnecessary technology-identification headers where practical.",
        );
    }
}

fn analyze_cookies(headers: &HeaderMap, url: &Url, report: &mut WebReport) {
    let mut cookie_count = 0usize;
    for value in headers.get_all(SET_COOKIE).iter() {
        let Ok(raw) = value.to_str() else { continue };
        cookie_count += 1;

        let mut pieces = raw.split(';');
        let first = pieces.next().unwrap_or_default().trim();
        let name = first.split('=').next().unwrap_or_default().trim();
        if name.is_empty() {
            continue;
        }
        // The cookie name is safe to show; the cookie value is never retained.
        let cookie_affected = format!("{} [cookie: {}]", url, safe_compact(name, 60));

        let lower_name = name.to_ascii_lowercase();
        let sensitive_name = ["session", "sess", "auth", "token", "jwt"]
            .iter()
            .any(|marker| lower_name.contains(marker))
            || lower_name == "sid"
            || lower_name.ends_with("_sid")
            || lower_name.ends_with("-sid");
        let attributes = pieces.map(|part| part.trim().to_ascii_lowercase()).collect::<Vec<_>>();
        let has_secure = attributes.iter().any(|item| item == "secure");
        let has_httponly = attributes.iter().any(|item| item == "httponly");
        let same_site = attributes
            .iter()
            .find_map(|item| item.strip_prefix("samesite="));

        if !has_secure {
            add_finding(
                report,
                "WHX-WEB-101",
                if sensitive_name { "Potential cookie security weakness" } else { "Cookie hardening observation" },
                if sensitive_name { "Low" } else { "Informational" },
                "High",
                "Cookie attribute absence observed; cookie purpose inferred from its name only",
                if sensitive_name { "A potentially sensitive cookie lacks Secure" } else { "A cookie lacks Secure" },
                &cookie_affected,
                &format!("Set-Cookie '{}' did not include the Secure attribute. The cookie value was not stored.", safe_compact(name, 80)),
                "Without Secure, a cookie may be sent over an unencrypted HTTP connection if the application is reachable over HTTP or through an unsafe deployment path.",
                "Set Secure on cookies that should only be transmitted over HTTPS. Confirm behavior across the full intended deployment.",
            );
        }

        if !has_httponly {
            add_finding(
                report,
                "WHX-WEB-102",
                if sensitive_name { "Potential cookie security weakness" } else { "Cookie hardening observation" },
                if sensitive_name { "Low" } else { "Informational" },
                "High",
                "Cookie attribute absence observed; cookie purpose inferred from its name only",
                if sensitive_name { "A potentially sensitive cookie lacks HttpOnly" } else { "A cookie lacks HttpOnly" },
                &cookie_affected,
                &format!("Set-Cookie '{}' did not include HttpOnly. The cookie value was not stored.", safe_compact(name, 80)),
                "If the cookie is used for authentication or session management, client-side scripts may be able to read it. The actual impact depends on cookie purpose and application design.",
                "Set HttpOnly on session and authentication cookies unless client-side access is an intentional requirement.",
            );
        }

        if same_site.is_none() {
            add_finding(
                report,
                "WHX-WEB-103",
                "Cookie hardening observation",
                "Informational",
                "High",
                "Observed directly",
                "Cookie SameSite attribute was not observed",
                &cookie_affected,
                &format!("Set-Cookie '{}' did not include SameSite. The cookie value was not stored.", safe_compact(name, 80)),
                "Cross-site cookie sending behavior may rely on browser defaults rather than an explicit application policy.",
                "Set an intentional SameSite value (Lax, Strict or None) based on the application's cross-site authentication and integration needs.",
            );
        } else if same_site == Some("none") && !has_secure {
            add_finding(
                report,
                "WHX-WEB-104",
                "Potential cookie configuration weakness",
                "Low",
                "High",
                "Observed directly",
                "SameSite=None cookie lacks Secure",
                &cookie_affected,
                &format!("Set-Cookie '{}' specified SameSite=None without Secure. The cookie value was not stored.", safe_compact(name, 80)),
                "Modern browsers require Secure for SameSite=None cookies; the cookie may be rejected or not behave as intended.",
                "Add Secure when SameSite=None is required, and verify the intended cross-site behavior.",
            );
        }
    }

    report.notes.push(format!(
        "Cookie check observed {} Set-Cookie header(s). Cookie values were not stored or printed.",
        cookie_count
    ));
}

fn header_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn has_frame_ancestors(csp: &str) -> bool {
    csp.split(';').any(|directive| {
        let mut words = directive.split_whitespace();
        words
            .next()
            .map(|name| name.eq_ignore_ascii_case("frame-ancestors"))
            .unwrap_or(false)
    })
}

#[allow(clippy::too_many_arguments)]
fn add_finding(
    report: &mut WebReport,
    id: &str,
    classification: &str,
    severity: &str,
    confidence: &str,
    validation: &str,
    title: &str,
    affected_url: &str,
    evidence: &str,
    impact: &str,
    recommendation: &str,
) {
    if report
        .findings
        .iter()
        .any(|existing| existing.id == id && existing.affected_url == affected_url)
    {
        return;
    }

    report.findings.push(WebFinding {
        id: id.to_string(),
        classification: classification.to_string(),
        severity: severity.to_string(),
        confidence: confidence.to_string(),
        validation: validation.to_string(),
        title: title.to_string(),
        affected_url: affected_url.to_string(),
        evidence: evidence.to_string(),
        impact: impact.to_string(),
        recommendation: recommendation.to_string(),
    });
}

fn extract_safe_same_host_links(html: &str, base: &Url, target: &Target) -> Vec<Url> {
    let lower = html.to_ascii_lowercase();
    let mut position = 0usize;
    let mut links = Vec::new();
    let mut seen = HashSet::new();

    while let Some(relative) = lower[position..].find("<a") {
        let start = position + relative;
        let after_name = start + 2;
        let next = lower.as_bytes().get(after_name).copied();
        if !matches!(next, Some(b'>') | Some(b'/') | Some(b' ') | Some(b'\n') | Some(b'\r') | Some(b'\t')) {
            position = after_name;
            continue;
        }

        let Some(end_relative) = lower[after_name..].find('>') else { break };
        let end = after_name + end_relative;
        let tag = &html[start..=end];
        position = end + 1;

        let Some(raw_href) = html_attribute(tag, "href") else { continue };
        let raw_href = raw_href.trim();
        if raw_href.is_empty() || raw_href.starts_with('#') {
            continue;
        }

        let Ok(mut candidate) = base.join(raw_href) else { continue };
        if candidate.scheme() != "https"
            || candidate.host_str() != Some(target.host.as_str())
            || candidate.port_or_known_default() != Some(443)
            || !candidate.username().is_empty()
            || candidate.password().is_some()
            || candidate.query().is_some()
        {
            continue;
        }
        candidate.set_fragment(None);

        if is_state_changing_looking_path(candidate.path()) {
            continue;
        }
        if candidate.path().len() > 256 || candidate.as_str() == base.as_str() {
            continue;
        }
        if seen.insert(candidate.as_str().to_string()) {
            links.push(candidate);
        }
        if links.len() >= MAX_DISCOVERED_PAGES {
            break;
        }
    }

    links
}

fn html_attribute(tag: &str, wanted: &str) -> Option<String> {
    let bytes = tag.as_bytes();
    let mut index = 1usize;

    while index < bytes.len() {
        while index < bytes.len() && (bytes[index].is_ascii_whitespace() || bytes[index] == b'/') {
            index += 1;
        }
        let name_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && bytes[index] != b'='
            && bytes[index] != b'>'
            && bytes[index] != b'/'
        {
            index += 1;
        }
        if name_start == index {
            index += 1;
            continue;
        }
        let name = &tag[name_start..index];
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            continue;
        }
        index += 1;
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }

        let value = if bytes[index] == b'"' || bytes[index] == b'\'' {
            let quote = bytes[index];
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != quote {
                index += 1;
            }
            let value_end = index;
            if index < bytes.len() {
                index += 1;
            }
            &tag[value_start..value_end]
        } else {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() && bytes[index] != b'>' {
                index += 1;
            }
            &tag[value_start..index]
        };

        if name.eq_ignore_ascii_case(wanted) {
            return Some(value.to_string());
        }
    }

    None
}

fn is_state_changing_looking_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    let blocked_segments = [
        "logout", "log-out", "signout", "sign-out", "delete", "remove", "destroy",
        "checkout", "purchase", "payment", "unsubscribe", "withdraw", "transfer",
    ];
    lower
        .split('/')
        .any(|segment| blocked_segments.iter().any(|blocked| segment == *blocked))
}

fn count_case_insensitive(text: &str, needle: &str) -> usize {
    text.to_ascii_lowercase().matches(&needle.to_ascii_lowercase()).count()
}

fn count_nonempty_robots_disallow(body: &str) -> usize {
    body.lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            let lower = trimmed.to_ascii_lowercase();
            lower
                .strip_prefix("disallow:")
                .map(str::trim)
                .filter(|value| !value.is_empty())
        })
        .count()
}

fn safe_compact(value: &str, max_chars: usize) -> String {
    let cleaned = value
        .chars()
        .filter(|character| !character.is_control())
        .collect::<String>();
    if cleaned.chars().count() <= max_chars {
        cleaned
    } else {
        let shortened = cleaned.chars().take(max_chars).collect::<String>();
        format!("{}…", shortened)
    }
}

fn finalize_report(report: &mut WebReport) {
    report.completed_at_unix = now_unix();
    let mut summary = ReportSummary::default();
    summary.total_observations = report.findings.len();

    for finding in &report.findings {
        match finding.severity.as_str() {
            "Low" => summary.low += 1,
            _ => summary.informational += 1,
        }
        if finding.validation == "Requires manual verification" {
            summary.needs_manual_verification += 1;
        }
    }

    // This version deliberately performs no exploit verification, so it never
    // claims a confirmed vulnerability based solely on passive observations.
    summary.confirmed_vulnerabilities = 0;
    report.summary = summary;
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn print_report(report: &WebReport) {
    println!();
    println!("====================================================");
    println!("                 WEB ASSESSMENT");
    println!("====================================================");
    println!("Target: {}", report.target);
    println!("Scope: {}", report.scope);
    println!("Requests attempted: {}/{}", report.requests_attempted, report.request_budget);
    println!("Observations: {}", report.summary.total_observations);
    println!("Confirmed vulnerabilities: {}", report.summary.confirmed_vulnerabilities);
    println!("Low: {} | Informational: {}", report.summary.low, report.summary.informational);
    println!("----------------------------------------------------");

    if report.findings.is_empty() {
        println!("No observations were generated by the selected checks.");
    } else {
        for finding in &report.findings {
            println!("[{}] {}", finding.severity, finding.title);
            println!("ID: {}", finding.id);
            println!("Type: {}", finding.classification);
            println!("Confidence: {}", finding.confidence);
            println!("Validation: {}", finding.validation);
            println!("Affected: {}", finding.affected_url);
            println!("Evidence: {}", finding.evidence);
            println!("Impact: {}", finding.impact);
            println!("Recommendation: {}", finding.recommendation);
            println!("----------------------------------------------------");
        }
    }

    println!("REQUEST LOG");
    for request in &report.request_log {
        let status = request.status.map(|value| value.to_string()).unwrap_or_else(|| "N/A".into());
        let duration = request.duration_ms.map(|value| format!("{} ms", value)).unwrap_or_else(|| "N/A".into());
        println!("{} {} | HTTP {} | {} | {}", request.method, request.url, status, duration, request.purpose);
    }

    println!("NOTES");
    for note in &report.notes {
        println!("- {}", note);
    }

    println!("LIMITATIONS");
    for limitation in &report.limitations {
        println!("- {}", limitation);
    }

    println!("----------------------------------------------------");
    println!("No forms were submitted and no website records were intentionally changed.");
    println!("This report describes observed responses, not a guarantee of security.");
}

fn save_report(report: &WebReport, path: &Path) -> Result<(), String> {
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("Could not create report file (existing files are not overwritten): {error}"))?;

    serde_json::to_writer_pretty(file, report)
        .map_err(|error| format!("Could not serialize JSON report: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_https_origin_on_standard_port() {
        let target = parse_target("https://example.com/").unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
    }

    #[test]
    fn rejects_http_target() {
        assert!(parse_target("http://example.com/").is_err());
    }

    #[test]
    fn rejects_nonstandard_port() {
        assert!(parse_target("https://example.com:8443/").is_err());
    }

    #[test]
    fn rejects_path_query_and_fragment() {
        assert!(parse_target("https://example.com/login").is_err());
        assert!(parse_target("https://example.com/?a=1").is_err());
        assert!(parse_target("https://example.com/#top").is_err());
    }

    #[test]
    fn rejects_ip_and_local_hosts() {
        assert!(parse_target("https://127.0.0.1/").is_err());
        assert!(parse_target("https://localhost/").is_err());
    }

    #[test]
    fn blocks_private_and_documentation_ipv4() {
        assert!(!is_public_ipv4(Ipv4Addr::new(10, 1, 2, 3)));
        assert!(!is_public_ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert!(!is_public_ipv4(Ipv4Addr::new(198, 51, 100, 10)));
        assert!(is_public_ipv4(Ipv4Addr::new(1, 1, 1, 1)));
    }

    #[test]
    fn blocks_non_global_and_documentation_ipv6() {
        assert!(!is_public_ipv6("::1".parse().unwrap()));
        assert!(!is_public_ipv6("2001:db8::1".parse().unwrap()));
        assert!(is_public_ipv6("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn parses_selection_and_deduplicates() {
        assert_eq!(parse_selection("1,2,2,4").unwrap(), vec![1, 2, 4]);
        assert_eq!(parse_selection("").unwrap(), vec![1, 2, 3, 4]);
        assert!(parse_selection("5").is_err());
        assert!(parse_selection("abc").is_err());
    }

    #[test]
    fn detects_frame_ancestors_directive() {
        assert!(has_frame_ancestors("default-src 'self'; frame-ancestors 'none'"));
        assert!(!has_frame_ancestors("default-src 'self'; img-src https:"));
    }

    #[test]
    fn reads_html_href_attribute() {
        assert_eq!(html_attribute("<a class='nav' href=\"/about\">", "href"), Some("/about".into()));
        assert_eq!(html_attribute("<a href='/contact'>", "href"), Some("/contact".into()));
    }

    #[test]
    fn skips_state_changing_looking_paths() {
        assert!(is_state_changing_looking_path("/account/logout"));
        assert!(is_state_changing_looking_path("/cart/checkout"));
        assert!(!is_state_changing_looking_path("/about-us"));
    }
}
