use reqwest::blocking::Client;
use reqwest::header::HeaderMap;
use reqwest::redirect::Policy;
use serde::Serialize;

use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use url::Url;

#[derive(Debug)]
struct Target {
    url: Url,
    host: String,
    port: u16,
}

#[derive(Serialize)]
struct WebReport {
    tool: String,
    version: String,
    target: String,
    scope: String,
    authorization_acknowledged: bool,
    started_at_unix: u64,
    requests_sent: usize,
    checks: Vec<String>,
    findings: Vec<WebFinding>,
    notes: Vec<String>,
}

#[derive(Serialize)]
struct WebFinding {
    id: String,
    severity: String,
    confidence: String,
    title: String,
    evidence: String,
    impact: String,
    recommendation: String,
}

struct ResponseSnapshot {
    status: u16,
    headers: HeaderMap,
}

pub fn run_interactive(output: Option<PathBuf>) -> Result<(), String> {
    println!();
    println!("========================================");
    println!("          WHONEX WEB ANALYST");
    println!("========================================");
    println!("Authorized, low-impact website assessment");
    println!("No file modification or data extraction.");
    println!();

    let raw_url = ask("Website URL (https://example.com): ")?;
    let target = parse_target(&raw_url)?;

    println!();
    println!("Target host: {}", target.host);
    println!("Scope: exact hostname only");
    println!("Subdomains: not included");
    println!("Redirects: not followed");
    println!();

    let authorization = ask(
        "Do you have written authorization for this exact host? Type EVET: "
    )?;

    if authorization.trim() != "EVET" {
        return Err(
            "Assessment cancelled: written authorization was not confirmed."
                .into(),
        );
    }

    let scope_confirmation = ask(
        &format!(
            "To confirm scope, type the hostname exactly ({}): ",
            target.host
        ),
    )?;

    if scope_confirmation.trim() != target.host {
        return Err("Hostname confirmation failed. Assessment cancelled.".into());
    }

    println!();
    println!("AVAILABLE CHECKS");
    println!("----------------------------------------");
    println!("1. HTTPS and security response headers");
    println!("2. Cookie security attributes");
    println!("3. Public security metadata");
    println!("----------------------------------------");
    println!("Select checks using commas, for example: 1,2,3");
    println!("Press Enter to select all three.");
    println!();

    let selection = ask("Selection: ")?;
    let selected = parse_selection(&selection)?;

    let mut checks = Vec::new();

    if selected.contains(&1) {
        checks.push("HTTPS and security response headers".to_string());
    }

    if selected.contains(&2) {
        checks.push("Cookie security attributes".to_string());
    }

    if selected.contains(&3) {
        checks.push("Public security metadata".to_string());
    }

    println!();
    println!("Starting controlled assessment...");
    println!("Maximum requests: 4");
    println!("Request interval: 700 ms");
    println!("Automatic redirect following: disabled");
    println!();

    let report = perform_scan(
        &target,
        selected,
        checks,
    )?;

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
        return Ok(vec![1, 2, 3]);
    }

    let mut selected = Vec::new();

    for item in input.split(',') {
        let number = item
            .trim()
            .parse::<u8>()
            .map_err(|_| "Invalid menu selection.".to_string())?;

        if !(1..=3).contains(&number) {
            return Err("Only options 1, 2 and 3 are available.".into());
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
    let url = Url::parse(input.trim())
        .map_err(|_| "Invalid website URL.".to_string())?;

    if url.scheme() != "https" {
        return Err(
            "Only HTTPS targets are supported in this version.".into(),
        );
    }

    if !url.username().is_empty() || url.password().is_some() {
        return Err("URLs containing credentials are not allowed.".into());
    }

    if url.path() != "/" || url.query().is_some() || url.fragment().is_some() {
        return Err(
            "Enter the website origin only, without a path, query or fragment."
                .into(),
        );
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
    {
        return Err("Local network targets are not supported.".into());
    }

    let port = url
        .port_or_known_default()
        .ok_or("Could not determine the target port.")?;

    Ok(Target { url, host, port })
}

fn resolve_public_address(target: &Target) -> Result<SocketAddr, String> {
    let addresses: Vec<SocketAddr> =
        (target.host.as_str(), target.port)
            .to_socket_addrs()
            .map_err(|error| format!("DNS resolution failed: {error}"))?
            .collect();

    if addresses.is_empty() {
        return Err("The hostname did not resolve to an address.".into());
    }

    if addresses
        .iter()
        .any(|address| !is_public_ip(address.ip()))
    {
        return Err(
            "The hostname resolves to a non-public or restricted IP address. Scan cancelled."
                .into(),
        );
    }

    Ok(addresses[0])
}

fn is_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_public_ipv4(address),
        IpAddr::V6(address) => is_public_ipv6(address),
    }
}

fn is_public_ipv4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    let a = octets[0];
    let b = octets[1];
    let c = octets[2];

    if a == 0 || a == 10 || a == 127 || a >= 224 {
        return false;
    }

    if a == 100 && (64..=127).contains(&b) {
        return false;
    }

    if a == 169 && b == 254 {
        return false;
    }

    if a == 172 && (16..=31).contains(&b) {
        return false;
    }

    if a == 192 && (b == 0 || b == 168) {
        return false;
    }

    if a == 192 && b == 88 && c == 99 {
        return false;
    }

    if a == 192 && b == 0 && c == 2 {
        return false;
    }

    if a == 198 && (b == 18 || b == 19 || b == 51 && c == 100) {
        return false;
    }

    if a == 203 && b == 0 && c == 113 {
        return false;
    }

    true
}

fn is_public_ipv6(ip: std::net::Ipv6Addr) -> bool {
    let segments = ip.segments();

    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }

    // IPv4-mapped IPv6 address.
    if segments[..5].iter().all(|value| *value == 0)
        && segments[5] == 0xffff
    {
        let ipv4 = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );

        return is_public_ipv4(ipv4);
    }

    // Only global unicast 2000::/3 is accepted.
    if segments[0] & 0xe000 != 0x2000 {
        return false;
    }

    // Documentation range 2001:db8::/32.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return false;
    }

    true
}

fn perform_scan(
    target: &Target,
    selected: Vec<u8>,
    checks: Vec<String>,
) -> Result<WebReport, String> {
    let pinned_address = resolve_public_address(target)?;

    let client = Client::builder()
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(5))
        .redirect(Policy::none())
        .user_agent("WHONEX/0.2 authorized-security-assessment")
        .resolve(&target.host, pinned_address)
        .build()
        .map_err(|error| format!("HTTP client initialization failed: {error}"))?;

    let started_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let mut report = WebReport {
        tool: "WHONEX".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        target: target.url.to_string(),
        scope: target.host.clone(),
        authorization_acknowledged: true,
        started_at_unix,
        requests_sent: 0,
        checks,
        findings: Vec::new(),
        notes: Vec::new(),
    };

    let root_response = fetch(&client, &target.url)?;
    report.requests_sent += 1;

    report.notes.push(
        "TLS certificate and hostname validation succeeded for the HTTPS connection."
            .to_string(),
    );

    report.notes.push(format!(
        "Root page returned HTTP status {}.",
        root_response.status
    ));

    if selected.contains(&1) {
        analyze_security_headers(
            &root_response.headers,
            &mut report,
        );
    }

    if selected.contains(&2) {
        analyze_cookies(
            &root_response.headers,
            &mut report,
        );
    }

    let server_requests_should_stop =
        root_response.status == 429 || root_response.status >= 500;

    if root_response.status >= 300 && root_response.status < 400 {
        report.notes.push(
            "The server returned a redirect. WHONEX did not follow it."
                .to_string(),
        );
    }

    if server_requests_should_stop {
        report.notes.push(
            "The server returned a rate-limit or server-error status. Additional requests were stopped."
                .to_string(),
        );
    }

    if selected.contains(&3) && !server_requests_should_stop {
        check_public_metadata(
            &client,
            target,
            &mut report,
        )?;
    }

    if report.findings.is_empty() {
        report.notes.push(
            "No findings matched the enabled checks. This does not prove that the website is vulnerability-free."
                .to_string(),
        );
    }

    Ok(report)
}

fn fetch(
    client: &Client,
    url: &Url,
) -> Result<ResponseSnapshot, String> {
    let response = client
        .get(url.clone())
        .header("Accept", "*/*")
        .send()
        .map_err(|error| {
            format!("Request failed. Connection or TLS verification error: {error}")
        })?;

    Ok(ResponseSnapshot {
        status: response.status().as_u16(),
        headers: response.headers().clone(),
    })
}

fn analyze_security_headers(
    headers: &HeaderMap,
    report: &mut WebReport,
) {
    check_header(
        headers,
        report,
        "strict-transport-security",
        "WHX-WEB-001",
        "HTTP Strict Transport Security is missing",
        "Low",
        "The HTTPS response did not include the Strict-Transport-Security header.",
        "Some browsers may not be instructed to enforce HTTPS on future visits.",
        "Configure an appropriate HSTS policy after confirming all required subdomains support HTTPS.",
    );

    check_header(
        headers,
        report,
        "content-security-policy",
        "WHX-WEB-002",
        "Content Security Policy is missing",
        "Low",
        "The response did not include an enforcing Content-Security-Policy header.",
        "The browser has fewer restrictions on which resources the page may load.",
        "Design and deploy a Content Security Policy suitable for the application.",
    );

    let nosniff = headers
        .get("x-content-type-options")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.eq_ignore_ascii_case("nosniff"))
        .unwrap_or(false);

    if !nosniff {
        add_finding(
            report,
            "WHX-WEB-003",
            "Low",
            "X-Content-Type-Options is missing or misconfigured",
            "The response did not contain X-Content-Type-Options: nosniff.",
            "Some browsers may perform MIME-type sniffing in situations where it should be disabled.",
            "Set X-Content-Type-Options: nosniff where appropriate.",
        );
    }

    check_header(
        headers,
        report,
        "referrer-policy",
        "WHX-WEB-004",
        "Referrer Policy is missing",
        "Informational",
        "The response did not include a Referrer-Policy header.",
        "Browsers may send more referrer information than the site owner intends.",
        "Choose and configure a suitable Referrer-Policy.",
    );

    check_header(
        headers,
        report,
        "permissions-policy",
        "WHX-WEB-005",
        "Permissions Policy is missing",
        "Informational",
        "The response did not include a Permissions-Policy header.",
        "Browser features may not be explicitly restricted by response policy.",
        "Configure Permissions-Policy for browser features the application does not need.",
    );

    let has_frame_protection =
        headers.contains_key("x-frame-options")
            || headers
                .get("content-security-policy")
                .and_then(|value| value.to_str().ok())
                .map(|value| {
                    value
                        .to_ascii_lowercase()
                        .contains("frame-ancestors")
                })
                .unwrap_or(false);

    if !has_frame_protection {
        add_finding(
            report,
            "WHX-WEB-006",
            "Low",
            "No frame protection policy was observed",
            "Neither X-Frame-Options nor a CSP frame-ancestors directive was observed.",
            "The page may be more exposed to clickjacking, depending on application behavior.",
            "Configure a suitable CSP frame-ancestors directive or X-Frame-Options.",
        );
    }
}

fn check_header(
    headers: &HeaderMap,
    report: &mut WebReport,
    header_name: &str,
    rule_id: &str,
    title: &str,
    severity: &str,
    evidence: &str,
    impact: &str,
    recommendation: &str,
) {
    if !headers.contains_key(header_name) {
        add_finding(
            report,
            rule_id,
            severity,
            title,
            evidence,
            impact,
            recommendation,
        );
    }
}

fn analyze_cookies(
    headers: &HeaderMap,
    report: &mut WebReport,
) {
    let cookies: Vec<String> = headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .map(str::to_string)
        .collect();

    if cookies.is_empty() {
        report.notes.push(
            "The root-page response did not set cookies. Cookie flags could not be assessed."
                .to_string(),
        );
        return;
    }

    let mut cookie_index = 0usize;

    for cookie in &cookies {
        cookie_index += 1;

        if !has_cookie_attribute(cookie, "Secure") {
            add_finding(
                report,
                &format!("WHX-WEB-COOKIE-{cookie_index:03}-SECURE"),
                "Low",
                "A cookie is missing the Secure attribute",
                "A Set-Cookie response did not include the Secure attribute. Cookie values were not stored.",
                "The cookie may be sent over an unencrypted connection in some circumstances.",
                "Use the Secure attribute for cookies that should only be sent over HTTPS.",
            );
        }

        if !has_cookie_attribute(cookie, "HttpOnly") {
            add_finding(
                report,
                &format!("WHX-WEB-COOKIE-{cookie_index:03}-HTTPONLY"),
                "Low",
                "A cookie is missing the HttpOnly attribute",
                "A Set-Cookie response did not include the HttpOnly attribute. Cookie values were not stored.",
                "Client-side scripts may be able to access the cookie.",
                "Use HttpOnly for cookies that do not need to be read by client-side scripts.",
            );
        }

        if !has_cookie_attribute(cookie, "SameSite") {
            add_finding(
                report,
                &format!("WHX-WEB-COOKIE-{cookie_index:03}-SAMESITE"),
                "Low",
                "A cookie is missing the SameSite attribute",
                "A Set-Cookie response did not include a SameSite attribute. Cookie values were not stored.",
                "Cross-site cookie behavior may not be explicitly restricted.",
                "Choose an appropriate SameSite policy, such as Lax or Strict, based on application requirements.",
            );
        }
    }

    report.notes.push(format!(
        "Inspected security attributes for {} Set-Cookie header(s). Cookie values were not saved.",
        cookies.len()
    ));
}

fn has_cookie_attribute(cookie: &str, expected: &str) -> bool {
    cookie
        .split(';')
        .skip(1)
        .any(|attribute| {
            attribute
                .trim()
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .eq_ignore_ascii_case(expected)
        })
}

fn check_public_metadata(
    client: &Client,
    target: &Target,
    report: &mut WebReport,
) -> Result<(), String> {
    let paths = [
        ("/.well-known/security.txt", "security.txt"),
        ("/security.txt", "legacy security.txt"),
        ("/robots.txt", "robots.txt"),
    ];

    for (path, label) in paths {
        if report.requests_sent >= 4 {
            report.notes.push(
                "Request limit reached. Remaining metadata checks were skipped."
                    .to_string(),
            );
            break;
        }

        thread::sleep(Duration::from_millis(700));

        let url = target
            .url
            .join(path)
            .map_err(|_| "Could not construct metadata URL.".to_string())?;

        let response = match fetch(client, &url) {
            Ok(response) => response,
            Err(error) => {
                report.notes.push(format!(
                    "Metadata check for {label} was stopped: {error}"
                ));
                break;
            }
        };

        report.requests_sent += 1;

        report.notes.push(format!(
            "{label} endpoint returned HTTP status {}. Response body was not stored.",
            response.status
        ));

        if response.status == 429 || response.status >= 500 {
            report.notes.push(
                "The server returned a rate-limit or server-error status. Further requests were stopped."
                    .to_string(),
            );
            break;
        }
    }

    Ok(())
}

fn add_finding(
    report: &mut WebReport,
    id: &str,
    severity: &str,
    title: &str,
    evidence: &str,
    impact: &str,
    recommendation: &str,
) {
    report.findings.push(WebFinding {
        id: id.to_string(),
        severity: severity.to_string(),
        confidence: "High".to_string(),
        title: title.to_string(),
        evidence: evidence.to_string(),
        impact: impact.to_string(),
        recommendation: recommendation.to_string(),
    });
}

fn print_report(report: &WebReport) {
    println!();
    println!("========================================");
    println!("           WEB ASSESSMENT");
    println!("========================================");

    println!("Target: {}", report.target);
    println!("Scope: {}", report.scope);
    println!("Requests sent: {}", report.requests_sent);
    println!("Findings: {}", report.findings.len());

    println!("----------------------------------------");

    if report.findings.is_empty() {
        println!("No findings from the selected checks.");
    } else {
        for finding in &report.findings {
            println!();
            println!(
                "[{}] {}",
                finding.severity,
                finding.title
            );
            println!("ID: {}", finding.id);
            println!("Evidence: {}", finding.evidence);
            println!("Impact: {}", finding.impact);
            println!("Recommendation: {}", finding.recommendation);
        }
    }

    println!();
    println!("NOTES");

    for note in &report.notes {
        println!("- {note}");
    }

    println!("----------------------------------------");
    println!("No files or website data were modified.");
    println!("This is not a complete penetration test.");
}

fn save_report(
    report: &WebReport,
    path: &Path,
) -> Result<(), String> {
    let json = serde_json::to_vec_pretty(report)
        .map_err(|error| format!("Could not serialize report: {error}"))?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            format!(
                "Could not create report file (existing files are not overwritten): {error}"
            )
        })?;

    if let Err(error) = file.write_all(&json) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(format!("Could not write report: {error}"));
    }

    file.sync_all()
        .map_err(|error| format!("Could not sync report: {error}"))?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_plain_http() {
        assert!(parse_target("http://example.com").is_err());
    }

    #[test]
    fn rejects_ip_address_target() {
        assert!(parse_target("https://8.8.8.8").is_err());
    }

    #[test]
    fn rejects_target_with_path() {
        assert!(parse_target("https://example.com/admin").is_err());
    }

    #[test]
    fn accepts_simple_https_origin() {
        assert!(parse_target("https://example.com").is_ok());
    }

    #[test]
    fn rejects_private_ipv4() {
        assert!(!is_public_ip(IpAddr::V4(
            Ipv4Addr::new(192, 168, 1, 1)
        )));
    }

    #[test]
    fn accepts_public_ipv4() {
        assert!(is_public_ip(IpAddr::V4(
            Ipv4Addr::new(8, 8, 8, 8)
        )));
    }

    #[test]
    fn detects_cookie_attributes() {
        let cookie = "session=value; Secure; HttpOnly; SameSite=Lax";

        assert!(has_cookie_attribute(cookie, "Secure"));
        assert!(has_cookie_attribute(cookie, "HttpOnly"));
        assert!(has_cookie_attribute(cookie, "SameSite"));
    }

    #[test]
    fn detects_missing_cookie_attribute() {
        let cookie = "session=value; Secure";

        assert!(!has_cookie_attribute(cookie, "HttpOnly"));
        assert!(!has_cookie_attribute(cookie, "SameSite"));
    }

    #[test]
    fn parses_menu_selection() {
        assert_eq!(
            parse_selection("1,3").unwrap(),
            vec![1, 3]
        );
    }

    #[test]
    fn rejects_invalid_menu_selection() {
        assert!(parse_selection("1,9").is_err());
    }
}
