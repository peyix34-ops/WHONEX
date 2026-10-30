use std::path::Path;

use crate::models::{Confidence, Finding, Severity};

pub fn analyze_text(path: &Path, text: &str) -> Vec<Finding> {
    let mut findings = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let trimmed = line.trim();

        if trimmed.is_empty()
            || trimmed.starts_with('#')
            || trimmed.starts_with("//")
            || trimmed.starts_with('*')
        {
            continue;
        }

        let lower = line.to_ascii_lowercase();

        if contains_hardcoded_secret(line) {
            findings.push(make_finding(
                path,
                line_number,
                "WHX-SEC-001",
                "Possible hardcoded secret",
                "A possible credential or secret assignment was detected. Its validity has not been verified.",
                Severity::High,
                Confidence::Medium,
                "Remove the hardcoded value and use a secure secret manager or environment variable.",
                Some("CWE-798"),
            ));
        }

        if lower.contains("eval(") || lower.contains("eval (") {
            findings.push(make_finding(
                path,
                line_number,
                "WHX-SEC-002",
                "Dynamic code execution",
                "A potentially dangerous dynamic evaluation function was detected. Exploitability has not been verified.",
                Severity::Medium,
                Confidence::Low,
                "Avoid evaluating dynamically supplied code. Use safer parsing or explicit allowlists.",
                None,
            ));
        }

        let compact: String = lower
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();

        if compact.contains("shell=true")
            && (compact.contains("subprocess") || compact.contains("popen"))
        {
            findings.push(make_finding(
                path,
                line_number,
                "WHX-SEC-003",
                "Potential unsafe shell execution",
                "Subprocess shell execution was detected. Command injection risk depends on how the command is constructed.",
                Severity::High,
                Confidence::Medium,
                "Avoid shell execution when possible. Pass arguments separately and validate untrusted input.",
                Some("CWE-78"),
            ));
        }

        if lower.contains("pickle.loads")
            || lower.contains("pickle.load(")
        {
            findings.push(make_finding(
                path,
                line_number,
                "WHX-SEC-004",
                "Potentially unsafe deserialization",
                "Python pickle deserialization was detected. Untrusted serialized data may create security risks.",
                Severity::High,
                Confidence::Medium,
                "Never deserialize untrusted data with pickle. Prefer safer serialization formats.",
                Some("CWE-502"),
            ));
        }

        if lower.contains("innerhtml") && line.contains('=') {
            findings.push(make_finding(
                path,
                line_number,
                "WHX-SEC-005",
                "Potential unsafe HTML insertion",
                "An innerHTML assignment was detected. Cross-site scripting risk depends on the source of the inserted content.",
                Severity::Medium,
                Confidence::Low,
                "Use textContent for plain text or sanitize HTML with a trusted sanitizer.",
                Some("CWE-79"),
            ));
        }
    }

    findings
}

fn contains_hardcoded_secret(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();

    let secret_names = [
        "password",
        "passwd",
        "api_key",
        "apikey",
        "secret",
        "access_token",
        "auth_token",
        "client_secret",
    ];

    if !secret_names.iter().any(|name| lower.contains(name)) {
        return false;
    }

    let separator = match line.find('=').or_else(|| line.find(':')) {
        Some(position) => position,
        None => return false,
    };

    let value = line[separator + 1..]
        .trim()
        .trim_matches(|character: char| {
            character == ';' || character == ','
        });

    if !(value.starts_with('"') || value.starts_with('\'')) {
        return false;
    }

    let value_lower = value.to_ascii_lowercase();

    let placeholders = [
        "example",
        "changeme",
        "your_",
        "replace_me",
        "placeholder",
        "dummy",
        "test",
        "none",
        "null",
    ];

    !placeholders
        .iter()
        .any(|placeholder| value_lower.contains(placeholder))
}

fn make_finding(
    path: &Path,
    line_number: usize,
    rule_id: &str,
    title: &str,
    description: &str,
    severity: Severity,
    confidence: Confidence,
    remediation: &str,
    cwe: Option<&str>,
) -> Finding {
    let mut finding = Finding::new(
        format!("{}-L{}", rule_id, line_number),
        rule_id.to_string(),
        title.to_string(),
        description.to_string(),
        severity,
        confidence,
        path.to_path_buf(),
    );

    finding.line = Some(line_number);

    finding.evidence = Some(
        "A heuristic rule matched this line. Original source content is not stored in the finding."
            .to_string(),
    );

    finding.remediation = Some(remediation.to_string());
    finding.cwe = cwe.map(str::to_string);

    finding
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_hardcoded_password() {
        let findings = analyze_text(
            Path::new("sample.py"),
            "password = \"real-looking-secret-value\"",
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "WHX-SEC-001"
        }));
    }

    #[test]
    fn ignores_empty_text() {
        let findings = analyze_text(
            Path::new("sample.py"),
            "",
        );

        assert!(findings.is_empty());
    }

    #[test]
    fn detects_pickle_usage() {
        let findings = analyze_text(
            Path::new("sample.py"),
            "data = pickle.loads(payload)",
        );

        assert!(findings.iter().any(|finding| {
            finding.rule_id == "WHX-SEC-004"
        }));
    }
}
