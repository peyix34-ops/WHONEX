use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use super::{Finding, Severity};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ScanSummary {
    pub total_findings: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
    pub info: usize,
}

impl ScanSummary {
    pub fn from_findings(findings: &[Finding]) -> Self {
        let mut summary = Self::default();

        summary.total_findings = findings.len();

        for finding in findings {
            match finding.severity {
                Severity::Critical => summary.critical += 1,
                Severity::High => summary.high += 1,
                Severity::Medium => summary.medium += 1,
                Severity::Low => summary.low += 1,
                Severity::Info => summary.info += 1,
            }
        }

        summary
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub schema_version: String,
    pub tool: String,
    pub version: String,
    pub target: PathBuf,
    pub file_size_bytes: u64,
    pub sha256: String,
    pub analysis_type: String,
    pub findings: Vec<Finding>,
    pub summary: ScanSummary,
}

impl ScanReport {
    pub fn new(
        target: PathBuf,
        file_size_bytes: u64,
        sha256: String,
        findings: Vec<Finding>,
    ) -> Self {
        let summary = ScanSummary::from_findings(&findings);

        Self {
            schema_version: "1.0".to_string(),
            tool: "WHONEX".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            target,
            file_size_bytes,
            sha256,
            analysis_type: "heuristic_text_analysis".to_string(),
            findings,
            summary,
        }
    }
}
