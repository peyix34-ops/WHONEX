use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Confidence {
    Low,
    Medium,
    High,
    Certain,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub rule_id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: Confidence,
    pub file_path: PathBuf,
    pub line: Option<usize>,
    pub evidence: Option<String>,
    pub remediation: Option<String>,
    pub cwe: Option<String>,
}

impl Finding {
    pub fn new(
        id: String,
        rule_id: String,
        title: String,
        description: String,
        severity: Severity,
        confidence: Confidence,
        file_path: PathBuf,
    ) -> Self {
        Self {
            id,
            rule_id,
            title,
            description,
            severity,
            confidence,
            file_path,
            line: None,
            evidence: None,
            remediation: None,
            cwe: None,
        }
    }
}
