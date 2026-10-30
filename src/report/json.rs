
use crate::models::ScanReport;

pub fn serialize_report(
    report: &ScanReport,
) -> Result<String, String> {
    serde_json::to_string_pretty(report)
        .map_err(|error| {
            format!("Failed to serialize report: {error}")
        })
}

pub fn serialize_report_compact(
    report: &ScanReport,
) -> Result<String, String> {
    serde_json::to_string(report)
        .map_err(|error| {
            format!("Failed to serialize report: {error}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn serializes_valid_json() {
        let report = ScanReport::new(
            "sample.txt".to_string(),
            0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            Vec::new(),
        );

        let json = serialize_report(&report)
            .expect("Serialization should succeed");

        let parsed: serde_json::Value =
            serde_json::from_str(&json)
                .expect("JSON should be valid");

        assert_eq!(parsed["tool"], "WHONEX");
        assert_eq!(parsed["target"], "sample.txt");
        assert_eq!(parsed["summary"]["total_findings"], 0);

        assert!(Path::new("sample.txt").is_relative());
    }
}
