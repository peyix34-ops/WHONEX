use crate::models::ScanReport;

pub fn serialize_report(
    report: &ScanReport,
) -> Result<String, String> {
    serde_json::to_string_pretty(report)
        .map_err(|error| {
            format!("Failed to serialize scan report: {error}")
        })
}

pub fn serialize_report_compact(
    report: &ScanReport,
) -> Result<String, String> {
    serde_json::to_string(report)
        .map_err(|error| {
            format!("Failed to serialize scan report: {error}")
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ScanReport;
    use std::path::PathBuf;

    #[test]
    fn serializes_empty_report_as_valid_json() {
        let report = ScanReport::new(
            PathBuf::from("sample.txt"),
            0,
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
            Vec::new(),
        );

        let json = serialize_report(&report)
            .expect("Report serialization should succeed");

        let parsed: serde_json::Value =
            serde_json::from_str(&json)
                .expect("Serialized report should be valid JSON");

        assert_eq!(parsed["tool"], "WHONEX");
        assert_eq!(parsed["summary"]["total_findings"], 0);
    }
}
