use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

use crate::models::ScanReport;
use super::serialize_report;

pub fn write_report(
    report: &ScanReport,
    output_path: &Path,
) -> Result<(), String> {
    let json = serialize_report(report)?;

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output_path)
        .map_err(|error| {
            format!("Cannot create report file: {error}")
        })?;

    let result = file
        .write_all(json.as_bytes())
        .and_then(|_| file.sync_all());

    if let Err(error) = result {
        drop(file);
        let _ = fs::remove_file(output_path);

        return Err(format!("Cannot write report: {error}"));
    }

    Ok(())
}
