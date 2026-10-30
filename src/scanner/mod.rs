
pub mod content;
pub mod hash;
pub mod rules;

use std::fs;
use std::path::Path;

use crate::models::ScanReport;

#[derive(Debug, Clone)]
pub struct ScanLimits {
    pub max_file_size: u64,
}

impl Default for ScanLimits {
    fn default() -> Self {
        Self {
            max_file_size: 20 * 1024 * 1024,
        }
    }
}

pub fn scan_file(
    path: &Path,
    limits: &ScanLimits,
) -> Result<ScanReport, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| {
            format!("Cannot inspect target file: {error}")
        })?;

    if metadata.file_type().is_symlink() {
        return Err("Symbolic links are not supported.".into());
    }

    if !metadata.is_file() {
        return Err("Target must be a regular file.".into());
    }

    if metadata.len() > limits.max_file_size {
        return Err("File exceeds the maximum allowed size.".into());
    }

    let content = content::read_text_file(
        path,
        limits.max_file_size,
    )?;

    let sha256 = hash::calculate_sha256(
        content.text.as_bytes(),
    );

    let findings = rules::analyze_text(
        path,
        &content.text,
    );

    let target_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("unknown-file")
        .to_string();

    Ok(ScanReport::new(
        target_name,
        content.byte_length as u64,
        sha256,
        findings,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limit_is_twenty_megabytes() {
        assert_eq!(
            ScanLimits::default().max_file_size,
            20 * 1024 * 1024
        );
    }
}
