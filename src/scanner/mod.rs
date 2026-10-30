pub mod content;
pub mod hash;
pub mod rules;

use std::fs;
use std::path::{Path, PathBuf};

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

#[derive(Debug, Clone)]
pub struct ScanTarget {
    pub path: PathBuf,
    pub size: u64,
}

impl ScanTarget {
    pub fn inspect(
        path: &Path,
        limits: &ScanLimits,
    ) -> Result<Self, String> {
        let metadata = fs::symlink_metadata(path)
            .map_err(|e| format!("Cannot inspect file: {e}"))?;

        if metadata.file_type().is_symlink() {
            return Err("Symbolic links are not allowed.".into());
        }

        if !metadata.is_file() {
            return Err("Target must be a regular file.".into());
        }

        if metadata.len() > limits.max_file_size {
            return Err(format!(
                "File exceeds the maximum allowed size of {} bytes.",
                limits.max_file_size
            ));
        }

        Ok(Self {
            path: path.to_path_buf(),
            size: metadata.len(),
        })
    }
}

pub fn scan_file(
    path: &Path,
    limits: &ScanLimits,
) -> Result<ScanReport, String> {
    let target = ScanTarget::inspect(path, limits)?;

    let initial_hash = hash::calculate_sha256(path, limits)?;

    let content = content::read_text_file(path, limits)?;

    let final_hash = hash::calculate_sha256(path, limits)?;

    if initial_hash.value != final_hash.value
        || initial_hash.bytes_hashed != content.byte_length as u64
        || final_hash.bytes_hashed != content.byte_length as u64
    {
        return Err(
            "File changed during analysis. Scan aborted.".to_string()
        );
    }

    let findings = rules::analyze_text(
        &target.path,
        &content.text,
    );

    Ok(ScanReport::new(
        target.path,
        content.byte_length as u64,
        final_hash.value,
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
