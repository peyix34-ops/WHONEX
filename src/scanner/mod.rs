pub mod content;

use std::fs;
use std::path::{Path, PathBuf};

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
            .map_err(|error| format!("Cannot inspect file: {error}"))?;

        if metadata.file_type().is_symlink() {
            return Err("Symbolic links are not allowed.".to_string());
        }

        if !metadata.is_file() {
            return Err("Target must be a regular file.".to_string());
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
