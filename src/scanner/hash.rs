use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use super::ScanLimits;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileHash {
    pub algorithm: String,
    pub value: String,
    pub bytes_hashed: u64,
}

pub fn calculate_sha256_bytes(data: &[u8]) -> FileHash {
    let digest = Sha256::digest(data);

    FileHash {
        algorithm: "SHA-256".to_string(),
        value: hex::encode(digest),
        bytes_hashed: data.len() as u64,
    }
}

pub fn calculate_sha256(
    path: &Path,
    limits: &ScanLimits,
) -> Result<FileHash, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|e| format!("Cannot inspect file: {e}"))?;

    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("Target must be a regular, non-symlink file.".into());
    }

    if metadata.len() > limits.max_file_size {
        return Err("File exceeds the maximum allowed size.".into());
    }

    let file = File::open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;

    let mut buffer = Vec::new();

    file.take(limits.max_file_size.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|e| format!("Cannot read file: {e}"))?;

    if buffer.len() as u64 > limits.max_file_size {
        return Err("File exceeded the maximum allowed size.".into());
    }

    Ok(calculate_sha256_bytes(&buffer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_content_is_correct() {
        let expected =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let actual = calculate_sha256_bytes(b"");

        assert_eq!(actual.value, expected);
        assert_eq!(actual.bytes_hashed, 0);
    }
}
