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

    let mut file = File::open(path)
        .map_err(|e| format!("Cannot open file: {e}"))?;

    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = file
            .read(&mut buffer)
            .map_err(|e| format!("Cannot read file: {e}"))?;

        if bytes_read == 0 {
            break;
        }

        total_bytes += bytes_read as u64;

        if total_bytes > limits.max_file_size {
            return Err("File exceeded the maximum allowed size during reading.".into());
        }

        hasher.update(&buffer[..bytes_read]);
    }

    let digest = hasher.finalize();

    Ok(FileHash {
        algorithm: "SHA-256".to_string(),
        value: hex::encode(digest),
        bytes_hashed: total_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_of_empty_content_is_correct() {
        let expected =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        let actual = hex::encode(Sha256::digest(b""));

        assert_eq!(actual, expected);
    }
}
