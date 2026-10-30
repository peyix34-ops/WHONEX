use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use super::ScanLimits;

#[derive(Debug, Clone)]
pub struct TextContent {
    pub text: String,
    pub byte_length: usize,
}

pub fn read_text_file(
    path: &Path,
    limits: &ScanLimits,
) -> Result<TextContent, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| format!("Cannot inspect file: {error}"))?;

    if metadata.file_type().is_symlink() {
        return Err("Symbolic links are not allowed.".to_string());
    }

    if !metadata.is_file() {
        return Err("Target must be a regular file.".to_string());
    }

    if metadata.len() > limits.max_file_size {
        return Err("File exceeds the maximum allowed size.".to_string());
    }

    let file = File::open(path)
        .map_err(|error| format!("Cannot open file: {error}"))?;

    let mut buffer = Vec::new();

    file.take(limits.max_file_size + 1)
        .read_to_end(&mut buffer)
        .map_err(|error| format!("Cannot read file: {error}"))?;

    if buffer.len() as u64 > limits.max_file_size {
        return Err("File exceeds the maximum allowed size.".to_string());
    }

    if buffer.contains(&0) {
        return Err("Binary files are not supported by the text reader.".to_string());
    }

    let byte_length = buffer.len();

    let text = String::from_utf8(buffer)
        .map_err(|_| "File is not valid UTF-8 text.".to_string())?;

    Ok(TextContent {
        text,
        byte_length,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_binary_content() {
        let result = String::from_utf8(vec![b'a', 0, b'b']);
        assert!(result.is_err());
    }
}
