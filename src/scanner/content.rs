
use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct TextContent {
    pub text: String,
    pub byte_length: usize,
}

pub fn read_text_file(
    path: &Path,
    max_file_size: u64,
) -> Result<TextContent, String> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| {
            format!("Cannot inspect file: {error}")
        })?;

    if metadata.file_type().is_symlink() {
        return Err("Symbolic links are not supported.".into());
    }

    if !metadata.is_file() {
        return Err("Target must be a regular file.".into());
    }

    if metadata.len() > max_file_size {
        return Err("File exceeds the maximum allowed size.".into());
    }

    let file = File::open(path)
        .map_err(|error| {
            format!("Cannot open file: {error}")
        })?;

    let mut buffer = Vec::new();

    file.take(max_file_size.saturating_add(1))
        .read_to_end(&mut buffer)
        .map_err(|error| {
            format!("Cannot read file: {error}")
        })?;

    if buffer.len() as u64 > max_file_size {
        return Err("File exceeded the maximum allowed size.".into());
    }

    if buffer.contains(&0) {
        return Err(
            "Binary files are not supported by this scanner.".into()
        );
    }

    let byte_length = buffer.len();

    let text = String::from_utf8(buffer)
        .map_err(|_| {
            "File is not valid UTF-8 text.".to_string()
        })?;

    Ok(TextContent {
        text,
        byte_length,
    })
}
