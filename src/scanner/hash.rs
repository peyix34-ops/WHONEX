
use sha2::{Digest, Sha256};

pub fn calculate_sha256(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_empty_content_hash() {
        let expected =
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        assert_eq!(calculate_sha256(b""), expected);
    }

    #[test]
    fn calculates_known_content_hash() {
        let expected =
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

        assert_eq!(calculate_sha256(b"hello"), expected);
    }
}
