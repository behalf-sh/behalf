//! Small byte utilities: SHA-256 and hex, with no panics on untrusted input.

use sha2::{Digest, Sha256};

/// SHA-256 of `data` as a raw 32-byte array.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// Lowercase hex encoding.
#[must_use]
pub fn hex_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX_CHARS[(b >> 4) as usize]);
        out.push(HEX_CHARS[(b & 0x0f) as usize]);
    }
    out
}

const HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// Decode a hex string (either case). Returns `None` on odd length or any
/// non-hex character.
#[must_use]
pub fn hex_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = hex_val(pair[0])?;
        let lo = hex_val(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Some(out)
}

fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Abbreviate a hex digest for human output: first 4 chars, an ellipsis, last
/// 4 chars (`4f0c…a19e`, mirroring the demo script). Strings too short to
/// abbreviate are returned whole.
#[must_use]
pub fn short_hex(s: &str) -> String {
    abbrev(s, 4, 4)
}

/// Abbreviate for inline mismatch details: first 4 chars plus an ellipsis
/// (`9b2e…`), mirroring the demo script.
#[must_use]
pub fn short4(s: &str) -> String {
    match s.get(..4) {
        Some(head) if s.len() > 4 => format!("{head}…"),
        _ => s.to_string(),
    }
}

fn abbrev(s: &str, head: usize, tail: usize) -> String {
    if s.len() <= head + tail {
        return s.to_string();
    }
    match (s.get(..head), s.get(s.len() - tail..)) {
        (Some(h), Some(t)) => format!("{h}…{t}"),
        _ => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        // sha256("") is the canonical empty-input digest.
        assert_eq!(
            hex_encode(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hex_roundtrip() {
        let data = [0x00, 0x01, 0x9b, 0xff];
        let s = hex_encode(&data);
        assert_eq!(s, "00019bff");
        assert_eq!(hex_decode(&s).as_deref(), Some(&data[..]));
        assert_eq!(hex_decode("00019BFF").as_deref(), Some(&data[..]));
    }

    #[test]
    fn hex_decode_rejects_bad_input() {
        assert_eq!(hex_decode("abc"), None); // odd length
        assert_eq!(hex_decode("zz"), None); // non-hex
        assert_eq!(hex_decode("0g"), None);
        assert_eq!(hex_decode(""), Some(vec![]));
    }

    #[test]
    fn short_forms() {
        let h = "4f0c11aa22bb33cc44dd55ee66ff7788990011223344556677889900aabba19e";
        assert_eq!(short_hex(h), "4f0c…a19e");
        assert_eq!(short4(h), "4f0c…");
        assert_eq!(short_hex("abcd"), "abcd");
        assert_eq!(short4("ab"), "ab");
    }
}
