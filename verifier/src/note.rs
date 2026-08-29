//! Signed-note checkpoint parsing and verification.
//!
//! The log's `checkpoint` file is a note in the `golang.org/x/mod/sumdb/note`
//! format, as written by Tessera v1.0.4: the checkpoint body (origin line,
//! decimal tree size, base64 root hash), a blank line, then signature lines
//! of the form `— <name> <base64(key_hash || sig)>`. The verifier key is the
//! note-format vkey at `keys/checkpoint.vkey`
//! (`<name>+<hash-hex8>+<base64(alg || pubkey)>`).
//!
//! Grease discipline (architecture Q78): unknown or unparseable signature
//! lines are ignored; the note authenticates iff at least one line matches
//! the given verifier's name and key hash and its Ed25519 signature verifies
//! over the note text. Nothing here panics on malformed input.

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::util::sha256;

/// The note algorithm byte for Ed25519 (`algEd25519` in sumdb/note).
const ALG_ED25519: u8 = 1;

/// Error decoding a note verifier key or note structure (exit-2 territory:
/// the input is not readable, nothing is classified).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoteError(pub String);

impl std::fmt::Display for NoteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for NoteError {}

fn malformed(msg: impl Into<String>) -> NoteError {
    NoteError(msg.into())
}

/// A parsed note verifier key (Ed25519 only).
pub struct NoteVerifier {
    name: String,
    key_hash: [u8; 4],
    key: VerifyingKey,
}

impl NoteVerifier {
    /// Parse a note vkey string: `<name>+<hash-hex8>+<base64(alg || pubkey)>`.
    ///
    /// The embedded 4-byte key hash is recomputed
    /// (`SHA-256(name || "\n" || alg || pubkey)[..4]`) and must match.
    pub fn from_vkey(vkey: &str) -> Result<Self, NoteError> {
        let vkey = vkey.trim();
        // Split from the left: note names cannot contain '+', but the
        // base64 key material can — the final field must stay whole.
        let mut parts = vkey.splitn(3, '+');
        let name = parts.next().ok_or_else(|| malformed("empty vkey"))?;
        let hash_hex = parts
            .next()
            .ok_or_else(|| malformed("vkey is not name+hash+key"))?;
        let key_b64 = parts
            .next()
            .ok_or_else(|| malformed("vkey is not name+hash+key"))?;
        if name.is_empty() || name.contains(['+', ' ', '\n']) {
            return Err(malformed("vkey has an invalid name"));
        }
        let declared_hash = crate::util::hex_decode(hash_hex)
            .filter(|v| v.len() == 4)
            .ok_or_else(|| malformed("vkey hash is not 8 hex chars"))?;
        let key_data = BASE64_STD
            .decode(key_b64)
            .map_err(|e| malformed(format!("vkey key material is not base64: {e}")))?;
        let (&alg, pub_bytes) = key_data
            .split_first()
            .ok_or_else(|| malformed("vkey key material is empty"))?;
        if alg != ALG_ED25519 {
            return Err(malformed(format!(
                "vkey algorithm {alg} is not Ed25519 (1)"
            )));
        }
        let arr: [u8; 32] = pub_bytes
            .try_into()
            .map_err(|_| malformed("vkey Ed25519 key is not 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&arr)
            .map_err(|e| malformed(format!("vkey Ed25519 key invalid: {e}")))?;
        let computed = key_hash(name, &key_data);
        if computed != declared_hash.as_slice() {
            return Err(malformed("vkey hash does not match its key material"));
        }
        Ok(NoteVerifier {
            name: name.to_string(),
            key_hash: computed,
            key,
        })
    }

    /// The key name (for checkpoints this is the log origin, by convention).
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// `SHA-256(name || "\n" || key_data)[..4]` — the sumdb/note key hash.
fn key_hash(name: &str, key_data: &[u8]) -> [u8; 4] {
    let mut input = Vec::with_capacity(name.len() + 1 + key_data.len());
    input.extend_from_slice(name.as_bytes());
    input.push(b'\n');
    input.extend_from_slice(key_data);
    let h = sha256(&input);
    [h[0], h[1], h[2], h[3]]
}

/// Verify a note against `verifier` and return the authenticated text
/// (everything up to and including the newline before the blank separator).
///
/// - `Err(NoteError)` — the bytes are not a note at all (exit 2).
/// - `Ok(Err(reason))` — structurally a note, but no signature by this
///   verifier authenticates it (class `head` for checkpoints).
/// - `Ok(Ok(text))` — authenticated.
pub fn verify_note<'a>(
    data: &'a [u8],
    verifier: &NoteVerifier,
) -> Result<Result<&'a [u8], String>, NoteError> {
    // The separator is the last blank line, as in sumdb/note.
    let split = find_last_blank_line(data)
        .ok_or_else(|| malformed("note has no blank-line separator"))?;
    let (text, sig_section) = (&data[..split + 1], &data[split + 2..]);
    if text.is_empty() {
        return Err(malformed("note text is empty"));
    }

    let mut saw_matching_line = false;
    for line in sig_section.split(|&b| b == b'\n') {
        let Some((name, key_hash4, sig)) = parse_sig_line(line) else {
            continue; // unknown/extra/garbage signature line: ignored (grease)
        };
        if name != verifier.name.as_bytes() || key_hash4 != verifier.key_hash {
            continue; // signature by some other key: ignored (grease)
        }
        saw_matching_line = true;
        if verifier.key.verify(text, &sig).is_ok() {
            return Ok(Ok(text));
        }
    }
    Ok(Err(if saw_matching_line {
        format!(
            "signature by {:?} does not verify over the note text",
            verifier.name
        )
    } else {
        format!("no signature by {:?} on the note", verifier.name)
    }))
}

/// Byte offset of the `\n` starting the last `\n\n` in `data`.
fn find_last_blank_line(data: &[u8]) -> Option<usize> {
    data.windows(2).rposition(|w| w == b"\n\n")
}

/// Parse one signature line: `— <name> <base64(hash4 || sig64)>`.
/// Returns `None` for anything that is not an Ed25519 signature line —
/// callers treat those as grease.
fn parse_sig_line(line: &[u8]) -> Option<(&[u8], [u8; 4], Signature)> {
    let rest = line.strip_prefix("\u{2014} ".as_bytes())?;
    let sp = rest.iter().position(|&b| b == b' ')?;
    let (name, b64) = (&rest[..sp], &rest[sp + 1..]);
    if name.is_empty() {
        return None;
    }
    let decoded = BASE64_STD.decode(b64).ok()?;
    // 4-byte key hash + 64-byte Ed25519 signature; other lengths are other
    // algorithms (or garbage) and are ignored.
    if decoded.len() != 4 + 64 {
        return None;
    }
    let (hash4, sig_bytes) = decoded.split_at(4);
    let hash4: [u8; 4] = hash4.try_into().ok()?;
    let sig = Signature::from_slice(sig_bytes).ok()?;
    Some((name, hash4, sig))
}

/// A parsed checkpoint body (already authenticated by [`verify_note`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checkpoint {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
}

/// Parse an authenticated note text as a tlog checkpoint: origin line,
/// decimal tree size, base64 root hash. Extension lines after the first
/// three are tolerated and ignored (they were covered by the signature).
pub fn parse_checkpoint_body(text: &[u8]) -> Result<Checkpoint, NoteError> {
    let text = std::str::from_utf8(text)
        .map_err(|_| malformed("checkpoint body is not valid UTF-8"))?;
    let mut lines = text.split('\n');
    let origin = lines
        .next()
        .filter(|l| !l.is_empty())
        .ok_or_else(|| malformed("checkpoint has no origin line"))?;
    let size_line = lines
        .next()
        .ok_or_else(|| malformed("checkpoint has no tree-size line"))?;
    if size_line.is_empty() || !size_line.bytes().all(|b| b.is_ascii_digit()) {
        return Err(malformed(format!(
            "checkpoint tree size {size_line:?} is not a decimal number"
        )));
    }
    let size: u64 = size_line
        .parse()
        .map_err(|_| malformed("checkpoint tree size does not fit in u64"))?;
    let root_line = lines
        .next()
        .ok_or_else(|| malformed("checkpoint has no root-hash line"))?;
    let root_bytes = BASE64_STD
        .decode(root_line)
        .map_err(|e| malformed(format!("checkpoint root hash is not base64: {e}")))?;
    let root: [u8; 32] = root_bytes
        .try_into()
        .map_err(|v: Vec<u8>| malformed(format!("checkpoint root is {} bytes, want 32", v.len())))?;
    Ok(Checkpoint {
        origin: origin.to_string(),
        size,
        root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // A checkpoint + vkey pair produced by the Go log service (Tessera
    // v1.0.4 POSIX driver + golang.org/x/mod/sumdb/note), captured verbatim:
    // the cross-implementation known answer for note verification.
    const GO_VKEY: &str =
        "behalf.sh/log/demo+1fc08bcd+ASPNUhW2PTHRxDpA4LfrOFzy6xcagvKVMuaNYi+CyRSt";
    const GO_CHECKPOINT: &[u8] = b"behalf.sh/log/demo\n\
94\n\
8M+jxrOKQeU94BPxbfuUIdMKW3/R8Cx5+1H8hoSfIKw=\n\
\n\
\xe2\x80\x94 behalf.sh/log/demo H8CLzaJB54JzH88QsZm8WtMHm8OKmM+w5zZ2e6v7E5dkrJZMM3/ACAtaZoaYvTecwLd5bDk5IBfIOZZhbZyMZmJ4Fwg=\n";

    fn go_verifier() -> NoteVerifier {
        NoteVerifier::from_vkey(GO_VKEY).expect("vkey should parse")
    }

    #[test]
    fn go_written_checkpoint_verifies() {
        let v = go_verifier();
        assert_eq!(v.name(), "behalf.sh/log/demo");
        let text = verify_note(GO_CHECKPOINT, &v)
            .expect("structurally a note")
            .expect("signature should verify");
        let cp = parse_checkpoint_body(text).expect("body should parse");
        assert_eq!(cp.origin, "behalf.sh/log/demo");
        assert_eq!(cp.size, 94);
        assert_eq!(
            crate::util::hex_encode(&cp.root),
            "f0cfa3c6b38a41e53de013f16dfb9421d30a5b7fd1f02c79fb51fc86849f20ac"
        );
    }

    #[test]
    fn grease_lines_are_ignored() {
        let v = go_verifier();
        // Unknown-key signature lines and plain garbage, before and after
        // the real signature line.
        let body_end = find_last_blank_line(GO_CHECKPOINT).unwrap();
        let mut note = GO_CHECKPOINT[..body_end + 2].to_vec();
        note.extend_from_slice("\u{2014} other.log/x abcd\n".as_bytes());
        note.extend_from_slice(b"not a signature line at all\n");
        note.extend_from_slice(&GO_CHECKPOINT[body_end + 2..]);
        note.extend_from_slice("\u{2014} behalf.sh/log/demo AAAA\n".as_bytes());
        let text = verify_note(&note, &v)
            .expect("structurally a note")
            .expect("real signature must still verify among grease");
        assert!(parse_checkpoint_body(text).is_ok());
    }

    #[test]
    fn edited_root_fails_signature() {
        let v = go_verifier();
        let mut edited = GO_CHECKPOINT.to_vec();
        // Flip one character of the root's base64.
        let pos = GO_CHECKPOINT
            .windows(4)
            .position(|w| w == b"8M+j")
            .expect("root b64 present");
        edited[pos] = b'9';
        let res = verify_note(&edited, &v).expect("still structurally a note");
        assert!(res.is_err(), "edited root must not verify");
    }

    #[test]
    fn edited_size_fails_signature() {
        let v = go_verifier();
        let mut edited = GO_CHECKPOINT.to_vec();
        let pos = edited.windows(3).position(|w| w == b"94\n").unwrap();
        edited[pos] = b'4';
        edited[pos + 1] = b'7';
        let res = verify_note(&edited, &v).expect("still structurally a note");
        assert!(res.is_err(), "edited size must not verify");
    }

    #[test]
    fn wrong_key_is_unauthenticated_not_malformed() {
        // Same name, different key: the key hash differs, so the only
        // signature line is ignored and the note is unauthenticated.
        let other =
            "behalf.sh/log/demo+00000000+AQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8g";
        // That fabricated vkey has a wrong hash; build a consistent one from
        // a fixed key instead.
        assert!(NoteVerifier::from_vkey(other).is_err());
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let mut key_data = vec![ALG_ED25519];
        key_data.extend_from_slice(signing.verifying_key().as_bytes());
        let h = key_hash("behalf.sh/log/demo", &key_data);
        let vkey = format!(
            "behalf.sh/log/demo+{}+{}",
            crate::util::hex_encode(&h),
            BASE64_STD.encode(&key_data)
        );
        let v = NoteVerifier::from_vkey(&vkey).expect("consistent vkey parses");
        let res = verify_note(GO_CHECKPOINT, &v).expect("structurally a note");
        assert!(res.is_err());
    }

    #[test]
    fn malformed_notes_error_not_panic() {
        let v = go_verifier();
        let cases: &[&[u8]] = &[
            b"",
            b"no separator at all",
            b"\n",
            b"\n\n",
            b"text only, no newline pair",
            b"\x00\xff\xfe binary garbage",
            b"origin\n94\nnotb64!!\n\n\xe2\x80\x94 x y\n",
        ];
        for case in cases {
            if let Ok(inner) = verify_note(case, &v) {
                // Structurally a note but unauthenticated is acceptable.
                assert!(inner.is_err(), "garbage must never authenticate");
            }
        }
    }

    #[test]
    fn body_parse_rejects_bad_shapes() {
        assert!(parse_checkpoint_body(b"").is_err());
        assert!(parse_checkpoint_body(b"origin\n").is_err());
        assert!(parse_checkpoint_body(b"origin\nnot-a-number\nAAAA\n").is_err());
        assert!(parse_checkpoint_body(b"origin\n-1\nAAAA\n").is_err());
        assert!(parse_checkpoint_body(b"origin\n+7\nAAAA\n").is_err());
        assert!(parse_checkpoint_body(b"origin\n99999999999999999999999\nAAAA\n").is_err());
        assert!(parse_checkpoint_body(b"origin\n7\nnot base64\n").is_err());
        // 3-byte root: wrong length.
        assert!(parse_checkpoint_body(b"origin\n7\nAAAA\n").is_err());
        assert!(parse_checkpoint_body(b"\xff\xfe\n7\nAAAA\n").is_err());
    }

    #[test]
    fn extension_lines_are_tolerated() {
        let text =
            b"origin\n7\ne3sMRwFCZ0BM9M9dt1zL9kJZlTNegkY3H2SBrcO3wpJkONdJvSpz7GObpjeR5PLbe1BLnjOSTzjKybBHDs8QSQ==";
        // 64-byte root: wrong length, must error.
        assert!(parse_checkpoint_body(text).is_err());
        let ok = b"origin\n7\nOzMEg7EiVjWzUxHhF/tvGmsC/uUdIY0+2gLYlmowo0c=\nextension line\nanother\n";
        let cp = parse_checkpoint_body(ok).expect("extensions tolerated");
        assert_eq!(cp.size, 7);
    }

    #[test]
    fn vkey_rejects_bad_inputs() {
        for bad in [
            "",
            "noplus",
            "name+zz+AAAA",
            "name+1fc08bcd+!!!",
            "name+1fc08bcd+AAAA",
            "+1fc08bcd+AAAA",
            // wrong algorithm byte (2 = cosignature/v1 style)
            "name+00000000+AgECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gIQ==",
        ] {
            assert!(NoteVerifier::from_vkey(bad).is_err(), "{bad:?}");
        }
    }
}
