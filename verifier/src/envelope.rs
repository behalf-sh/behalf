//! Stored log-entry envelope verification.
//!
//! The Go log service (`internal/tlog/envelope.go`) stores each entry as
//!
//! ```json
//! {"v":"behalf.sh/envelope/v1","payloadType":"…","payload":{…},"sig":{"keyid":"<jkt>","sig":"<b64std>"}}
//! ```
//!
//! with the payload spliced verbatim (the span rule: the signed bytes are
//! the stored bytes). Verification mirrors the Week-1 leaf pipeline: the
//! payload span is extracted from the raw envelope bytes with the span
//! scanner — never parse-and-reserialized — PAE is recomputed over
//! `(payloadType, payload_span)`, and the emitter Ed25519 signature is
//! checked when an emitter key set is available. Unknown extra JSON fields
//! are ignored (grease discipline).

use std::collections::HashMap;
use std::path::Path;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::keys::validate_header_key;
use crate::pae::pae;
use crate::span::extract_top_level_bytes;

/// The only envelope version this verifier reads.
pub const ENVELOPE_VERSION: &str = "behalf.sh/envelope/v1";

/// Emitter public keys, keyed by RFC 7638 JWK thumbprint. Loaded from a
/// JSON file of the same shape as the export header's key set:
/// `{"keys":[{"jkt":"…","jwk":{"kty":"OKP","crv":"Ed25519","x":"…"}}]}`.
pub struct EmitterKeys {
    keys: HashMap<String, VerifyingKey>,
}

#[derive(Deserialize)]
struct KeySetWire {
    keys: Vec<KeyEntryWire>,
}

#[derive(Deserialize)]
struct KeyEntryWire {
    jkt: String,
    jwk: JwkWire,
}

#[derive(Deserialize)]
struct JwkWire {
    kty: String,
    crv: String,
    x: String,
}

impl EmitterKeys {
    /// Parse a key-set JSON document. Every key must be a valid Ed25519
    /// OKP JWK whose RFC 7638 thumbprint matches its declared `jkt`.
    pub fn from_json(data: &[u8]) -> Result<Self, String> {
        let wire: KeySetWire = serde_json::from_slice(data)
            .map_err(|e| format!("emitter key set is not valid JSON: {e}"))?;
        let mut keys = HashMap::new();
        for entry in wire.keys {
            let key = validate_header_key(&entry.jkt, &entry.jwk.kty, &entry.jwk.crv, &entry.jwk.x)
                .map_err(|e| format!("emitter key {:?}: {e}", entry.jkt))?;
            if keys.insert(entry.jkt.clone(), key).is_some() {
                return Err(format!("emitter key {:?} declared twice", entry.jkt));
            }
        }
        Ok(EmitterKeys { keys })
    }

    /// Load a key-set file.
    pub fn load(path: &Path) -> Result<Self, String> {
        let data = std::fs::read(path)
            .map_err(|e| format!("cannot read emitter keys {}: {e}", path.display()))?;
        Self::from_json(&data)
    }
}

#[derive(Deserialize)]
struct EnvelopeWire {
    v: String,
    #[serde(rename = "payloadType")]
    payload_type: String,
    sig: SigWire,
}

#[derive(Deserialize)]
struct SigWire {
    keyid: String,
    sig: String,
}

/// Verify one stored envelope. `Err(reason)` is a content finding at the
/// caller's leaf index: the envelope is malformed, its version is unknown,
/// its signature is structurally invalid, or (when `keys` is given) the
/// emitter signature over PAE does not verify or its key is not in the set.
pub fn check_envelope(env: &[u8], keys: Option<&EmitterKeys>) -> Result<(), String> {
    let wire: EnvelopeWire = serde_json::from_slice(env)
        .map_err(|e| format!("envelope is not a valid stored envelope: {e}"))?;
    if wire.v != ENVELOPE_VERSION {
        return Err(format!(
            "envelope version {:?} is not {ENVELOPE_VERSION:?}",
            wire.v
        ));
    }
    let payload = extract_top_level_bytes(env, "payload")
        .map_err(|e| format!("envelope payload span: {e}"))?;
    let sig_bytes = BASE64_STD
        .decode(&wire.sig.sig)
        .map_err(|_| "envelope signature is not valid base64".to_string())?;
    let signature = Signature::from_slice(&sig_bytes)
        .map_err(|_| "envelope signature has wrong length".to_string())?;

    let Some(keys) = keys else {
        return Ok(()); // structural checks only; the caller reports this
    };
    let Some(key) = keys.keys.get(&wire.sig.keyid) else {
        return Err(format!(
            "envelope signed by key {:?} not in the emitter key set",
            wire.sig.keyid
        ));
    };
    let pae_bytes = pae(&wire.payload_type, payload);
    if key.verify(&pae_bytes, &signature).is_err() {
        return Err("emitter signature verification failed".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::okp_thumbprint;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};

    /// Byte-for-byte what internal/tlog/envelope.go BuildEnvelope writes.
    fn build_envelope(payload_type: &str, payload: &[u8], keyid: &str, sig: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(b"{\"v\":\"behalf.sh/envelope/v1\",\"payloadType\":");
        b.extend_from_slice(serde_json::to_string(payload_type).unwrap().as_bytes());
        b.extend_from_slice(b",\"payload\":");
        b.extend_from_slice(payload);
        b.extend_from_slice(b",\"sig\":{\"keyid\":");
        b.extend_from_slice(serde_json::to_string(keyid).unwrap().as_bytes());
        b.extend_from_slice(b",\"sig\":\"");
        b.extend_from_slice(BASE64_STD.encode(sig).as_bytes());
        b.extend_from_slice(b"\"}}");
        b
    }

    fn test_emitter() -> (SigningKey, String, EmitterKeys) {
        let signing = SigningKey::from_bytes(&[42u8; 32]);
        let x = URL_SAFE_NO_PAD.encode(signing.verifying_key().as_bytes());
        let jkt = okp_thumbprint("Ed25519", "OKP", &x).expect("thumbprint");
        let json = format!(
            "{{\"keys\":[{{\"jkt\":{jkt:?},\"jwk\":{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":{x:?}}}}}]}}"
        );
        let keys = EmitterKeys::from_json(json.as_bytes()).expect("key set parses");
        (signing, jkt, keys)
    }

    fn signed_envelope(payload: &[u8]) -> (Vec<u8>, EmitterKeys) {
        let (signing, jkt, keys) = test_emitter();
        let payload_type = "application/vnd.behalf.receipt+json";
        let sig = signing.sign(&pae(payload_type, payload));
        (
            build_envelope(payload_type, payload, &jkt, &sig.to_bytes()),
            keys,
        )
    }

    #[test]
    fn intact_envelope_verifies() {
        let (env, keys) = signed_envelope(br#"{"receipt_id":"r1","amount":"12.00"}"#);
        check_envelope(&env, Some(&keys)).expect("intact envelope verifies");
        check_envelope(&env, None).expect("structural check passes too");
    }

    #[test]
    fn payload_flip_fails_signature() {
        let (env, keys) = signed_envelope(br#"{"receipt_id":"r1","amount":"1200.00"}"#);
        let flipped = String::from_utf8(env).unwrap().replace("1200.00", "12000.0");
        let err = check_envelope(flipped.as_bytes(), Some(&keys)).expect_err("must fail");
        assert!(err.contains("signature verification failed"), "{err}");
    }

    #[test]
    fn unknown_keyid_is_a_content_finding() {
        let (signing, _, _) = test_emitter();
        let payload = br#"{"a":1}"#;
        let sig = signing.sign(&pae("t", payload));
        let env = build_envelope("t", payload, "some-other-jkt", &sig.to_bytes());
        let (_, _, keys) = test_emitter();
        let err = check_envelope(&env, Some(&keys)).expect_err("must fail");
        assert!(err.contains("not in the emitter key set"), "{err}");
    }

    #[test]
    fn unknown_version_rejected() {
        let (env, keys) = signed_envelope(br#"{"a":1}"#);
        let v2 = String::from_utf8(env)
            .unwrap()
            .replace("behalf.sh/envelope/v1", "behalf.sh/envelope/v2");
        assert!(check_envelope(v2.as_bytes(), Some(&keys)).is_err());
    }

    #[test]
    fn extra_fields_are_ignored() {
        let (env, keys) = signed_envelope(br#"{"a":1}"#);
        // Splice a grease field before the closing brace; the payload span
        // and signature are untouched.
        let mut greased = env;
        greased.truncate(greased.len() - 1);
        greased.extend_from_slice(br#","ext":{"future":true}}"#);
        check_envelope(&greased, Some(&keys)).expect("grease fields ignored");
    }

    #[test]
    fn malformed_envelopes_error_not_panic() {
        let (env, keys) = signed_envelope(br#"{"a":1}"#);
        let cases: Vec<Vec<u8>> = vec![
            b"".to_vec(),
            b"not json".to_vec(),
            b"{}".to_vec(),
            br#"{"v":"behalf.sh/envelope/v1"}"#.to_vec(),
            br#"{"v":"behalf.sh/envelope/v1","payloadType":"t","sig":{"keyid":"k","sig":"!!"},"payload":{}}"#.to_vec(),
            br#"{"v":"behalf.sh/envelope/v1","payloadType":"t","sig":{"keyid":"k","sig":"AAAA"},"payload":{}}"#.to_vec(),
            // Duplicate payload key (span smuggling).
            br#"{"v":"behalf.sh/envelope/v1","payloadType":"t","payload":{"a":1},"payload":{"b":2},"sig":{"keyid":"k","sig":"AAAA"}}"#.to_vec(),
            vec![0x00, 0xff, 0x7b],
        ];
        for case in &cases {
            assert!(
                check_envelope(case, Some(&keys)).is_err(),
                "case {:?} must fail",
                String::from_utf8_lossy(case)
            );
        }
        // And every prefix of a real envelope is error-not-panic.
        for end in 0..env.len() {
            let _ = check_envelope(&env[..end], Some(&keys));
        }
    }
}
