//! Ed25519 JWK handling: RFC 7638 thumbprints and key decoding.
//!
//! Week-1 verification checks signatures against the keys embedded in the
//! export header. Key *provenance* (the published key log) is a later
//! milestone and nothing here claims it.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;

use crate::util::sha256;

/// Error decoding or validating a JWK from the export header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyError(pub String);

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}

/// RFC 7638 JWK thumbprint for an OKP key: SHA-256 over the JSON object with
/// exactly the required members (`crv`, `kty`, `x`) in lexicographic order,
/// no whitespace; base64url without padding.
pub fn okp_thumbprint(crv: &str, kty: &str, x: &str) -> Result<String, KeyError> {
    // serde_json's default map is ordered (BTreeMap), and `crv` < `kty` < `x`
    // is already the required lexicographic order. Serializing through
    // serde_json also gets string escaping right for hostile inputs.
    let canonical = serde_json::json!({ "crv": crv, "kty": kty, "x": x });
    let bytes = serde_json::to_string(&canonical)
        .map_err(|e| KeyError(format!("thumbprint serialization failed: {e}")))?;
    Ok(URL_SAFE_NO_PAD.encode(sha256(bytes.as_bytes())))
}

/// Decode an Ed25519 verifying key from a JWK `x` coordinate
/// (base64url, no padding, 32 bytes).
pub fn decode_verifying_key(x_b64: &str) -> Result<VerifyingKey, KeyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(x_b64)
        .map_err(|e| KeyError(format!("jwk x is not base64url: {e}")))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|v: Vec<u8>| KeyError(format!("jwk x is {} bytes, want 32", v.len())))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|e| KeyError(format!("jwk x is not a valid Ed25519 point: {e}")))
}

/// Validate one header key entry: correct key type, decodable point, and a
/// thumbprint that matches the declared `jkt`.
pub fn validate_header_key(
    jkt: &str,
    kty: &str,
    crv: &str,
    x: &str,
) -> Result<VerifyingKey, KeyError> {
    if kty != "OKP" {
        return Err(KeyError(format!("unsupported jwk kty {kty:?}, want \"OKP\"")));
    }
    if crv != "Ed25519" {
        return Err(KeyError(format!(
            "unsupported jwk crv {crv:?}, want \"Ed25519\""
        )));
    }
    let key = decode_verifying_key(x)?;
    let computed = okp_thumbprint(crv, kty, x)?;
    if computed != jkt {
        return Err(KeyError(format!(
            "jwk thumbprint mismatch: declared jkt {jkt:?}, computed {computed:?}"
        )));
    }
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 8037 appendix A.2 Ed25519 public key; A.3 gives its thumbprint.
    const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const RFC8037_JKT: &str = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k";

    #[test]
    fn rfc8037_thumbprint_known_answer() {
        assert_eq!(
            okp_thumbprint("Ed25519", "OKP", RFC8037_X).expect("thumbprint should compute"),
            RFC8037_JKT
        );
    }

    #[test]
    fn validate_accepts_the_rfc8037_key() {
        assert!(validate_header_key(RFC8037_JKT, "OKP", "Ed25519", RFC8037_X).is_ok());
    }

    #[test]
    fn validate_rejects_wrong_jkt() {
        let err = validate_header_key("not-the-thumbprint", "OKP", "Ed25519", RFC8037_X)
            .expect_err("must reject");
        assert!(err.0.contains("thumbprint mismatch"), "{}", err.0);
    }

    #[test]
    fn validate_rejects_wrong_kty_and_crv() {
        assert!(validate_header_key(RFC8037_JKT, "EC", "Ed25519", RFC8037_X).is_err());
        assert!(validate_header_key(RFC8037_JKT, "OKP", "P-256", RFC8037_X).is_err());
    }

    #[test]
    fn decode_rejects_bad_x() {
        assert!(decode_verifying_key("!!!not-base64url!!!").is_err());
        assert!(decode_verifying_key("AAAA").is_err()); // 3 bytes, not 32
        // Padded base64url must be rejected by the no-pad decoder.
        assert!(decode_verifying_key("11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo=").is_err());
    }

    #[test]
    fn thumbprint_escapes_hostile_strings() {
        // A quote inside x must be escaped in the canonical form, not break it.
        let t = okp_thumbprint("Ed25519", "OKP", "a\"b").expect("thumbprint should compute");
        assert_eq!(t.len(), 43); // base64url(32 bytes) without padding
    }
}
