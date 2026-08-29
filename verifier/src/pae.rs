//! DSSE pre-authentication encoding (PAE).
//!
//! `PAE(type, payload) = "DSSEv1" SP LEN(type) SP type SP LEN(payload) SP payload`
//! where LEN is the decimal ASCII byte length and SP is a single 0x20
//! (contract §1.2). The payload bytes are framed opaquely — no
//! canonicalization step exists.

/// `payloadType` for receipt leaves.
pub const RECEIPT_PAYLOAD_TYPE: &str = "application/vnd.behalf.receipt+json";

/// `payloadType` for the signed chain head.
pub const CHAIN_HEAD_PAYLOAD_TYPE: &str = "application/vnd.behalf.chain-head+json";

/// Build the PAE byte string for `payload_type` and raw `payload` bytes.
#[must_use]
pub fn pae(payload_type: &str, payload: &[u8]) -> Vec<u8> {
    let type_bytes = payload_type.as_bytes();
    let mut out = Vec::with_capacity(type_bytes.len() + payload.len() + 32);
    out.extend_from_slice(b"DSSEv1 ");
    out.extend_from_slice(type_bytes.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(type_bytes);
    out.push(b' ');
    out.extend_from_slice(payload.len().to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::{hex_encode, sha256};

    #[test]
    fn dsse_spec_known_answer() {
        // Worked example from the DSSE specification.
        let got = pae("http://example.com/HelloWorld", b"hello world");
        assert_eq!(
            got,
            b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
        );
        // Hash of those exact bytes (independently computed).
        assert_eq!(
            hex_encode(&sha256(&got)),
            "217751fac2c4f14edb2c9297fbc34abcb016ba88e74757e875ec4ac16fb6b6a1"
        );
    }

    #[test]
    fn receipt_type_length_is_35() {
        let got = pae(RECEIPT_PAYLOAD_TYPE, b"{\"a\":1}");
        assert_eq!(
            got,
            b"DSSEv1 35 application/vnd.behalf.receipt+json 7 {\"a\":1}"
        );
    }

    #[test]
    fn empty_payload() {
        let got = pae("t", b"");
        assert_eq!(got, b"DSSEv1 1 t 0 ");
    }

    #[test]
    fn lengths_are_byte_lengths_not_char_counts() {
        // payloadType with a multibyte char: LEN must count UTF-8 bytes.
        let got = pae("é", "é".as_bytes());
        assert_eq!(got, b"DSSEv1 2 \xc3\xa9 2 \xc3\xa9");
    }
}
