//! `wasm-bindgen-test` coverage of the browser surface.
//!
//! These run against the real `wasm32-unknown-unknown` build, through the
//! same `#[wasm_bindgen]` entry point the page calls, and mirror the three
//! guarantees the native suite makes:
//!
//! 1. an intact export verifies (exit 0, `✔ N/N receipts intact`),
//! 2. a tampered export classifies exactly as the CLI classifies it
//!    (`class`/`index`, plus the unverifiable range),
//! 3. malformed input comes back as a structured `unverifiable` result —
//!    never a panic, never a thrown `RuntimeError` JavaScript would have to
//!    tell apart from a real verdict.
//!
//! The exports are built here, in raw strings, exactly as `tests/common`
//! builds them for the native suite — the bytes are under the test's control,
//! which is the same byte-exactness the verifier promises.
//!
//! Run with `make wasm-test`.
//!
//! `tests/common` is not reused because it pulls in the filesystem-backed
//! tile-directory helpers, which do not exist on wasm32.

#![cfg(target_arch = "wasm32")]

use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use wasm_bindgen_test::wasm_bindgen_test;

use behalf_verify::chain::compute_chain;
use behalf_verify::keys::okp_thumbprint;
use behalf_verify::pae::{pae, CHAIN_HEAD_PAYLOAD_TYPE, RECEIPT_PAYLOAD_TYPE};
use behalf_verify::util::{hex_encode, sha256};
use behalf_verify::wasm::{verifier_info, verify_export_wasm};

const ORIGIN: &str = "behalf.sh/test-origin";

struct Signer0 {
    sk: SigningKey,
    x_b64: String,
    jkt: String,
}

fn test_signer() -> Signer0 {
    let sk = SigningKey::from_bytes(&[1u8; 32]);
    let x_b64 = URL_SAFE_NO_PAD.encode(sk.verifying_key().to_bytes());
    let jkt = okp_thumbprint("Ed25519", "OKP", &x_b64).expect("thumbprint");
    Signer0 { sk, x_b64, jkt }
}

fn build_export(s: &Signer0, payloads: &[String]) -> String {
    let hashes: Vec<[u8; 32]> = payloads
        .iter()
        .map(|p| sha256(&pae(RECEIPT_PAYLOAD_TYPE, p.as_bytes())))
        .collect();
    let chain_hex = hex_encode(&compute_chain(ORIGIN, &hashes));

    let mut out = format!(
        "{{\"kind\":\"header\",\"format\":\"behalf.sh/export/v1\",\"log_origin\":\"{ORIGIN}\",\
         \"keys\":[{{\"jkt\":\"{}\",\"jwk\":{{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"{}\"}}}}]}}\n",
        s.jkt, s.x_b64
    );
    for (i, p) in payloads.iter().enumerate() {
        let pae_bytes = pae(RECEIPT_PAYLOAD_TYPE, p.as_bytes());
        let sig = BASE64_STD.encode(s.sk.sign(&pae_bytes).to_bytes());
        let leaf_hash = hex_encode(&sha256(&pae_bytes));
        out.push_str(&format!(
            "{{\"kind\":\"leaf\",\"index\":{i},\"payloadType\":\"{RECEIPT_PAYLOAD_TYPE}\",\
             \"payload\":{p},\"sig\":{{\"keyid\":\"{}\",\"sig\":\"{sig}\"}},\
             \"leaf_hash\":\"{leaf_hash}\"}}\n",
            s.jkt
        ));
    }
    let head_value = format!(
        "{{\"format\":\"behalf.sh/export/v1\",\"log_origin\":\"{ORIGIN}\",\
         \"count\":{},\"chain\":\"{chain_hex}\"}}",
        payloads.len()
    );
    let head_sig = BASE64_STD.encode(
        s.sk.sign(&pae(CHAIN_HEAD_PAYLOAD_TYPE, head_value.as_bytes()))
            .to_bytes(),
    );
    out.push_str(&format!(
        "{{\"kind\":\"head\",\"head\":{head_value},\"sig\":{{\"keyid\":\"{}\",\"sig\":\"{head_sig}\"}}}}\n",
        s.jkt
    ));
    out
}

/// Five receipts; index 3 carries the `1200.00` the cover-up edits, exactly
/// as the demo fixture's step 31 does.
fn demo_payloads() -> Vec<String> {
    (0..5)
        .map(|i| {
            let amount = if i == 3 { "1200.00" } else { "12.00" };
            format!("{{\"receipt_id\":\"r{i}\",\"step\":{i},\"amount\":\"{amount}\"}}")
        })
        .collect()
}

/// The wasm entry point returns a JSON string; parse it the way the page does.
fn verify(bytes: &[u8]) -> serde_json::Value {
    serde_json::from_str(&verify_export_wasm(bytes)).expect("result is valid JSON")
}

fn class_index(v: &serde_json::Value, n: usize) -> (String, i64) {
    let f = &v["failures"][n];
    (
        f["class"].as_str().expect("class").to_string(),
        f["index"].as_i64().expect("index"),
    )
}

#[wasm_bindgen_test]
fn intact_export_verifies() {
    let s = test_signer();
    let export = build_export(&s, &demo_payloads());
    let v = verify(export.as_bytes());

    assert_eq!(v["verdict"], "verified");
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["receipts"], 5);
    assert_eq!(v["head_count"], 5);
    assert!(v["failures"].as_array().expect("failures").is_empty());
    assert!(v["duplicates"].as_array().expect("duplicates").is_empty());
    assert!(v["stderr"].as_array().expect("stderr").is_empty());
    assert!(v["reason"].is_null());

    // The CLI's own vocabulary, verbatim.
    let stdout = v["stdout"].as_str().expect("stdout");
    assert!(
        stdout.starts_with("\u{2714} 5/5 receipts intact   chain head "),
        "unexpected stdout: {stdout}"
    );
    let chain = v["chain_head"].as_str().expect("chain head");
    let short = v["chain_head_short"].as_str().expect("short chain head");
    assert_eq!(chain.len(), 64);
    assert_eq!(short, format!("{}\u{2026}{}", &chain[..4], &chain[60..]));
    assert!(stdout.ends_with(short));
}

#[wasm_bindgen_test]
fn cover_up_is_content_tampering_with_the_unverifiable_range() {
    let s = test_signer();
    let export = build_export(&s, &demo_payloads()).replace("1200.00", "12.00");
    let v = verify(export.as_bytes());

    assert_eq!(v["verdict"], "tampered");
    assert_eq!(v["exit_code"], 1);
    assert_eq!(class_index(&v, 0), ("content".to_string(), 3));
    assert_eq!(v["stderr"][0], "class=content index=3");
    assert_eq!(v["failures"][0]["machine"], "class=content index=3");
    assert_eq!(v["notes"][0], "chain breaks at 3; receipts 4-4 unverifiable.");
    let stdout = v["stdout"].as_str().expect("stdout");
    assert!(stdout.starts_with("\u{2716} TAMPERED\n"), "{stdout}");
    assert!(stdout.contains("receipt 3: content hash mismatch"), "{stdout}");
}

#[wasm_bindgen_test]
fn dropped_receipt_classifies_as_drop() {
    let s = test_signer();
    let export = build_export(&s, &demo_payloads());
    let kept: Vec<&str> = export
        .lines()
        .filter(|l| !l.contains("\"kind\":\"leaf\",\"index\":2,"))
        .collect();
    let v = verify(format!("{}\n", kept.join("\n")).as_bytes());

    assert_eq!(v["verdict"], "tampered");
    assert_eq!(v["exit_code"], 1);
    assert_eq!(class_index(&v, 0), ("drop".to_string(), 2));
}

#[wasm_bindgen_test]
fn edited_chain_head_classifies_as_chain() {
    let s = test_signer();
    let export = build_export(&s, &demo_payloads());
    // Flip the first hex digit of head.chain, staying in the alphabet — the
    // same edit the page's "Edit the chain head" button makes.
    let at = export.rfind("\"chain\":\"").expect("head chain present") + 9;
    let mut bytes = export.into_bytes();
    bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
    let v = verify(&bytes);

    assert_eq!(v["verdict"], "tampered");
    assert_eq!(v["exit_code"], 1);
    assert_eq!(class_index(&v, 0), ("chain".to_string(), -1));
}

#[wasm_bindgen_test]
fn truncated_export_classifies_as_truncation() {
    let s = test_signer();
    let export = build_export(&s, &demo_payloads());
    // Keep the head (which still declares 5) but drop the last two leaves.
    let lines: Vec<&str> = export.lines().collect();
    let mut kept: Vec<&str> = lines[..lines.len() - 3].to_vec();
    kept.push(lines[lines.len() - 1]);
    let v = verify(format!("{}\n", kept.join("\n")).as_bytes());

    assert_eq!(v["verdict"], "tampered");
    assert_eq!(v["exit_code"], 1);
    assert_eq!(class_index(&v, 0), ("truncation".to_string(), 3));
}

#[wasm_bindgen_test]
fn malformed_input_is_a_structured_error_not_a_panic() {
    let cases: &[&[u8]] = &[
        b"",
        b"   ",
        b"not json at all",
        b"{}",
        b"[1,2,3]",
        b"{\"kind\":\"header\"}",
        b"{\"kind\":\"header\",\"format\":\"behalf.sh/export/v2\",\"log_origin\":\"x\",\"keys\":[]}",
        b"{\"kind\":\"leaf\",\"index\":0}",
        &[0x00, 0xff, 0xfe, 0x7b],
    ];
    for case in cases {
        let v = verify(case);
        assert_eq!(v["verdict"], "unverifiable", "case {case:?}");
        assert_eq!(v["exit_code"], 2, "case {case:?}");
        assert!(v["reason"].is_string(), "case {case:?} must carry a reason");
        assert!(v["receipts"].is_null(), "case {case:?}");
        assert!(
            v["stdout"]
                .as_str()
                .is_some_and(|s| s.starts_with("\u{2716} UNVERIFIABLE: ")),
            "case {case:?}"
        );
    }
}

#[wasm_bindgen_test]
fn every_prefix_of_a_real_export_is_panic_free() {
    let s = test_signer();
    let export = build_export(&s, &demo_payloads());
    let bytes = export.as_bytes();
    // A truncated download is the most ordinary malformed input there is.
    for end in (0..bytes.len()).step_by(7) {
        let v = verify(&bytes[..end]);
        let verdict = v["verdict"].as_str().expect("verdict");
        assert!(
            matches!(verdict, "verified" | "tampered" | "unverifiable"),
            "prefix {end}: {verdict}"
        );
    }
}

#[wasm_bindgen_test]
fn duplicate_receipt_ids_are_reported_but_still_verify() {
    let s = test_signer();
    let dup = "{\"receipt_id\":\"r0\",\"step\":9,\"amount\":\"1.00\"}".to_string();
    let mut payloads = demo_payloads();
    payloads.push(dup);
    let v = verify(build_export(&s, &payloads).as_bytes());

    // Q46: duplicates are reported, never tampering.
    assert_eq!(v["verdict"], "verified");
    assert_eq!(v["exit_code"], 0);
    assert_eq!(v["duplicates"][0]["class"], "duplicate");
    assert_eq!(v["duplicates"][0]["index"], 5);
    assert_eq!(v["stderr"][0], "class=duplicate index=5");
}

#[wasm_bindgen_test]
fn verifier_info_names_file_mode_only() {
    let info: serde_json::Value =
        serde_json::from_str(&verifier_info()).expect("info is valid JSON");
    assert_eq!(info["name"], "behalf-verify");
    assert_eq!(info["format"], "behalf.sh/export/v1");
    // Tile-directory mode needs a filesystem and is deliberately absent.
    assert_eq!(info["modes"].as_array().expect("modes").len(), 1);
    assert_eq!(info["modes"][0], "file");
}
