//! Pipeline tests over hand-built exports — independent of the Go vector
//! corpus, so symmetric bugs in the two implementations can't hide here.
// Native-only: it shares the filesystem-backed helpers in tests/common. The
// same pipeline is exercised through the browser entry point in
// tests/wasm_verify.rs.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use behalf_verify::{exit_code, verify_export, TamperClass};
use common::{
    as_strs, build_export, head_line, header_line, leaf_line, simple_payloads, test_signer,
};

/// Flip the first character after `marker` in `line`, staying inside the
/// base64/hex alphabet so the field remains decodable.
fn flip_after(line: &str, marker: &str, from_to: (char, char, char)) -> String {
    let (a, b, fallback) = from_to;
    let pos = line.rfind(marker).expect("marker present") + marker.len();
    let mut chars: Vec<char> = line.chars().collect();
    let c = chars[pos];
    chars[pos] = if c == a { b } else if c == b { fallback } else { a };
    chars.into_iter().collect()
}

fn classes(report: &behalf_verify::Report) -> Vec<(TamperClass, i64)> {
    report.failures.iter().map(|f| (f.class, f.index)).collect()
}

#[test]
fn intact_export_verifies() {
    let signer = test_signer(1);
    let payloads = simple_payloads(3);
    let export = build_export(&signer, &as_strs(&payloads));
    let report = verify_export(export.as_bytes()).expect("readable export");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
    assert!(report.duplicates.is_empty());
    assert_eq!(report.leaves_present, 3);
    assert_eq!(report.head_count, Some(3));
    assert_eq!(exit_code(&Ok(report.clone())), 0);
    let out = report.human_stdout();
    assert!(
        out.starts_with("\u{2714} 3/3 receipts intact   chain head "),
        "unexpected stdout: {out}"
    );
    // <first4>…<last4> of the chain digest, mirroring the demo script.
    let chain = report.head_chain.as_ref().expect("chain present");
    assert!(out.ends_with(&format!("{}\u{2026}{}", &chain[..4], &chain[60..])));
    assert!(report.machine_stderr_lines().is_empty());
}

#[test]
fn zero_receipt_export_verifies() {
    let signer = test_signer(1);
    let export = build_export(&signer, &[]);
    let report = verify_export(export.as_bytes()).expect("readable export");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
    assert_eq!(report.leaves_present, 0);
}

#[test]
fn cover_up_is_content_tamper_with_unverifiable_range() {
    let signer = test_signer(1);
    let payloads: Vec<String> = (0..5)
        .map(|i| {
            let amount = if i == 2 { "1200.00" } else { "5.00" };
            format!("{{\"receipt_id\":\"r{i}\",\"amount\":\"{amount}\"}}")
        })
        .collect();
    let export = build_export(&signer, &as_strs(&payloads));
    // The demo's cover-up: sed s/1200.00/12.00/ on the raw file.
    let tampered = export.replace("1200.00", "12.00");
    assert_ne!(export, tampered);

    let report = verify_export(tampered.as_bytes()).expect("still a readable export");
    assert_eq!(classes(&report), vec![(TamperClass::Content, 2)]);
    assert_eq!(
        report.machine_stderr_lines(),
        vec!["class=content index=2".to_string()]
    );
    assert_eq!(exit_code(&Ok(report.clone())), 1);
    let out = report.human_stdout();
    assert!(out.starts_with("\u{2716} TAMPERED"), "stdout: {out}");
    assert!(
        out.contains("receipt 2: content hash mismatch (expected "),
        "stdout: {out}"
    );
    assert!(
        out.contains("chain breaks at 2; receipts 3-4 unverifiable."),
        "stdout: {out}"
    );
}

#[test]
fn content_tamper_at_last_receipt_has_no_range() {
    let signer = test_signer(1);
    let payloads: Vec<String> = (0..3)
        .map(|i| {
            let tag = if i == 2 { "target" } else { "ok" };
            format!("{{\"receipt_id\":\"r{i}\",\"tag\":\"{tag}\"}}")
        })
        .collect();
    let export = build_export(&signer, &as_strs(&payloads));
    let tampered = export.replace("target", "edited");
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(classes(&report), vec![(TamperClass::Content, 2)]);
    assert!(report.notes.iter().any(|n| n == "chain breaks at 2."));
}

#[test]
fn signature_flip_is_content_tamper() {
    let signer = test_signer(1);
    let payloads = simple_payloads(4);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    // Leaf index 1 is file line 2; the last "sig":" in the line is the
    // signature value itself.
    lines[2] = flip_after(&lines[2], "\"sig\":\"", ('A', 'B', 'C'));
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(classes(&report), vec![(TamperClass::Content, 1)]);
    assert!(report.failures[0].human.contains("signature"));
}

#[test]
fn unknown_signing_key_is_content_tamper() {
    let signer = test_signer(1);
    let rogue = test_signer(9);
    let payloads = simple_payloads(2);
    let strs = as_strs(&payloads);
    // Leaf 1 signed by a key the header does not carry.
    let rogue_leaf = leaf_line(&rogue, 1, strs[1]);
    let intact = build_export(&signer, &strs);
    let mut lines: Vec<String> = intact.lines().map(str::to_string).collect();
    lines[2] = rogue_leaf;
    // Rebuild the head over the (unchanged) leaf hashes so only the keyid is
    // at fault... the leaf hash itself is unchanged because the payload is.
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(classes(&report), vec![(TamperClass::Content, 1)]);
    assert!(report.failures[0].human.contains("not in header"));
}

#[test]
fn dropped_leaf_is_classified_drop_at_missing_index() {
    let signer = test_signer(1);
    let payloads = simple_payloads(5);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    lines.remove(4); // leaf index 3
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(classes(&report), vec![(TamperClass::Drop, 3)]);
    assert_eq!(
        report.machine_stderr_lines(),
        vec!["class=drop index=3".to_string()]
    );
}

#[test]
fn multiple_dropped_leaves_report_each_missing_index() {
    let signer = test_signer(1);
    let payloads = simple_payloads(6);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    lines.remove(4); // leaf 3
    lines.remove(2); // leaf 1
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(
        classes(&report),
        vec![(TamperClass::Drop, 1), (TamperClass::Drop, 3)]
    );
}

#[test]
fn swapped_leaves_are_classified_reorder() {
    let signer = test_signer(1);
    let payloads = simple_payloads(5);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    lines.swap(2, 3); // leaves 1 and 2
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(classes(&report), vec![(TamperClass::Reorder, 1)]);
}

#[test]
fn removed_trailing_leaves_are_truncation() {
    let signer = test_signer(1);
    let payloads = simple_payloads(5);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    let head = lines.pop().expect("head");
    lines.truncate(4); // header + leaves 0..=2
    lines.push(head);
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(classes(&report), vec![(TamperClass::Truncation, 3)]);
    let out = report.human_stdout();
    assert!(
        out.contains("truncated: 3 receipts present, head declares 5"),
        "stdout: {out}"
    );
}

#[test]
fn missing_head_line_is_truncation() {
    let signer = test_signer(1);
    let payloads = simple_payloads(5);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    lines.pop();
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    // No leaf index is at fault when the head itself is gone: index -1.
    assert_eq!(classes(&report), vec![(TamperClass::Truncation, -1)]);
    assert!(report.failures[0].human.contains("head line missing"));
}

#[test]
fn edited_head_chain_is_chain_mismatch() {
    let signer = test_signer(1);
    let payloads = simple_payloads(4);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    let last = lines.len() - 1;
    lines[last] = flip_after(&lines[last], "\"chain\":\"", ('0', '1', '2'));
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    // Chain findings carry no leaf index: -1. The §2 ordering runs the chain
    // recompute before the head signature, so an edited head.chain is
    // class=chain even though the head signature is now also broken.
    assert_eq!(classes(&report), vec![(TamperClass::Chain, -1)]);
    assert!(report.failures[0].human.contains("chain mismatch"));
}

#[test]
fn flipped_head_signature_is_head_tamper() {
    let signer = test_signer(1);
    let payloads = simple_payloads(4);
    let export = build_export(&signer, &as_strs(&payloads));
    let mut lines: Vec<String> = export.lines().map(str::to_string).collect();
    let last = lines.len() - 1;
    lines[last] = flip_after(&lines[last], "\"sig\":\"", ('A', 'B', 'C'));
    let tampered = lines.join("\n") + "\n";
    let report = verify_export(tampered.as_bytes()).expect("readable");
    assert_eq!(classes(&report), vec![(TamperClass::Head, -1)]);
}

#[test]
fn head_signed_by_a_second_header_key_verifies() {
    // The intact_tiny vector has two header keys: leaves signed by the
    // emitter, head signed by a separate head-signer key. Lookup must be
    // per-signature by keyid.
    let emitter = test_signer(1);
    let head_signer = test_signer(2);
    let payloads = simple_payloads(2);
    let export = common::build_export_two_keys(&emitter, &head_signer, &as_strs(&payloads));
    let report = verify_export(export.as_bytes()).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
    assert_eq!(report.leaves_present, 2);
}

#[test]
fn duplicate_receipt_id_reported_but_exit_zero() {
    let signer = test_signer(1);
    let payloads = vec![
        "{\"receipt_id\":\"r0\",\"n\":0}".to_string(),
        "{\"receipt_id\":\"dup\",\"n\":1}".to_string(),
        "{\"receipt_id\":\"dup\",\"n\":2}".to_string(),
    ];
    let export = build_export(&signer, &as_strs(&payloads));
    let report = verify_export(export.as_bytes()).expect("readable");
    assert!(report.is_verified());
    assert_eq!(exit_code(&Ok(report.clone())), 0);
    assert_eq!(report.duplicates.len(), 1);
    assert_eq!(report.duplicates[0].class, TamperClass::Duplicate);
    assert_eq!(report.duplicates[0].index, 2);
    assert_eq!(
        report.machine_stderr_lines(),
        vec!["class=duplicate index=2".to_string()]
    );
    // Still shows the intact banner, plus the warning.
    let out = report.human_stdout();
    assert!(out.contains("3/3 receipts intact"), "stdout: {out}");
    assert!(out.contains("duplicate receipt_id"), "stdout: {out}");
}

#[test]
fn unknown_format_is_unverifiable() {
    let signer = test_signer(1);
    let export = build_export(&signer, &as_strs(&simple_payloads(2)))
        .replacen("behalf.sh/export/v1", "behalf.sh/export/v2", 1);
    let err = verify_export(export.as_bytes()).expect_err("must be unverifiable");
    assert!(err.reason.contains("unknown format"), "{}", err.reason);
    assert_eq!(exit_code(&Err(err)), 2);
}

#[test]
fn header_key_thumbprint_mismatch_is_unverifiable() {
    let signer = test_signer(1);
    let mut export = build_export(&signer, &as_strs(&simple_payloads(2)));
    export = export.replacen(&signer.jkt, "bm90LXRoZS1yaWdodC10aHVtYnByaW50", 1);
    let err = verify_export(export.as_bytes()).expect_err("must be unverifiable");
    assert!(err.reason.contains("thumbprint"), "{}", err.reason);
}

#[test]
fn malformed_inputs_are_unverifiable_never_panic() {
    let signer = test_signer(1);
    let intact = build_export(&signer, &as_strs(&simple_payloads(3)));

    // Truncated JSON: cut the file mid-line.
    let cut = &intact.as_bytes()[..intact.len() - 10];
    assert!(verify_export(cut).is_err());

    // Wrong type for index.
    let wrong_type = intact.replacen("\"index\":1", "\"index\":\"1\"", 1);
    assert!(verify_export(wrong_type.as_bytes()).is_err());

    // Negative index.
    let negative = intact.replacen("\"index\":1", "\"index\":-1", 1);
    assert!(verify_export(negative.as_bytes()).is_err());

    // Empty and whitespace-only files.
    assert!(verify_export(b"").is_err());
    assert!(verify_export(b"\n").is_err());
    assert!(verify_export(b"\n\n\n").is_err());

    // Binary garbage.
    assert!(verify_export(&[0x00, 0xff, 0xfe, 0x80, 0x7b, 0x22]).is_err());

    // A blank line in the middle.
    let blank = intact.replacen('\n', "\n\n", 1);
    assert!(verify_export(blank.as_bytes()).is_err());

    // First line is not a header.
    let mut lines: Vec<&str> = intact.lines().collect();
    lines.remove(0);
    let headless = lines.join("\n");
    assert!(verify_export(headless.as_bytes()).is_err());
}

#[test]
fn duplicate_payload_key_is_rejected_as_unverifiable() {
    let signer = test_signer(1);
    let intact = build_export(&signer, &as_strs(&simple_payloads(2)));
    // Smuggle a second top-level "payload" member into leaf 1.
    let tampered = intact.replacen(
        "{\"kind\":\"leaf\",\"index\":1,",
        "{\"kind\":\"leaf\",\"payload\":{\"shadow\":1},\"index\":1,",
        1,
    );
    let err = verify_export(tampered.as_bytes()).expect_err("must reject");
    assert!(err.reason.contains("duplicate"), "{}", err.reason);
}

#[test]
fn unknown_fields_are_ignored_everywhere() {
    let signer = test_signer(1);
    let export = build_export(&signer, &as_strs(&simple_payloads(2)))
        // Header gains an unknown field.
        .replacen(
            "{\"kind\":\"header\",",
            "{\"kind\":\"header\",\"greased\":\"checkpoint\",",
            1,
        )
        // A leaf line gains an unknown field (outside the payload span).
        .replacen(
            "{\"kind\":\"leaf\",\"index\":0,",
            "{\"kind\":\"leaf\",\"future\":[1,2,{}],\"index\":0,",
            1,
        )
        // The head line gains an unknown field outside the signed head value.
        .replacen(
            "{\"kind\":\"head\",",
            "{\"kind\":\"head\",\"note\":\"ignore me\",",
            1,
        );
    let report = verify_export(export.as_bytes()).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
}

#[test]
fn gnarly_payload_bytes_still_verify() {
    let signer = test_signer(1);
    let payloads = vec![
        // Escaped quotes, braces inside strings, escaped backslashes,
        // unicode escapes, nested arrays/objects.
        "{\"receipt_id\":\"r0\",\"note\":\"a \\\"b\\\" } { \\\\ \\u00e9 \\u007d\",\"nest\":[1,{\"x\":\"]\"}]}"
            .to_string(),
        // Multibyte UTF-8 straight in the bytes.
        "{\"receipt_id\":\"r1\",\"who\":\"よし … ✓\"}".to_string(),
    ];
    let export = build_export(&signer, &as_strs(&payloads));
    let report = verify_export(export.as_bytes()).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
}

#[test]
fn whitespace_variant_leaf_line_verifies() {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    use behalf_verify::chain::compute_chain;
    use behalf_verify::pae::{pae, RECEIPT_PAYLOAD_TYPE};
    use behalf_verify::util::{hex_encode, sha256};
    use ed25519_dalek::Signer;

    let signer = test_signer(1);
    // Payload with interior whitespace — signed over these exact bytes.
    let payload = "{ \"receipt_id\" : \"ws0\" , \"v\" : [ 1 , 2 ] }";
    let pae_bytes = pae(RECEIPT_PAYLOAD_TYPE, payload.as_bytes());
    let sig = B64.encode(signer.sk.sign(&pae_bytes).to_bytes());
    let hash = hex_encode(&sha256(&pae_bytes));
    let leaf = format!(
        "{{ \"kind\" : \"leaf\" , \"index\" : 0 , \"payloadType\" : \"{RECEIPT_PAYLOAD_TYPE}\" , \
         \"payload\" : {payload} , \"sig\" : {{ \"keyid\" : \"{}\" , \"sig\" : \"{sig}\" }} , \
         \"leaf_hash\" : \"{hash}\" }}",
        signer.jkt
    );
    let chain = hex_encode(&compute_chain(common::ORIGIN, &[sha256(&pae_bytes)]));
    let export = format!(
        "{}\n{leaf}\n{}\n",
        header_line(&signer),
        head_line(&signer, 1, &chain)
    );
    let report = verify_export(export.as_bytes()).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
}

#[test]
fn fuzz_shaped_no_panics() {
    let signer = test_signer(1);
    let intact = build_export(&signer, &as_strs(&simple_payloads(4)));
    let bytes = intact.as_bytes();

    // Every truncation length (stepped) must return, not panic.
    for end in (0..bytes.len()).step_by(3) {
        let _ = verify_export(&bytes[..end]);
    }

    // Single-byte corruptions across the file.
    for pos in (0..bytes.len()).step_by(5) {
        let mut mutated = bytes.to_vec();
        mutated[pos] ^= 0x01;
        let _ = verify_export(&mutated);
        mutated[pos] = 0x00;
        let _ = verify_export(&mutated);
    }

    // Deterministic pseudo-random garbage buffers.
    let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
    for _ in 0..32 {
        let mut buf = Vec::with_capacity(512);
        for _ in 0..512 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            buf.push((state & 0xff) as u8);
        }
        let _ = verify_export(&buf);
    }
}
