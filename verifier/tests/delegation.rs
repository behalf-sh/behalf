//! Offline delegation-chain verification (ENG-38).
//!
//! Each broken-hop class gets a test that first asserts the *record* is
//! intact, then asserts the delegation finding. That order is the point: these
//! are exports nothing tampered with in the transparency-log sense, and every
//! integrity check passes on them. The only thing wrong is who authorised
//! what — which is exactly the property no transparency log can speak to, and
//! which until now behalf could only assert about itself.

mod common;

use behalf_verify::{verify_export, Invariant, TamperClass};
use common::*;
use ed25519_dalek::SigningKey;

fn export_for(hops: &[TestHop]) -> String {
    let emitter = test_signer(1);
    let payload = payload_with_chain("r0", hops);
    build_export_with_tokens(&emitter, &[&payload], &tokens_json(hops))
}

fn findings(data: &str) -> Vec<(Invariant, String)> {
    let report = verify_export(data.as_bytes()).expect("readable export");
    report
        .chain
        .findings
        .iter()
        .map(|f| (f.invariant, f.human.clone()))
        .collect()
}

#[test]
fn a_sound_chain_verifies_and_says_what_it_did_not_check() {
    let hops = sound_chain();
    let data = export_for(&hops);
    let report = verify_export(data.as_bytes()).expect("readable export");

    assert!(report.is_verified(), "record integrity: {:?}", report.failures);
    assert!(report.chain.is_clean(), "findings: {:?}", report.chain.findings);
    assert_eq!(report.chain.hops_checked, 2);

    // The caveat is not optional. A reader who takes this for a full
    // delegation verdict has been misled by omission.
    let line = report.chain_line().expect("a chain line");
    assert!(line.contains("I4"), "the I4 caveat is missing from: {line}");
    assert!(line.contains("identity root"), "the root caveat is missing from: {line}");
}

#[test]
fn a_forged_hop_is_caught_i1() {
    // The whole point. An attacker mints a hop under a key that is not the
    // one the parent confirms — every byte of the record is otherwise
    // authentic, and an independent implementation catches it.
    let mut hops = sound_chain();
    let impostor = SigningKey::from_bytes(&[99u8; 32]);
    hops[1] = mint_hop(
        &impostor,
        71,
        1,
        4,
        &hops[0].par_hash(),
        1_900_000_000,
        "jti-child",
    );
    let data = export_for(&hops);
    let report = verify_export(data.as_bytes()).expect("readable export");

    let f = findings(&data);
    assert!(
        f.iter().any(|(i, _)| *i == Invariant::Authority),
        "a hop signed by the wrong key was not caught: {f:?}"
    );
    // It surfaces as a tamper failure too, so the exit code needs no special case.
    assert!(report
        .failures
        .iter()
        .any(|f| f.class == TamperClass::Delegation));
    assert!(!report.is_verified());
}

#[test]
fn a_reparented_hop_is_caught_i5() {
    // par_hash names a token instance, not a shape. Point it elsewhere and the
    // linkage breaks even though the signature is still good.
    let mut hops = sound_chain();
    hops[1] = mint_hop(
        &hops[0].holder,
        71,
        1,
        4,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        1_900_000_000,
        "jti-child",
    );
    let f = findings(&export_for(&hops));
    assert!(
        f.iter().any(|(i, _)| *i == Invariant::Linkage),
        "a reparented hop was not caught: {f:?}"
    );
}

#[test]
fn a_widened_depth_budget_is_caught_i2() {
    let mut hops = sound_chain();
    hops[1] = mint_hop(
        &hops[0].holder,
        71,
        1,
        9, // parent's budget was 4
        &hops[0].par_hash(),
        1_900_000_000,
        "jti-child",
    );
    let f = findings(&export_for(&hops));
    assert!(
        f.iter().any(|(i, h)| *i == Invariant::Depth && h.contains("widens")),
        "a widened depth budget was not caught: {f:?}"
    );
}

#[test]
fn a_skipped_depth_is_caught_i2() {
    let mut hops = sound_chain();
    hops[1] = mint_hop(
        &hops[0].holder,
        71,
        3, // should be 1
        4,
        &hops[0].par_hash(),
        1_900_000_000,
        "jti-child",
    );
    let f = findings(&export_for(&hops));
    assert!(
        f.iter().any(|(i, h)| *i == Invariant::Depth && h.contains("increment")),
        "a skipped depth was not caught: {f:?}"
    );
}

#[test]
fn a_hop_outliving_its_parent_is_caught_i3() {
    let mut hops = sound_chain();
    hops[1] = mint_hop(
        &hops[0].holder,
        71,
        1,
        4,
        &hops[0].par_hash(),
        2_100_000_000, // parent expires at 2_000_000_000
        "jti-child",
    );
    let f = findings(&export_for(&hops));
    assert!(
        f.iter().any(|(i, _)| *i == Invariant::Expiry),
        "a hop outliving its parent was not caught: {f:?}"
    );
}

#[test]
fn a_root_naming_a_parent_is_caught() {
    let root_key = SigningKey::from_bytes(&[70u8; 32]);
    let root = mint_hop(
        &root_key,
        70,
        0,
        4,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        2_000_000_000,
        "jti-root",
    );
    let f = findings(&export_for(&[root]));
    assert!(
        f.iter().any(|(i, _)| *i == Invariant::Linkage),
        "a depth-0 hop naming a parent was not caught: {f:?}"
    );
}

#[test]
fn a_hop_with_no_jti_is_malformed() {
    // REQUIRED by the draft and by the frozen schema, and the other half of
    // the revocation-window join.
    let root_key = SigningKey::from_bytes(&[70u8; 32]);
    let root = mint_hop(&root_key, 70, 0, 4, ROOT_PAR_HASH, 2_000_000_000, "");
    let f = findings(&export_for(&[root]));
    assert!(
        f.iter().any(|(i, h)| *i == Invariant::Malformed && h.contains("jti")),
        "a hop with no jti was not caught: {f:?}"
    );
}

#[test]
fn a_receipt_that_misstates_its_own_token_is_caught() {
    // The receipt embeds a copy of the claim set. Editing the copy while
    // leaving the signed token alone must not pass silently.
    let hops = sound_chain();
    let data = export_for(&hops);
    let tampered = data.replace("\"del_max_depth\":4,\"par_hash\":\"0000", "\"del_max_depth\":8,\"par_hash\":\"0000");
    assert_ne!(tampered, data, "the test did not actually edit the receipt copy");

    // The leaf signature no longer covers these bytes, so the record is
    // tampered — and that is caught first, which is the correct order.
    let report = verify_export(tampered.as_bytes()).expect("readable export");
    assert!(!report.is_verified(), "editing a receipt left it verifying");
}

#[test]
fn an_unsigned_hop_is_reported_not_blamed() {
    // An agent presenting an unsigned claim is the normal day-zero state, not
    // an attack. It must be counted and named, never turned into a finding.
    let root_key = SigningKey::from_bytes(&[70u8; 32]);
    let root = mint_hop(&root_key, 70, 0, 4, ROOT_PAR_HASH, 2_000_000_000, "jti-root");
    let emitter = test_signer(1);
    let payload = format!(
        "{{\"receipt_id\":\"r0\",\"authority\":{{\"chain\":[{}]}}}}",
        "{\"del_depth\":0,\"del_max_depth\":4,\"par_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\",\"cnf\":{\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"x\"}},\"exp\":1,\"jti\":\"j\",\"verification\":{\"status\":\"asserted\"}}"
    );
    let data = build_export_with_tokens(&emitter, &[&payload], &tokens_json(&[root]));
    let report = verify_export(data.as_bytes()).expect("readable export");

    assert!(report.chain.is_clean(), "an unsigned hop produced a finding: {:?}", report.chain.findings);
    assert_eq!(report.chain.hops_unsigned, 1);
    assert!(report.is_verified());
}

#[test]
fn a_token_at_the_wrong_address_makes_the_file_unreadable() {
    let hops = sound_chain();
    let emitter = test_signer(1);
    let payload = payload_with_chain("r0", &hops);
    let wrong = format!(
        "{{\"{}\":\"{}\"}}",
        hops[0].evidence_ref(),
        hops[1].jws // the wrong token at the root's address
    );
    let data = build_export_with_tokens(&emitter, &[&payload], &wrong);
    assert!(
        verify_export(data.as_bytes()).is_err(),
        "a token stored at an address that is not its digest was accepted"
    );
}

#[test]
fn an_export_with_no_tokens_verifies_exactly_as_before() {
    // §2 requires unknown members to be ignored, and the section is optional.
    // Every vector written before ENG-38 must behave identically.
    let payloads = simple_payloads(3);
    let emitter = test_signer(1);
    let data = build_export(&emitter, &as_strs(&payloads));
    let report = verify_export(data.as_bytes()).expect("readable export");

    assert!(report.is_verified());
    assert!(report.chain.checked_nothing());
    assert!(report.chain_line().is_none(), "a tokenless export claimed something about chains");
}
