//! Integration tests for `behalf-verify log`: tiny tile directories built
//! by hand (bytes, not via Go) covering the ENG-7 tamper matrix, plus
//! no-panic robustness on malformed inputs and the CLI surface itself.
// Native-only by construction: log mode walks a tile directory, and is not
// part of the wasm build at all (see the crate docs).
#![cfg(not(target_arch = "wasm32"))]

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use common::test_signer;
use common::tiledir::{
    build_envelope, checkpoint_note, emitter_keys_json, make_envelopes, note_signing_key,
    root_over, signed_envelope, write_log_dir, write_stale_partials, write_tiles, LOG_ORIGIN,
};

use behalf_verify::{verify_log_dir, LogOptions, TamperClass};

/// A unique scratch dir under cargo's test tmpdir.
fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn write_file(path: &Path, data: &[u8]) {
    std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    std::fs::write(path, data).expect("write");
}

/// Standard fixture: an emitter, a note key, `n` envelopes, an intact dir.
struct Fixture {
    dir: PathBuf,
    envelopes: Vec<Vec<u8>>,
    note_sk: ed25519_dalek::SigningKey,
    emitter: common::TestSigner,
    keys_path: PathBuf,
}

fn fixture(name: &str, n: usize) -> Fixture {
    let dir = scratch(name);
    let emitter = test_signer(9);
    let note_sk = note_signing_key(3);
    let envelopes = make_envelopes(&emitter, n);
    write_log_dir(&dir, &note_sk, &envelopes, n);
    let keys_path = dir.join("emitter-keys.json");
    write_file(&keys_path, emitter_keys_json(&emitter).as_bytes());
    Fixture {
        dir,
        envelopes,
        note_sk,
        emitter,
        keys_path,
    }
}

fn opts_with_keys(f: &Fixture) -> LogOptions {
    LogOptions {
        emitter_keys: Some(f.keys_path.clone()),
        ..LogOptions::default()
    }
}

// ---- intact -----------------------------------------------------------------

#[test]
fn intact_directory_verifies() {
    let f = fixture("log_intact", 5);
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
    assert_eq!(report.tree_size, 5);
    assert!(report.emitter_sigs_checked);
}

#[test]
fn intact_without_emitter_keys_verifies_with_caveat() {
    let f = fixture("log_intact_keyless", 5);
    let report = verify_log_dir(&f.dir, &LogOptions::default()).expect("readable");
    assert!(report.is_verified());
    assert!(!report.emitter_sigs_checked);
    assert!(report.human_stdout().contains("emitter signatures not checked"));
}

#[test]
fn intact_multi_bundle_with_full_tile() {
    // 260 entries: one full bundle (256) + a partial of 4. Exercises the
    // full-tile path and multi-bundle indexing.
    let f = fixture("log_multi_bundle", 260);
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
    assert!(f.dir.join("tile/entries/000").is_file(), "full tile expected");
}

#[test]
fn stale_partials_are_never_evidence_of_tampering() {
    // A grown log keeps its earlier partials on disk (GC off). The full
    // set must verify with the stale partials sitting right there.
    let f = fixture("log_stale_partials", 5);
    write_stale_partials(&f.dir, &f.envelopes, 3);
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
}

#[test]
fn tiles_ahead_of_checkpoint_are_tolerated() {
    // Integration runs ahead of checkpoint publication: 5 entries on disk,
    // checkpoint covers 4. Only the covered prefix is verified.
    let dir = scratch("log_checkpoint_lag");
    let emitter = test_signer(9);
    let note_sk = note_signing_key(3);
    let envelopes = make_envelopes(&emitter, 5);
    write_log_dir(&dir, &note_sk, &envelopes, 4);
    let report = verify_log_dir(&dir, &LogOptions::default()).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
    assert_eq!(report.tree_size, 4);
}

// ---- content ----------------------------------------------------------------

/// Flip one byte inside the payload region of stored entry `idx`.
fn flip_payload_byte(dir: &Path, bundle_rel: &str, marker: &[u8]) {
    let path = dir.join("tile/entries").join(bundle_rel);
    let mut data = std::fs::read(&path).expect("read bundle");
    let pos = data
        .windows(marker.len())
        .position(|w| w == marker)
        .expect("marker present in bundle");
    data[pos + marker.len() - 1] ^= 0x01; // flip a bit in the last marker byte
    std::fs::write(&path, data).expect("write bundle");
}

#[test]
fn flipped_envelope_byte_is_content_at_index_with_keys() {
    let f = fixture("log_flip_keys", 5);
    flip_payload_byte(&f.dir, "000.p/5", b"\"receipt_id\":\"r3\",\"step\":3");
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert_eq!(report.failures.len(), 1);
    assert_eq!(report.failures[0].class, TamperClass::Content);
    assert_eq!(report.failures[0].index, 3);
    assert_eq!(report.machine_stderr_lines(), ["class=content index=3"]);
    assert!(
        report.notes.iter().any(|n| n.contains("entries 4-4 unverifiable")),
        "notes: {:?}",
        report.notes
    );
}

#[test]
fn flipped_envelope_byte_is_content_at_index_keyless() {
    // Without emitter keys the stored level-0 hash tiles still localize
    // the divergence from the signed root.
    let f = fixture("log_flip_keyless", 5);
    flip_payload_byte(&f.dir, "000.p/5", b"\"receipt_id\":\"r3\",\"step\":3");
    let report = verify_log_dir(&f.dir, &LogOptions::default()).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=content index=3"]);
}

#[test]
fn foreign_emitter_key_is_content() {
    // Entry signed by a key outside the emitter set: content, like file
    // mode's swapped-in-foreign-key rule.
    let dir = scratch("log_foreign_key");
    let emitter = test_signer(9);
    let foreign = test_signer(13);
    let note_sk = note_signing_key(3);
    let mut envelopes = make_envelopes(&emitter, 4);
    envelopes[2] = signed_envelope(&foreign, "{\"receipt_id\":\"rf\",\"step\":2}");
    write_log_dir(&dir, &note_sk, &envelopes, 4);
    let keys_path = dir.join("emitter-keys.json");
    write_file(&keys_path, emitter_keys_json(&emitter).as_bytes());
    let report = verify_log_dir(
        &dir,
        &LogOptions {
            emitter_keys: Some(keys_path),
            ..LogOptions::default()
        },
    )
    .expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=content index=2"]);
    // Keyless, the same directory is internally consistent and verifies —
    // exactly the gap the emitter key set closes.
    let keyless = verify_log_dir(&dir, &LogOptions::default()).expect("readable");
    assert!(keyless.is_verified());
}

// ---- truncation -------------------------------------------------------------

#[test]
fn deleted_bundle_is_truncation() {
    let f = fixture("log_truncate_missing", 5);
    std::fs::remove_file(f.dir.join("tile/entries/000.p/5")).expect("delete bundle");
    std::fs::remove_file(f.dir.join("tile/0/000.p/5")).expect("delete hash tile");
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=truncation index=0"]);
}

#[test]
fn deleted_bundle_with_stale_partial_left_is_truncation_at_coverage_end() {
    // The highest bundle is deleted but a stale partial (size 3) lingers:
    // coverage ends at 3, and the stale partial itself is not the finding.
    let f = fixture("log_truncate_stale", 5);
    write_stale_partials(&f.dir, &f.envelopes, 3);
    std::fs::remove_file(f.dir.join("tile/entries/000.p/5")).expect("delete bundle");
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=truncation index=3"]);
}

#[test]
fn deleted_second_bundle_is_truncation_at_256() {
    let f = fixture("log_truncate_second", 260);
    std::fs::remove_file(f.dir.join("tile/entries/001.p/4")).expect("delete bundle");
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=truncation index=256"]);
}

// ---- head -------------------------------------------------------------------

#[test]
fn edited_checkpoint_root_is_head() {
    // Check order decision (documented in logdir.rs): the checkpoint note
    // signature is verified before anything else, so an edited root
    // classifies as head — unlike file mode, where the chain compare runs
    // before the head-signature check.
    let f = fixture("log_head_edit", 5);
    let cp_path = f.dir.join("checkpoint");
    let mut cp = std::fs::read(&cp_path).expect("read checkpoint");
    // Line 3 is the base64 root: flip its first character.
    let mut newlines = cp
        .iter()
        .enumerate()
        .filter(|(_, &b)| b == b'\n')
        .map(|(i, _)| i);
    let second_nl = newlines.nth(1).expect("root line exists");
    cp[second_nl + 1] = if cp[second_nl + 1] == b'A' { b'B' } else { b'A' };
    std::fs::write(&cp_path, cp).expect("write checkpoint");
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=head index=-1"]);
}

#[test]
fn checkpoint_resigned_with_wrong_key_is_head() {
    let f = fixture("log_head_wrong_key", 5);
    let other = note_signing_key(200);
    let root = root_over(&f.envelopes, 5);
    write_file(
        &f.dir.join("checkpoint"),
        &checkpoint_note(LOG_ORIGIN, &other, 5, &root),
    );
    let report = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=head index=-1"]);
}

// ---- chain ------------------------------------------------------------------

#[test]
fn consistently_rewritten_history_is_chain() {
    // Entry 2 rewritten AND the level-0 hash tile rebuilt to match: the
    // stored tiles no longer reproduce the signed root, so no index can be
    // pinned — chain.
    let dir = scratch("log_chain_rewrite");
    let emitter = test_signer(9);
    let note_sk = note_signing_key(3);
    let mut envelopes = make_envelopes(&emitter, 5);
    let root_before = root_over(&envelopes, 5);
    write_file(
        &dir.join("keys").join("checkpoint.vkey"),
        format!("{}\n", common::tiledir::vkey_string(LOG_ORIGIN, &note_sk)).as_bytes(),
    );
    write_file(
        &dir.join("checkpoint"),
        &checkpoint_note(LOG_ORIGIN, &note_sk, 5, &root_before),
    );
    // Rewrite entry 2 and lay tiles (incl. hash tiles) over the rewritten set.
    envelopes[2] = signed_envelope(&emitter, "{\"receipt_id\":\"rX\",\"step\":2}");
    write_tiles(&dir, &envelopes);
    let keys_path = dir.join("emitter-keys.json");
    write_file(&keys_path, emitter_keys_json(&emitter).as_bytes());
    let report = verify_log_dir(
        &dir,
        &LogOptions {
            emitter_keys: Some(keys_path),
            ..LogOptions::default()
        },
    )
    .expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=chain index=-1"]);
}

// ---- the Q76 stale-restore rule and forks (--latest-known) ------------------

#[test]
fn stale_restore_is_truncation_against_latest_known() {
    // The directory was restored from a backup taken at size 3; the
    // caller still holds the later checkpoint at size 5.
    let f = fixture("log_stale_restore", 5);
    let root3 = root_over(&f.envelopes, 3);
    let old_cp = checkpoint_note(LOG_ORIGIN, &f.note_sk, 3, &root3);
    write_file(&f.dir.join("checkpoint"), &old_cp);
    write_stale_partials(&f.dir, &f.envelopes, 3);
    let latest = f.dir.join("checkpoint.latest");
    let root5 = root_over(&f.envelopes, 5);
    write_file(&latest, &checkpoint_note(LOG_ORIGIN, &f.note_sk, 5, &root5));

    // Without the latest-known checkpoint the restore is undetectable —
    // the tree at size 3 is a valid prefix. That is exactly Q76's point.
    let silent = verify_log_dir(&f.dir, &opts_with_keys(&f)).expect("readable");
    assert!(silent.is_verified());

    let mut opts = opts_with_keys(&f);
    opts.latest_known = Some(latest);
    let report = verify_log_dir(&f.dir, &opts).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=truncation index=-1"]);
}

#[test]
fn fork_at_smaller_known_size_is_chain() {
    // The latest-known checkpoint (size 3) signed a history whose entry 2
    // differs from what the directory now contains: recomputing the old
    // root from current tiles must expose the fork.
    let f = fixture("log_fork_smaller", 5);
    let mut forked = f.envelopes.clone();
    forked[2] = signed_envelope(&f.emitter, "{\"receipt_id\":\"rY\",\"step\":2}");
    let known_root = root_over(&forked, 3);
    let latest = f.dir.join("checkpoint.known");
    write_file(
        &latest,
        &checkpoint_note(LOG_ORIGIN, &f.note_sk, 3, &known_root),
    );
    let mut opts = opts_with_keys(&f);
    opts.latest_known = Some(latest);
    let report = verify_log_dir(&f.dir, &opts).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=chain index=-1"]);
}

#[test]
fn fork_at_equal_size_is_chain() {
    let f = fixture("log_fork_equal", 5);
    let forked: Vec<Vec<u8>> = {
        let mut v = f.envelopes.clone();
        v[4] = signed_envelope(&f.emitter, "{\"receipt_id\":\"rZ\",\"step\":4}");
        v
    };
    let latest = f.dir.join("checkpoint.known");
    write_file(
        &latest,
        &checkpoint_note(LOG_ORIGIN, &f.note_sk, 5, &root_over(&forked, 5)),
    );
    let mut opts = opts_with_keys(&f);
    opts.latest_known = Some(latest);
    let report = verify_log_dir(&f.dir, &opts).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=chain index=-1"]);
}

#[test]
fn consistent_latest_known_passes_and_is_reported() {
    let f = fixture("log_known_ok", 5);
    let latest = f.dir.join("checkpoint.known");
    write_file(
        &latest,
        &checkpoint_note(LOG_ORIGIN, &f.note_sk, 3, &root_over(&f.envelopes, 3)),
    );
    let mut opts = opts_with_keys(&f);
    opts.latest_known = Some(latest);
    let report = verify_log_dir(&f.dir, &opts).expect("readable");
    assert!(report.is_verified(), "failures: {:?}", report.failures);
    assert_eq!(report.latest_known_size, Some(3));
    assert!(report.human_stdout().contains("consistent with latest-known"));
}

// ---- exit-2 malformation and no-panic robustness ----------------------------

#[test]
fn unreadable_inputs_are_unverifiable_not_panics() {
    // Missing directory.
    assert!(verify_log_dir(Path::new("/nonexistent/behalf-log"), &LogOptions::default()).is_err());

    // Missing vkey.
    let dir = scratch("log_no_vkey");
    assert!(verify_log_dir(&dir, &LogOptions::default()).is_err());

    // Garbage vkey.
    let f = fixture("log_bad_vkey", 2);
    write_file(&f.dir.join("keys/checkpoint.vkey"), b"not a vkey at all");
    assert!(verify_log_dir(&f.dir, &LogOptions::default()).is_err());

    // Missing checkpoint.
    let f = fixture("log_no_checkpoint", 2);
    std::fs::remove_file(f.dir.join("checkpoint")).expect("rm");
    assert!(verify_log_dir(&f.dir, &LogOptions::default()).is_err());

    // Garbage checkpoint bytes.
    let f = fixture("log_garbage_checkpoint", 2);
    write_file(&f.dir.join("checkpoint"), b"\x00\xff\xfe not a note");
    assert!(verify_log_dir(&f.dir, &LogOptions::default()).is_err());

    // Garbage bundle framing: an oversized length prefix.
    let f = fixture("log_garbage_bundle", 2);
    write_file(&f.dir.join("tile/entries/000.p/2"), &[0xff, 0xff, 0x01]);
    assert!(verify_log_dir(&f.dir, &LogOptions::default()).is_err());

    // Short frame inside the bundle.
    let f = fixture("log_short_frame", 2);
    write_file(&f.dir.join("tile/entries/000.p/2"), &[0x00, 0x09, b'x']);
    assert!(verify_log_dir(&f.dir, &LogOptions::default()).is_err());

    // Bad emitter key set.
    let f = fixture("log_bad_keys", 2);
    write_file(&f.dir.join("emitter-keys.json"), b"{\"keys\":42}");
    assert!(verify_log_dir(&f.dir, &opts_with_keys(&f)).is_err());

    // Bad latest-known bytes.
    let f = fixture("log_bad_known", 2);
    let known = f.dir.join("checkpoint.known");
    write_file(&known, b"garbage");
    let opts = LogOptions {
        latest_known: Some(known),
        ..LogOptions::default()
    };
    assert!(verify_log_dir(&f.dir, &opts).is_err());
}

#[test]
fn malformed_envelope_in_bundle_is_content_not_panic() {
    // A frame that parses as a frame but is not a stored envelope.
    let dir = scratch("log_bad_envelope");
    let emitter = test_signer(9);
    let note_sk = note_signing_key(3);
    let mut envelopes = make_envelopes(&emitter, 3);
    envelopes[1] = b"not an envelope at all".to_vec();
    write_log_dir(&dir, &note_sk, &envelopes, 3);
    let report = verify_log_dir(&dir, &LogOptions::default()).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=content index=1"]);

    // Duplicate-payload smuggling inside an envelope is content too.
    let dir = scratch("log_dup_payload");
    let mut envelopes = make_envelopes(&emitter, 3);
    envelopes[2] = build_envelope(
        "application/vnd.behalf.receipt+json",
        b"{\"a\":1},\"payload\":{\"b\":2}",
        &emitter.jkt,
        &[0u8; 64],
    );
    // That splice produces a duplicate top-level payload key.
    write_log_dir(&dir, &note_sk, &envelopes, 3);
    let report = verify_log_dir(&dir, &LogOptions::default()).expect("readable");
    assert_eq!(report.machine_stderr_lines(), ["class=content index=2"]);
}

// ---- CLI surface ------------------------------------------------------------

fn run_verifier(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_behalf-verify"))
        .args(args)
        .output()
        .expect("spawn behalf-verify")
}

#[test]
fn cli_intact_log_exits_zero() {
    let f = fixture("log_cli_intact", 5);
    let out = run_verifier(&[
        "log",
        f.dir.to_str().expect("utf8"),
        "--emitter-keys",
        f.keys_path.to_str().expect("utf8"),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\u{2714} 5/5 entries intact   checkpoint root "),
        "stdout: {stdout}"
    );
    assert!(out.stderr.is_empty(), "stderr: {:?}", out.stderr);
}

#[test]
fn cli_tampered_log_exits_one_with_machine_line() {
    let f = fixture("log_cli_tampered", 5);
    flip_payload_byte(&f.dir, "000.p/5", b"\"receipt_id\":\"r3\",\"step\":3");
    let out = run_verifier(&[
        "log",
        f.dir.to_str().expect("utf8"),
        "--emitter-keys",
        f.keys_path.to_str().expect("utf8"),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.lines().any(|l| l == "class=content index=3"),
        "stderr: {stderr}"
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("\u{2716} TAMPERED"));
}

#[test]
fn cli_explicit_vkey_flag_works() {
    let f = fixture("log_cli_vkey", 3);
    // Move the vkey out of its default location.
    let alt = f.dir.join("elsewhere.vkey");
    std::fs::rename(f.dir.join("keys/checkpoint.vkey"), &alt).expect("rename vkey");
    let out = run_verifier(&["log", f.dir.to_str().expect("utf8")]);
    assert_eq!(out.status.code(), Some(2), "default vkey path is gone");
    let out = run_verifier(&[
        "log",
        f.dir.to_str().expect("utf8"),
        "--vkey",
        alt.to_str().expect("utf8"),
    ]);
    assert_eq!(out.status.code(), Some(0));
}

#[test]
fn cli_latest_known_stale_restore_exits_one() {
    let f = fixture("log_cli_restore", 5);
    let root3 = root_over(&f.envelopes, 3);
    write_file(
        &f.dir.join("checkpoint"),
        &checkpoint_note(LOG_ORIGIN, &f.note_sk, 3, &root3),
    );
    write_stale_partials(&f.dir, &f.envelopes, 3);
    let latest = f.dir.join("checkpoint.latest");
    write_file(
        &latest,
        &checkpoint_note(LOG_ORIGIN, &f.note_sk, 5, &root_over(&f.envelopes, 5)),
    );
    let out = run_verifier(&[
        "log",
        f.dir.to_str().expect("utf8"),
        "--latest-known",
        latest.to_str().expect("utf8"),
    ]);
    assert_eq!(out.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.lines().any(|l| l == "class=truncation index=-1"),
        "stderr: {stderr}"
    );
}

#[test]
fn cli_bad_usage_exits_two() {
    assert_eq!(run_verifier(&["log"]).status.code(), Some(2));
    assert_eq!(
        run_verifier(&["log", "a", "b"]).status.code(),
        Some(2),
        "two positional args"
    );
    assert_eq!(
        run_verifier(&["log", "--vkey"]).status.code(),
        Some(2),
        "flag without value"
    );
    assert_eq!(
        run_verifier(&["log", "--unknown", "x"]).status.code(),
        Some(2)
    );
    assert_eq!(
        run_verifier(&["log", "/nonexistent/behalf-log"]).status.code(),
        Some(2)
    );
}

#[test]
fn cli_help_mentions_log_mode() {
    let out = run_verifier(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("behalf-verify log <dir>"), "stdout: {stdout}");
}
