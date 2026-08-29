//! Proof that the browser and the terminal say the same thing.
//!
//! The wasm entry point (`src/wasm.rs`) is a one-line forward to
//! `behalf_verify::json::verify_export_json`. This test runs the *real
//! `behalf-verify` binary* over a corpus of exports — intact, each documented
//! tamper class, and unreadable garbage — and asserts that for every one of
//! them the structured result the browser receives carries:
//!
//! - the same exit code,
//! - byte-identical stdout,
//! - byte-identical stderr,
//! - the same `class`/`index` pairs.
//!
//! So the shared-core claim is not a comment in a Cargo manifest: if anyone
//! ever forks the pipeline, or re-words a finding on one side only, this
//! fails. It runs in the ordinary native `cargo test`, on every commit,
//! without a wasm toolchain.
// Native-only: it spawns the CLI binary, which is the whole point — the
// comparison must be against the real terminal output.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use std::path::PathBuf;
use std::process::Command;

use behalf_verify::{verify_export_json, VerificationJson, Verdict};
use common::{as_strs, build_export, simple_payloads, test_signer};

fn write_temp(name: &str, contents: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&dir).expect("create tmpdir");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write temp file");
    path
}

/// Every mutation the browser page offers a button for, plus the ones the
/// tamper suite gates on, plus unreadable input.
fn corpus() -> Vec<(&'static str, Vec<u8>)> {
    let signer = test_signer(1);
    let payloads: Vec<String> = (0..6)
        .map(|i| {
            let amount = if i == 3 { "1200.00" } else { "12.00" };
            format!("{{\"receipt_id\":\"r{i}\",\"step\":{i},\"amount\":\"{amount}\"}}")
        })
        .collect();
    let intact = build_export(&signer, &as_strs(&payloads));

    let cover_up = intact.replace("1200.00", "12.00");

    let dropped: String = {
        let kept: Vec<&str> = intact
            .lines()
            .filter(|l| !l.contains("\"kind\":\"leaf\",\"index\":2,"))
            .collect();
        format!("{}\n", kept.join("\n"))
    };

    let reordered: String = {
        let mut lines: Vec<&str> = intact.lines().collect();
        lines.swap(2, 3); // leaves 1 and 2 (line 1 is the header)
        format!("{}\n", lines.join("\n"))
    };

    let truncated: String = {
        let lines: Vec<&str> = intact.lines().collect();
        let mut kept: Vec<&str> = lines[..lines.len() - 3].to_vec();
        kept.push(lines[lines.len() - 1]); // keep the head, which still says 6
        format!("{}\n", kept.join("\n"))
    };

    let chain_edited: Vec<u8> = {
        let at = intact.rfind("\"chain\":\"").expect("head chain present") + 9;
        let mut bytes = intact.clone().into_bytes();
        bytes[at] = if bytes[at] == b'0' { b'1' } else { b'0' };
        bytes
    };

    let head_missing: String = {
        let lines: Vec<&str> = intact.lines().collect();
        format!("{}\n", lines[..lines.len() - 1].join("\n"))
    };

    let duplicated: String = {
        let mut p = payloads.clone();
        p.push(p[0].clone());
        build_export(&signer, &as_strs(&p))
    };

    vec![
        ("intact", intact.into_bytes()),
        ("cover_up", cover_up.into_bytes()),
        ("dropped", dropped.into_bytes()),
        ("reordered", reordered.into_bytes()),
        ("truncated", truncated.into_bytes()),
        ("chain_edited", chain_edited),
        ("head_missing", head_missing.into_bytes()),
        ("duplicated", duplicated.into_bytes()),
        ("empty", Vec::new()),
        ("garbage", vec![0x00, 0xff, 0xfe, 0x7b, 0x0a]),
        ("not_an_export", b"{\"hello\":\"world\"}\n".to_vec()),
        ("zero_receipts", build_export(&test_signer(2), &[]).into_bytes()),
    ]
}

#[test]
fn browser_result_matches_the_cli_byte_for_byte() {
    for (name, bytes) in corpus() {
        let path = write_temp(&format!("parity_{name}.jsonl"), &bytes);
        let out = Command::new(env!("CARGO_BIN_EXE_behalf-verify"))
            .arg(&path)
            .output()
            .expect("spawn behalf-verify");

        let structured = VerificationJson::verify(&bytes);

        // Exit code.
        assert_eq!(
            out.status.code(),
            Some(structured.exit_code),
            "{name}: exit code differs"
        );

        // stdout, verbatim (the CLI adds the trailing newline `println!` does).
        let cli_stdout = String::from_utf8(out.stdout).expect("stdout is utf8");
        assert_eq!(
            cli_stdout,
            format!("{}\n", structured.stdout),
            "{name}: stdout differs"
        );

        // stderr, verbatim, line for line.
        let cli_stderr = String::from_utf8(out.stderr).expect("stderr is utf8");
        let cli_lines: Vec<&str> = if cli_stderr.is_empty() {
            Vec::new()
        } else {
            cli_stderr.trim_end_matches('\n').split('\n').collect()
        };
        assert_eq!(cli_lines, structured.stderr, "{name}: stderr differs");

        // And the JSON always renders, for every one of these inputs.
        let json = verify_export_json(&bytes);
        assert!(json.starts_with('{'), "{name}: result is not a JSON object");
        assert!(
            json.contains(&format!("\"exit_code\":{}", structured.exit_code)),
            "{name}: exit code missing from JSON"
        );
    }
}

/// One row of the documented contract: a corpus case and what the page must
/// show for it.
struct Expected {
    case: &'static str,
    verdict: Verdict,
    exit_code: i32,
    classes: &'static [(&'static str, i64)],
}

const fn row(
    case: &'static str,
    verdict: Verdict,
    exit_code: i32,
    classes: &'static [(&'static str, i64)],
) -> Expected {
    Expected {
        case,
        verdict,
        exit_code,
        classes,
    }
}

#[test]
fn verdicts_and_classes_track_the_documented_contract() {
    // docs/export-format-v1.md §5, in the structured shape the page renders.
    let expected = [
        row("intact", Verdict::Verified, 0, &[]),
        row("cover_up", Verdict::Tampered, 1, &[("content", 3)]),
        row("dropped", Verdict::Tampered, 1, &[("drop", 2)]),
        row("reordered", Verdict::Tampered, 1, &[("reorder", 1)]),
        row("truncated", Verdict::Tampered, 1, &[("truncation", 4)]),
        row("chain_edited", Verdict::Tampered, 1, &[("chain", -1)]),
        row("head_missing", Verdict::Tampered, 1, &[("truncation", -1)]),
        row("empty", Verdict::Unverifiable, 2, &[]),
        row("garbage", Verdict::Unverifiable, 2, &[]),
        row("not_an_export", Verdict::Unverifiable, 2, &[]),
        row("zero_receipts", Verdict::Verified, 0, &[]),
    ];
    let corpus = corpus();
    for e in &expected {
        let name = e.case;
        let bytes = &corpus
            .iter()
            .find(|(n, _)| *n == name)
            .unwrap_or_else(|| panic!("corpus case {name}"))
            .1;
        let v = VerificationJson::verify(bytes);
        assert_eq!(v.verdict, e.verdict, "{name}: verdict");
        assert_eq!(v.exit_code, e.exit_code, "{name}: exit code");
        let got: Vec<(&str, i64)> = v.failures.iter().map(|f| (f.class, f.index)).collect();
        assert_eq!(got, e.classes, "{name}: classes");
        if e.verdict == Verdict::Unverifiable {
            assert!(v.reason.is_some(), "{name}: unverifiable needs a reason");
        }
    }

    // Q46: a duplicate receipt_id is reported and still exits 0.
    let dup = &corpus
        .iter()
        .find(|(n, _)| *n == "duplicated")
        .expect("duplicated case")
        .1;
    let v = VerificationJson::verify(dup);
    assert_eq!(v.verdict, Verdict::Verified);
    assert_eq!(v.exit_code, 0);
    assert!(v.failures.is_empty());
    assert_eq!(v.duplicates.len(), 1);
    assert_eq!(v.duplicates[0].class, "duplicate");
    assert_eq!(v.duplicates[0].machine, "class=duplicate index=6");
}

#[test]
fn structured_result_carries_the_chain_head_the_cli_prints() {
    let signer = test_signer(3);
    let export = build_export(&signer, &as_strs(&simple_payloads(4)));
    let v = VerificationJson::verify(export.as_bytes());

    let chain = v.chain_head.as_deref().expect("chain head");
    let short = v.chain_head_short.as_deref().expect("short chain head");
    assert_eq!(chain.len(), 64);
    assert_eq!(short, format!("{}\u{2026}{}", &chain[..4], &chain[60..]));
    assert_eq!(
        v.stdout,
        format!("\u{2714} 4/4 receipts intact   chain head {short}")
    );
    assert_eq!(v.receipts, Some(4));
    assert_eq!(v.head_count, Some(4));
    assert_eq!(v.format, "behalf.sh/export/v1");
}
