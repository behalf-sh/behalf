//! End-to-end CLI tests: exit codes, stdout/stderr shape.
// Native-only: it spawns the CLI binary and writes temp files. The browser
// surface has its own wasm32 suite in tests/wasm_verify.rs.
#![cfg(not(target_arch = "wasm32"))]

mod common;

use std::path::PathBuf;
use std::process::{Command, Output};

use common::{as_strs, build_export, simple_payloads, test_signer};

fn write_temp(name: &str, contents: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&dir).expect("create tmpdir");
    let path = dir.join(name);
    std::fs::write(&path, contents).expect("write temp file");
    path
}

fn run_verifier(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_behalf-verify"))
        .args(args)
        .output()
        .expect("spawn behalf-verify")
}

#[test]
fn intact_file_exits_zero() {
    let signer = test_signer(1);
    let export = build_export(&signer, &as_strs(&simple_payloads(3)));
    let path = write_temp("cli_intact.jsonl", export.as_bytes());
    let out = run_verifier(&[path.to_str().expect("utf8 path")]);
    assert_eq!(out.status.code(), Some(0));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("\u{2714} 3/3 receipts intact   chain head "),
        "stdout: {stdout}"
    );
    assert!(out.stderr.is_empty(), "stderr not empty: {:?}", out.stderr);
}

#[test]
fn tampered_file_exits_one_with_machine_line() {
    let signer = test_signer(1);
    let payloads: Vec<String> = (0..5)
        .map(|i| {
            let amount = if i == 2 { "1200.00" } else { "7.00" };
            format!("{{\"receipt_id\":\"r{i}\",\"amount\":\"{amount}\"}}")
        })
        .collect();
    let export = build_export(&signer, &as_strs(&payloads)).replace("1200.00", "12.00");
    let path = write_temp("cli_tampered.jsonl", export.as_bytes());
    let out = run_verifier(&[path.to_str().expect("utf8 path")]);
    assert_eq!(out.status.code(), Some(1));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stdout.contains("\u{2716} TAMPERED"), "stdout: {stdout}");
    assert!(
        stdout.contains("chain breaks at 2; receipts 3-4 unverifiable."),
        "stdout: {stdout}"
    );
    assert!(
        stderr.lines().any(|l| l == "class=content index=2"),
        "stderr: {stderr}"
    );
}

#[test]
fn garbage_file_exits_two() {
    let path = write_temp("cli_garbage.bin", &[0x00, 0xde, 0xad, 0xbe, 0xef, 0x0a, 0x7b]);
    let out = run_verifier(&[path.to_str().expect("utf8 path")]);
    assert_eq!(out.status.code(), Some(2));
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("UNVERIFIABLE"), "stdout: {stdout}");
}

#[test]
fn missing_file_exits_two() {
    let out = run_verifier(&["/nonexistent/behalf/export.jsonl"]);
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn bad_args_exit_two() {
    assert_eq!(run_verifier(&[]).status.code(), Some(2));
    assert_eq!(run_verifier(&["a", "b"]).status.code(), Some(2));
}

#[test]
fn help_exits_zero() {
    let out = run_verifier(&["--help"]);
    assert_eq!(out.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&out.stdout).contains("usage:"));
}
