//! `behalf-verify` — offline verifier for behalf audit evidence.
//!
//! Two modes, one classification vocabulary and one set of exit codes:
//!
//!   behalf-verify <export.jsonl>
//!       verify a behalf.sh/export/v1 export file (Week 1)
//!   behalf-verify log <dir> [--vkey <path>] [--latest-known <file>]
//!                           [--emitter-keys <file>]
//!       verify a tlog-tiles log directory (Week 2): checkpoint note
//!       signature, entry bundles, RFC 6962 root recomputation, and the
//!       Q76 stale-restore rule against a previously-seen checkpoint
//!
//! Exit codes (stable, load-bearing for CI):
//!   0  verified
//!   1  tampering detected (content, drop, reorder, chain, truncation, head)
//!   2  unverifiable: not readable evidence (bad args, missing file,
//!      malformed input, unknown format)
//!
//! Human output goes to stdout; machine-readable findings go to stderr as
//! `class=<class> index=<N>` lines (`-1` where no leaf index applies).
//!
//! The CLI is native-only: it reads files, walks directories and exits with
//! a status code, none of which a browser has. On `wasm32-unknown-unknown`
//! this binary is an empty stub and the verification core is reached through
//! `behalf_verify::wasm` instead (see the crate docs).

#[cfg(not(target_arch = "wasm32"))]
use std::path::PathBuf;

#[cfg(not(target_arch = "wasm32"))]
use behalf_verify::{exit_code, verify_export, verify_log_dir, LogOptions};

#[cfg(not(target_arch = "wasm32"))]
const USAGE: &str = "usage: behalf-verify <export.jsonl>
       behalf-verify log <dir> [--vkey <path>] [--latest-known <file>] [--emitter-keys <file>]";

#[cfg(not(target_arch = "wasm32"))]
fn main() {
    std::process::exit(run());
}

#[cfg(target_arch = "wasm32")]
fn main() {}

#[cfg(not(target_arch = "wasm32"))]
fn run() -> i32 {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return 0;
    }
    if args.first().map(String::as_str) == Some("log") {
        return run_log(&args[1..]);
    }
    let [path] = args.as_slice() else {
        eprintln!("{USAGE}");
        return 2;
    };

    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) => {
            println!("\u{2716} UNVERIFIABLE: cannot read {path}: {e}");
            eprintln!("behalf-verify: cannot read {path}: {e}");
            return 2;
        }
    };

    let result = verify_export(&data);
    match &result {
        Ok(report) => {
            println!("{}", report.human_stdout());
            for line in report.machine_stderr_lines() {
                eprintln!("{line}");
            }
        }
        Err(u) => {
            println!("\u{2716} UNVERIFIABLE: {u}");
            eprintln!("behalf-verify: {u}");
        }
    }
    exit_code(&result)
}

#[cfg(not(target_arch = "wasm32"))]
fn run_log(args: &[String]) -> i32 {
    let mut dir: Option<PathBuf> = None;
    let mut opts = LogOptions::default();
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        let flag_value = |it: &mut std::slice::Iter<'_, String>| -> Option<PathBuf> {
            it.next().map(PathBuf::from)
        };
        match arg.as_str() {
            "--vkey" => {
                let Some(v) = flag_value(&mut it) else {
                    eprintln!("behalf-verify: --vkey needs a path\n{USAGE}");
                    return 2;
                };
                opts.vkey = Some(v);
            }
            "--latest-known" => {
                let Some(v) = flag_value(&mut it) else {
                    eprintln!("behalf-verify: --latest-known needs a path\n{USAGE}");
                    return 2;
                };
                opts.latest_known = Some(v);
            }
            "--emitter-keys" => {
                let Some(v) = flag_value(&mut it) else {
                    eprintln!("behalf-verify: --emitter-keys needs a path\n{USAGE}");
                    return 2;
                };
                opts.emitter_keys = Some(v);
            }
            other if other.starts_with('-') => {
                eprintln!("behalf-verify: unknown flag {other}\n{USAGE}");
                return 2;
            }
            other => {
                if dir.replace(PathBuf::from(other)).is_some() {
                    eprintln!("{USAGE}");
                    return 2;
                }
            }
        }
    }
    let Some(dir) = dir else {
        eprintln!("{USAGE}");
        return 2;
    };

    match verify_log_dir(&dir, &opts) {
        Ok(report) => {
            println!("{}", report.human_stdout());
            for line in report.machine_stderr_lines() {
                eprintln!("{line}");
            }
            i32::from(!report.is_verified())
        }
        Err(u) => {
            println!("\u{2716} UNVERIFIABLE: {u}");
            eprintln!("behalf-verify: {u}");
            2
        }
    }
}
