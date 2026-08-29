//! Conformance runner over the Go-generated vector corpus (contract §3).
//!
//! Reads the directory named by `BEHALF_VECTORS` (default
//! `../testdata/vectors` relative to this crate). If the directory does not
//! exist the test prints a skip message and passes — the Go generator may not
//! have run locally.
//!
//! Comparison conventions shared with the Go generator:
//! - `expected.json` is `{exit_code, classes:[{class, index}]}`;
//! - garbage-style cases are `exit_code: 2` with empty `classes`;
//! - `index` is `-1` for classes with no leaf index (chain, head).
// Native-only: the vector corpus is read from disk. The browser surface has
// its own wasm32 suite in tests/wasm_verify.rs.
#![cfg(not(target_arch = "wasm32"))]

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::{
    STANDARD as B64_STD, STANDARD_NO_PAD as B64_STD_NP, URL_SAFE as B64_URL, URL_SAFE_NO_PAD as B64_URL_NP,
};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey, Verifier};
use serde::Deserialize;

use behalf_verify::chain::compute_chain;
use behalf_verify::keys::okp_thumbprint;
use behalf_verify::pae::pae;
use behalf_verify::util::{hex_decode, hex_encode, sha256};
use behalf_verify::{exit_code, verify_export};

fn vectors_dir() -> Option<PathBuf> {
    let dir = match std::env::var_os("BEHALF_VECTORS") {
        Some(v) => PathBuf::from(v),
        None => Path::new(env!("CARGO_MANIFEST_DIR")).join("../testdata/vectors"),
    };
    dir.is_dir().then_some(dir)
}

/// Decode base64 that may come from any common Go encoder configuration.
fn b64_any(s: &str) -> Option<Vec<u8>> {
    B64_STD
        .decode(s)
        .or_else(|_| B64_STD_NP.decode(s))
        .or_else(|_| B64_URL.decode(s))
        .or_else(|_| B64_URL_NP.decode(s))
        .ok()
}

fn json_files(dir: &Path, ext: &str) -> Vec<PathBuf> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().and_then(|e| e.to_str()) == Some(ext))
        .collect();
    files.sort();
    files
}

#[derive(Deserialize)]
struct PaeVector {
    payload_type: String,
    payload_b64: String,
    expected_pae_sha256_hex: String,
}

#[derive(Deserialize)]
struct SigVector {
    seed_b64: String,
    jkt: String,
    pae_sha256_hex: String,
    expected_sig_b64: String,
    // Beyond the contract's field list, the generator also emits the PAE
    // inputs so the signature can be verified over the full PAE bytes.
    payload_type: Option<String>,
    payload_b64: Option<String>,
}

#[derive(Deserialize)]
struct ChainVector {
    log_origin: String,
    leaf_hashes_hex: Vec<String>,
    expected_chain_hex: String,
}

#[derive(Deserialize)]
struct Expected {
    exit_code: i32,
    #[serde(default)]
    classes: Vec<ExpectedClass>,
}

#[derive(Deserialize)]
struct ExpectedClass {
    class: String,
    index: Option<i64>,
}

struct Tally {
    checked: usize,
    errors: Vec<String>,
}

impl Tally {
    fn fail(&mut self, msg: String) {
        self.errors.push(msg);
    }
}

#[test]
fn conformance_corpus() {
    let Some(dir) = vectors_dir() else {
        println!(
            "skipping conformance: vector corpus not found (set BEHALF_VECTORS or generate \
             testdata/vectors with the Go writer)"
        );
        return;
    };
    let mut tally = Tally {
        checked: 0,
        errors: Vec::new(),
    };

    check_pae_vectors(&dir.join("pae"), &mut tally);
    check_sig_vectors(&dir.join("sig"), &mut tally);
    check_chain_vectors(&dir.join("chain"), &mut tally);
    check_exports(&dir.join("exports"), &mut tally);

    println!(
        "conformance: {} vectors checked, {} failures",
        tally.checked,
        tally.errors.len()
    );
    assert!(
        tally.errors.is_empty(),
        "conformance failures:\n{}",
        tally.errors.join("\n")
    );
}

fn check_pae_vectors(dir: &Path, tally: &mut Tally) {
    for path in json_files(dir, "json") {
        let name = path.display().to_string();
        tally.checked += 1;
        let v: PaeVector = match read_json(&path) {
            Ok(v) => v,
            Err(e) => {
                tally.fail(format!("{name}: {e}"));
                continue;
            }
        };
        let Some(payload) = b64_any(&v.payload_b64) else {
            tally.fail(format!("{name}: payload_b64 does not decode"));
            continue;
        };
        let got = hex_encode(&sha256(&pae(&v.payload_type, &payload)));
        if got != v.expected_pae_sha256_hex.to_lowercase() {
            tally.fail(format!(
                "{name}: pae sha256 mismatch: got {got}, want {}",
                v.expected_pae_sha256_hex
            ));
        }
    }
}

fn check_sig_vectors(dir: &Path, tally: &mut Tally) {
    for path in json_files(dir, "json") {
        let name = path.display().to_string();
        tally.checked += 1;
        let v: SigVector = match read_json(&path) {
            Ok(v) => v,
            Err(e) => {
                tally.fail(format!("{name}: {e}"));
                continue;
            }
        };
        let Some(seed) = b64_any(&v.seed_b64) else {
            tally.fail(format!("{name}: seed_b64 does not decode"));
            continue;
        };
        let Ok(seed32) = <[u8; 32]>::try_from(seed.as_slice()) else {
            tally.fail(format!("{name}: seed is {} bytes, want 32", seed.len()));
            continue;
        };
        let sk = SigningKey::from_bytes(&seed32);
        let x_b64 = B64_URL_NP.encode(sk.verifying_key().to_bytes());
        match okp_thumbprint("Ed25519", "OKP", &x_b64) {
            Ok(jkt) if jkt == v.jkt => {}
            Ok(jkt) => {
                tally.fail(format!("{name}: jkt mismatch: got {jkt}, want {}", v.jkt));
                continue;
            }
            Err(e) => {
                tally.fail(format!("{name}: thumbprint: {e}"));
                continue;
            }
        }
        // Reconstruct the full PAE from the generator's extra fields; the
        // signature is over the PAE bytes, never their hash.
        let (Some(payload_type), Some(payload_b64)) = (&v.payload_type, &v.payload_b64) else {
            tally.fail(format!(
                "{name}: missing payload_type/payload_b64; cannot verify signature over PAE"
            ));
            continue;
        };
        let Some(payload) = b64_any(payload_b64) else {
            tally.fail(format!("{name}: payload_b64 does not decode"));
            continue;
        };
        let pae_bytes = pae(payload_type, &payload);
        let pae_hash = hex_encode(&sha256(&pae_bytes));
        if pae_hash != v.pae_sha256_hex.to_lowercase() {
            tally.fail(format!(
                "{name}: pae_sha256 cross-check failed: got {pae_hash}, want {}",
                v.pae_sha256_hex
            ));
            continue;
        }
        let Some(sig_bytes) = b64_any(&v.expected_sig_b64) else {
            tally.fail(format!("{name}: expected_sig_b64 does not decode"));
            continue;
        };
        // Ed25519 is deterministic: signing must reproduce the vector.
        let ours = sk.sign(&pae_bytes);
        if ours.to_bytes().as_slice() != sig_bytes.as_slice() {
            tally.fail(format!("{name}: deterministic signature differs from vector"));
            continue;
        }
        let Ok(sig) = ed25519_dalek::Signature::from_slice(&sig_bytes) else {
            tally.fail(format!("{name}: expected sig has wrong length"));
            continue;
        };
        if sk.verifying_key().verify(&pae_bytes, &sig).is_err() {
            tally.fail(format!("{name}: expected sig does not verify over PAE"));
        }
    }
}

fn check_chain_vectors(dir: &Path, tally: &mut Tally) {
    for path in json_files(dir, "json") {
        let name = path.display().to_string();
        tally.checked += 1;
        let v: ChainVector = match read_json(&path) {
            Ok(v) => v,
            Err(e) => {
                tally.fail(format!("{name}: {e}"));
                continue;
            }
        };
        let mut hashes: Vec<[u8; 32]> = Vec::with_capacity(v.leaf_hashes_hex.len());
        let mut bad = false;
        for h in &v.leaf_hashes_hex {
            match hex_decode(h).and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok()) {
                Some(arr) => hashes.push(arr),
                None => {
                    tally.fail(format!("{name}: leaf hash {h:?} is not 32-byte hex"));
                    bad = true;
                    break;
                }
            }
        }
        if bad {
            continue;
        }
        let got = hex_encode(&compute_chain(&v.log_origin, &hashes));
        if got != v.expected_chain_hex.to_lowercase() {
            tally.fail(format!(
                "{name}: chain mismatch: got {got}, want {}",
                v.expected_chain_hex
            ));
        }
    }
}

fn check_exports(dir: &Path, tally: &mut Tally) {
    // intact_*.jsonl: must verify with exit-0 semantics.
    for path in json_files(dir, "jsonl") {
        let name = path.display().to_string();
        let stem = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if !stem.starts_with("intact_") {
            continue;
        }
        tally.checked += 1;
        let Ok(data) = fs::read(&path) else {
            tally.fail(format!("{name}: unreadable"));
            continue;
        };
        let result = verify_export(&data);
        let code = exit_code(&result);
        if code != 0 {
            let detail = describe_result(&result);
            tally.fail(format!("{name}: expected exit 0, got {code} ({detail})"));
        }
    }

    // tampered_*/: {file.jsonl, expected.json}.
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("tampered_"))
        })
        .collect();
    dirs.sort();
    for case_dir in dirs {
        let name = case_dir.display().to_string();
        tally.checked += 1;
        let expected: Expected = match read_json(&case_dir.join("expected.json")) {
            Ok(e) => e,
            Err(e) => {
                tally.fail(format!("{name}: expected.json: {e}"));
                continue;
            }
        };
        let Ok(data) = fs::read(case_dir.join("file.jsonl")) else {
            tally.fail(format!("{name}: file.jsonl unreadable"));
            continue;
        };
        let result = verify_export(&data);
        let code = exit_code(&result);
        if code != expected.exit_code {
            tally.fail(format!(
                "{name}: exit code {code}, want {} ({})",
                expected.exit_code,
                describe_result(&result)
            ));
            continue;
        }
        let actual: Vec<(String, i64)> = match &result {
            Ok(report) => report
                .failures
                .iter()
                .chain(report.duplicates.iter())
                .map(|f| (f.class.as_str().to_string(), f.index))
                .collect(),
            Err(_) => Vec::new(),
        };
        if let Some(msg) = compare_classes(&expected.classes, &actual) {
            tally.fail(format!("{name}: {msg}"));
        }
    }
}

/// Compare the expected class list with the actual findings. Order-insensitive;
/// an expected entry without an index matches any finding of that class.
fn compare_classes(expected: &[ExpectedClass], actual: &[(String, i64)]) -> Option<String> {
    let mut remaining: Vec<&(String, i64)> = actual.iter().collect();
    for e in expected {
        let pos = remaining
            .iter()
            .position(|(class, index)| class == &e.class && e.index.is_none_or(|i| i == *index));
        match pos {
            Some(p) => {
                remaining.remove(p);
            }
            None => {
                return Some(format!(
                    "expected finding class={} index={:?} not produced; actual: {}",
                    e.class,
                    e.index,
                    render(actual)
                ));
            }
        }
    }
    if remaining.is_empty() {
        None
    } else {
        Some(format!(
            "unexpected extra findings: {}; expected only {}",
            render(&remaining.into_iter().cloned().collect::<Vec<_>>()),
            expected.len()
        ))
    }
}

fn render(findings: &[(String, i64)]) -> String {
    let mut out = String::from("[");
    for (i, (class, index)) in findings.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "class={class} index={index}");
    }
    out.push(']');
    out
}

fn describe_result(result: &Result<behalf_verify::Report, behalf_verify::Unverifiable>) -> String {
    match result {
        Ok(report) => {
            if report.failures.is_empty() {
                "verified".to_string()
            } else {
                render(
                    &report
                        .failures
                        .iter()
                        .map(|f| (f.class.as_str().to_string(), f.index))
                        .collect::<Vec<_>>(),
                )
            }
        }
        Err(u) => format!("unverifiable: {u}"),
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let data = fs::read(path).map_err(|e| format!("read: {e}"))?;
    serde_json::from_slice(&data).map_err(|e| format!("parse: {e}"))
}
