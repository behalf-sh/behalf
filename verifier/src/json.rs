//! The structured verification result, as JSON.
//!
//! This is the *only* shaping layer between [`crate::verify_export`] and the
//! browser. It is compiled on every target — native included — so the native
//! test suite covers the exact bytes the wasm shim hands to JavaScript, and
//! so the shim itself ([`crate::wasm`]) stays a dozen lines of
//! `#[wasm_bindgen]` with no logic of its own.
//!
//! The fields are the CLI's own output, not a parallel vocabulary:
//!
//! - `exit_code` is [`crate::exit_code`] verbatim (0 / 1 / 2, Q92),
//! - `stdout` is [`crate::Report::human_stdout`] — the `✔ N/N receipts
//!   intact   chain head <first4>…<last4>` line, or `✖ TAMPERED` plus the
//!   per-failure lines and the unverifiable range,
//! - `stderr` is [`crate::Report::machine_stderr_lines`] — the
//!   `class=<class> index=<N>` lines,
//! - `failures[]`/`duplicates[]` carry the same `class` and `index` the CLI
//!   reports, already split out so a caller need not re-parse `stderr`.
//!
//! Unreadable input is a *value*, never a panic and never a thrown error:
//! `{"verdict":"unverifiable","exit_code":2,"reason":"…"}`.

use serde::Serialize;

use crate::verify::{verify_export, Failure, Report};
use crate::util::short_hex;

/// Overall verdict, matching the exit-code triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// Exit 0: every receipt, the chain and the head verify.
    Verified,
    /// Exit 1: tampering detected; `failures` says which class and where.
    Tampered,
    /// Exit 2: not a readable export; `reason` says why.
    Unverifiable,
}

impl Verdict {
    /// The stable lowercase token (`"verified"`, `"tampered"`,
    /// `"unverifiable"`).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Verified => "verified",
            Verdict::Tampered => "tampered",
            Verdict::Unverifiable => "unverifiable",
        }
    }
}

/// One finding, in the same `class` / `index` vocabulary as the CLI's
/// stderr lines.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FindingJson {
    /// `content`, `drop`, `reorder`, `chain`, `truncation`, `head`,
    /// `duplicate`.
    pub class: &'static str,
    /// Leaf index, or `-1` where no leaf index applies.
    pub index: i64,
    /// The CLI's one-line human description.
    pub human: String,
    /// The CLI's machine-readable stderr line for this finding.
    pub machine: String,
}

impl From<&Failure> for FindingJson {
    fn from(f: &Failure) -> Self {
        FindingJson {
            class: f.class.as_str(),
            index: f.index,
            human: f.human.clone(),
            machine: f.machine_line(),
        }
    }
}

/// The structured result handed to the browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationJson {
    /// `verified` / `tampered` / `unverifiable`.
    pub verdict: Verdict,
    /// The CLI exit code this verification would produce.
    pub exit_code: i32,
    /// The verifier's own `format` string, so a page can state what it read.
    pub format: &'static str,
    /// Leaf lines present in the file (`null` when unverifiable).
    pub receipts: Option<u64>,
    /// `head.count` as declared, when a head line was present.
    pub head_count: Option<u64>,
    /// `head.chain` in full, lowercase hex, when present.
    pub chain_head: Option<String>,
    /// `head.chain` abbreviated the way the CLI prints it (`4f0c…a19e`).
    pub chain_head_short: Option<String>,
    /// Tamper findings. Empty on a clean verify; never contains `duplicate`.
    pub failures: Vec<FindingJson>,
    /// Duplicate `receipt_id` findings — reported, but exit-0 compatible
    /// (Q46).
    pub duplicates: Vec<FindingJson>,
    /// Extra context lines, e.g. the unverifiable range after a content
    /// finding.
    pub notes: Vec<String>,
    /// Exactly what the CLI writes to stdout.
    pub stdout: String,
    /// Exactly what the CLI writes to stderr, one string per line.
    pub stderr: Vec<String>,
    /// Why the input was unreadable, when `verdict` is `unverifiable`.
    pub reason: Option<String>,
}

impl VerificationJson {
    /// Run the file-mode pipeline over raw export bytes and shape the result.
    ///
    /// Never panics and never returns an error: an unreadable export is the
    /// `unverifiable` verdict with `exit_code` 2.
    #[must_use]
    pub fn verify(data: &[u8]) -> Self {
        let result = verify_export(data);
        let exit_code = crate::exit_code(&result);
        match result {
            Ok(report) => Self::from_report(&report, exit_code),
            Err(u) => VerificationJson {
                verdict: Verdict::Unverifiable,
                exit_code,
                format: crate::verify::EXPORT_FORMAT,
                receipts: None,
                head_count: None,
                chain_head: None,
                chain_head_short: None,
                failures: Vec::new(),
                duplicates: Vec::new(),
                notes: Vec::new(),
                stdout: format!("\u{2716} UNVERIFIABLE: {u}"),
                stderr: vec![format!("behalf-verify: {u}")],
                reason: Some(u.reason),
            },
        }
    }

    fn from_report(report: &Report, exit_code: i32) -> Self {
        VerificationJson {
            verdict: if report.is_verified() {
                Verdict::Verified
            } else {
                Verdict::Tampered
            },
            exit_code,
            format: crate::verify::EXPORT_FORMAT,
            receipts: Some(report.leaves_present),
            head_count: report.head_count,
            chain_head: report.head_chain.clone(),
            chain_head_short: report.head_chain.as_deref().map(short_hex),
            failures: report.failures.iter().map(FindingJson::from).collect(),
            duplicates: report.duplicates.iter().map(FindingJson::from).collect(),
            notes: report.notes.clone(),
            stdout: report.human_stdout(),
            stderr: report.machine_stderr_lines(),
            reason: None,
        }
    }

    /// Serialize to a JSON string. Serialization of this struct cannot fail;
    /// the fallback keeps the no-panic guarantee absolute anyway.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| {
            String::from(
                r#"{"verdict":"unverifiable","exit_code":2,"reason":"result serialization failed"}"#,
            )
        })
    }
}

/// Verify export bytes and return the structured result as a JSON string.
///
/// The one entry point the wasm shim wraps.
#[must_use]
pub fn verify_export_json(data: &[u8]) -> String {
    VerificationJson::verify(data).to_json()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unverifiable_input_is_a_value_not_a_panic() {
        for case in [&b""[..], b"not json", b"{}", b"\x00\xff\xfe", b"{\"kind\":\"leaf\"}"] {
            let v = VerificationJson::verify(case);
            assert_eq!(v.verdict, Verdict::Unverifiable);
            assert_eq!(v.exit_code, 2);
            assert!(v.reason.is_some());
            assert!(v.stdout.starts_with("\u{2716} UNVERIFIABLE: "));
            // And the JSON always renders.
            assert!(v.to_json().contains("\"verdict\":\"unverifiable\""));
        }
    }

    #[test]
    fn verdict_tokens_are_stable() {
        assert_eq!(Verdict::Verified.as_str(), "verified");
        assert_eq!(Verdict::Tampered.as_str(), "tampered");
        assert_eq!(Verdict::Unverifiable.as_str(), "unverifiable");
        // Serde uses the same tokens.
        for v in [Verdict::Verified, Verdict::Tampered, Verdict::Unverifiable] {
            assert_eq!(
                serde_json::to_string(&v).expect("verdict serializes"),
                format!("\"{}\"", v.as_str())
            );
        }
    }
}
