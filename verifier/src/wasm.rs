//! The browser shim: `wasm32-unknown-unknown` bindings over the same
//! verification core the CLI runs.
//!
//! Deliberately thin. Every function here forwards straight to
//! [`crate::json`], which forwards straight to [`crate::verify_export`] —
//! there is no second implementation of the pipeline, no re-classification,
//! and no re-wording of the CLI's output. What the terminal prints and what
//! the page shows come from the same bytes.
//!
//! What is *not* here, on purpose:
//!
//! - **No filesystem.** Log-directory mode ([`crate::verify_log_dir`]) reads
//!   a tile tree and is compiled out of the wasm target entirely; the page
//!   says so rather than half-supporting it.
//! - **No network.** Nothing in the verification path fetches anything —
//!   that is Q18's whole point, and it is a property of the code, not a
//!   promise in the UI.
//! - **No panics on untrusted bytes.** Malformed input returns the
//!   structured `unverifiable` result, so JavaScript never sees a thrown
//!   `RuntimeError` it has to distinguish from a real verdict.

use wasm_bindgen::prelude::wasm_bindgen;

/// Verify an export file's bytes and return the structured result as a JSON
/// string.
///
/// The shape is [`crate::json::VerificationJson`]: `verdict`, `exit_code`,
/// `receipts`, `chain_head`, `failures[{class,index,human,machine}]`,
/// `duplicates[]`, `notes[]`, `stdout`, `stderr[]`, `reason`.
///
/// Never throws: unreadable bytes come back as
/// `{"verdict":"unverifiable","exit_code":2,"reason":"…"}`.
#[wasm_bindgen(js_name = verifyExport)]
#[must_use]
pub fn verify_export_wasm(data: &[u8]) -> String {
    crate::json::verify_export_json(data)
}

/// The verifier version and the export `format` string it reads, as JSON —
/// so the page can state exactly which contract it is checking against.
#[wasm_bindgen(js_name = verifierInfo)]
#[must_use]
pub fn verifier_info() -> String {
    format!(
        r#"{{"name":"behalf-verify","version":"{}","format":"{}","modes":["file"]}}"#,
        env!("CARGO_PKG_VERSION"),
        crate::verify::EXPORT_FORMAT
    )
}
