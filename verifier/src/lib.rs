//! Offline verifier for behalf audit evidence.
//!
//! Two verification surfaces share one classification vocabulary and the
//! stable exit codes:
//!
//! - **File mode** ([`verify_export`]): the `behalf.sh/export/v1` JSONL
//!   export per `docs/export-format-v1.md` (Week-1 hand-rolled chain).
//! - **Log mode** ([`verify_log_dir`]): a Tessera-written tlog-tiles
//!   directory — signed note checkpoint, entry bundles, RFC 6962 Merkle
//!   root recomputation over the vendored azul `tlog_core` (Week 2).
//!
//! The load-bearing property everywhere is byte-exactness: the signed
//! bytes are the stored bytes are the hashed bytes. Payload bytes are
//! extracted from raw lines/envelopes by a span scanner ([`span`]) and fed
//! to PAE ([`pae`]) verbatim — nothing is ever parse-and-reserialized on
//! the verification path.
//!
//! # The wasm32 surface
//!
//! Building for `wasm32-unknown-unknown` gives the browser verifier the same
//! core, not a second one. File mode is target-independent — it takes a byte
//! slice and returns a [`Report`] — so it compiles unchanged; [`json`] shapes
//! that report into the structured result, and [`wasm`] is a `wasm-bindgen`
//! shim over [`json`] with no logic of its own.
//!
//! Log mode is the one thing that does not cross: [`logdir`] walks a tile
//! directory, which needs a filesystem. Rather than stub the filesystem out
//! and let the browser appear to support something it cannot, the
//! log-directory modules ([`logdir`], [`tiles`], [`envelope`], [`note`],
//! [`merkle`]) are simply absent from the wasm build, and the page says so.

pub mod aat;
/// The vendored RFC 6962 Merkle math from cloudflare/azul, compiled in as a
/// module rather than pulled as a dependency (crates.io accepts no path
/// dependencies, and azul is unpublished there). Verbatim upstream source
/// under a BSD-3-Clause licence; see `vendor/azul/VENDOR.md` and `NOTICE`.
#[cfg(not(target_arch = "wasm32"))]
#[path = "../vendor/azul/tlog_core/src/lib.rs"]
#[allow(clippy::all, dead_code, unused_imports)]
pub mod tlog_core;

pub mod chain;
#[cfg(not(target_arch = "wasm32"))]
pub mod envelope;
pub mod json;
pub mod keys;
#[cfg(not(target_arch = "wasm32"))]
pub mod logdir;
#[cfg(not(target_arch = "wasm32"))]
pub mod merkle;
#[cfg(not(target_arch = "wasm32"))]
pub mod note;
pub mod pae;
pub mod span;
#[cfg(not(target_arch = "wasm32"))]
pub mod tiles;
pub mod util;
pub mod verify;
#[cfg(target_arch = "wasm32")]
pub mod wasm;

pub use json::{verify_export_json, FindingJson, VerificationJson, Verdict};
#[cfg(not(target_arch = "wasm32"))]
pub use logdir::{verify_log_dir, LogOptions, LogReport};
pub use aat::{ChainFinding, ChainReport, Invariant};
pub use verify::{verify_export, Failure, Report, TamperClass, Unverifiable};

/// Stable exit codes (load-bearing for CI, Q92).
///
/// 0 = verified, 1 = tampering detected, 2 = unverifiable.
#[must_use]
pub fn exit_code(result: &Result<Report, Unverifiable>) -> i32 {
    match result {
        Ok(report) => {
            if report.failures.is_empty() {
                0
            } else {
                1
            }
        }
        Err(_) => 2,
    }
}
