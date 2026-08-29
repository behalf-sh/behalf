//! The `behalf verify` pipeline (contract §2).
//!
//! Checks in contract order, reporting the **first** failure class and
//! continuing only where that stays meaningful:
//!
//! 1. header (unknown `format` → unverifiable; unknown extra fields ignored
//!    everywhere),
//! 2. per-leaf content (span → PAE → `leaf_hash` → signature); a mismatch is
//!    content tampering at that index and every later receipt is unverifiable,
//! 3. index sequence (gap → drop, non-ascending → reorder),
//! 4. chain recomputation vs `head.chain`,
//! 5. `head.count` vs leaves present (fewer → truncation),
//! 6. head signature,
//! 7. missing head line → truncation.
//!
//! Duplicate `receipt_id` values are reported but never tampering (Q46):
//! exit 0 if everything else verifies.

use std::collections::HashMap;

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::Deserialize;

use crate::aat::{check_chains, ChainReport};
use crate::chain::compute_chain;
use crate::keys::validate_header_key;
use crate::pae::{pae, CHAIN_HEAD_PAYLOAD_TYPE};
use crate::span::extract_top_level_bytes;
use crate::util::{hex_decode, hex_encode, sha256, short4, short_hex};

/// The only `format` this Week-1 verifier reads.
pub const EXPORT_FORMAT: &str = "behalf.sh/export/v1";

/// Tamper classification (stable machine-readable names).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TamperClass {
    Content,
    Drop,
    Reorder,
    Chain,
    Truncation,
    Head,
    Duplicate,
    /// A delegation invariant broke (ENG-38). Distinct from `Chain`, which is
    /// the hash chain over leaves: this one is about who authorised what.
    Delegation,
}

impl TamperClass {
    /// The `class=` token emitted on stderr.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            TamperClass::Content => "content",
            TamperClass::Drop => "drop",
            TamperClass::Reorder => "reorder",
            TamperClass::Chain => "chain",
            TamperClass::Truncation => "truncation",
            TamperClass::Head => "head",
            TamperClass::Duplicate => "duplicate",
            TamperClass::Delegation => "delegation",
        }
    }
}

impl std::fmt::Display for TamperClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One classified finding.
///
/// `index` conventions (shared with the Go implementation so conformance
/// comparison is direct): content → the tampered leaf's index; drop → the
/// missing index; reorder → the first position where ascending order breaks;
/// truncation → the first missing index; chain and head (and a missing head
/// line) carry no leaf index and use `-1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    pub class: TamperClass,
    pub index: i64,
    /// Human-readable one-line description.
    pub human: String,
}

impl Failure {
    /// The machine-readable stderr line: `class=<...> index=<N>`.
    #[must_use]
    pub fn machine_line(&self) -> String {
        format!("class={} index={}", self.class, self.index)
    }
}

/// Result of running the pipeline over a readable export.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    /// Number of leaf lines present in the file.
    pub leaves_present: u64,
    /// `head.count`, when a head line was present and parseable.
    pub head_count: Option<u64>,
    /// `head.chain` as declared, when present.
    pub head_chain: Option<String>,
    /// Tamper findings (exit 1 when non-empty). Never contains `Duplicate`.
    pub failures: Vec<Failure>,
    /// Duplicate `receipt_id` findings (reported, exit-0 compatible).
    pub duplicates: Vec<Failure>,
    /// Extra human-readable context lines (e.g. the unverifiable range).
    pub notes: Vec<String>,
    /// What the delegation chains could and could not be checked against
    /// (ENG-38). Its findings are also mirrored into `failures` as
    /// `TamperClass::Delegation`, so exit codes need no special case.
    pub chain: ChainReport,
}

impl Report {
    /// True when the export verified (duplicates alone do not fail it).
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.failures.is_empty()
    }

    /// The human stdout block, mirroring the demo script.
    #[must_use]
    pub fn human_stdout(&self) -> String {
        let mut out = String::new();
        if self.is_verified() {
            let n = self.leaves_present;
            let chain = self.head_chain.as_deref().unwrap_or("");
            out.push_str(&format!(
                "\u{2714} {n}/{n} receipts intact   chain head {}",
                short_hex(chain)
            ));
        } else {
            out.push_str("\u{2716} TAMPERED");
            for f in &self.failures {
                out.push('\n');
                out.push_str(&f.human);
            }
            for note in &self.notes {
                out.push('\n');
                out.push_str(note);
            }
        }
        for d in &self.duplicates {
            out.push('\n');
            out.push_str(&format!("\u{26a0} {}", d.human));
        }
        if let Some(line) = self.chain_line() {
            out.push('\n');
            out.push_str(&line);
        }
        out
    }

    /// The delegation line: what was checked, and — always — what was not.
    ///
    /// The second half is not decoration. This verifier checks four of the
    /// draft's six invariants; a reader who takes a clean run as "the
    /// delegation chain is fully verified" has been misled by omission, and
    /// that is the failure mode this product exists to argue against. So the
    /// caveat is printed on success, where it is inconvenient, rather than
    /// only in documentation.
    #[must_use]
    pub fn chain_line(&self) -> Option<String> {
        let c = &self.chain;
        if c.checked_nothing() && c.hops_unsigned == 0 && c.hops_missing_token == 0 {
            // No export-carried chain material at all: an export written
            // before ENG-38, or a run with no delegation. Saying nothing is
            // right — there is no claim to qualify.
            return None;
        }
        let mut line = if c.is_clean() {
            format!(
                "\u{2714} {} delegation hop(s) checked: I1 authority, I2 depth, I3 expiry, I5 linkage",
                c.hops_checked
            )
        } else {
            format!("\u{2716} {} delegation finding(s)", c.findings.len())
        };
        line.push_str("\n  not checked here: I4 capability monotonicity, I6 proof of possession, and the identity root");
        if c.hops_unsigned > 0 {
            line.push_str(&format!(
                "\n  {} hop(s) caller-asserted: no token accompanies them, so nothing about them was checked",
                c.hops_unsigned
            ));
        }
        if c.hops_missing_token > 0 {
            line.push_str(&format!(
                "\n  {} hop(s) reference a token this export does not carry",
                c.hops_missing_token
            ));
        }
        Some(line)
    }

    /// Machine-readable stderr lines, one per finding.
    #[must_use]
    pub fn machine_stderr_lines(&self) -> Vec<String> {
        self.failures
            .iter()
            .chain(self.duplicates.iter())
            .map(Failure::machine_line)
            .collect()
    }
}

/// The export could not be read at all (exit 2): bad structure, malformed
/// JSON, unknown format, inconsistent header keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unverifiable {
    pub reason: String,
}

impl std::fmt::Display for Unverifiable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for Unverifiable {}

fn unverifiable(reason: impl Into<String>) -> Unverifiable {
    Unverifiable {
        reason: reason.into(),
    }
}

// ---- wire structs (unknown fields are ignored by serde's default) ----

#[derive(Deserialize)]
struct KindProbe {
    kind: String,
}

#[derive(Deserialize)]
struct HeaderLine {
    format: String,
    log_origin: String,
    keys: Vec<HeaderKeyEntry>,
    /// The delegation hop tokens the receipts reference, keyed by
    /// `evidence_ref` (ENG-38). Absent on exports written before the section
    /// existed, which §2 requires this reader to accept unchanged.
    #[serde(default)]
    tokens: HashMap<String, String>,
}

#[derive(Deserialize)]
struct HeaderKeyEntry {
    jkt: String,
    jwk: Jwk,
}

#[derive(Deserialize)]
struct Jwk {
    kty: String,
    crv: String,
    x: String,
}

#[derive(Deserialize)]
struct SigBlock {
    keyid: String,
    sig: String,
}

#[derive(Deserialize)]
struct LeafLine {
    index: u64,
    #[serde(rename = "payloadType")]
    payload_type: String,
    payload: serde_json::Value,
    sig: SigBlock,
    leaf_hash: String,
}

#[derive(Deserialize)]
struct HeadLine {
    head: HeadValue,
    sig: SigBlock,
}

#[derive(Deserialize)]
struct HeadValue {
    count: u64,
    chain: String,
}

/// Run the full verification pipeline over raw export file bytes.
///
/// `Ok(report)` means the file was a readable export; `report.failures`
/// carries any tamper findings (exit 1 when non-empty, exit 0 otherwise).
/// `Err` means the file is not a readable export (exit 2).
pub fn verify_export(data: &[u8]) -> Result<Report, Unverifiable> {
    let lines = split_lines(data)?;
    let (first, rest) = lines
        .split_first()
        .ok_or_else(|| unverifiable("empty file"))?;

    // Step 1: header.
    let header = parse_header(first)?;
    let keys = build_key_map(&header)?;
    check_token_addresses(&header.tokens)?;

    // Structure: leaves in file order, then exactly one optional head (last).
    let mut leaves: Vec<(usize, &[u8], LeafLine)> = Vec::new();
    let mut head: Option<(&[u8], HeadLine)> = None;
    for (offset, raw) in rest.iter().enumerate() {
        let line_no = offset + 2; // 1-based, after the header
        let kind =
            probe_kind(raw).map_err(|e| unverifiable(format!("line {line_no}: {e}")))?;
        match kind.as_str() {
            "leaf" => {
                if head.is_some() {
                    return Err(unverifiable(format!(
                        "line {line_no}: leaf line after the head line"
                    )));
                }
                let leaf: LeafLine = serde_json::from_slice(raw).map_err(|e| {
                    unverifiable(format!("line {line_no}: malformed leaf line: {e}"))
                })?;
                leaves.push((line_no, raw, leaf));
            }
            "head" => {
                if head.is_some() {
                    return Err(unverifiable(format!("line {line_no}: second head line")));
                }
                let parsed: HeadLine = serde_json::from_slice(raw).map_err(|e| {
                    unverifiable(format!("line {line_no}: malformed head line: {e}"))
                })?;
                head = Some((raw, parsed));
            }
            other => {
                return Err(unverifiable(format!(
                    "line {line_no}: unknown line kind {other:?}"
                )));
            }
        }
    }

    let leaves_present = leaves.len() as u64;
    let head_count = head.as_ref().map(|(_, h)| h.head.count);
    let head_chain = head.as_ref().map(|(_, h)| h.head.chain.clone());
    let duplicates = find_duplicate_receipt_ids(&leaves);

    let mut report = Report {
        leaves_present,
        head_count,
        head_chain,
        failures: Vec::new(),
        duplicates,
        notes: Vec::new(),
        chain: ChainReport::default(),
    };

    // Step 2: per-leaf content — span, PAE, leaf_hash, signature.
    let mut computed_hashes: Vec<[u8; 32]> = Vec::with_capacity(leaves.len());
    for (line_no, raw, leaf) in &leaves {
        match check_leaf_content(raw, leaf, &keys) {
            Ok(hash) => computed_hashes.push(hash),
            Err(LeafContentError::Malformed(msg)) => {
                return Err(unverifiable(format!("line {line_no}: {msg}")));
            }
            Err(LeafContentError::Tampered(human)) => {
                let n = leaf.index;
                report.failures.push(Failure {
                    class: TamperClass::Content,
                    index: as_i64(n),
                    human,
                });
                let last = head_count.unwrap_or(leaves_present).saturating_sub(1);
                if n < last {
                    report.notes.push(format!(
                        "chain breaks at {n}; receipts {}-{last} unverifiable.",
                        n + 1
                    ));
                } else {
                    report.notes.push(format!("chain breaks at {n}."));
                }
                return Ok(report);
            }
        }
    }

    // Step 3: index sequence.
    let indices: Vec<u64> = leaves.iter().map(|(_, _, l)| l.index).collect();
    match classify_sequence(&indices) {
        SequenceIssue::Ok => {}
        SequenceIssue::Reorder { index } => {
            report.failures.push(Failure {
                class: TamperClass::Reorder,
                index: as_i64(index),
                human: format!("receipt {index}: out of order (export reordered)"),
            });
            return Ok(report);
        }
        SequenceIssue::Drops(missing) => {
            for m in missing {
                report.failures.push(Failure {
                    class: TamperClass::Drop,
                    index: as_i64(m),
                    human: format!("receipt {m}: missing from export (dropped)"),
                });
            }
            return Ok(report);
        }
    }

    // Step 7 (checked here because nothing beyond needs the head absent case):
    // a missing head line is truncation. No leaf index is at fault: -1.
    let Some((head_raw, head_line)) = head else {
        report.failures.push(Failure {
            class: TamperClass::Truncation,
            index: -1,
            human: "head line missing; export truncated".to_string(),
        });
        return Ok(report);
    };

    // Step 5: head.count vs leaves present — fewer leaves is truncation at
    // the first missing index. (Checked before the chain compare: a count
    // mismatch makes the chain compare trivially meaningless.)
    if leaves_present < head_line.head.count {
        report.failures.push(Failure {
            class: TamperClass::Truncation,
            index: as_i64(leaves_present),
            human: format!(
                "truncated: {leaves_present} receipts present, head declares {}",
                head_line.head.count
            ),
        });
        return Ok(report);
    }

    // Step 4: recompute the chain and compare with head.chain.
    let computed_chain = compute_chain(&header.log_origin, &computed_hashes);
    let computed_chain_hex = hex_encode(&computed_chain);
    let declared_chain = hex_decode(&head_line.head.chain).filter(|v| v.len() == 32);
    if declared_chain.as_deref() != Some(&computed_chain[..]) {
        report.failures.push(Failure {
            class: TamperClass::Chain,
            index: -1,
            human: format!(
                "chain mismatch: head declares {} computed {}",
                short_hex(&head_line.head.chain),
                short_hex(&computed_chain_hex)
            ),
        });
        return Ok(report);
    }

    // Step 6: head signature over PAE(chain-head type, head_bytes).
    if let Err(human) = check_head_signature(head_raw, &head_line, &keys)? {
        report.failures.push(Failure {
            class: TamperClass::Head,
            index: -1,
            human,
        });
        return Ok(report);
    }

    // Step 7: delegation chains (ENG-38).
    //
    // Last on purpose. Every step above establishes that the record is the one
    // that was written; only then is it worth asking who authorised what.
    // Running this over a record already known to be tampered would produce
    // findings about forged content, which is noise on top of a verdict the
    // reader already has.
    let payloads: Vec<(u64, &serde_json::Value)> =
        leaves.iter().map(|(_, _, l)| (l.index, &l.payload)).collect();
    report.chain = check_chains(&payloads, &header.tokens);
    for finding in &report.chain.findings {
        report.failures.push(Failure {
            class: TamperClass::Delegation,
            index: as_i64(finding.leaf_index),
            human: finding.human.clone(),
        });
    }

    Ok(report)
}

/// Leaf indices are wire-`u64`; findings are reported as `i64` (with `-1`
/// reserved for "no leaf index"). Saturate rather than wrap on absurd input.
/// Shared with the log-directory pipeline.
pub(crate) fn as_i64(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

fn split_lines(data: &[u8]) -> Result<Vec<&[u8]>, Unverifiable> {
    if data.is_empty() {
        return Err(unverifiable("empty file"));
    }
    let mut lines: Vec<&[u8]> = data.split(|&b| b == b'\n').collect();
    // A trailing newline produces one final empty segment; drop it.
    if lines.last() == Some(&&b""[..]) {
        lines.pop();
    }
    if lines.is_empty() {
        return Err(unverifiable("empty file"));
    }
    if let Some(pos) = lines.iter().position(|l| l.is_empty()) {
        return Err(unverifiable(format!("line {}: blank line", pos + 1)));
    }
    Ok(lines)
}

/// Read a line's `kind` discriminator, with error messages that do not leak
/// internal type names.
fn probe_kind(raw: &[u8]) -> Result<String, String> {
    match serde_json::from_slice::<KindProbe>(raw) {
        Ok(probe) => Ok(probe.kind),
        Err(_) => match serde_json::from_slice::<serde_json::Value>(raw) {
            Ok(_) => Err("not an export line (missing or invalid \"kind\")".to_string()),
            Err(e) => Err(format!("malformed JSON: {e}")),
        },
    }
}

/// Check that every header token sits at an address that is its own digest.
///
/// The address IS the integrity property here. A token stored under a digest
/// that is not its own would let an export keep a receipt's `verified` claim
/// while swapping the evidence underneath it — so a mismatch makes the file
/// unreadable rather than merely suspicious.
fn check_token_addresses(tokens: &HashMap<String, String>) -> Result<(), Unverifiable> {
    for (reference, jws) in tokens {
        let want = format!("sha256:{}", hex_encode(&sha256(jws.as_bytes())));
        if *reference != want {
            return Err(unverifiable(format!(
                "header token keyed {} digests to {}: the token at this address is not the one the receipts reference",
                short_hex(reference),
                short_hex(&want)
            )));
        }
    }
    Ok(())
}

fn parse_header(raw: &[u8]) -> Result<HeaderLine, Unverifiable> {
    let kind = probe_kind(raw).map_err(|e| unverifiable(format!("line 1: {e}")))?;
    if kind != "header" {
        return Err(unverifiable(format!(
            "line 1: expected a header line, got kind {kind:?}"
        )));
    }
    let header: HeaderLine = serde_json::from_slice(raw)
        .map_err(|e| unverifiable(format!("line 1: malformed header: {e}")))?;
    if header.format != EXPORT_FORMAT {
        return Err(unverifiable(format!(
            "unknown format {:?} (this verifier reads {EXPORT_FORMAT:?})",
            header.format
        )));
    }
    Ok(header)
}

fn build_key_map(header: &HeaderLine) -> Result<HashMap<String, VerifyingKey>, Unverifiable> {
    let mut keys = HashMap::new();
    for entry in &header.keys {
        let key = validate_header_key(&entry.jkt, &entry.jwk.kty, &entry.jwk.crv, &entry.jwk.x)
            .map_err(|e| unverifiable(format!("header key {:?}: {e}", entry.jkt)))?;
        if keys.insert(entry.jkt.clone(), key).is_some() {
            return Err(unverifiable(format!(
                "header declares key {:?} twice",
                entry.jkt
            )));
        }
    }
    Ok(keys)
}

enum LeafContentError {
    /// The line cannot even be checked (exit 2 territory).
    Malformed(String),
    /// The line was checked and its content does not verify (class=content).
    Tampered(String),
}

/// Verify one leaf's content: extract the payload span from the raw line,
/// recompute PAE and the leaf hash, and check the signature against the
/// header key for `sig.keyid`. Returns the computed leaf hash.
fn check_leaf_content(
    raw: &[u8],
    leaf: &LeafLine,
    keys: &HashMap<String, VerifyingKey>,
) -> Result<[u8; 32], LeafContentError> {
    let n = leaf.index;
    let payload_bytes = extract_top_level_bytes(raw, "payload")
        .map_err(|e| LeafContentError::Malformed(format!("payload span: {e}")))?;
    let pae_bytes = pae(&leaf.payload_type, payload_bytes);
    let computed = sha256(&pae_bytes);
    let computed_hex = hex_encode(&computed);

    let declared = hex_decode(&leaf.leaf_hash).filter(|v| v.len() == 32);
    if declared.as_deref() != Some(&computed[..]) {
        return Err(LeafContentError::Tampered(format!(
            "receipt {n}: content hash mismatch (expected {} computed {})",
            short4(&leaf.leaf_hash),
            short4(&computed_hex)
        )));
    }

    let Some(key) = keys.get(&leaf.sig.keyid) else {
        return Err(LeafContentError::Tampered(format!(
            "receipt {n}: signature key {:?} not in header",
            leaf.sig.keyid
        )));
    };
    let sig_bytes = match BASE64_STD.decode(&leaf.sig.sig) {
        Ok(b) => b,
        Err(_) => {
            return Err(LeafContentError::Tampered(format!(
                "receipt {n}: signature is not valid base64"
            )));
        }
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return Err(LeafContentError::Tampered(format!(
            "receipt {n}: signature has wrong length"
        )));
    };
    if key.verify(&pae_bytes, &signature).is_err() {
        return Err(LeafContentError::Tampered(format!(
            "receipt {n}: signature verification failed"
        )));
    }
    Ok(computed)
}

/// Verify the head signature. Outer `Err` is exit-2 malformation; inner
/// `Err(human)` is a head tamper finding.
fn check_head_signature(
    head_raw: &[u8],
    head_line: &HeadLine,
    keys: &HashMap<String, VerifyingKey>,
) -> Result<Result<(), String>, Unverifiable> {
    let head_bytes = extract_top_level_bytes(head_raw, "head")
        .map_err(|e| unverifiable(format!("head span: {e}")))?;
    let pae_bytes = pae(CHAIN_HEAD_PAYLOAD_TYPE, head_bytes);

    let Some(key) = keys.get(&head_line.sig.keyid) else {
        return Ok(Err(format!(
            "head signature key {:?} not in header",
            head_line.sig.keyid
        )));
    };
    let Ok(sig_bytes) = BASE64_STD.decode(&head_line.sig.sig) else {
        return Ok(Err("head signature is not valid base64".to_string()));
    };
    let Ok(signature) = Signature::from_slice(&sig_bytes) else {
        return Ok(Err("head signature has wrong length".to_string()));
    };
    if key.verify(&pae_bytes, &signature).is_err() {
        return Ok(Err("head signature verification failed".to_string()));
    }
    Ok(Ok(()))
}

#[derive(Debug, PartialEq, Eq)]
enum SequenceIssue {
    Ok,
    /// Indices are present but not in ascending order; `index` is the first
    /// position where the sequence deviates from 0,1,2,…
    Reorder { index: u64 },
    /// Indices ascend but with gaps: these are the missing indices.
    Drops(Vec<u64>),
}

fn classify_sequence(indices: &[u64]) -> SequenceIssue {
    let contiguous = indices.iter().enumerate().all(|(p, &ix)| ix == p as u64);
    if contiguous {
        return SequenceIssue::Ok;
    }
    let strictly_ascending = indices.windows(2).all(|w| w[0] < w[1]);
    if strictly_ascending {
        // Ascending with gaps (or not starting at 0): dropped receipts.
        let mut missing = Vec::new();
        let mut expected: u64 = 0;
        for &ix in indices {
            while expected < ix {
                missing.push(expected);
                expected += 1;
            }
            expected = ix.saturating_add(1);
        }
        SequenceIssue::Drops(missing)
    } else {
        let index = indices
            .iter()
            .enumerate()
            .find(|&(p, &ix)| ix != p as u64)
            .map_or(0, |(p, _)| p as u64);
        SequenceIssue::Reorder { index }
    }
}

fn find_duplicate_receipt_ids(leaves: &[(usize, &[u8], LeafLine)]) -> Vec<Failure> {
    let mut first_seen: HashMap<&str, u64> = HashMap::new();
    let mut dups = Vec::new();
    for (_, _, leaf) in leaves {
        let Some(id) = leaf.payload.get("receipt_id").and_then(|v| v.as_str()) else {
            continue;
        };
        match first_seen.get(id) {
            Some(&first) => {
                dups.push(Failure {
                    class: TamperClass::Duplicate,
                    index: as_i64(leaf.index),
                    human: format!(
                        "duplicate receipt_id {id:?}: receipt {} repeats receipt {first}",
                        leaf.index
                    ),
                });
            }
            None => {
                first_seen.insert(id, leaf.index);
            }
        }
    }
    dups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_contiguous_is_ok() {
        assert_eq!(classify_sequence(&[0, 1, 2, 3]), SequenceIssue::Ok);
        assert_eq!(classify_sequence(&[]), SequenceIssue::Ok);
        assert_eq!(classify_sequence(&[0]), SequenceIssue::Ok);
    }

    #[test]
    fn sequence_gap_is_drop_at_the_missing_index() {
        // Delete leaf 20 out of 0..=22.
        let indices: Vec<u64> = (0..23).filter(|&i| i != 20).collect();
        assert_eq!(classify_sequence(&indices), SequenceIssue::Drops(vec![20]));
    }

    #[test]
    fn sequence_multiple_gaps_report_each_missing_index() {
        assert_eq!(
            classify_sequence(&[0, 1, 4, 6]),
            SequenceIssue::Drops(vec![2, 3, 5])
        );
        // Not starting at zero drops the leading indices.
        assert_eq!(classify_sequence(&[2, 3]), SequenceIssue::Drops(vec![0, 1]));
    }

    #[test]
    fn sequence_swap_is_reorder_at_first_deviation() {
        // Swap leaves 10 and 11 in 0..=12.
        let mut indices: Vec<u64> = (0..13).collect();
        indices.swap(10, 11);
        assert_eq!(
            classify_sequence(&indices),
            SequenceIssue::Reorder { index: 10 }
        );
    }

    #[test]
    fn sequence_duplicate_index_is_reorder() {
        assert_eq!(
            classify_sequence(&[0, 1, 1, 2]),
            SequenceIssue::Reorder { index: 2 }
        );
    }

    #[test]
    fn machine_line_format() {
        let f = Failure {
            class: TamperClass::Content,
            index: 31,
            human: String::new(),
        };
        assert_eq!(f.machine_line(), "class=content index=31");
        let f = Failure {
            class: TamperClass::Chain,
            index: -1,
            human: String::new(),
        };
        assert_eq!(f.machine_line(), "class=chain index=-1");
    }

    #[test]
    fn class_names_are_stable() {
        let all = [
            (TamperClass::Content, "content"),
            (TamperClass::Drop, "drop"),
            (TamperClass::Reorder, "reorder"),
            (TamperClass::Chain, "chain"),
            (TamperClass::Truncation, "truncation"),
            (TamperClass::Head, "head"),
            (TamperClass::Duplicate, "duplicate"),
        ];
        for (class, name) in all {
            assert_eq!(class.as_str(), name);
        }
    }
}
