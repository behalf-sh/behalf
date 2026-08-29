//! `behalf-verify log <dir>` — verification of a Tessera-written tlog-tiles
//! directory (Week 2, ENG-7).
//!
//! Check order (deliberate, and different from file mode where the chain
//! compare precedes the head-signature check):
//!
//! 1. **Checkpoint signature first** (class `head` on failure). The
//!    checkpoint is the only trust anchor and the only source of the tree
//!    size; nothing in the directory can be interpreted before it is
//!    authenticated. An edited checkpoint root therefore classifies as
//!    `head`, not `chain`.
//! 2. **Stale-restore rule** (Q76): with `--latest-known`, a checkpoint
//!    covering a smaller tree than the latest known one is `truncation` —
//!    a restore may never present a tree older than the last witnessed
//!    checkpoint. A same-size root mismatch is a fork: `chain`.
//! 3. **Entry bundles** up to the checkpoint size: a missing bundle, or one
//!    with fewer entries than the checkpoint commits to, is `truncation`
//!    at the first uncovered index. (Stale partials are never themselves
//!    evidence of tampering; only missing *coverage* is.)
//! 4. **Per-entry content**: each stored envelope must parse, carry the
//!    known envelope version, and (when `--emitter-keys` is given) verify
//!    its emitter Ed25519 signature over PAE — failures are `content` at
//!    that leaf index and later entries are unverifiable, as in file mode.
//! 5. **Root recompute** (vendored azul `tlog_core`): the RFC 6962 root
//!    over the recomputed leaf hashes must equal the checkpoint root.
//!    On mismatch, the stored level-0 hash tiles are consulted only to
//!    *localize*: if the stored hashes still fold to the signed root, the
//!    first index where they diverge from the recomputed leaf hashes is
//!    `content` at that index; otherwise the finding is `chain`.
//! 6. **Consistency with `--latest-known`** when it covers a smaller tree:
//!    the recomputed root at that earlier size must equal the known root,
//!    else the log forked: `chain`.
//!
//! Hash tiles are rebuildable derived data; the evidence is the entry
//! bundles plus the signed checkpoint, so tiles are read only for step 5's
//! localization. Unreadable or unframeable inputs (garbage checkpoint,
//! malformed bundle framing, bad key files) are exit 2, mirroring file
//! mode's malformed-JSON rule.

use std::path::{Path, PathBuf};

use crate::envelope::{check_envelope, EmitterKeys};
use crate::merkle::{leaf_hash, HashStore};
use crate::note::{parse_checkpoint_body, verify_note, Checkpoint, NoteVerifier};
use crate::tiles::{parse_entry_bundle, parse_hash_tile, read_tile, TileData, TILE_WIDTH};
use crate::util::{hex_encode, short_hex};
use crate::verify::{as_i64, Failure, TamperClass, Unverifiable};

/// Options for [`verify_log_dir`].
#[derive(Debug, Default, Clone)]
pub struct LogOptions {
    /// Path to the checkpoint note verifier key. Default:
    /// `<dir>/keys/checkpoint.vkey`.
    pub vkey: Option<PathBuf>,
    /// A previously-seen checkpoint (or its serialized copy) for the Q76
    /// stale-restore rule and the fork consistency check.
    pub latest_known: Option<PathBuf>,
    /// Emitter public keys (JSON key set, export-header shape). Without
    /// it, emitter signatures are checked structurally only and the
    /// report says so.
    pub emitter_keys: Option<PathBuf>,
}

/// Result of verifying a readable log directory.
#[derive(Debug)]
pub struct LogReport {
    /// Checkpoint origin line.
    pub origin: String,
    /// Checkpoint tree size.
    pub tree_size: u64,
    /// Checkpoint root hash, lowercase hex.
    pub root_hex: String,
    /// Whether emitter signatures were verified against a key set.
    pub emitter_sigs_checked: bool,
    /// Tree size of the `--latest-known` checkpoint, when given.
    pub latest_known_size: Option<u64>,
    /// Tamper findings (exit 1 when non-empty).
    pub failures: Vec<Failure>,
    /// Extra human-readable context lines.
    pub notes: Vec<String>,
}

impl LogReport {
    /// True when the directory verified.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        self.failures.is_empty()
    }

    /// The human stdout block, mirroring file mode.
    #[must_use]
    pub fn human_stdout(&self) -> String {
        let mut out = String::new();
        if self.is_verified() {
            let n = self.tree_size;
            out.push_str(&format!(
                "\u{2714} {n}/{n} entries intact   checkpoint root {}",
                short_hex(&self.root_hex)
            ));
            if let Some(m) = self.latest_known_size {
                out.push('\n');
                out.push_str(&format!(
                    "  consistent with latest-known checkpoint (size {m})"
                ));
            }
        } else {
            out.push_str("\u{2716} TAMPERED");
            for f in &self.failures {
                out.push('\n');
                out.push_str(&f.human);
            }
        }
        for note in &self.notes {
            out.push('\n');
            out.push_str(note);
        }
        if !self.emitter_sigs_checked {
            out.push('\n');
            out.push_str(
                "\u{26a0} emitter signatures not checked (no --emitter-keys); \
                 content findings rest on the checkpoint and hash tiles only",
            );
        }
        out
    }

    /// Machine-readable stderr lines, one per finding (same format as file
    /// mode: `class=<class> index=<N>`, `-1` where no leaf index applies).
    #[must_use]
    pub fn machine_stderr_lines(&self) -> Vec<String> {
        self.failures.iter().map(Failure::machine_line).collect()
    }
}

fn unv(reason: impl Into<String>) -> Unverifiable {
    Unverifiable {
        reason: reason.into(),
    }
}

/// Verify a tlog-tiles log directory. `Err` means the directory is not a
/// readable log (exit 2); `Ok(report)` carries any classified findings.
pub fn verify_log_dir(dir: &Path, opts: &LogOptions) -> Result<LogReport, Unverifiable> {
    // Verifier key.
    let vkey_path = opts
        .vkey
        .clone()
        .unwrap_or_else(|| dir.join("keys").join("checkpoint.vkey"));
    let vkey_str = std::fs::read_to_string(&vkey_path)
        .map_err(|e| unv(format!("cannot read vkey {}: {e}", vkey_path.display())))?;
    let verifier = NoteVerifier::from_vkey(&vkey_str)
        .map_err(|e| unv(format!("vkey {}: {e}", vkey_path.display())))?;

    // Step 1: the checkpoint, signature first.
    let cp_path = dir.join("checkpoint");
    let cp_raw = std::fs::read(&cp_path)
        .map_err(|e| unv(format!("cannot read checkpoint {}: {e}", cp_path.display())))?;
    let mut report = LogReport {
        origin: String::new(),
        tree_size: 0,
        root_hex: String::new(),
        emitter_sigs_checked: opts.emitter_keys.is_some(),
        latest_known_size: None,
        failures: Vec::new(),
        notes: Vec::new(),
    };
    let text = match verify_note(&cp_raw, &verifier).map_err(|e| unv(format!("checkpoint: {e}")))? {
        Ok(text) => text,
        Err(reason) => {
            report.failures.push(Failure {
                class: TamperClass::Head,
                index: -1,
                human: format!("checkpoint signature: {reason}"),
            });
            return Ok(report);
        }
    };
    let cp = parse_checkpoint_body(text).map_err(|e| unv(format!("checkpoint: {e}")))?;
    report.origin.clone_from(&cp.origin);
    report.tree_size = cp.size;
    report.root_hex = hex_encode(&cp.root);
    if cp.origin != verifier.name() {
        report.failures.push(Failure {
            class: TamperClass::Head,
            index: -1,
            human: format!(
                "checkpoint origin {:?} does not match the verifier key name {:?}",
                cp.origin,
                verifier.name()
            ),
        });
        return Ok(report);
    }

    // Emitter key set (optional).
    let emitter_keys = match &opts.emitter_keys {
        Some(path) => Some(EmitterKeys::load(path).map_err(unv)?),
        None => None,
    };

    // Step 2: the latest-known checkpoint (Q76).
    let known = match &opts.latest_known {
        Some(path) => Some(load_latest_known(path, &verifier, &cp)?),
        None => None,
    };
    report.latest_known_size = known.as_ref().map(|k| k.size);
    if let Some(k) = &known {
        if k.size > cp.size {
            report.failures.push(Failure {
                class: TamperClass::Truncation,
                index: -1,
                human: format!(
                    "stale restore: checkpoint covers {} entries but the latest known \
                     checkpoint covers {} (a restore may never present a tree older \
                     than the last witnessed checkpoint)",
                    cp.size, k.size
                ),
            });
            return Ok(report);
        }
        if k.size == cp.size && k.root != cp.root {
            report.failures.push(Failure {
                class: TamperClass::Chain,
                index: -1,
                human: format!(
                    "fork: checkpoint and latest-known checkpoint both cover {} entries \
                     with different roots ({} vs {})",
                    cp.size,
                    short_hex(&report.root_hex),
                    short_hex(&hex_encode(&k.root))
                ),
            });
            return Ok(report);
        }
    }

    // Steps 3 + 4: entry bundles, per-entry content, leaf hashes.
    let mut store = HashStore::new();
    let mut computed: Vec<[u8; 32]> = Vec::with_capacity(usize::try_from(cp.size).unwrap_or(0));
    let bundles = cp.size.div_ceil(TILE_WIDTH);
    for b in 0..bundles {
        let first = b * TILE_WIDTH;
        let needed = (cp.size - first).min(TILE_WIDTH);
        let (data, path) = match read_tile(dir, "entries", b, needed).map_err(unv)? {
            TileData::Found { data, path } | TileData::Short { data, path } => (data, path),
            TileData::Missing => {
                report.failures.push(truncation_failure(first, cp.size));
                return Ok(report);
            }
        };
        let entries = parse_entry_bundle(&data)
            .map_err(|e| unv(format!("entry bundle {}: {e}", path.display())))?;
        let have = u64::try_from(entries.len()).unwrap_or(u64::MAX);
        if have < needed {
            report
                .failures
                .push(truncation_failure(first + have, cp.size));
            return Ok(report);
        }
        for (j, env) in entries.iter().take(usize::try_from(needed).unwrap_or(usize::MAX)).enumerate() {
            let index = first + j as u64;
            if let Err(reason) = check_envelope(env, emitter_keys.as_ref()) {
                push_content_failure(&mut report, index, cp.size, &reason);
                return Ok(report);
            }
            let leaf = leaf_hash(env);
            computed.push(leaf);
            store
                .push_leaf(leaf)
                .map_err(|e| unv(format!("merkle bookkeeping at index {index}: {e}")))?;
        }
    }

    // Step 5: the recomputed root against the signed checkpoint root.
    let computed_root = store
        .root_at(cp.size)
        .map_err(|e| unv(format!("root computation: {e}")))?;
    if computed_root != cp.root {
        localize_root_mismatch(dir, &cp, &computed, &computed_root, &mut report);
        return Ok(report);
    }

    // Step 6: consistency with the latest-known checkpoint (fork check).
    if let Some(k) = &known {
        if k.size < cp.size {
            let old_root = store
                .root_at(k.size)
                .map_err(|e| unv(format!("prefix root computation: {e}")))?;
            if old_root != k.root {
                report.failures.push(Failure {
                    class: TamperClass::Chain,
                    index: -1,
                    human: format!(
                        "fork: the tree at size {} does not reproduce the latest-known \
                         checkpoint root ({} computed, {} known)",
                        k.size,
                        short_hex(&hex_encode(&old_root)),
                        short_hex(&hex_encode(&k.root))
                    ),
                });
                return Ok(report);
            }
        }
    }

    Ok(report)
}

fn truncation_failure(first_missing: u64, size: u64) -> Failure {
    Failure {
        class: TamperClass::Truncation,
        index: as_i64(first_missing),
        human: format!(
            "truncated: entries {first_missing}-{} missing below the checkpoint tree size {size}",
            size - 1
        ),
    }
}

fn push_content_failure(report: &mut LogReport, index: u64, size: u64, reason: &str) {
    report.failures.push(Failure {
        class: TamperClass::Content,
        index: as_i64(index),
        human: format!("entry {index}: {reason}"),
    });
    let last = size.saturating_sub(1);
    if index < last {
        report.notes.push(format!(
            "chain breaks at {index}; entries {}-{last} unverifiable.",
            index + 1
        ));
    } else {
        report.notes.push(format!("chain breaks at {index}."));
    }
}

/// The recomputed root does not match the signed checkpoint. Consult the
/// stored level-0 hash tiles purely to localize: when the stored hashes
/// still fold to the signed root, the first divergence from the recomputed
/// leaf hashes names the tampered entry (`content`); anything else is
/// `chain`.
fn localize_root_mismatch(
    dir: &Path,
    cp: &Checkpoint,
    computed: &[[u8; 32]],
    computed_root: &[u8; 32],
    report: &mut LogReport,
) {
    let chain_failure = Failure {
        class: TamperClass::Chain,
        index: -1,
        human: format!(
            "root mismatch: checkpoint declares {} computed {}",
            short_hex(&report.root_hex),
            short_hex(&hex_encode(computed_root))
        ),
    };
    // Stored level-0 hashes count as a localization witness only when they
    // themselves fold to the signed checkpoint root.
    let witness = read_stored_leaf_hashes(dir, cp.size).filter(|stored| {
        let mut store = HashStore::new();
        stored.iter().all(|&h| store.push_leaf(h).is_ok())
            && store.root_at(cp.size).is_ok_and(|root| root == cp.root)
    });
    let divergence = witness
        .as_ref()
        .and_then(|stored| stored.iter().zip(computed).position(|(s, c)| s != c));
    match divergence {
        Some(idx) => {
            let index = u64::try_from(idx).unwrap_or(u64::MAX);
            push_content_failure(
                report,
                index,
                cp.size,
                "stored envelope does not hash to the leaf the signed checkpoint covers",
            );
        }
        None => report.failures.push(chain_failure),
    }
}

/// Read the stored level-0 hash tiles covering `size` leaves. `None` when
/// they are missing, short, or malformed — they are rebuildable derived
/// data, so their absence is never itself a finding.
fn read_stored_leaf_hashes(dir: &Path, size: u64) -> Option<Vec<[u8; 32]>> {
    let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0));
    for b in 0..size.div_ceil(TILE_WIDTH) {
        let needed = (size - b * TILE_WIDTH).min(TILE_WIDTH);
        let data = match read_tile(dir, "0", b, needed) {
            Ok(TileData::Found { data, .. }) => data,
            _ => return None,
        };
        let hashes = parse_hash_tile(&data).ok()?;
        if (hashes.len() as u64) < needed {
            return None;
        }
        out.extend_from_slice(&hashes[..usize::try_from(needed).ok()?]);
    }
    Some(out)
}

fn load_latest_known(
    path: &Path,
    verifier: &NoteVerifier,
    cp: &Checkpoint,
) -> Result<Checkpoint, Unverifiable> {
    let raw = std::fs::read(path)
        .map_err(|e| unv(format!("cannot read latest-known checkpoint {}: {e}", path.display())))?;
    let text = verify_note(&raw, verifier)
        .map_err(|e| unv(format!("latest-known checkpoint: {e}")))?
        .map_err(|reason| unv(format!("latest-known checkpoint: {reason}")))?;
    let known =
        parse_checkpoint_body(text).map_err(|e| unv(format!("latest-known checkpoint: {e}")))?;
    if known.origin != cp.origin {
        return Err(unv(format!(
            "latest-known checkpoint is for origin {:?}, the log is {:?}",
            known.origin, cp.origin
        )));
    }
    Ok(known)
}
