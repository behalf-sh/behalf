//! tlog-tiles (C2SP) on-disk layout: tile paths, entry-bundle framing, and
//! the full-tile-over-stale-partial selection rule.
//!
//! The Tessera v1.0.4 POSIX driver writes hash tiles at
//! `tile/<level>/<NNN>` with partials at `tile/<level>/<NNN>.p/<width>`,
//! and entry bundles at `tile/entries/<NNN>[.p/<width>]` — 256 entries per
//! bundle, each entry framed as a 2-byte big-endian length followed by the
//! envelope bytes. Garbage collection is off, so **stale partials linger**:
//! a full tile supersedes its partials, and a partial written at an earlier
//! tree size stays on disk next to later ones. Selection therefore prefers
//! the full tile, then the exact partial for the width the checkpoint
//! requires, then the largest partial that still covers it; a stale (too
//! small) partial is never itself evidence of tampering — but if nothing on
//! disk covers the entries the signed checkpoint commits to, that absence
//! is truncation.

use std::path::{Path, PathBuf};

/// Entries per entry bundle / hashes per tile row (C2SP tlog-tiles, and
/// Tessera's `layout.EntryBundleWidth`).
pub const TILE_WIDTH: u64 = 256;

/// Encode a tile index as its path form: groups of three decimal digits,
/// all but the last prefixed with `x` (`0` → `000`, `1234067` →
/// `x001/x234/067`).
#[must_use]
pub fn tile_index_path(n: u64) -> String {
    let mut out = format!("{:03}", n % 1000);
    let mut n = n / 1000;
    while n > 0 {
        out = format!("x{:03}/{out}", n % 1000);
        n /= 1000;
    }
    out
}

/// What a tile lookup found on disk.
#[derive(Debug)]
pub enum TileData {
    /// A file covering at least the needed width: its bytes and where they
    /// came from (for error messages).
    Found { data: Vec<u8>, path: PathBuf },
    /// Only files narrower than the needed width exist (stale partials).
    /// The widest one is returned so truncation can be reported precisely.
    Short { data: Vec<u8>, path: PathBuf },
    /// Nothing usable on disk for this tile index.
    Missing,
}

/// Read the best available file for tile `index` under `dir/tile/<kind>`
/// (`kind` is `"entries"` or a level number as a string), needing `needed`
/// entries (1..=256). Preference order: full tile, exact partial, largest
/// larger partial; else the largest stale partial as [`TileData::Short`].
///
/// I/O errors other than not-found are surfaced as `Err` (exit-2
/// territory: the directory cannot be read).
pub fn read_tile(
    dir: &Path,
    kind: &str,
    index: u64,
    needed: u64,
) -> Result<TileData, String> {
    let base = dir.join("tile").join(kind).join(tile_index_path(index));
    if let Some(data) = read_optional(&base)? {
        return Ok(TileData::Found { data, path: base });
    }
    // Partial directory: <base>.p/<width>. Collect numeric widths.
    let pdir = PathBuf::from(format!("{}.p", base.display()));
    let mut widths: Vec<u64> = Vec::new();
    match std::fs::read_dir(&pdir) {
        Ok(entries) => {
            for entry in entries {
                let entry =
                    entry.map_err(|e| format!("cannot list {}: {e}", pdir.display()))?;
                if let Some(w) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<u64>().ok())
                {
                    if (1..=TILE_WIDTH).contains(&w) {
                        widths.push(w);
                    }
                }
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(format!("cannot list {}: {e}", pdir.display())),
    }
    // Exact width first, then the largest width that covers `needed`.
    let pick = if widths.contains(&needed) {
        Some(needed)
    } else {
        widths.iter().copied().filter(|&w| w > needed).max()
    };
    if let Some(w) = pick {
        let path = pdir.join(w.to_string());
        if let Some(data) = read_optional(&path)? {
            return Ok(TileData::Found { data, path });
        }
    }
    // Only stale partials (narrower than needed), if any: return the widest
    // so the caller can report where coverage ends.
    if let Some(w) = widths.iter().copied().max() {
        let path = pdir.join(w.to_string());
        if let Some(data) = read_optional(&path)? {
            return Ok(TileData::Short { data, path });
        }
    }
    Ok(TileData::Missing)
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match std::fs::read(path) {
        Ok(data) => Ok(Some(data)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("cannot read {}: {e}", path.display())),
    }
}

/// Parse an entry bundle: a sequence of `<u16 big-endian length><bytes>`
/// frames. Returns the framed entries; any framing violation (a length
/// prefix cut short, or a declared length running past the end of the
/// file) is an error — the bundle is not readable evidence.
pub fn parse_entry_bundle(data: &[u8]) -> Result<Vec<&[u8]>, String> {
    let mut entries = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let Some((len_bytes, after_len)) = rest.split_first_chunk::<2>() else {
            return Err(format!(
                "entry {} has a truncated length prefix",
                entries.len()
            ));
        };
        let len = usize::from(u16::from_be_bytes(*len_bytes));
        if after_len.len() < len {
            return Err(format!(
                "entry {} declares {len} bytes but only {} remain",
                entries.len(),
                after_len.len()
            ));
        }
        let (entry, after_entry) = after_len.split_at(len);
        entries.push(entry);
        rest = after_entry;
    }
    Ok(entries)
}

/// Split a level-0 hash tile into 32-byte hashes. Errors when the file
/// length is not a multiple of 32.
pub fn parse_hash_tile(data: &[u8]) -> Result<Vec<[u8; 32]>, String> {
    let (chunks, rem) = data.as_chunks::<32>();
    if !rem.is_empty() {
        return Err(format!(
            "hash tile length {} is not a multiple of 32",
            data.len()
        ));
    }
    Ok(chunks.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tile_index_paths() {
        assert_eq!(tile_index_path(0), "000");
        assert_eq!(tile_index_path(67), "067");
        assert_eq!(tile_index_path(999), "999");
        assert_eq!(tile_index_path(1000), "x001/000");
        assert_eq!(tile_index_path(1234067), "x001/x234/067");
    }

    #[test]
    fn bundle_roundtrip() {
        let mut data = Vec::new();
        let entries: [&[u8]; 3] = [b"hello", b"", b"a longer envelope {\"v\":1}"];
        for e in entries {
            data.extend_from_slice(&u16::try_from(e.len()).unwrap().to_be_bytes());
            data.extend_from_slice(e);
        }
        let parsed = parse_entry_bundle(&data).expect("well-framed bundle parses");
        assert_eq!(parsed, entries);
        assert_eq!(parse_entry_bundle(b"").expect("empty is fine").len(), 0);
    }

    #[test]
    fn bundle_framing_violations() {
        // Truncated length prefix.
        assert!(parse_entry_bundle(&[0x00]).is_err());
        // Declared length runs past EOF.
        assert!(parse_entry_bundle(&[0x00, 0x05, b'a', b'b']).is_err());
        // Oversized length (max u16) with almost no data.
        assert!(parse_entry_bundle(&[0xff, 0xff, 0x01]).is_err());
        // A valid frame followed by a bad one.
        let mut data = vec![0x00, 0x01, b'x'];
        data.extend_from_slice(&[0x00, 0x09, b'y']);
        assert!(parse_entry_bundle(&data).is_err());
    }

    #[test]
    fn no_panics_on_arbitrary_prefixes() {
        let mut data = Vec::new();
        for e in [&b"abc"[..], &[0u8; 300][..], b"z"] {
            data.extend_from_slice(&u16::try_from(e.len()).unwrap().to_be_bytes());
            data.extend_from_slice(e);
        }
        for end in 0..=data.len() {
            let _ = parse_entry_bundle(&data[..end]);
        }
    }

    #[test]
    fn hash_tile_parsing() {
        assert_eq!(parse_hash_tile(&[]).expect("empty ok").len(), 0);
        assert_eq!(parse_hash_tile(&[0u8; 64]).expect("two hashes").len(), 2);
        assert!(parse_hash_tile(&[0u8; 33]).is_err());
    }

    fn write(path: &Path, data: &[u8]) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, data).unwrap();
    }

    #[test]
    fn selection_prefers_full_then_exact_then_larger_partial() {
        let dir = std::env::temp_dir().join(format!("behalf-tiles-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let entries = dir.join("tile").join("entries");

        // Only a stale partial narrower than needed: Short.
        write(&entries.join("000.p").join("47"), b"47");
        match read_tile(&dir, "entries", 0, 94).expect("readable") {
            TileData::Short { data, .. } => assert_eq!(data, b"47"),
            other => panic!("want Short, got {other:?}"),
        }

        // Exact partial appears: preferred over the stale one.
        write(&entries.join("000.p").join("94"), b"94");
        match read_tile(&dir, "entries", 0, 94).expect("readable") {
            TileData::Found { data, .. } => assert_eq!(data, b"94"),
            other => panic!("want Found, got {other:?}"),
        }

        // A larger partial serves smaller widths when no exact one exists.
        match read_tile(&dir, "entries", 0, 60).expect("readable") {
            TileData::Found { data, .. } => assert_eq!(data, b"94"),
            other => panic!("want Found, got {other:?}"),
        }

        // The full tile supersedes every partial.
        write(&entries.join("000"), b"full");
        match read_tile(&dir, "entries", 0, 94).expect("readable") {
            TileData::Found { data, .. } => assert_eq!(data, b"full"),
            other => panic!("want Found, got {other:?}"),
        }

        // Nothing at all for another index: Missing.
        match read_tile(&dir, "entries", 1, 10).expect("readable") {
            TileData::Missing => {}
            other => panic!("want Missing, got {other:?}"),
        }

        // Junk names in the partial dir are ignored, not a crash.
        write(&entries.join("002.p").join("not-a-number"), b"x");
        write(&entries.join("002.p").join("300"), b"too wide to be real");
        match read_tile(&dir, "entries", 2, 10).expect("readable") {
            TileData::Missing => {}
            other => panic!("want Missing, got {other:?}"),
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
