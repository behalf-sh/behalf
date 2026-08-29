# Vendored code: cloudflare/azul

Per the architecture decision record: the Rust verifier vendors its Merkle-tree math from
cloudflare/azul (BSD-3-Clause) at a pinned SHA, and behalf owns the update
burden. azul is unpublished on crates.io (cloudflare/azul#16), so the source
is vendored rather than pulled as a registry dependency.

| | |
|---|---|
| Repository | https://github.com/cloudflare/azul |
| Commit | `2051772e09255fa940f56b808bd4b44d00d5b8d2` (`2051772e`, HEAD of main when pinned) |
| Upstream commit date | 2026-08-26 |
| Vendored on | 2026-08-27 |
| License | BSD-3-Clause (`LICENSE` here is the repo top-level license; the crate carries its own copy) |

## What was taken, and why only this

**`tlog_core` only** (`crates/tlog_core` upstream → `tlog_core/` here): the
algorithm-only RFC 6962 Merkle math — `record_hash` (leaf hash),
`node_hash`, `tree_hash`, the stored-hash-index scheme and `HashReader`.
It is an attributed port of Go's `golang.org/x/mod/sumdb/tlog` (the header
of `src/lib.rs` carries the Go Authors copyright) and depends only on
`base64`, `serde`, `sha2`, `thiserror`. `behalf-verify log` uses it to
recompute the tree root from entry-bundle leaf hashes and to recompute
prefix roots for the `--latest-known` consistency check.

Deliberately **not** vendored:

- `tlog_tiles` (C2SP tile wire format): behalf's tile reading is a local
  filesystem walk with behalf's own full-tile-over-stale-partial rule
  (Tessera GC off); the crate's HTTP-shaped reader abstractions would be
  carried dead weight. The tile *path* layout and 2-byte big-endian entry
  framing are reimplemented in `verifier/src/tiles.rs` (~100 lines) and
  cross-checked against Tessera-written directories by the tamper suite.
- `signed_note` (checkpoint note verification): correct and small, but it
  depends on `ed25519-dalek 3.x` while the verifier is on `ed25519-dalek 2`;
  vendoring it would ship two dalek majors for ~120 lines of note parsing.
  Note verification is implemented in `verifier/src/note.rs` against the Go
  `golang.org/x/mod/sumdb/note` format, with a known-answer test pinning a
  checkpoint + vkey pair produced by the Go log service (Tessera v1.0.4).

## Verbatim vs modified

- `tlog_core/src/lib.rs`, `tlog_core/LICENSE`, `tlog_core/README.md`,
  `LICENSE`: byte-for-byte upstream copies.
  sha256 of `src/lib.rs` at vendoring:
  `6345ae6ac726ffb438f06f7fa069acf0c0ad881da68870b056f11c59ecb5cf2b`.
- `tlog_core/Cargo.toml`: **rewritten** — upstream inherits fields and
  dependency versions from the azul workspace manifest; this copy pins the
  same versions standalone (base64 0.22, serde 1.0, sha2 0.11, thiserror
  2.0, edition 2024) and sets `publish = false`. No source changes.

Wired as a path dependency from `verifier/Cargo.toml`
(`tlog_core = { path = "vendor/azul/tlog_core" }`). The vendored crate's own
unit tests ride along in `src/lib.rs`; the verifier additionally pins the
RFC 6962 known-answer vectors (empty/1/2/3/7-leaf roots from the C2SP /
CT / sumdb corpus) against it in `verifier/src/merkle.rs`, and the tamper
suite cross-checks it end-to-end against trees written by Tessera v1.0.4
(Go) on every CI run.

## Updating

Re-clone azul, check out the new SHA, re-copy the files above, re-apply the
Cargo.toml rewrite, update the table and the lib.rs digest here, and re-run
`make ci` (the conformance vectors and tamper suite are the gate).

## Compiled in as a module, not a crate (29 Aug 2026)

`tlog_core/` no longer carries a `Cargo.toml`. The verifier includes
`tlog_core/src/lib.rs` directly, as `#[path]` module `behalf_verify::tlog_core`
(native builds only), because crates.io accepts no path dependencies and azul
is unpublished there — and because a nested manifest makes cargo treat the
directory as a separate package and drop it from this crate's tarball.

The upstream manifest that was here declared, at the pinned SHA: edition 2024,
`base64 = "0.22"`, `serde = "1.0"` (derive), `sha2 = "0.11"`, `thiserror = "2.0"`.
Those are now the verifier's own dependency lines. `src/lib.rs`, `LICENSE` and
`README.md` remain verbatim upstream copies; the vendoring procedure below is
unchanged except that the manifest is not copied.
