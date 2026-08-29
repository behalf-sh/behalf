# behalf export format v1 (Week-1 scope)

Written 27 Aug 2026. This is the interchange contract between the Go writer and the Rust
verifier for the Week-1 milestone ("The claim, under test", ENG-1…ENG-5). It defines the
`run_*.jsonl` export file that `behalf verify` checks offline. It is deliberately the
**hand-rolled chain** the plan calls for (build the reader first, swap Tessera in
underneath): in Week 2 the export gains checkpoint and inclusion-proof material from the
Tessera log, under a new `format` string, and this format remains readable.

Two invariants from [`receipt-schema-v1.md`](receipt-schema-v1.md) govern everything:
stored bytes are the signed bytes are the hashed bytes (no canonicalization step exists,
DSSE/PAE), and the verifier needs no network and no call to behalf.

One deliberate deviation from standard DSSE, forced by the demo: the payload is embedded as
**plaintext JSON, not base64**, so that `sed 's/1200.00/12.00/'` on the export file edits the
receipt content directly (the cover-up demo). Signing and hashing are still over exact bytes —
the *byte span* of the payload value as it appears in the file — so there is still no
canonicalization: the writer emits the payload bytes it signed, verbatim, and the verifier
extracts that exact span from the raw line before doing anything else.

## 1. File layout

UTF-8, one JSON object per line (`\n` separators, no CR). Three line kinds, in order:

1. **Header** — exactly one, first line.
2. **Leaf** — one per receipt, `index` strictly ascending from 0, no gaps.
3. **Head** — exactly one, last line.

### 1.1 Header line

```json
{"kind":"header","format":"behalf.sh/export/v1","log_origin":"<origin string>","keys":[{"jkt":"<RFC 7638 thumbprint, base64url>","jwk":{"kty":"OKP","crv":"Ed25519","x":"<base64url>"}}]}
```

`keys` carries every Ed25519 public key referenced by any signature in the file, keyed by its
RFC 7638 JWK thumbprint (SHA-256, base64url, no padding). Week-1 verification checks
signatures against these embedded keys; key *provenance* (the published key log) is a later
milestone and the verifier's output must not claim it.

#### `tokens` — delegation hop tokens (optional, ENG-38)

```json
{"kind":"header", "…":"…", "tokens":{"sha256:<hex>":"<compact JWS>"}}
```

Each entry is one delegation hop's compact JWS, keyed by **exactly** the string that hop's
`verification.evidence_ref` carries. Keying by the whole reference rather than by the bare
digest is deliberate: a reader looks the token up by the value the receipt already holds, with
no string surgery in between, so there is no opportunity to reconstruct the key slightly
differently on one side and miss.

**The address is the integrity property.** A reader MUST check that each token digests to the
key it sits under — `sha256:` + lowercase-hex SHA-256 over the compact JWS's ASCII bytes, all
three segments and both dots included, the same preimage as `par_hash` (§3). A mismatch makes
the file **unverifiable** (exit 2), not merely suspicious: a token stored at an address that
is not its own digest is an attempt to keep a receipt's `verified` claim while swapping the
evidence underneath it.

The member is **optional** and hops deduplicate — a run's 47 receipts typically share three
hops, so the section grows with distinct hops rather than with receipts. An export written
before this section existed carries none, and §2's rule that unknown members MUST be ignored
means such a file verifies exactly as it always did. The format string does not move.

An entry is absent for two legitimate reasons, neither of which is a break: a hop that arrived
caller-asserted has no token and carries no `evidence_ref` at all, and a depth-0 root's
`evidence_ref` may name the signed login statement rather than a hop token. A verifier reports
these as **unchecked**, never as findings.

### 1.2 Leaf line

```json
{"kind":"leaf","index":31,"payloadType":"application/vnd.behalf.receipt+json","payload":{…receipt JSON…},"sig":{"keyid":"<emitter jkt>","sig":"<base64std>"},"leaf_hash":"<hex>"}
```

- `payload` is the receipt object per `receipt-schema-v1.schema.json`, embedded as plaintext.
- **`payload_bytes`** is defined as the exact byte span of the `payload` value in the raw
  line — from its opening `{` to its matching closing `}` inclusive. The writer MUST splice
  the payload bytes it signed into the line unmodified (no re-serialization, no
  re-indentation). The verifier MUST extract the span from the raw line bytes with a scanner
  that respects JSON strings and escapes — it MUST NOT parse-and-reserialize.
- `pae = PAE(payloadType, payload_bytes)` per the DSSE spec:
  `"DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload_bytes) SP payload_bytes`
  where LEN is the decimal ASCII byte length and SP is a single 0x20.
- `sig.sig` = Ed25519 signature over `pae`, base64 (standard alphabet, padded), by the
  emitter key identified by `sig.keyid`.
- `leaf_hash` = lowercase hex SHA-256 over `pae`. (Week-1 leaf definition; the Week-2 Tessera
  leaf hashes the stored envelope per the schema doc — the `format` string is the switch.)

### 1.3 Head line

```json
{"kind":"head","head":{"format":"behalf.sh/export/v1","log_origin":"<origin>","count":47,"chain":"<hex>"},"sig":{"keyid":"<jkt>","sig":"<base64std>"}}
```

- Chain rule: `chain_start = SHA-256("behalf.sh/chain/v1\n" + log_origin)`;
  `chain_i = SHA-256(chain_{i-1} || leaf_hash_i_raw)` for i = 0…count−1, where
  `leaf_hash_i_raw` is the 32 raw bytes (not hex). `head.chain` is the final value, hex.
- `head_bytes` = the exact byte span of the `head` value in the raw line (same span rule).
- `sig.sig` = Ed25519 over `PAE("application/vnd.behalf.chain-head+json", head_bytes)`.

## 1.4 Reading an export back

`behalf-log import` rebuilds a local log from export files — the path
`npx onbehalf demo` takes, because the built tile directory is 23 MB against 452 KB for the
two exports it was made from, and `npx` re-downloads on every run.

Two properties, and the second one is the honest half:

- **Every leaf survives byte for byte.** The envelope is reassembled from the payload span
  and the emitter's original signature, both verbatim, and `envelope.Build` is byte-for-byte
  the assembly the capture surface performed. Re-export an imported log and the leaf lines
  come back identical — `TestImportPreservesEveryLeafByteForByte`. That is what makes it an
  import rather than a re-signing: a re-signed receipt would verify beautifully and mean
  nothing, because it would be attested by whoever ran the import.
- **The head does not, and must not.** The imported log signs its own checkpoint. The
  original log's checkpoint key is not in an export and could not be: a local process able
  to mint a checkpoint under another log's identity is precisely the forgery this format
  exists to make detectable. So the export file remains the artefact to check against the
  head that actually signed it, and the imported log stands on the emitter signature each
  receipt still carries.

The reader (`internal/exportv1.Read`) is deliberately **not** a third verifier. It parses
structure and checks each leaf's `leaf_hash` against its own payload span — an importer that
ingested a self-inconsistent line would launder a broken record into a fresh log — and stops
there. Signatures, the chain, the head and the ordering rules are `behalf-verify`'s, which
`import` runs over each file first and refuses to proceed without. Two implementations of the
verification contract, pinned to each other by the conformance corpus, is the design; a third
growing quietly inside an importer is how they would come to disagree.

## 2. Verifier contract (`behalf verify <file>`)

Checks, in order, reporting the **first** failure class but continuing where meaningful:

1. Parse header; unknown `format` → unverifiable. Unknown *extra* JSON fields anywhere MUST
   be ignored (the greased-checkpoint discipline).
2. Per leaf: extract `payload_bytes` span, recompute `pae`, check `leaf_hash`, verify `sig`
   against the header key for `keyid`. A mismatch is **content tampering at index N**; every
   later receipt is reported unverifiable (`chain breaks at N; receipts N+1..count-1 unverifiable`).
3. Index sequence: a gap is a **dropped receipt**; a non-ascending index is **reordering**.
4. `head.count` vs actual leaf count: fewer leaves is **truncation**. This check runs
   *before* the chain compare — a truncated file must classify as truncation, not as the
   trivially-mismatched chain it also implies. More leaves than `head.count` classifies as
   **chain**.
5. Recompute the chain (over the header's `log_origin`); mismatch with `head.chain` (with
   counts matching and all leaves individually valid) is a **chain mismatch**. An edited
   `head.chain` therefore surfaces as class `chain`, since this runs before the head
   signature check.
6. Verify the head signature; failure is **head tampering**. An unknown or undecodable
   `sig.keyid`/signature on a *leaf* classifies as **content** at that leaf (a swapped-in
   foreign key is tampering, not unverifiability); on the head, as **head**.
7. Missing head line entirely is **truncation**.

Malformed JSON, wrong types, or missing required fields anywhere in the file — not just the
header — make the export unreadable: exit 2. A duplicated top-level `payload`/`head` key
inside a line (span-smuggling) is likewise exit 2.

Duplicate `receipt_id` inside `payload` is classified as **duplicate**, never as tampering — report it, exit 0 if everything else verifies.

### Exit codes (stable, documented, load-bearing for CI)

| code | meaning |
|---|---|
| 0 | verified: all receipts intact, chain and head verify |
| 1 | tampering detected (any class above: content, drop, reorder, chain, truncation, head) |
| 2 | unverifiable: not a readable export (bad args, missing file, malformed header/JSON) |

Human output mirrors the demo script: `✔ 47/47 receipts intact   chain head <first4>…<last4>`
(e.g. `4f0c…a19e`) on success; on tampering, the class, the index, and the unverifiable
range. Also emit a machine-readable line per failure on stderr:
`class=<content|drop|reorder|chain|truncation|head|duplicate> index=<N>`, with these index
conventions: content/sig failures → the tampered leaf's index; drop → the first missing
index; reorder → the first position where ascending order breaks; truncation → the first
missing index; chain/head/missing-head → `-1` (no leaf index).

## 2a. Log mode (Week 2): `behalf verify log <dir>`

Verifies the tlog-tiles directory the Tessera POSIX log writes, with the same class
vocabulary and exit codes. Differences from file mode, for the record:

- **Check order**: checkpoint note signature first (grease lines ignored) — an edited
  checkpoint root classifies **`head`** here, where file mode's edited `head.chain`
  classifies `chain`; the checkpoint is the size oracle and must authenticate before
  anything else is interpreted. Then the stale-restore check (`--latest-known`),
  bundle coverage (`truncation`), per-entry content, root recompute (level-0 hash tiles
  are rebuildable derived data — consulted only to *localize* a mismatch, and trusted for
  that only when they reproduce the signed root), and prefix-root consistency (`chain` =
  fork).
- **Missing `checkpoint` file is exit 2**, not truncation: without it there is no
  authenticated size to measure truncation against.
- **A stale restore verifies clean in isolation** (deliberately tested): only
  `--latest-known <earlier-checkpoint>` — and, in production, the witness — makes
  restore-as-truncation detectable. The CI suite carries this case as exit 0 on purpose.
- **Witness cosignatures ride on the checkpoint** (Week 2, ENG-11). When witnesses are
  configured, the log writes `<dir>/checkpoint.witnessed`: the published checkpoint with
  the witness's C2SP `cosignature/v1` signature line appended. The verifier needs no
  change to read it — a cosignature/v1 signature decodes to 4+8+64 bytes rather than the
  4+64 an Ed25519 note line has, so `note.rs` skips it as an unknown line under the same
  grease rule as `grease.invalid`, and `checkpoint.witnessed` therefore works verbatim as
  a `--latest-known` argument. Checking the cosignature itself — which would turn the
  witness's independently held tree head into a verifier-enforced check rather than an
  operator-side one — is not implemented and would need a witness key set on the command
  line, in the shape `--emitter-keys` already uses. The suite asserts the tolerance today
  (`witness-cosigned-checkpoint-tolerated`).
- **Emitter keys have no distribution channel in the tile dir**: envelopes carry key
  thumbprints only, and `index.db` is out of scope for verification. `--emitter-keys
  <file>` (export-header `keys` shape) enables full DSSE verification; without it,
  envelope checks are structural and the output says so (the no-overclaiming rule).
  The real channel is the published-key-log milestone; key-registration receipts as log
  leaves (ENG-22) would close it from inside the log.

## 2b. Browser mode (Week 4): the WASM verifier

The same crate built for `wasm32-unknown-unknown` (`make wasm`), exposing **file mode
only** through two `wasm-bindgen` entry points:

- `verifyExport(bytes) -> string` — the structured result as JSON:
  `{verdict, exit_code, format, receipts, head_count, chain_head, chain_head_short,
  failures[{class,index,human,machine}], duplicates[], notes[], stdout, stderr[], reason}`.
  `verdict` is `verified` / `tampered` / `unverifiable`, tracking exit 0 / 1 / 2;
  `stdout` and `stderr` are the CLI's own bytes, so a page can show the terminal's
  vocabulary rather than invent its own.
- `verifierInfo() -> string` — `{name, version, format, modes}`; `modes` is `["file"]`.

Constraints that follow from the no-overclaiming rule:

- **Unreadable input is a value, never an exception.** Malformed bytes return the
  `unverifiable` verdict with a `reason`; the wasm surface does not throw, so JavaScript
  never has to tell a thrown `RuntimeError` apart from a real finding.
- **Log mode is absent, not stubbed.** `verify log <dir>` walks a tile tree, so
  `logdir`, `tiles`, `envelope`, `note` and `merkle` are compiled out of the wasm target
  entirely rather than given a fake filesystem that fails at runtime. The page says so.
- **No network, by construction.** Nothing in the verification path fetches anything.
- **Signatures are still checked only against the keys the export carries.** The browser
  proves internal consistency, not key provenance — the published key log remains the
  missing piece, and the page must not let a green tick imply otherwise (the
  no-overclaiming rule).

`verifier/tests/browser_parity.rs` runs the real CLI binary over the corpus above and
asserts the structured result carries the same exit code and byte-identical stdout and
stderr — so the two surfaces cannot drift.

## 3. Test-vector corpus (ENG-4)

Generated by the Go writer into `testdata/vectors/` (gitignored; regenerated in CI):

- `pae/*.json` — `{payload_type, payload_b64, expected_pae_sha256_hex}`
- `sig/*.json` — `{seed_b64, jkt, payload_type, payload_b64, pae_sha256_hex,
  expected_sig_b64}` (deterministic test keys derived from fixed 32-byte seeds; never used
  outside tests). Ed25519 signs the full PAE, not its hash — verifiers reconstruct the PAE
  from `payload_type` + `payload_b64` and check the signature over it; `pae_sha256_hex` is a
  cross-check.
- `chain/*.json` — `{log_origin, leaf_hashes_hex[], expected_chain_hex}`
- `exports/intact_*.jsonl` — full exports that must verify (exit 0)
- `exports/tampered_*/` — `{file.jsonl, expected.json}` where expected.json gives
  `{exit_code, classes[{class, index}]}`

The Rust verifier ships a conformance test that consumes this directory (path via env var
`BEHALF_VECTORS`, default `../testdata/vectors` relative to the crate).

## 4. Fixture pair (ENG-5, placeholder until Week 3's recorded runs)

`cmd/behalf-fixtures` writes `run_9f2a.jsonl` and `run_c71e.jsonl`: 47 receipts each,
deterministic (fixed seeds, fixed timestamps: runs start 2026-08-25T22:04:00Z and
2026-08-26T02:17:00Z), payloads valid against `receipt-schema-v1.schema.json`. The runs
diverge at step 12 (`orders.search` returns `ord_5512`/`$12.00` first vs `ord_5518`/`$1200.00`
first) with the consequence at step 31 (`refund.issue` `"amount":"12.00"` vs
`"amount":"1200.00"`); the literal string `1200.00` MUST appear exactly once in run_c71e's
step-31 payload so the demo's `sed` hits it. All other steps are identical between the runs.
These are explicitly placeholders: Week 3 replaces them with genuinely recorded runs.

## 5. The tamper suite (ENG-1)

The CI-gating cases, run against the fixture pair with the shipped Rust verifier:

| case | mutation | expected |
|---|---|---|
| intact | none | exit 0 |
| cover-up | `sed s/1200.00/12.00/` on run_c71e | exit 1, `class=content index=31`, 32–46 unverifiable |
| drop | delete leaf line index 20 | exit 1, `class=drop` |
| reorder | swap leaf lines 10 and 11 | exit 1, `class=reorder` |
| truncate | remove last 5 leaf lines (head kept) | exit 1, `class=truncation` |
| sig-flip | flip one byte inside a signature | exit 1, `class=content` |
| head-edit | edit `head.chain` | exit 1, `class=chain` (chain compare runs before the head signature check) |
| garbage | random bytes | exit 2 |

The suite runs on every commit and a commit that breaks it cannot merge.
