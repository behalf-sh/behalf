# behalf-verify

The offline verifier for behalf action-receipt exports. It takes an export file and returns a
verdict, with no call to behalf, no call to an identity provider, no account and no network.

```sh
cargo install behalf-verify
behalf-verify run_c71e.jsonl
```

```
✔ 47/47 receipts intact   chain head 7189…93ee
✔ 94 delegation hop(s) checked: I1 authority, I2 depth, I3 expiry, I5 linkage
  not checked here: I4 capability monotonicity, I6 proof of possession, and the identity root
  47 hop(s) caller-asserted: no token accompanies them, so nothing about them was checked
```

Exit codes are stable and documented: **0** verified, **1** tampering detected, **2**
unverifiable (not a readable export). Every finding is also emitted as one machine-readable
line on stderr, `class=<content|drop|reorder|chain|truncation|head|duplicate|delegation>
index=<N>`.

## What it checks

**Record integrity.** Each receipt's payload bytes, taken as the exact byte span in the file,
hash to the declared leaf hash; each receipt's Ed25519 signature verifies over those bytes
framed by DSSE PAE; indices are contiguous and ascending; the hash chain recomputed over
every leaf equals the signed head. Nothing is re-serialised on the verification path.

**Delegation chains.** Where the export carries the hop tokens, four of the
attenuating-agent-token draft's six invariants are re-checked: each hop was signed by the key
its parent confirms, depth increments and the budget never widens, no hop outlives its
parent, and each `par_hash` names one specific parent token. It reports findings rather than a
hop verdict, and prints on every run — including successful ones — what it does not check.

**Log directories.** `behalf-verify log <dir>` verifies a tlog-tiles directory: checkpoint
signature, entry bundles, RFC 6962 root recomputation, the stale-restore rule.

## What it does not claim

That the signing key is the legitimate one (the export carries its own keys; binding them to a
real emitter is a published key log's job), that the agent did what the receipt says, or that
this is the current export. The verifier is integrity, not truth, and its output says so.

## Where it comes from

This crate is built from the same source as the browser verifier at
[behalf.sh/verify](https://behalf.sh/verify): one Rust crate, compiled once natively and once
to wasm32. The Go writer and this verifier are pinned against each other by a conformance
corpus in CI, so they cannot quietly drift on what counts as tampering.

The RFC 6962 Merkle math is vendored from [cloudflare/azul](https://github.com/cloudflare/azul)
at a pinned commit, under its BSD-3-Clause licence (`vendor/azul/`). Everything else is
Apache-2.0. Source, format specification and the conformance corpus:
<https://github.com/behalf-sh/behalf>.
