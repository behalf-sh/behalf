# behalf v1 Action Receipt — frozen schema

Written 27 Aug 2026. Every field here traces to a recorded design decision. Where a decision
settled a shape, this freezes it; where it only *reserved* optionality, this reserves the slot and
says so. The machine-readable form is [`receipt-schema-v1.schema.json`](receipt-schema-v1.schema.json).

This is a **v1 freeze**: the fields below are the ones that must exist in the first receipt ever
written, because receipts are immutable and hash-chained and none of this can be re-cut onto
historical records. The adversarial pass in the final section is the reason the
freeze is drawn where it is.

---

## 1. What freezes, and what deliberately does not

Two invariants from the corpus govern everything here:

- **Stored bytes are the signed bytes are the hashed bytes — verbatim forever, never rewritten**. Schema evolution lives entirely on the *read* path: reads project by `schema_version`, one
  export surface returns canonical bytes for the verifier, and a reconstruction spanning an upgrade
  legally mixes versions with each record labelled. A `schema_version` bump therefore does not
  rewrite or re-chain a single existing record.
- **Raw inputs are hashed evidence; computed values are recomputable and live on the read path**. Anything a verifier can recompute from captured bytes — an attenuation delta, a
  rollup classification, an index column — is deliberately kept *out* of the hashed envelope so a
  computation bug can never freeze into evidence. Anything that can only be observed *at
  capture* must be inside the envelope, because it cannot be backfilled.

The second invariant is the whole design tension. It is stated once here and applied field by field,
and it is the test the adversarial pass (§9) runs to decide what else must freeze now.

**Not in this schema, by construction:** log index (`seq`), inclusion proofs, checkpoint
membership, `checkpoint_id`. These are ingest-assigned and live in the log structure and the index
projection, never inside the signed receipt — which kills the `checkpoint_id`-in-the-record
circularity outright. Arrival time and grouping provenance that ingest computes also live in
the index projection, not the envelope. The hash provably covers *what was captured*, not what
behalf later computed.

---

## 2. The canonicalisation decision — DSSE, decided

**Decision: DSSE with pre-authentication encoding (PAE) is the envelope. RFC 8785 JCS is not
adopted.** This settles the envelope as DSSE.

### The record

| | RFC 8785 JCS | **DSSE + PAE (chosen)** |
|---|---|---|
| What is signed | a *canonicalised* JSON document | the exact submitted bytes, wrapped in PAE |
| Canonicalisation step | required, and must agree byte-for-byte across writer and every verifier, forever | **none — there is no canonicalisation step to disagree about** |
| Number/whitespace ambiguity | a live failure surface (several products canonicalise with JCS or RFC 8785 before hashing) | structurally absent: PAE frames length-prefixed opaque bytes, so serialisation is never re-derived |
| Path to COSE/SCITT (RFC 9942) | re-canonicalisation tax when COSE emission lands | later COSE/SCITT emission wraps *the same bytes* |

### Why DSSE wins here

PAE's structural sidestep is the entire argument: because the signed bytes are
the stored bytes, "no canonicalization step exists to disagree about." A tiled transparency log
recomputes the leaf hash from bytes on every verification; a canonicalisation function that
must produce identical output on a Go writer and a Rust verifier years apart, across
`schema_version` bumps and storage-engine replacement, is exactly the kind of hidden coupling
that "years-old receipts must still verify" cannot afford. DSSE removes the function.

**Explicitly not used as evidence:** the retracted JCS number-serialisation anecdote (`1250.0` vs
`1250`) that is not relied on plays no role in this decision — the argument is structural, not
anecdotal. The decision would stand even if that anecdote were false.

### The two artifacts

1. **The producer envelope** — the DSSE-signed receipt payload: everything the capture surface
   asserts, and the subject of the schema in §4–§7. `payloadType` is
   `application/vnd.behalf.receipt+json`; `payload` is the receipt JSON; `signatures[]` carries the
   emitter key signature (§5).
2. **The log leaf** — the hash of that complete DSSE envelope. Tessera's tree covers the leaf;
   log index, inclusion proofs and checkpoint membership stay external in the log structure.

The offline Rust verifier recomputes the leaf hash from the DSSE envelope bytes and checks the
emitter signature and the delegation chain against published JWKS, with no call to behalf or the IdP.

---

## 3. Record kinds — the receipt family

Everything evidentiary is a leaf in the **one global log**; there is no separate control
stream. `kind` is a **closed vendor enum**; customer vocabulary rides the verbatim, non-load-bearing
`kind_ext` namespace.

| `kind` | What it records | Anchoring rule when no action exists |
|---|---|---|
| `action` | the default: one trust-boundary crossing | — |
| `tool_call` / `resource_read` / `message` | operation sub-kinds of the above | — |
| `delegation` | a minted hop / sub-agent invocation | — |
| `delegation_failed` | a chain a customer tried to build and couldn't | anchors to the delegation token `jti`/`par_hash` + intent digest |
| `approval` / `denial` | human consent / refusal, from the Claude Code `PermissionRequest`/`PermissionDenied` hook pair | anchors to the delegation token `jti` + intent digest |
| `revocation` | a revocation event, never a mutation | links to affected actions by `credential_ref` (`jti`) match |
| `erasure_notice` | the customer deleted their own payload blob | references what it destroyed by digest |
| `policy_change` | a retention/capture policy change, itself audited | — |
| `orphan_intent` | intent flushed on crash recovery — payment fired, agent died | carries the spooled intent digest |
| `import` | a record brought in by `behalf import`, `asserted` floor no later op can raise | — |
| `refusal` | rejection of unhashable/oversized bytes — even refusal leaves evidence | carries the submission digest |
| `loss_marker` | spool overflow: N records shed, signed, with count + digest range | carries count + digest range |
| `attestation` | late-arriving evidence linked to a sealed record; folds into a "current best" read view | links to the target record |

`kind` is a closed enum precisely so "we record everything" is falsifiable; widening is forward-only. Reclassification acts forward only.

---

## 4. Envelope core

The receipt payload. Legend: **R** required at write, **O** optional, **R\*** required-if
(condition given).

| Field | Req | Type / values | Decision & why it is here |
|---|---|---|---|
| `schema_version` | R | const `"behalf.sh/receipt/v1"` | Read-path projection key; verbatim bytes never rewritten. |
| `otel_conventions_version` | R | string | The gen_ai.* conventions version in force at capture; the second projection key that lets old records be re-normalised when the still-Development conventions move. |
| `receipt_id` | R | client-minted ULID | The idempotency key, minted **client-side at capture** so a retried send can never occupy two immutable chain positions. Ingest dedups on it against a bounded window before append. |
| `kind` | R | enum (§3) | Closed vendor enum. |
| `kind_ext` | O | string (namespaced) | Verbatim, non-load-bearing customer vocabulary. |
| `risk_class` | R | enum | Assigned by the proxy's capture-time tool-policy config, **not** producer-self-reported. |
| `risk_policy_digest` | R | sha256 | Digest of the policy that assigned `risk_class`, recorded on the receipt so the assignment is auditable rather than free-floating self-report. Write-time-only (see §9). |
| `captured_at` | R | RFC 3339 | Capture-surface timestamp (asserted; clock trust is a later concern). |

---

## 5. Identity — emitter vs actor

behalf's own records must not be the caller-supplied strings the product condemns, so the
surface that *produced* the evidence and the actor it *attributes* to are separated first-class.

| Field | Req | Type / values | Decision & why |
|---|---|---|---|
| `emitter` | R | object | The capture surface. `emitter.jkt` = the surface's own Ed25519 key thumbprint, generated at install, distinct from any human device key. This key signs the DSSE envelope and is bound under the leaf hash. |
| `emitter.surface` | R | enum `mcp-proxy` \| `claude-code-hook` \| `cli` | The canonical v1 surface is the MCP proxy; hooks are the demo companion. `cli` widened forward-only on 27 Aug for receipts the `behalf` CLI itself emits — the first being `behalf login`'s root receipt. |
| `emitter.counter` | R | integer, per-emitter monotonic | Stamped before spooling so loss or reordering between capture and append is detectable — custody begins at capture-signature. Write-time-only integrity primitive (see §9). |
| `actor` | O | object | Who acted, if distinct from emitter. |
| `actor.jkt` | R\* | key thumbprint | The **canonical actor identity is the hop's key thumbprint** — keys are what the cryptography proves. Required if `actor` present. |
| `actor.labels` | O | object | `clientInfo`, hook `agent_id`/`agent_type`, MCP server name — stored **verbatim as asserted labels**, per MCP's own warning that they are self-reported. Never used for security decisions. |
| `actor.emitter_to_actor` | O | const `"asserted"` | The emitter-to-actor assertion is recorded but never enforced — recording who produced the evidence without becoming an authorization engine. |

Human-readable identity is **not** in the receipt: it lives in the customer-held ID-token blob and a
local, versioned alias map in the index; no IdP write-back in v1.

---

## 6. Operation, attempt, run

| Field | Req | Type / values | Decision & why |
|---|---|---|---|
| `operation` | R | object | The trust-boundary crossing: one JSON-RPC request/response pair for the v1 proxy. |
| `operation.name` | R | string | Tool/operation name. |
| `operation.target` | O | string | The resource acted on. |
| `operation.outcome` | R | object | Result or failure; `outcome` covers failure of the attempted operation. |
| `operation.idempotency_key` | O | string | The *target operation's* idempotency key, if any — distinct from `receipt_id`. |
| `attempt` | O | object | Intent is durably spooled by the proxy before forwarding, then merged into the single completion receipt in the common case; on crash it flushes as an `orphan_intent` receipt. One record in the common case. |
| `attempt.intent_digest` | R\* | sha256 | The spooled intent digest — also the anchor for `denial`/`delegation_failed` records. Required on `orphan_intent`. Write-time-only: the payment-fired-agent-died hole cannot be backfilled. |
| `run_id` | R | string | The replay grouping key. Populated by **normative precedence**: caller/SDK-supplied key → Claude Code session/agent id (hooks) → root `trace_id` from carried `traceparent` → proxy-process session. |
| `run_id_provenance` | R | enum `caller` \| `hook-session` \| `traceparent` \| `proxy-session` | Which fallback produced `run_id`, so grouping is honest about its own provenance. Write-time-only (see §9). |
| `correlation` | O | object | The other five of the six correlation keys — `trace_id`, `session_id`, `txn`, `acti`, `conversation_id` — as index columns; **all six are indexed, none but `run_id` is required at ingest**. |
| `step_key` | O | sha256 of (tool name, normalized argument schema, causal ordinal) | Reserved and populated by the proxy now so the flagship `behalf diff` works on day-one data; query-time sequence alignment is the fallback. Reserving it now is the point: receipts written before this decision would be **permanently invisible to the diff demo** (see §9). |

---

## 7. Delegation chain — per-hop

The chain is the **AAT token chain itself** — a JWS chain per
`draft-niyikiza-oauth-attenuating-agent-tokens-01` whose `par_hash` linkage *is* the DAG edge —
**embedded whole** in the receipt (2,316–2,565 bytes at 3 hops, measured). Embedding
wins at v1 depth because the offline verifier must verify a single receipt with no store to chase. The OCSF `delegation{uid, parent_uid}` envelope is populated in *export* mapping from
`par_hash`.

`authority.chain` is an ordered array of hop objects. Per hop:

| Field | Req | Source / values | Decision & why |
|---|---|---|---|
| `del_depth`, `del_max_depth` | R\* | AAT draft, verbatim | Adopt the draft's field set as specified. Required if a chain is present. |
| `par_hash` | R\* | AAT draft | The linkage that *is* the DAG edge. |
| `cnf.jwk` | R\* | AAT draft | Hop key confirmation. |
| `authorization_details` | R\* | RFC 9396, **raw** | The raw per-hop grant, captured verbatim. The attenuation delta is **computed at read/verify time** from these raw inputs, stamped with a comparator version, so computation bugs never freeze into evidence. |
| `exp` | R\* | AAT draft, **verbatim** | Per-hop expiry. Half of the revocation-window join. |
| `jti` | R\* | **draft-required** | Per-hop token id. *Corrected 27 Aug 2026:* this said **behalf extension**; the AAT draft REQUIRES `jti` (§3.2) and denies a hop without it (§7), so it is not ours and never was. The other half of the revocation-window join. **Unbackfillable**. |
| `credential` | R\* | object `{issuer, kind, id, exp, jkt}` | The canonical credential reference — namespaced opaque ids, `exp` verbatim, **never the token**. This is "the write-time half that cannot be retrofitted": retrofitting a canonical key onto a year of opaque per-IdP strings is a rekeying migration against immutable data. Carries `auth_time` and `amr` where the exchange exposes them (e.g. the observed `id_jag`). |
| `root_principal_binding` | R\* | **behalf extension** | At depth 0, the OIDC nonce-thumbprint binding (`nonce == jkt(device_pubkey)`) — the one genuinely verifiable thing in the stack. |
| `trigger` | R\* | object `{kind: schedule\|webhook, descriptor_digest}` | For autonomous roots: depth-0 is the installing operator's device key carrying a `trigger` claim, honestly `asserted`. Required if the root is autonomous. |
| `verification` | R\* | object `{status, method, evidence_ref}` | Per-hop three-state — `verified` \| `asserted` \| `broken` — carried per hop. See §8. |
| `carriage_route` | O | enum / string | How the hop arrived (in-band signatures vs out-of-band `params._meta` `sh.behalf/chain` over MCP); recorded as metadata so an out-of-band hop is explicit, since verification comes from the signatures regardless. |
| `attenuation_flag` | R\* | includes value `unknown` | Vocabularies the AAT invariants cannot compare (proprietary role systems, wildcard grants) yield `attenuation: unknown`, **recorded and flagged, never swallowed**. The hop carrying one is `asserted`, never `verified`: the flag says the comparison could not be made, and the status must not claim otherwise. |

No bespoke normalization layer in v1; comparison is the AAT draft's six invariants, adopted not
reinvented. The draft's deliberate `sub` omission is preserved above the root — the
token proves *which key*, not *who*.

---

## 8. Attribution — the two orthogonal axes

Attribution is **stored at write, never derived at query time** (spec §3 rule 3). Two
orthogonal axes:

| Field | Req | Values | Decision & why |
|---|---|---|---|
| `attribution.verification` | R | `verified` \| `asserted` \| `broken` | The receipt-level rollup = the **weakest hop**. Composition rule: any invalid signature or invariant violation → `broken`; an invariant that could not be *run* — a grant vocabulary the comparator has no rules for — → `asserted`, never `verified`; else a chain whose root passes the root-binding checks is `verified` at the root and `asserted` above it. Three states, not two — collapsing the middle into `broken` reads as FUD; naming it `asserted` reads as engineering. |
| `attribution.class` | R | `direct` \| `delegated` \| `autonomous` \| `unattributed` | A second axis stored at write from chain shape. Derived strictly from token-path evidence; a linked `approval` receipt is recorded and joined but **never reclassifies** the stored attribution. |

Day-zero-with-login renders as "verified root, asserted chain" — honest, not a hostile
100%-unattributed wall (architecture.md "two collisions"). The dashboard metric (numerator =
share of consequential action receipts at each verification state; denominator = all action
receipts; sliced by capture source and session) is a **read-path** computation over these stored
fields and is *not* frozen here.

---

## 9-adjacent. Payload custody

Payloads are **customer-held, everywhere** — in local-first v1, the customer's own disk.
behalf holds the index, digests, references, sizes, content types and custody-mode — never content. `payload` is an array of slots; per slot:

| Field | Req | Type / values | Decision & why |
|---|---|---|---|
| `digest` | R\* | **plain SHA-256 over raw plaintext bytes** | Commitment and storage address are one value in v1: the CAS is customer-side, so salting would break third-party verification and dedup while defending against nobody; the residual low-entropy re-identification risk is accepted and documented. |
| `custody` | R\* | enum `customer-held` \| `dropped-with-digest` \| `vendor-held` (reserved) | Frozen into the schema deliberately: a verifier reading a receipt years later must distinguish "never here" from "deleted" from "no access" — three different findings. **Unbackfillable** (§9). |
| `content_type`, `size` | O | string / int | Metadata behalf may hold. |
| `ref` | R\* | path \| URI \| opaque handle \| content address | The payload reference shape — immutable from record one; it determines whether a payload can ever be relocated without breaking the binding. Frozen as a **content address**. |
| `field_digest_manifest` | O | Merkle over canonicalized JSON fields | Whole-blob digest **plus** a field-digest manifest captured at write for JSON payloads (non-JSON gets whole-blob only) — precisely what keeps verifiable redaction, per-field retention and selective disclosure *possible* for v1-era records. **Unbackfillable** (§9). |
| `subjects[]` | O | array, explicitly `asserted` | Reserved so future erasure queries can enumerate scope; per-subject separation cannot be applied retroactively. A schema reservation, not a feature. Asserted, per the never-accept-self-asserted-identity rule. |
| `state` | R\* | `present` \| `missing` \| `deleted` \| `unreadable` \| `dropped-at-capture` | The reconstruction placeholder: a run full of placeholders is still verifiable evidence because the receipts carry digests regardless. This is the normal path, not the edge case. |
| `cause_ref` | O | link | Reference to the `policy_change`/`erasure_notice` receipt that explains a non-`present` state. |

`model_call` is a **reserved context class** — a customer-held payload artifact referenced by digest
from the acting receipt, populated when the in-process SDK surface arrives; keeps receipts sparse
(1–3% of trace volume) while leaving full-fidelity model capture reachable without a schema break.

Identity in the receipt is pseudonymous only: key thumbprints for actors (§5) and issuer +
`sub`-digest for the human principal. `human_in_loop` (`approval_receipt_id`, `satisfied_by`,
`binding_message` digest) is marked `asserted` — a click is not cryptography.

**Provenance & links.** `provenance.source` ∈ `native` | `import`; an `import` carries an `asserted`
floor no later operation can raise, and the provenance class travels in every rendering and proof. `links[]` are typed references carrying the target's log index + leaf hash.
`annex_iii_category` is reserved as a **forward provision only** — nothing is sold on compliance
today.

---

## 9. Adversarial pass — what we will wish we had captured

**The one question:** what must be captured *now*, into the hashed envelope, that cannot be added
later without splitting the evidence corpus into a blind pre-field era and a sighted post-field era?

Because a `schema_version` bump does **not** re-chain existing records, "splits the chain" here
means the sharper thing: a field whose absence
**permanently forecloses a capability for every record already written**. The retrofit is impossible
not because the format can't grow, but because the *information was only observable at capture* and
is gone.

### The test (the contribution, not just the list)

A field must freeze into v1 iff **both**:

1. **Hash-covered** — it belongs inside the DSSE envelope (it is part of what the capture surface
   asserts), not the index projection; and
2. **Capture-only** — it is derived from information available **only at capture time** and is
   **not recomputable** from other captured bytes later.

Fields failing (2) are safe to defer to the read path — and the corpus deliberately puts them there:
the attenuation **delta** (recomputable from raw `authorization_details`), the
verification **rollup** and attribution **class** (recomputable from per-hop `verification` — though
the corpus stores them at write anyway per spec §3 rule 3, they *could* be recomputed), the
unattributed-rate **metric**, OCSF export envelopes, `seq`/checkpoint membership,
and every index column. This boundary is why the list below is finite.

### The four known (confirmed against the test)

| # | Field | Passes because | Foreclosed if omitted |
|---|---|---|---|
| K1 | Per-hop `jti` and `exp` (§7) | capture-only: ephemeral IdP token ids, uncaptured elsewhere; identity providers do not stream them | the revocation-window finding — "last action under a revoked/expired credential" — is uncomputable for all v1 data |
| K2 | Per-hop `verification` three-state + `attribution.class` (§8) | capture-only: verification evidence exists only at the moment of the exchange | attribution cannot be backfilled; the moat metric is blind for pre-field records |
| K3 | Payload `custody` enum (§9-adjacent) | capture-only: only the capturing surface knows whether the blob was held, dropped, or never present | a verifier can't distinguish "never here"/"deleted"/"no access" — three findings collapse to one |
| K4 | `provenance.source` = `import` + asserted floor (§8) | capture-only: import context exists only at import | an imported record could later be dishonestly claimed as write-time-signed evidence |

### The rest (found — same test, ranked by severity)

1. **`payload.field_digest_manifest` — Merkle over canonicalized JSON fields.** The sharpest
   one worth flagging. A whole-blob digest **permanently** forecloses verifiable redaction,
   per-field retention, and RFC 9942 selective-disclosure proofs for every v1-era record — the
   retrofit trap. Cheap at capture, impossible
   after. *Passes: hash-covered, capture-only.*

2. **`step_key` — hash(tool name, normalized arg schema, causal ordinal).** If not stamped
   now, "every receipt written before this decision is permanently invisible to the flagship demo". The diff feature ships *later*, but the field cannot. *Passes: hash-covered, capture-only
   (the normalized argument schema and causal ordinal are a capture-time observation).*

3. **`emitter.counter` — per-emitter monotonic counter.** Custody begins at capture-signature;
   without the counter stamped before spooling, anything suppressed in the capture-to-append window
   (which the spool can widen from milliseconds to hours) leaves **no gap to find**, and the
   "prove nothing was deleted" demo rebounds onto behalf's own transit window. *Passes:
   hash-covered, capture-only.*

4. **`credential` object `{issuer, kind, id, exp, jkt}` with namespacing.** Beyond the raw
   `jti`/`exp` of K1: the *canonical, namespaced* form. Storing opaque un-namespaced per-IdP strings
   makes cross-mechanism revocation joins a "rekeying migration against immutable data".
   Includes `auth_time`/`amr` where the exchange exposes them (the `id_jag` carries both):
   strength-of-authentication evidence is capture-only and unbackfillable. *Passes.*

5. **`attempt.intent_digest` — spooled intent, and the `orphan_intent` kind.** The
   payment-fired-agent-died incident "leaves no receipt, and that hole cannot be backfilled onto
   history". The intent must be durably spooled *before* forwarding, and it is the anchor for
   `denial`/`delegation_failed` records that have no action to point at. *Passes: hash-covered,
   capture-only.*

6. **`receipt_id` client-minted at capture, as idempotency key.** If ingest mints the id
   instead, a retried send can occupy two immutable chain positions and the duplicate reads as
   tampering, "poisoning the prove-nothing-was-deleted demo" — uncorrectable once chained
   (immutability). The *mint location* is the frozen decision. *Passes: capture-only by
   construction.*

7. **`run_id_provenance` — which precedence rung produced `run_id`.** Without it you can never
   later distinguish a caller-supplied `run_id` from a proxy-session guess, so grouping cannot be
   honest about its own provenance. Capture-only: the fallback that fired is knowable only at
   capture. *Passes.*

8. **`risk_policy_digest` — digest of the capture-time policy that assigned `risk_class`.**
   `risk_class` self-reported by the producer "reproduces the exact self-asserted-metadata failure
   the product exists to correct"; the policy digest is what makes the assignment auditable
   rather than free-floating. The policy in force is a capture-time fact. *Passes.*

9. **Raw `authorization_details` retained verbatim in the hop.** Not the delta — the delta
   is read-path (it *fails* test 2 and is correctly deferred). But the **raw inputs** must be
   hash-covered at capture, or the delta can never be computed *at all*, and non-comparable
   vocabularies must be stamped `attenuation: unknown` rather than silently dropped. The raw
   grant is capture-only, and the hop carrying such a stamp is `asserted` rather than `verified`. *Passes — and marks the exact boundary: raw in, computed out.*

10. **`otel_conventions_version` stamped per record, and optional `raw_frame_ref`.**
    Old records can only be re-normalised when the still-Development gen_ai.* conventions move if the
    conventions version is stamped at write and (optionally) the raw source frame is retained by
    digest. The version in force is capture-only. *Passes (the version; the raw frame is the
    optional stronger form).*

11. **`emitter.jkt` distinct from `actor.jkt` — the emitter/actor split.** If evidence is not
    signed by an emitter key distinct from the actor identity from record one, "behalf's own records
    are caller-supplied strings", and you can never retroactively
    prove *who produced* a given historical record. *Passes: hash-covered, capture-only.*

12. **`carriage_route` on out-of-band MCP hops, and the reserved `subjects[]` asserted tag.** Lower severity — both are honesty/optionality markers. `carriage_route` records whether
    a hop arrived signed-in-band or asserted-out-of-band; `subjects[]` reserves erasure-scope
    enumeration that "cannot be applied retroactively". Reserving the *slot* now is the
    unbackfillable part; populating it can lag. *Passes weakly (reservation, not full population).*

### The boundary, stated for the record

Everything above is capture-only and hash-covered. The corpus's discipline — **raw inputs hashed,
computed values recomputed on read** — is what keeps this list from being infinite: the
delta, the rollup, the class, the metric, the OCSF envelope, the checkpoint id, and every index
column are all recomputable or ingest-assigned, so they are *not* frozen here and carry no retrofit
risk. If a proposed field can be recomputed from what these receipts already carry, it does not
belong in the v1 freeze. If it cannot, it does — and this section is the complete v1 set the corpus
supports.
