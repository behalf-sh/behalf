# The behalf AAT profile, v1

What `internal/aat` mints and verifies, and every place behalf had to decide something the
adopted draft does not settle for it. This is the upstream-submission obligation written down: the extensions
are named here rather than shipped quietly proprietary, and the two definitions behalf supplied
itself are stated precisely enough to reimplement.

Scope: the delegation token only. The receipt fields it feeds are frozen in
[`receipt-schema-v1.md`](receipt-schema-v1.md) §7 and are not restated here.

---

## 1. The normative reference

The token is `draft-niyikiza-oauth-attenuating-agent-tokens-01`.

**The draft text is vendored**, at
[`vendor/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt`](vendor/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt),
retrieved 27 Aug 2026 from `https://www.ietf.org/archive/id/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt`.
Individual submission, no working group, expires 17 Dec 2026.
[`vendor/README.md`](vendor/README.md) records the provenance and why a copy was the only durable
option. Every section number cited below is a section of that file, and can be read.

That changes what this document is. It was previously a statement of what behalf built with a
note saying the reference could not be checked. It is now a **conformance claim that has been
checked**, hop by hop, in §8. The result of checking it is that several things this document
and its neighbours previously asserted were wrong, and they are corrected in place below —
notably `jti`, which is not a behalf extension (§2), and `par_hash`, whose value the draft does
fix and behalf diverges from (§3).

The reader's rule is unchanged and now enforceable: do not treat this document as a restatement
of the draft. Treat it as what behalf implemented, with every divergence labelled — and where
the two disagree, the vendored file wins as the description of the draft, and this file wins as
the description of behalf.

## 2. The claim set

One hop is one compact JWS. The payload is exactly the §7 field set, in §7's order:

| Claim | Source | Draft §3.2 says |
|---|---|---|
| `del_depth`, `del_max_depth` | AAT draft | REQUIRED |
| `par_hash` | AAT draft — **but not the draft's value**, see §3 | MUST (derived) / MUST NOT (root) |
| `cnf.jwk` | AAT draft | REQUIRED |
| `authorization_details` | RFC 9396, raw and verbatim. behalf mints its own grant shape, not the draft's `attenuating_agent_token` profile — but verifies both, see §8 I4 | REQUIRED |
| `exp` | AAT draft | REQUIRED |
| `jti` | AAT draft — **not a behalf extension**, see below | REQUIRED |
| `credential` `{issuer, kind, id, exp, jkt, auth_time, amr}` | **behalf extension** | — |
| `root_principal_binding` `{nonce, device_jkt, id_token_ref}` | **behalf extension**, depth 0 only | — |
| `trigger` `{kind, descriptor_digest}` | **behalf extension**, autonomous depth-0 roots only | — |
| *(absent)* `iss` | **behalf omits a REQUIRED claim**, see §8 I1 | REQUIRED |
| *(absent)* `iat` | **behalf omits a REQUIRED claim**, see §8 I3 | REQUIRED |

**`jti` is not behalf's.** [`receipt-schema-v1.md`](receipt-schema-v1.md) §7 and
`receipt-schema-v1.schema.json` all describe per-hop `jti` as a named behalf extension submitted
upstream. Against the vendored -01 that is false: `jti` is a REQUIRED claim in Table 1 of §3.2
("Unique token identifier. SHOULD be a UUIDv7 value"), and §7 steps 3j and 4b1 DENY a chain
whose tokens lack it. Whatever the gap was when the extension was first proposed, -01 closed it. behalf's actual
extension in this area is narrower and worth stating precisely: not the claim, but *carrying the
claim into durable queryable evidence* — the receipt-side revocation-window join, which
is a behalf product feature and not a token format claim at all. Those three neighbouring
documents still say otherwise and are left alone here deliberately: the schema is frozen, and
correcting a provenance label inside it is a change for a human to make, not one to slip into a
verification pass.

Three §7 members are deliberately **not** claims: `verification`, `carriage_route` and
`attenuation_flag`. Those are what behalf writes after checking, not what a caller asserts. A
token carrying its own verification status would be a self-graded exam, and
`TestReceiptHopMatchesTheFrozenFieldSet` fails if one ever appears in a minted payload.

The draft's deliberate omission of `sub` above the root is preserved: the token proves which key
narrowed authority, never who. Identity enters exactly once, at depth 0, through
`root_principal_binding`.

## 3. `par_hash` — behalf's definition, and where it diverges

**Correction.** This section previously said "the draft names `par_hash` as the parent linkage;
behalf had to fix the value." That was written from the architecture's description of the draft
rather than from the draft, and it is wrong. The vendored -01 fixes the value four times over —
Table 1 in §3.2, invariant I5 in §4.6, derivation step 7 in §6, and verification step 4q in §7:

> `derived.par_hash == base64url-nopad(SHA-256(parent token signing input))` — §4.6

where the signing input is the JWS Signing Input of [RFC7515] §5.1: `BASE64URL(header) "."
BASE64URL(payload)`, **two segments, the signature excluded**. The draft also requires `par_hash`
to be **absent** in root tokens (§3.2 Table 1, §7 step 3d).

behalf's value is therefore a divergence, not a gap behalf filled. It is:

```
par_hash = lowercase-hex SHA-256 over the parent hop's compact JWS,
           taken as the ASCII bytes of all three dot-joined segments:
           BASE64URL(protected) "." BASE64URL(payload) "." BASE64URL(signature)
```

At depth 0 there is no parent and the value is the all-zero sentinel
(`0000…0000`, 64 hex zeros), which the frozen schema requires the field to carry regardless.
`behalf login` mints the same sentinel into its root receipt.

**Why the signature is inside the hash — and why that argument does not survive the draft.**
The stated reason was that hashing only the parent's claims would let a hop be re-parented under
any other hop asserting the same claims, including one minted by a different key. Against the
draft's actual definition that reason does not hold: the JWS Signing Input covers the payload
(which carries `cnf`, `exp` and the REQUIRED `jti`) *and* the protected header (which carries
`kid`, the signing key's thumbprint). Two parents differing in their signer or their `jti`
already produce different signing inputs. `TestReparentedHopIsBroken` — two parents confirming
the same agent key and differing only in their `jti` — would pass unchanged under the draft's
definition.

So behalf's preimage is **strictly tighter than required and buys nothing the draft did not
already provide**, while costing full wire incompatibility: hex where the draft says
base64url-nopad, three segments where the draft says two, and an all-zero sentinel at the root
where the draft says the claim must be absent. No behalf `par_hash` will ever equal a conforming
implementation's, in either direction.

This is **not** changed here. Changing it would rewrite every minted token, every shipped
fixture and every byte-for-byte CI recording, which is a decision for a human and
not a verification pass. It is recorded in §9 as a divergence awaiting one.

## 4. The JWS shape — behalf's profile

```
BASE64URL(UTF8(protected)) "." BASE64URL(payload) "." BASE64URL(signature)

protected = {"alg":"EdDSA","typ":"aat+jwt","kid":"<signing key's RFC 7638 thumbprint>"}
```

- **EdDSA over Ed25519 only.** All four v1 keys are Ed25519; an algorithm-agility surface
  nobody needs is an attack surface nobody wanted. A token whose `alg` is anything else is
  refused, not negotiated.
- **Each hop is signed by its PARENT's key** — the key the parent confirmed in its own `cnf.jwk`.
  `kid` is that key's thumbprint.
- **The depth-0 hop is self-signed** by the device key `behalf login` bound, which is also the
  key it confirms. That signature proves key possession and nothing more; what makes the root
  evidence is the OIDC nonce binding under it.
- **Minting is deterministic.** No clock, no randomness: Ed25519 signing is deterministic, the
  claim set marshals in declaration order, and `authorization_details` objects marshal with
  sorted keys. The same parameters under the same keys produce the same bytes forever, which is
  what lets a shipped recording be re-verified byte for byte in CI.

## 5. Carriage

Chain material — what travels in `params._meta["sh.behalf/chain"]` — is:

```json
{"schema_version":"behalf.sh/aat-chain/v1",
 "hops":[{"jws":"eyJ…"}, {"claims":{…}}]}
```

Each hop presents **either** a token **or** a bare claim set. The distinction is the product: a
hop that presents claims with no token is saying, in the wire format itself, that nothing backs
it. The proxy records that as `asserted` with reason `caller-asserted: no signature` — never
`verified`, never `broken`.

## 6. The verification vocabulary

`verification.method` is the frozen schema's only free string on a hop besides `evidence_ref`, so
it carries the machine-readable reason. The values are closed and stable:

| `status` | `method` | meaning |
|---|---|---|
| `verified` | `oidc-nonce-binding` | depth 0: the three offline root checks held |
| `verified` | `aat-jws-ed25519` | the parent-key signature, the linkage and the invariants held |
| `asserted` | `caller-asserted: no signature` | the hop arrived with no token |
| `asserted` | `caller-asserted: no root material` | no `behalf login` in this state directory |
| `asserted` | `caller-asserted: root material incomplete` | login evidence deleted; the root is behalf-attested |
| `asserted` | `caller-asserted: parent unverified` | this hop's token holds, the hop beneath it is not verified |
| `asserted` | `caller-asserted: unsupported key type` | a `cnf.jwk` outside v1's Ed25519 scope |
| `asserted` | `caller-asserted: not verified at capture` | a hop embedded with no verification result — unreachable today, and the reason an empty status can never be recorded |
| `broken` | `broken: signature invalid` | a signature was checked and failed |
| `broken` | `broken: par_hash mismatch` | the hop names a parent that is not its parent |
| `broken` | `broken: depth invariant` | depth did not increment, or the budget was widened or exceeded |
| `broken` | `broken: expiry invariant` | the hop outlives its parent, or had expired at capture |
| `broken` | `broken: attenuation broadened` | the grant widens the authority its parent delegated |
| `broken` | `broken: root predicate failed` | the root checks ran and failed, or the root is not this login's device key |
| `broken` | `broken: malformed hop` | a required claim is missing or unusable |

`evidence_ref` addresses what a reader should fetch: `sha256:<digest of the signed root
delegation statement>` for a verified root, `sha256:<digest of the hop's compact JWS>` everywhere
else there is a token. An unsigned hop has none, because there is no evidence.

**Corrected 28 Aug 2026.** That sentence was aspirational until this pass: every capture
surface wrote the reference from the first record and none of them wrote the blob, so the
reference pointed into an empty store. The consequence was not cosmetic — it meant a hop's
signature was checked exactly once, at capture, by behalf's own code, and the evidence was
then discarded, leaving a receipt that asserts `verified` as the only record of the check.
`capture.RetainHopTokens` now writes each signed hop's compact JWS into the customer-held CAS
at the address the receipt already names (`cas.Digest` and `ParHash` are the same function
over the same bytes, so no receipt byte changes). `TestEveryEvidenceRefResolves` and
`TestVerifiedAttributionOnRecordedData` pin it, the second over a real recorded run.

This is the prerequisite for teaching the offline verifier to check chains: an export cannot
carry token material the writer never kept.

The receipt-level rollup is the weakest hop, ordered `broken` < `asserted` < `verified` (§8).

**`asserted` is not a soft failure.** A hop with no signature is `asserted` because nothing was
checked; a hop with a bad signature is `broken` because something was checked and failed. Every
status in the table above has a test for every reason in `internal/aat/aat_test.go`, because that
distinction is the product.

## 7. Attenuation

Comparison is internal/why's comparator (`why.CompareGrants`, stamped
`behalf.sh/attenuation/v1`) over the raw RFC 9396 `authorization_details` — the same code
`behalf why` runs at read time, so mint-time, capture-time and read-time comparisons cannot
disagree. There is no second comparator and no bespoke normalization layer.

**Two grant vocabularies, one comparator, routed by `type`.** The comparator's own
doc comment used to say flatly that this comparison *is* the draft's, adopted rather than
reinvented. Against the vendored text that was the largest error this document had, and it is
half-corrected as of this pass:

- An `authorization_details` entry of `type: "attenuating_agent_token"` on either side is
  compared by **the draft's own rules** — §4.5's subsumption matrix over the `tools` map, as §7
  steps 4n–4p apply it. That is `internal/why/aat_i4.go`, and it is new. §8 I4 and §9.1 record
  what it covers and where it reads the draft conservatively.
- Every other grant shape — behalf's `type` + `actions` + `privileges[].limit`, the proprietary-role-style
  vocabularies, anything else — keeps **behalf's own six rules**, unchanged. The draft does not
  define those shapes, so there is nothing to adopt for them.

Both comparisons always run and the stricter answer wins. A side carrying none of the other's
vocabulary is a *known-empty* side, not an uncomparable one — the hop's `authorization_details`
were read in full, so a child that keeps its parent's capability entry byte for byte and bolts on
a grant of behalf's own shape the parent never delegated is `broadened`, not `unchanged`
(`TestI4DoesNotHideTheOtherVocabulary`; the guard in `compareV1` that answers `unknown` for a hop
with no grants at all is about a hop that says nothing, which is not this case).

The routing is by the RFC 9396 `type` member alone, so no grant behalf has ever minted or
recorded changes classification: that claim is asserted by `TestI4LeavesTheV1ComparatorAlone` and
was checked by regenerating every fixture and conformance vector against both trees.

Outcomes:

- **broadened** → the hop is `broken`. `Mint` also refuses to produce one — as a typed
  `aat.BroadeningError` naming the tool, the argument and both `constraint_type` values when the
  finding came from the draft's rules — so behalf's own minter cannot emit a chain its verifier
  would reject for attenuation. That now holds for draft-shaped grants too, which is the §9.1
  fix; it still holds only for grants the comparator can read at all.
- **unknown** → recorded and flagged, never swallowed, and **the hop is `asserted`** —
  method `caller-asserted: grant not comparable`, `attenuation_flag: unknown`. It used to
  keep whatever status its signature earned, which meant `verified` beside a flag saying the
  comparison had not been made. Nothing failed here and nothing was established, which is exactly
  what `asserted` has always meant in this vocabulary. `Mint` still emits such a grant: an
  uncomparable delegation is a real thing to record, just not a verified one. **The draft's rules
  never produce `unknown`**: §7 answers every draft-shaped pair with permit or DENY, so a
  draft-shaped grant is always classified, and `unknown` remains what it always was — behalf's
  answer for a vocabulary it has no rules for.
- **attenuated / unchanged** → the flag says so.

The frozen `attenuation_flag` enum has no `broadened` value, deliberately: a broadened grant is
not a flag but a break, carried by `status` and `method`. The comparison itself is recomputed
from the raw grants on every read, so a comparator bug never freezes into evidence.

## 8. The six invariants, checked

There are **six**, and the count our documents gave was right. What they *are* was not.

The draft enumerates them in §4 as I1–I6, under the heading "Attenuation Invariants", governed by
one sentence (§4, opening):

> "Every derived token in a chain MUST satisfy all of the following invariants. […]
> enforcement points MUST reject any chain that violates any invariant."

§7 above and [`receipt-schema-v1.md`](receipt-schema-v1.md) §7 all read "the draft's
six invariants" as six *grant-comparison* rules, and §8 of this document previously offered six
`CompareGrants` behaviours as a candidate match. That reading was wrong in structure, not just in
detail. Only **one** of the draft's six (I4) is about comparing grants at all. Two are the
structural token rules this document had filed as "two further invariants […] rather than the
attenuation comparison" — they are I2 and I3, squarely inside the six. One is the signature
trail (I1), one is the `par_hash` linkage (I5), and one is proof of possession (I6), which behalf
does not implement in any form.

### The table

| # | Invariant | Draft § | Our code | Our test | Status |
|---|---|---|---|---|---|
| **I1** | Delegation authority: the child was signed by the parent's holder key | §4.2, §7 step 4b–4c | `internal/aat/verify.go` `verifyHop` (`verifySignature` under `parent.Claims.Cnf.JWK`); `internal/aat/aat.go` `Mint` refuses any other signer | `TestWrongSignerIsBroken`, `TestMintRefusesUnsoundChains`, `TestFullChainVerifies` | **partially implemented** — the property is enforced *cryptographically*, which is strictly stronger than the draft's string check. The `iss` claim carrying it is **absent**, so §7 steps 3k, 4b5 and 4c cannot run. §9.2. |
| **I2** | Depth monotonicity: `+1` per hop, budget may narrow, never widen or be exceeded | §4.3, §7 steps 4d–4g, 4m | `verify.go` `verifyHop` depth switch; `verifyRootHop` pins depth 0; `Mint` derives depth from the parent | `TestDepthInvariants`, `TestRootMustBeDepthZero`, `TestMintRefusesUnsoundChains` | **partially implemented** — all four ordering clauses hold. The fifth, `del_depth <= MAX_DELEGATION_DEPTH` (§4.3, a MUST), has no counterpart: behalf enforces no finite ceiling. §9.4. |
| **I3** | TTL monotonicity: child never outlives parent, and six clauses over `iat`/`exp` | §4.4, §7 steps 4h–4l | `verify.go` `checkExpiry`; `Mint` refuses `exp` above the parent's | `TestExpiryInvariants`, `TestMintRefusesUnsoundChains` | **partially implemented** — `exp <= parent.exp` and `exp > now` hold (the latter only when a capture instant is supplied, deliberately). Every clause involving `iat` is **unimplementable**: there is no `iat` claim. §9.3. |
| **I4** | Capability monotonicity: `tools(child) ⊆ tools(parent)`, closed-world key sets, nine-type constraint subsumption | §4.5, §7 step 4n–4p | `internal/why/aat_i4.go` `compareAAT` + `subsumes` (all nine constraint types); routed by `internal/why/chain.go` `CompareGrantsDetail`; called from `verify.go` `verifyHop` and from `Mint` | `TestI4ToolMonotonicity`, `TestI4ConstraintSubsumption`, `TestI4FailsClosed`, `TestI4MatchesTheDraftsWorkedExample`, `TestI4SubsumptionIsAntisymmetricOnStrictNarrowings`, `TestI4ViolationNamesTheConstraint`, `TestI4LeavesTheV1ComparatorAlone`, `TestDraftShapedBroadeningIsBroken`, `TestDraftShapedNarrowingVerifies` | **implemented for draft-shaped grants** — the tool-subset rule, the closed-world key-set rule, all nine constraint types with their cross-type matrix, `all`'s backtracking one-to-one clause matcher and `any`'s clause rule. behalf's own grant shape keeps `CompareGrants`'s v1 rules, which the draft does not define. The conservative readings and the pairs left un-enumerated by the draft are listed in §9.1. |
| **I5** | Cryptographic linkage: `par_hash` binds the child to one parent token instance | §4.6, §6 step 7, §7 step 4q | `internal/aat/aat.go` `ParHash`; checked in `verify.go` `verifyHop`; sentinel pinned in `verifyRootHop` | `TestReparentedHopIsBroken`, `TestChainRoundTrip` | **implemented, divergent value** — the invariant holds, more tightly than required. The encoding and preimage are wire-incompatible with the draft in three ways. §3, §9.5. |
| **I6** | Proof of possession: the presenter proves control of the leaf's `cnf.jwk` | §4.7, §5, §7 step 7 | *(none)* | *(none)* | **not applicable to v1** — behalf records, it does not enforce; there is no invocation to bind and no denial to make. The consequence is real and stated in §9.6. |

### What the offline verifier checks (ENG-38)

The table above is the *Go* implementation: what behalf's own tooling establishes at capture
and recomputes at read time. Since ENG-38 there is a second implementation, in
`verifier/src/aat.rs`, that shares no code with it and runs against an export alone.

| # | Offline (Rust) | Note |
|---|---|---|
| **I1** | **checked** | Signature under the parent's `cnf.jwk`; root self-signature. `EdDSA` only, so `none` cannot reach a key. |
| **I2** | **checked** | All four ordering clauses. The draft's `MAX_DELEGATION_DEPTH` ceiling is still unenforced, as Go-side. |
| **I3** | **checked** | `exp <= parent.exp` only. Wall-clock expiry is deliberately not applied: the record states what was true at capture, and re-reading it years later must not turn a then-valid token into a finding. Same choice as Go. |
| **I4** | **not checked** | The §4.5 subsumption matrix is nine constraint types with a backtracking clause matcher, and `internal/why/aat_i4.go` is the only implementation. A second one that was subtly *looser* would be worse than none: it would stay silent exactly where the first reports a break. Reported as not evaluated, on every run, including clean ones. |
| **I5** | **checked** | `par_hash` recomputed over the parent's compact JWS; the depth-0 sentinel pinned. |
| **I6** | **n/a** | Unchanged: behalf records, it does not enforce. |

Two consequences worth stating plainly.

**The offline verifier emits findings, not hop verdicts.** A verdict in behalf's vocabulary
is a claim about every invariant, and this implementation does not evaluate I4, so it is not
entitled to one. Silence from it means "the invariants this implementation checks all held" —
which is why the CLI prints the un-checked list on success, where it is inconvenient, rather
than only here.

**The identity root is out of scope and stays out.** The offline check covers the root's
*structure* — self-signature, depth 0, the no-parent sentinel — and says nothing about whose
device key it is. That needs an `id_token` checked against the IdP's published keys, which is
a network call or a pinned JWKS in the export, and is its own decision.

The corpus pins both directions: `testdata/vectors/exports/tampered_delegation_*` are
Go-minted and Rust-verified, and `TestGoAndRustAgreeTheForgedChainsAreBroken` asserts the Go
verifier calls the same bytes broken for the same reason. A corpus where the two
implementations disagreed about what is broken would launder a divergence as agreement.

### Beyond the six

The draft's §7 carries obligations that are not invariants but are MUSTs, and the honest status
of each:

| Requirement | Draft § | Status |
|---|---|---|
| Reject `alg: none`; algorithm allowlist consistent with the key | §7 steps 3a/4a, §8.13 | **implemented** — `verifySignature` accepts `EdDSA` and nothing else; `none` cannot reach a key. |
| Signature verified before claims are parsed | §7 closing note | **not implemented** — `ParseChain` decodes and unmarshals every payload before `Verify` runs. A parser-DoS hardening rule, not an authority rule. §9.4. |
| `jti` present in every token | §3.2, §7 steps 3j, 4b1 | **implemented** — as of this pass. `checkRequiredClaims`, `TestHopWithoutJTIIsMalformed`. §9.7. |
| `jti` unique within the presented chain (cycle detection) | §7 step 2c | **not implemented** — though a true *instance* cycle is structurally impossible here: a repeated token would carry the wrong `del_depth` and the wrong `par_hash`. Two distinct tokens sharing a `jti` are not caught. §9.4. |
| `MAX_TOKEN_SIZE`, `MAX_STACK_SIZE`, `MAX_CONSTRAINT_DEPTH` finite | §4.3.1, §3.4, §7 step 2 | **not implemented** — no limits of any kind. §9.4. |
| `len(chain) == leaf.del_depth + 1` | §7 step 5 | **implemented transitively** — depth 0 at the root plus a strict `+1` per hop forces it. |
| Leaf constraint evaluation against the actual invocation | §7 step 6b | **not applicable to v1** — behalf does not gate invocations. `why.CheckScope` is behalf's own read-time excess *finding*, not the draft's enforcement step, and it says so. |
| `cnf.jwk` carries no private key parameter | §7 steps 3l, 4b2 | **implemented incidentally** — `ed25519JWK` accepts only `{kty, crv, x}`; a `d` member is ignored, never used, and never re-emitted. |

## 9. Divergences

Everything below is a place where behalf and the draft do not agree. Most of it is not fixed, for
the reason stated in each entry: changing verification semantics to match a document no working
group has adopted is a decision for a human (the bet is on the format, not on a working
group), and the pass that wrote this section existed to make the divergences *visible*, not to
close them.

Two are closed: **§9.7** (a signed hop with no `jti` read as `verified`) and **§9.1** (I4 was not
implemented at all). Both were fixed rather than flagged for the same reason — neither is a
semantics change adopted from an unadopted document. §9.7 contradicted behalf's own frozen schema
and its own minter; §9.1 was behalf recording `verified` over a chain it had not compared, which
contradicts what `verified` means here regardless of which draft is right.

**§9.8** is neither a divergence nor a fix but a decision, taken by a human on 27 Aug 2026 and
recorded here because it is the same sentence in a third form: an uncomparable grant no longer
keeps a hop `verified`. All three closures say one thing — the word `verified` is reserved for
invariants that were actually checked.

### 9.1 Fixed here: I4 is now the draft's comparison for draft-shaped grants

**The gap that was here.** The draft profiles RFC 9396 with a single entry of
`type: "attenuating_agent_token"` carrying a `tools` map — tool name → argument name → a typed
constraint object:

```json
{"type":"attenuating_agent_token",
 "tools":{"read_file":{"path":{"constraint_type":"one_of","values":["/data/q3.pdf"]}}}}
```

behalf compared a different object — `type` + `actions` + `privileges[].limit` — by different
rules, and not one of §4.5's nine constraint types existed in the code. Fed a genuinely
draft-conforming chain, the comparator found no `actions` array, answered `unknown`, and
`verifyHop` let the hop keep the status its signature earned. A child that added a tool its
parent never granted — which §7 step 4p1 says DENY — was recorded **`verified`**, with
`attenuation_flag: unknown`, and `Mint` would emit that chain rather than refuse it. That was
the overclaim this product exists to avoid, reachable by any client following the draft behalf
cites.

**What is implemented now.** `internal/why/aat_i4.go` implements §7 steps 4n–4p over the
capability entry: the tool-subset rule (4p1), the closed-world key-set rule (4p2/4p3), and
per-argument subsumption (4p4) across **all nine** constraint types §3.4 defines —
`exact`, `range`, `one_of`, `not_one_of`, `contains`, `subset`, `wildcard`, `all`, `any` —
including the cross-type rules, `all`'s backtracking one-to-one clause matcher (§4.5's own
pseudocode) and `any`'s per-clause rule. `CompareGrantsDetail` routes to it on the RFC 9396
`type` member alone; behalf's own grant shapes keep the v1 rules untouched. §3.6.1's root token
and §3.6.2's derived token, run against each other, compare as an attenuation
(`TestI4MatchesTheDraftsWorkedExample`), and §4.5's worked `any` example is a test case in both
its permitted and its refused form.

`Mint` refuses what the verifier would reject, as a typed `aat.BroadeningError` carrying the
tool, the argument key and both `constraint_type` values. §7's promise now holds for
draft-shaped grants.

**What is not implemented, named rather than omitted.**

| Not implemented | Draft § | Why |
|---|---|---|
| Registered **extension** constraint types | §3.5 | behalf implements none. Encountering one **denies**, which is what §3.5.2 requires of an enforcement point that has not implemented a registered type — conforming behaviour, not a gap, but it means no extension-typed chain will ever verify here. |
| The `check` predicate against a live invocation | §3.4, §7 step 6b | behalf does not gate invocations (§9.6, I6). Only `range`'s predicate exists, and only because the derived-`exact`-under-parent-`range` cross-type rule needs it. |
| `MAX_CONSTRAINT_DEPTH` as a **token rejection** step | §7 steps 3n, 4o | The comparator bounds its *own* recursion at the RECOMMENDED 32 and fails closed past it, so a deep tree is denied rather than crashing — but behalf still does not reject a token for depth as such. Grouped with the other resource limits in §9.4. |

**Where the draft was read conservatively, and why.** §3.5.1 requires a subsumption procedure to
be sound — never true for a non-subsuming pair — and permits it to be conservative. Each of these
is a deliberate false-negative:

1. **Cross-type pairs the draft does not enumerate are rejected**, per §4.5's closing sentence
   ("Any (parent constraint type, derived constraint type) pair not explicitly permitted by the
   above rules … MUST be rejected"). Several of those are semantic narrowings a human would
   accept: a derived `one_of(["/a"])` under a parent `exact("/a")`, a derived `one_of` of numbers
   under a parent `range` that contains all of them, a derived `subset` under a parent `one_of`.
   All are refused. This is the literal reading *and* the conservative one, so it is not a
   judgement call — but a conforming issuer can write a narrowing behalf will call a broadening,
   and that is worth knowing before the first interop test.
2. **`range` inclusivity is compared only at an equal bound.** §4.5 says "a derived
   `min_inclusive: false` is valid when the parent has `min_inclusive: true` **at the same min
   value**" — the sentence is scoped, and it is silent about a bound that strictly moves. Read as
   a blanket rule it would reject `min: 5, inclusive` under `min: 0, exclusive`, which is
   provably a narrowing (`[5,∞) ⊂ (0,∞)`). behalf accepts it: at an equal bound inclusivity may
   only tighten, and past it the bound itself decides. The alternative reading is *stricter*, not
   safer, so soundness is not at stake either way.
3. **An `any` with no parent clauses accepts nothing derived.** The draft requires the *derived*
   `any` to carry at least one clause and says nothing about an empty parent. It falls out as a
   refusal: no derived clause can be matched.
4. **Duplicate argument keys are malformed, not just duplicate tool identifiers.** §3.3.1 makes
   only duplicate *tool* identifiers malformed. behalf extends the same refusal to argument keys
   inside a constraint map, because JSON last-key-wins is exactly the divergence between
   implementations that §3.4's "two independent implementations MUST produce identical results"
   exists to prevent. Stricter than the letter of the draft.
5. **Fail-closed lands on `broadened`.** The draft has two outcomes, permit and DENY; behalf's
   frozen vocabulary has three words, and `broadened` is the one that makes a hop `broken`. So a
   malformed `tools` map, an unrecognised `constraint_type` (§3.4's fail-closed rule), an
   unimplemented extension type, and a constraint tree past the depth or search budget are all
   recorded as `broadened` with a reason that says otherwise. The word overclaims slightly; the
   alternative — routing them to `unknown` — would leave the hop `verified`, which is the bug
   this section used to describe.

**A notational trap for anyone reimplementing.** §4.5 and §7 step 4p4 write the relation as
`subsumes(derived, parent)` — "the child's constraint subsumes the parent's". §3.5.1 writes the
same relation with the arguments reversed, `subsumes(C_parent, C_child)`. The meaning is
identical in both places ("the child accepts nothing the parent would have rejected"); only the
argument order differs. behalf follows §4.5's order.

**What this did not settle, and §9.8 since has.** Closing I4 left `unknown` keeping a hop
`verified` — the explicit rule, and not that pass's to revisit. It has since been revisited and
reversed: an uncomparable grant now holds its hop at `asserted`. §9.8 records the decision
and why closing I4 is what made it safe to take.

### 9.2 `iss` is absent (I1)

The draft REQUIRES `iss` in every token: a URI at the root, and a JWK Thumbprint URI
(`urn:ietf:params:oauth:jwk-thumbprint:sha-256:<thumbprint>`, RFC 9278) of the signing key in
every derived token. behalf has no `iss` claim; the signer's thumbprint travels in the JWS
protected header's `kid` instead.

behalf's check is the stronger one — it verifies the signature under the parent's confirmed key
rather than comparing a string a delegating party wrote. But a conforming enforcement point would
DENY every behalf token at §7 step 4b5 for the missing claim, and behalf cannot verify a
conforming chain's I1 by the draft's own method. Interoperability is one-way broken in both
directions.

### 9.3 `iat` is absent, so token lifetime is unbounded (I3)

`iat` is REQUIRED (§3.2). behalf has no such claim, so four of I3's six clauses cannot be
evaluated: `child.iat >= parent.iat` (the draft's clock-manipulation and chain-forgery detector),
`iat <= now + MAX_IAT_SKEW`, `exp > iat`, and `exp <= iat + MAX_TOKEN_LIFETIME`.

The last one has a consequence worth naming: the draft caps a token's life at
`MAX_TOKEN_LIFETIME` (90 days RECOMMENDED as an *upper bound*, §4.4). behalf caps nothing. A root
minted with `exp` a decade out is accepted, and every hop below it inherits that ceiling legally.
Nothing in `internal/aat` would call that chain anything but `verified`.

### 9.4 Resource limits and structural hygiene, all absent

`MAX_DELEGATION_DEPTH`, `MAX_TOKEN_SIZE` (64 KiB RECOMMENDED), `MAX_STACK_SIZE` (256 KiB) and
`MAX_CONSTRAINT_DEPTH` (32) are each an explicit MUST-enforce-a-finite-value. behalf enforces
none: a chain of ten thousand hops, or a single 40 MB token, verifies on its merits. So does the
verify-before-parse ordering rule, and `jti` uniqueness within a chain.

These are denial-of-service and hygiene rules rather than authority rules — none of them lets a
chain claim authority it was not given — which is why they are grouped and flagged rather than
fixed one by one. Picking the constants is a product decision.

### 9.5 `par_hash` value (I5)

Covered in §3: hex rather than base64url-nopad, three JWS segments rather than the two-segment
signing input, and an all-zero sentinel at the root where the draft requires absence. Stricter
than the draft, fully wire-incompatible with it, and — per §3 — buying nothing the draft's own
definition did not already provide.

### 9.6 No proof of possession (I6), and what `verified` therefore means

The draft's I6 requires the presenter to sign a PoP JWT under the leaf's `cnf.jwk`, binding
`aat_id` to the leaf's `jti`, `aat_tool` to the tool, and `hta` to the JCS-canonical argument map
(§5, §7 step 7). behalf implements none of it, and this is the one status in the table that is
**not applicable to v1** rather than missing: behalf is a recorder at a proxy, not an enforcement
point. It never decides whether a call proceeds, so there is no invocation to bind a proof to and
no denial to withhold.

The consequence must be stated rather than left implicit, because it bounds what behalf's
strongest word means. A chain lifted verbatim out of one receipt and presented alongside a
completely different call verifies identically. **`verified` means "these tokens form a sound
delegation chain rooted in this human's device key". It has never meant "the holder of the leaf
key authorised this specific invocation".** The draft's I6 is the invariant that would carry the
second claim, and behalf does not make that claim.

### 9.7 Fixed here: a signed hop with no `jti` read as `verified`

The one clear bug. `Mint` has always refused to produce a hop without `jti`; the frozen schema
marks it R\*; the draft REQUIRES it and DENIES without it (§3.2, §7 steps 3j/4b1). `Verify`
checked none of that, so a hand-built token with the claim dropped — cryptographically
impeccable, correctly linked, correctly attenuated — was reported `verified`. It cannot be joined
to a revocation window, which is the whole reason the claim is carried.

Now `broken` with `broken: malformed hop`, at every depth. `internal/aat/verify.go`
`checkRequiredClaims`, pinned by `TestHopWithoutJTIIsMalformed` — which also pins the boundary
that matters: an *unsigned* hop missing `jti` stays `asserted`, because nothing was checked and
so nothing broke.

This was fixed rather than flagged because it contradicts behalf's own frozen schema and its own
minter, independently of the draft. It is not a semantics change adopted from an unadopted
document.

### 9.8 Decided: an uncomparable grant no longer keeps a hop `verified`

**Decision (27 Aug 2026).** A hop whose grant the comparator has no rules for is
`asserted`, with method `caller-asserted: grant not comparable` and `attenuation_flag: unknown`.
It was `verified`. `Mint` still emits such a grant, and the comparator's own answer is unchanged:
`unknown` is still what `why.CompareGrants` returns for a proprietary app-role grant or a wildcard.
What changed is what `internal/aat` does with that answer.

The rule survives intact — recorded and flagged, never swallowed. The word that had to go was
`verified`, which asserts that every invariant was checked. On these hops I4 was not checked, and
a status is not the place to round that up. `asserted` already carries exactly this meaning
elsewhere in the vocabulary: nothing failed, nothing was established — the same word a hop gets
when its parent does not verify, or when there is no login material to check the root against. It is not `broken`, because no invariant failed; a grant behalf cannot read is a fact about
behalf's rules, not a finding about the delegation.

**Closing I4 is what made this safe to take, and it is worth recording that it argued the
*opposite* way to what this section used to say.** `unknown` had been doing two incompatible jobs.
One honest: a vocabulary behalf has no rules for, where `unknown` is the true answer and flagging
it is right. One not: a **draft-conforming grant behalf simply had not implemented**, where
`unknown` meant "not compared" and sat next to `verified` on a chain the draft says DENY. The
second job is gone — §7 answers every draft-shaped pair with permit or DENY, so the I4 path never
returns `unknown`. So this decision reclassifies only the honest population, and it reclassifies
it as what it always was.

**Migration: none.** The cost that made this a human's call is that it is retroactive over the
meaning of records already written. Checked before taking it: no fixture, conformance vector or
recorded chain in this repository carries `attenuation_flag: unknown`, so no existing record
changes status. The population is entirely future.

**What this costs.** A cross-IdP chain whose vocabularies behalf cannot compare will roll up
`asserted` rather than `verified`, and the rollup is the weakest hop (schema §8). That is the
intended effect — the alternative was a `verified` that meant less than it said — but it does mean
the honest answer for a proprietary-role chain is now visibly weaker on the dashboard. The way to
raise it is to give the comparator rules for that vocabulary, which is the work the alternative design describes and v1 deliberately does not do.

`TestUnknownAttenuationIsFlaggedNeverSwallowed` pins both halves: the flag and reason are still
recorded, and the hop is `asserted`.

## 10. behalf's extensions, restated against the vendored text

The upstream-submission obligation is that anything of behalf's is visible as behalf's. Checked against -01, the
list changes:

| Field | Previously described as | Actually |
|---|---|---|
| `jti` | behalf extension, to be submitted upstream | **REQUIRED draft claim** (§3.2). Not behalf's. §2. |
| `root_principal_binding` | behalf extension | **Confirmed behalf's.** Nothing in the draft binds a chain root to a human; §3.2 states the deliberate `sub` omission and stops there. Genuinely the gap. |
| `credential` | behalf extension | **Confirmed behalf's.** No draft counterpart. |
| `trigger` | behalf extension | **Confirmed behalf's.** No draft counterpart. |
| `intent` inside a grant | behalf extension | **Confirmed behalf's.** No draft counterpart. |
| `sh.behalf/*` grant types | — | **behalf's.** The draft registers `attenuating_agent_token` (§10.2) and behalf does not *mint* it — but as of this pass behalf does **verify** it, by the draft's own §4.5 rules. §9.1. |
| `par_hash` value | behalf filling a gap | **A divergence, not an extension.** §3. |

So the upstream submission is **one** extension, not two: the root principal binding. The per-hop
`jti` half of that commitment is already satisfied by the draft itself, and the three neighbouring
documents that still describe it as behalf's — `receipt-schema-v1.md` §7,
`receipt-schema-v1.schema.json` — should be corrected by a human, deliberately, rather than
swept in a verification pass.
