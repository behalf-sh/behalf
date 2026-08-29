//! Offline verification of delegation chains (ENG-38).
//!
//! This is the half that makes behalf different from a transparency log. Every
//! other module here establishes *record integrity* — nothing was modified,
//! dropped, reordered or back-dated. None of it says anything about **who
//! authorised what**, and until this module that property was established
//! exactly once, at capture, by behalf's own Go code, with the evidence then
//! discarded.
//!
//! # What this module checks, and what it deliberately does not
//!
//! The vendored AAT draft states six attenuation invariants (see
//! `docs/aat-profile-v1.md` §8). This implementation covers four of them plus
//! the structural root predicate:
//!
//! - **I1** — delegation authority: each hop's token verifies under the key its
//!   parent confirms in `cnf.jwk`. The root is self-signed under the key it
//!   confirms.
//! - **I2** — depth monotonicity: `del_depth` increments by exactly one, the
//!   budget never widens, and depth never exceeds it.
//! - **I3** — TTL monotonicity: a hop never outlives its parent.
//! - **I5** — cryptographic linkage: `par_hash` is SHA-256 over the parent's
//!   compact JWS, and depth 0 carries the all-zero no-parent sentinel.
//!
//! **I4 (capability monotonicity) is not evaluated here, and this module never
//! claims it was.** The draft's §4.5 subsumption matrix is nine constraint
//! types with a backtracking clause matcher; the Go implementation in
//! `internal/why/aat_i4.go` is the only one. A second implementation that was
//! subtly *looser* would be worse than none — it would stay silent exactly
//! where the Go side reports a break — so this verifier reports I4 as
//! **not evaluated** and leaves the word `verified` alone. That is the same
//! discipline D8.7 applies to an uncomparable grant: an invariant that was not
//! checked is not an invariant that held.
//!
//! **I6 (proof of possession) is not applicable to v1** — behalf records, it
//! does not enforce, so there is no invocation to bind.
//!
//! **The identity root is out of scope.** Verifying that the depth-0 hop
//! belongs to a particular human means checking an OIDC `id_token` against the
//! IdP's published keys, which needs either a network call or a pinned JWKS in
//! the export. This module checks the root's *structure* — self-signature,
//! depth, sentinel — and says nothing about whose device key it is.
//!
//! # Why findings rather than a verdict
//!
//! A hop verdict in behalf's vocabulary (`verified` / `asserted` / `broken`) is
//! a claim about every invariant. This module cannot make that claim, because
//! it does not evaluate I4. So it emits *findings*: a broken invariant is a
//! finding, and silence means "the invariants this implementation checks all
//! held". That is a genuine second opinion on four of the six, and it is
//! stated as exactly that rather than dressed up as a full verdict.

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::Deserialize;

use crate::keys::decode_verifying_key;
use crate::util::{hex_encode, sha256};

/// `par_hash` at depth 0: the explicit no-parent sentinel. Mirrors
/// `oidclogin.RootParHash`; a chain root naming a parent is a finding.
pub const ROOT_PAR_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// The only JWS algorithm v1 mints or accepts (Q69). `none` cannot reach a key.
pub const ALG: &str = "EdDSA";

/// Which invariant a finding is about. The names match
/// `docs/aat-profile-v1.md` §8 so a finding can be traced to the draft clause
/// it violates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Invariant {
    /// I1 — the child was not signed by the parent's confirmed key.
    Authority,
    /// I2 — depth did not increment, or the budget widened or was exceeded.
    Depth,
    /// I3 — the hop outlives its parent.
    Expiry,
    /// I5 — `par_hash` does not name the parent token instance.
    Linkage,
    /// The token is not a well-formed EdDSA compact JWS, or a required claim
    /// is absent. Malformed rather than broken-by-attenuation.
    Malformed,
    /// The receipt's embedded claim set disagrees with the signed token.
    Disagreement,
}

impl Invariant {
    /// The stable `invariant=` token emitted on stderr.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Invariant::Authority => "I1-authority",
            Invariant::Depth => "I2-depth",
            Invariant::Expiry => "I3-expiry",
            Invariant::Linkage => "I5-linkage",
            Invariant::Malformed => "malformed",
            Invariant::Disagreement => "receipt-disagrees-with-token",
        }
    }
}

impl std::fmt::Display for Invariant {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One delegation finding, anchored to the leaf and hop it was found on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainFinding {
    /// Leaf index within the export.
    pub leaf_index: u64,
    /// Position of the offending hop in the chain (0 is the root).
    pub hop: usize,
    pub invariant: Invariant,
    pub human: String,
}

/// What a run's chains could and could not be checked against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ChainReport {
    /// Findings, in leaf then hop order.
    pub findings: Vec<ChainFinding>,
    /// Hops whose signature was checked.
    pub hops_checked: u64,
    /// Hops carrying no `evidence_ref` — caller-asserted, nothing to check.
    /// Not a finding: an agent presenting an unsigned claim is the normal
    /// day-zero state (Q21), not an attack.
    pub hops_unsigned: u64,
    /// Hops whose `evidence_ref` named a token the export does not carry.
    /// Reported so silence is never mistaken for verification.
    pub hops_missing_token: u64,
}

impl ChainReport {
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// True when the export carried nothing to check at all.
    #[must_use]
    pub fn checked_nothing(&self) -> bool {
        self.hops_checked == 0
    }
}

// ---- the receipt's view of a chain ----------------------------------------

#[derive(Deserialize)]
struct ReceiptView {
    authority: Option<AuthorityView>,
}

#[derive(Deserialize)]
struct AuthorityView {
    #[serde(default)]
    chain: Vec<HopView>,
}

#[derive(Deserialize)]
struct HopView {
    #[serde(default)]
    del_depth: i64,
    #[serde(default)]
    del_max_depth: i64,
    #[serde(default)]
    par_hash: String,
    #[serde(default)]
    cnf: CnfView,
    #[serde(default)]
    exp: i64,
    #[serde(default)]
    jti: String,
    #[serde(default)]
    verification: VerificationView,
}

#[derive(Deserialize, Default)]
struct CnfView {
    #[serde(default)]
    jwk: JwkView,
}

#[derive(Deserialize, Default, Clone)]
struct JwkView {
    #[serde(default)]
    kty: String,
    #[serde(default)]
    crv: String,
    #[serde(default)]
    x: String,
}

#[derive(Deserialize, Default)]
struct VerificationView {
    #[serde(default)]
    evidence_ref: String,
}

/// The claim set as carried inside a signed token. Only the members the
/// invariants are stated over are named; everything else in the payload is
/// ignored, which is what lets the claim set grow without breaking readers.
#[derive(Deserialize)]
struct TokenClaims {
    #[serde(default)]
    del_depth: i64,
    #[serde(default)]
    del_max_depth: i64,
    #[serde(default)]
    par_hash: String,
    #[serde(default)]
    cnf: CnfView,
    #[serde(default)]
    exp: i64,
    #[serde(default)]
    jti: String,
}

#[derive(Deserialize)]
struct JwsHeader {
    alg: String,
}

/// One hop as this module reasons about it: the signed token, the claims it
/// carries, and the key it confirms.
struct Hop {
    jws: String,
    claims: TokenClaims,
    key: VerifyingKey,
}

/// Check every delegation chain carried by the export's leaves.
///
/// `leaves` are `(leaf_index, parsed_payload)`; `tokens` is the header's token
/// section, keyed by `evidence_ref`. Callers have already checked that each
/// token digests to the key it sits under.
///
/// The payload arrives parsed rather than as bytes on purpose. Its exact byte
/// span has already been through PAE and the emitter signature in the leaf
/// content step — that is where the span rule is load-bearing. Here the
/// receipt is only being *read*, so there is no signature to invalidate and
/// nothing is gained by re-scanning the span.
#[must_use]
pub fn check_chains(
    leaves: &[(u64, &serde_json::Value)],
    tokens: &HashMap<String, String>,
) -> ChainReport {
    let mut report = ChainReport::default();
    for (leaf_index, payload) in leaves {
        check_one_chain(*leaf_index, payload, tokens, &mut report);
    }
    report
}

fn check_one_chain(
    leaf_index: u64,
    payload: &serde_json::Value,
    tokens: &HashMap<String, String>,
    report: &mut ChainReport,
) {
    let view: ReceiptView = match ReceiptView::deserialize(payload) {
        Ok(v) => v,
        // A payload that does not parse as a receipt is not this module's
        // finding to make: the leaf signature check already covers it.
        Err(_) => return,
    };
    let Some(authority) = view.authority else {
        return;
    };

    // Resolve each hop to its signed token before any invariant is stated over
    // it, so an invariant is never evaluated against claims nobody signed.
    let mut hops: Vec<Option<Hop>> = Vec::with_capacity(authority.chain.len());
    for (i, hv) in authority.chain.iter().enumerate() {
        if hv.verification.evidence_ref.is_empty() {
            report.hops_unsigned += 1;
            hops.push(None);
            continue;
        }
        // A hop's evidence_ref names its token — except at depth 0, where a
        // *verified* root's evidence is the signed login statement the OIDC
        // checks ran against, not the hop token. The root's token is reached
        // the other way: `par_hash` is defined as SHA-256 over the parent's
        // compact JWS, so the hop above already names this one's address.
        let by_child_par_hash = || {
            let next = authority.chain.get(i + 1)?;
            (next.par_hash != ROOT_PAR_HASH && !next.par_hash.is_empty())
                .then(|| tokens.get(&format!("sha256:{}", next.par_hash)))?
        };
        let Some(jws) = tokens
            .get(&hv.verification.evidence_ref)
            .or_else(by_child_par_hash)
        else {
            report.hops_missing_token += 1;
            hops.push(None);
            continue;
        };
        match parse_token(jws) {
            Ok(hop) => {
                // The receipt embeds a copy of the claim set. If the copy and
                // the signed original disagree, the receipt is misrepresenting
                // its own evidence — report it rather than silently preferring
                // one.
                if let Some(what) = claims_disagree(hv, &hop.claims) {
                    report.findings.push(ChainFinding {
                        leaf_index,
                        hop: i,
                        invariant: Invariant::Disagreement,
                        human: format!(
                            "the receipt's hop {i} states {what}, but the token it points at states otherwise: \
                             the embedded claim set is not the one that was signed"
                        ),
                    });
                }
                report.hops_checked += 1;
                hops.push(Some(hop));
            }
            Err(why) => {
                report.findings.push(ChainFinding {
                    leaf_index,
                    hop: i,
                    invariant: Invariant::Malformed,
                    human: format!("hop {i}: {why}"),
                });
                hops.push(None);
            }
        }
    }

    for (i, hop) in hops.iter().enumerate() {
        let Some(hop) = hop else { continue };
        if i == 0 {
            check_root(leaf_index, hop, report);
        } else if let Some(parent) = hops[i - 1].as_ref() {
            check_hop(leaf_index, i, hop, parent, report);
        }
        // A hop above an unresolvable one is not checked against a parent: it
        // has nothing to be checked against. `hops_missing_token` already says
        // so, and inventing a finding here would blame this hop for its
        // parent's absence.
    }
}

/// Depth 0: self-signed under the key it confirms, no parent named.
fn check_root(leaf_index: u64, hop: &Hop, report: &mut ChainReport) {
    let mut push = |invariant, human: String| {
        report.findings.push(ChainFinding {
            leaf_index,
            hop: 0,
            invariant,
            human,
        });
    };
    if hop.claims.del_depth != 0 {
        push(
            Invariant::Depth,
            format!(
                "the first hop of the chain carries del_depth {}: every chain has a depth-0 root",
                hop.claims.del_depth
            ),
        );
    }
    if hop.claims.par_hash != ROOT_PAR_HASH {
        push(
            Invariant::Linkage,
            "the depth-0 hop names a parent: par_hash must be the all-zero no-parent sentinel".to_string(),
        );
    }
    // The root is signed by the very key it confirms. That proves key
    // possession and nothing more — what would make it identity evidence is
    // the OIDC binding, which is not checkable offline and is not claimed here.
    if verify_jws(&hop.jws, &hop.key).is_err() {
        push(
            Invariant::Authority,
            "the root token does not verify under the device key it confirms".to_string(),
        );
    }
}

/// Depth >= 1: the four invariants against the hop beneath it.
fn check_hop(leaf_index: u64, i: usize, hop: &Hop, parent: &Hop, report: &mut ChainReport) {
    let mut push = |invariant, human: String| {
        report.findings.push(ChainFinding {
            leaf_index,
            hop: i,
            invariant,
            human,
        });
    };

    // I1 — signed by the key the parent confirms.
    if verify_jws(&hop.jws, &parent.key).is_err() {
        push(
            Invariant::Authority,
            format!("hop {i}: the token does not verify under the key its parent confirms"),
        );
    }

    // I2 — depth increments, the budget narrows or holds, depth stays inside it.
    if hop.claims.del_depth != parent.claims.del_depth + 1 {
        push(
            Invariant::Depth,
            format!(
                "hop {i}: del_depth {} does not increment its parent's {}",
                hop.claims.del_depth, parent.claims.del_depth
            ),
        );
    }
    if hop.claims.del_max_depth > parent.claims.del_max_depth {
        push(
            Invariant::Depth,
            format!(
                "hop {i}: del_max_depth widens from the parent's {} to {}: a hop cannot raise its own depth budget",
                parent.claims.del_max_depth, hop.claims.del_max_depth
            ),
        );
    }
    if hop.claims.del_depth > hop.claims.del_max_depth {
        push(
            Invariant::Depth,
            format!(
                "hop {i}: del_depth {} exceeds del_max_depth {}",
                hop.claims.del_depth, hop.claims.del_max_depth
            ),
        );
    }

    // I3 — a delegation cannot last longer than the authority it came from.
    //
    // Only the parent comparison is made. "Expired at this instant" is
    // deliberately absent: the record states what was true at capture, and
    // re-reading it years later must not turn a then-valid token into a
    // finding. The Go side makes the same choice and only checks wall-clock
    // expiry when a capture instant is supplied.
    if parent.claims.exp > 0 && hop.claims.exp > parent.claims.exp {
        push(
            Invariant::Expiry,
            format!(
                "hop {i}: exp {} outlives the parent hop's {}: a delegation cannot last longer than the authority it came from",
                hop.claims.exp, parent.claims.exp
            ),
        );
    }

    // I5 — par_hash names this parent token instance, not merely a token
    // with the same claims.
    let want = hex_encode(&sha256(parent.jws.as_bytes()));
    if hop.claims.par_hash != want {
        push(
            Invariant::Linkage,
            format!(
                "hop {i}: par_hash {} does not name the parent hop ({}): this token was minted under a different parent",
                short(&hop.claims.par_hash),
                short(&want)
            ),
        );
    }
}

/// Report which member of the receipt's embedded copy disagrees with the
/// signed token, if any.
fn claims_disagree(view: &HopView, claims: &TokenClaims) -> Option<String> {
    if view.del_depth != claims.del_depth {
        return Some(format!("del_depth {}", view.del_depth));
    }
    if view.del_max_depth != claims.del_max_depth {
        return Some(format!("del_max_depth {}", view.del_max_depth));
    }
    if view.par_hash != claims.par_hash {
        return Some(format!("par_hash {}", short(&view.par_hash)));
    }
    if view.exp != claims.exp {
        return Some(format!("exp {}", view.exp));
    }
    if view.jti != claims.jti {
        return Some(format!("jti {:?}", view.jti));
    }
    if view.cnf.jwk.x != claims.cnf.jwk.x {
        return Some("a different confirmed key".to_string());
    }
    None
}

/// Parse a compact JWS into its claims and the key the hop confirms.
fn parse_token(jws: &str) -> Result<Hop, String> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|p| p.is_empty()) {
        return Err("not a compact JWS: want three non-empty dot-separated segments".to_string());
    }
    let protected = URL_SAFE_NO_PAD
        .decode(parts[0])
        .map_err(|_| "protected header is not base64url".to_string())?;
    let header: JwsHeader = serde_json::from_slice(&protected)
        .map_err(|_| "protected header is not JSON".to_string())?;
    if header.alg != ALG {
        // `none` cannot reach a key, and neither can anything else: the
        // allowlist is one algorithm long.
        return Err(format!(
            "alg {:?} is not {ALG}: v1 mints and accepts Ed25519 only",
            header.alg
        ));
    }
    let payload = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|_| "payload is not base64url".to_string())?;
    let claims: TokenClaims =
        serde_json::from_slice(&payload).map_err(|e| format!("payload is not a claim set: {e}"))?;

    // Required claims. `jti` is REQUIRED by the draft (§3.2) and by behalf's
    // own frozen schema, and it is the other half of the revocation-window
    // join: a hop with no token id cannot be joined to a window at all.
    if claims.jti.is_empty() {
        return Err("the hop carries no jti: the per-hop token id is required".to_string());
    }
    if claims.exp <= 0 {
        return Err("the hop carries no exp: per-hop expiry is required".to_string());
    }
    if claims.cnf.jwk.kty != "OKP" || claims.cnf.jwk.crv != "Ed25519" {
        return Err(format!(
            "cnf.jwk is {:?}/{:?}: only Ed25519 OKP keys are in scope",
            claims.cnf.jwk.kty, claims.cnf.jwk.crv
        ));
    }
    let key = decode_verifying_key(&claims.cnf.jwk.x).map_err(|e| e.to_string())?;

    Ok(Hop {
        jws: jws.to_string(),
        claims,
        key,
    })
}

/// Verify a compact JWS's signature over its own `protected.payload` signing
/// input, under `key`.
fn verify_jws(jws: &str, key: &VerifyingKey) -> Result<(), String> {
    let parts: Vec<&str> = jws.split('.').collect();
    if parts.len() != 3 {
        return Err("not a compact JWS".to_string());
    }
    let sig_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| "signature is not base64url".to_string())?;
    let arr: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|v: Vec<u8>| format!("signature is {} bytes, want 64", v.len()))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    key.verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&arr))
        .map_err(|_| "signature does not verify under the key".to_string())
}

fn short(hex_digest: &str) -> String {
    if hex_digest.len() <= 12 {
        return hex_digest.to_string();
    }
    format!("{}…", &hex_digest[..12])
}
