package aat

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/why"
)

// Verification (Q12, Q17, D5). Three states, per hop, and the distinction
// between the middle one and the last one is the product:
//
//	verified   something was checked and it held
//	asserted   nothing was checked — the caller said so, and behalf says so
//	broken     something was checked and it failed
//
// A hop that arrives with no signature is `asserted`. It is never `broken`,
// because nothing broke: an agent presenting an unsigned claim is the normal
// day-zero state (Q21), not an attack. And it is never `verified`, because
// nothing was checked — that is Q29's rule, and it is the whole reason the
// middle state exists (D5: naming it `asserted` reads as engineering;
// collapsing it into `broken` reads as FUD).
//
// A hop that arrives with a signature that does not verify, a par_hash that
// does not name its parent, or a grant that widens its parent's IS `broken`.
// Something was checked and it failed.

// The three per-hop states (schema §7, §8).
const (
	StatusVerified = "verified"
	StatusAsserted = "asserted"
	StatusBroken   = "broken"
)

// The method vocabulary. `verification.method` is the frozen schema's only
// free string on a hop besides `evidence_ref`, so it carries the
// machine-readable reason: for a verified hop, which predicate established
// it; for anything else, why it was not established. The values are stable
// and greppable; the human sentence lives in HopResult.Reason, and the
// variable detail behind an attenuation finding is recomputed at read time
// from the raw grants the record already holds (Q11, Q13).
const (
	// MethodRootOIDC is D5's three offline checks at depth 0 (Q17).
	MethodRootOIDC = oidclogin.VerificationMethodRoot // "oidc-nonce-binding"
	// MethodHopJWS is the AAT signature chain plus its invariants (Q17).
	MethodHopJWS = "aat-jws-ed25519"

	// MethodNoSignature is THE caller-asserted case: a hop with no token.
	MethodNoSignature = "caller-asserted: no signature"
	// MethodNoRootMaterial: `behalf login` never ran here, so the root
	// binding cannot be checked and nothing above it can be either (Q21).
	MethodNoRootMaterial = "caller-asserted: no root material"
	// MethodRootDegraded: the customer deleted login evidence, so the root
	// is behalf-attested rather than third-party re-verifiable (Q22).
	MethodRootDegraded = "caller-asserted: root material incomplete"
	// MethodParentUnverified: this hop's own token checks out, but the hop
	// beneath it is not verified, so its authority chains to nothing.
	MethodParentUnverified = "caller-asserted: parent unverified"
	// MethodUncomparableGrant: this hop's own token checks out and its
	// parent's does too, but the two grants are written in a vocabulary the
	// comparator has no rules for, so the delegation was never shown to
	// narrow. `verified` on a hop means every invariant was checked, and I4
	// was not (Q13, D8.7).
	MethodUncomparableGrant = "caller-asserted: grant not comparable"
	// MethodUnsupportedKey: a cnf.jwk v1 cannot verify. Out of scope is
	// asserted, not broken (Q17).
	MethodUnsupportedKey = "caller-asserted: unsupported key type"
	// MethodNotVerifiedAtCapture is the belt-and-braces value for a hop the
	// capture surface embedded without a verification result to go with it.
	// Nothing reaches it today; it exists so that an empty status can never
	// be what a receipt records.
	MethodNotVerifiedAtCapture = "caller-asserted: not verified at capture"

	MethodBrokenSignature   = "broken: signature invalid"
	MethodBrokenParHash     = "broken: par_hash mismatch"
	MethodBrokenDepth       = "broken: depth invariant"
	MethodBrokenExpiry      = "broken: expiry invariant"
	MethodBrokenAttenuation = "broken: attenuation broadened"
	MethodBrokenRoot        = "broken: root predicate failed"
	MethodBrokenMalformed   = "broken: malformed hop"
)

// RootMaterial is the login-time evidence the depth-0 predicate needs,
// gathered once rather than per receipt.
type RootMaterial struct {
	// Report is oidclogin.VerifyRoot's outcome over the customer's state
	// directory — the D5 three checks, run offline against persisted
	// material and reused verbatim here (Q17, Q18). Nil means no usable
	// login: the root hop is asserted and everything above it stays
	// asserted.
	Report *oidclogin.Report
	// Absent explains a nil Report in plain language.
	Absent string
	// At is the instant verification runs — capture time for the proxy.
	// Zero disables the wall-clock freshness check, which is what offline
	// re-verification wants: the record already states what was true at
	// capture, and re-reading it years later must not turn a then-valid
	// token into a finding (the same reasoning as D5's deliberate
	// no-expiry-check on the root).
	At time.Time
}

// LoadRootMaterial runs the D5 root predicate once against stateDir. It
// never touches the network and never fails: a state directory with no
// login is a first-class, expected condition (Q21), reported as absent
// material rather than as an error.
func LoadRootMaterial(stateDir string) RootMaterial {
	if stateDir == "" {
		return RootMaterial{Absent: "no behalf state directory: nothing to check the chain root against"}
	}
	rep, err := oidclogin.VerifyRoot(stateDir)
	switch {
	case errors.Is(err, oidclogin.ErrNoLogin):
		return RootMaterial{Absent: "`behalf login` has not run in this state directory, so the chain root " +
			"carries no OIDC binding to check (Q21)"}
	case err != nil:
		return RootMaterial{Absent: fmt.Sprintf("the login material could not be read: %v", err)}
	}
	return RootMaterial{Report: rep}
}

// HopResult is one hop's verification outcome. Status, Method and
// EvidenceRef are what the receipt stores (schema §7); Reason and the
// attenuation fields are the read-side detail, surfaced to the operator and
// recomputable from the record.
type HopResult struct {
	Status      string
	Method      string
	EvidenceRef string
	Reason      string

	// Attenuation is this hop's grant compared against its parent's, by
	// internal/why's comparator (Q13). Empty at depth 0, which has no parent
	// to be compared against.
	Attenuation why.Attenuation
	// AttenuationReason is the comparator's explanation for the outcomes
	// that need one — `unknown` above all, which is recorded and flagged,
	// never swallowed, and which keeps the hop out of `verified` (D8.7).
	AttenuationReason string
}

// StoredFlag is the value that goes into the hop's `attenuation_flag`.
//
// The frozen schema's enum is {attenuated, unchanged, unknown}: it has no
// `broadened`, because a broadened grant is not a flag, it is a break — the
// hop's status says `broken` and its method says so. Leaving the flag empty
// there is deliberate; the finding is not lost, and `behalf why` recomputes
// the comparison from the raw grants on every read anyway (Q11).
func (r HopResult) StoredFlag() string {
	switch r.Attenuation {
	case why.AttenuationUnchanged, why.AttenuationAttenuated, why.AttenuationUnknown:
		return string(r.Attenuation)
	default:
		return ""
	}
}

// Verify checks a chain from the root up and returns one result per hop, in
// chain order. It runs entirely offline.
//
// Verification is bottom-up because authority is: a hop can be `verified`
// only if the hop beneath it is. A hop whose own token checks out but whose
// parent does not verify is `asserted`, not `verified` and not `broken` —
// nothing about it failed, and nothing about it was established either. The
// same word covers a hop whose grant the comparator has no rules for: an
// invariant that could not be checked is not an invariant that held (D8.7).
func Verify(chain []Hop, root RootMaterial) []HopResult {
	out := make([]HopResult, len(chain))
	for i := range chain {
		if i == 0 {
			out[0] = verifyRootHop(chain[0], root)
			continue
		}
		out[i] = verifyHop(chain[i], chain[i-1], out[i-1], root)
	}
	return out
}

// Weakest returns the receipt-level rollup: the weakest hop, ordered
// broken < asserted < verified (schema §8, Q12). An empty chain has no
// authority to roll up and is `asserted`.
func Weakest(results []HopResult) string {
	rollup := StatusVerified
	for _, r := range results {
		switch r.Status {
		case StatusBroken:
			return StatusBroken
		case StatusAsserted:
			rollup = StatusAsserted
		}
	}
	if len(results) == 0 {
		return StatusAsserted
	}
	return rollup
}

// verifyRootHop runs the depth-0 predicate: the hop's own self-signature,
// then D5's three offline checks by way of oidclogin.VerifyRoot (Q17).
func verifyRootHop(h Hop, root RootMaterial) HopResult {
	if h.Claims.DelDepth != 0 {
		return broken(MethodBrokenDepth, "",
			fmt.Sprintf("the first hop of a chain carries del_depth %d: every chain has a depth-0 root (Q14)",
				h.Claims.DelDepth))
	}
	if !h.Signed() {
		return asserted(MethodNoSignature, "",
			"the chain root arrived caller-asserted: no signature accompanies it, so nothing here was checked")
	}
	evidence := "sha256:" + ParHash(h.JWS) // the token itself, by digest

	if h.Claims.ParHash != RootParHash {
		return broken(MethodBrokenParHash, evidence,
			"the depth-0 hop names a parent: par_hash must be the all-zero no-parent sentinel")
	}
	pub, ok := publicKey(h.Claims.Cnf.JWK)
	if !ok {
		return asserted(MethodUnsupportedKey, evidence,
			"the root hop confirms a key v1 cannot verify: only Ed25519 OKP keys are in scope (Q17)")
	}
	// The root is self-signed: signed by the device key it confirms. That
	// alone proves only key possession — what makes it identity evidence is
	// the OIDC binding checked below (D5).
	if err := verifySignature(h.JWS, pub, h.Raw); err != nil {
		return broken(MethodBrokenSignature, evidence,
			fmt.Sprintf("the root token does not verify under the device key it confirms: %v", err))
	}
	if res, bad := checkRequiredClaims(h, evidence); bad {
		return res
	}
	if res, bad := checkExpiry(h, nil, root, evidence); bad {
		return res
	}

	if root.Report == nil {
		return asserted(MethodNoRootMaterial, evidence, root.Absent)
	}
	rep := root.Report
	jkt := h.JKT()
	if rep.DeviceJKT != "" && rep.DeviceJKT != jkt {
		return broken(MethodBrokenRoot, evidence, fmt.Sprintf(
			"the chain root confirms key %s, but this login bound device key %s: the chain does not "+
				"root in this human's device", jkt, rep.DeviceJKT))
	}
	if b := h.Claims.RootPrincipalBinding; b != nil {
		if b.Nonce != "" && b.Nonce != jkt {
			return broken(MethodBrokenRoot, evidence, fmt.Sprintf(
				"root_principal_binding.nonce %q is not the thumbprint of the key the hop confirms (%s): "+
					"the D5 binding is nonce == jkt(device_pubkey)", b.Nonce, jkt))
		}
		if b.DeviceJKT != "" && b.DeviceJKT != jkt {
			return broken(MethodBrokenRoot, evidence, fmt.Sprintf(
				"root_principal_binding.device_jkt %q is not the key the hop confirms (%s)", b.DeviceJKT, jkt))
		}
	}

	switch rep.State {
	case oidclogin.StateBroken:
		return broken(MethodBrokenRoot, evidence,
			"the D5 root predicate failed: "+strings.Join(rep.Reasons, "; "))
	case oidclogin.StateDegraded:
		return asserted(MethodRootDegraded, evidence,
			"the D5 root predicate could not run in full: "+strings.Join(rep.Reasons, "; "))
	}
	// Verified. The evidence a reader should fetch is the signed root
	// delegation statement, not the hop token: the statement is what carries
	// the full binding the three checks ran against (Q22).
	if rep.StatementDigest != "" {
		evidence = "sha256:" + rep.StatementDigest
	}
	return HopResult{
		Status:      StatusVerified,
		Method:      MethodRootOIDC,
		EvidenceRef: evidence,
		Reason:      "the IdP signed this ID token, its nonce is jkt(device_pubkey), and the device key signed the root delegation (D5)",
	}
}

// verifyHop runs the hop predicate at depth >= 1: the AAT signature chain
// plus its invariants (Q17), then the attenuation comparison (Q13), then the
// question of what the hop beneath it established.
func verifyHop(h, parent Hop, parentRes HopResult, root RootMaterial) HopResult {
	if !h.Signed() {
		// THE caller-asserted case. An agent claiming to act as the human,
		// with nothing behind the claim.
		return asserted(MethodNoSignature, "",
			"this hop arrived caller-asserted: no signature accompanies it, so nothing here was checked")
	}
	evidence := "sha256:" + ParHash(h.JWS)

	parentPub, ok := publicKey(parent.Claims.Cnf.JWK)
	if !ok {
		return asserted(MethodUnsupportedKey, evidence,
			"the parent hop confirms a key v1 cannot verify: only Ed25519 OKP keys are in scope (Q17)")
	}
	if err := verifySignature(h.JWS, parentPub, h.Raw); err != nil {
		return broken(MethodBrokenSignature, evidence, fmt.Sprintf(
			"the token does not verify under the parent hop's confirmed key %s: %v", parent.JKT(), err))
	}
	if h.JKT() == "" {
		return asserted(MethodUnsupportedKey, evidence,
			"this hop confirms a key v1 cannot verify: only Ed25519 OKP keys are in scope (Q17)")
	}
	if res, bad := checkRequiredClaims(h, evidence); bad {
		return res
	}

	// Depth invariants: increment by one, never widen the budget, never
	// exceed it.
	switch {
	case h.Claims.DelDepth != parent.Claims.DelDepth+1:
		return broken(MethodBrokenDepth, evidence, fmt.Sprintf(
			"del_depth %d does not increment its parent's %d", h.Claims.DelDepth, parent.Claims.DelDepth))
	case h.Claims.DelMaxDepth > parent.Claims.DelMaxDepth:
		return broken(MethodBrokenDepth, evidence, fmt.Sprintf(
			"del_max_depth widens from the parent's %d to %d: a hop cannot raise its own depth budget",
			parent.Claims.DelMaxDepth, h.Claims.DelMaxDepth))
	case h.Claims.DelDepth > h.Claims.DelMaxDepth:
		return broken(MethodBrokenDepth, evidence, fmt.Sprintf(
			"del_depth %d exceeds del_max_depth %d", h.Claims.DelDepth, h.Claims.DelMaxDepth))
	}
	if res, bad := checkExpiry(h, &parent, root, evidence); bad {
		return res
	}

	// The linkage that IS the DAG edge (Q10). It can only be checked against
	// a parent that has a token; past a caller-asserted hop there is nothing
	// for par_hash to name, and the chain cannot be verified above it either
	// way.
	if parent.Signed() {
		if want := ParHash(parent.JWS); h.Claims.ParHash != want {
			return broken(MethodBrokenParHash, evidence, fmt.Sprintf(
				"par_hash %s does not name the parent hop (%s): this token was minted under a different parent",
				short(h.Claims.ParHash), short(want)))
		}
	}

	// Attenuation: the draft's invariants over the raw RFC 9396 grants,
	// through internal/why's comparator (Q13, D8.1).
	att, reason := why.CompareGrants(grantsOf(parent.Claims), grantsOf(h.Claims))
	if att == why.AttenuationBroadened {
		res := broken(MethodBrokenAttenuation, evidence,
			"the grant widens the authority its parent delegated: "+reason)
		res.Attenuation, res.AttenuationReason = att, reason
		return res
	}

	res := HopResult{EvidenceRef: evidence, Attenuation: att, AttenuationReason: reason}
	if parentRes.Status != StatusVerified {
		// Everything here checked out, and it chains to a hop that did not.
		res.Status = StatusAsserted
		res.Method = MethodParentUnverified
		res.Reason = fmt.Sprintf(
			"this hop's own token verifies, but the hop beneath it is %s (%s), so its authority chains to nothing checked",
			parentRes.Status, parentRes.Method)
		return res
	}
	if att == why.AttenuationUnknown {
		// The signature, the depth, the expiry and the linkage all hold, and
		// I4 does not — not because the grant widened, but because nothing
		// here can say whether it did. That is `asserted`: nothing failed and
		// nothing was established (D8.7). The flag still says `unknown` and
		// the reason still says why, so Q13's "recorded and flagged, never
		// swallowed" is unchanged; what changed is that the hop no longer
		// borrows the word `verified` for an invariant nobody checked.
		res.Status = StatusAsserted
		res.Method = MethodUncomparableGrant
		res.Reason = "this hop's own token verifies, but its grant cannot be compared against its parent's, " +
			"so the delegation was never shown to narrow: " + reason
		return res
	}
	res.Status = StatusVerified
	res.Method = MethodHopJWS
	res.Reason = fmt.Sprintf("signed by the parent hop's confirmed key %s, linked by par_hash, within the delegated scope",
		parent.JKT())
	return res
}

// checkRequiredClaims applies the presence rules for claims a signed hop
// cannot be read without and that have no other check to hide inside. `exp`
// is not among them: checkExpiry needs its value anyway and reports its
// absence itself.
//
// Today that is `jti`. A signed hop carrying none is malformed, not merely
// unlabelled. It is REQUIRED by the vendored draft (§3.2; §7 steps 3j and 4b1
// DENY without it) and R* in behalf's own frozen schema
// (receipt-schema-v1.md §7), and Mint has always refused to produce one — so
// a verifier that read it as `verified` was contradicting both specs behalf
// holds. What it would be overclaiming is specific: `jti` is the other half of
// the revocation-window join (Q23), and a hop with no token id cannot be
// joined to a revocation window at all.
//
// Only signed hops reach here. An unsigned hop is `asserted` well before this
// point and is not being checked against anything.
func checkRequiredClaims(h Hop, evidence string) (HopResult, bool) {
	if h.Claims.JTI == "" {
		return broken(MethodBrokenMalformed, evidence,
			"the hop carries no jti: the per-hop token id is required (Q23, schema §7, draft §3.2), "+
				"and a hop without one cannot be joined to a revocation window"), true
	}
	return HopResult{}, false
}

// checkExpiry applies the two expiry rules: a hop never outlives its parent,
// and — only when the caller supplied an instant — a hop is not already
// expired at that instant.
func checkExpiry(h Hop, parent *Hop, root RootMaterial, evidence string) (HopResult, bool) {
	if h.Claims.Exp <= 0 {
		return broken(MethodBrokenMalformed, evidence,
			"the hop carries no exp: per-hop expiry is required, verbatim (Q11, Q23)"), true
	}
	if parent != nil && parent.Claims.Exp > 0 && h.Claims.Exp > parent.Claims.Exp {
		return broken(MethodBrokenExpiry, evidence, fmt.Sprintf(
			"exp %d outlives the parent hop's %d: a delegation cannot last longer than the authority it came from",
			h.Claims.Exp, parent.Claims.Exp)), true
	}
	if !root.At.IsZero() && root.At.Unix() > h.Claims.Exp {
		return broken(MethodBrokenExpiry, evidence, fmt.Sprintf(
			"the token expired at %s, before this crossing at %s",
			time.Unix(h.Claims.Exp, 0).UTC().Format(time.RFC3339), root.At.UTC().Format(time.RFC3339))), true
	}
	return HopResult{}, false
}

func asserted(method, evidence, reason string) HopResult {
	return HopResult{Status: StatusAsserted, Method: method, EvidenceRef: evidence, Reason: reason}
}

func broken(method, evidence, reason string) HopResult {
	return HopResult{Status: StatusBroken, Method: method, EvidenceRef: evidence, Reason: reason}
}

func short(hexDigest string) string {
	if len(hexDigest) <= 12 {
		return hexDigest
	}
	return hexDigest[:12] + "…"
}
