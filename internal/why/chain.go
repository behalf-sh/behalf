package why

import (
	"encoding/json"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// ComparatorVersion stamps every attenuation comparison and scope check this
// package computes. Computed values are recomputable and travel stamped with
// the comparator that produced them, so a comparison bug never freezes into
// evidence (Q11, Q13, schema §1).
const ComparatorVersion = "behalf.sh/attenuation/v1"

// Grant is one RFC 9396 authorization_details object, read out of a hop
// verbatim. Raw keeps the exact stored bytes so nothing is normalized away:
// the fields below are a read-time projection for comparison, never a
// rewrite of the record (Q11).
type Grant struct {
	Type       string      `json:"type"`
	Actions    []string    `json:"actions"`
	Locations  []string    `json:"locations"`
	Datatypes  []string    `json:"datatypes"`
	Identifier string      `json:"identifier"`
	Privileges []Privilege `json:"privileges"`
	// Intent is a named behalf extension on the RFC 9396 object: the
	// human's words for what was delegated ("resolve ticket 4417").
	Intent string `json:"intent"`
	// Tools is the AAT draft's own profile of RFC 9396 (§3.3): a map of tool
	// name to argument constraint set, carried on an entry whose Type is
	// AATGrantType. It is held as raw bytes rather than a decoded map so that
	// a malformed `tools` member cannot abort the projection of the fields
	// beside it — the draft's shape is read, and validated, in aat_i4.go.
	Tools json.RawMessage `json:"tools"`
	Raw   json.RawMessage `json:"-"`
}

// Privilege is one per-operation constraint inside a grant.
type Privilege struct {
	Operation string `json:"operation"`
	Limit     *Limit `json:"limit"`
}

// Limit is a decimal ceiling on an operation. Amount is kept as the verbatim
// decimal string — it is rendered exactly as captured and compared as an
// exact rational, never through a float.
type Limit struct {
	Amount   string `json:"amount"`
	Currency string `json:"currency"`
}

// Attenuation is the read-time comparison of one hop's grants against its
// parent's (Q13). `unknown` is a first-class outcome: vocabularies the AAT
// invariants cannot compare are recorded and flagged, never swallowed — and
// since D8.7 they hold the hop at `asserted`, because an invariant that could
// not be checked is not one that held. The comparator itself is unchanged by
// that decision; it answers, and internal/aat decides what the answer is
// worth.
type Attenuation string

const (
	AttenuationUnchanged  Attenuation = "unchanged"
	AttenuationAttenuated Attenuation = "attenuated"
	AttenuationBroadened  Attenuation = "broadened"
	AttenuationUnknown    Attenuation = "unknown"
)

// grantsFor flattens a hop's authorization_details into comparison form.
func grantsFor(raw []json.RawMessage) []Grant {
	out := make([]Grant, 0, len(raw))
	for _, r := range raw {
		var g Grant
		// A grant that does not parse into the projection is still a grant:
		// it keeps its raw bytes and simply has nothing comparable in it,
		// which the comparator reports as unknown rather than ignoring.
		_ = json.Unmarshal(r, &g)
		g.Raw = r
		out = append(out, g)
	}
	return out
}

// limitFor returns the ceiling this grant set places on operation, if any,
// plus whether every grant covering the operation was comparable.
func limitFor(grants []Grant, operation string) (*Limit, bool) {
	var tightest *Limit
	for _, g := range grants {
		for _, p := range g.Privileges {
			if p.Operation != operation || p.Limit == nil {
				continue
			}
			r, ok := decimal(p.Limit.Amount)
			if !ok {
				return nil, false
			}
			if tightest == nil {
				l := *p.Limit
				tightest = &l
				continue
			}
			cur, _ := decimal(tightest.Amount)
			if r.Cmp(cur) < 0 {
				l := *p.Limit
				tightest = &l
			}
		}
	}
	return tightest, true
}

// actionSet is the union of a grant set's actions, keyed by grant type. A
// grant carrying no actions array is not comparable under the AAT
// invariants: its type is returned as the reason.
func actionSet(grants []Grant) (map[string]map[string]bool, string) {
	out := map[string]map[string]bool{}
	for _, g := range grants {
		if len(g.Actions) == 0 {
			t := g.Type
			if t == "" {
				t = "(untyped)"
			}
			return nil, t
		}
		if out[g.Type] == nil {
			out[g.Type] = map[string]bool{}
		}
		for _, a := range g.Actions {
			out[g.Type][a] = true
		}
	}
	return out, ""
}

// isWildcard reports whether action is a wildcard pattern, and whether it
// would match candidate. The AAT draft cannot compare wildcard grants, so a
// match here means "unknown", not "covered" (Q13).
func isWildcard(action, candidate string) (wild, matches bool) {
	switch {
	case action == "*":
		return true, true
	case strings.HasSuffix(action, "*"):
		return true, strings.HasPrefix(candidate, strings.TrimSuffix(action, "*"))
	default:
		return false, false
	}
}

// CompareGrants compares a child hop's grants against its parent's and
// returns the classification plus a human-readable reason for the non-obvious
// ones.
//
// This is a pure read-time computation over the raw stored grants. Nothing
// it produces is written back to the record (Q11).
func CompareGrants(parent, child []Grant) (Attenuation, string) {
	att, reason, _ := CompareGrantsDetail(parent, child)
	return att, reason
}

// CompareGrantsDetail is CompareGrants plus the structured finding behind a
// `broadened` verdict, when the verdict came from the AAT draft's capability
// monotonicity rules (I4) and therefore names a tool and a constraint. Mint
// uses it to refuse with a typed error rather than a sentence; everything
// that only needs the classification calls CompareGrants.
//
// # Which comparison runs
//
// Two grant vocabularies live here and the routing between them is by the
// RFC 9396 `type` member alone:
//
//   - An entry of type `attenuating_agent_token` on EITHER side selects the
//     vendored draft's own comparison — §4.5's subsumption matrix over the
//     `tools` map, as §7 steps 4n–4p apply it (aat_i4.go). The draft defines
//     this shape; behalf implements the draft for it.
//   - Everything else keeps compareV1: behalf's own `type` + `actions` +
//     `privileges[].limit` rules, unchanged and still stamped
//     ComparatorVersion.
//
// Both comparisons always run and the stricter answer wins — the draft's
// rules never replace behalf's for a shape the draft does not define, and a
// side that carries none of the other's vocabulary is a known-empty side
// rather than an uncomparable one.
func CompareGrantsDetail(parent, child []Grant) (Attenuation, string, *I4Violation) {
	pAAT, pOther := splitAAT(parent)
	cAAT, cOther := splitAAT(child)

	// No draft-shaped grant anywhere: the v1 comparison, byte for byte the
	// behaviour it always had.
	if len(pAAT) == 0 && len(cAAT) == 0 {
		att, reason := compareV1(parent, child)
		return att, reason, nil
	}

	att, reason, v := compareAAT(pAAT, cAAT)
	if att == AttenuationBroadened {
		return att, reason, v
	}
	// The grant shapes the draft does not define, alongside: the draft
	// ignores the entries it does not profile (§3.3), behalf does not.
	switch vAtt, vReason := compareOther(pOther, cOther); vAtt {
	case AttenuationBroadened, AttenuationUnknown:
		return vAtt, vReason, nil
	case AttenuationAttenuated:
		return AttenuationAttenuated, reason, v
	}
	return att, reason, v
}

// compareOther is the v1 comparison over the entries the draft does not
// define, in the company of a draft-shaped entry on one side or the other.
//
// It exists because compareV1's own opening guard answers `unknown` when
// EITHER side carries no authorization_details at all — a hop with no grants
// says nothing about what was delegated, so nothing can be compared. That
// guard does not apply here. The hop does carry authorization_details: the
// capability entry compareAAT has just read. A side with no entry of THIS
// vocabulary is therefore a known-empty side, and the two asymmetric answers
// follow from what is known rather than from what is missing — a child that
// invents a vocabulary its parent carried none of has gained authority, and
// a child that drops the vocabulary entirely has given it up.
//
// Without this, a child could keep its parent's capability entry byte for
// byte, bolt on a whole grant of behalf's own shape that the parent never
// delegated, and be recorded `unchanged`.
func compareOther(parent, child []Grant) (Attenuation, string) {
	switch {
	case len(parent) > 0 && len(child) > 0:
		return compareV1(parent, child)
	case len(child) > 0:
		// compareV1's own rule for a grant type the parent never delegated,
		// applied to a parent set that is empty rather than merely missing
		// this type.
		return AttenuationBroadened, fmt.Sprintf(
			"grant type %q was never delegated by the parent hop", leastType(child))
	case len(parent) > 0:
		return AttenuationAttenuated, ""
	}
	return AttenuationUnchanged, ""
}

// leastType names one grant type out of a set, chosen in sort order so a
// refusal reads the same on every run.
func leastType(grants []Grant) string {
	types := make([]string, 0, len(grants))
	for _, g := range grants {
		types = append(types, g.Type)
	}
	sort.Strings(types)
	return types[0]
}

// compareV1 is behalf's own comparison, over behalf's own grant shape: grant
// type containment, action containment, wildcard non-comparability, and
// per-operation decimal ceilings that may tighten and never rise (Q13, D8.1).
// `unknown` is a first-class answer here: the vocabulary has no rules to
// apply, which is a fact about behalf and not a finding about the hop. It is
// recorded and flagged (Q13), and it holds the hop at `asserted` (D8.7).
func compareV1(parent, child []Grant) (Attenuation, string) {
	if len(parent) == 0 || len(child) == 0 {
		return AttenuationUnknown, "a hop carries no authorization_details to compare"
	}
	parentActions, badParent := actionSet(parent)
	if badParent != "" {
		return AttenuationUnknown, fmt.Sprintf("grant type %q carries no RFC 9396 actions the AAT invariants can compare", badParent)
	}
	childActions, badChild := actionSet(child)
	if badChild != "" {
		return AttenuationUnknown, fmt.Sprintf("grant type %q carries no RFC 9396 actions the AAT invariants can compare", badChild)
	}

	narrowed := false
	for typ, actions := range childActions {
		pa, ok := parentActions[typ]
		if !ok {
			return AttenuationBroadened, fmt.Sprintf("grant type %q was never delegated by the parent hop", typ)
		}
		for a := range actions {
			if pa[a] {
				continue
			}
			for p := range pa {
				if wild, matches := isWildcard(p, a); wild && matches {
					return AttenuationUnknown, fmt.Sprintf("action %q rests on the parent's wildcard grant %q, which the AAT invariants cannot compare", a, p)
				}
			}
			return AttenuationBroadened, fmt.Sprintf("action %q was never delegated by the parent hop", a)
		}
		if len(actions) < len(pa) {
			narrowed = true
		}
	}
	for typ := range parentActions {
		if _, ok := childActions[typ]; !ok {
			narrowed = true
		}
	}

	// Per-operation limits: a child may tighten a ceiling, never raise or
	// drop one.
	for _, a := range sortedActions(childActions) {
		pl, okP := limitFor(parent, a)
		cl, okC := limitFor(child, a)
		if !okP || !okC {
			return AttenuationUnknown, fmt.Sprintf("the limit on %q is not a comparable decimal", a)
		}
		if pl == nil {
			continue
		}
		if cl == nil {
			return AttenuationBroadened, fmt.Sprintf("the parent's limit on %q is dropped at this hop", a)
		}
		if pl.Currency != cl.Currency {
			return AttenuationUnknown, fmt.Sprintf("the limit on %q changes currency (%s to %s), which the AAT invariants cannot compare", a, pl.Currency, cl.Currency)
		}
		pv, _ := decimal(pl.Amount)
		cv, _ := decimal(cl.Amount)
		switch cv.Cmp(pv) {
		case 1:
			return AttenuationBroadened, fmt.Sprintf("the limit on %q rises from %s to %s", a, pl.Amount, cl.Amount)
		case -1:
			narrowed = true
		}
	}

	if narrowed {
		return AttenuationAttenuated, ""
	}
	return AttenuationUnchanged, ""
}

// ScopeExcess is a read-time finding: the operation exceeded the ceiling the
// chain delegated. It is computed from the raw per-hop authorization_details
// against the operation every time it is rendered, stamped with the
// comparator version, and never stored — a computed delta that froze into
// evidence would be a computation bug preserved forever (Q11, Q13).
type ScopeExcess struct {
	Operation         string
	Limit             string // the tightest delegated ceiling, verbatim
	Currency          string
	Amount            string // what the operation actually did, verbatim
	ComparatorVersion string
}

// CheckScope compares operation/amount against the tightest ceiling any hop
// of the chain placed on that operation. It returns nil when the operation
// is inside the delegated ceiling, when no hop constrained it, or when the
// values are not comparable — behalf records, it does not enforce.
func CheckScope(hops []Hop, operation, amount string) *ScopeExcess {
	if operation == "" || amount == "" {
		return nil
	}
	amt, ok := decimal(amount)
	if !ok {
		return nil
	}
	var tightest *Limit
	for _, h := range hops {
		l, ok := limitFor(h.Grants, operation)
		if !ok || l == nil {
			continue
		}
		if tightest == nil {
			tightest = l
			continue
		}
		lv, _ := decimal(l.Amount)
		tv, _ := decimal(tightest.Amount)
		if lv.Cmp(tv) < 0 {
			tightest = l
		}
	}
	if tightest == nil {
		return nil
	}
	lim, _ := decimal(tightest.Amount)
	if amt.Cmp(lim) <= 0 {
		return nil
	}
	return &ScopeExcess{
		Operation:         operation,
		Limit:             tightest.Amount,
		Currency:          tightest.Currency,
		Amount:            amount,
		ComparatorVersion: ComparatorVersion,
	}
}

// sortedActions flattens an action set into a deterministic order, so the
// reason a comparison gives is stable across runs.
func sortedActions(set map[string]map[string]bool) []string {
	var out []string
	for _, actions := range set {
		for a := range actions {
			out = append(out, a)
		}
	}
	sort.Strings(out)
	return out
}

// decimal parses a captured decimal string exactly (no float rounding).
func decimal(s string) (*big.Rat, bool) {
	if s == "" {
		return nil, false
	}
	r, ok := new(big.Rat).SetString(s)
	if !ok {
		return nil, false
	}
	return r, true
}
