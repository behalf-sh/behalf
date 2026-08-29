package why

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"strings"
)

// I4: capability monotonicity, as the vendored draft actually defines it.
//
// `draft-niyikiza-oauth-attenuating-agent-tokens-01` §3.3 profiles RFC 9396
// with a single `authorization_details` entry of type
// `attenuating_agent_token` carrying a `tools` map — tool name → argument
// name → a typed constraint object. §4.5 then defines capability
// monotonicity over that shape, and §7 steps 4n–4p turn it into the
// verification algorithm's DENY conditions.
//
// behalf's own grants are a different object (`type` + `actions` +
// `privileges[].limit`), compared by compareV1 in chain.go. That comparison
// is sound for the shape it reads and is left exactly as it was. What was
// missing is this file: fed a genuinely draft-conforming chain, compareV1
// found no `actions`, answered `unknown`, and the hop kept the status its
// signature earned — so a child that added a tool its parent never granted
// was recorded `verified` where §7 step 4p1 says DENY.
//
// The routing rule is in CompareGrantsDetail: an `attenuating_agent_token`
// entry on either side selects the draft's comparison for that entry; grant
// shapes the draft does not define keep compareV1. Nothing behalf mints or
// has ever recorded uses the draft shape, so this is strictly additive.
//
// # Fail-closed
//
// Everything the draft says DENY to is reported here as
// AttenuationBroadened, which is what makes verifyHop call the hop `broken`.
// That includes conditions whose plain-English name is not "broadened":
// a malformed `tools` map, an unrecognised `constraint_type` (§3.4: "MUST
// deny authorization if they encounter a constraint_type they do not
// recognize"), a registered extension type behalf does not implement (§3.5.2),
// and a constraint tree too deep or too branchy to walk. v1's vocabulary has
// three words and the draft has two outcomes; `broadened` is the one that
// denies, and the reason string carries the truth. Routing them to `unknown`
// instead would be wrong even now that `unknown` no longer reads `verified`
// (D8.7): the draft says DENY for these, and `asserted` is not a denial.

// AATGrantType is the draft's RFC 9396 `authorization_details` type
// (§3.3, registered in §10.2).
const AATGrantType = "attenuating_agent_token"

// MaxConstraintDepth bounds how deep a nested `all`/`any` tree this
// comparison will walk. The draft requires a finite ceiling and RECOMMENDS
// 32 (§3.4); a tree past it is not rejected as a token here — behalf's
// resource limits are a separate, tracked question (profile §9.4) — it is
// simply not something this comparison can prove to be a narrowing, so it
// fails closed like any other unprovable subsumption.
const MaxConstraintDepth = 32

// maxSubsumptionSteps bounds the `all` matcher's backtracking. §4.5's own
// pseudocode backtracks and the draft notes the search space is bounded by
// the clause counts, but the bound is factorial in the worst case; a budget
// keeps a hostile constraint tree from becoming a stall. Exhausting it fails
// closed.
const maxSubsumptionSteps = 200000

// I4Violation names the specific §4.5 rule a hop broke, so a caller — Mint
// above all — can refuse with something more precise than a sentence. Tool
// is always set; Argument is empty when the finding is tool-level (a tool the
// parent never granted, a key set that changed shape); ParentType and
// DerivedType are the two `constraint_type` values when both are known.
type I4Violation struct {
	Tool        string
	Argument    string
	ParentType  string
	DerivedType string
	Detail      string
}

// String renders the violation the way a refusal should read.
func (v *I4Violation) String() string {
	if v == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("tool ")
	b.WriteString(quoted(v.Tool))
	if v.Argument != "" {
		b.WriteString(", argument ")
		b.WriteString(quoted(v.Argument))
	}
	if v.DerivedType != "" || v.ParentType != "" {
		b.WriteString(" (")
		b.WriteString(named(v.DerivedType))
		b.WriteString(" under a parent ")
		b.WriteString(named(v.ParentType))
		b.WriteString(")")
	}
	if v.Detail != "" {
		b.WriteString(": ")
		b.WriteString(v.Detail)
	}
	return b.String()
}

func named(kind string) string {
	if kind == "" {
		return "(absent)"
	}
	return kind
}

func quoted(s string) string { return `"` + s + `"` }

// splitAAT separates a hop's grants into the draft's capability entries and
// everything else. §3.3: "Enforcement points implementing this specification
// process only entries with type set to attenuating_agent_token and MUST
// ignore entries of other types." behalf does not ignore the others — it has
// real rules for its own grant shapes — so they are kept and returned.
func splitAAT(grants []Grant) (aat, others []Grant) {
	for _, g := range grants {
		if g.Type == AATGrantType {
			aat = append(aat, g)
			continue
		}
		others = append(others, g)
	}
	return aat, others
}

// toolMap is one AAT entry read out: tool identifier → argument name → the
// raw constraint object. Both levels are decoded with duplicate-key
// detection, because §3.3.1 makes a duplicate tool identifier malformed and
// last-key-wins is exactly the kind of quiet disagreement between
// implementations that a delegation format cannot afford.
type toolMap map[string]map[string]json.RawMessage

// compareAAT is §7 steps 4n–4p over the two hops' capability entries.
//
// Either side may legitimately have no entry: §7 step 4n defines the missing
// side as "an empty capability entry with an empty `tools` map". That gives
// the two asymmetric answers the draft wants — a child with no capability
// entry has narrowed to nothing, and a child that invents a `tools` map its
// parent never had has every one of its tools absent from the parent, which
// step 4p1 denies.
func compareAAT(parent, child []Grant) (Attenuation, string, *I4Violation) {
	// §3.3 / §7 step 4n: more than one entry of this type is invalid.
	if len(parent) > 1 {
		return AttenuationBroadened, fmt.Sprintf(
			"the parent hop carries %d %s entries; draft §3.3 permits exactly one, so the authority it "+
				"delegated cannot be established", len(parent), AATGrantType), nil
	}
	if len(child) > 1 {
		return AttenuationBroadened, fmt.Sprintf(
			"this hop carries %d %s entries; draft §3.3 permits exactly one (§7 step 4n: DENY)",
			len(child), AATGrantType), nil
	}

	pTools, err := readTools(parent)
	if err != nil {
		return AttenuationBroadened, fmt.Sprintf(
			"the parent hop's %s entry cannot be read, so nothing can be shown to narrow it: %v",
			AATGrantType, err), nil
	}
	cTools, err := readTools(child)
	if err != nil {
		return AttenuationBroadened, fmt.Sprintf(
			"this hop's %s entry cannot be read (draft §3.3, fail closed): %v", AATGrantType, err), nil
	}

	s := &i4{steps: maxSubsumptionSteps}
	narrowed := false

	// Step 4p1: every tool in the child must be present in the parent.
	for _, tool := range sortedKeys(cTools) {
		pArgs, ok := pTools[tool]
		if !ok {
			v := &I4Violation{Tool: tool, Detail: "the parent hop never granted this tool"}
			return AttenuationBroadened, fmt.Sprintf(
				"tool %q was never delegated by the parent hop (draft §7 step 4p1)", tool), v
		}
		cArgs := cTools[tool]

		// Steps 4p2/4p3: closed-world key sets. A parent with a non-empty
		// constraint map has fixed the required invocation shape (§3.3), so
		// the child's key set must be identical — adding a key admits an
		// argument the parent's closed-world check rejects, dropping one
		// omits an argument the parent required. A parent with an empty map
		// is open-world and the child may introduce any keys at all.
		if len(pArgs) > 0 {
			if added, removed := keyDiff(pArgs, cArgs); added != "" || removed != "" {
				var detail string
				switch {
				case added != "":
					detail = fmt.Sprintf("the constraint map adds the argument key %q, which the parent's "+
						"closed-world shape does not permit", added)
				default:
					detail = fmt.Sprintf("the constraint map drops the parent's required argument key %q", removed)
				}
				key := added
				if key == "" {
					key = removed
				}
				v := &I4Violation{Tool: tool, Argument: key, Detail: detail}
				return AttenuationBroadened, fmt.Sprintf(
					"tool %q: %s (draft §4.5, §7 step 4p2)", tool, detail), v
			}
		} else if len(cArgs) > 0 {
			// Open-world parent, closed-world child: a real narrowing.
			narrowed = true
		}

		// Step 4p4: per-argument subsumption.
		for _, arg := range sortedKeys(cArgs) {
			pRaw, ok := pArgs[arg]
			if !ok {
				continue // only reachable from the open-world branch above
			}
			cRaw := cArgs[arg]

			pc, err := s.parse(pRaw, 0)
			if err != nil {
				v := &I4Violation{Tool: tool, Argument: arg, Detail: err.Error()}
				return AttenuationBroadened, fmt.Sprintf(
					"tool %q, argument %q: the parent's constraint cannot be read, so nothing can be shown "+
						"to narrow it: %v", tool, arg, err), v
			}
			cc, err := s.parse(cRaw, 0)
			if err != nil {
				v := &I4Violation{Tool: tool, Argument: arg, ParentType: pc.kind, Detail: err.Error()}
				return AttenuationBroadened, fmt.Sprintf(
					"tool %q, argument %q: %v (draft §3.4, fail closed)", tool, arg, err), v
			}
			if ok, reason := s.subsumes(cc, pc, 0); !ok {
				v := &I4Violation{
					Tool: tool, Argument: arg,
					ParentType: pc.kind, DerivedType: cc.kind,
					Detail: reason,
				}
				return AttenuationBroadened, fmt.Sprintf(
					"tool %q, argument %q: %s (draft §4.5, §7 step 4p4)", tool, arg, reason), v
			}
			if !jsonEqual(pRaw, cRaw) {
				narrowed = true
			}
		}
	}

	// A tool the parent granted and the child did not is authority given up.
	for tool := range pTools {
		if _, ok := cTools[tool]; !ok {
			narrowed = true
		}
	}

	if narrowed {
		return AttenuationAttenuated, "", nil
	}
	return AttenuationUnchanged, "", nil
}

// readTools decodes the single capability entry, if there is one. An absent
// entry is the empty capability set (§7 step 4n), not an error.
func readTools(entries []Grant) (toolMap, error) {
	if len(entries) == 0 {
		return toolMap{}, nil
	}
	g := entries[0]
	if len(g.Tools) == 0 {
		return nil, errors.New(`the entry carries no "tools" member, which draft §3.3 requires of every ` +
			AATGrantType + " entry")
	}
	top, err := decodeObject(g.Tools)
	if err != nil {
		return nil, fmt.Errorf(`"tools" %w`, err)
	}
	out := make(toolMap, len(top))
	for name, raw := range top {
		args, err := decodeObject(raw)
		if err != nil {
			return nil, fmt.Errorf("tool %q: its constraint map %w", name, err)
		}
		out[name] = args
	}
	return out, nil
}

// keyDiff returns the first key present in child but not parent, and the
// first present in parent but not child, in deterministic order.
func keyDiff(parent, child map[string]json.RawMessage) (added, removed string) {
	for _, k := range sortedKeys(child) {
		if _, ok := parent[k]; !ok {
			added = k
			break
		}
	}
	for _, k := range sortedKeys(parent) {
		if _, ok := child[k]; !ok {
			removed = k
			break
		}
	}
	return added, removed
}

// ---- constraints -------------------------------------------------------

// constraint is one parsed argument constraint (§3.4 Table 2). Only the
// members its own type defines are populated.
type constraint struct {
	kind string
	raw  json.RawMessage

	value  json.RawMessage   // exact
	values []json.RawMessage // one_of / not_one_of / contains / subset
	nested []constraint      // all / any

	hasMin, hasMax             bool
	min, max                   *big.Rat
	minText, maxText           string
	minInclusive, maxInclusive bool
}

// i4 carries the budget shared across one hop comparison.
type i4 struct{ steps int }

// parse reads one constraint object. Every failure is a refusal: §3.4's
// fail-closed rule covers unrecognised `constraint_type` values, and a
// constraint that cannot be read cannot be shown to narrow anything.
func (s *i4) parse(raw json.RawMessage, depth int) (constraint, error) {
	if depth > MaxConstraintDepth {
		return constraint{}, fmt.Errorf("the constraint tree nests deeper than %d, so it cannot be walked "+
			"(draft §3.4 requires a finite MAX_CONSTRAINT_DEPTH; %d is the RECOMMENDED value)",
			MaxConstraintDepth, MaxConstraintDepth)
	}
	obj, err := decodeObject(raw)
	if err != nil {
		return constraint{}, fmt.Errorf("the constraint %w", err)
	}
	kindRaw, ok := obj["constraint_type"]
	if !ok {
		return constraint{}, errors.New("the constraint carries no constraint_type member")
	}
	var kind string
	if err := json.Unmarshal(kindRaw, &kind); err != nil {
		return constraint{}, errors.New("constraint_type is not a string")
	}
	c := constraint{kind: kind, raw: raw}

	switch kind {
	case "exact":
		v, ok := obj["value"]
		if !ok {
			return constraint{}, errors.New(`the exact constraint carries no "value" member`)
		}
		c.value = v

	case "range":
		c.minInclusive, c.maxInclusive = true, true
		if r, ok := obj["min"]; ok {
			n, text, ok := number(r)
			if !ok {
				return constraint{}, errors.New("the range constraint's min is not a number")
			}
			c.hasMin, c.min, c.minText = true, n, text
		}
		if r, ok := obj["max"]; ok {
			n, text, ok := number(r)
			if !ok {
				return constraint{}, errors.New("the range constraint's max is not a number")
			}
			c.hasMax, c.max, c.maxText = true, n, text
		}
		if r, ok := obj["min_inclusive"]; ok {
			if err := json.Unmarshal(r, &c.minInclusive); err != nil {
				return constraint{}, errors.New("the range constraint's min_inclusive is not a boolean")
			}
		}
		if r, ok := obj["max_inclusive"]; ok {
			if err := json.Unmarshal(r, &c.maxInclusive); err != nil {
				return constraint{}, errors.New("the range constraint's max_inclusive is not a boolean")
			}
		}
		if !c.hasMin && !c.hasMax {
			return constraint{}, errors.New("the range constraint carries neither a min nor a max bound")
		}

	case "one_of":
		c.values, err = arrayMember(obj, "values", kind)
	case "not_one_of":
		c.values, err = arrayMember(obj, "excluded", kind)
	case "contains":
		c.values, err = arrayMember(obj, "required", kind)
	case "subset":
		c.values, err = arrayMember(obj, "allowed", kind)

	case "wildcard":
		// No additional members (§3.4 Table 2).

	case "all", "any":
		clauses, aerr := arrayMember(obj, "constraints", kind)
		if aerr != nil {
			return constraint{}, aerr
		}
		c.nested = make([]constraint, 0, len(clauses))
		for _, cl := range clauses {
			nc, err := s.parse(cl, depth+1)
			if err != nil {
				return constraint{}, err
			}
			c.nested = append(c.nested, nc)
		}

	default:
		// §3.4: "Enforcement points MUST deny authorization if they encounter
		// a constraint_type they do not recognize (fail-closed behavior)."
		// §3.5.2 extends the same rule to registered extension types an
		// enforcement point has not implemented — behalf implements none.
		return constraint{}, fmt.Errorf("constraint_type %q is not one of the draft's nine core types "+
			"(exact, range, one_of, not_one_of, contains, subset, wildcard, all, any) and behalf implements "+
			"no registered extension type, so §3.4 and §3.5.2 require denial rather than skipping the check",
			kind)
	}
	if err != nil {
		return constraint{}, err
	}
	return c, nil
}

func arrayMember(obj map[string]json.RawMessage, member, kind string) ([]json.RawMessage, error) {
	raw, ok := obj[member]
	if !ok {
		return nil, fmt.Errorf("the %s constraint carries no %q member", kind, member)
	}
	var out []json.RawMessage
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("the %s constraint's %q member is not an array", kind, member)
	}
	return out, nil
}

// subsumes reports whether the derived constraint is at least as restrictive
// as the parent's — §4.5's relation, in §4.5's and §7 step 4p4's argument
// order (derived first). §3.5.1 writes the same relation with the arguments
// reversed, `subsumes(C_parent, C_child)`; the notation differs, the meaning
// does not, and the meaning is "the child accepts nothing the parent would
// have rejected".
//
// The relation is deliberately conservative, per §3.5.1's soundness
// requirement: it returns true only for pairs §4.5 explicitly permits, and
// false for everything else — including pairs that happen to be semantic
// narrowings the draft did not enumerate. Those are listed in the profile.
func (s *i4) subsumes(derived, parent constraint, depth int) (bool, string) {
	if s.steps <= 0 {
		return false, fmt.Sprintf("the constraint tree needs more than %d subsumption steps to decide, "+
			"so the narrowing cannot be established", maxSubsumptionSteps)
	}
	s.steps--
	if depth > MaxConstraintDepth {
		return false, fmt.Sprintf("the constraint tree nests deeper than %d (draft §3.4)", MaxConstraintDepth)
	}

	// §4.5, wildcard: "Any other constraint type subsumes a parent wildcard."
	// The parent placed no restriction, so nothing the child writes can widen
	// it — including another wildcard.
	if parent.kind == "wildcard" {
		return true, ""
	}

	switch derived.kind {
	case "exact":
		// §4.5, exact: identical exact, a number inside a parent range, a
		// member of a parent one_of, or any parent wildcard (above). "All
		// other parent types are invalid cross-type targets."
		switch parent.kind {
		case "exact":
			if jsonEqual(derived.value, parent.value) {
				return true, ""
			}
			return false, fmt.Sprintf("exact %s is not the parent's exact %s",
				brief(derived.value), brief(parent.value))
		case "range":
			n, _, ok := number(derived.value)
			if !ok {
				return false, fmt.Sprintf("exact %s is not a number, so it cannot be shown to fall "+
					"inside the parent's range", brief(derived.value))
			}
			if inRange(n, parent) {
				return true, ""
			}
			return false, fmt.Sprintf("exact %s falls outside the parent's range %s",
				brief(derived.value), rangeText(parent))
		case "one_of":
			if containsValue(parent.values, derived.value) {
				return true, ""
			}
			return false, fmt.Sprintf("exact %s is not a member of the parent's one_of set",
				brief(derived.value))
		default:
			return false, crossType("exact", parent.kind)
		}

	case "range":
		if parent.kind != "range" {
			return false, crossType("range", parent.kind)
		}
		return rangeSubsumes(derived, parent)

	case "one_of":
		if parent.kind != "one_of" {
			return false, crossType("one_of", parent.kind)
		}
		// §4.5, one_of: "valid only if its value set is a subset of the
		// parent's value set."
		for _, v := range derived.values {
			if !containsValue(parent.values, v) {
				return false, fmt.Sprintf("one_of admits %s, which the parent's set does not permit",
					brief(v))
			}
		}
		return true, ""

	case "not_one_of":
		// §4.5, one_of: a derived not_one_of against a parent one_of is
		// named invalid outright — "Enforcement points MUST reject this
		// cross-type pair."
		if parent.kind == "one_of" {
			return false, "a derived not_one_of under a parent one_of is invalid: it accepts values " +
				"outside the parent's permitted set and cannot be shown to subsume it without domain " +
				"knowledge (§4.5)"
		}
		if parent.kind != "not_one_of" {
			return false, crossType("not_one_of", parent.kind)
		}
		// "valid only if its excluded set is a superset of the parent's."
		for _, v := range parent.values {
			if !containsValue(derived.values, v) {
				return false, fmt.Sprintf("not_one_of drops the parent's exclusion of %s", brief(v))
			}
		}
		return true, ""

	case "contains":
		if parent.kind != "contains" {
			return false, crossType("contains", parent.kind)
		}
		// §4.5, contains: derived required must be a superset of the parent's.
		for _, v := range parent.values {
			if !containsValue(derived.values, v) {
				return false, fmt.Sprintf("contains drops the parent's required element %s", brief(v))
			}
		}
		return true, ""

	case "subset":
		if parent.kind != "subset" {
			return false, crossType("subset", parent.kind)
		}
		// §4.5, subset: derived allowed must be a subset of the parent's.
		for _, v := range derived.values {
			if !containsValue(parent.values, v) {
				return false, fmt.Sprintf("subset admits %s, which the parent's allowed set does not contain",
					brief(v))
			}
		}
		return true, ""

	case "wildcard":
		// §4.5: "A derived wildcard is valid only if the parent is also
		// wildcard." The parent-wildcard case returned above.
		return false, fmt.Sprintf("a derived wildcard drops the parent's %s constraint entirely; §4.5 "+
			"permits a derived wildcard only under a parent wildcard", parent.kind)

	case "all":
		if parent.kind != "all" {
			return false, crossType("all", parent.kind)
		}
		return s.allSubsumes(derived.nested, parent.nested, depth)

	case "any":
		if parent.kind != "any" {
			return false, crossType("any", parent.kind)
		}
		// §4.5, any: every derived clause must be subsumed by at least one
		// parent clause. Removing clauses narrows; adding widens. "The
		// derived any MUST contain at least one clause."
		if len(derived.nested) == 0 {
			return false, "the derived any carries no clauses; §4.5 requires at least one"
		}
		for _, cd := range derived.nested {
			matched := false
			for _, cp := range parent.nested {
				if ok, _ := s.subsumes(cd, cp, depth+1); ok {
					matched = true
					break
				}
			}
			if !matched {
				return false, fmt.Sprintf("the any clause %s is not subsumed by any clause of the "+
					"parent's any", brief(cd.raw))
			}
		}
		return true, ""
	}
	return false, fmt.Sprintf("constraint_type %q is not one of the draft's nine core types", derived.kind)
}

// allSubsumes is §4.5's one-to-one clause assignment for `all`: every parent
// clause must be matched by a DISTINCT derived clause that subsumes it, extra
// derived clauses are permitted, and no parent clause may be dropped. The
// draft gives the algorithm as pseudocode and notes that a greedy match can
// dead-end, so this backtracks exactly as written.
func (s *i4) allSubsumes(derived, parent []constraint, depth int) (bool, string) {
	used := make([]bool, len(derived))
	var match func(i int) bool
	match = func(i int) bool {
		if i == len(parent) {
			return true
		}
		if s.steps <= 0 {
			return false
		}
		for j := range derived {
			if used[j] {
				continue
			}
			if ok, _ := s.subsumes(derived[j], parent[i], depth+1); ok {
				used[j] = true
				if match(i + 1) {
					return true
				}
				used[j] = false
			}
		}
		return false
	}
	if match(0) {
		return true, ""
	}
	if s.steps <= 0 {
		return false, fmt.Sprintf("the all clause matching needs more than %d steps to decide, so the "+
			"narrowing cannot be established", maxSubsumptionSteps)
	}
	return false, "no one-to-one assignment exists in which every clause of the parent's all is matched " +
		"by a distinct derived clause that subsumes it; §4.5 forbids dropping any parent clause"
}

// rangeSubsumes is §4.5's range rule: derived min >= parent min and derived
// max <= parent max, a missing parent bound is unbounded, a missing derived
// bound is valid only where the parent's is missing too, and inclusivity may
// only tighten.
//
// The inclusivity sentence is scoped by the draft to "the same min value",
// so it is applied only at an equal bound: a strictly tighter bound is a
// narrowing whatever its inclusivity, which is provable and therefore sound
// to accept. Profile §9.1 records that reading.
func rangeSubsumes(d, p constraint) (bool, string) {
	switch {
	case p.hasMin && !d.hasMin:
		return false, fmt.Sprintf("range drops the parent's min bound of %s, leaving it unbounded below",
			p.minText)
	case p.hasMin && d.hasMin:
		switch d.min.Cmp(p.min) {
		case -1:
			return false, fmt.Sprintf("range min %s falls below the parent's %s", d.minText, p.minText)
		case 0:
			if d.minInclusive && !p.minInclusive {
				return false, fmt.Sprintf("range makes the min bound %s inclusive where the parent "+
					"excludes it, admitting a value the parent rejects", d.minText)
			}
		}
	}
	switch {
	case p.hasMax && !d.hasMax:
		return false, fmt.Sprintf("range drops the parent's max bound of %s, leaving it unbounded above",
			p.maxText)
	case p.hasMax && d.hasMax:
		switch d.max.Cmp(p.max) {
		case 1:
			return false, fmt.Sprintf("range max %s rises above the parent's %s", d.maxText, p.maxText)
		case 0:
			if d.maxInclusive && !p.maxInclusive {
				return false, fmt.Sprintf("range makes the max bound %s inclusive where the parent "+
					"excludes it, admitting a value the parent rejects", d.maxText)
			}
		}
	}
	return true, ""
}

// inRange is the `range` check predicate (§3.4 Table 2), used by the
// exact-under-range cross-type rule.
func inRange(n *big.Rat, p constraint) bool {
	if p.hasMin {
		switch c := n.Cmp(p.min); {
		case c < 0, c == 0 && !p.minInclusive:
			return false
		}
	}
	if p.hasMax {
		switch c := n.Cmp(p.max); {
		case c > 0, c == 0 && !p.maxInclusive:
			return false
		}
	}
	return true
}

func rangeText(p constraint) string {
	lo, hi := "-inf", "+inf"
	loBracket, hiBracket := "(", ")"
	if p.hasMin {
		lo = p.minText
		if p.minInclusive {
			loBracket = "["
		}
	}
	if p.hasMax {
		hi = p.maxText
		if p.maxInclusive {
			hiBracket = "]"
		}
	}
	return loBracket + lo + ", " + hi + hiBracket
}

func crossType(derived, parent string) string {
	return fmt.Sprintf("a derived %s under a parent %s is not a pair §4.5 permits, and any pair the "+
		"draft does not explicitly permit MUST be rejected", derived, named(parent))
}

// ---- JSON value handling -----------------------------------------------

// decodeObject reads a JSON object and refuses duplicate member names.
// §3.3.1 makes duplicate tool identifiers malformed, and encoding/json's
// last-key-wins would otherwise silently pick one — the kind of divergence
// between implementations §3.4's "two independent implementations MUST
// produce identical results" exists to prevent.
func decodeObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New("is absent")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return nil, errors.New("is not readable JSON")
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("is not a JSON object")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, errors.New("is not a well-formed JSON object")
		}
		key, ok := kt.(string)
		if !ok {
			return nil, errors.New("is not a well-formed JSON object")
		}
		if _, dup := out[key]; dup {
			return nil, fmt.Errorf("names %q twice, which draft §3.3.1 makes malformed", key)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return nil, fmt.Errorf("has no readable value for %q", key)
		}
		out[key] = v
	}
	if _, err := dec.Token(); err != nil {
		return nil, errors.New("is not a well-formed JSON object")
	}
	return out, nil
}

// number reads a JSON number exactly, as a rational — never through a float,
// for the same reason why's decimal ceilings are not. A quoted string is not
// a number: the draft's range constraint says "Argument MUST be a number",
// and coercing "5" to 5 would be exactly the bespoke normalization layer Q13
// ruled out.
func number(raw json.RawMessage) (*big.Rat, string, bool) {
	t := strings.TrimSpace(string(raw))
	if t == "" || t[0] == '"' {
		return nil, "", false
	}
	r, ok := new(big.Rat).SetString(t)
	if !ok {
		return nil, "", false
	}
	return r, t, true
}

// jsonEqual compares two JSON values by value rather than by bytes: numbers
// as exact rationals (so 1 and 1.0 are one value), objects irrespective of
// member order, everything else structurally.
func jsonEqual(a, b json.RawMessage) bool {
	av, aok := jsonValue(a)
	bv, bok := jsonValue(b)
	if !aok || !bok {
		return false
	}
	return valueEqual(av, bv)
}

func jsonValue(raw json.RawMessage) (any, bool) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	return v, true
}

func valueEqual(a, b any) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	switch av := a.(type) {
	case json.Number:
		bv, ok := b.(json.Number)
		if !ok {
			return false
		}
		ar, aok := new(big.Rat).SetString(av.String())
		br, bok := new(big.Rat).SetString(bv.String())
		if !aok || !bok {
			return av.String() == bv.String()
		}
		return ar.Cmp(br) == 0
	case string:
		bv, ok := b.(string)
		return ok && av == bv
	case bool:
		bv, ok := b.(bool)
		return ok && av == bv
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !valueEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, v := range av {
			w, ok := bv[k]
			if !ok || !valueEqual(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

func containsValue(set []json.RawMessage, v json.RawMessage) bool {
	for _, s := range set {
		if jsonEqual(s, v) {
			return true
		}
	}
	return false
}

// brief renders a JSON value for a reason string: compacted, and clipped so
// a hostile constraint cannot turn a finding into a wall of text.
func brief(raw json.RawMessage) string {
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		buf.Reset()
		buf.Write(raw)
	}
	s := buf.String()
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
