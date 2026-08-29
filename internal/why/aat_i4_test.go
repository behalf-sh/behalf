package why

import (
	"fmt"
	"strings"
	"testing"
)

// aatGrant wraps a `tools` map in the draft §3.3 authorization_details entry
// it always travels in.
func aatGrant(t *testing.T, tools string) []Grant {
	t.Helper()
	return grants(t, `{"type":"attenuating_agent_token","tools":`+tools+`}`)
}

// oneArg is the common shape: a single tool with a single constrained
// argument, which is what the per-constraint-type cases below vary.
func oneArg(constraint string) string {
	return `{"read_file":{"path":` + constraint + `}}`
}

// TestI4ToolMonotonicity is draft §4.5's `tools(derived) ⊆ tools(parent)` and
// the closed-world key-set rules, as §7 steps 4p1–4p3 apply them.
//
// `broadened` is what makes a hop `broken` in internal/aat; the status
// mapping itself is pinned there by TestDraftShapedBroadeningIsBroken.
func TestI4ToolMonotonicity(t *testing.T) {
	cases := []struct {
		name           string
		parent, child  []Grant
		want           Attenuation
		reasonContains string
	}{
		{
			// §7 step 4p1: "If any child tool is absent from the parent, DENY."
			name:           "a tool the parent never granted broadens",
			parent:         aatGrant(t, `{"read_file":{}}`),
			child:          aatGrant(t, `{"read_file":{},"delete_file":{}}`),
			want:           AttenuationBroadened,
			reasonContains: `tool "delete_file" was never delegated`,
		},
		{
			name:   "dropping a tool attenuates",
			parent: aatGrant(t, `{"read_file":{},"search_index":{}}`),
			child:  aatGrant(t, `{"read_file":{}}`),
			want:   AttenuationAttenuated,
		},
		{
			name:   "an identical tools map is unchanged",
			parent: aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			want:   AttenuationUnchanged,
		},
		{
			// §4.5: "If the parent's constraint map is empty (open-world),
			// the derived token MAY introduce constraint keys."
			name:   "an open-world parent may be closed by the child",
			parent: aatGrant(t, `{"read_file":{}}`),
			child:  aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/data/q3.pdf"}`)),
			want:   AttenuationAttenuated,
		},
		{
			// §7 step 4p2: the key sets must match exactly under a
			// closed-world parent. An added key is an argument the parent's
			// own check would reject as unknown.
			name:           "adding an argument key to a closed-world parent broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:          aatGrant(t, `{"read_file":{"path":{"constraint_type":"wildcard"},"mode":{"constraint_type":"wildcard"}}}`),
			want:           AttenuationBroadened,
			reasonContains: `adds the argument key "mode"`,
		},
		{
			// Dropping a key produces invocations that omit an argument the
			// parent required — disjoint from the parent's set, not a subset.
			name:           "dropping an argument key from a closed-world parent broadens",
			parent:         aatGrant(t, `{"read_file":{"path":{"constraint_type":"wildcard"},"mode":{"constraint_type":"wildcard"}}}`),
			child:          aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			want:           AttenuationBroadened,
			reasonContains: `drops the parent's required argument key "mode"`,
		},
		{
			// §7 step 4n: a child with no capability entry is the empty
			// capability set, and an empty tool set is always a subset. The
			// child carries nothing else either — a child that drops the
			// capability entry and invents a vocabulary of its own has
			// gained authority on that other axis, which is
			// TestI4DoesNotHideTheOtherVocabulary's case.
			name:   "a child with no capability entry has narrowed to nothing",
			parent: aatGrant(t, `{"read_file":{}}`),
			child:  grants(t),
			want:   AttenuationAttenuated,
		},
		{
			// The mirror image, and the one that matters: a child inventing
			// draft-shaped authority its parent never carried.
			name:           "a child inventing a capability entry broadens",
			parent:         grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read"]}`),
			child:          aatGrant(t, `{"read_file":{}}`),
			want:           AttenuationBroadened,
			reasonContains: `tool "read_file" was never delegated`,
		},
		{
			// §3.3: "An authorization_details array containing multiple
			// entries with type attenuating_agent_token is invalid."
			name:   "two capability entries are invalid",
			parent: aatGrant(t, `{"read_file":{}}`),
			child: grants(t,
				`{"type":"attenuating_agent_token","tools":{"read_file":{}}}`,
				`{"type":"attenuating_agent_token","tools":{"read_file":{}}}`),
			want:           AttenuationBroadened,
			reasonContains: "permits exactly one",
		},
	}
	runI4(t, cases)
}

// TestI4ConstraintSubsumption walks §4.5's subsumption matrix: for every one
// of the draft's nine constraint types, a narrowing the draft permits and a
// broadening it does not.
func TestI4ConstraintSubsumption(t *testing.T) {
	cases := []struct {
		name           string
		parent, child  []Grant
		want           Attenuation
		reasonContains string
	}{
		// ---- exact ----
		{
			name:   "exact: an identical value is unchanged",
			parent: aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/data/q3.pdf"}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/data/q3.pdf"}`)),
			want:   AttenuationUnchanged,
		},
		{
			name:           "exact: a different value broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/data/q3.pdf"}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/data/q4.pdf"}`)),
			want:           AttenuationBroadened,
			reasonContains: "is not the parent's exact",
		},
		{
			name:   "exact: a member of the parent's one_of attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a","/b"]}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/a"}`)),
			want:   AttenuationAttenuated,
		},
		{
			name:           "exact: a non-member of the parent's one_of broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a","/b"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/c"}`)),
			want:           AttenuationBroadened,
			reasonContains: "is not a member of the parent's one_of set",
		},
		{
			name:   "exact: a number inside the parent's range attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"range","min":1,"max":100}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"exact","value":50}`)),
			want:   AttenuationAttenuated,
		},
		{
			name:           "exact: a number outside the parent's range broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"range","min":1,"max":100}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"exact","value":101}`)),
			want:           AttenuationBroadened,
			reasonContains: "falls outside the parent's range",
		},
		{
			name:   "exact: any value under a parent wildcard attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"exact","value":"anything"}`)),
			want:   AttenuationAttenuated,
		},
		{
			// §4.5: "All other parent types are invalid cross-type targets
			// for a derived exact constraint."
			name:           "exact: under a parent not_one_of is an invalid cross-type pair",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"not_one_of","excluded":["/secret"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/a"}`)),
			want:           AttenuationBroadened,
			reasonContains: "not a pair §4.5 permits",
		},

		// ---- range ----
		{
			name:   "range: tighter bounds attenuate",
			parent: aatGrant(t, oneArg(`{"constraint_type":"range","min":1,"max":100}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"range","min":10,"max":50}`)),
			want:   AttenuationAttenuated,
		},
		{
			name:           "range: a min below the parent's broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"range","min":10,"max":100}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"range","min":0,"max":100}`)),
			want:           AttenuationBroadened,
			reasonContains: "falls below the parent's",
		},
		{
			name:           "range: a max above the parent's broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"range","min":1,"max":100}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"range","min":1,"max":1000}`)),
			want:           AttenuationBroadened,
			reasonContains: "rises above the parent's",
		},
		{
			// §4.5: "a missing bound on the derived constraint is only valid
			// if the parent bound is also missing."
			name:           "range: dropping the parent's max broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"range","min":1,"max":100}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"range","min":1}`)),
			want:           AttenuationBroadened,
			reasonContains: "drops the parent's max bound",
		},
		{
			name:   "range: introducing a bound the parent left open attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"range","min":1}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"range","min":1,"max":10}`)),
			want:   AttenuationAttenuated,
		},
		{
			// "a derived min_inclusive: false is valid when the parent has
			// min_inclusive: true at the same min value".
			name:   "range: excluding a bound the parent included attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"range","min":0,"max":100}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"range","min":0,"max":100,"min_inclusive":false}`)),
			want:   AttenuationAttenuated,
		},
		{
			// "...but the reverse is not."
			name:           "range: including a bound the parent excluded broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"range","min":0,"max":100,"min_inclusive":false}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"range","min":0,"max":100}`)),
			want:           AttenuationBroadened,
			reasonContains: "inclusive where the parent excludes it",
		},
		{
			// The inclusivity rule is scoped by the draft to "the same min
			// value", so a strictly tighter bound is a narrowing whatever its
			// inclusivity — provable, and therefore sound to accept. Profile
			// §9.1 records the reading.
			name:   "range: a strictly tighter bound narrows whatever its inclusivity",
			parent: aatGrant(t, oneArg(`{"constraint_type":"range","min":0,"min_inclusive":false,"max":100}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"range","min":5,"min_inclusive":true,"max":100}`)),
			want:   AttenuationAttenuated,
		},
		{
			// Exact rationals, never floats — the same rule why's decimal
			// ceilings follow.
			name:   "range: bounds compare as exact decimals",
			parent: aatGrant(t, oneArg(`{"constraint_type":"range","max":100}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"range","max":100.0}`)),
			want:   AttenuationUnchanged,
		},

		// ---- one_of ----
		{
			name:   "one_of: a subset attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a","/b","/c"]}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a"]}`)),
			want:   AttenuationAttenuated,
		},
		{
			name:           "one_of: an added value broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a","/b"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a","/z"]}`)),
			want:           AttenuationBroadened,
			reasonContains: `one_of admits "/z"`,
		},

		// ---- not_one_of ----
		{
			name:   "not_one_of: an added exclusion attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"not_one_of","excluded":["/secret"]}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"not_one_of","excluded":["/secret","/private"]}`)),
			want:   AttenuationAttenuated,
		},
		{
			name:           "not_one_of: a dropped exclusion broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"not_one_of","excluded":["/secret","/private"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"not_one_of","excluded":["/secret"]}`)),
			want:           AttenuationBroadened,
			reasonContains: `drops the parent's exclusion of "/private"`,
		},
		{
			// §4.5 names this cross-type pair invalid outright:
			// "Enforcement points MUST reject this cross-type pair."
			name:           "not_one_of: under a parent one_of is rejected outright",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a","/b"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"not_one_of","excluded":["/c"]}`)),
			want:           AttenuationBroadened,
			reasonContains: "accepts values outside the parent's permitted set",
		},

		// ---- contains ----
		{
			name:   "contains: an added requirement attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"contains","required":["read"]}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"contains","required":["read","audit"]}`)),
			want:   AttenuationAttenuated,
		},
		{
			name:           "contains: a dropped requirement broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"contains","required":["read","audit"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"contains","required":["read"]}`)),
			want:           AttenuationBroadened,
			reasonContains: `drops the parent's required element "audit"`,
		},

		// ---- subset ----
		{
			name:   "subset: a smaller allowed set attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"subset","allowed":["read","write"]}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"subset","allowed":["read"]}`)),
			want:   AttenuationAttenuated,
		},
		{
			name:           "subset: an added allowed element broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"subset","allowed":["read"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"subset","allowed":["read","delete"]}`)),
			want:           AttenuationBroadened,
			reasonContains: `subset admits "delete"`,
		},

		// ---- wildcard ----
		{
			name:   "wildcard: under a parent wildcard is unchanged",
			parent: aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:  aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			want:   AttenuationUnchanged,
		},
		{
			// §4.5: "A derived wildcard is valid only if the parent is also
			// wildcard." This is the constraint-level version of the whole
			// bug: dropping a restriction is not a delegation.
			name:           "wildcard: dropping the parent's constraint broadens",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"one_of","values":["/a"]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			want:           AttenuationBroadened,
			reasonContains: "drops the parent's one_of constraint entirely",
		},

		// ---- all ----
		{
			name: "all: keeping every parent clause and adding one attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a","/b"]}]}`)),
			child: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a"]},
				{"constraint_type":"not_one_of","excluded":["/z"]}]}`)),
			want: AttenuationAttenuated,
		},
		{
			name: "all: dropping a parent clause broadens",
			parent: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a","/b"]},
				{"constraint_type":"not_one_of","excluded":["/z"]}]}`)),
			child: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a"]}]}`)),
			want:           AttenuationBroadened,
			reasonContains: "no one-to-one assignment exists",
		},
		{
			// §4.5's matcher backtracks because a greedy match can dead-end.
			// Greedy pairs the parent's first clause with the derived one_of
			// ["/a"], which is then unavailable for the second; the only
			// working assignment is the other way round.
			name: "all: the clause matcher backtracks out of a greedy dead end",
			parent: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a","/b","/c"]},
				{"constraint_type":"one_of","values":["/a","/b"]}]}`)),
			child: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a"]},
				{"constraint_type":"one_of","values":["/c"]}]}`)),
			want: AttenuationAttenuated,
		},
		{
			// "a single derived clause MUST NOT be used to satisfy more than
			// one parent clause."
			name: "all: one derived clause cannot satisfy two parent clauses",
			parent: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a","/b"]},
				{"constraint_type":"one_of","values":["/a","/c"]}]}`)),
			child: aatGrant(t, oneArg(`{"constraint_type":"all","constraints":[
				{"constraint_type":"one_of","values":["/a"]}]}`)),
			want:           AttenuationBroadened,
			reasonContains: "distinct derived clause",
		},

		// ---- any ----
		{
			// §4.5's own example, verbatim: "a parent token carries
			// any([exact("pdf"), exact("csv"), exact("xlsx")]). A derived
			// token MAY carry any([exact("pdf"), exact("csv")])".
			name: "any: the draft's own permitted example attenuates",
			parent: aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[
				{"constraint_type":"exact","value":"pdf"},
				{"constraint_type":"exact","value":"csv"},
				{"constraint_type":"exact","value":"xlsx"}]}`)),
			child: aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[
				{"constraint_type":"exact","value":"pdf"},
				{"constraint_type":"exact","value":"csv"}]}`)),
			want: AttenuationAttenuated,
		},
		{
			// The same example's refusal: "A derived token MUST NOT carry
			// any([exact("pdf"), exact("docx")]) because exact("docx") is not
			// subsumed by any parent clause."
			name: "any: the draft's own refused example broadens",
			parent: aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[
				{"constraint_type":"exact","value":"pdf"},
				{"constraint_type":"exact","value":"csv"},
				{"constraint_type":"exact","value":"xlsx"}]}`)),
			child: aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[
				{"constraint_type":"exact","value":"pdf"},
				{"constraint_type":"exact","value":"docx"}]}`)),
			want:           AttenuationBroadened,
			reasonContains: "is not subsumed by any clause of the parent's any",
		},
		{
			// "Cross-type subsumption between clauses is permitted: for
			// example, a derived clause of exact("pdf") is subsumed by a
			// parent clause of one_of(["pdf", "csv"])."
			name: "any: cross-type clause subsumption is permitted",
			parent: aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[
				{"constraint_type":"one_of","values":["pdf","csv"]}]}`)),
			child: aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[
				{"constraint_type":"exact","value":"pdf"}]}`)),
			want: AttenuationAttenuated,
		},
		{
			name: "any: a derived any with no clauses is refused",
			parent: aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[
				{"constraint_type":"exact","value":"pdf"}]}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"any","constraints":[]}`)),
			want:           AttenuationBroadened,
			reasonContains: "requires at least one",
		},
	}
	runI4(t, cases)
}

// TestI4FailsClosed covers the conditions the draft answers with DENY rather
// than with a subsumption verdict. Every one of them lands on `broadened`,
// because that is v1's word for "this hop is broken" — routing them to
// `unknown` would leave the hop `verified`, which is the overclaim the whole
// change exists to close.
func TestI4FailsClosed(t *testing.T) {
	deep := `{"constraint_type":"wildcard"}`
	for i := 0; i < MaxConstraintDepth+4; i++ {
		deep = `{"constraint_type":"all","constraints":[` + deep + `]}`
	}

	cases := []struct {
		name           string
		parent, child  []Grant
		want           Attenuation
		reasonContains string
	}{
		{
			// §3.4: "Enforcement points MUST deny authorization if they
			// encounter a constraint_type they do not recognize."
			name:           "an unrecognised constraint_type is denied, not skipped",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"path_containment","root":"/data"}`)),
			want:           AttenuationBroadened,
			reasonContains: "is not one of the draft's nine core types",
		},
		{
			// §3.5.2: an enforcement point that does not implement a
			// registered extension type MUST deny rather than skip.
			name:           "an unimplemented extension type on the parent side is denied",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"path_containment","root":"/data"}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"exact","value":"/data/q3.pdf"}`)),
			want:           AttenuationBroadened,
			reasonContains: "no registered extension type",
		},
		{
			// §3.3: the entry "MUST include a tools member".
			name:           "a capability entry with no tools member is denied",
			parent:         aatGrant(t, `{"read_file":{}}`),
			child:          grants(t, `{"type":"attenuating_agent_token"}`),
			want:           AttenuationBroadened,
			reasonContains: `carries no "tools" member`,
		},
		{
			name:           "a tools member that is not an object is denied",
			parent:         aatGrant(t, `{"read_file":{}}`),
			child:          aatGrant(t, `"read_file"`),
			want:           AttenuationBroadened,
			reasonContains: "is not a JSON object",
		},
		{
			// §3.3.1: "An authorization_details entry containing duplicate
			// tool identifier keys is malformed and MUST be rejected."
			name:           "a duplicate tool identifier is malformed",
			parent:         aatGrant(t, `{"read_file":{}}`),
			child:          aatGrant(t, `{"read_file":{},"read_file":{}}`),
			want:           AttenuationBroadened,
			reasonContains: "twice",
		},
		{
			name:           "a constraint with no constraint_type is denied",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:          aatGrant(t, oneArg(`{"values":["/a"]}`)),
			want:           AttenuationBroadened,
			reasonContains: "carries no constraint_type",
		},
		{
			name:           "a one_of with no values member is denied",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"one_of"}`)),
			want:           AttenuationBroadened,
			reasonContains: `carries no "values" member`,
		},
		{
			name:           "a range bound that is a quoted string is not a number",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:          aatGrant(t, oneArg(`{"constraint_type":"range","max":"100"}`)),
			want:           AttenuationBroadened,
			reasonContains: "max is not a number",
		},
		{
			// The comparator bounds its own recursion at the draft's
			// RECOMMENDED MAX_CONSTRAINT_DEPTH; a tree past it cannot be
			// shown to narrow anything.
			name:           "a constraint tree past the depth ceiling cannot be proven a narrowing",
			parent:         aatGrant(t, oneArg(`{"constraint_type":"wildcard"}`)),
			child:          aatGrant(t, oneArg(deep)),
			want:           AttenuationBroadened,
			reasonContains: "nests deeper than 32",
		},
	}
	runI4(t, cases)
}

// TestI4MatchesTheDraftsWorkedExample runs §3.6.1's root token and §3.6.2's
// derived token against each other. The draft presents that pair as a
// conforming derivation, so it must read as an attenuation: the derived token
// narrows `read_file.path` from a two-value one_of to an exact, and drops
// `search_index` entirely.
func TestI4MatchesTheDraftsWorkedExample(t *testing.T) {
	root := aatGrant(t, `{
		"read_file": {"path": {"constraint_type":"one_of",
			"values": ["/data/q3-report.pdf", "/data/q4-report.pdf"]}},
		"search_index": {}
	}`)
	derived := aatGrant(t, `{
		"read_file": {"path": {"constraint_type":"exact","value":"/data/q3-report.pdf"}}
	}`)

	got, reason := CompareGrants(root, derived)
	if got != AttenuationAttenuated {
		t.Fatalf("the draft's own §3.6.1/§3.6.2 pair compares as %q (%s), want attenuated", got, reason)
	}
	// And the reverse is a broadening: the root does not narrow the derived.
	if got, _ := CompareGrants(derived, root); got != AttenuationBroadened {
		t.Fatalf("reversing the draft's pair compares as %q, want broadened", got)
	}
}

// TestI4ViolationNamesTheConstraint pins the structured half of a refusal —
// what Mint turns into a typed error. A sentence is not enough for a caller
// that has to decide which capability to drop.
func TestI4ViolationNamesTheConstraint(t *testing.T) {
	parent := aatGrant(t, `{"search_index":{"limit":{"constraint_type":"range","max":100}}}`)
	child := aatGrant(t, `{"search_index":{"limit":{"constraint_type":"range","max":1000}}}`)

	att, reason, v := CompareGrantsDetail(parent, child)
	if att != AttenuationBroadened {
		t.Fatalf("CompareGrantsDetail = %q (%s), want broadened", att, reason)
	}
	if v == nil {
		t.Fatal("a capability broadening produced no I4Violation")
	}
	if v.Tool != "search_index" || v.Argument != "limit" {
		t.Fatalf("violation names tool %q argument %q, want search_index/limit", v.Tool, v.Argument)
	}
	if v.ParentType != "range" || v.DerivedType != "range" {
		t.Fatalf("violation names types %q/%q, want range/range", v.ParentType, v.DerivedType)
	}
	if s := v.String(); !strings.Contains(s, "search_index") || !strings.Contains(s, "limit") {
		t.Fatalf("the rendered violation names neither tool nor argument: %q", s)
	}
	// A grant shape the draft does not define has no tool to name, so the
	// detail is absent rather than invented.
	_, _, v = CompareGrantsDetail(
		grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read"]}`),
		grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read","payouts.send"]}`))
	if v != nil {
		t.Fatalf("a v1-shaped broadening produced an I4Violation: %+v", v)
	}
}

// TestI4LeavesTheV1ComparatorAlone is the additive claim, asserted rather
// than assumed: no grant shape behalf actually uses is routed through the
// draft's rules, so no existing record can change verification state.
func TestI4LeavesTheV1ComparatorAlone(t *testing.T) {
	// A grant carrying a `tools` member but not the draft's type stays with
	// the v1 comparator, which reads its actions and nothing else.
	parent := grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read","refund.issue"],
	                      "tools":{"read_file":{}}}`)
	child := grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read"],
	                     "tools":{"read_file":{},"delete_file":{}}}`)
	if got, reason := CompareGrants(parent, child); got != AttenuationAttenuated {
		t.Fatalf("a non-draft grant type was routed through I4: %q (%s)", got, reason)
	}

	// And the proprietary-role vocabulary is still `unknown` here,
	// still flagged, still not reclassified into a finding it is not. D8.7
	// changed what internal/aat does with that answer — the hop is now
	// `asserted` rather than `verified` — and deliberately did not change the
	// answer itself: the comparator reports, it does not adjudicate.
	got, reason := CompareGrants(
		grants(t, deskRoot),
		grants(t, `{"type":"entra-roles","roles":["Directory.ReadWrite.All"]}`))
	if got != AttenuationUnknown {
		t.Fatalf("an uncomparable vocabulary now compares as %q, want unknown: D8.7 demoted the hop's "+
			"status, not the comparator's answer", got)
	}
	if !strings.Contains(reason, "entra-roles") {
		t.Fatalf("reason %q no longer names the uncomparable grant type", reason)
	}
}

// TestI4DoesNotHideTheOtherVocabulary pins the routing rule from the other
// side: a capability entry on a hop must not stop behalf's own comparison
// from running over the entries beside it.
//
// compareV1 answers `unknown` when EITHER side carries no
// authorization_details at all. Reading that guard as "no entries of this
// vocabulary" let a child keep its parent's capability entry byte for byte,
// bolt on a whole grant of behalf's own shape the parent never delegated,
// and be recorded `unchanged` — a broadening reported as nothing happening,
// which is the failure this whole file exists to prevent.
func TestI4DoesNotHideTheOtherVocabulary(t *testing.T) {
	const capEntry = `{"type":"attenuating_agent_token",
	                   "tools":{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"}}}}`

	runI4(t, []struct {
		name           string
		parent, child  []Grant
		want           Attenuation
		reasonContains string
	}{
		{
			// The hole. The capability half is identical; the child helps
			// itself to a vocabulary the parent carried none of.
			name:           "a vocabulary the parent carried none of is broadened",
			parent:         grants(t, capEntry),
			child:          grants(t, capEntry, deskHop),
			want:           AttenuationBroadened,
			reasonContains: `grant type "sh.behalf/support-desk" was never delegated`,
		},
		{
			// The same asymmetry as a dropped tool: authority given up.
			name:   "dropping the other vocabulary entirely is attenuation",
			parent: grants(t, capEntry, deskHop),
			child:  grants(t, capEntry),
			want:   AttenuationAttenuated,
		},
		{
			// A child that drops the capability entry has narrowed on that
			// axis and widened on this one. The broadening wins.
			name:           "dropping the capability entry does not license a new vocabulary",
			parent:         grants(t, capEntry),
			child:          grants(t, deskHop),
			want:           AttenuationBroadened,
			reasonContains: `grant type "sh.behalf/support-desk" was never delegated`,
		},
		{
			// Both vocabularies on both sides: v1 still decides its own half,
			// exactly as it did before the draft's rules arrived.
			name:   "both sides carry both: the v1 half still broadens",
			parent: grants(t, capEntry, deskHop),
			child: grants(t, capEntry,
				`{"type":"sh.behalf/support-desk","actions":["orders.read","refund.issue","payouts.send"],
				  "privileges":[{"operation":"refund.issue","limit":{"amount":"100.00","currency":"USD"}}]}`),
			want:           AttenuationBroadened,
			reasonContains: `action "payouts.send" was never delegated`,
		},
		{
			name:   "both sides carry both: the v1 half still narrows",
			parent: grants(t, capEntry, deskRoot),
			child:  grants(t, capEntry, deskHop),
			want:   AttenuationAttenuated,
		},
		{
			// Precedence: a capability broadening is still the finding, even
			// when the other vocabulary is untouched.
			name:   "a capability broadening outranks an unchanged v1 half",
			parent: grants(t, capEntry, deskHop),
			child: grants(t, deskHop,
				`{"type":"attenuating_agent_token",
				  "tools":{"read_file":{"path":{"constraint_type":"exact","value":"/data/q3.pdf"}},
				           "delete_file":{}}}`),
			want:           AttenuationBroadened,
			reasonContains: `tool "delete_file" was never delegated`,
		},
	})
}

func runI4(t *testing.T, cases []struct {
	name           string
	parent, child  []Grant
	want           Attenuation
	reasonContains string
}) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := CompareGrants(tc.parent, tc.child)
			if got != tc.want {
				t.Fatalf("CompareGrants = %q (%s), want %q", got, reason, tc.want)
			}
			if tc.reasonContains != "" && !strings.Contains(reason, tc.reasonContains) {
				t.Fatalf("reason %q does not mention %q", reason, tc.reasonContains)
			}
		})
	}
}

// TestI4SubsumptionIsAntisymmetricOnStrictNarrowings is a property check over
// the table above's building blocks: wherever a child strictly narrows a
// parent, reversing the pair must broaden. A subsumption relation that said
// yes in both directions would be unsound in one of them.
func TestI4SubsumptionIsAntisymmetricOnStrictNarrowings(t *testing.T) {
	pairs := [][2]string{
		{`{"constraint_type":"one_of","values":["/a","/b"]}`, `{"constraint_type":"one_of","values":["/a"]}`},
		{`{"constraint_type":"range","min":1,"max":100}`, `{"constraint_type":"range","min":10,"max":50}`},
		{`{"constraint_type":"not_one_of","excluded":["/x"]}`, `{"constraint_type":"not_one_of","excluded":["/x","/y"]}`},
		{`{"constraint_type":"contains","required":["read"]}`, `{"constraint_type":"contains","required":["read","audit"]}`},
		{`{"constraint_type":"subset","allowed":["read","write"]}`, `{"constraint_type":"subset","allowed":["read"]}`},
		{`{"constraint_type":"wildcard"}`, `{"constraint_type":"exact","value":"/a"}`},
	}
	for i, p := range pairs {
		t.Run(fmt.Sprintf("pair-%d", i), func(t *testing.T) {
			wide, narrow := aatGrant(t, oneArg(p[0])), aatGrant(t, oneArg(p[1]))
			if got, reason := CompareGrants(wide, narrow); got != AttenuationAttenuated {
				t.Fatalf("narrowing compares as %q (%s), want attenuated", got, reason)
			}
			if got, reason := CompareGrants(narrow, wide); got != AttenuationBroadened {
				t.Fatalf("the same pair reversed compares as %q (%s), want broadened", got, reason)
			}
		})
	}
}
