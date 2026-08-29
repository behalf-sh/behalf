package diff

import "encoding/json"

// The causal reading, and the exact size of the claim it makes.
//
// v1 has two rules and they are not the same strength, which is why the
// render labels them differently.
//
//  1. FIRST DIVERGENCE — the first difference in aligned order. This is a
//     fact about the alignment, not a claim about the world.
//
//  2. DOWNSTREAM SUPPRESSION — a heuristic, stated as one on screen and
//     here: everything after the first divergence is PRESUMED downstream of
//     it. There is no dataflow tracer behind this and v1 does not pretend
//     otherwise; `--all` is the escape hatch, and the render never prints
//     the word "suppressed" without the heuristic note beside it.
//
//  3. CONSEQUENCE — the one downstream step the render features. This is
//     the strongest claim the package makes and it is only made when it can
//     be SHOWN: a differing step whose differing argument values are
//     traceable to the first divergence's differing result values by value
//     equality. `ord_5518` came back from the search and `ord_5518` went
//     into the refund, so the link is exhibited, not asserted. When no such
//     link exists the render shows the last differing step and calls it a
//     "later difference" — never a consequence.
//
// What rule 3 deliberately is not: a dataflow tracer, a taint analysis, or
// anything that would let the output say "step 12 caused step 31" as a
// proven fact. It says "this value came out of step 12 and went into step
// 31", which is what the stored data can support.
//
// # Which linked step gets featured, and why that changed
//
// Rule 3 used to take the LATEST linked step, on the reasoning that the
// furthest-downstream reach of the divergence is the most it can be shown to
// have done. That reasoning holds when exactly one step carries the value
// forward. It fails as soon as the value really propagates — which is the
// normal case for a wrong selection, and is what the demo pair now records.
// In a session where the wrongly-selected order flows through eighteen later
// calls, the latest of them is whichever bookkeeping call the agent happened
// to make last: on the demo pair that is an `orders.read` at step 33, and
// featuring it buries the $1200 refund at step 31 under a step that read a
// row. "Latest" is a proxy for "worst", and the moment there is more than
// one candidate it stops being a good one.
//
// So the featured step is the HIGHEST-RISK linked step, ties broken by the
// latest. The risk class is the capture-time tool policy's assignment (Q6) —
// read from the receipt, never recomputed here, never compared as a
// difference (it stays in NotCompared) — and it is precisely the operator's
// own record of which actions matter. Only the classes v1 names are ranked;
// a policy with a vocabulary this package does not know ranks flat and the
// rule degrades to the old latest-wins, which is the honest failure.
//
// This does not widen the claim. Every candidate considered here is one the
// value-equality link already proved the divergence reached; the change is
// only which of them the render leads with.

// minLinkValueLen is the shortest value that may carry a causal link. Two
// runs sharing the string "ok" or "1" is a coincidence, not a lineage, and
// a link built on one would be the feature's most embarrassing failure.
const minLinkValueLen = 3

// analyzeCausality fills in First, Featured, Link and SuppressedCount.
func analyzeCausality(res *Result) {
	if len(res.Differences) == 0 {
		return
	}
	res.First = &res.Differences[0]
	for i := 1; i < len(res.Differences); i++ {
		res.Differences[i].Suppressed = true
	}
	if len(res.Differences) == 1 {
		return
	}

	linkA, linkB := carriedValues(res.First)
	// Walk latest first and keep the highest-risk link, so a tie keeps the
	// latest step and the old behaviour survives wherever risk says nothing.
	best := -1
	for i := len(res.Differences) - 1; i >= 1; i-- {
		d := &res.Differences[i]
		link, ok := linkTo(linkA, linkB, d)
		if !ok {
			continue
		}
		if best < 0 || riskOf(d) > riskOf(&res.Differences[best]) {
			best = i
			res.Link = link
		}
	}
	if best >= 0 {
		res.Featured = &res.Differences[best]
		res.FeaturedIsConsequence = true
	} else {
		// Nothing links. On customer-held data this is the normal case, not
		// the edge one: the arguments and results live in the customer's own
		// store, so the diff sees digests and there are no values to match.
		// Taking the last difference then features whatever bookkeeping call
		// the agent happened to make on the way out — a session summary
		// rather than the refund that mattered. Rank by risk here too, ties
		// to the latest, so the most consequential difference leads. It is
		// still only a later difference, never called a consequence: with
		// nothing but digests the causal link genuinely cannot be shown.
		best = len(res.Differences) - 1
		for i := len(res.Differences) - 2; i >= 1; i-- {
			if riskOf(&res.Differences[i]) > riskOf(&res.Differences[best]) {
				best = i
			}
		}
		res.Featured = &res.Differences[best]
	}
	res.Featured.Suppressed = false

	for i := range res.Differences {
		if res.Differences[i].Suppressed {
			res.SuppressedCount++
		}
	}
}

// riskRanks orders the capture-time risk classes v1 names, for the one
// purpose of choosing between linked candidates. An unlisted class ranks 0 —
// the same as no class at all — because guessing where a bespoke vocabulary
// sits would be worse than not ranking it. Nothing here is compared, stored
// or rendered: it only decides which true statement leads.
var riskRanks = map[string]int{"low": 1, "medium": 2, "high": 3, "critical": 4}

// riskOf is the pair's risk class, taken as the higher of the two sides. The
// two runs are one script under one policy, so they agree in practice; when
// they do not, the louder assignment is the one to answer for.
func riskOf(d *Difference) int {
	rank := 0
	for _, s := range []*Step{d.Pair.A, d.Pair.B} {
		if s == nil {
			continue
		}
		if r := riskRanks[s.RiskClass]; r > rank {
			rank = r
		}
	}
	return rank
}

// carrier is the set of values one side of the first divergence produced,
// keyed by the path they came from so the render can name it.
type carrier struct {
	path   string
	index  int // element position for a reordered array, else -1
	values map[string]bool
}

// carriedValues extracts, per run, the values the first divergence's
// differing RESULT could have handed to a later step.
//
// For a reordered array the extraction is positional and deliberately so:
// the elements are the same on both sides, so the only thing that differs
// is which one sits where the agent looked. Taking the leaves of the first
// differing INDEX is what makes the demo's "the agent used orders[0] in both
// runs" a derived statement rather than a decorative one.
func carriedValues(first *Difference) (a, b []carrier) {
	changes := classChanges(first.Changes, ClassResult)
	if len(changes) == 0 {
		// A first divergence with no result difference at all still has
		// values: fall back to everything it changed.
		changes = first.Changes
	}
	for _, ch := range changes {
		if ch.Kind == KindReordered {
			i, va, vb, ok := firstDifferingElement(ch.A, ch.B)
			if !ok {
				continue
			}
			la, lb := map[string]bool{}, map[string]bool{}
			leaves(va, la)
			leaves(vb, lb)
			a = append(a, carrier{path: ch.Path, index: i, values: la})
			b = append(b, carrier{path: ch.Path, index: i, values: lb})
			continue
		}
		la, lb := map[string]bool{}, map[string]bool{}
		leaves(ch.A, la)
		leaves(ch.B, lb)
		a = append(a, carrier{path: ch.Path, index: -1, values: la})
		b = append(b, carrier{path: ch.Path, index: -1, values: lb})
	}
	return a, b
}

// firstDifferingElement finds the first index at which two reordered arrays
// hold different elements.
func firstDifferingElement(rawA, rawB json.RawMessage) (int, json.RawMessage, json.RawMessage, bool) {
	ca, errA := canon(rawA)
	cb, errB := canon(rawB)
	if errA != nil || errB != nil {
		return 0, nil, nil, false
	}
	var aa, ab []json.RawMessage
	if json.Unmarshal(ca, &aa) != nil || json.Unmarshal(cb, &ab) != nil {
		return 0, nil, nil, false
	}
	n := len(aa)
	if len(ab) < n {
		n = len(ab)
	}
	for i := 0; i < n; i++ {
		if string(aa[i]) != string(ab[i]) {
			return i, aa[i], ab[i], true
		}
	}
	return 0, nil, nil, false
}

// linkTo tests one candidate downstream step for a value-equality link back
// to the first divergence.
//
// The test is deliberately two-sided and asymmetric-checked. A value v must
// (a) be one of the values run A's first divergence produced, (b) appear in
// run A's arguments at the candidate step, and (c) NOT be among the values
// run B produced — otherwise it is a value both runs saw and its presence
// downstream explains nothing. The mirror image must hold for run B, and
// the two values must differ. That is what makes the link an explanation of
// the divergence rather than an observation that both runs mention "USD".
func linkTo(carriersA, carriersB []carrier, d *Difference) (*Link, bool) {
	if d.Pair.A == nil || d.Pair.B == nil {
		return nil, false
	}
	argsA := changeValues(d.Changes, ClassArguments, sideA)
	argsB := changeValues(d.Changes, ClassArguments, sideB)
	if len(argsA) == 0 || len(argsB) == 0 {
		return nil, false
	}
	for k := range carriersA {
		ca, cb := carriersA[k], carriersB[k]
		v, okA := pickLink(ca.values, cb.values, argsA)
		w, okB := pickLink(cb.values, ca.values, argsB)
		if okA && okB && v != w {
			return &Link{Path: ca.path, Index: ca.index, ValueA: v, ValueB: w}, true
		}
	}
	return nil, false
}

// pickLink finds a value that is in mine, not in theirs, and used by the
// candidate step. Deterministic: the longest such value wins, with ties
// broken lexically, so the answer does not depend on map iteration order.
func pickLink(mine, theirs, used map[string]bool) (string, bool) {
	best := ""
	for v := range mine {
		if len(v) < minLinkValueLen || theirs[v] || !used[v] {
			continue
		}
		if len(v) > len(best) || (len(v) == len(best) && v < best) {
			best = v
		}
	}
	return best, best != ""
}

type side int

const (
	sideA side = iota
	sideB
)

// changeValues collects the scalar values one side of a pair's changes
// carries, within one class.
func changeValues(changes []Change, class Class, s side) map[string]bool {
	out := map[string]bool{}
	for _, ch := range changes {
		if ch.Class != class {
			continue
		}
		if s == sideA {
			leaves(ch.A, out)
		} else {
			leaves(ch.B, out)
		}
	}
	return out
}

func classChanges(changes []Change, class Class) []Change {
	var out []Change
	for _, ch := range changes {
		if ch.Class == class {
			out = append(out, ch)
		}
	}
	return out
}
