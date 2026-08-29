package htmlexport

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/behalf-sh/behalf/internal/diff"
	"github.com/behalf-sh/behalf/internal/why"
)

// DiffView is the comparison, led by the answer: which step diverged first,
// and the one later step the divergence can be SHOWN to have reached.
//
// The claims here are exactly the engine's claims, at exactly the engine's
// strength (internal/diff, causality.go): the first divergence is a fact
// about the alignment; the consequence is exhibited by value equality or it
// is not called a consequence; and the downstream suppression is a
// heuristic, labelled as one on the page, with every suppressed difference
// still listed further down. A rendering that quietly hardened any of those
// would be worse than no rendering.
type DiffView struct {
	RunA, RunB     string
	CountA, CountB int
	// Summary is the headline sentence.
	Summary string
	// Aligner names the tier that produced the pairing (Q85), so the reader
	// knows whether steps were matched by stored key or by sequence.
	Aligner     string
	AlignerNote string

	First    *DiffBlock
	Featured *DiffBlock
	// FeaturedIsFirst is true when the engine featured the first divergence
	// itself — there is nothing after it to show. Templates cannot compare
	// pointers, and this is the comparison they need.
	FeaturedIsFirst bool
	// FeaturedIsConsequence distinguishes the strong claim ("this value came
	// out of that step and went into this one") from the weak one ("a later
	// difference").
	FeaturedIsConsequence bool
	FeaturedTitle         string
	LinkText              string

	// All is every difference in aligned order, including the suppressed
	// ones. The default terminal view hides them behind a count; the page
	// has room to show them, and the suppression note still names the rule.
	All []DiffBlock
	// Opaque are the pairs whose only difference is a payload-slot digest:
	// the receipt records that customer-held content changed, not what
	// changed in it. Never named as a cause.
	Opaque []DiffBlock

	SuppressedCount int
	SuppressionNote string
	OpaqueNote      string

	// Warnings are the handoffs to `behalf why`: the featured step sits on a
	// receipt whose stored attribution is not `verified`.
	Warnings []DiffWarning
	// AttributionNote states a run-wide authority difference that the action
	// diff deliberately does not count.
	AttributionNote    string
	WeakestA, WeakestB string
}

// DiffWarning is one attribution handoff.
type DiffWarning struct {
	Operation string
	RunID     string
	Actor     string
	State     string
	Command   string
	// Unattributed is set when the receipt carries no delegation chain at
	// all, which is a different sentence from a weak one.
	Unattributed bool
}

// DiffBlock is one aligned pair that is not identical.
type DiffBlock struct {
	// Label is the step coordinate, showing both ordinals when alignment put
	// different ones opposite each other.
	Label string
	// RunA and RunB name the two runs, so the side-by-side columns are
	// headed by the thing they are rather than by "A" and "B".
	RunA      string
	RunB      string
	AnchorA   string
	AnchorB   string
	StepA     int // -1 when the pair has no counterpart on that side
	StepB     int
	Operation string
	Target    string
	Actor     string
	Classes   []string
	// Coords is where in the chain and how far into the run — "hop 3, t+60s".
	Coords string

	// Rows are the field-level findings, one per differing path.
	Rows []DiffRow
	// Reordered is the same-elements-different-sequence finding, which is
	// the divergence that reads as "nothing changed" to every other tool.
	Reordered *ReorderView

	// Missing names the run that has no counterpart step, for an insertion
	// or a deletion.
	MissingFrom string
	// Truncated is set when the pair carried more field-level changes than
	// the engine keeps.
	Truncated     bool
	NoiseFiltered []string
	// Opaque marks a digest-only difference.
	Opaque bool
	// Suppressed marks a difference the downstream heuristic hid from the
	// causal view.
	Suppressed bool
}

// DiffRow is one differing path, with both stored values.
type DiffRow struct {
	Path string
	A    string
	B    string
	// Kind is changed | only-in-A | only-in-B.
	Kind  string
	Class string
	// Gloss is a display convention the renderer added, never something the
	// bytes say — currently only the minor-units reading of a `_cents`
	// field. Stated separately so it can never be mistaken for stored data.
	GlossA string
	GlossB string
}

// ReorderView is the positional reading of a reordered array: the first
// position at which the two runs hold different elements, and the
// sub-fields of that element that actually differ.
type ReorderView struct {
	Path  string
	Count int
	Index int
	// Fields are the differing sub-fields, named once because both sides
	// show the same fields in the same order.
	Fields []string
	RowsA  []string
	RowsB  []string
	// GlossA and GlossB parallel Rows with the renderer's display
	// conventions, empty where none applies.
	GlossA []string
	GlossB []string
}

// buildDiffView projects a diff.Result into the page model.
func buildDiffView(res *diff.Result, aliases why.Aliases, anchors map[string]map[int]string) *DiffView {
	v := &DiffView{
		RunA:     res.RunA,
		RunB:     res.RunB,
		CountA:   res.CountA,
		CountB:   res.CountB,
		Aligner:  res.Aligner,
		WeakestA: res.WeakestA,
		WeakestB: res.WeakestB,
	}
	v.Summary = diffSummary(res)
	v.AlignerNote = alignerNote(res.Aligner)

	for i := range res.Differences {
		b := diffBlock(res, &res.Differences[i], aliases, anchors)
		v.All = append(v.All, b)
	}
	for i := range res.Opaque {
		b := diffBlock(res, &res.Opaque[i], aliases, anchors)
		b.Opaque = true
		v.Opaque = append(v.Opaque, b)
	}
	// First and Featured point INTO All so the page and the list agree
	// about the same block; the engine's pointers are into its own slice.
	for i := range res.Differences {
		if res.First == &res.Differences[i] {
			v.First = &v.All[i]
		}
		if res.Featured == &res.Differences[i] {
			v.Featured = &v.All[i]
		}
	}
	v.FeaturedIsFirst = v.Featured == nil || v.Featured == v.First
	v.FeaturedIsConsequence = res.FeaturedIsConsequence
	v.FeaturedTitle = "Later difference"
	if res.FeaturedIsConsequence {
		v.FeaturedTitle = "Consequence"
	}
	v.LinkText = linkText(res)
	v.SuppressedCount = res.SuppressedCount
	if res.SuppressedCount > 0 {
		v.SuppressionNote = fmt.Sprintf(
			"%d further difference%s %s presumed downstream of the first divergence and left out of the causal reading above. "+
				"They are listed in full under “every difference”.",
			res.SuppressedCount, plural(res.SuppressedCount), verb(res.SuppressedCount))
	}
	if n := len(res.Opaque); n > 0 {
		v.OpaqueNote = fmt.Sprintf(
			"%d further step%s differ only in a payload digest: the receipt records that customer-held content changed, "+
				"not what changed in it. These are never named as a cause.", n, plural(n))
	}
	v.Warnings = diffWarnings(res, aliases)
	if a, b := res.WeakestA, res.WeakestB; a != "" && b != "" && a != b {
		v.AttributionNote = fmt.Sprintf(
			"Attribution differs run-wide: %s is %s, %s is %s. That is authority, not action — "+
				"the comparison above deliberately does not count it, because a chain difference lands on every "+
				"receipt of the run and would make step 0 the first divergence of every such pair.",
			res.RunA, a, res.RunB, b)
	}
	return v
}

// diffSummary is the headline, computed from the alignment — the same
// sentence the terminal leads with, in prose rather than in columns.
func diffSummary(res *diff.Result) string {
	var head string
	if res.CountA == res.CountB {
		head = fmt.Sprintf("%d actions in both runs.", res.CountA)
	} else {
		head = fmt.Sprintf("%d actions in %s, %d in %s.", res.CountA, res.RunA, res.CountB, res.RunB)
	}
	switch n := len(res.Differences); {
	case n == 0:
		return head + " None differ."
	case n == 1:
		return head + " 1 differs."
	case n == 2:
		return head + " 2 differ. 1 caused the other."
	default:
		return fmt.Sprintf("%s %d differ. 1 caused the rest.", head, n)
	}
}

func alignerNote(aligner string) string {
	switch aligner {
	case diff.AlignerStepKey:
		return "Steps were paired on the stored step_key — a capture-time hash of tool name, " +
			"normalised argument schema and causal ordinal (Q85) — which required a perfect bijection between the two runs."
	case diff.AlignerSequence:
		return "The step keys did not line up one-to-one, so steps were paired by sequence alignment over " +
			"tool name, argument shape and ordinal proximity. Insertions and deletions are first-class in that pairing."
	case diff.AlignerBlocked:
		return "The runs were long enough that full sequence alignment was refused; pairing was decomposed on " +
			"unique step_key anchors and aligned within each block. A cheaper method was used and this line says so."
	default:
		return ""
	}
}

func diffBlock(res *diff.Result, d *diff.Difference, aliases why.Aliases, anchors map[string]map[int]string) DiffBlock {
	step := d.Pair.A
	if step == nil {
		step = d.Pair.B
	}
	b := DiffBlock{
		Label:         stepLabel(d),
		RunA:          res.RunA,
		RunB:          res.RunB,
		StepA:         -1,
		StepB:         -1,
		Operation:     step.Operation,
		Target:        step.Target,
		Actor:         aliases.Label(step.ActorJKT),
		Truncated:     d.Truncated,
		NoiseFiltered: d.NoiseFiltered,
		Suppressed:    d.Suppressed,
	}
	for _, c := range d.Classes {
		b.Classes = append(b.Classes, string(c))
	}
	if d.Pair.A != nil {
		b.StepA = d.Pair.A.Ordinal
		b.AnchorA = anchors[res.RunA][d.Pair.A.Ordinal]
	} else {
		b.MissingFrom = res.RunA
	}
	if d.Pair.B != nil {
		b.StepB = d.Pair.B.Ordinal
		b.AnchorB = anchors[res.RunB][d.Pair.B.Ordinal]
	} else {
		b.MissingFrom = res.RunB
	}
	b.Coords = blockCoords(res, d)

	for _, ch := range d.Changes {
		if ch.Kind == diff.KindReordered {
			b.Reordered = reorderView(ch)
			continue
		}
		row := DiffRow{
			Path:  ch.Path,
			Kind:  string(ch.Kind),
			Class: string(ch.Class),
			A:     valueText(ch.Path, ch.A),
			B:     valueText(ch.Path, ch.B),
		}
		row.GlossA = gloss(ch.Path, ch.A)
		row.GlossB = gloss(ch.Path, ch.B)
		b.Rows = append(b.Rows, row)
	}
	// An insertion or a deletion has nothing to compare against, so what the
	// reader wants is what the step that only exists on one side actually
	// did. The receipt's operation and target are already on the header
	// line; the rest comes off the stored payload.
	if len(b.Rows) == 0 && b.Reordered == nil && b.MissingFrom != "" {
		b.Rows = soloRows(step)
	}
	return b
}

// blockCoords is where in the delegation chain the acting hop sits, and how
// far into the run the step happened. Both are read from the receipt.
func blockCoords(res *diff.Result, d *diff.Difference) string {
	step, start := d.Pair.A, res.StartA
	if step == nil {
		step, start = d.Pair.B, res.StartB
	}
	var parts []string
	if step.HopCount > 0 {
		parts = append(parts, fmt.Sprintf("hop %d", step.HopCount))
	}
	if t := elapsed(start, step.CapturedAt); t != "" {
		parts = append(parts, t)
	}
	return strings.Join(parts, ", ")
}

func stepLabel(d *diff.Difference) string {
	switch {
	case d.Pair.A != nil && d.Pair.B != nil:
		if d.Pair.A.Ordinal == d.Pair.B.Ordinal {
			return fmt.Sprintf("step %d", d.Pair.A.Ordinal)
		}
		return fmt.Sprintf("step %d / %d", d.Pair.A.Ordinal, d.Pair.B.Ordinal)
	case d.Pair.A != nil:
		return fmt.Sprintf("step %d", d.Pair.A.Ordinal)
	default:
		return fmt.Sprintf("step %d", d.Pair.B.Ordinal)
	}
}

// soloRows reads the operation view straight off a step's stored payload,
// for the one case where there is no counterpart to diff against.
func soloRows(step *diff.Step) []DiffRow {
	var v struct {
		Operation struct {
			Name           string                     `json:"name"`
			Target         string                     `json:"target"`
			IdempotencyKey string                     `json:"idempotency_key"`
			Outcome        map[string]json.RawMessage `json:"outcome"`
		} `json:"operation"`
	}
	if json.Unmarshal(step.Payload, &v) != nil {
		return nil
	}
	var rows []DiffRow
	add := func(path string, raw json.RawMessage) {
		rows = append(rows, DiffRow{Path: path, Kind: "only", A: valueText(path, raw), GlossA: gloss(path, raw)})
	}
	if v.Operation.IdempotencyKey != "" {
		add("idempotency_key", jsonString(v.Operation.IdempotencyKey))
	}
	keys := make([]string, 0, len(v.Operation.Outcome))
	for k := range v.Operation.Outcome {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		add(k, v.Operation.Outcome[k])
	}
	return rows
}

// reorderView locates the first position at which two reordered arrays hold
// different elements, and the sub-fields of that element that differ. The
// field names are stated once because both sides show the same fields in
// the same order — which is what lets the two value rows read as columns.
func reorderView(ch diff.Change) *ReorderView {
	v := &ReorderView{Path: ch.Path, Count: ch.Count, Index: -1}
	if v.Path == "" {
		v.Path = "results"
	}
	var aa, ab []json.RawMessage
	if json.Unmarshal(ch.A, &aa) != nil || json.Unmarshal(ch.B, &ab) != nil {
		return v
	}
	i, va, vb, ok := firstDifferingElement(aa, ab)
	if !ok {
		return v
	}
	v.Index = i
	var oa, ob map[string]json.RawMessage
	if json.Unmarshal(va, &oa) != nil || json.Unmarshal(vb, &ob) != nil {
		// Not objects: the whole element is the finding.
		v.RowsA = []string{valueText(v.Path, va)}
		v.RowsB = []string{valueText(v.Path, vb)}
		v.GlossA = []string{""}
		v.GlossB = []string{""}
		return v
	}
	for _, k := range unionKeys(oa, ob) {
		if string(oa[k]) == string(ob[k]) {
			continue
		}
		v.Fields = append(v.Fields, k)
		v.RowsA = append(v.RowsA, valueText(k, oa[k]))
		v.RowsB = append(v.RowsB, valueText(k, ob[k]))
		v.GlossA = append(v.GlossA, gloss(k, oa[k]))
		v.GlossB = append(v.GlossB, gloss(k, ob[k]))
	}
	return v
}

// linkText states the value-equality evidence behind a consequence claim.
// It is derived, not decorative: the index is the array position the two
// runs disagreed at, and the values are the ones that actually travelled
// into the featured step's arguments.
func linkText(res *diff.Result) string {
	l, target := res.Link, res.Featured
	if l == nil || target == nil {
		return ""
	}
	step := target.Pair.A
	if step == nil {
		step = target.Pair.B
	}
	if l.Index >= 0 {
		return fmt.Sprintf("The agent used %s[%d] in both runs, and step %d carries it forward: %s here, %s there.",
			l.Path, l.Index, step.Ordinal, l.ValueA, l.ValueB)
	}
	return fmt.Sprintf("%s here, %s there — both carried into step %d.", l.ValueA, l.ValueB, step.Ordinal)
}

// diffWarnings is the handoff to `behalf why`: everything here is read out
// of the receipt — the stored rollup, the stored per-hop state, and a
// display label off the local alias map. No chain is recomputed.
func diffWarnings(res *diff.Result, aliases why.Aliases) []DiffWarning {
	d := res.Featured
	if d == nil {
		d = res.First
	}
	if d == nil {
		return nil
	}
	var out []DiffWarning
	for _, step := range []*diff.Step{d.Pair.A, d.Pair.B} {
		if step == nil || step.Attribution == "" || step.Attribution == "verified" {
			continue
		}
		w := DiffWarning{
			Operation: step.Operation,
			RunID:     step.RunID,
			Command:   "behalf why " + step.Address(),
		}
		if step.HopCount == 0 {
			w.Unattributed = true
			out = append(out, w)
			continue
		}
		w.Actor = aliases.Label(step.RootJKT)
		w.State = "unverified"
		if step.LeafHopStatus == "broken" {
			w.State = "broken"
		}
		out = append(out, w)
	}
	return out
}

// firstDifferingElement is the position at which two same-length arrays
// first hold different elements. Comparison is on canonical bytes, so a
// key-order difference inside an element is not a finding.
func firstDifferingElement(a, b []json.RawMessage) (int, json.RawMessage, json.RawMessage, bool) {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if canonEqual(a[i], b[i]) {
			continue
		}
		return i, a[i], b[i], true
	}
	return 0, nil, nil, false
}

func unionKeys(a, b map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for k := range a {
		seen[k] = true
		out = append(out, k)
	}
	for k := range b {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func verb(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}
