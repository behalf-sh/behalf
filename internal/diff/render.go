package diff

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/behalf-sh/behalf/internal/why"
)

// Layout. One summary line, then at most three blocks and two footers, so
// the answer to "which step caused it" is the first thing on screen and the
// evidence sits under it:
//
//	47 actions in both runs.  2 differ.  1 caused the other.
//
//	── first divergence ──────────────────────────── hop 3, t+60s
//	step 12   billing-agent → orders.search
//	          returned 2 orders, reordered (order_id, amount_cents)
//	   9f2a   [0] ord_5512  $12.00   → ok
//	   c71e   [0] ord_5518  $1200.00   → ok   ← different first result
//	          the agent used orders[0] in both runs; step 31 carries it.
//
//	── consequence ───────────────────────────────────────────
//	step 31   billing-agent → refund.issue(...)
//	   9f2a   amount=12.00  target=ord_5512  +3 more   → ok
//	   c71e   amount=1200.00  target=ord_5518  +3 more   → ok
//
//	── 39 downstream differences suppressed (--all to show) ──
//
//	⚠ refund.issue in run_c71e is attributed to alice@acme.com,
//	  but that hop is UNVERIFIED.        behalf why run_c71e:31
//
// Only the reordered block carries a descriptor line: its two run lines are
// columns of bare values, so something has to name the columns. Everywhere
// else the lines read `field=value` and a gloss would be the same finding
// printed twice.
const (
	ruleWidth  = 61 // rule length, after the two-space indent
	stepIndent = 12 // column the operation and its detail lines start at
	maxLine    = 78 // soft wrap budget for a side line
)

// ANSI attributes, used only when the destination is a terminal — the same
// set and the same discipline as `behalf why`.
const (
	ansiReset  = "\033[0m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
)

// Options controls rendering. Colour is opt-in and off by default so piped
// and captured output is plain text.
type Options struct {
	Color bool
	// All turns suppression off and lists every difference, grouped.
	All     bool
	Aliases why.Aliases
}

// ColorFor reports whether w should get ANSI colour. It is `behalf why`'s
// rule, reused rather than restated.
func ColorFor(w io.Writer) bool { return why.ColorFor(w) }

type painter struct{ on bool }

func (p painter) paint(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return code + s + ansiReset
}

// Render writes the diff.
func Render(w io.Writer, res *Result, opt Options) error {
	p := painter{on: opt.Color}
	aliases := opt.Aliases
	if aliases == nil {
		aliases = why.Aliases{}
	}
	var b strings.Builder

	b.WriteString("  " + p.paint(ansiBold, summaryLine(res)) + "\n")

	if res.First == nil {
		b.WriteString("\n  no divergence: every aligned step matches in operation, arguments\n")
		b.WriteString("  and outcome. only run-scoped fields differ, and those are filtered.\n")
		if opt.All && len(res.Opaque) > 0 {
			renderOpaqueList(&b, res, p, aliases, labelWidths(res))
		}
		b.WriteString(opaqueNote(res, p))
		b.WriteString(attributionNote(res))
		_, err := io.WriteString(w, b.String())
		return err
	}

	widths := labelWidths(res)
	if opt.All {
		renderAll(&b, res, p, aliases, widths)
	} else {
		renderCausal(&b, res, p, aliases, widths)
	}

	b.WriteString(opaqueNote(res, p))
	b.WriteString(attributionWarning(res, p, aliases))
	b.WriteString("\n")
	b.WriteString("  " + p.paint(ansiDim, "heuristic: the first difference in aligned order is named the cause,") + "\n")
	b.WriteString("  " + p.paint(ansiDim, "and every later difference is presumed downstream of it. --all shows") + "\n")
	b.WriteString("  " + p.paint(ansiDim, "every difference with suppression off.") + "\n")
	b.WriteString(attributionNote(res))

	_, err := io.WriteString(w, b.String())
	return err
}

// summaryLine is the headline, computed. Nothing here is a constant: the
// counts come from the alignment, and the causal clause appears only when
// there is in fact a first divergence with something after it.
func summaryLine(res *Result) string {
	var head string
	if res.CountA == res.CountB {
		head = fmt.Sprintf("%d actions in both runs.", res.CountA)
	} else {
		head = fmt.Sprintf("%d actions in %s, %d in %s.", res.CountA, res.RunA, res.CountB, res.RunB)
	}
	n := len(res.Differences)
	switch {
	case n == 0:
		return head + "  None differ."
	case n == 1:
		return head + "  1 differs."
	case n == 2:
		return head + "  2 differ.  1 caused the other."
	default:
		return fmt.Sprintf("%s  %d differ.  1 caused the rest.", head, n)
	}
}

func renderCausal(b *strings.Builder, res *Result, p painter, aliases why.Aliases, w widths) {
	b.WriteString("\n")
	b.WriteString("  " + p.paint(ansiBold, rule("first divergence", divergenceCoords(res))) + "\n")
	renderDifference(b, res, res.First, p, aliases, w, "", false)
	if res.Link != nil {
		b.WriteString(padTo("", stepIndent) + linkLine(res) + "\n")
	}

	if res.Featured != nil && res.Featured != res.First {
		title := "later difference"
		if res.FeaturedIsConsequence {
			title = "consequence"
		}
		b.WriteString("\n")
		b.WriteString("  " + p.paint(ansiBold, rule(title, "")) + "\n")
		renderDifference(b, res, res.Featured, p, aliases, w, "", false)
	}

	if res.SuppressedCount > 0 {
		b.WriteString("\n")
		title := fmt.Sprintf("%d downstream difference%s suppressed (--all to show)",
			res.SuppressedCount, plural(res.SuppressedCount))
		b.WriteString("  " + p.paint(ansiDim, rule(title, "")) + "\n")
	}
}

func renderAll(b *strings.Builder, res *Result, p painter, aliases why.Aliases, w widths) {
	b.WriteString("\n")
	b.WriteString("  " + p.paint(ansiBold, rule("all differences (suppression off)", "")) + "\n")
	for i := range res.Differences {
		d := &res.Differences[i]
		marker := classText(d.Classes)
		if d == res.First {
			marker = "first divergence · " + marker
		}
		if i > 0 {
			b.WriteString("\n")
		}
		renderDifference(b, res, d, p, aliases, w, marker, true)
		if d == res.First && res.Link != nil {
			b.WriteString(padTo("", stepIndent) + linkLine(res) + "\n")
		}
		if len(d.NoiseFiltered) > 0 {
			b.WriteString(padTo("", stepIndent) +
				p.paint(ansiDim, fmt.Sprintf("%d field%s ignored as run-scoped noise: %s",
					len(d.NoiseFiltered), plural(len(d.NoiseFiltered)), joinCapped(d.NoiseFiltered, 4))) + "\n")
		}
	}
	renderOpaqueList(b, res, p, aliases, w)
}

// renderOpaqueList is the --all listing of the pairs whose only difference
// is a digest. They are kept out of the main list because they cannot be
// explained, and kept in the output because they are true.
func renderOpaqueList(b *strings.Builder, res *Result, p painter, aliases why.Aliases, w widths) {
	if len(res.Opaque) == 0 {
		return
	}
	b.WriteString("\n")
	b.WriteString("  " + p.paint(ansiBold, rule("payload digest only", "")) + "\n")
	for i := range res.Opaque {
		if i > 0 {
			b.WriteString("\n")
		}
		renderDifference(b, res, &res.Opaque[i], p, aliases, w, "unexplained", true)
	}
}

// opaqueNote is the one-line report of the digest-only pairs in the default
// view: stated, counted, and honestly labelled as something the receipt
// cannot decompose.
func opaqueNote(res *Result, p painter) string {
	n := len(res.Opaque)
	if n == 0 {
		return ""
	}
	return "\n  " + p.paint(ansiDim, fmt.Sprintf(
		"%d further step%s differ only in a payload digest: the receipt records", n, plural(n))) + "\n" +
		"  " + p.paint(ansiDim, "that customer-held content changed, not what changed in it.") + "\n" +
		"  " + p.paint(ansiDim, "--all lists them.") + "\n"
}

// renderDifference writes one difference block: the step header, a
// descriptor of what differs, and one line per run.
func renderDifference(b *strings.Builder, res *Result, d *Difference, p painter, aliases why.Aliases, w widths, marker string, wrap bool) {
	step := d.Pair.A
	if step == nil {
		step = d.Pair.B
	}
	actor := aliases.Label(step.ActorJKT)

	head := padTo("  step "+stepNumbers(d), stepIndent) + actor + " → " + step.Operation
	if d.Has(ClassArguments) {
		head += "(...)"
	}
	// The class tag rides the header only in --all, where the blocks are a
	// list and need labelling; the causal view's section rules have already
	// said what each block is.
	if marker != "" {
		b.WriteString(padGap(head, 2+ruleWidth-utf8.RuneCountInString(marker), 2) + p.paint(ansiDim, marker) + "\n")
	} else {
		b.WriteString(head + "\n")
	}

	if desc := descriptor(d); desc != "" {
		b.WriteString(padTo("", stepIndent) + desc + "\n")
	}

	write := func(lines []string) {
		for _, l := range lines {
			b.WriteString(l + "\n")
		}
	}
	switch {
	case d.Pair.B == nil:
		write(sideLines(res.RunA, d, sideA, p, w, wrap))
		b.WriteString(padTo("", stepIndent) + p.paint(ansiYellow, "no counterpart in "+res.RunB) + "\n")
	case d.Pair.A == nil:
		b.WriteString(padTo("", stepIndent) + p.paint(ansiYellow, "no counterpart in "+res.RunA) + "\n")
		write(sideLines(res.RunB, d, sideB, p, w, wrap))
	default:
		write(sideLines(res.RunA, d, sideA, p, w, wrap))
		lines := sideLines(res.RunB, d, sideB, p, w, wrap)
		if m := orderMarker(d); m != "" {
			lines[len(lines)-1] += "   " + p.paint(ansiYellow, m)
		}
		write(lines)
	}
	if d.Truncated {
		b.WriteString(padTo("", stepIndent) +
			p.paint(ansiDim, fmt.Sprintf("(only the first %d field differences are shown)", maxChangesPerPair)) + "\n")
	}
}

// sideLines are one run's half of a difference: the fields that differ,
// with their stored values, and the operation's outcome. The first line
// carries the run label; any continuation lines (only in --all, which
// wraps rather than elides) are indented under it.
func sideLines(runID string, d *Difference, s side, p painter, w widths, wrap bool) []string {
	step := d.Pair.A
	if s == sideB {
		step = d.Pair.B
	}
	prefix := "     " + padTo(shortRun(runID), w.label) + "  "
	if step == nil {
		return []string{prefix + p.paint(ansiDim, "(absent)")}
	}

	suffix, plainSuffix := "", ""
	if st, ok := step.outcome.get("status"); ok {
		if text := scalarText(st); text != "" {
			plainSuffix = "   → " + text
			suffix = plainSuffix
			if text != "ok" {
				suffix = "   → " + p.paint(ansiRed, text)
			}
		}
	}

	budget := maxLine - utf8.RuneCountInString(prefix) - utf8.RuneCountInString(plainSuffix)
	var body []string
	if d.Has(ClassOnlyInA) || d.Has(ClassOnlyInB) {
		// An insertion or a deletion has no field-level changes to list —
		// there is nothing to compare it against. What the reader wants is
		// what the step that only exists here actually did.
		body = viewText(step.args, budget, wrap)
	} else {
		body = fieldsText(d, s, budget, wrap)
	}
	if len(body) == 0 {
		return []string{prefix + p.paint(ansiDim, "(no arguments recorded)") + suffix}
	}
	out := []string{prefix + body[0] + suffix}
	for _, more := range body[1:] {
		out = append(out, padTo("", stepIndent)+more)
	}
	return out
}

// fieldsText renders the fields that differ, for one side of a pair.
func fieldsText(d *Difference, s side, budget int, wrap bool) []string {
	// A reordered array renders positionally: only the element that moved,
	// and within it only the sub-fields that actually differ.
	for _, ch := range d.Changes {
		if ch.Kind != KindReordered {
			continue
		}
		if text, ok := reorderedElement(ch, s); ok {
			return []string{text}
		}
	}

	var items []item
	for _, ch := range d.Changes {
		// The operation's status already reads as the "→ ok" at the end of
		// the line; repeating it as status=ok is the same fact twice.
		if ch.Class == ClassOutcome && ch.Path == "status" {
			continue
		}
		raw := ch.A
		if s == sideB {
			raw = ch.B
		}
		if raw == nil {
			continue
		}
		items = append(items, newItem(ch.Path, raw, classRank(ch.Class)))
	}
	return packLines(items, budget, wrap)
}

// viewText renders a whole compared view rather than a set of changes. It
// is what an insertion or a deletion shows: that step has no counterpart to
// differ from, so what the reader needs is what it actually did.
func viewText(view fields, budget int, wrap bool) []string {
	var items []item
	for _, f := range view {
		if f.path == "operation" {
			continue // already on the header line
		}
		items = append(items, newItem(f.path, f.value, classRank(ClassArguments)))
	}
	return packLines(items, budget, wrap)
}

// item is one `field=value` chip on a run line.
type item struct {
	text   string
	opaque bool
	class  int
	path   string
}

func newItem(path string, raw json.RawMessage, class int) item {
	return item{path + "=" + formatValue(path, raw), isDigest(raw), class, path}
}

// packLines lays the chips out shortest first, so the scannable values lead
// and one long opaque field never crowds out three readable ones, with
// digests last.
//
// Two modes, and the difference between them is the whole point of --all:
// the default elides past the line budget with a truthful "+N more", while
// wrap mode continues onto further lines and hides nothing.
func packLines(items []item, budget int, wrap bool) []string {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].opaque != items[j].opaque {
			return !items[i].opaque
		}
		if len(items[i].text) != len(items[j].text) {
			return len(items[i].text) < len(items[j].text)
		}
		if items[i].class != items[j].class {
			return items[i].class < items[j].class
		}
		return items[i].path < items[j].path
	})

	var lines []string
	var parts []string
	used := 0
	flush := func() {
		if len(parts) > 0 {
			lines = append(lines, strings.Join(parts, "  "))
			parts, used = nil, 0
		}
	}
	for i, it := range items {
		cost := utf8.RuneCountInString(it.text)
		if len(parts) > 0 {
			cost += 2
		}
		// The "+N more" tail has to fit too: a line that runs over to admit
		// it is eliding something has elided the admission.
		tail := 0
		if !wrap && i < len(items)-1 {
			tail = len(fmt.Sprintf("  +%d more", len(items)-i-1))
		}
		if used+cost+tail > budget && len(parts) > 0 {
			if !wrap {
				lines = append(lines, strings.Join(parts, "  ")+fmt.Sprintf("  +%d more", len(items)-i))
				return lines
			}
			flush()
			cost = utf8.RuneCountInString(it.text)
		}
		used += cost
		parts = append(parts, it.text)
	}
	flush()
	return lines
}

// reorderedFields locates the first position at which two reordered arrays
// hold different elements, and the sub-fields of that element that actually
// differ. Both runs show the same fields in the same order — which is what
// lets the field NAMES be stated once, on the descriptor line, and the
// values line up as columns underneath.
func reorderedFields(ch Change) (index int, keys []string, a, b map[string]json.RawMessage, ok bool) {
	i, va, vb, ok := firstDifferingElement(ch.A, ch.B)
	if !ok {
		return 0, nil, nil, nil, false
	}
	var oa, ob map[string]json.RawMessage
	if json.Unmarshal(va, &oa) != nil || json.Unmarshal(vb, &ob) != nil {
		// Not objects: the whole element is the finding.
		return i, nil, nil, nil, true
	}
	for _, k := range unionKeys(oa, ob) {
		if string(oa[k]) != string(ob[k]) {
			keys = append(keys, k)
		}
	}
	// Identifiers first, then shortest. A magnitude on its own says nothing
	// without knowing which thing it belongs to, so the field that names the
	// element leads — and in stored data that field holds a string while the
	// measures hold numbers.
	width := func(k string) int {
		w := utf8.RuneCountInString(formatValue(k, oa[k]))
		if n := utf8.RuneCountInString(formatValue(k, ob[k])); n > w {
			w = n
		}
		return w
	}
	numeric := func(k string) bool {
		return jsonKind(oa[k]) != kindString && jsonKind(ob[k]) != kindString
	}
	sort.SliceStable(keys, func(x, y int) bool {
		if nx, ny := numeric(keys[x]), numeric(keys[y]); nx != ny {
			return !nx
		}
		if wx, wy := width(keys[x]), width(keys[y]); wx != wy {
			return wx < wy
		}
		return keys[x] < keys[y]
	})
	return i, keys, oa, ob, true
}

// reorderedElement renders one run's half of the moved element.
func reorderedElement(ch Change, s side) (string, bool) {
	i, keys, oa, ob, ok := reorderedFields(ch)
	if !ok {
		return "", false
	}
	mine := oa
	if s == sideB {
		mine = ob
	}
	if len(keys) == 0 {
		_, va, vb, _ := firstDifferingElement(ch.A, ch.B)
		raw := va
		if s == sideB {
			raw = vb
		}
		return fmt.Sprintf("[%d] %s", i, formatValue(ch.Path, raw)), true
	}
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		v, present := mine[k]
		if !present {
			parts = append(parts, "(absent)")
			continue
		}
		parts = append(parts, formatValue(k, v))
	}
	return fmt.Sprintf("[%d] %s", i, strings.Join(parts, "  ")), true
}

// orderMarker points at the moved element on the second run's line.
func orderMarker(d *Difference) string {
	for _, ch := range d.Changes {
		if ch.Kind != KindReordered {
			continue
		}
		i, _, _, ok := firstDifferingElement(ch.A, ch.B)
		if !ok {
			continue
		}
		if i == 0 {
			return "← different first result"
		}
		return fmt.Sprintf("← differs at [%d]", i)
	}
	return ""
}

// descriptor is the one-line statement above the two run lines. It exists
// for exactly one case: a reordering, where the two lines are columns of
// bare values and something has to name the columns. Every other kind of
// difference renders as `field=value` on both lines and needs no gloss —
// restating it here would be the same finding printed twice.
func descriptor(d *Difference) string {
	for _, ch := range d.Changes {
		if ch.Kind != KindReordered {
			continue
		}
		name := ch.Path
		if name == "" {
			name = "results"
		}
		line := fmt.Sprintf("returned %d %s, reordered", ch.Count, name)
		if _, keys, _, _, ok := reorderedFields(ch); ok && len(keys) > 0 {
			line += " (" + joinCapped(keys, 4) + ")"
		}
		return line
	}
	return ""
}

// linkLine states the value-equality evidence behind the consequence claim.
// It is derived, not decorative: Link.Index is the array position the two
// runs disagreed at, and Link.ValueA / ValueB are the values that actually
// travelled from that position into the featured step's arguments.
func linkLine(res *Result) string {
	l, target := res.Link, res.Featured
	if l == nil || target == nil {
		return ""
	}
	step := target.Pair.A
	if step == nil {
		step = target.Pair.B
	}
	if l.Index >= 0 {
		return fmt.Sprintf("the agent used %s[%d] in both runs; step %d carries it forward.",
			l.Path, l.Index, step.Ordinal)
	}
	return fmt.Sprintf("%s here, %s there — both carried into step %d.", l.ValueA, l.ValueB, step.Ordinal)
}

// attributionWarning is the handoff to `behalf why`: when the step this
// diff features sits on a receipt whose STORED attribution is not
// `verified`, say so and name the command that explains it. Everything here
// is read out of the receipt — the stored rollup, the stored per-hop state,
// and a display label off the local alias map. No chain is recomputed.
func attributionWarning(res *Result, p painter, aliases why.Aliases) string {
	d := res.Featured
	if d == nil {
		d = res.First
	}
	if d == nil {
		return ""
	}
	var out strings.Builder
	for _, step := range []*Step{d.Pair.A, d.Pair.B} {
		if step == nil || step.Attribution == "" || step.Attribution == "verified" {
			continue
		}
		cmd := "behalf why " + step.Address()
		if step.HopCount == 0 {
			out.WriteString("\n  " + p.paint(ansiYellow, "⚠ ") +
				fmt.Sprintf("%s in %s carries no delegation chain:", step.Operation, step.RunID) + "\n")
			out.WriteString(padTo("    attribution is unattributed.", 2+ruleWidth-len(cmd)) + cmd + "\n")
			continue
		}
		state := "UNVERIFIED"
		if step.LeafHopStatus == "broken" {
			state = "BROKEN"
		}
		out.WriteString("\n  " + p.paint(ansiYellow, "⚠ ") +
			fmt.Sprintf("%s in %s is attributed to %s,", step.Operation, step.RunID, aliases.Label(step.RootJKT)) + "\n")
		line := "    but that hop is " + p.paint(ansiYellow, state) + "."
		plain := "    but that hop is " + state + "."
		out.WriteString(padPlain(line, plain, 2+ruleWidth-len(cmd)) + cmd + "\n")
	}
	return out.String()
}

// attributionNote states the run-wide authority difference that the action
// diff deliberately does not count. Two runs can be identical in every
// action and still differ in who could prove they authorised them; saying
// "2 differ" and stopping would be the more misleading answer.
func attributionNote(res *Result) string {
	a, b := res.WeakestA, res.WeakestB
	if a == "" || b == "" || a == b {
		return ""
	}
	return fmt.Sprintf("\n  note: attribution differs run-wide — %s %s, %s %s.\n"+
		"  that is authority, not action. see behalf why.\n",
		res.RunA, a, res.RunB, b)
}

// divergenceCoords is the right half of the first-divergence rule: where in
// the delegation chain the acting hop sits, and how far into the run the
// step happened. Both are read from the stored receipt.
func divergenceCoords(res *Result) string {
	step := res.First.Pair.A
	start := res.StartA
	if step == nil {
		step, start = res.First.Pair.B, res.StartB
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

// elapsed renders the offset from a run's first capture to this step's.
func elapsed(from, to string) string {
	a, errA := time.Parse(time.RFC3339, from)
	b, errB := time.Parse(time.RFC3339, to)
	if errA != nil || errB != nil {
		return ""
	}
	d := b.Sub(a)
	switch {
	case d < 0:
		return ""
	case d < time.Second:
		return fmt.Sprintf("t+%dms", d.Milliseconds())
	case d < 90*time.Second:
		if d%time.Second == 0 {
			return fmt.Sprintf("t+%ds", int(d.Seconds()))
		}
		return fmt.Sprintf("t+%.1fs", d.Seconds())
	default:
		m := int(d / time.Minute)
		s := int((d % time.Minute) / time.Second)
		return fmt.Sprintf("t+%dm%02ds", m, s)
	}
}

// formatValue renders one stored value for display.
//
// Two display conventions, both documented because both are the renderer
// adding something the bytes do not say:
//
//   - a field whose name ends in _cents holds money in minor units, and is
//     shown as a currency amount. The receipts store integer cents on
//     purpose (so a decimal string never appears where it should not), and
//     showing 120000 to a human reading a refund diff would be a worse lie
//     than showing $1200.00.
//   - a 64-hex digest is shown short. Printing them whole is how a diff
//     turns into a wall.
func formatValue(path string, raw json.RawMessage) string {
	if isDigest(raw) {
		s, _ := jsonString(raw)
		return "sha256:" + s[:6] + "…"
	}
	if strings.HasSuffix(leafKey(path), "_cents") {
		if n, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
			return money(n)
		}
	}
	text := scalarText(raw)
	if text == "" {
		text = string(raw)
	}
	const maxValue = 44
	if utf8.RuneCountInString(text) > maxValue {
		r := []rune(text)
		return string(r[:maxValue]) + fmt.Sprintf("…(%d bytes)", len(raw))
	}
	return text
}

func money(cents int64) string {
	sign := ""
	if cents < 0 {
		sign, cents = "-", -cents
	}
	return fmt.Sprintf("%s$%d.%02d", sign, cents/100, cents%100)
}

func isDigest(raw json.RawMessage) bool {
	s, ok := jsonString(raw)
	if !ok || len(s) != 64 {
		return false
	}
	for _, c := range s {
		if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
			return false
		}
	}
	return true
}

// widths holds the per-render column sizes derived from the run names.
type widths struct{ label int }

func labelWidths(res *Result) widths {
	w := widths{label: 4}
	for _, id := range []string{res.RunA, res.RunB} {
		if n := utf8.RuneCountInString(shortRun(id)); n > w.label {
			w.label = n
		}
	}
	return w
}

// shortRun is the run id as the side column shows it: run_9f2a -> 9f2a.
func shortRun(runID string) string {
	return strings.TrimPrefix(runID, "run_")
}

// stepNumbers names the step, per side, and shows both when alignment put
// different ordinals opposite each other.
func stepNumbers(d *Difference) string {
	switch {
	case d.Pair.A != nil && d.Pair.B != nil:
		if d.Pair.A.Ordinal == d.Pair.B.Ordinal {
			return strconv.Itoa(d.Pair.A.Ordinal)
		}
		return strconv.Itoa(d.Pair.A.Ordinal) + "/" + strconv.Itoa(d.Pair.B.Ordinal)
	case d.Pair.A != nil:
		return strconv.Itoa(d.Pair.A.Ordinal) + "/—"
	default:
		return "—/" + strconv.Itoa(d.Pair.B.Ordinal)
	}
}

func classText(cs []Class) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, string(c))
	}
	return strings.Join(parts, ", ")
}

func classRank(c Class) int {
	for i, got := range classOrder {
		if got == c {
			return i
		}
	}
	return len(classOrder)
}

// rule draws a section rule, optionally with a right-hand coordinate.
func rule(title, right string) string {
	n := ruleWidth - 3 - utf8.RuneCountInString(title) - 1
	if right != "" {
		n -= utf8.RuneCountInString(right) + 1
	}
	if n < 3 {
		n = 3
	}
	out := "── " + title + " " + strings.Repeat("─", n)
	if right != "" {
		out += " " + right
	}
	return out
}

func joinCapped(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(", +%d more", len(items)-max)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// padTo left-aligns s in a field of width columns, adding a single space
// when the value is already wider rather than breaking the column.
func padTo(s string, width int) string { return padPlain(s, s, width) }

// padGap is padTo with a floor on the gap, for a column whose left half can
// legitimately overflow: a long operation name pushes the right-hand tag
// out rather than colliding with it.
func padGap(s string, width, minGap int) string {
	out := padPlain(s, s, width)
	if n := utf8.RuneCountInString(s); n+minGap > width {
		out = s + strings.Repeat(" ", minGap)
	}
	return out
}

// padPlain pads s to width, measuring plain (the same text without ANSI
// escapes) so colour never shifts the grid.
func padPlain(s, plain string, width int) string {
	n := utf8.RuneCountInString(plain)
	if n >= width {
		return s + " "
	}
	return s + strings.Repeat(" ", width-n)
}
