package diff

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// A synthetic corpus generator, not a directory of checked-in blobs.
//
// The known failure mode for run-vs-run diff is an alignment that works
// beautifully on the two curated demo runs and falls apart the first time a
// real agent retries a call. Curated fixtures cannot catch that, because the
// thing being tested is behaviour on inputs nobody thought to curate. So the
// corpus is generated, deliberately hostile, and asserted on the SHAPE of
// the result — counts, classifications, no panic — rather than on golden
// text, which would just be a second way of overfitting.

// call is one synthetic tool call.
type call struct {
	tool   string
	target string
	// argFields are extra per-argument evidence, as a field-digest manifest
	// (Q37). Adding one changes the argument shape without changing the
	// tool, which is how an agent version bump usually looks.
	argFields map[string]string
	result    map[string]any
	status    string
	// shape is folded into step_key alongside tool and ordinal, standing in
	// for Q85's "normalized argument schema".
	shape string
	// opaqueOutput perturbs the OUTPUT slot's digest and nothing else: the
	// raw response changed in a way the receipt's outcome does not record,
	// because the content is customer-held (Q34–Q38).
	opaqueOutput string
	// meta stands in for the MCP `_meta` envelope the proxy forwards beside
	// a tool's real arguments — the delegation chain and the W3C baggage
	// that carries behalf-run-id. It differs between any two runs.
	meta string
	// counter overrides the emitter counter. On recorded data two runs share
	// one monotonic per-emitter counter, so run B starts where run A ended.
	counter int
	// risk is the capture-time tool policy's class (Q6). It is never
	// compared; it decides which of several linked steps is featured as the
	// consequence (causality.go).
	risk string
}

// synth projects a list of calls into a run.
func synth(t *testing.T, runID string, calls []call) []Step {
	t.Helper()
	start := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	steps := make([]Step, 0, len(calls))
	for i, c := range calls {
		payload := synthReceipt(runID, i, start.Add(time.Duration(i)*time.Second), c)
		s, err := NewStep(runID, i, uint64(i), "", payload)
		if err != nil {
			t.Fatalf("synth %s step %d: %v", runID, i, err)
		}
		steps = append(steps, s)
	}
	return steps
}

func synthReceipt(runID string, i int, at time.Time, c call) []byte {
	status := c.status
	if status == "" {
		status = "ok"
	}
	shape := c.shape
	if shape == "" {
		shape = "v1"
	}
	outcome := map[string]any{"status": status}
	for k, v := range c.result {
		outcome[k] = v
	}
	// The input slot's digest covers the params object AS FORWARDED, `_meta`
	// and all — which is exactly why the comparison never looks at it. The
	// per-field manifest below is the comparable cut.
	params := map[string]any{
		"name": c.tool,
		"arguments": map[string]any{
			"tool": c.tool, "target": c.target, "shape": shape,
		},
		"_meta": map[string]any{"baggage": "behalf-run-id=" + runID},
	}
	input := map[string]any{
		"role": "input", "digest": digest(params), "custody": "customer-held", "state": "present",
	}
	// The manifest pins the real arguments per field, plus the forwarding
	// envelope the filter has to drop.
	manifest := map[string]string{
		"$.arguments.tool":   c.tool,
		"$.arguments.target": c.target,
	}
	if c.meta != "" {
		manifest["$._meta.baggage"] = c.meta
	}
	for k, v := range c.argFields {
		manifest[k] = v
	}
	fields := make([]any, 0, len(manifest))
	for _, k := range sortedKeys(manifest) {
		fields = append(fields, map[string]any{"path": k, "digest": hashOf(manifest[k])})
	}
	input["field_digest_manifest"] = map[string]any{"fields": fields}

	output := map[string]any{
		"role": "output", "digest": hashOf(digest(outcome) + c.opaqueOutput),
		"custody": "customer-held", "state": "present",
	}

	hop := func(depth int, jwkX string) map[string]any {
		return map[string]any{
			"del_depth": depth, "del_max_depth": 3,
			"cnf":          map[string]any{"jwk": map[string]any{"kty": "OKP", "crv": "Ed25519", "x": jwkX}},
			"verification": map[string]any{"status": "verified", "method": "aat-jws-ed25519"},
		}
	}
	r := map[string]any{
		"schema_version": "behalf.sh/receipt/v1",
		"receipt_id":     ulidLike(runID, i),
		"kind":           "tool_call",
		"risk_class":     c.risk,
		"captured_at":    at.Format(time.RFC3339),
		"emitter":        map[string]any{"jkt": "emitter", "surface": "mcp-proxy", "counter": c.counter + i},
		"actor":          map[string]any{"jkt": "actor-key", "labels": map[string]any{"client_name": "synth-agent"}},
		"operation":      map[string]any{"name": c.tool, "target": c.target, "outcome": outcome},
		"run_id":         runID,
		"correlation":    map[string]any{"session_id": "sess-" + runID},
		"step_key":       hashOf(c.tool + "\nargschema:" + shape + "\n" + itoa(i)),
		"authority": map[string]any{"chain": []any{
			hop(0, "IKSExFn4jLtkWGd6xUkob2mFRgh0iyTH77ZpAGHSbNg"),
			hop(1, "OokF63diIPLm2dNl_V9UHTYAneeOLc9szF1JPfaTU_4"),
			hop(2, "p2hWpXUzaCQgq3O0M5lifs8l5iGZQ9Wr4eN9hfQ4szk"),
		}},
		"attribution": map[string]any{"verification": "verified", "class": "delegated"},
		"payload":     []any{input, output},
		"provenance":  map[string]any{"source": "native"},
	}
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}
	return b
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

func digest(v any) string {
	b, _ := json.Marshal(v)
	return hashOf(string(b))
}

// ulidLike mints a value shaped like the client-minted ULID a receipt id
// really is (Q46), so the noise filter is exercised on realistic shapes.
func ulidLike(runID string, i int) string {
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
	sum := sha256.Sum256([]byte(runID + "/" + itoa(i)))
	out := make([]byte, 26)
	for k := range out {
		out[k] = alphabet[int(sum[k%len(sum)])%len(alphabet)]
	}
	return string(out)
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// tools cycles a plausible support-desk toolset, so consecutive steps never
// share a tool name and the aligner cannot get the right answer by accident.
var tools = []string{
	"tickets.read", "customers.lookup", "orders.list", "kb.search",
	"policies.read", "payments.history", "crm.notes.append",
}

// baseline builds a straightforward n-step run.
func baseline(n int) []call {
	out := make([]call, n)
	for i := range out {
		out[i] = call{
			tool:   tools[i%len(tools)],
			target: fmt.Sprintf("obj_%04d", i),
			result: map[string]any{"rows": i % 5},
		}
	}
	return out
}

// countClass counts the differences carrying a class.
func countClass(res *Result, c Class) int {
	n := 0
	for i := range res.Differences {
		if res.Differences[i].Has(c) {
			n++
		}
	}
	return n
}

func render(t *testing.T, res *Result, all bool) string {
	t.Helper()
	var b strings.Builder
	if err := Render(&b, res, Options{All: all}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// ---------------------------------------------------------------------------
// The corpus.
// ---------------------------------------------------------------------------

// TestRetryStorm: run B retries one call five times with backoff before it
// succeeds. The retries must surface as INSERTIONS, not as five spurious
// divergences, and — the part that matters most — everything after the
// retry block must still line up. An aligner that smears here reports the
// whole tail of the run as different.
func TestRetryStorm(t *testing.T) {
	base := baseline(20)
	a := synth(t, "run_a", base)

	var withRetries []call
	withRetries = append(withRetries, base[:4]...)
	for attempt := 0; attempt < 4; attempt++ {
		retry := base[4]
		retry.status = "error"
		retry.result = map[string]any{"error": "rate_limited", "backoff_ms": 100 << attempt}
		withRetries = append(withRetries, retry)
	}
	withRetries = append(withRetries, base[4:]...)
	b := synth(t, "run_b", withRetries)

	res := Analyze(a, b)
	if res.Aligner == AlignerStepKey {
		t.Fatal("runs of different lengths cannot have a step_key bijection")
	}
	inserted := countClass(res, ClassOnlyInB)
	if inserted != 4 {
		t.Errorf("%d insertions, want 4 (one per retry); differences: %s", inserted, summarize(res))
	}
	// At most one content difference — the retried step's own outcome.
	if other := len(res.Differences) - inserted; other > 1 {
		t.Errorf("%d non-insertion differences, want at most 1: %s", other, summarize(res))
	}
	// The anti-smear assertion: nothing after the retry block differs.
	for i := range res.Differences {
		if idx := res.Differences[i].Index; idx > 9 {
			t.Errorf("difference at aligned index %d: the retry block smeared into the tail\n%s", idx, summarize(res))
		}
	}
	if countClass(res, ClassOnlyInA) != 0 {
		t.Errorf("a pure insertion must not produce deletions: %s", summarize(res))
	}
}

// TestInsertedStepEarly is the headline anti-overfit case. B has one extra
// step at position 3 and is otherwise identical. A zip-by-position
// implementation reports ~100% of the run as different here; this must
// report exactly one insertion.
func TestInsertedStepEarly(t *testing.T) {
	base := baseline(30)
	a := synth(t, "run_a", base)

	inserted := append([]call{}, base[:3]...)
	inserted = append(inserted, call{tool: "audit.log", target: "extra", result: map[string]any{"ok": true}})
	inserted = append(inserted, base[3:]...)
	b := synth(t, "run_b", inserted)

	res := Analyze(a, b)
	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want exactly 1 insertion — a positional diff would report ~27\n%s",
			len(res.Differences), summarize(res))
	}
	d := res.Differences[0]
	if !d.Has(ClassOnlyInB) {
		t.Fatalf("the difference is %v, want only-in-B", d.Classes)
	}
	if d.Pair.B.Ordinal != 3 {
		t.Fatalf("insertion reported at step %d, want 3", d.Pair.B.Ordinal)
	}
	if !strings.Contains(render(t, res, false), "no counterpart in run_a") {
		t.Error("an insertion must render as having no counterpart")
	}
}

// TestDeletedStep is the mirror image.
func TestDeletedStep(t *testing.T) {
	base := baseline(30)
	a := synth(t, "run_a", base)
	shortened := append([]call{}, base[:12]...)
	shortened = append(shortened, base[13:]...)
	b := synth(t, "run_b", shortened)

	res := Analyze(a, b)
	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want exactly 1 deletion\n%s", len(res.Differences), summarize(res))
	}
	if !res.Differences[0].Has(ClassOnlyInA) {
		t.Fatalf("the difference is %v, want only-in-A", res.Differences[0].Classes)
	}
	if res.Differences[0].Pair.A.Ordinal != 12 {
		t.Fatalf("deletion reported at step %d, want 12", res.Differences[0].Pair.A.Ordinal)
	}
}

// TestArgumentShapeChanged: one step gains an optional argument, so its
// step_key changes and the key bijection fails. The fallback must pair the
// two steps anyway — on tool name and position — and report ONE argument
// difference, not a deletion plus an insertion. This is the case Q85 means
// by "identity survives an agent version change via alignment".
func TestArgumentShapeChanged(t *testing.T) {
	base := baseline(20)
	a := synth(t, "run_a", base)

	changed := append([]call{}, base...)
	changed[7].shape = "v2"
	changed[7].argFields = map[string]string{"$.dry_run": "true"}
	b := synth(t, "run_b", changed)

	res := Analyze(a, b)
	if res.Aligner != AlignerSequence {
		t.Fatalf("aligner %q: a changed step_key breaks the bijection and must fall back", res.Aligner)
	}
	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want 1\n%s", len(res.Differences), summarize(res))
	}
	d := res.Differences[0]
	if d.Has(ClassOnlyInA) || d.Has(ClassOnlyInB) {
		t.Fatalf("classes %v: a reshaped step must pair, not split into a delete plus an insert", d.Classes)
	}
	if !d.Has(ClassArguments) {
		t.Fatalf("classes %v, want arguments", d.Classes)
	}
	if d.Pair.A.Ordinal != 7 || d.Pair.B.Ordinal != 7 {
		t.Fatalf("paired %d against %d, want 7 against 7", d.Pair.A.Ordinal, d.Pair.B.Ordinal)
	}
}

// TestLargePayloads: ~40 KB argument blobs. The diff must not print them
// wholesale and must finish quickly, in both the identical and the
// divergent case.
func TestLargePayloads(t *testing.T) {
	blob := func(seed string) map[string]any {
		m := map[string]any{}
		for i := 0; i < 400; i++ {
			m[fmt.Sprintf("field_%03d", i)] = seed + strings.Repeat("x", 80) + itoa(i)
		}
		return m
	}
	measure := func(name string, a, b []Step) *Result {
		t.Helper()
		start := time.Now()
		res := Analyze(a, b)
		out := render(t, res, false)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("%s: took %s, want well under 5s", name, d)
		}
		if len(out) > 4000 {
			t.Errorf("%s: rendered %d bytes — the blob was printed wholesale:\n%s", name, len(out), out)
		}
		if strings.Contains(out, strings.Repeat("x", 60)) {
			t.Errorf("%s: a 40 KB value reached the screen verbatim", name)
		}
		return res
	}

	same := baseline(20)
	same[9].result = map[string]any{"blob": blob("same")}
	if res := measure("identical", synth(t, "run_a", same), synth(t, "run_b", same)); len(res.Differences) != 0 {
		t.Errorf("identical 40 KB blobs differ: %s", summarize(res))
	}

	left := baseline(20)
	left[9].result = map[string]any{"blob": blob("left")}
	right := baseline(20)
	right[9].result = map[string]any{"blob": blob("right")}
	res := measure("divergent", synth(t, "run_a", left), synth(t, "run_b", right))
	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want 1: %s", len(res.Differences), summarize(res))
	}
	d := res.Differences[0]
	if len(d.Changes) > maxChangesPerPair {
		t.Errorf("%d changes kept, want at most %d", len(d.Changes), maxChangesPerPair)
	}
	if !d.Truncated {
		t.Error("400 differing fields must be reported as truncated, not silently trimmed")
	}
	if out := render(t, res, false); !strings.Contains(out, "only the first") {
		t.Errorf("a truncated pair must say so on screen:\n%s", out)
	}
}

// TestNoDifferences: two runs that agree must say so plainly, with no
// divergence section and no causal claim.
func TestNoDifferences(t *testing.T) {
	base := baseline(25)
	res := Analyze(synth(t, "run_a", base), synth(t, "run_b", base))
	if len(res.Differences) != 0 {
		t.Fatalf("identical runs differ: %s", summarize(res))
	}
	if res.First != nil || res.Featured != nil || res.SuppressedCount != 0 {
		t.Fatal("a pair with no differences must carry no divergence, no featured step and no suppression")
	}
	out := render(t, res, false)
	if !strings.Contains(out, "None differ.") || !strings.Contains(out, "no divergence") {
		t.Fatalf("want a plain statement that nothing differs:\n%s", out)
	}
	for _, banned := range []string{"first divergence", "caused", "suppressed"} {
		if strings.Contains(out, banned) {
			t.Errorf("output claims %q with nothing to claim it about:\n%s", banned, out)
		}
	}
}

// TestUnequalLengths: 30 against 47. The shared prefix must align and the
// 17-step tail must read as deletions, not as 47 divergences.
func TestUnequalLengths(t *testing.T) {
	long := baseline(47)
	res := Analyze(synth(t, "run_a", long), synth(t, "run_b", long[:30]))
	if res.CountA != 47 || res.CountB != 30 {
		t.Fatalf("counts %d/%d", res.CountA, res.CountB)
	}
	if n := countClass(res, ClassOnlyInA); n != 17 {
		t.Fatalf("%d deletions, want 17\n%s", n, summarize(res))
	}
	if len(res.Differences) != 17 {
		t.Fatalf("%d differences, want 17 — the shared 30-step prefix must align\n%s",
			len(res.Differences), summarize(res))
	}
	out := render(t, res, false)
	if !strings.Contains(out, "47 actions in run_a, 30 in run_b.") {
		t.Fatalf("unequal runs must be counted honestly, not as \"both\":\n%s", out)
	}
}

// TestDifferenceInLastStep: nothing downstream to suppress, so nothing may
// be claimed as suppressed and no consequence may be invented.
func TestDifferenceInLastStep(t *testing.T) {
	base := baseline(20)
	changed := append([]call{}, base...)
	changed[19].result = map[string]any{"rows": 99}
	res := Analyze(synth(t, "run_a", base), synth(t, "run_b", changed))

	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want 1\n%s", len(res.Differences), summarize(res))
	}
	if res.SuppressedCount != 0 {
		t.Fatalf("%d suppressed with nothing downstream", res.SuppressedCount)
	}
	if res.Featured != nil {
		t.Fatal("a single difference has no consequence and no later difference to feature")
	}
	out := render(t, res, false)
	if strings.Contains(out, "suppressed") || strings.Contains(out, "consequence") {
		t.Fatalf("nothing downstream, so nothing to suppress or blame:\n%s", out)
	}
	if !strings.Contains(out, "1 differs.") {
		t.Fatalf("want the singular count:\n%s", out)
	}
}

// TestSuppressionCountsDownstream exercises the machinery the demo pair
// happens not to: a divergence at step 2 that propagates through the rest of
// the run. The suppression line must state the count, name --all, and sit
// beside the heuristic note.
func TestSuppressionCountsDownstream(t *testing.T) {
	base := baseline(20)
	a := append([]call{}, base...)
	b := append([]call{}, base...)
	a[2].result = map[string]any{"picked": "ord_1111"}
	b[2].result = map[string]any{"picked": "ord_2222"}
	for i := 5; i < 20; i++ {
		a[i].target = "ord_1111"
		b[i].target = "ord_2222"
	}
	res := Analyze(synth(t, "run_a", a), synth(t, "run_b", b))

	if res.First.Pair.A.Ordinal != 2 {
		t.Fatalf("first divergence at %d, want 2", res.First.Pair.A.Ordinal)
	}
	if !res.FeaturedIsConsequence {
		t.Fatal("ord_2222 came out of step 2 and went into step 19: that link must be found")
	}
	if res.Featured.Pair.A.Ordinal != 19 {
		t.Fatalf("consequence at %d, want the latest linked step, 19", res.Featured.Pair.A.Ordinal)
	}
	want := len(res.Differences) - 2 // minus the first divergence and the consequence
	if res.SuppressedCount != want {
		t.Fatalf("suppressed %d of %d differences, want %d", res.SuppressedCount, len(res.Differences), want)
	}
	out := render(t, res, false)
	line := fmt.Sprintf("%d downstream differences suppressed (--all to show)", res.SuppressedCount)
	if !strings.Contains(out, line) {
		t.Fatalf("want %q:\n%s", line, out)
	}
	if !strings.Contains(out, "heuristic") {
		t.Fatalf("the word \"suppressed\" must never appear without the heuristic note:\n%s", out)
	}
	// And --all really does show them all.
	all := render(t, res, true)
	if strings.Contains(all, "suppressed") {
		t.Errorf("--all must not suppress:\n%s", all)
	}
	for i := range res.Differences {
		step := res.Differences[i].Pair.A.Ordinal
		if !strings.Contains(all, "step "+itoa(step)+" ") {
			t.Errorf("--all omitted step %d", step)
		}
	}
}

// TestTheFeaturedConsequenceIsTheRiskiestLink is the regression for the
// failure the propagating demo scenario exposed (ENG-30).
//
// When the divergence reaches many later steps, "the latest linked step" is
// whichever bookkeeping call the agent happened to end on — here a read at
// step 19 — and featuring it buries the one step that spent money. The rule
// is therefore the highest-risk linked step, from the capture-time class the
// receipt already stores (Q6), with the latest winning ties.
//
// TestSuppressionCountsDownstream is the other half of this pair: no risk
// classes there, so the tie-break alone runs and the answer stays "the
// latest", which is what it should be when nothing says otherwise.
func TestTheFeaturedConsequenceIsTheRiskiestLink(t *testing.T) {
	base := baseline(20)
	a := append([]call{}, base...)
	b := append([]call{}, base...)
	a[2].result = map[string]any{"picked": "ord_1111"}
	b[2].result = map[string]any{"picked": "ord_2222"}
	for i := 5; i < 20; i++ {
		a[i].target, b[i].target = "ord_1111", "ord_2222"
		a[i].risk, b[i].risk = "low", "low"
	}
	// One of them is the refund.
	a[11].tool, b[11].tool = "refund.issue", "refund.issue"
	a[11].risk, b[11].risk = "high", "high"

	res := Analyze(synth(t, "run_a", a), synth(t, "run_b", b))
	if !res.FeaturedIsConsequence {
		t.Fatal("ord_2222 came out of step 2 and went into every later step: the link must be found")
	}
	if res.Featured.Pair.A.Ordinal != 11 {
		t.Fatalf("consequence at step %d, want 11 — the highest-risk linked step, not the latest (19)",
			res.Featured.Pair.A.Ordinal)
	}
	out := render(t, res, false)
	if !strings.Contains(out, "── consequence") || !strings.Contains(out, "refund.issue") {
		t.Fatalf("the consequence block must feature the refund:\n%s", out)
	}

	// A vocabulary the ranking does not know ranks flat, so the rule degrades
	// to the old latest-takes-it rather than guessing where it sits.
	for i := 5; i < 20; i++ {
		a[i].risk, b[i].risk = "spicy", "spicy"
	}
	a[11].risk, b[11].risk = "very spicy", "very spicy"
	res = Analyze(synth(t, "run_a", a), synth(t, "run_b", b))
	if res.Featured.Pair.A.Ordinal != 19 {
		t.Fatalf("consequence at step %d, want the latest linked step 19 under an unknown vocabulary",
			res.Featured.Pair.A.Ordinal)
	}
}

// TestNoLinkIsNotAConsequence is the honesty test for rule 3. Two unrelated
// differences share no value, so the render must say "later difference" and
// must not claim a consequence.
func TestNoLinkIsNotAConsequence(t *testing.T) {
	base := baseline(20)
	a := append([]call{}, base...)
	b := append([]call{}, base...)
	a[3].result = map[string]any{"weather": "sunny"}
	b[3].result = map[string]any{"weather": "rain"}
	a[15].target = "unrelated_aaa"
	b[15].target = "unrelated_bbb"
	res := Analyze(synth(t, "run_a", a), synth(t, "run_b", b))

	if res.FeaturedIsConsequence {
		t.Fatalf("no value travels from step 3 to step 15; link = %+v", res.Link)
	}
	if res.Featured == nil || res.Featured.Pair.A.Ordinal != 15 {
		t.Fatal("with no link, the last differing step is featured as a later difference")
	}
	out := render(t, res, false)
	if !strings.Contains(out, "── later difference") {
		t.Fatalf("want the later-difference heading:\n%s", out)
	}
	if strings.Contains(out, "consequence") {
		t.Fatalf("causality that cannot be shown must not be claimed:\n%s", out)
	}
}

// TestUnlinkedStillFeaturesTheRiskiestStep is the customer-held case, and on
// recorded data it is the normal one rather than the exception.
//
// Arguments and results live in the customer's own store, so the diff sees
// digests and there are no values to link by. Taking "the last difference"
// then features whatever bookkeeping call the agent ended on — a session
// summary — and buries the step that spent money. Rank by risk here too.
//
// It stays a *later difference*: with nothing but digests the causal link
// genuinely cannot be shown, and claiming one would be the overclaim this
// whole feature is built to avoid.
func TestUnlinkedStillFeaturesTheRiskiestStep(t *testing.T) {
	base := baseline(20)
	a := append([]call{}, base...)
	b := append([]call{}, base...)
	// Every later step differs, and none of them shares a value with any
	// other — the shape customer-held payloads produce.
	for i := 5; i < 20; i++ {
		a[i].target = fmt.Sprintf("opaque_a_%02d", i)
		b[i].target = fmt.Sprintf("opaque_b_%02d", i)
		a[i].risk, b[i].risk = "low", "low"
	}
	a[11].tool, b[11].tool = "refund.issue", "refund.issue"
	a[11].risk, b[11].risk = "high", "high"

	res := Analyze(synth(t, "run_a", a), synth(t, "run_b", b))
	if res.FeaturedIsConsequence {
		t.Fatal("no value links these steps; a consequence must not be claimed")
	}
	if res.Featured == nil || res.Featured.Pair.A.Ordinal != 11 {
		got := -1
		if res.Featured != nil {
			got = res.Featured.Pair.A.Ordinal
		}
		t.Fatalf("featured step %d, want 11 — the riskiest difference, not the last (19)", got)
	}
	out := render(t, res, false)
	if !strings.Contains(out, "── later difference") || !strings.Contains(out, "refund.issue") {
		t.Fatalf("want the refund featured under a later-difference heading:\n%s", out)
	}
}

// TestNoiseFilterHoldsTheLine: two runs identical in substance, differing
// only in machinery — a fresh ULID, a timestamp, a request id, a latency —
// on every single step. A diff that reports 20 timestamp differences here
// is the failure this feature exists to avoid.
func TestNoiseFilterHoldsTheLine(t *testing.T) {
	base := baseline(20)
	withNoise := func(seed string, offset int) []call {
		out := append([]call{}, base...)
		for i := range out {
			out[i].result = map[string]any{
				"rows":       i % 5,
				"request_id": ulidLike(seed, i),
				"created_at": time.Date(2026, 8, 26, 12, offset, i, 0, time.UTC).Format(time.RFC3339),
				"latency_ms": 10 + i + offset,
				"trace_id":   hashOf(seed + itoa(i))[:32],
				// A ULID under a field name nobody thought to list: caught by
				// shape rather than by name.
				"batch": ulidLike(seed+"batch", i),
			}
		}
		return out
	}
	res := Analyze(synth(t, "run_a", withNoise("a", 0)), synth(t, "run_b", withNoise("b", 30)))
	if len(res.Differences) != 0 {
		t.Fatalf("the noise filter let %d machinery differences through: %s", len(res.Differences), summarize(res))
	}

	// The filter is auditable, not silent: --all names what it dropped. To
	// see that, give the runs one real difference to hang the report on.
	a := withNoise("a", 0)
	b := withNoise("b", 30)
	a[7].target, b[7].target = "real_aaa", "real_bbb"
	res = Analyze(synth(t, "run_a", a), synth(t, "run_b", b))
	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want the 1 real one: %s", len(res.Differences), summarize(res))
	}
	if len(res.Differences[0].NoiseFiltered) == 0 {
		t.Fatal("the dropped fields must be recorded so a reader can audit the filter")
	}
	if out := render(t, res, true); !strings.Contains(out, "ignored as run-scoped noise") {
		t.Fatalf("--all must name what the noise filter dropped:\n%s", out)
	}
}

// TestReorderedResultIsItsOwnClass: same values, different sequence. Every
// other tool calls this "no change".
func TestReorderedResultIsItsOwnClass(t *testing.T) {
	base := baseline(10)
	a := append([]call{}, base...)
	b := append([]call{}, base...)
	rows := []any{
		map[string]any{"id": "row_aaa", "n": 1},
		map[string]any{"id": "row_bbb", "n": 2},
		map[string]any{"id": "row_ccc", "n": 3},
	}
	a[4].result = map[string]any{"rows": rows}
	b[4].result = map[string]any{"rows": []any{rows[2], rows[0], rows[1]}}
	res := Analyze(synth(t, "run_a", a), synth(t, "run_b", b))

	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want 1: %s", len(res.Differences), summarize(res))
	}
	d := res.Differences[0]
	if !d.Has(ClassOrder) || !d.Has(ClassResult) {
		t.Fatalf("classes %v, want both result and order", d.Classes)
	}
	if len(d.Changes) != 1 || d.Changes[0].Kind != KindReordered || d.Changes[0].Count != 3 {
		t.Fatalf("a reordering is ONE finding at the container, not one per element: %+v", d.Changes)
	}
	if out := render(t, res, false); !strings.Contains(out, "returned 3 rows, reordered") {
		t.Fatalf("want the reordering named:\n%s", out)
	}
}

// TestOutcomeDifferenceIsLoudest: ok in one run, error in the other.
func TestOutcomeDifferenceIsLoudest(t *testing.T) {
	base := baseline(10)
	b := append([]call{}, base...)
	b[6].status = "error"
	b[6].result = map[string]any{"error": "insufficient_funds"}
	res := Analyze(synth(t, "run_a", base), synth(t, "run_b", b))

	if len(res.Differences) != 1 || !res.Differences[0].Has(ClassOutcome) {
		t.Fatalf("want one outcome difference: %s", summarize(res))
	}
	if out := render(t, res, false); !strings.Contains(out, "→ error") {
		t.Fatalf("a failed operation must show its status:\n%s", out)
	}
}

// TestAnchoredPathOnLongRuns drives the decomposition that keeps the
// dynamic programming bounded on runs too long for a full matrix. The
// budget is lowered rather than generating six thousand receipts.
func TestAnchoredPathOnLongRuns(t *testing.T) {
	restore := maxCells
	maxCells = 40
	defer func() { maxCells = restore }()

	base := baseline(30)
	longer := append([]call{}, base...)
	longer = append(longer, call{tool: "session.summary", target: "session"})
	res := Analyze(synth(t, "run_a", base), synth(t, "run_b", longer))

	if res.Aligner != AlignerBlocked {
		t.Fatalf("aligner %q, want the anchored fallback to be named honestly", res.Aligner)
	}
	if len(res.Differences) != 1 || !res.Differences[0].Has(ClassOnlyInB) {
		t.Fatalf("a trailing insertion should survive anchoring: %s", summarize(res))
	}
}

// TestOpaqueDigestIsNotACause is the case the corpus itself forced into the
// design. Several steps differ only in their output-slot digest: the receipt
// records that the customer-held response changed, but not what changed.
// Those may be reported and must never be named as a cause, because "which
// step caused it" cannot be answered by a hash — and because a digest is
// the one signal that fires by construction, so letting it count would bury
// the real finding under a wall of unexplainable ones.
func TestOpaqueDigestIsNotACause(t *testing.T) {
	base := baseline(20)
	a := append([]call{}, base...)
	b := append([]call{}, base...)
	for i := 2; i < 20; i++ {
		a[i].opaqueOutput = "left"
		b[i].opaqueOutput = "right"
	}
	// One difference the receipt CAN explain, later in the run.
	a[14].target, b[14].target = "ord_aaa", "ord_bbb"

	res := Analyze(synth(t, "run_a", a), synth(t, "run_b", b))
	if len(res.Opaque) != 17 {
		t.Fatalf("%d digest-only differences, want 17\n%s", len(res.Opaque), summarize(res))
	}
	if len(res.Differences) != 1 {
		t.Fatalf("%d explainable differences, want 1\n%s", len(res.Differences), summarize(res))
	}
	if res.First.Pair.A.Ordinal != 14 {
		t.Fatalf("first divergence at step %d, want 14 — a digest must never be named as the cause",
			res.First.Pair.A.Ordinal)
	}
	out := render(t, res, false)
	if !strings.Contains(out, "17 further steps differ only in a payload digest") {
		t.Fatalf("digest-only differences must be reported, not silently dropped:\n%s", out)
	}
	if !strings.Contains(out, "1 differs.") {
		t.Fatalf("the headline counts what can be explained:\n%s", out)
	}
	if all := render(t, res, true); !strings.Contains(all, "── payload digest only") {
		t.Fatalf("--all must list them:\n%s", all)
	}
}

// TestEmptyRuns: degenerate inputs must not panic.
func TestEmptyRuns(t *testing.T) {
	base := baseline(5)
	for _, tc := range []struct{ a, b []Step }{
		{nil, nil},
		{synth(t, "run_a", base), nil},
		{nil, synth(t, "run_b", base)},
	} {
		res := Analyze(tc.a, tc.b)
		render(t, res, false)
		render(t, res, true)
	}
}

// TestForwardingMetadataIsNotADifference is the recorded-data case. The
// proxy stores the params object AS FORWARDED, so every step carries a
// `_meta` envelope holding the delegation chain and W3C baggage — and that
// baggage carries behalf-run-id, which is by definition different between
// the two runs being compared.
//
// A diff that compares the forwarded blob reports every step of every
// recorded pair as changed. Two runs that differ only in run-scoped
// forwarding metadata must report ZERO differences.
func TestForwardingMetadataIsNotADifference(t *testing.T) {
	base := baseline(47)
	withMeta := func(runID string) []call {
		out := append([]call{}, base...)
		for i := range out {
			out[i].meta = "behalf-run-id=" + runID
		}
		return out
	}
	res := Analyze(synth(t, "run_a", withMeta("run_a")), synth(t, "run_b", withMeta("run_b")))
	if len(res.Differences) != 0 || len(res.Opaque) != 0 {
		t.Fatalf("run-scoped forwarding metadata reported as a difference — 47 of 47 steps is the "+
			"exact noise failure this feature exists to prevent:\n%s", summarize(res))
	}
	if out := render(t, res, false); !strings.Contains(out, "None differ.") {
		t.Fatalf("want a plain statement that nothing differs:\n%s", out)
	}

	// And the filter is not over-broad: a real argument difference beside the
	// same metadata is still found.
	a, b := withMeta("run_a"), withMeta("run_b")
	a[20].argFields = map[string]string{"$.arguments.customer": "c_1111"}
	b[20].argFields = map[string]string{"$.arguments.customer": "c_2222"}
	res = Analyze(synth(t, "run_a", a), synth(t, "run_b", b))
	if len(res.Differences) != 1 {
		t.Fatalf("%d differences, want the 1 real argument change:\n%s", len(res.Differences), summarize(res))
	}
	if !res.Differences[0].Has(ClassArguments) || res.Differences[0].Pair.A.Ordinal != 20 {
		t.Fatalf("want an argument difference at step 20, got %v at %d",
			res.Differences[0].Classes, res.Differences[0].Pair.A.Ordinal)
	}
	if len(res.Differences[0].NoiseFiltered) == 0 {
		t.Error("the dropped _meta path must be recorded so a reader can audit the filter")
	}
}

// TestOrdinalIsRunRelativeNotEmitterCounter: two runs recorded through one
// proxy share one monotonic emitter counter, so run B's counters start where
// run A's ended. The step number must come from the run view (Q82) — a diff
// that indexed by the counter would work on hand-built fixtures and
// misalign every recorded pair.
func TestOrdinalIsRunRelativeNotEmitterCounter(t *testing.T) {
	base := baseline(47)
	shifted := append([]call{}, base...)
	for i := range shifted {
		shifted[i].counter = 47 // run B follows run A in one counter space
	}
	a := synth(t, "run_a", base)
	b := synth(t, "run_b", shifted)

	for i := range b {
		if b[i].Ordinal != i {
			t.Fatalf("step %d has ordinal %d: the ordinal must be the run-relative position, "+
				"never the emitter counter", i, b[i].Ordinal)
		}
	}
	res := Analyze(a, b)
	if len(res.Differences) != 0 || len(res.Opaque) != 0 {
		t.Fatalf("a shared emitter counter must not make two identical runs differ:\n%s", summarize(res))
	}
	if res.Aligner != AlignerStepKey {
		t.Fatalf("aligner %q: identical step keys must still pair by the primary key", res.Aligner)
	}
}

// summarize renders a Result compactly for a failure message.
func summarize(res *Result) string {
	var b strings.Builder
	fmt.Fprintf(&b, "aligner=%s pairs=%d differences=%d\n", res.Aligner, len(res.Pairs), len(res.Differences))
	for i := range res.Differences {
		d := &res.Differences[i]
		var paths []string
		for _, ch := range d.Changes {
			paths = append(paths, ch.Path)
		}
		fmt.Fprintf(&b, "  [%d] step %s %v %v\n", d.Index, stepNumbers(d), d.Classes, paths)
		if i > 24 {
			fmt.Fprintf(&b, "  ... %d more\n", len(res.Differences)-i-1)
			break
		}
	}
	return b.String()
}
