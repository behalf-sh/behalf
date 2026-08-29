// Golden tests for `behalf diff`, driven end to end: the fixture runs are
// ingested through the production log path, read back out of the entry
// bundles, aligned, compared and rendered.
//
// External test package: internal/tlog imports internal/index, and the
// helpers here drive the log, so these tests sit outside package diff.
package diff_test

import (
	"bytes"
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/diff"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
	"github.com/behalf-sh/behalf/internal/why"
)

// demoLog ingests the fixture pair into a fresh log dir through the real
// ingest path and returns the dir.
func demoLog(t *testing.T, specs ...fixture.Spec) string {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	key, err := tlog.GenerateCheckpointKey("behalf.sh/log/diff-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.SaveCheckpointKey(dir, key); err != nil {
		t.Fatal(err)
	}
	l, err := tlog.Open(ctx, dir, key, tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	emitter := testkeys.Emitter()
	jwk, err := json.Marshal(emitter.JWK)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterKey(emitter.JKT, string(jwk)); err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		res, err := fixture.Generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		var pendings []*tlog.Pending
		for i, payload := range res.Payloads {
			sig := dsse.Sign(emitter.Private, exportv1.PayloadTypeReceipt, payload)
			env := tlog.BuildEnvelope(exportv1.PayloadTypeReceipt, payload, emitter.JKT, sig)
			p, err := l.BeginAppend(ctx, env)
			if err != nil {
				t.Fatalf("%s %d: %v", spec.RunID, i, err)
			}
			pendings = append(pendings, p)
		}
		for i, p := range pendings {
			if _, err := p.Wait(ctx); err != nil {
				t.Fatalf("%s %d: %v", spec.RunID, i, err)
			}
		}
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
	return dir
}

func renderDemo(t *testing.T, dir string, all bool) string {
	t.Helper()
	res, err := diff.Load(context.Background(), dir, "run_9f2a", "run_c71e")
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := why.LoadAliases(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := diff.Render(&b, res, diff.Options{All: all, Aliases: aliases}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// wantDemo is the demo screen, canonical down to the column.
//
// Two honest departures from the artifact's script, both forced by the data
// rather than chosen:
//
//   - "22 differ", not "41 differ". 41 was never reachable: the divergence
//     is at step 12 of 47, so steps 0..11 cannot differ and the ceiling is
//     35. Of those 35, the pair differs at the 22 the selection actually
//     reaches — the order, its card, its payments, its shipment, its SKU,
//     the prechecks, the approval, the refund, and everything that records
//     what was refunded — and does not differ at the 13 that do not depend
//     on which order the search put first (the refund policy, the knowledge
//     base, verifying the customer, setting and closing the ticket). The
//     number is what the flow produces, not a figure the flow was cut to.
//   - "t+60s", not "t+412ms": captured_at is RFC 3339 at second granularity
//     and the fixture steps five seconds apart, so step 12 is exactly a
//     minute in. Sub-second offsets render as ms when the data has them.
//
// Everything else is the artifact: the ordered-result finding at step 12,
// the refund it caused at step 31, the twenty downstream differences
// suppressed behind an admitted heuristic, the cents-to-currency display,
// the value-equality link, and the attribution handoff to `behalf why`.
const wantDemo = `  47 actions in both runs.  22 differ.  1 caused the rest.

  ── first divergence ──────────────────────────── hop 3, t+60s
  step 12   billing-agent → orders.search
            returned 2 orders, reordered (order_id, amount_cents)
     9f2a   [0] ord_5512  $12.00   → ok
     c71e   [0] ord_5518  $1200.00   → ok   ← different first result
            the agent used orders[0] in both runs; step 31 carries it forward.

  ── consequence ──────────────────────────────────────────────
  step 31   billing-agent → refund.issue(...)
     9f2a   amount=12.00  target=ord_5512  +4 more   → ok
     c71e   amount=1200.00  target=ord_5518  +4 more   → ok

  ── 20 downstream differences suppressed (--all to show) ─────

  ⚠ refund.issue in run_c71e is attributed to alice@acme.com,
    but that hop is UNVERIFIED.          behalf why run_c71e:31

  heuristic: the first difference in aligned order is named the cause,
  and every later difference is presumed downstream of it. --all shows
  every difference with suppression off.

  note: attribution differs run-wide — run_9f2a verified, run_c71e asserted.
  that is authority, not action. see behalf why.
`

// TestDiffGoldenDemo is the demo, byte for byte.
func TestDiffGoldenDemo(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	got := renderDemo(t, dir, false)
	if got != wantDemo {
		t.Fatalf("behalf diff run_9f2a run_c71e output drifted.\n--- got ---\n%s\n--- want ---\n%s", got, wantDemo)
	}
	// The load-bearing lines, asserted on their own so a layout change
	// cannot quietly reword the finding.
	for _, line := range []string{
		"47 actions in both runs.  22 differ.  1 caused the rest.",
		"── first divergence ──────────────────────────── hop 3, t+60s",
		"returned 2 orders, reordered (order_id, amount_cents)",
		"the agent used orders[0] in both runs; step 31 carries it forward.",
		"── 20 downstream differences suppressed (--all to show) ─────",
		"⚠ refund.issue in run_c71e is attributed to alice@acme.com,",
		"but that hop is UNVERIFIED.          behalf why run_c71e:31",
		"heuristic: the first difference in aligned order is named the cause,",
	} {
		if !strings.Contains(got, line) {
			t.Errorf("missing verbatim line: %q", line)
		}
	}
	// The suppression line and the heuristic note travel together: the word
	// "suppressed" may never appear without the admission beside it.
	if strings.Contains(got, "suppressed") && !strings.Contains(got, "heuristic:") {
		t.Error("the suppression count was printed without the heuristic note")
	}
	// 22 differences, of which the causal view shows two: the first
	// divergence and the consequence. The rest are counted, not hidden.
	if !strings.Contains(got, "step 12") || !strings.Contains(got, "step 31") {
		t.Error("the causal view must show both the divergence and the consequence")
	}
	for _, hidden := range []string{"step 13", "step 33", "step 45"} {
		if strings.Contains(got, hidden) {
			t.Errorf("the default view showed %s: suppression is not doing its job", hidden)
		}
	}
}

// TestDiffGoldenAll pins `--all`: all 22 differences, listed rather than
// triaged, with every field spelled out instead of elided. The difference
// between the two views is the point — the default shows two and says how
// many it hid, `--all` hides nothing.
//
// It is also the clearest statement of what a receipt can and cannot say
// about an argument. Where the policy named a target, the value is on
// screen (target=ord_5518, target=apr_5518_01); everywhere else the
// arguments are customer-held and all the record has is the per-field
// digest manifest (input.$.amount_cents=sha256:…), which proves the field
// changed without disclosing it (Q34–Q38, Q37).
const wantDemoAll = `  47 actions in both runs.  22 differ.  1 caused the rest.

  ── all differences (suppression off) ────────────────────────
  step 12   billing-agent → orders.search  first divergence · result, order
            returned 2 orders, reordered (order_id, amount_cents)
     9f2a   [0] ord_5512  $12.00   → ok
     c71e   [0] ord_5518  $1200.00   → ok   ← different first result
            the agent used orders[0] in both runs; step 31 carries it forward.

  step 13   billing-agent → orders.read(...)          arguments
     9f2a   target=ord_5512  input.$.order_id=sha256:6910f9…   → ok
     c71e   target=ord_5518  input.$.order_id=sha256:ef9de5…   → ok

  step 14   billing-agent → payments.method.read(...)  arguments
     9f2a   target=pm_5512  input.$.order_id=sha256:6910f9…   → ok
            input.$.payment_method=sha256:748928…
     c71e   target=pm_5518  input.$.order_id=sha256:ef9de5…   → ok
            input.$.payment_method=sha256:690dae…

  step 15   billing-agent → payments.history(...)     arguments
     9f2a   input.$.order_id=sha256:6910f9…   → ok
     c71e   input.$.order_id=sha256:ef9de5…   → ok

  step 16   billing-agent → shipping.track(...)       arguments
     9f2a   target=shp_5512  input.$.order_id=sha256:6910f9…   → ok
            input.$.shipment_id=sha256:06f153…
     c71e   target=shp_5518  input.$.order_id=sha256:ef9de5…   → ok
            input.$.shipment_id=sha256:ae7561…

  step 17   billing-agent → inventory.check(...)      arguments
     9f2a   target=sku_5512  input.$.sku=sha256:161412…   → ok
            input.$.order_id=sha256:6910f9…
     c71e   target=sku_5518  input.$.sku=sha256:6f9a94…   → ok
            input.$.order_id=sha256:ef9de5…

  step 21   billing-agent → orders.read(...)          arguments
     9f2a   target=ord_5512  input.$.order_id=sha256:6910f9…   → ok
     c71e   target=ord_5518  input.$.order_id=sha256:ef9de5…   → ok

  step 22   billing-agent → refund.precheck(...)  arguments, result
     9f2a   target=ord_5512  order_id=ord_5512  amount_cents=$12.00   → ok
            input.$.order_id=sha256:6910f9…
            input.$.amount_cents=sha256:15197c…
     c71e   target=ord_5518  order_id=ord_5518  amount_cents=$1200.00   → ok
            input.$.order_id=sha256:ef9de5…
            input.$.amount_cents=sha256:4f9f73…

  step 23   billing-agent → tickets.comment(...)      arguments
     9f2a   input.$.order_id=sha256:6910f9…   → ok
            input.$.amount_cents=sha256:15197c…
     c71e   input.$.order_id=sha256:ef9de5…   → ok
            input.$.amount_cents=sha256:4f9f73…

  step 24   billing-agent → crm.notes.append(...)     arguments
     9f2a   input.$.order_id=sha256:6910f9…   → ok
            input.$.amount_cents=sha256:15197c…
     c71e   input.$.order_id=sha256:ef9de5…   → ok
            input.$.amount_cents=sha256:4f9f73…

  step 26   billing-agent → approvals.request(...)  arguments, result
     9f2a   target=apr_5512_01  approval_id=apr_5512_01   → ok
            input.$.order_id=sha256:6910f9…
            input.$.approval_id=sha256:3a7bfd…
            input.$.amount_cents=sha256:15197c…
     c71e   target=apr_5518_01  approval_id=apr_5518_01   → ok
            input.$.order_id=sha256:ef9de5…
            input.$.approval_id=sha256:d6da4d…
            input.$.amount_cents=sha256:4f9f73…

  step 27   billing-agent → approvals.poll(...)  arguments, result
     9f2a   target=apr_5512_01  approval_id=apr_5512_01   → ok
            input.$.approval_id=sha256:3a7bfd…
     c71e   target=apr_5518_01  approval_id=apr_5518_01   → ok
            input.$.approval_id=sha256:d6da4d…

  step 29   billing-agent → orders.read(...)          arguments
     9f2a   target=ord_5512  input.$.order_id=sha256:6910f9…   → ok
     c71e   target=ord_5518  input.$.order_id=sha256:ef9de5…   → ok

  step 30   billing-agent → refund.precheck(...)  arguments, result
     9f2a   target=ord_5512  order_id=ord_5512  amount_cents=$12.00   → ok
            input.$.order_id=sha256:6910f9…
            input.$.amount_cents=sha256:15197c…
     c71e   target=ord_5518  order_id=ord_5518  amount_cents=$1200.00   → ok
            input.$.order_id=sha256:ef9de5…
            input.$.amount_cents=sha256:4f9f73…

  step 31   billing-agent → refund.issue(...)  arguments, result
     9f2a   amount=12.00  target=ord_5512  refund_id=rf_5512_01   → ok
            idempotency_key=refund-ord_5512-a1
            input.$.amount=sha256:60bc77…
            input.$.order_id=sha256:6910f9…
     c71e   amount=1200.00  target=ord_5518  refund_id=rf_5518_01   → ok
            idempotency_key=refund-ord_5518-a1
            input.$.amount=sha256:7a4a53…
            input.$.order_id=sha256:ef9de5…

  step 32   billing-agent → payments.history(...)     arguments
     9f2a   input.$.order_id=sha256:6910f9…   → ok
     c71e   input.$.order_id=sha256:ef9de5…   → ok

  step 33   billing-agent → orders.read(...)          arguments
     9f2a   target=ord_5512  input.$.order_id=sha256:6910f9…   → ok
     c71e   target=ord_5518  input.$.order_id=sha256:ef9de5…   → ok

  step 34   billing-agent → tickets.comment(...)      arguments
     9f2a   input.$.refund_id=sha256:e39e6b…   → ok
            input.$.amount_cents=sha256:15197c…
     c71e   input.$.refund_id=sha256:d96a39…   → ok
            input.$.amount_cents=sha256:4f9f73…

  step 35   billing-agent → crm.notes.append(...)     arguments
     9f2a   input.$.refund_id=sha256:e39e6b…   → ok
            input.$.amount_cents=sha256:15197c…
     c71e   input.$.refund_id=sha256:d96a39…   → ok
            input.$.amount_cents=sha256:4f9f73…

  step 36   billing-agent → notifications.email.send(...)  arguments
     9f2a   input.$.refund_id=sha256:e39e6b…   → ok
            input.$.amount_cents=sha256:15197c…
     c71e   input.$.refund_id=sha256:d96a39…   → ok
            input.$.amount_cents=sha256:4f9f73…

  step 38   billing-agent → metrics.emit(...)         arguments
     9f2a   input.$.amount_cents=sha256:15197c…   → ok
     c71e   input.$.amount_cents=sha256:4f9f73…   → ok

  step 45   billing-agent → session.summary(...)      arguments
     9f2a   input.$.refund_id=sha256:e39e6b…   → ok
            input.$.amount_cents=sha256:15197c…
     c71e   input.$.refund_id=sha256:d96a39…   → ok
            input.$.amount_cents=sha256:4f9f73…

  ⚠ refund.issue in run_c71e is attributed to alice@acme.com,
    but that hop is UNVERIFIED.          behalf why run_c71e:31

  heuristic: the first difference in aligned order is named the cause,
  and every later difference is presumed downstream of it. --all shows
  every difference with suppression off.

  note: attribution differs run-wide — run_9f2a verified, run_c71e asserted.
  that is authority, not action. see behalf why.
`

func TestDiffGoldenAll(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	got := renderDemo(t, dir, true)
	if got != wantDemoAll {
		t.Fatalf("behalf diff --all output drifted.\n--- got ---\n%s\n--- want ---\n%s", got, wantDemoAll)
	}
	// --all must not elide. The default view says "+4 more"; this one names
	// the fields instead.
	if strings.Contains(got, "more\n") {
		t.Error("--all elided a field: the escape hatch has to actually show everything")
	}
	if !strings.Contains(got, "idempotency_key=refund-ord_5518-a1") {
		t.Error("--all must spell out the fields the default view elides")
	}
	// ...and it must not suppress: every one of the 22 differing steps is on
	// screen, and the count the default view printed is gone.
	if strings.Contains(got, "suppressed") {
		t.Error("--all must not suppress")
	}
	for _, step := range []int{12, 13, 14, 15, 16, 17, 21, 22, 23, 24, 26, 27, 29, 30, 31,
		32, 33, 34, 35, 36, 38, 45} {
		if !strings.Contains(got, "step "+strconv.Itoa(step)+" ") {
			t.Errorf("--all omitted step %d", step)
		}
	}
	// The propagation, on screen: the wrongly-selected order reaches the
	// card, the shipment, the SKU and the approval, and the refund it
	// produced reaches the steps that record what happened.
	for _, want := range []string{
		"target=pm_5518", "target=shp_5518", "target=sku_5518", "target=apr_5518_01",
		"refund_id=rf_5518_01",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--all does not show %q: the selection did not propagate", want)
		}
	}
}

// TestDiffReadsRealPayloadBytes pins the two things the render could most
// easily fake: the numbers come out of the alignment, and the values come
// out of the stored payload spans.
func TestDiffReadsRealPayloadBytes(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	res, err := diff.Load(context.Background(), dir, "run_9f2a", "run_c71e")
	if err != nil {
		t.Fatal(err)
	}
	if res.CountA != 47 || res.CountB != 47 {
		t.Fatalf("counts %d/%d, want 47/47", res.CountA, res.CountB)
	}
	if res.Aligner != diff.AlignerStepKey {
		t.Fatalf("aligner %q: the fixture pair has a perfect step_key bijection and must use the primary key (Q85)", res.Aligner)
	}
	if len(res.Differences) != 22 {
		t.Fatalf("%d differences, want 22", len(res.Differences))
	}
	if res.SuppressedCount != 20 {
		t.Fatalf("%d suppressed, want 20 (22 differences, less the divergence and the consequence)",
			res.SuppressedCount)
	}
	if res.First.Pair.A.Ordinal != 12 {
		t.Fatalf("first divergence at step %d, want 12", res.First.Pair.A.Ordinal)
	}
	if !res.FeaturedIsConsequence {
		t.Fatal("step 31 is reachable from step 12 by value equality and must be labelled a consequence")
	}
	// Eighteen later steps carry ord_5518 forward and any of them could be
	// shown; the one worth showing is the refund. `orders.read` at step 33 is
	// the LATEST linked step and would win a latest-takes-it rule — the
	// capture-time risk class (Q6) is what puts the high-risk refund in front
	// of it. See causality.go.
	if res.Featured.Pair.B.Ordinal != 31 {
		t.Fatalf("consequence at step %d, want 31 — the highest-risk linked step, not the latest",
			res.Featured.Pair.B.Ordinal)
	}
	if res.Featured.Pair.B.RiskClass != "high" {
		t.Fatalf("the featured step is %q risk; the rule that chose it reads the stored class",
			res.Featured.Pair.B.RiskClass)
	}
	if res.Link == nil || res.Link.Path != "orders" || res.Link.Index != 0 {
		t.Fatalf("link = %+v, want the orders[0] element", res.Link)
	}
	if res.Link.ValueA != "ord_5512" || res.Link.ValueB != "ord_5518" {
		t.Fatalf("link values %q/%q, want ord_5512/ord_5518", res.Link.ValueA, res.Link.ValueB)
	}
	// The payload the diff read is the payload the log stores.
	if !bytes.Contains(res.Featured.Pair.B.Payload, []byte(`"amount":"1200.00"`)) {
		t.Fatal("the consequence's rendered amount must come from the stored payload span")
	}
	// And the fixture invariant the tamper demo depends on still holds: the
	// literal 1200.00 lives in exactly one place, and the diff's $1200.00 at
	// step 12 is a display of integer cents, not a second copy of it.
	if bytes.Contains(res.First.Pair.B.Payload, []byte("1200.00")) {
		t.Fatal("step 12 must store integer cents; the renderer, not the fixture, formats them")
	}
}

// TestDiffOneRunAgainstItself: a run compared with itself has nothing to
// say and must say exactly that — no divergence section, no causal claim.
func TestDiffOneRunAgainstItself(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	res, err := diff.Load(context.Background(), dir, "run_9f2a", "run_9f2a")
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := diff.Render(&b, res, diff.Options{}); err != nil {
		t.Fatal(err)
	}
	got := b.String()
	want := `  47 actions in both runs.  None differ.

  no divergence: every aligned step matches in operation, arguments
  and outcome. only run-scoped fields differ, and those are filtered.
`
	if got != want {
		t.Fatalf("self-diff drifted.\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
	for _, banned := range []string{"first divergence", "caused", "suppressed", "⚠"} {
		if strings.Contains(got, banned) {
			t.Errorf("a run with no differences must not print %q", banned)
		}
	}
}

// TestColourNeverShiftsTheGrid: the coloured render must be the plain
// render plus escapes and nothing else. Padding measured against escaped
// text is the classic way a terminal layout rots, and it rots invisibly
// because tests capture the plain form.
func TestColourNeverShiftsTheGrid(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	res, err := diff.Load(context.Background(), dir, "run_9f2a", "run_c71e")
	if err != nil {
		t.Fatal(err)
	}
	aliases, err := why.LoadAliases(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, all := range []bool{false, true} {
		var plain, coloured bytes.Buffer
		if err := diff.Render(&plain, res, diff.Options{All: all, Aliases: aliases}); err != nil {
			t.Fatal(err)
		}
		if err := diff.Render(&coloured, res, diff.Options{All: all, Color: true, Aliases: aliases}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(coloured.String(), "\033[") {
			t.Fatalf("all=%v: colour was requested and none was emitted", all)
		}
		if got := stripANSI(coloured.String()); got != plain.String() {
			t.Fatalf("all=%v: colour shifted the layout.\n--- coloured, stripped ---\n%s\n--- plain ---\n%s",
				all, got, plain.String())
		}
	}
}

var ansiRE = regexp.MustCompile(`\033\[[0-9;]*m`)

func stripANSI(s string) string { return ansiRE.ReplaceAllString(s, "") }

// TestDiffUnknownRun: the error names the run, the way `behalf why` names a
// missing address.
func TestDiffUnknownRun(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A())
	_, err := diff.Load(context.Background(), dir, "run_9f2a", "run_nope")
	if err == nil || !strings.Contains(err.Error(), "run_nope") {
		t.Fatalf("err = %v, want one naming run_nope", err)
	}
}
