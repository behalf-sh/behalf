// Golden tests for `behalf why` and `behalf runs`, driven end to end: the
// fixture runs are ingested through the production log path, then read back
// out of the entry bundles by run and step.
//
// External test package: internal/tlog imports internal/index, and the
// helpers here drive the log, so these tests sit outside package why.
package why_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/index"
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
	key, err := tlog.GenerateCheckpointKey("behalf.sh/log/why-test")
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

func render(t *testing.T, dir, addr string) string {
	t.Helper()
	a, err := why.ParseAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	res, err := why.Load(context.Background(), dir, a)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := why.Render(&b, res, why.Options{}); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// wantC71E is the demo screen, canonical down to the column: a verified
// human root, a verified orchestrator hop, an unverified sub-agent hop that
// merely claims the human's identity, the refund it issued, and the scope
// excess computed at read time. The one place it differs from the artifact
// is the ed25519 thumbprint suffix, which is the real RFC 7638 thumbprint
// of the deterministic hop key rather than the artifact's illustrative one.
const wantC71E = `refund.issue(amount=1200.00)                    run_c71e  step 31

  ✔ alice@acme.com                    verified   OIDC/google  02:16:58Z
       │ delegated: "resolve ticket 4417"
       │ scope: tickets.*, orders.read, refund.issue<=100.00
       ▼
  ✔ support-orchestrator @1.4.2       verified   ed25519 ..whCQN8
       ▼
  ✖ billing-agent                     UNVERIFIED
       │ actor "alice@acme.com" is caller-asserted. no signature.
       ▼
    refund.issue  amount=1200.00

  ⚠ scope: refund.issue<=100.00 delegated; 1200.00 issued. (recorded, not enforced)

  chain intact for 2 of 3 hops.
`

// TestWhyGoldenC71E is the demo, byte for byte.
func TestWhyGoldenC71E(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	got := render(t, dir, "run_c71e:31")
	if got != wantC71E {
		t.Fatalf("behalf why run_c71e:31 output drifted.\n--- got ---\n%s\n--- want ---\n%s", got, wantC71E)
	}
	// The two load-bearing sentences, asserted on their own so a layout
	// change cannot quietly reword the finding.
	if !strings.Contains(got, "⚠ scope: refund.issue<=100.00 delegated; 1200.00 issued. (recorded, not enforced)") {
		t.Fatal("the scope-excess line is not verbatim")
	}
	if !strings.Contains(got, "chain intact for 2 of 3 hops.") {
		t.Fatal("the chain-intact line is not verbatim")
	}
}

const want9F2A = `refund.issue(amount=12.00)                      run_9f2a  step 31

  ✔ alice@acme.com                    verified   OIDC/google  22:03:58Z
       │ delegated: "resolve ticket 4417"
       │ scope: tickets.*, orders.read, refund.issue<=100.00
       ▼
  ✔ support-orchestrator @1.4.2       verified   ed25519 ..whCQN8
       ▼
  ✔ billing-agent                     verified   ed25519 ..652H7M
       ▼
    refund.issue  amount=12.00

  chain intact for 3 of 3 hops.
`

// TestWhyFullyVerified: the same step of the baseline run has a
// signature-verified leaf hop and a refund inside the delegated ceiling, so
// it carries no warning at all — the honest counterpart to the demo.
func TestWhyFullyVerified(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	got := render(t, dir, "run_9f2a:31")
	if got != want9F2A {
		t.Fatalf("behalf why run_9f2a:31 output drifted.\n--- got ---\n%s\n--- want ---\n%s", got, want9F2A)
	}
	if strings.Contains(got, "⚠") || strings.Contains(got, "scope:") && strings.Contains(got, "issued") {
		t.Fatalf("a refund inside the delegated ceiling must not warn:\n%s", got)
	}
	if !strings.Contains(got, "chain intact for 3 of 3 hops.") {
		t.Fatalf("want 3 of 3 hops:\n%s", got)
	}
}

const wantRuns = `RUN       STARTED               STATUS  ACTIONS  ACTOR           ATTRIBUTION
run_9f2a  2026-08-25T22:04:00Z  ok      47       alice@acme.com  verified
run_c71e  2026-08-26T02:17:00Z  ok      47       alice@acme.com  1 hop unverified
`

// TestRunsListing: one row per run, in the log's own order, with the
// attribution column rendered from the stored per-hop verification states —
// a run whose every hop verified says so, and a run with an unverified hop
// says how many (Q12, Q86).
//
// Two things this pins deliberately. ACTOR is the human at the root of the
// chain, not the acting agent: "on whose behalf" is the question the
// product exists to answer, and the acting agent is the same in both rows
// anyway. And both runs read STATUS `ok` — that is the demo's whole point,
// since an error tracker shows nothing here and only `behalf diff` finds
// the divergence that matters.
func TestRunsListing(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	rows, err := why.ListRuns(context.Background(), dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := why.RenderRuns(&b, rows, why.Options{}); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != wantRuns {
		t.Fatalf("behalf runs output drifted.\n--- got ---\n%s\n--- want ---\n%s", got, wantRuns)
	}
}

// TestStepIsRunRelativeOrdinal pins the addressing scheme: the step is the
// receipt's position in the run view (log-index order filtered to the run,
// Q82), which is independent of the global log index — run_c71e:31 is the
// 32nd receipt of run_c71e even though it sits at log index 78 — and
// matches the ordinal the fixtures stamp at capture in emitter.counter.
func TestStepIsRunRelativeOrdinal(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	ctx := context.Background()
	addr, _ := why.ParseAddress("run_c71e:31")
	res, err := why.Load(ctx, dir, addr)
	if err != nil {
		t.Fatal(err)
	}
	if res.LogIndex != 78 {
		t.Fatalf("run_c71e:31 is at log index %d, want 78 (47 + 31)", res.LogIndex)
	}
	if res.Operation != "refund.issue" {
		t.Fatalf("run_c71e:31 is %q, want refund.issue", res.Operation)
	}

	db, err := index.Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.RunRows("run_c71e")
	if err != nil {
		t.Fatal(err)
	}
	for step, row := range rows {
		if row.EmitterCounter != int64(step) {
			t.Fatalf("step %d is emitter counter %d: the run-relative ordinal and the captured counter disagree",
				step, row.EmitterCounter)
		}
	}
	if _, err := why.Load(ctx, dir, why.Address{RunID: "run_c71e", Step: 47}); err == nil {
		t.Fatal("step 47 is past the end of a 47-receipt run and must error")
	}
	if _, err := why.Load(ctx, dir, why.Address{RunID: "run_nope", Step: 0}); err == nil {
		t.Fatal("an unknown run must error")
	}
}

// TestNothingIsStampedBack is the read-path discipline under test (Q11,
// schema §1): the scope excess is computed on every render, and the stored
// receipt carries no computed delta — not before the render, not after.
func TestNothingIsStampedBack(t *testing.T) {
	dir := demoLog(t, fixture.RunC71E())
	ctx := context.Background()
	addr, _ := why.ParseAddress("run_c71e:31")

	res, err := why.Load(ctx, dir, addr)
	if err != nil {
		t.Fatal(err)
	}
	if res.Excess == nil {
		t.Fatal("the demo receipt must produce a scope-excess finding at read time")
	}
	if res.Excess.ComparatorVersion != why.ComparatorVersion {
		t.Fatalf("the finding is stamped %q, want the comparator version %q", res.Excess.ComparatorVersion, why.ComparatorVersion)
	}
	before := append([]byte(nil), res.Payload...)

	var b bytes.Buffer
	if err := why.Render(&b, res, why.Options{}); err != nil {
		t.Fatal(err)
	}

	// No computed value may appear anywhere in the signed bytes.
	var doc any
	if err := json.Unmarshal(res.Payload, &doc); err != nil {
		t.Fatal(err)
	}
	for _, k := range walkKeys(doc, "") {
		lower := strings.ToLower(k)
		for _, banned := range []string{"delta", "excess", "over_limit", "overage", "violation", "computed"} {
			if strings.Contains(lower, banned) {
				t.Fatalf("the stored receipt carries a computed field %q: computed values live on the read path (Q11)", k)
			}
		}
	}
	if bytes.Contains(res.Payload, []byte("recorded, not enforced")) {
		t.Fatal("the rendered finding leaked into the stored receipt")
	}

	// And re-reading the log yields the same bytes: rendering is a read.
	res2, err := why.Load(ctx, dir, addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, res2.Payload) {
		t.Fatal("the stored payload changed across a render — why must never write")
	}
}

// walkKeys returns every JSON object key in a parsed document, as dotted
// paths.
func walkKeys(v any, prefix string) []string {
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for k, sub := range t {
			p := k
			if prefix != "" {
				p = prefix + "." + k
			}
			out = append(out, p)
			out = append(out, walkKeys(sub, p)...)
		}
	case []any:
		for _, sub := range t {
			out = append(out, walkKeys(sub, prefix)...)
		}
	}
	return out
}

// TestParseAddress covers the addressing surface's error messages.
func TestParseAddress(t *testing.T) {
	if a, err := why.ParseAddress("run_c71e:31"); err != nil || a.RunID != "run_c71e" || a.Step != 31 {
		t.Fatalf("ParseAddress = %+v, %v", a, err)
	}
	for _, bad := range []string{"run_c71e", "run_c71e:", ":31", "run_c71e:x", "run_c71e:-1", ""} {
		if _, err := why.ParseAddress(bad); err == nil {
			t.Fatalf("ParseAddress(%q) should have failed", bad)
		}
	}
}
