package diff

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// The three pieces, each driven on its own. The corpus exercises them
// together through Analyze; these pin the boundaries that are easy to get
// wrong in isolation and hard to see through the whole pipeline.

// ---------------------------------------------------------------------------
// Align
// ---------------------------------------------------------------------------

// keyed builds a bare run with explicit step keys, so the tier-1 guard can
// be driven without generating receipts.
func keyed(runID string, keys ...string) []Step {
	out := make([]Step, len(keys))
	for i, k := range keys {
		out[i] = Step{RunID: runID, Ordinal: i, StepKey: k, Operation: "t" + itoa(i)}
	}
	return out
}

// TestAlignByStepKeyRequiresBijection pins the tier-1 guard. step_key is
// the primary identity (Q85), but it may only decide the alignment when it
// explains the ENTIRE pair of runs — anything less and a key pairing would
// report insertions as run-wide differences, which is the failure the
// fallback exists to prevent.
func TestAlignByStepKeyRequiresBijection(t *testing.T) {
	for _, tc := range []struct {
		name string
		a, b []Step
		want bool
	}{
		{"identical keys", keyed("a", "k0", "k1", "k2"), keyed("b", "k0", "k1", "k2"), true},
		{"reordered keys still bijective", keyed("a", "k0", "k1", "k2"), keyed("b", "k2", "k0", "k1"), true},
		{"unequal length", keyed("a", "k0", "k1"), keyed("b", "k0", "k1", "k2"), false},
		{"one key missing", keyed("a", "k0", "k1", "k2"), keyed("b", "k0", "k1", "kX"), false},
		{"duplicate key in A", keyed("a", "k0", "k0", "k2"), keyed("b", "k0", "k1", "k2"), false},
		{"duplicate key in B", keyed("a", "k0", "k1", "k2"), keyed("b", "k0", "k0", "k2"), false},
		{"empty key", keyed("a", "k0", "", "k2"), keyed("b", "k0", "k1", "k2"), false},
		{"empty runs", nil, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, ok := alignByStepKey(tc.a, tc.b)
			if ok != tc.want {
				t.Fatalf("alignByStepKey ok = %v, want %v", ok, tc.want)
			}
			pairs, tier := Align(tc.a, tc.b)
			if tc.want && tier != AlignerStepKey {
				t.Fatalf("Align chose %q, want the primary key", tier)
			}
			if !tc.want && len(tc.a)+len(tc.b) > 0 && tier == AlignerStepKey {
				t.Fatalf("Align chose the primary key without a bijection")
			}
			for _, p := range pairs {
				if p.A == nil && p.B == nil {
					t.Fatal("alignment produced an empty pair")
				}
			}
		})
	}
}

// TestSimilarityNeverMatchesDifferentTools: the score scale must place a
// pair of different tools below two gaps, so the aligner never matches a
// refund against a ticket close merely to avoid an insertion.
func TestSimilarityNeverMatchesDifferentTools(t *testing.T) {
	refund := &Step{Operation: "refund.issue", Target: "ord_1"}
	closeTicket := &Step{Operation: "tickets.close", Target: "ord_1"}
	if got := score(refund, closeTicket, 3, 3); got >= 2*gapPenalty {
		t.Fatalf("score for two different tools is %.2f, must be worse than two gaps (%.2f)", got, 2*gapPenalty)
	}
	// A shared namespace is a hint, never a match.
	search := &Step{Operation: "orders.search", Target: "x"}
	query := &Step{Operation: "orders.query", Target: "x"}
	if got := score(search, query, 3, 3); got >= 2*gapPenalty {
		t.Fatalf("score for a shared namespace is %.2f, must still be worse than two gaps", got)
	}
	// The same tool at the same position must comfortably beat two gaps.
	same := &Step{Operation: "orders.search", Target: "x"}
	if got := score(same, same, 3, 3); got <= 2*gapPenalty {
		t.Fatalf("score for an identical step is %.2f, must beat two gaps", got)
	}
	// step_key equality short-circuits to a certain match.
	ka := &Step{StepKey: "k", Operation: "a"}
	kb := &Step{StepKey: "k", Operation: "b"}
	if got := similarity(ka, kb, 0, 40); got != 1 {
		t.Fatalf("similarity with equal step keys is %.2f, want 1 (Q85's primary identity)", got)
	}
}

// ---------------------------------------------------------------------------
// Compare — the noise filter
// ---------------------------------------------------------------------------

// TestNoiseFilter drives the filter directly. It is the piece with the most
// power to make the whole feature wrong in either direction, so both
// directions are asserted: what it must drop, and what it must never drop.
func TestNoiseFilter(t *testing.T) {
	raw := func(s string) json.RawMessage { return json.RawMessage(s) }

	drop := []struct{ path, a, b string }{
		{"receipt_id", `"01M0XF92Q0P1YDTY5EFJEYGEH1"`, `"01M0XXRAY087D1XQ74D67EEY89"`},
		{"orders[0].created_at", `"2026-08-25T22:04:00Z"`, `"2026-08-26T02:17:00Z"`},
		{"latency_ms", `12`, `98`},
		{"result.request_id", `"req-a"`, `"req-b"`},
		{"trace_id", `"aaa"`, `"bbb"`},
		// Volatile by SHAPE, under names nobody listed.
		{"batch", `"01M0XF92Q0P1YDTY5EFJEYGEH1"`, `"01M0XXRAY087D1XQ74D67EEY89"`},
		{"whenever", `"2026-08-25T22:04:00Z"`, `"2026-08-26T02:17:00Z"`},
		{"job", `"6ba7b810-9dad-11d1-80b4-00c04fd430c8"`, `"6ba7b811-9dad-11d1-80b4-00c04fd430c8"`},
		// The forwarding envelope: noise at any depth beneath `_meta`, not
		// just at a leaf of that name. The baggage carries behalf-run-id, so
		// this fires on every step of every recorded pair.
		{"input.$._meta.baggage", `"behalf-run-id=run_9f2a"`, `"behalf-run-id=run_c71e"`},
		{"params._meta", `{"chain":"a"}`, `{"chain":"b"}`},
		{"rows[0]._meta.progressToken", `1`, `2`},
	}
	for _, tc := range drop {
		if !isNoise(tc.path, raw(tc.a), raw(tc.b)) {
			t.Errorf("isNoise(%q, %s, %s) = false, want true", tc.path, tc.a, tc.b)
		}
	}

	keep := []struct{ path, a, b string }{
		// The values the whole feature turns on.
		{"orders[0].order_id", `"ord_5512"`, `"ord_5518"`},
		{"amount", `"12.00"`, `"1200.00"`},
		{"amount_cents", `1200`, `120000`},
		{"refund_id", `"rf_5512_01"`, `"rf_5518_01"`},
		{"status", `"ok"`, `"error"`},
		{"target", `"ord_5512"`, `"ord_5518"`},
		// A minted id against nothing is a presence difference, not noise.
		{"request_uuid", `"6ba7b810-9dad-11d1-80b4-00c04fd430c8"`, `null`},
		// A field whose name merely resembles a volatile one.
		{"timestamp_policy", `"strict"`, `"lax"`},
		// The real arguments sit beside `_meta` in the forwarded params and
		// must survive it: filtering the envelope must not filter the call.
		{"input.$.arguments.customer", `"c_8831"`, `"c_9942"`},
		{"params.arguments.status", `"refundable"`, `"shipped"`},
		// A field whose name merely contains the segment.
		{"_metadata", `"a"`, `"b"`},
	}
	for _, tc := range keep {
		if isNoise(tc.path, raw(tc.a), raw(tc.b)) {
			t.Errorf("isNoise(%q, %s, %s) = true — the filter swallowed a real finding", tc.path, tc.a, tc.b)
		}
	}
}

// TestNoiseFilterListIsDocumented ties the code to the documentation: every
// name the filter acts on is in the published list, and the list has no
// duplicates to hide behind.
func TestNoiseFilterListIsDocumented(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range NoisyFields {
		if seen[f] {
			t.Errorf("NoisyFields lists %q twice", f)
		}
		seen[f] = true
		if !noisyField[f] {
			t.Errorf("%q is documented but not in the lookup", f)
		}
	}
	if len(noisyField) != len(NoisyFields) {
		t.Errorf("the lookup holds %d names, the documented list %d", len(noisyField), len(NoisyFields))
	}
	for _, seg := range NoisyPathSegments {
		if !noisySegment[seg] {
			t.Errorf("%q is documented as a path segment but not in the lookup", seg)
		}
	}
	if len(noisySegment) != len(NoisyPathSegments) {
		t.Errorf("the segment lookup holds %d names, the documented list %d",
			len(noisySegment), len(NoisyPathSegments))
	}
	if !noisySegment["_meta"] {
		t.Error("`_meta` must be filtered: it carries the W3C baggage holding behalf-run-id, " +
			"which differs at every step of every recorded pair")
	}
	if len(NotCompared) == 0 {
		t.Error("NotCompared must document the receipt fields kept out of the compared view")
	}
	for field, reason := range NotCompared {
		if strings.TrimSpace(reason) == "" {
			t.Errorf("NotCompared[%q] has no reason: the list exists so the reason is written down", field)
		}
	}
	for _, required := range []string{
		"receipt_id", "captured_at", "run_id", "step_key", "authority", "attribution",
		// The input slot's digest covers the params blob as forwarded,
		// `_meta` included, so it is not a digest of the action.
		"payload[input].digest",
	} {
		if _, ok := NotCompared[required]; !ok {
			t.Errorf("NotCompared must name %q", required)
		}
	}
}

// TestProjectViewsExcludesNotCompared: the coarse filter is structural, not
// aspirational — nothing NotCompared names may reach a compared view.
func TestProjectViewsExcludesNotCompared(t *testing.T) {
	payload := synthReceipt("run_x", 3, time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC), call{
		tool: "refund.issue", target: "ord_1", result: map[string]any{"amount": "12.00"},
	})
	s, err := NewStep("run_x", 3, 0, "", payload)
	if err != nil {
		t.Fatal(err)
	}
	for _, view := range []fields{s.args, s.result, s.outcome} {
		for _, f := range view {
			head, _, _ := strings.Cut(f.path, ".")
			if reason, banned := NotCompared[head]; banned {
				t.Errorf("compared view carries %q, which NotCompared excludes (%s)", f.path, reason)
			}
		}
	}
	// And the projection did find the things it is meant to.
	if _, ok := s.args.get("target"); !ok {
		t.Error("the argument view must carry the operation target")
	}
	if _, ok := s.result.get("amount"); !ok {
		t.Error("the result view must carry the outcome's result fields")
	}
	if _, ok := s.outcome.get("status"); !ok {
		t.Error("the outcome view must carry the status")
	}
}

// TestCanonEqualityIgnoresKeyOrderAndKeepsDecimals: two receipts that spell
// the same object differently are not a finding, and a stored decimal is
// never round-tripped through a float.
func TestCanonEqualityIgnoresKeyOrder(t *testing.T) {
	var changes []Change
	var noise []string
	budget := maxChangesPerPair
	diffValue(ClassResult, "o",
		json.RawMessage(`{"b":2,"a":1}`), json.RawMessage(`{"a":1,"b":2}`),
		&changes, &noise, &budget)
	if len(changes) != 0 {
		t.Fatalf("key order is not a difference: %+v", changes)
	}
	c, err := canon(json.RawMessage(`{"amount":1200.00}`))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(c), "1200.00") {
		t.Fatalf("canon(%s) = %s — a stored decimal must not be reformatted", `1200.00`, c)
	}
}

// TestPathSegments pins the split the segment filter depends on.
func TestPathSegments(t *testing.T) {
	for _, tc := range []struct {
		path string
		want string
	}{
		{"", ""},
		{"amount", "amount"},
		{"input.$._meta.baggage", "input $ _meta baggage"},
		{"rows[0]._meta.progressToken", "rows 0 _meta progressToken"},
		{"orders[12].order_id", "orders 12 order_id"},
	} {
		if got := strings.Join(pathSegments(tc.path), " "); got != tc.want {
			t.Errorf("pathSegments(%q) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// Causality
// ---------------------------------------------------------------------------

// TestLinkRejectsCoincidence pins the value-equality rule's guards. A link
// is the strongest claim this package makes, so the ways it must refuse to
// fire matter more than the way it fires.
func TestLinkRejectsCoincidence(t *testing.T) {
	values := func(vs ...string) map[string]bool {
		m := map[string]bool{}
		for _, v := range vs {
			m[v] = true
		}
		return m
	}
	// Too short to carry a lineage.
	if _, ok := pickLink(values("ok"), values("no"), values("ok")); ok {
		t.Error("a two-character value must not carry a causal link")
	}
	// Present on both sides of the divergence: it explains nothing.
	if _, ok := pickLink(values("USD"), values("USD"), values("USD")); ok {
		t.Error("a value both runs produced cannot explain why they differ")
	}
	// Not actually used downstream.
	if _, ok := pickLink(values("ord_5512"), values("ord_5518"), values("something_else")); ok {
		t.Error("a value the downstream step never used is not a link")
	}
	// The real thing.
	got, ok := pickLink(values("ord_5512", "USD"), values("ord_5518", "USD"), values("ord_5512", "noise"))
	if !ok || got != "ord_5512" {
		t.Errorf("pickLink = %q, %v; want ord_5512", got, ok)
	}
	// Deterministic: the longest candidate wins, not whichever the map
	// happened to yield first.
	for i := 0; i < 50; i++ {
		got, ok := pickLink(values("ord_5512", "ord_5512_long"), values("x"), values("ord_5512", "ord_5512_long"))
		if !ok || got != "ord_5512_long" {
			t.Fatalf("pickLink is not deterministic: got %q", got)
		}
	}
}

// TestFirstDivergenceIsFirstInAlignedOrder: the causality rule reads the
// alignment, not the log index, and marks everything after it downstream.
func TestFirstDivergenceIsFirstInAlignedOrder(t *testing.T) {
	base := baseline(10)
	a := append([]call{}, base...)
	b := append([]call{}, base...)
	for _, i := range []int{3, 5, 8} {
		a[i].result = map[string]any{"v": "left_" + itoa(i)}
		b[i].result = map[string]any{"v": "right_" + itoa(i)}
	}
	res := Analyze(synth(t, "run_a", a), synth(t, "run_b", b))
	if len(res.Differences) != 3 {
		t.Fatalf("%d differences, want 3", len(res.Differences))
	}
	if res.First != &res.Differences[0] || res.First.Pair.A.Ordinal != 3 {
		t.Fatal("the first divergence is the first difference in aligned order")
	}
	if res.Differences[0].Suppressed {
		t.Error("the first divergence is never suppressed")
	}
	if res.Featured == nil || res.Featured.Suppressed {
		t.Error("the featured step is never suppressed")
	}
	// With no value link, the last difference is featured as a later
	// difference and the middle one is the only thing suppressed.
	if res.FeaturedIsConsequence {
		t.Error("no value travels between these steps; no consequence may be claimed")
	}
	if res.SuppressedCount != 1 {
		t.Fatalf("suppressed %d, want 1 (the middle difference)", res.SuppressedCount)
	}
}
