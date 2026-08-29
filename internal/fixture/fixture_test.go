package fixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
)

// TestDeterminism: two generator runs must produce byte-identical files
// (docs/export-format-v1.md §4 — "fully deterministic").
func TestDeterminism(t *testing.T) {
	for _, spec := range []Spec{Run9F2A(), RunC71E(), Tiny()} {
		t.Run(spec.RunID, func(t *testing.T) {
			a, err := Generate(spec)
			if err != nil {
				t.Fatal(err)
			}
			b, err := Generate(spec)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(a.Bytes, b.Bytes) {
				t.Fatal("two generations of the same spec differ")
			}
		})
	}
}

// TestPayloadsValidateAgainstSchema validates every generated payload against
// the frozen machine-readable schema (docs/receipt-schema-v1.schema.json).
func TestPayloadsValidateAgainstSchema(t *testing.T) {
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("../../docs/receipt-schema-v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	for _, spec := range []Spec{Run9F2A(), RunC71E(), Tiny()} {
		res, err := Generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		for i, p := range res.Payloads {
			v, err := jsonschema.UnmarshalJSON(bytes.NewReader(p))
			if err != nil {
				t.Fatalf("%s step %d: unmarshal: %v", spec.RunID, i, err)
			}
			if err := sch.Validate(v); err != nil {
				t.Fatalf("%s step %d: schema violation: %v\npayload: %s", spec.RunID, i, err, p)
			}
		}
	}
}

// TestCoverUpTargetIsUnique is the demo-critical constraint: the literal
// string 1200.00 appears EXACTLY ONCE in run_c71e.jsonl, in the step-31
// payload, and nothing else in the file matches the demo's unescaped sed
// pattern /1200.00/ (where '.' matches any byte). Otherwise
// `sed 's/1200.00/12.00/'` would corrupt an additional line and the
// verifier would report a second break.
func TestCoverUpTargetIsUnique(t *testing.T) {
	res, err := Generate(RunC71E())
	if err != nil {
		t.Fatal(err)
	}

	if n := bytes.Count(res.Bytes, []byte("1200.00")); n != 1 {
		t.Fatalf("literal \"1200.00\" occurs %d times in run_c71e.jsonl, want exactly 1", n)
	}

	// The sed pattern is an unescaped regex: '.' matches any byte.
	sedPattern := regexp.MustCompile(`1200.00`)
	matches := sedPattern.FindAllIndex(res.Bytes, -1)
	if len(matches) != 1 {
		t.Fatalf("sed pattern /1200.00/ matches %d times, want exactly 1 (extra matches would corrupt other lines)", len(matches))
	}

	// The one occurrence must be on the leaf line with index 31.
	lines := bytes.Split(bytes.TrimSuffix(res.Bytes, []byte("\n")), []byte("\n"))
	for li, line := range lines {
		hit := sedPattern.Match(line)
		if li == 32 { // header is line 0; leaf index 31 is line 32
			if !hit {
				t.Fatal("leaf index 31 does not contain 1200.00")
			}
			if !bytes.Contains(line, []byte(`"index":31`)) {
				t.Fatalf("line 32 is not leaf 31: %.120s", line)
			}
			if !bytes.Contains(line, []byte(`"amount":"1200.00"`)) {
				t.Fatal(`leaf 31 does not contain "amount":"1200.00"`)
			}
		} else if hit {
			t.Fatalf("line %d unexpectedly matches /1200.00/: %.200s", li, line)
		}
	}

	// And in the payload specifically (not e.g. a signature accident): the
	// sealed payload for step 31 carries the amount.
	if !bytes.Contains(res.Payloads[31], []byte(`"amount":"1200.00"`)) {
		t.Fatal(`step-31 payload does not contain "amount":"1200.00"`)
	}
}

// TestExportLayoutIsFortyNineLines pins the file layout the tamper suite
// indexes by line number: 1 header + 47 leaves + 1 head. Growing the
// receipt payload (the delegation chain) must never grow the line count.
func TestExportLayoutIsFortyNineLines(t *testing.T) {
	for _, spec := range []Spec{Run9F2A(), RunC71E()} {
		res, err := Generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		lines := bytes.Split(bytes.TrimSuffix(res.Bytes, []byte("\n")), []byte("\n"))
		if len(lines) != 49 {
			t.Fatalf("%s has %d lines, want 49 (header + 47 leaves + head)", spec.RunID, len(lines))
		}
		if len(res.Payloads) != 47 {
			t.Fatalf("%s has %d payloads, want 47", spec.RunID, len(res.Payloads))
		}
	}
}

// chainOf reads the delegation chain out of a generated payload.
func chainOf(t *testing.T, payload []byte) []map[string]any {
	t.Helper()
	var r struct {
		Authority *struct {
			Chain []map[string]any `json:"chain"`
		} `json:"authority"`
		Attribution map[string]string `json:"attribution"`
	}
	if err := json.Unmarshal(payload, &r); err != nil {
		t.Fatal(err)
	}
	if r.Authority == nil {
		t.Fatal("payload carries no authority.chain")
	}
	return r.Authority.Chain
}

// TestChainIsThreeHopsWithTheFrozenFieldSet: every receipt of both demo runs
// embeds the whole chain (Q10), and every hop carries the schema §7 field
// set — the AAT draft's fields plus behalf's two named extensions. The root
// carries the OIDC nonce-thumbprint binding (D5) and the raw RFC 9396 grant
// the read path computes attenuation from (Q11, Q13).
func TestChainIsThreeHopsWithTheFrozenFieldSet(t *testing.T) {
	required := []string{
		"del_depth", "del_max_depth", "par_hash", "cnf",
		"authorization_details", "exp", "jti", "credential", "verification",
	}
	for _, spec := range []Spec{Run9F2A(), RunC71E()} {
		res, err := Generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		for i, p := range res.Payloads {
			chain := chainOf(t, p)
			if len(chain) != 3 {
				t.Fatalf("%s step %d has %d hops, want 3", spec.RunID, i, len(chain))
			}
			for depth, hop := range chain {
				for _, f := range required {
					if _, ok := hop[f]; !ok {
						t.Fatalf("%s step %d hop %d is missing %q", spec.RunID, i, depth, f)
					}
				}
				if got := hop["del_depth"]; got != float64(depth) {
					t.Fatalf("%s hop %d has del_depth %v", spec.RunID, depth, got)
				}
			}
			if _, ok := chain[0]["root_principal_binding"]; !ok {
				t.Fatalf("%s step %d: the root hop carries no root_principal_binding (D5)", spec.RunID, i)
			}
			// The raw grant must be present with its limit: the delta is
			// computed from these bytes at read time, so their absence
			// would make it uncomputable forever (Q11, schema §9 item 9).
			raw, err := json.Marshal(chain[0]["authorization_details"])
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{`"tickets.*"`, `"orders.read"`, `"refund.issue"`, `"100.00"`, "resolve ticket 4417"} {
				if !bytes.Contains(raw, []byte(want)) {
					t.Fatalf("%s step %d: the root grant does not carry %s: %s", spec.RunID, i, want, raw)
				}
			}
		}
	}
}

// TestAttributionRollupIsTheWeakestHop (Q12, schema §8): run_9f2a verifies
// end to end; run_c71e's leaf hop is caller-asserted, so the whole receipt
// rolls up to asserted. The rollup is stored at write, never derived at
// query time.
func TestAttributionRollupIsTheWeakestHop(t *testing.T) {
	cases := []struct {
		spec           Spec
		wantRollup     string
		wantLeafStatus string
	}{
		{Run9F2A(), "verified", "verified"},
		{RunC71E(), "asserted", "asserted"},
	}
	for _, tc := range cases {
		res, err := Generate(tc.spec)
		if err != nil {
			t.Fatal(err)
		}
		for i, p := range res.Payloads {
			var r struct {
				Attribution struct {
					Verification string `json:"verification"`
					Class        string `json:"class"`
				} `json:"attribution"`
			}
			if err := json.Unmarshal(p, &r); err != nil {
				t.Fatal(err)
			}
			if r.Attribution.Verification != tc.wantRollup {
				t.Fatalf("%s step %d rolls up to %q, want %q",
					tc.spec.RunID, i, r.Attribution.Verification, tc.wantRollup)
			}
			if r.Attribution.Class != "delegated" {
				t.Fatalf("%s step %d has class %q, want delegated", tc.spec.RunID, i, r.Attribution.Class)
			}
			chain := chainOf(t, p)
			leaf := chain[2]["verification"].(map[string]any)
			if leaf["status"] != tc.wantLeafStatus {
				t.Fatalf("%s step %d leaf hop is %v, want %q", tc.spec.RunID, i, leaf["status"], tc.wantLeafStatus)
			}
			for _, depth := range []int{0, 1} {
				v := chain[depth]["verification"].(map[string]any)
				if v["status"] != "verified" {
					t.Fatalf("%s step %d hop %d is %v, want verified", tc.spec.RunID, i, depth, v["status"])
				}
			}
		}
	}
}

// TestReceiptsCarryNoHumanReadableIdentity (Q40, schema §5): the human
// principal appears only as issuer plus sub-digest. The display name that
// `behalf why` prints comes from the CLI's local alias map, and must not be
// reachable from the record itself.
func TestReceiptsCarryNoHumanReadableIdentity(t *testing.T) {
	banned := []string{"alice", "@acme.com", "acme.com"}
	for _, spec := range []Spec{Run9F2A(), RunC71E(), Tiny()} {
		res, err := Generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range banned {
			if bytes.Contains(bytes.ToLower(res.Bytes), []byte(b)) {
				t.Fatalf("%s leaks the human-readable identity %q into the record", spec.RunID, b)
			}
		}
		if !bytes.Contains(res.Payloads[0], []byte("oidc-sub-digest:")) {
			t.Fatalf("%s: the root credential should name the principal by sub-digest", spec.RunID)
		}
	}
}

// wantDiffering is the set of steps at which the two runs differ, spelled
// out rather than derived from the script, so a change to the flow has to be
// written down here and looked at.
//
// It is 22 of 47. The ceiling is 35: the divergence is at step 12, so steps
// 0..11 cannot differ, and 25 steps of the run are the same call with the
// same arguments in both runs because they do not depend on which order the
// search put first — reading the refund policy, searching the knowledge
// base, verifying the customer, setting and closing the ticket.
var wantDiffering = []int{
	12,                 // the divergence: the search result order
	13, 14, 15, 16, 17, // the order, its card, its payments, its shipment, its SKU
	21, 22, 23, 24, // re-read, precheck, and record what is about to be refunded
	26, 27, 29, 30, // the approval raised against it, the final re-check
	31,                         // the consequence: refund.issue
	32, 33, 34, 35, 36, 38, 45, // what was refunded, recorded and reported
}

// TestTheSelectionPropagates checks the divergence and how far it travels:
// step 12's order results are swapped, every step that a support agent would
// hang off the order it chose carries the wrongly-chosen one, and every step
// that would not is byte-identical between the runs.
func TestTheSelectionPropagates(t *testing.T) {
	r9, err := Generate(Run9F2A())
	if err != nil {
		t.Fatal(err)
	}
	rc, err := Generate(RunC71E())
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Contains(r9.Payloads[31], []byte(`"amount":"12.00"`)) {
		t.Fatal(`run_9f2a step 31 should refund "12.00"`)
	}
	if regexp.MustCompile(`1200.00`).Match(r9.Bytes) {
		t.Fatal(`run_9f2a must not match the demo's sed pattern /1200.00/ anywhere`)
	}

	differs := map[int]bool{}
	for _, i := range wantDiffering {
		differs[i] = true
	}

	type op struct {
		Name           string          `json:"name"`
		Target         string          `json:"target"`
		IdempotencyKey string          `json:"idempotency_key"`
		Outcome        json.RawMessage `json:"outcome"`
	}
	type slot struct {
		Role     string `json:"role"`
		Manifest *struct {
			Fields []struct {
				Path   string `json:"path"`
				Digest string `json:"digest"`
			} `json:"fields"`
		} `json:"field_digest_manifest"`
	}
	type payload struct {
		Operation op     `json:"operation"`
		Payload   []slot `json:"payload"`
		StepKey   string `json:"step_key"`
	}
	decode := func(raw []byte, step int, run string) payload {
		t.Helper()
		var p payload
		if err := json.Unmarshal(raw, &p); err != nil {
			t.Fatalf("step %d %s: %v", step, run, err)
		}
		return p
	}
	// inputManifest is the per-field evidence for the (customer-held)
	// arguments: the only place a difference in an argument that is not the
	// target can show up in a receipt at all (Q37).
	inputManifest := func(p payload) string {
		for _, s := range p.Payload {
			if s.Role != "input" || s.Manifest == nil {
				continue
			}
			var b strings.Builder
			for _, f := range s.Manifest.Fields {
				fmt.Fprintf(&b, "%s=%s;", f.Path, f.Digest)
			}
			return b.String()
		}
		return ""
	}

	var got []int
	for i := 0; i < 47; i++ {
		p9, pc := decode(r9.Payloads[i], i, "9f2a"), decode(rc.Payloads[i], i, "c71e")
		if p9.Operation.Name != pc.Operation.Name {
			t.Fatalf("step %d calls %s in one run and %s in the other: it is one script",
				i, p9.Operation.Name, pc.Operation.Name)
		}
		// step_key is the alignment key (Q85). It must match at every step,
		// differing steps included — the argument SHAPE is the same, only the
		// values differ — or `behalf diff` falls back to sequence alignment.
		if p9.StepKey != pc.StepKey {
			t.Fatalf("step %d has different step_keys across runs; the two runs are one script", i)
		}
		same := p9.Operation.Target == pc.Operation.Target &&
			p9.Operation.IdempotencyKey == pc.Operation.IdempotencyKey &&
			bytes.Equal(p9.Operation.Outcome, pc.Operation.Outcome) &&
			inputManifest(p9) == inputManifest(pc)
		if !same {
			got = append(got, i)
		}
	}
	if fmt.Sprint(got) != fmt.Sprint(wantDiffering) {
		t.Fatalf("the runs differ at steps %v, want %v", got, wantDiffering)
	}

	// Step 12: the same request, the same two orders, the other way round.
	p9, pc := decode(r9.Payloads[12], 12, "9f2a"), decode(rc.Payloads[12], 12, "c71e")
	if bytes.Equal(p9.Operation.Outcome, pc.Operation.Outcome) {
		t.Fatal("step 12 outcomes should differ (result order)")
	}
	i9 := strings.Index(string(p9.Operation.Outcome), "ord_5512")
	j9 := strings.Index(string(p9.Operation.Outcome), "ord_5518")
	ic := strings.Index(string(pc.Operation.Outcome), "ord_5512")
	jc := strings.Index(string(pc.Operation.Outcome), "ord_5518")
	if i9 < 0 || j9 < 0 || ic < 0 || jc < 0 {
		t.Fatal("step 12 outcomes should mention both orders")
	}
	if !(i9 < j9) {
		t.Fatal("run_9f2a step 12 should list ord_5512 first")
	}
	if !(jc < ic) {
		t.Fatal("run_c71e step 12 should list ord_5518 first")
	}

	// The selection reaches the operations the receipts name in the clear:
	// the refund, and the steps that address the order or the refund it
	// produced.
	for _, tc := range []struct {
		step int
		a, b string
	}{
		{13, "ord_5512", "ord_5518"},
		{14, "pm_5512", "pm_5518"},
		{16, "shp_5512", "shp_5518"},
		{17, "sku_5512", "sku_5518"},
		{26, "apr_5512_01", "apr_5518_01"},
		{31, "ord_5512", "ord_5518"},
		{33, "ord_5512", "ord_5518"},
	} {
		a, b := decode(r9.Payloads[tc.step], tc.step, "9f2a"), decode(rc.Payloads[tc.step], tc.step, "c71e")
		if a.Operation.Target != tc.a || b.Operation.Target != tc.b {
			t.Fatalf("step %d targets = %q / %q, want %q / %q",
				tc.step, a.Operation.Target, b.Operation.Target, tc.a, tc.b)
		}
	}
	if got := decode(rc.Payloads[31], 31, "c71e").Operation.IdempotencyKey; got != "refund-ord_5518-a1" {
		t.Fatalf("step 31 idempotency key = %q", got)
	}

	// The money discipline that keeps the cover-up target unique: step 31's
	// outcome is the only one in the run that reports a decimal amount.
	// Every later step reports what was refunded in integer cents and names
	// the order and the refund by id. (The chain's own `limit.amount` is a
	// delegated ceiling, not a reported amount, and is "100.00" everywhere.)
	for i := range rc.Payloads {
		if i == 31 {
			continue
		}
		outcome := decode(rc.Payloads[i], i, "c71e").Operation.Outcome
		if bytes.Contains(outcome, []byte(`"amount":`)) {
			t.Fatalf("step %d reports a decimal amount; only step 31 may: %s", i, outcome)
		}
	}
}

// TestReceiptIDsAreULIDs pins the receipt_id shape to the schema pattern
// (Crockford base32, 26 chars) and uniqueness within a run.
func TestReceiptIDsAreULIDs(t *testing.T) {
	ulidRe := regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	res, err := Generate(Run9F2A())
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for i, p := range res.Payloads {
		var r struct {
			ReceiptID string `json:"receipt_id"`
		}
		if err := json.Unmarshal(p, &r); err != nil {
			t.Fatal(err)
		}
		if !ulidRe.MatchString(r.ReceiptID) {
			t.Fatalf("step %d: receipt_id %q is not a ULID", i, r.ReceiptID)
		}
		if seen[r.ReceiptID] {
			t.Fatalf("step %d: duplicate receipt_id %q", i, r.ReceiptID)
		}
		seen[r.ReceiptID] = true
	}
}
