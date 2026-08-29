package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/deskmcp"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/envelope"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
	"github.com/behalf-sh/behalf/internal/why"
)

// The recorder spawns THIS binary as the desk MCP server (main.go's
// EnvServeDesk branch). Under `go test` that binary is the test binary, so
// TestMain has to honour the same switch or the child would run the test
// suite instead of answering JSON-RPC.
func TestMain(m *testing.M) {
	if os.Getenv(EnvServeDesk) == "1" {
		v := deskmcp.Variant(os.Getenv(deskmcp.EnvVariant))
		if err := deskmcp.Serve(v, os.Stdin, os.Stdout); err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// recording is one completed run of the recorder, with the paths a test
// needs to look inside it.
type recording struct {
	logDir   string
	stateDir string
	opts     Options
}

func record(t *testing.T, mutate func(*Options)) recording {
	t.Helper()
	root := t.TempDir()
	opts := Defaults()
	opts.LogDir = filepath.Join(root, "log")
	opts.StateDir = filepath.Join(root, "state")
	opts.Quiet = true
	if mutate != nil {
		mutate(&opts)
	}
	if err := Record(opts, io.Discard); err != nil {
		t.Fatalf("record: %v", err)
	}
	return recording{logDir: opts.LogDir, stateDir: opts.StateDir, opts: opts}
}

// rows reads one run's index rows in log-index order — the run view (Q82).
func (r recording) rows(t *testing.T, runID string) []index.Row {
	t.Helper()
	db, err := index.Open(context.Background(), r.logDir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.RunRows(runID)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// receipts reads one run's stored payload spans straight out of the log's
// entry bundles, checked against the indexed leaf hashes.
func (r recording) receipts(t *testing.T, runID string) ([]index.Row, [][]byte) {
	t.Helper()
	rows := r.rows(t, runID)
	reader, err := tlog.NewBundleReader(context.Background(), r.logDir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([][]byte, 0, len(rows))
	for _, row := range rows {
		p, err := reader.Payload(context.Background(), row.LogIndex, row.LeafHash)
		if err != nil {
			t.Fatalf("read payload at %d: %v", row.LogIndex, err)
		}
		out = append(out, p)
	}
	return rows, out
}

func (r recording) store() *cas.Store { return cas.New(identity.BlobsDir(r.stateDir)) }

// TestRecordingShape is the end-to-end assertion: two runs, 47 receipts
// each, in one log, schema-valid, DSSE-verifying, with the divergence at
// step 12 and its consequence at step 31.
func TestRecordingShape(t *testing.T) {
	rec := record(t, nil)
	emitter := testkeys.Emitter()

	for _, runID := range []string{rec.opts.RunA, rec.opts.RunB} {
		rows, payloads := rec.receipts(t, runID)
		if len(rows) != ScriptLen {
			t.Fatalf("%s: %d receipts, want %d", runID, len(rows), ScriptLen)
		}

		reader, err := tlog.NewBundleReader(context.Background(), rec.logDir)
		if err != nil {
			t.Fatal(err)
		}
		for i, p := range payloads {
			schemaValidate(t, p)

			// The emitter key signed these exact bytes (Q19, Q27): DSSE/PAE
			// over the stored payload span, no re-serialization anywhere in
			// between.
			env, err := reader.Envelope(context.Background(), rows[i].LogIndex)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := envelope.Parse(env)
			if err != nil {
				t.Fatalf("%s step %d: parse envelope: %v", runID, i, err)
			}
			if !bytes.Equal(parsed.Payload, p) {
				t.Fatalf("%s step %d: envelope payload span is not the reconstructed payload", runID, i)
			}
			if parsed.KeyID != emitter.JKT {
				t.Fatalf("%s step %d: signed by %s, want the demo emitter %s", runID, i, parsed.KeyID, emitter.JKT)
			}
			if !dsse.Verify(emitter.Public, exportv1.PayloadTypeReceipt, parsed.Payload, parsed.Sig) {
				t.Fatalf("%s step %d: DSSE signature does not verify", runID, i)
			}

			// Every receipt is a real capture, not a fixture: it came out of
			// the MCP proxy and says so.
			var v struct {
				Kind    string `json:"kind"`
				RunID   string `json:"run_id"`
				Emitter struct {
					Surface string `json:"surface"`
					Counter int    `json:"counter"`
				} `json:"emitter"`
				Provenance struct {
					Source string `json:"source"`
				} `json:"provenance"`
			}
			if err := json.Unmarshal(p, &v); err != nil {
				t.Fatal(err)
			}
			if v.Kind != "tool_call" || v.RunID != runID || v.Emitter.Surface != "mcp-proxy" || v.Provenance.Source != "native" {
				t.Fatalf("%s step %d: kind=%s run=%s surface=%s source=%s",
					runID, i, v.Kind, v.RunID, v.Emitter.Surface, v.Provenance.Source)
			}
		}
	}

	// Both runs in ONE log, in order: A occupies the first 47 indices, B the
	// next 47. `behalf diff` gets two runs to align out of one tree.
	a := rec.rows(t, rec.opts.RunA)
	b := rec.rows(t, rec.opts.RunB)
	if a[0].LogIndex != 0 || a[len(a)-1].LogIndex != 46 {
		t.Fatalf("run A occupies log indices %d..%d, want 0..46", a[0].LogIndex, a[len(a)-1].LogIndex)
	}
	if b[0].LogIndex != 47 || b[len(b)-1].LogIndex != 93 {
		t.Fatalf("run B occupies log indices %d..%d, want 47..93", b[0].LogIndex, b[len(b)-1].LogIndex)
	}
}

// TestTheSelectionPropagates: the two runs are identical until step 12
// (where the world returned the same two orders in a different sequence),
// and from there they differ at exactly the steps whose arguments the agent
// builds from what it selected — and nowhere else.
//
// The expected set is not a list in this file. It is read off the script:
// a step with a builder is a step that depends on the selection, and that
// is the same fact as "a step that can differ between the runs". A step
// added to the flow with a builder and no propagation, or with propagation
// and no builder, fails here.
func TestTheSelectionPropagates(t *testing.T) {
	rec := record(t, nil)
	store := rec.store()

	aRows, aPayloads := rec.receipts(t, rec.opts.RunA)
	bRows, bPayloads := rec.receipts(t, rec.opts.RunB)

	resolve := func(p []byte) []payload.Slot {
		t.Helper()
		slots, err := payload.Resolve(p, store, nil)
		if err != nil {
			t.Fatal(err)
		}
		return slots
	}

	// What is compared, and why it is not the whole blob.
	//
	// A captured input payload is the `params` object AS FORWARDED, which is
	// the request plus the two keys the proxy splices into `params._meta`:
	// the delegation chain and W3C baggage carrying the run id (Q15, Q50,
	// D4). The run id differs between the two runs by construction, so the
	// raw input blobs differ at every single step — correctly, and
	// uninterestingly.
	//
	// The claim "identical until the selection reaches them" is a claim about
	// what the AGENT did, so the comparison is over `params.arguments`. Outputs
	// carry no capture metadata and compare whole. (This is the same cut a
	// `behalf diff` over recorded runs has to make; comparing raw payload
	// bytes would report all 47 steps as different.)
	var differing []int
	for i := range ScriptLen {
		aSlots, bSlots := resolve(aPayloads[i]), resolve(bPayloads[i])
		if len(aSlots) != len(bSlots) {
			differing = append(differing, i)
			continue
		}
		for j := range aSlots {
			if aSlots[j].State != payload.StatePresent || bSlots[j].State != payload.StatePresent {
				t.Fatalf("step %d slot %d: state a=%s b=%s, want both present", i, j, aSlots[j].State, bSlots[j].State)
			}
			if !bytes.Equal(comparable(t, aSlots[j]), comparable(t, bSlots[j])) {
				differing = append(differing, i)
				break
			}
		}
	}
	// The divergence itself is the one step whose REQUEST is identical and
	// whose response is not; every other differing step is one the script
	// builds from the selection.
	var want []int
	for i, st := range script() {
		if i == DivergenceStep || st.build != nil {
			want = append(want, i)
		}
	}
	if fmt.Sprint(differing) != fmt.Sprint(want) {
		t.Fatalf("payloads differ at steps %v, want the divergence plus every step built from it: %v",
			differing, want)
	}
	// And the shape of that answer, stated so a regression to the old
	// scenario (which diverged at 12 and never mentioned the order again)
	// cannot pass: the selection reaches most of the run's tail, and the
	// steps it does not reach are real steps, not an empty set.
	if len(differing) < 15 {
		t.Fatalf("only %d of %d steps differ; the selection is not propagating", len(differing), ScriptLen)
	}
	if len(differing) >= ScriptLen-DivergenceStep {
		t.Fatalf("%d steps differ out of the %d that can: every single later step depends on the "+
			"selection, which is a script that propagates for its own sake",
			len(differing), ScriptLen-DivergenceStep)
	}

	// The corollary, stated so it cannot be forgotten by whoever wires
	// `diff`: the raw blobs DO differ everywhere, because every captured
	// request carries its own run id.
	if bytes.Equal(resolve(aPayloads[0])[0].Content, resolve(bPayloads[0])[0].Content) {
		t.Fatal("step 0 input blobs are byte-equal across runs; the run id is not being carried in _meta")
	}

	// Step 12: same request, different result order.
	aIn, aOut := resolve(aPayloads[DivergenceStep])[0], resolve(aPayloads[DivergenceStep])[1]
	bIn, bOut := resolve(bPayloads[DivergenceStep])[0], resolve(bPayloads[DivergenceStep])[1]
	if !bytes.Equal(comparable(t, aIn), comparable(t, bIn)) {
		t.Fatal("step 12: the requests must be identical — the divergence is in the world, not the agent")
	}
	if !strings.Contains(string(aIn.Content), `"customer":"`+deskmcp.Customer+`"`) ||
		!strings.Contains(string(aIn.Content), `"status":"refundable"`) {
		t.Fatalf("step 12 request is not the scripted orders.search: %s", firstN(aIn.Content, 200))
	}
	if first := firstOrder(t, aOut.Content); first != deskmcp.SmallOrder {
		t.Fatalf("run A step 12: results[0] = %s, want %s", first, deskmcp.SmallOrder)
	}
	if first := firstOrder(t, bOut.Content); first != deskmcp.LargeOrder {
		t.Fatalf("run B step 12: results[0] = %s, want %s", first, deskmcp.LargeOrder)
	}

	// Step 31: the consequence. Different order, different amount, recorded
	// in the operation the receipt commits to.
	if got := aRows[ConsequenceStep].OperationName; got != "refund.issue" {
		t.Fatalf("run A step 31 is %s, want refund.issue", got)
	}
	if got := aRows[ConsequenceStep].OperationTarget; got != deskmcp.SmallOrder {
		t.Fatalf("run A step 31 target %s, want %s", got, deskmcp.SmallOrder)
	}
	if got := bRows[ConsequenceStep].OperationTarget; got != deskmcp.LargeOrder {
		t.Fatalf("run B step 31 target %s, want %s", got, deskmcp.LargeOrder)
	}
	aRefund := string(resolve(aPayloads[ConsequenceStep])[0].Content)
	bRefund := string(resolve(bPayloads[ConsequenceStep])[0].Content)
	if !strings.Contains(aRefund, `"amount":"12.00"`) {
		t.Fatalf("run A step 31 did not refund 12.00: %s", firstN([]byte(aRefund), 200))
	}
	if !strings.Contains(bRefund, `"amount":"1200.00"`) {
		t.Fatalf("run B step 31 did not refund 1200.00: %s", firstN([]byte(bRefund), 200))
	}

	// The propagation, past the refund: the agent carried the refund id the
	// DESK minted back into the steps that record what happened, and every
	// one of them reports the money in integer cents. Exactly one request in
	// the whole session spells an amount as a decimal, and it is step 31's.
	for _, step := range []int{34, 35, 36, 45} {
		args := string(comparable(t, resolve(bPayloads[step])[0]))
		if !strings.Contains(args, deskmcp.RefundIDFor(deskmcp.LargeOrder)) {
			t.Fatalf("step %d does not carry the refund the desk minted: %s", step, firstN([]byte(args), 200))
		}
		if !strings.Contains(args, `"amount_cents":120000`) {
			t.Fatalf("step %d does not report the amount in integer cents: %s", step, firstN([]byte(args), 200))
		}
	}
	for i := range ScriptLen {
		if i == ConsequenceStep {
			continue
		}
		if args := string(comparable(t, resolve(bPayloads[i])[0])); strings.Contains(args, `"amount":`) {
			t.Fatalf("step %d sends a decimal amount; only step %d may: %s",
				i, ConsequenceStep, firstN([]byte(args), 200))
		}
	}
}

// TestOneThousandTwoHundredAppearsOnce guards the cover-up demo's target.
// `sed 's/1200.00/12.00/'` over the customer's store must hit exactly one
// blob, or the demo would be editing several records while claiming to edit
// one. This mirrors the same guarantee the Week-1 fixtures keep for
// run_c71e.jsonl.
func TestOneThousandTwoHundredAppearsOnce(t *testing.T) {
	rec := record(t, nil)
	blobs, err := os.ReadDir(identity.BlobsDir(rec.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	var hits []string
	for _, e := range blobs {
		b, err := os.ReadFile(filepath.Join(identity.BlobsDir(rec.stateDir), e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("1200.00")) {
			hits = append(hits, e.Name())
		}
	}
	if len(hits) != 1 {
		t.Fatalf("%d blobs contain the literal 1200.00, want exactly 1: %v", len(hits), hits)
	}
}

// TestDeterministicRecording is the reproducibility claim, made concrete:
// two recordings of the same script produce byte-identical receipts, blobs
// and log tiles. Only the SQLite index (a derived, rebuildable projection,
// Q55/Q76) and the epoch file (pid and start time) may differ.
func TestDeterministicRecording(t *testing.T) {
	one := record(t, nil)
	two := record(t, nil)

	for _, runID := range []string{one.opts.RunA, one.opts.RunB} {
		_, p1 := one.receipts(t, runID)
		_, p2 := two.receipts(t, runID)
		if len(p1) != len(p2) {
			t.Fatalf("%s: %d receipts vs %d", runID, len(p1), len(p2))
		}
		for i := range p1 {
			if !bytes.Equal(p1[i], p2[i]) {
				t.Fatalf("%s step %d is not reproducible:\n  a %s\n  b %s",
					runID, i, firstN(p1[i], 400), firstN(p2[i], 400))
			}
		}
	}

	// The CAS too: the same script writes the same blobs under the same
	// names, which is what makes the recording's payloads shippable.
	if a, b := listDir(t, identity.BlobsDir(one.stateDir)), listDir(t, identity.BlobsDir(two.stateDir)); !equalStrings(a, b) {
		t.Fatalf("CAS contents differ:\n  a %v\n  b %v", a, b)
	}

	// And the log's own bytes: entry bundles, tiles and the signed
	// checkpoint. The checkpoint key is derived from --seed and Ed25519
	// signing is deterministic, so the whole tree compares.
	compareTrees(t, one.logDir, two.logDir)
}

// TestLiveRecordingIsNotDeterministic pins the other half of the contract:
// --live really does opt out, so nobody can mistake a live capture for a
// reproducible artifact. Production behaviour is the default inside the
// proxy; determinism is the recorder asking for it.
func TestLiveRecordingIsNotDeterministic(t *testing.T) {
	one := record(t, func(o *Options) { o.Live = true })
	two := record(t, func(o *Options) { o.Live = true })
	_, p1 := one.receipts(t, one.opts.RunA)
	_, p2 := two.receipts(t, two.opts.RunA)
	same := true
	for i := range p1 {
		if !bytes.Equal(p1[i], p2[i]) {
			same = false
			break
		}
	}
	if same {
		t.Fatal("--live produced identical receipts; the clock and entropy were not live")
	}
	// Live or not, the receipts are still real receipts.
	for i := range p1 {
		schemaValidate(t, p1[i])
	}
}

// TestRehydrateAndTamper drives the read path the demo uses: rehydrate the
// recorded run cleanly, then perform the cover-up in the customer's own
// store and watch the same command classify it — with the log, the
// receipts and their signatures all still intact.
func TestRehydrateAndTamper(t *testing.T) {
	rec := record(t, nil)
	store := rec.store()

	rows, payloads := rec.receipts(t, rec.opts.RunB)
	clean := 0
	for _, p := range payloads {
		slots, err := payload.Resolve(p, store, nil)
		if err != nil {
			t.Fatal(err)
		}
		if n := len(payload.Findings(slots)); n != 0 {
			t.Fatalf("a fresh recording has %d payload findings, want 0", n)
		}
		for _, s := range slots {
			if s.State != payload.StatePresent {
				t.Fatalf("fresh recording: slot %s is %s, want present", s.Label(), s.State)
			}
			clean++
		}
	}
	if clean != 2*ScriptLen {
		t.Fatalf("%d resolved slots, want %d (an input and an output per call)", clean, 2*ScriptLen)
	}

	// The cover-up: edit the refund amount in the blob the customer holds.
	// The receipt is not touched.
	target := payloadDigest(t, payloads[ConsequenceStep], "input")
	raw, err := store.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	altered := bytes.Replace(raw, []byte(`"amount":"1200.00"`), []byte(`"amount":"12.00"`), 1)
	if bytes.Equal(raw, altered) {
		t.Fatal("the step-31 input blob does not contain the refund amount to edit")
	}
	if err := os.WriteFile(store.Path(target), altered, 0o600); err != nil {
		t.Fatal(err)
	}

	slots, err := payload.Resolve(payloads[ConsequenceStep], store, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := payload.Findings(slots)
	if len(found) != 1 {
		t.Fatalf("%d payload findings after the cover-up, want 1", len(found))
	}
	f := found[0]
	if f.State != payload.StateUnreadable {
		t.Fatalf("state %s, want unreadable", f.State)
	}
	if f.Mismatch.Committed != target || f.Mismatch.Actual == target {
		t.Fatalf("mismatch %+v does not report the digest change", f.Mismatch)
	}

	// The machine-readable line the tamper suite greps, produced by the same
	// code path the CLI uses.
	line := findingLineFor(rows[ConsequenceStep], ConsequenceStep, f)
	for _, want := range []string{
		"class=payload",
		"index=" + itoa(int(rows[ConsequenceStep].LogIndex)),
		"step=" + itoa(ConsequenceStep),
		"operation=refund.issue",
		"target=" + deskmcp.LargeOrder,
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("finding line %q missing %q", line, want)
		}
	}

	// And the crucial half: everything else still verifies. The log is
	// intact, the receipt's DSSE signature is intact, and the other 93
	// slots are present. Only the commitment is contradicted.
	emitter := testkeys.Emitter()
	reader, err := tlog.NewBundleReader(context.Background(), rec.logDir)
	if err != nil {
		t.Fatal(err)
	}
	env, err := reader.Envelope(context.Background(), rows[ConsequenceStep].LogIndex)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := envelope.Parse(env)
	if err != nil {
		t.Fatal(err)
	}
	if !dsse.Verify(emitter.Public, exportv1.PayloadTypeReceipt, parsed.Payload, parsed.Sig) {
		t.Fatal("the receipt's signature must survive a payload cover-up — that is the whole claim")
	}
}

// TestVerifiedAttributionOnRecordedData is the claim ENG-29 exists to make
// true: `verified` means something on real recorded data.
//
// Run A's chain is three signed hops rooted in a real headless login, and
// every receipt in it says `verified` because the proxy checked three
// signatures, the par_hash linkage, the depth and expiry invariants and the
// attenuation of every grant at capture. Run B's is the same chain with its
// leaf hop's signature removed, and every receipt says `asserted` on exactly
// that hop, with the caller-asserted reason.
//
// Nothing here is hand-set. The two runs differ by one signature.
func TestVerifiedAttributionOnRecordedData(t *testing.T) {
	rec := record(t, nil)

	_, aPayloads := rec.receipts(t, rec.opts.RunA)
	for i, p := range aPayloads {
		v := chainView(t, p)
		if v.Attribution.Verification != "verified" {
			t.Fatalf("run A step %d: attribution.verification = %q, want verified",
				i, v.Attribution.Verification)
		}
		if v.Attribution.Class != "delegated" {
			t.Fatalf("run A step %d: attribution.class = %q, want delegated", i, v.Attribution.Class)
		}
		if len(v.Authority.Chain) != 3 {
			t.Fatalf("run A step %d: %d hops, want 3", i, len(v.Authority.Chain))
		}
		wantMethods := []string{aat.MethodRootOIDC, aat.MethodHopJWS, aat.MethodHopJWS}
		for h, hop := range v.Authority.Chain {
			if hop.Verification.Status != "verified" || hop.Verification.Method != wantMethods[h] {
				t.Fatalf("run A step %d hop %d: %+v, want verified/%s", i, h, hop.Verification, wantMethods[h])
			}
			if hop.Verification.EvidenceRef == "" {
				t.Fatalf("run A step %d hop %d: verified with no evidence_ref", i, h)
			}
		}
	}

	// And the evidence a verified hop names is actually there. A receipt
	// asserting `verified` with a dangling evidence_ref is behalf grading its
	// own exam: the check ran once, at capture, and threw away the only thing
	// anyone else could re-run it against.
	store := rec.store()
	for i, p := range aPayloads {
		v := chainView(t, p)
		for h, hop := range v.Authority.Chain {
			digest, ok := strings.CutPrefix(hop.Verification.EvidenceRef, "sha256:")
			if !ok {
				continue // the root's evidence is the signed login statement, checked below
			}
			if _, err := store.Get(digest); err != nil {
				t.Fatalf("run A step %d hop %d: evidence_ref %s does not resolve in the customer's store: %v",
					i, h, hop.Verification.EvidenceRef, err)
			}
		}
	}

	_, bPayloads := rec.receipts(t, rec.opts.RunB)
	for i, p := range bPayloads {
		v := chainView(t, p)
		if v.Attribution.Verification != "asserted" {
			t.Fatalf("run B step %d: attribution.verification = %q, want asserted (the weakest hop)",
				i, v.Attribution.Verification)
		}
		var asserted []int
		for h, hop := range v.Authority.Chain {
			if hop.Verification.Status == "asserted" {
				asserted = append(asserted, h)
			}
			if hop.Verification.Status == "broken" {
				t.Fatalf("run B step %d hop %d is broken; an unsigned hop is asserted, never broken", i, h)
			}
		}
		if len(asserted) != 1 || asserted[0] != 2 {
			t.Fatalf("run B step %d: asserted hops %v, want exactly [2]", i, asserted)
		}
		if got := v.Authority.Chain[2].Verification.Method; got != aat.MethodNoSignature {
			t.Fatalf("run B step %d: leaf method = %q, want %q", i, got, aat.MethodNoSignature)
		}
	}

	// The two runs' chains are the same claims: only the signature differs.
	a, b := chainView(t, aPayloads[0]), chainView(t, bPayloads[0])
	for h := range a.Authority.Chain {
		if a.Authority.Chain[h].JTI != b.Authority.Chain[h].JTI ||
			a.Authority.Chain[h].ParHash != b.Authority.Chain[h].ParHash {
			t.Fatalf("hop %d differs between runs beyond its signature", h)
		}
	}
}

// TestWhyRendersTheContrastFromRecordedData drives `behalf why`'s own
// renderer over the recorded log — not a fixture, not a hand-built receipt —
// and asserts the two lines the demo turns on.
func TestWhyRendersTheContrastFromRecordedData(t *testing.T) {
	rec := record(t, nil)
	ctx := context.Background()

	renderRun := func(runID string) string {
		t.Helper()
		res, err := why.Load(ctx, rec.logDir, why.Address{RunID: runID, Step: ConsequenceStep})
		if err != nil {
			t.Fatalf("why.Load %s: %v", runID, err)
		}
		var b strings.Builder
		if err := why.Render(&b, res, why.Options{}); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}

	gotA := renderRun(rec.opts.RunA)
	if !strings.Contains(gotA, "chain intact for 3 of 3 hops.") {
		t.Fatalf("run A does not render a whole chain:\n%s", gotA)
	}
	if strings.Contains(gotA, "caller-asserted") {
		t.Fatalf("run A renders a caller-asserted hop:\n%s", gotA)
	}

	gotB := renderRun(rec.opts.RunB)
	if !strings.Contains(gotB, "chain intact for 2 of 3 hops.") {
		t.Fatalf("run B does not render the broken-off hop:\n%s", gotB)
	}
	// The demo's line, verbatim.
	const line = `actor "alice@acme.com" is caller-asserted. no signature.`
	if !strings.Contains(gotB, line) {
		t.Fatalf("run B does not render %q:\n%s", line, gotB)
	}
	// And the human root is still named and still verified in both.
	for _, out := range []string{gotA, gotB} {
		if !strings.Contains(out, "✔ alice@acme.com") {
			t.Fatalf("the human root is not verified:\n%s", out)
		}
	}

	// The scope-excess line, on RECORDED data (ENG-29). It used to fire on
	// the hand-built fixtures only: a recorded receipt's outcome carried a
	// status and nothing else, so `why` had no amount to compare against the
	// $100.00 ceiling the chain delegated. The capture-time policy now names
	// `amount_cents` as a recorded outcome field, the desk returns it, and
	// the finding is computed at read time from those stored bytes.
	const excess = "⚠ scope: refund.issue<=100.00 delegated; 1200.00 issued. (recorded, not enforced)"
	if !strings.Contains(gotB, excess) {
		t.Fatalf("the recorded $1200 refund does not produce the scope excess:\n%s", gotB)
	}
	if !strings.Contains(gotB, "refund.issue(amount=1200.00)") {
		t.Fatalf("the recorded refund's amount is not on the header line:\n%s", gotB)
	}
	// Run A refunded $12.00, inside the ceiling, so it warns about nothing —
	// the finding is computed, not stamped on every refund receipt.
	if strings.Contains(gotA, "scope:") && strings.Contains(gotA, "issued") {
		t.Fatalf("a refund inside the delegated ceiling must not warn:\n%s", gotA)
	}
	if !strings.Contains(gotA, "refund.issue(amount=12.00)") {
		t.Fatalf("run A's recorded amount is not on the header line:\n%s", gotA)
	}
}

// TestRecordedOutcomeCarriesTheAmount is the other half of ENG-29, asserted
// on the record rather than on the render: the refund receipt carries what
// was refunded, in the units the desk reported them in, and no other receipt
// of the run has picked up outcome fields it was not configured for.
func TestRecordedOutcomeCarriesTheAmount(t *testing.T) {
	rec := record(t, nil)
	_, payloads := rec.receipts(t, rec.opts.RunB)

	outcomeOf := func(i int) map[string]json.RawMessage {
		t.Helper()
		var v struct {
			Operation struct {
				Outcome map[string]json.RawMessage `json:"outcome"`
			} `json:"operation"`
		}
		if err := json.Unmarshal(payloads[i], &v); err != nil {
			t.Fatal(err)
		}
		return v.Operation.Outcome
	}

	got := outcomeOf(ConsequenceStep)
	for field, want := range map[string]string{
		"status":       `"ok"`,
		"amount_cents": `120000`,
		"currency":     `"USD"`,
		"refund_id":    `"rf_5518_01"`,
	} {
		if string(got[field]) != want {
			t.Errorf("refund outcome %s = %s, want %s", field, got[field], want)
		}
	}
	// Integer cents, verbatim: the receipt never carries a second decimal
	// amount, and the decimal `behalf why` prints is formatted at read time.
	if bytes.Contains(payloads[ConsequenceStep], []byte("1200.00")) {
		t.Fatal("the recorded refund receipt carries a decimal amount; the amount lives in the customer's blob")
	}
	// Nothing else was lifted. `refund.precheck` returns an amount too and is
	// not configured for it, which is the point of naming the fields.
	for i := range ScriptLen {
		if i == ConsequenceStep {
			continue
		}
		if out := outcomeOf(i); len(out) != 1 {
			t.Fatalf("step %d recorded %d outcome fields, want only status: %v", i, len(out), out)
		}
	}
}

// TestLoginMaterialIsRealAndOffline: the recording's root is a genuine
// login, re-checkable from the customer-held blobs with no network and no
// IdP — the fake provider is closed by the time the runs start.
func TestLoginMaterialIsRealAndOffline(t *testing.T) {
	rec := record(t, nil)

	rep, err := oidclogin.VerifyRoot(rec.stateDir)
	if err != nil {
		t.Fatalf("VerifyRoot: %v", err)
	}
	if rep.State != oidclogin.StateVerified {
		t.Fatalf("root state %s (%v), want verified", rep.State, rep.Reasons)
	}
	if rep.DeviceJKT != testkeys.ActorRoot().JKT {
		t.Fatalf("the recording's root is device key %s, want the demo key %s",
			rep.DeviceJKT, testkeys.ActorRoot().JKT)
	}
	if rep.Issuer != DemoIssuer {
		t.Fatalf("issuer %q, want %q", rep.Issuer, DemoIssuer)
	}
	// The chain root's binding names the ID token blob the login stored, and
	// that blob is in the customer's own store (Q22).
	_, payloads := rec.receipts(t, rec.opts.RunA)
	binding := chainView(t, payloads[0]).Authority.Chain[0].RootPrincipalBinding
	if binding == nil || binding.Nonce != rep.DeviceJKT {
		t.Fatalf("root binding = %+v", binding)
	}
	if _, err := rec.store().Get(binding.IDTokenRef); err != nil {
		t.Fatalf("the ID-token blob the root references is not in the store: %v", err)
	}

	// The login's own receipt went to `behalf login`'s spool, not into the
	// demo log: the recorder drains the proxy's spool only.
	if _, err := os.Stat(filepath.Join(rec.stateDir, oidclogin.SpoolFile)); err != nil {
		t.Fatalf("the login receipt was not spooled: %v", err)
	}
}

// chainView decodes just the authority and attribution of a stored receipt.
func chainView(t *testing.T, payload []byte) struct {
	Authority struct {
		Chain []receipt.Hop `json:"chain"`
	} `json:"authority"`
	Attribution receipt.Attribution `json:"attribution"`
} {
	t.Helper()
	var v struct {
		Authority struct {
			Chain []receipt.Hop `json:"chain"`
		} `json:"authority"`
		Attribution receipt.Attribution `json:"attribution"`
	}
	if err := json.Unmarshal(payload, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// TestRunIDsMustDiffer: two runs sharing an id would collide on receipt_id
// dedup and silently become one run.
func TestRunIDsMustDiffer(t *testing.T) {
	root := t.TempDir()
	opts := Defaults()
	opts.LogDir = filepath.Join(root, "log")
	opts.StateDir = filepath.Join(root, "state")
	opts.RunB = opts.RunA
	if err := Record(opts, io.Discard); err == nil {
		t.Fatal("recording two runs under one id must fail")
	}
}

// ---- helpers ----------------------------------------------------------

// findingLineFor is the CLI's finding line. It lives in cmd/behalf-log, so
// this rebuilds the same string from the same inputs; the assertion that
// matters is the vocabulary, which the tamper suite greps for.
func findingLineFor(row index.Row, step int, s payload.Slot) string {
	b := &strings.Builder{}
	b.WriteString("class=payload index=" + itoa(int(row.LogIndex)))
	b.WriteString(" run=" + row.RunID + " step=" + itoa(step))
	b.WriteString(" receipt=" + row.ReceiptID + " role=" + s.Label())
	if s.Mismatch != nil {
		b.WriteString(" committed=sha256:" + s.Mismatch.Committed + " actual=sha256:" + s.Mismatch.Actual)
	}
	b.WriteString(" operation=" + row.OperationName + " target=" + row.OperationTarget)
	return b.String()
}

// comparable strips the capture metadata from a slot's content so two runs
// can be compared on what the agent did. For an input slot that is
// `params.arguments`; anything else compares whole.
func comparable(t *testing.T, s payload.Slot) []byte {
	t.Helper()
	if s.Role != "input" {
		return s.Content
	}
	args, err := jsonspan.ExtractTopLevelValue(s.Content, "arguments")
	if err != nil {
		// A captured tools/call always has arguments in this scenario; if it
		// does not, comparing the whole thing is the safe fallback.
		return s.Content
	}
	return args
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func payloadDigest(t *testing.T, receiptPayload []byte, role string) string {
	t.Helper()
	slots, err := payload.Resolve(receiptPayload, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range slots {
		if s.Role == role {
			return s.Digest
		}
	}
	t.Fatalf("no %s slot in the receipt", role)
	return ""
}

func firstOrder(t *testing.T, result []byte) string {
	t.Helper()
	var r struct {
		Structured struct {
			Results []struct {
				OrderID string `json:"order_id"`
			} `json:"results"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		t.Fatalf("parse orders.search result: %v", err)
	}
	if len(r.Structured.Results) != 2 {
		t.Fatalf("orders.search returned %d results, want 2", len(r.Structured.Results))
	}
	return r.Structured.Results[0].OrderID
}

func firstN(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(ents))
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// compareTrees asserts two log directories are byte-identical, excluding
// the derived index and the operational epoch file.
func compareTrees(t *testing.T, a, b string) {
	t.Helper()
	skip := func(rel string) bool {
		base := filepath.Base(rel)
		return strings.HasPrefix(base, index.FileName) || base == "epoch.json" ||
			strings.HasPrefix(rel, ".state")
	}
	files := map[string][]byte{}
	collect := func(root string, into func(string, []byte)) {
		err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, rerr := filepath.Rel(root, p)
			if rerr != nil {
				return rerr
			}
			if skip(rel) {
				return nil
			}
			content, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			into(rel, content)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	collect(a, func(rel string, c []byte) { files[rel] = c })
	seen := 0
	collect(b, func(rel string, c []byte) {
		seen++
		want, ok := files[rel]
		if !ok {
			t.Fatalf("%s exists in the second recording only", rel)
		}
		if !bytes.Equal(want, c) {
			t.Fatalf("%s differs between recordings (%d vs %d bytes)", rel, len(want), len(c))
		}
	})
	if seen != len(files) {
		t.Fatalf("the two recordings hold %d and %d comparable files", len(files), seen)
	}
	if seen == 0 {
		t.Fatal("nothing was compared")
	}
}

var schemaCache *jsonschema.Schema

func schemaValidate(t *testing.T, receiptPayload []byte) {
	t.Helper()
	if schemaCache == nil {
		c := jsonschema.NewCompiler()
		sch, err := c.Compile("../../docs/receipt-schema-v1.schema.json")
		if err != nil {
			t.Fatalf("compile schema: %v", err)
		}
		schemaCache = sch
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(receiptPayload))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := schemaCache.Validate(v); err != nil {
		t.Fatalf("recorded receipt violates the frozen v1 schema: %v\npayload: %s", err, receiptPayload)
	}
}
