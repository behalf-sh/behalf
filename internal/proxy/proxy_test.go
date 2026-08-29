package proxy

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
)

// TestPassThroughFidelity is the transparency claim, tested both ways:
// every non-tools/call line reaches the server byte-identical to what the
// client sent, every server line reaches the client byte-identical to what
// the server sent, and the one tools/call line that IS modified differs
// only inside params._meta.
func TestPassThroughFidelity(t *testing.T) {
	sent := []string{
		initializeLine(`1`),
		initializedLine(),
		toolsListLine(`2`),
		// The client answering the server's sampling request: a
		// client->server RESPONSE, which must cross untouched.
		`{"jsonrpc":"2.0","id":"srv-1","result":{"role":"assistant","content":{"type":"text","text":"pong"},"model":"none"}}` + "\n",
		toolsCallLine(`3`, "orders.search", `{"query":"acme"}`),
		// A response to an id the proxy never saw: unmatched, no receipt.
		`{"jsonrpc":"2.0","id":"stray","result":{"ignored":true}}` + "\n",
	}
	res := runSession(t, sessionOpts{
		lines:  sent,
		server: map[string]string{envPush: "1"},
	})
	if res.err != nil {
		t.Fatalf("proxy: %v (stderr %s)", res.err, res.stderr)
	}

	got := splitLines(res.inWitness)
	if len(got) != len(sent) {
		t.Fatalf("server saw %d lines, client sent %d:\n%s", len(got), len(sent), res.inWitness)
	}
	for i, want := range sent {
		isToolsCall := methodOf([]byte(want)) == MethodToolsCall
		if !isToolsCall {
			if !bytes.Equal(got[i], []byte(want)) {
				t.Fatalf("line %d crossed modified:\n  sent %s  saw  %s", i, want, got[i])
			}
			continue
		}
		assertDiffersOnlyInMeta(t, []byte(want), got[i])
	}

	// Server->client: verbatim, in order, nothing added or dropped.
	if !bytes.Equal(res.stdout, res.outWitness) {
		t.Fatalf("client stdout is not byte-identical to what the server wrote:\n  client %q\n  server %q", res.stdout, res.outWitness)
	}

	// Q2's closed rule: exactly one receipt, for the one tools/call.
	rs, _ := spooledReceipts(t, res.spoolDir)
	if len(rs) != 1 {
		t.Fatalf("spooled %d receipts, want exactly 1 (only tools/call is a receipt)", len(rs))
	}
	if rs[0].Operation.Name != "orders.search" || rs[0].Kind != KindToolCall {
		t.Fatalf("receipt = kind %q op %q", rs[0].Kind, rs[0].Operation.Name)
	}
}

// assertDiffersOnlyInMeta compares two lines as JSON: identical once
// params._meta is removed from the forwarded one, and the injected _meta
// carries the baggage key.
func assertDiffersOnlyInMeta(t *testing.T, sent, forwarded []byte) {
	t.Helper()
	var a, b map[string]any
	if err := json.Unmarshal(sent, &a); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(forwarded, &b); err != nil {
		t.Fatalf("forwarded line is not JSON: %v (%s)", err, forwarded)
	}
	bp, _ := b["params"].(map[string]any)
	if bp == nil {
		t.Fatalf("forwarded tools/call lost its params: %s", forwarded)
	}
	meta, ok := bp["_meta"].(map[string]any)
	if !ok {
		t.Fatalf("forwarded tools/call has no params._meta: %s", forwarded)
	}
	if _, ok := meta[MetaKeyBaggage].(string); !ok {
		t.Fatalf("params._meta carries no %s: %s", MetaKeyBaggage, forwarded)
	}
	delete(bp, "_meta")
	if len(bp) == 0 {
		delete(b, "params")
		delete(a, "params")
	}
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("tools/call differs outside params._meta:\n  sent      %#v\n  forwarded %#v", a, b)
	}
}

// TestReceiptIsSchemaValidAndSigned walks the whole capture contract on one
// call: schema validity, DSSE verification by the emitter key, the risk
// assignment and its policy digest, the intent digest, the payload slots
// and their field-digest manifests.
func TestReceiptIsSchemaValidAndSigned(t *testing.T) {
	res := runSession(t, sessionOpts{lines: []string{
		initializeLine(`1`),
		toolsCallLine(`2`, "refund.issue", `{"order_id":"ord_5518","amount":"1200.00"}`),
	}})
	if res.err != nil {
		t.Fatalf("proxy: %v (stderr %s)", res.err, res.stderr)
	}
	rs, envs := spooledReceipts(t, res.spoolDir)
	if len(rs) != 1 {
		t.Fatalf("spooled %d receipts, want 1", len(rs))
	}
	r, env := rs[0], envs[0]
	schemaValidate(t, env.Payload)

	emitter, err := identity.LoadKey(identity.EmitterKeyPath(res.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if env.KeyID != emitter.JKT {
		t.Fatalf("envelope keyid %s, want emitter %s", env.KeyID, emitter.JKT)
	}
	if !dsse.Verify(emitter.Public, exportv1.PayloadTypeReceipt, env.Payload, env.Sig) {
		t.Fatal("emitter DSSE signature does not verify over the spooled payload")
	}
	if r.Emitter.Surface != Surface || r.Emitter.JKT != emitter.JKT {
		t.Fatalf("emitter = %+v", r.Emitter)
	}

	// risk_class is assigned by the capture-time policy, never self-reported,
	// and the digest of that policy rides the receipt (Q6).
	if r.RiskClass != "high" {
		t.Fatalf("refund.issue classified %q, want high", r.RiskClass)
	}
	if want := cas.Digest([]byte(DefaultPolicyJSON)); r.RiskPolicyDigest != want {
		t.Fatalf("risk_policy_digest = %s, want the built-in policy's %s", r.RiskPolicyDigest, want)
	}

	if r.Operation.Outcome.Status != "ok" {
		t.Fatalf("outcome = %+v", r.Operation.Outcome)
	}
	if r.Attempt == nil || r.Attempt.IntentDigest == "" {
		t.Fatal("completion receipt carries no intent digest (Q4)")
	}
	if r.Provenance.Source != "native" {
		t.Fatalf("provenance = %+v", r.Provenance)
	}

	// Payload slots: the raw params and the raw result, customer-held in the
	// CAS, each with a field-digest manifest over its top-level fields.
	if len(r.Payload) != 2 {
		t.Fatalf("payload has %d slots, want input+output", len(r.Payload))
	}
	store := cas.New(identity.BlobsDir(res.stateDir))
	for _, slot := range r.Payload {
		if slot.Custody != "customer-held" || slot.State != "present" {
			t.Fatalf("slot %q: custody=%q state=%q", slot.Role, slot.Custody, slot.State)
		}
		if slot.Ref != "sha256:"+slot.Digest {
			t.Fatalf("slot %q ref %q is not the content address", slot.Role, slot.Ref)
		}
		blob, err := store.Get(slot.Digest)
		if err != nil {
			t.Fatalf("slot %q blob: %v", slot.Role, err)
		}
		if slot.Size != len(blob) {
			t.Fatalf("slot %q size %d, blob is %d bytes", slot.Role, slot.Size, len(blob))
		}
		if slot.Manifest == nil || len(slot.Manifest.Fields) == 0 {
			t.Fatalf("slot %q has no field-digest manifest (Q37)", slot.Role)
		}
		assertManifestMatches(t, blob, slot.Manifest.Fields)
	}

	// The input slot is the params bytes as forwarded, and the intent
	// digest is computed over those same bytes.
	input := slotByRole(t, r.Payload, "input")
	params, err := store.Get(input.Digest)
	if err != nil {
		t.Fatal(err)
	}
	if got := intentDigest("refund.issue", params); got != r.Attempt.IntentDigest {
		t.Fatalf("intent_digest %s does not cover the recorded params (%s)", r.Attempt.IntentDigest, got)
	}
	if !bytes.Contains(params, []byte(`"_meta"`)) {
		t.Fatal("the recorded input is not the params as forwarded: no _meta")
	}
}

// assertManifestMatches recomputes the field-digest manifest from the blob
// itself: one entry per top-level field, each the SHA-256 of that field's
// exact raw value bytes (Q37). A manifest a verifier could not reproduce
// from the payload it commits to would be decoration, not evidence.
func assertManifestMatches(t *testing.T, blob []byte, fields []receipt.ManifestField) {
	t.Helper()
	spans, err := jsonspan.TopLevelKeys(blob)
	if err != nil {
		t.Fatalf("scan blob: %v", err)
	}
	if len(spans) != len(fields) {
		t.Fatalf("manifest has %d fields, payload has %d top-level fields", len(fields), len(spans))
	}
	want := map[string]string{}
	for _, f := range spans {
		want["$."+f.Name] = digestOf(blob[f.Start:f.End])
	}
	for _, f := range fields {
		if want[f.Path] != f.Digest {
			t.Fatalf("manifest entry %s = %s, recomputes to %s", f.Path, f.Digest, want[f.Path])
		}
	}
}

// slotByRole finds one payload slot.
func slotByRole(t *testing.T, slots []receipt.Slot, role string) receipt.Slot {
	t.Helper()
	for _, s := range slots {
		if s.Role == role {
			return s
		}
	}
	t.Fatalf("no payload slot with role %q", role)
	return receipt.Slot{}
}

// TestOutcomeErrorPaths: a JSON-RPC error and a result carrying isError
// both land as error outcomes, with the raw failure recorded as the output
// payload (Q4 — outcome covers failure of the attempted operation).
func TestOutcomeErrorPaths(t *testing.T) {
	res := runSession(t, sessionOpts{lines: []string{
		toolsCallLine(`1`, "orders.explode", `{"why":"testing"}`),
		toolsCallLine(`2`, "no.such.tool", `{}`),
	}})
	if res.err != nil {
		t.Fatalf("proxy: %v", res.err)
	}
	rs, envs := spooledReceipts(t, res.spoolDir)
	if len(rs) != 2 {
		t.Fatalf("spooled %d receipts, want 2", len(rs))
	}
	for i := range rs {
		schemaValidate(t, envs[i].Payload)
		if rs[i].Operation.Outcome.Status != "error" {
			t.Fatalf("receipt %d outcome = %+v, want error", i, rs[i].Operation.Outcome)
		}
	}
	if got := rs[0].Operation.Outcome.Error; got != "tool result reported isError" {
		t.Fatalf("isError outcome message = %q", got)
	}
	if !bytes.Contains(envs[1].Payload, []byte(`"jsonrpc_error_code":-32602`)) {
		t.Fatalf("jsonrpc error code not recorded: %s", envs[1].Payload)
	}
}

// TestCountersStrictlyMonotonicAcrossRestarts: custody begins at
// capture-signature, and the per-emitter counter is what makes a gap in the
// capture-to-append window findable (Q48). It must not restart with the
// process.
func TestCountersStrictlyMonotonicAcrossRestarts(t *testing.T) {
	state := t.TempDir()
	for run := 0; run < 3; run++ {
		res := runSession(t, sessionOpts{
			stateDir: state,
			lines: []string{
				toolsCallLine(`1`, "orders.search", `{"query":"a"}`),
				toolsCallLine(`2`, "orders.search", `{"query":"b"}`),
			},
		})
		if res.err != nil {
			t.Fatalf("run %d: %v", run, res.err)
		}
	}
	rs, _ := spooledReceipts(t, filepath.Join(state, DefaultSpoolDirName))
	if len(rs) != 6 {
		t.Fatalf("spooled %d receipts across three runs, want 6", len(rs))
	}
	for i, r := range rs {
		if r.Emitter.Counter != i {
			t.Fatalf("receipt %d has counter %d: counters are not gapless and monotonic (%v)", i, r.Emitter.Counter, counters(rs))
		}
	}
}

func counters(rs []receipt.Receipt) []int {
	out := make([]int, 0, len(rs))
	for _, r := range rs {
		out = append(out, r.Emitter.Counter)
	}
	return out
}

// TestStepKeyStabilityAndArgShape: identical calls in the same position
// hash the same across runs, and a changed argument shape hashes
// differently — the property the flagship diff rests on (Q85).
func TestStepKeyStabilityAndArgShape(t *testing.T) {
	script := []string{
		toolsCallLine(`1`, "orders.search", `{"query":"acme"}`),
		toolsCallLine(`2`, "refund.issue", `{"order_id":"ord_5518","amount":"1200.00"}`),
	}
	a := runSession(t, sessionOpts{lines: script})
	b := runSession(t, sessionOpts{lines: []string{
		// Same tools, same argument shapes, different values.
		toolsCallLine(`7`, "orders.search", `{"query":"zeta"}`),
		toolsCallLine(`8`, "refund.issue", `{"order_id":"ord_0001","amount":"12.00"}`),
	}})
	c := runSession(t, sessionOpts{lines: []string{
		toolsCallLine(`1`, "orders.search", `{"query":"acme"}`),
		// Argument shape changed: an extra top-level key.
		toolsCallLine(`2`, "refund.issue", `{"order_id":"ord_5518","amount":"1200.00","reason":"duplicate"}`),
	}})
	for _, r := range []sessionResult{a, b, c} {
		if r.err != nil {
			t.Fatalf("proxy: %v", r.err)
		}
	}
	ra, _ := spooledReceipts(t, a.spoolDir)
	rb, _ := spooledReceipts(t, b.spoolDir)
	rc, _ := spooledReceipts(t, c.spoolDir)

	if ra[0].StepKey != rb[0].StepKey || ra[1].StepKey != rb[1].StepKey {
		t.Fatal("step_key is not stable across runs of the same scripted session")
	}
	if ra[0].StepKey == ra[1].StepKey {
		t.Fatal("different steps share a step_key")
	}
	if rc[1].StepKey == ra[1].StepKey {
		t.Fatal("step_key did not change when the argument shape changed")
	}
	if rc[0].StepKey != ra[0].StepKey {
		t.Fatal("an unchanged earlier step lost its step_key when a later step changed")
	}
}

// TestRunIDProvenanceRungs covers each precedence rung the proxy can reach
// (Q7); `hook-session` belongs to the Claude Code hook surface.
func TestRunIDProvenanceRungs(t *testing.T) {
	const traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	cases := []struct {
		name       string
		env        map[string]string
		provenance string
		runID      string
		traceID    string
	}{
		{
			name:       "caller supplied",
			env:        map[string]string{EnvRunID: "run_from_caller", EnvTraceparent: traceparent},
			provenance: ProvenanceCaller,
			runID:      "run_from_caller",
			traceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			name:       "traceparent",
			env:        map[string]string{EnvTraceparent: traceparent},
			provenance: ProvenanceTraceparent,
			runID:      "4bf92f3577b34da6a3ce929d0e0e4736",
			traceID:    "4bf92f3577b34da6a3ce929d0e0e4736",
		},
		{
			name:       "proxy session",
			env:        map[string]string{},
			provenance: ProvenanceProxySession,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := runSession(t, sessionOpts{
				lines: []string{toolsCallLine(`1`, "orders.search", `{"query":"a"}`)},
				env:   tc.env,
			})
			if res.err != nil {
				t.Fatal(res.err)
			}
			rs, envs := spooledReceipts(t, res.spoolDir)
			schemaValidate(t, envs[0].Payload)
			r := rs[0]
			if r.RunIDProvenance != tc.provenance {
				t.Fatalf("run_id_provenance = %q, want %q", r.RunIDProvenance, tc.provenance)
			}
			if tc.runID != "" && r.RunID != tc.runID {
				t.Fatalf("run_id = %q, want %q", r.RunID, tc.runID)
			}
			if tc.runID == "" && r.RunID == "" {
				t.Fatal("proxy-session rung produced no run_id")
			}
			switch {
			case tc.traceID == "" && r.Correlation != nil && r.Correlation.TraceID != "":
				t.Fatalf("unexpected correlation.trace_id %q", r.Correlation.TraceID)
			case tc.traceID != "" && (r.Correlation == nil || r.Correlation.TraceID != tc.traceID):
				t.Fatalf("correlation.trace_id = %+v, want %q", r.Correlation, tc.traceID)
			}
			// The run id also rides W3C baggage on the wire.
			forwarded := splitLines(res.inWitness)
			if !bytes.Contains(forwarded[0], []byte(BaggageRunKey+"="+r.RunID)) {
				t.Fatalf("baggage does not carry the run id: %s", forwarded[0])
			}
		})
	}
}

// TestOutOfOrderResponsesMatchByID: the fake server answers in pairs,
// reversed. Each receipt must still describe its own call.
func TestOutOfOrderResponsesMatchByID(t *testing.T) {
	res := runSession(t, sessionOpts{
		server: map[string]string{envReverse: "1"},
		lines: []string{
			toolsCallLine(`1`, "orders.search", `{"query":"first"}`),
			toolsCallLine(`2`, "refund.issue", `{"order_id":"ord_second","amount":"12.00"}`),
		},
	})
	if res.err != nil {
		t.Fatalf("proxy: %v (stderr %s)", res.err, res.stderr)
	}
	rs, _ := spooledReceipts(t, res.spoolDir)
	if len(rs) != 2 {
		t.Fatalf("spooled %d receipts, want 2", len(rs))
	}
	store := cas.New(identity.BlobsDir(res.stateDir))
	byTool := map[string]string{}
	for _, r := range rs {
		out := slotByRole(t, r.Payload, "output")
		blob, err := store.Get(out.Digest)
		if err != nil {
			t.Fatal(err)
		}
		byTool[r.Operation.Name] = string(blob)
	}
	if !bytes.Contains([]byte(byTool["orders.search"]), []byte("2 orders for first")) {
		t.Fatalf("orders.search receipt carries the wrong result: %s", byTool["orders.search"])
	}
	if !bytes.Contains([]byte(byTool["refund.issue"]), []byte("ord_second")) {
		t.Fatalf("refund.issue receipt carries the wrong result: %s", byTool["refund.issue"])
	}
	// Distinct counters and distinct ordinals for two in-flight calls.
	if rs[0].Emitter.Counter == rs[1].Emitter.Counter {
		t.Fatal("two in-flight calls shared an emitter counter")
	}
	if rs[0].StepKey == rs[1].StepKey {
		t.Fatal("two in-flight calls shared a step_key")
	}
}

// TestCrashLeavesOrphanIntent is Q4's payment-fired-agent-died case: the
// server dies with the request received and no response sent, and recovery
// mints a schema-valid orphan_intent carrying the spooled intent digest.
func TestCrashLeavesOrphanIntent(t *testing.T) {
	state := t.TempDir()
	res := runSession(t, sessionOpts{
		stateDir: state,
		server:   map[string]string{envDieAfter: "1"},
		lines: []string{
			toolsCallLine(`1`, "refund.issue", `{"order_id":"ord_5518","amount":"1200.00"}`),
		},
	})
	// The server exiting mid-call is not a proxy error.
	_ = res.err

	spoolDir := filepath.Join(state, DefaultSpoolDirName)
	if rs, _ := spooledReceipts(t, spoolDir); len(rs) != 0 {
		t.Fatalf("a completion was spooled for a call that never returned: %+v", rs)
	}
	rec, err := spool.Recover(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Orphans) != 1 {
		t.Fatalf("recovery found %d orphaned intents, want 1", len(rec.Orphans))
	}
	spooledDigest := rec.Orphans[0].IntentDigest

	// Restarting the proxy flushes it.
	res2 := runSession(t, sessionOpts{
		stateDir: state,
		lines:    []string{toolsCallLine(`1`, "orders.search", `{"query":"after-restart"}`)},
	})
	if res2.err != nil {
		t.Fatalf("restart: %v", res2.err)
	}
	rs, envs := spooledReceipts(t, spoolDir)
	if len(rs) != 2 {
		t.Fatalf("after restart the spool holds %d receipts, want the orphan plus the new call", len(rs))
	}
	orphan, orphanEnv := rs[0], envs[0]
	if orphan.Kind != KindOrphanIntent {
		t.Fatalf("first receipt kind = %q, want %s", orphan.Kind, KindOrphanIntent)
	}
	schemaValidate(t, orphanEnv.Payload)
	if orphan.Attempt == nil || orphan.Attempt.IntentDigest != spooledDigest {
		t.Fatalf("orphan_intent does not carry the spooled intent digest: %+v", orphan.Attempt)
	}
	if orphan.Operation.Name != "refund.issue" || orphan.Operation.Outcome.Status != "error" {
		t.Fatalf("orphan operation = %+v", orphan.Operation)
	}
	if orphan.RiskClass != "high" {
		t.Fatalf("orphan lost the capture-time risk class: %q", orphan.RiskClass)
	}
	// One crossing, one counter: the orphan reuses what the intent stamped,
	// so the appended sequence has no gap (Q48).
	if orphan.Emitter.Counter != 0 || rs[1].Emitter.Counter != 1 {
		t.Fatalf("counters after recovery = %v, want 0,1", counters(rs))
	}
	// Recovery is idempotent: a second pass mints nothing new.
	if _, err := spool.Recover(spoolDir); err != nil {
		t.Fatal(err)
	}
	flushed, err := RecoverOrphans(Config{StateDir: state})
	if err != nil {
		t.Fatal(err)
	}
	if flushed != 0 {
		t.Fatalf("a second recovery pass flushed %d intents, want 0", flushed)
	}
}

// TestChainCarriageAndAttribution: with chain material the proxy injects it
// under sh.behalf/chain, embeds it whole in the receipt, and records the
// out-of-band carriage route; without it, receipts say unattributed.
func TestChainCarriageAndAttribution(t *testing.T) {
	chain := testChainJSON()
	res := runSession(t, sessionOpts{
		chain: chain,
		lines: []string{toolsCallLine(`1`, "orders.search", `{"query":"a"}`)},
	})
	if res.err != nil {
		t.Fatalf("proxy: %v (stderr %s)", res.err, res.stderr)
	}
	forwarded := splitLines(res.inWitness)[0]
	var line map[string]any
	if err := json.Unmarshal(forwarded, &line); err != nil {
		t.Fatal(err)
	}
	meta := line["params"].(map[string]any)["_meta"].(map[string]any)
	if _, ok := meta[MetaKeyChain]; !ok {
		t.Fatalf("chain not injected: %s", forwarded)
	}

	rs, envs := spooledReceipts(t, res.spoolDir)
	schemaValidate(t, envs[0].Payload)
	r := rs[0]
	if r.Authority == nil || len(r.Authority.Chain) != 2 {
		t.Fatalf("receipt does not embed the chain whole: %+v", r.Authority)
	}
	for i, hop := range r.Authority.Chain {
		if hop.CarriageRoute != CarriageRouteMeta {
			t.Fatalf("hop %d carriage_route = %q, want %q", i, hop.CarriageRoute, CarriageRouteMeta)
		}
	}
	// This material is pre-AAT: hop objects with no tokens behind them. It
	// carries `"status":"verified"` on its root hop, and the proxy records
	// `asserted` anyway, because it checked and found no signature (Q29).
	// See TestVerificationAtCapture for the same proxy over signed material.
	if r.Attribution.Verification != "asserted" {
		t.Fatalf("attribution.verification = %q, want asserted", r.Attribution.Verification)
	}
	if r.Attribution.Class != "delegated" {
		t.Fatalf("attribution.class = %q, want delegated for a 2-hop chain", r.Attribution.Class)
	}
	if r.Actor == nil || r.Actor.EmitterToActor != "asserted" {
		t.Fatalf("actor = %+v", r.Actor)
	}

	// No chain: no injection, unattributed.
	bare := runSession(t, sessionOpts{lines: []string{toolsCallLine(`1`, "orders.search", `{"query":"a"}`)}})
	if bare.err != nil {
		t.Fatal(bare.err)
	}
	if bytes.Contains(bare.inWitness, []byte(MetaKeyChain)) {
		t.Fatalf("chain key injected with no chain material: %s", bare.inWitness)
	}
	br, _ := spooledReceipts(t, bare.spoolDir)
	if br[0].Authority != nil {
		t.Fatal("receipt carries an authority block with no chain material")
	}
	if br[0].Attribution.Class != "unattributed" || br[0].Attribution.Verification != "asserted" {
		t.Fatalf("attribution without a chain = %+v", br[0].Attribution)
	}
}

// TestCustomPolicyDigestTravels: the digest recorded is the digest of the
// operator's own config bytes, not of the built-in one (Q6).
func TestCustomPolicyDigestTravels(t *testing.T) {
	policy := `{"version":"behalf.sh/tool-policy/v1","default":"medium","rules":[{"pattern":"orders.*","class":"critical","target_arg":"query"}]}`
	res := runSession(t, sessionOpts{
		policy: policy,
		lines:  []string{toolsCallLine(`1`, "orders.search", `{"query":"acme"}`)},
	})
	if res.err != nil {
		t.Fatal(res.err)
	}
	rs, envs := spooledReceipts(t, res.spoolDir)
	schemaValidate(t, envs[0].Payload)
	if rs[0].RiskClass != "critical" {
		t.Fatalf("risk_class = %q, want critical", rs[0].RiskClass)
	}
	if rs[0].RiskPolicyDigest != cas.Digest([]byte(policy)) {
		t.Fatal("risk_policy_digest does not cover the operator's policy bytes")
	}
	if rs[0].Operation.Target != "acme" {
		t.Fatalf("operation.target = %q, want the policy's target_arg value", rs[0].Operation.Target)
	}
}

// TestPolicyRecordsNamedOutcomeFields covers the capture-time policy's
// `outcome_fields` (ENG-29): the operator names which scalars of a tool's
// own result belong in `operation.outcome`, and the proxy records exactly
// those, verbatim, and nothing else.
//
// It exists because a receipt that says a refund happened without saying for
// how much cannot be read against the ceiling the delegation chain granted —
// `behalf why` computes its scope excess from this field.
func TestPolicyRecordsNamedOutcomeFields(t *testing.T) {
	// `orders` is an array (content, not a scalar), `nope` is not in the
	// response at all, and `status` is the outcome's own verdict: all three
	// must be refused, and only `amount` and `refund_id` recorded.
	policy := `{"version":"behalf.sh/tool-policy/v1","default":"low","rules":[` +
		`{"pattern":"refund.issue","class":"high","target_arg":"order_id",` +
		`"outcome_fields":["amount","refund_id","orders","nope","status"]},` +
		`{"pattern":"orders.*","class":"low"}]}`
	res := runSession(t, sessionOpts{
		policy: policy,
		lines: []string{
			toolsCallLine(`1`, "refund.issue", `{"order_id":"ord_5518","amount":"1200.00"}`),
			toolsCallLine(`2`, "orders.search", `{"query":"acme"}`),
		},
	})
	if res.err != nil {
		t.Fatal(res.err)
	}
	rs, envs := spooledReceipts(t, res.spoolDir)
	if len(rs) != 2 {
		t.Fatalf("spooled %d receipts, want 2", len(rs))
	}
	for _, env := range envs {
		schemaValidate(t, env.Payload)
	}

	var refund struct {
		Operation struct {
			Outcome map[string]json.RawMessage `json:"outcome"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(envs[0].Payload, &refund); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"status":    `"ok"`,
		"amount":    `"1200.00"`,
		"refund_id": `"rf_0001"`,
	}
	if len(refund.Operation.Outcome) != len(want) {
		t.Fatalf("outcome = %v, want only %v", refund.Operation.Outcome, want)
	}
	for k, v := range want {
		if string(refund.Operation.Outcome[k]) != v {
			t.Errorf("outcome[%s] = %s, want %s", k, refund.Operation.Outcome[k], v)
		}
	}

	// A tool whose rule names no outcome fields records the status alone: the
	// default stays "the record holds a digest, not the content" (Q34–Q38).
	var search struct {
		Operation struct {
			Outcome map[string]json.RawMessage `json:"outcome"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(envs[1].Payload, &search); err != nil {
		t.Fatal(err)
	}
	if len(search.Operation.Outcome) != 1 || string(search.Operation.Outcome["status"]) != `"ok"` {
		t.Fatalf("orders.search outcome = %v, want status alone", search.Operation.Outcome)
	}
}

// TestOutcomeFieldsAreNotRecordedOnFailure: a tool that failed has no result
// to lift from, and an outcome that reported an amount beside `status:error`
// would read as a refund that happened.
func TestOutcomeFieldsAreNotRecordedOnFailure(t *testing.T) {
	policy := `{"version":"behalf.sh/tool-policy/v1","default":"low","rules":[` +
		`{"pattern":"orders.explode","class":"low","outcome_fields":["amount","isError"]}]}`
	res := runSession(t, sessionOpts{
		policy: policy,
		lines:  []string{toolsCallLine(`1`, "orders.explode", `{}`)},
	})
	if res.err != nil {
		t.Fatal(res.err)
	}
	_, envs := spooledReceipts(t, res.spoolDir)
	schemaValidate(t, envs[0].Payload)
	// Read the stored bytes, not the decoded struct: Outcome.Extra is
	// write-only (json:"-"), so a decoded receipt would show an empty map
	// whether or not the proxy recorded anything.
	var got struct {
		Operation struct {
			Outcome map[string]json.RawMessage `json:"outcome"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(envs[0].Payload, &got); err != nil {
		t.Fatal(err)
	}
	if string(got.Operation.Outcome["status"]) != `"error"` {
		t.Fatalf("outcome = %v, want an error", got.Operation.Outcome)
	}
	if len(got.Operation.Outcome) != 2 || got.Operation.Outcome["error"] == nil {
		t.Fatalf("a failed call recorded more than status and error: %v", got.Operation.Outcome)
	}
}

// digestOf is the manifest's per-field hash.
func digestOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
