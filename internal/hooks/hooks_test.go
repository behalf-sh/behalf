package hooks

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/behalf-sh/behalf/internal/capture"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// TestEveryEventProducesASchemaValidReceipt drives one golden payload per hook
// event through the surface and checks the result against the FROZEN schema —
// not against a snapshot of this code's own output, which would only prove the
// code agrees with itself.
func TestEveryEventProducesASchemaValidReceipt(t *testing.T) {
	s := newSession(t)
	s.chain = testChainJSON()

	// A whole session, in the order Claude Code would fire it.
	for _, name := range []string{
		"pre_tool_use_bash.json",
		"post_tool_use_bash.json",
		"pre_tool_use_mcp.json",
		"permission_request.json",
		"post_tool_use_mcp.json",
		"pre_tool_use_denied.json",
		"permission_denied.json",
		"subagent_start.json",
		"subagent_stop.json",
		"post_tool_use_failure.json",
		"stop.json",
		"session_end.json",
	} {
		s.fire(golden(t, name))
	}

	rs, payloads := spooled(t, s.spoolDir())
	for i, p := range payloads {
		schemaValidate(t, p)
		if rs[i].Emitter.Surface != Surface {
			t.Fatalf("receipt %d: emitter.surface = %q, want %q", i, rs[i].Emitter.Surface, Surface)
		}
		if rs[i].OtelConventionsVer == "" || rs[i].SchemaVersion != receipt.SchemaVersion {
			t.Fatalf("receipt %d: missing version stamps", i)
		}
		if rs[i].RawFrameRef == "" {
			t.Fatalf("receipt %d (%s): no raw_frame_ref: the hook JSON was not retained (Q49)", i, rs[i].Kind)
		}
	}

	// The kinds this surface uniquely contributes, all present exactly once
	// each except tool_call (three crossings: Bash, the MCP refund, the
	// erroring MCP call) and delegation (a start and a stop).
	counts := map[string]int{}
	for _, r := range rs {
		counts[r.Kind]++
	}
	want := map[string]int{
		KindToolCall:   3,
		KindApproval:   1,
		KindDenial:     1,
		KindDelegation: 2,
		KindAction:     2, // Stop and SessionEnd
	}
	for kind, n := range want {
		if counts[kind] != n {
			t.Fatalf("kind %q appears %d times, want %d (all: %v)", kind, counts[kind], n, counts)
		}
	}
	// PreToolUse mints no receipt of its own: the intent merges into the
	// completion (Q4). The one PreToolUse that was denied merged into the
	// denial, so nothing orphaned.
	if counts[KindOrphanIntent] != 0 {
		t.Fatalf("%d orphan_intent receipts: every intent should have been claimed", counts[KindOrphanIntent])
	}
}

// TestToolCallReceiptShape checks the fields a tool_call carries and, more
// importantly, that they came from the PreToolUse intent rather than being
// re-derived at PostToolUse time.
func TestToolCallReceiptShape(t *testing.T) {
	s := newSession(t)
	pre := s.fire(golden(t, "pre_tool_use_mcp.json"))
	if !pre.Pending || pre.Kind != "" {
		t.Fatalf("PreToolUse minted a receipt: %+v", pre)
	}
	post := s.fire(golden(t, "post_tool_use_mcp.json"))
	if post.Kind != KindToolCall {
		t.Fatalf("PostToolUse minted %q, want %q", post.Kind, KindToolCall)
	}
	if post.Counter != pre.Counter {
		t.Fatalf("the completion carries counter %d but the intent consumed %d: one crossing, one counter (Q48)",
			post.Counter, pre.Counter)
	}

	rs, _ := spooled(t, s.spoolDir())
	r := findKind(t, rs, KindToolCall)

	// The MCP name is the one Claude Code reported, which is the wire name
	// with every character outside [A-Za-z0-9_-] replaced by `_`. This surface
	// records what it saw; reconciling it with the proxy's `refund.issue` is
	// the join's job, not the writer's, because the substitution cannot be
	// undone (ENG-33, testdata/PROVENANCE.md).
	if r.Operation.Name != "refund_issue" {
		t.Fatalf("operation.name = %q, want the client's spelling %q", r.Operation.Name, "refund_issue")
	}
	if r.RiskClass != "high" {
		t.Fatalf("risk_class = %q: the shared *refund* rule should classify this high", r.RiskClass)
	}
	if len(r.RiskPolicyDigest) != 64 {
		t.Fatalf("risk_policy_digest = %q, want a sha256", r.RiskPolicyDigest)
	}
	if r.RunID != goldenSessionID || r.RunIDProvenance != capture.ProvenanceHookSession {
		t.Fatalf("run grouping = %q/%q, want the session id on the hook-session rung (Q7)", r.RunID, r.RunIDProvenance)
	}
	if r.Correlation == nil || r.Correlation.SessionID != goldenSessionID {
		t.Fatal("the session id is not in correlation")
	}
	if len(r.StepKey) != 64 {
		t.Fatalf("step_key = %q, want a sha256 (Q85)", r.StepKey)
	}
	if r.Attempt == nil || len(r.Attempt.IntentDigest) != 64 {
		t.Fatal("no attempt.intent_digest: the spooled intent did not reach the receipt (Q4)")
	}
	if r.Provenance.Source != "native" {
		t.Fatalf("provenance.source = %q", r.Provenance.Source)
	}

	// The input slot commits to the exact tool_input bytes, with a field
	// manifest (Q37).
	in := slotByRole(t, r.Payload, "input")
	if in.Custody != "customer-held" || in.State != "present" {
		t.Fatalf("input slot custody/state = %q/%q", in.Custody, in.State)
	}
	if in.Manifest == nil || len(in.Manifest.Fields) != 2 {
		t.Fatalf("input slot has no two-field manifest: %+v", in.Manifest)
	}
	store := cas.New(identity.BlobsDir(s.stateDir))
	blob, err := store.Get(in.Digest)
	if err != nil {
		t.Fatalf("input blob: %v", err)
	}
	if string(blob) != `{"order_id":"ord_5518","amount":"1200.00"}` {
		t.Fatalf("the receipt commits to tool_input bytes Claude Code never wrote: %s", blob)
	}

	// The raw hook frame is retained by digest (Q49), which is where the
	// self-reported names live when there is no chain to hang an actor off.
	frame := slotByRole(t, r.Payload, "hook_event")
	if frame.Digest != r.RawFrameRef {
		t.Fatal("raw_frame_ref does not point at the hook_event slot")
	}
	raw, err := store.Get(frame.Digest)
	if err != nil {
		t.Fatalf("frame blob: %v", err)
	}
	if !strings.Contains(string(raw), "mcp__payments__refund_issue") {
		t.Fatal("the retained frame is not the hook payload")
	}

	// No chain material: `asserted` and `unattributed` is the honest day-zero
	// reading, and there is no actor object because the schema requires a jkt
	// on one and nothing proved a key.
	if r.Attribution.Verification != "asserted" || r.Attribution.Class != "unattributed" {
		t.Fatalf("attribution = %+v, want asserted/unattributed with no chain (Q21)", r.Attribution)
	}
	if r.Actor != nil {
		t.Fatalf("actor present with no chain: %+v", r.Actor)
	}
}

// TestOutcomeFromToolResponse: the status a hook can honestly report, and the
// evidence field that says how it got there.
//
// A failing tool call does NOT arrive as a PostToolUse carrying an error flag —
// it arrives as PostToolUseFailure, and no PostToolUse for that call is emitted
// at all. That was the sharpest of ENG-33's findings and it is what this test
// now pins.
func TestOutcomeFromToolResponse(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "pre_tool_use_mcp.json"))
	s.fire(golden(t, "post_tool_use_failure.json"))
	rs, payloads := spooled(t, s.spoolDir())
	r := findKind(t, rs, KindToolCall)
	if r.Operation.Outcome.Status != "error" {
		t.Fatalf("PostToolUseFailure produced status %q", r.Operation.Outcome.Status)
	}
	if r.Operation.Outcome.Error != "MCP error: the tool failed" {
		t.Fatalf("outcome.error = %q, want the payload's own error string", r.Operation.Outcome.Error)
	}
	if got := outcomeExtra(t, payloads[0], "status_evidence"); got != "PostToolUseFailure.error" {
		t.Fatalf("status_evidence = %v, want the signal that decided it", got)
	}

	// An MCP success response is a bare content-block array. It has no status
	// member of any kind, and the receipt says that rather than implying a
	// check happened.
	sMCP := newSession(t)
	sMCP.fire(golden(t, "pre_tool_use_mcp.json"))
	sMCP.fire(golden(t, "post_tool_use_mcp.json"))
	rsMCP, payloadsMCP := spooled(t, sMCP.spoolDir())
	rMCP := findKind(t, rsMCP, KindToolCall)
	if rMCP.Operation.Outcome.Status != "ok" {
		t.Fatalf("MCP success produced status %q", rMCP.Operation.Outcome.Status)
	}
	evMCP, _ := outcomeExtra(t, payloadsMCP[0], "status_evidence").(string)
	if !strings.HasPrefix(evMCP, "none:") || !strings.Contains(evMCP, "content-block array") {
		t.Fatalf("status_evidence = %q: an MCP array carries no status and must say so", evMCP)
	}

	// A Bash response carries no error signal this surface reads, and the
	// receipt says exactly that rather than implying behalf checked.
	s2 := newSession(t)
	s2.fire(golden(t, "post_tool_use_bash.json"))
	rs2, payloads2 := spooled(t, s2.spoolDir())
	r2 := findKind(t, rs2, KindToolCall)
	if r2.Operation.Outcome.Status != "ok" {
		t.Fatalf("status = %q", r2.Operation.Outcome.Status)
	}
	ev, _ := outcomeExtra(t, payloads2[0], "status_evidence").(string)
	if !strings.HasPrefix(ev, "none:") {
		t.Fatalf("status_evidence = %q: an unobserved status must say so", ev)
	}
	// Bash is classified high by this surface's policy: the proxy cannot see
	// it, and letting arbitrary shell execution fall to the `low` default
	// would be the self-asserted-metadata failure the product exists to fix.
	if r2.RiskClass != "high" {
		t.Fatalf("Bash risk_class = %q, want high", r2.RiskClass)
	}
}

// TestApprovalAndDenialAnchoring is Q24 and Q5 together: the human's decision
// as a first-class event, anchored to the delegation token jti plus the intent
// digest, and marked `asserted` because a click is not cryptography.
func TestApprovalAndDenialAnchoring(t *testing.T) {
	s := newSession(t)
	s.chain = testChainJSON()

	// The approved path: request, then the tool runs.
	preApproved := s.fire(golden(t, "pre_tool_use_mcp.json"))
	s.fire(golden(t, "permission_request.json"))
	s.fire(golden(t, "post_tool_use_mcp.json"))
	// The refused path: request never granted, denial arrives.
	preDenied := s.fire(golden(t, "pre_tool_use_denied.json"))
	denialRes := s.fire(golden(t, "permission_denied.json"))

	rs, payloads := spooled(t, s.spoolDir())
	for _, p := range payloads {
		schemaValidate(t, p)
	}
	approval := findKind(t, rs, KindApproval)
	denial := findKind(t, rs, KindDenial)
	toolCall := findKind(t, rs, KindToolCall)

	const leafJTI = "behalf-hop-01hzzzzzzzzzzzzzzzzzzzzzzz"
	const leafParHash = "1111111111111111111111111111111111111111111111111111111111111111"

	for _, tc := range []struct {
		name string
		r    receipt.Receipt
	}{{"approval", approval}, {"denial", denial}} {
		anchor := anchorOf(t, tc.r)
		if anchor.JTI != leafJTI {
			t.Fatalf("%s anchors to jti %q, want the leaf hop's %q (Q5)", tc.name, anchor.JTI, leafJTI)
		}
		if anchor.ParHash != leafParHash {
			t.Fatalf("%s anchors to par_hash %q, want %q", tc.name, anchor.ParHash, leafParHash)
		}
		if anchor.IntentDigest == "" || anchor.IntentDigest != tc.r.Attempt.IntentDigest {
			t.Fatalf("%s: the anchor's intent digest and attempt.intent_digest disagree", tc.name)
		}
		if tc.r.HumanInLoop == nil || tc.r.HumanInLoop.Marked != "asserted" {
			t.Fatalf("%s: human_in_loop is not marked asserted — a click is not cryptography (Q24)", tc.name)
		}
		if tc.r.HumanInLoop.BindingMessageDigest != tc.r.RawFrameRef {
			t.Fatalf("%s: the binding message does not commit to the prompt payload", tc.name)
		}
		// The click never reclassifies attribution, in either direction
		// (Q14): this chain is unsigned, so it rolls up asserted regardless
		// of who clicked what.
		if tc.r.Attribution.Verification == "verified" {
			t.Fatalf("%s claims verified attribution: a click cannot raise the chain rollup (Q14, Q24)", tc.name)
		}
		if tc.r.Attribution.Class != "delegated" {
			t.Fatalf("%s: attribution.class = %q, want delegated from the two-hop chain", tc.name, tc.r.Attribution.Class)
		}
	}

	// The approval anchors to the SAME intent digest the tool_call carries, so
	// a reader joins consent to action without a log index — and to the same
	// step key, so `behalf diff` can align the consent with the step.
	if approval.Attempt.IntentDigest != toolCall.Attempt.IntentDigest {
		t.Fatal("the approval and the tool_call do not share an intent digest: consent cannot be joined to the action")
	}
	if approval.StepKey == "" || approval.StepKey != toolCall.StepKey {
		t.Fatalf("the approval's step_key (%q) does not match the action's (%q)", approval.StepKey, toolCall.StepKey)
	}

	// The denial claimed the pending intent: same counter, and no orphan.
	if denial.Emitter.Counter != preDenied.Counter {
		t.Fatalf("denial counter %d, intent consumed %d: the denial must reuse it (Q48)",
			denial.Emitter.Counter, preDenied.Counter)
	}
	if denialRes.Note != "" {
		t.Fatalf("the denial did not find its pending intent: %s", denialRes.Note)
	}
	if denial.Operation.Outcome.Status != "error" {
		t.Fatalf("denial outcome = %q, want error", denial.Operation.Outcome.Status)
	}
	if !strings.Contains(denial.Operation.Outcome.Error, "manual-review threshold") {
		t.Fatalf("the denial dropped the reason the payload carried: %q", denial.Operation.Outcome.Error)
	}
	// The approval did NOT consume the intent — the tool still ran.
	if toolCall.Emitter.Counter != preApproved.Counter {
		t.Fatal("the approval consumed the pending intent that PostToolUse needed")
	}

	// The approval's consent evidence names the inference rather than hiding it.
	ev, _ := outcomeExtra(t, payloadOf(t, rs, payloads, KindApproval), "consent_evidence").(string)
	if !strings.Contains(ev, "inferred") {
		t.Fatalf("the approval overclaims: consent_evidence = %q", ev)
	}
	// The denial's does the opposite: the refusal is observed directly.
	dev, _ := outcomeExtra(t, payloadOf(t, rs, payloads, KindDenial), "consent_evidence").(string)
	if !strings.Contains(dev, "observed directly") {
		t.Fatalf("the denial understates itself: consent_evidence = %q", dev)
	}
}

// TestSubagentDelegationEdges: SubagentStart/Stop are the human->agent->
// subagent edge, and the pair joins on one digest computed from what both
// payloads carry.
func TestSubagentDelegationEdges(t *testing.T) {
	s := newSession(t)
	s.chain = testChainJSON()
	s.fire(golden(t, "subagent_start.json"))
	s.fire(golden(t, "subagent_stop.json"))

	rs, payloads := spooled(t, s.spoolDir())
	for _, p := range payloads {
		schemaValidate(t, p)
	}
	if len(rs) != 2 {
		t.Fatalf("got %d receipts, want a start and a stop", len(rs))
	}
	start, stop := rs[0], rs[1]
	if start.Kind != KindDelegation || stop.Kind != KindDelegation {
		t.Fatalf("kinds = %q/%q, want delegation for both (Q1, Q5)", start.Kind, stop.Kind)
	}
	if start.KindExt != KindExtSubagentStart || stop.KindExt != KindExtSubagentStop {
		t.Fatalf("kind_ext = %q/%q", start.KindExt, stop.KindExt)
	}
	if start.Attempt.IntentDigest != stop.Attempt.IntentDigest {
		t.Fatal("the start and stop do not share a digest: the delegation edge cannot be closed")
	}
	want := subagentDigest(goldenSessionID, goldenAgentID, goldenAgentType)
	if start.Attempt.IntentDigest != want {
		t.Fatalf("delegation digest = %q, want %q", start.Attempt.IntentDigest, want)
	}
	if start.Operation.Target != "code-reviewer" {
		t.Fatalf("operation.target = %q, want the agent type", start.Operation.Target)
	}
	// The self-reported agent identity rides as an asserted label on the
	// actor the chain proves (Q16).
	if start.Actor == nil || start.Actor.Labels["agent_id"] != goldenAgentID {
		t.Fatalf("the agent id is not an asserted label: %+v", start.Actor)
	}
	if start.Actor.EmitterToActor != "asserted" {
		t.Fatal("emitter_to_actor is not marked asserted (Q19)")
	}
	// Nothing signed this edge, and the receipt says so rather than implying
	// a minted hop.
	ev, _ := outcomeExtra(t, payloads[0], "delegation_evidence").(string)
	if !strings.Contains(ev, "not signed") {
		t.Fatalf("delegation_evidence = %q: an unsigned edge must say so", ev)
	}
}

// TestChainIsVerifiedAtCapture: the chain travels into the receipt whole, with
// the verification THIS surface performed — never the status the material
// claimed about itself (Q18, Q29).
func TestChainIsVerifiedAtCapture(t *testing.T) {
	s := newSession(t)
	s.chain = testChainJSON()
	s.fire(golden(t, "pre_tool_use_mcp.json"))
	s.fire(golden(t, "post_tool_use_mcp.json"))

	rs, _ := spooled(t, s.spoolDir())
	r := findKind(t, rs, KindToolCall)
	if r.Authority == nil || len(r.Authority.Chain) != 2 {
		t.Fatal("the chain was not embedded whole (Q10)")
	}
	// The material claimed `verified` at the root. It is unsigned, so this
	// surface checked nothing and records `asserted` with a reason.
	root := r.Authority.Chain[0]
	if root.Verification.Status != "asserted" {
		t.Fatalf("the root records %q: a carried hop's claim about itself is not evidence (Q29)",
			root.Verification.Status)
	}
	if !strings.Contains(root.Verification.Method, "caller-asserted") {
		t.Fatalf("verification.method = %q, want a caller-asserted reason", root.Verification.Method)
	}
	// The carriage route is this surface's, not the proxy's: nothing tied
	// this chain to this tool call.
	for i, h := range r.Authority.Chain {
		if h.CarriageRoute != CarriageRouteLocal {
			t.Fatalf("hop %d carriage_route = %q, want %q", i, h.CarriageRoute, CarriageRouteLocal)
		}
	}
	if r.Attribution.Verification != "asserted" || r.Attribution.Class != "delegated" {
		t.Fatalf("attribution = %+v, want the weakest hop and the chain shape (Q12)", r.Attribution)
	}
	// The actor is the deepest hop's key, not the emitter's.
	if r.Actor == nil || r.Actor.JKT == "" {
		t.Fatal("no actor from a chain that proves a key (Q16)")
	}
	emitter, err := identity.LoadKey(identity.EmitterKeyPath(s.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if r.Actor.JKT == emitter.JKT {
		t.Fatal("actor.jkt is the emitter key: the emitter/actor split is the point (Q19)")
	}
	if r.Emitter.JKT != emitter.JKT {
		t.Fatal("emitter.jkt is not the emitter key")
	}
}

// TestOrphanIntentOnSessionEnd is Q4's other half for this surface: an intent
// nothing ever claimed becomes an orphan_intent receipt carrying the spooled
// digest, reusing the counter so there is no gap.
func TestOrphanIntentOnSessionEnd(t *testing.T) {
	s := newSession(t)
	pre := s.fire(golden(t, "pre_tool_use_mcp.json")) // the tool never returns
	res := s.fire(golden(t, "session_end.json"))
	if len(res.Orphans) != 1 {
		t.Fatalf("session end flushed %d orphans, want 1", len(res.Orphans))
	}

	rs, payloads := spooled(t, s.spoolDir())
	for _, p := range payloads {
		schemaValidate(t, p)
	}
	orphan := findKind(t, rs, KindOrphanIntent)
	if orphan.Emitter.Counter != pre.Counter {
		t.Fatalf("orphan counter %d, intent consumed %d: one crossing, one counter (Q48)",
			orphan.Emitter.Counter, pre.Counter)
	}
	if orphan.Attempt == nil || len(orphan.Attempt.IntentDigest) != 64 {
		t.Fatal("the orphan does not carry the spooled intent digest (Q4, Q5)")
	}
	if orphan.Operation.Outcome.Status != "error" {
		t.Fatalf("orphan outcome = %q", orphan.Operation.Outcome.Status)
	}
	in := slotByRole(t, orphan.Payload, "input")
	if in.State != "present" || in.Manifest == nil {
		t.Fatalf("the orphan's input slot did not rehydrate from the CAS: %+v", in)
	}
	// The session-end marker is the last record, and it says what it does and
	// does not assert.
	end := rs[len(rs)-1]
	if end.Kind != KindAction || end.KindExt != KindExtSessionEnd {
		t.Fatalf("the last record is %q/%q, want the session-end marker (Q82)", end.Kind, end.KindExt)
	}
	if n, _ := outcomeExtra(t, payloads[len(payloads)-1], "orphan_intents_flushed").(float64); int(n) != 1 {
		t.Fatal("the session-end marker does not record the flush")
	}
}

// TestRecoverSweepRespectsAge: a sweep run beside a live session must not
// steal calls that are merely in flight.
func TestRecoverSweepRespectsAge(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "pre_tool_use_mcp.json"))

	c := s.open()
	ids, err := c.Recover("", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("a young intent was swept as an orphan: %v", ids)
	}
	// Same sweep with no age floor takes it.
	ids, err = s.open().Recover("", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 {
		t.Fatalf("swept %d intents, want 1", len(ids))
	}
}

// TestPostOnlyIsMarked: a completion with no intent behind it is recorded, and
// is distinguishable from one that had the Q4 durability property.
func TestPostOnlyIsMarked(t *testing.T) {
	s := newSession(t)
	res := s.fire(golden(t, "post_tool_use_mcp.json")) // no PreToolUse
	if res.KindExt != KindExtPostOnly {
		t.Fatalf("kind_ext = %q, want the post-only marker", res.KindExt)
	}
	rs, payloads := spooled(t, s.spoolDir())
	schemaValidate(t, payloads[0])
	if rs[0].KindExt != KindExtPostOnly {
		t.Fatalf("the receipt does not carry the marker: %q", rs[0].KindExt)
	}
	if rs[0].Attempt == nil || len(rs[0].Attempt.IntentDigest) != 64 {
		t.Fatal("a post-only receipt still anchors to a computable intent digest")
	}
}

// TestSignatureOverSpooledBytes: the emitter key signs the exact stored
// payload bytes, and nothing re-marshals them on the way to the spool.
func TestSignatureOverSpooledBytes(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "pre_tool_use_bash.json"))
	s.fire(golden(t, "post_tool_use_bash.json"))

	emitter, err := identity.LoadKey(identity.EmitterKeyPath(s.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	completions, err := readCompletions(s.spoolDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(completions) != 1 {
		t.Fatalf("spooled %d completions, want 1", len(completions))
	}
	env := completions[0]
	if !dsse.Verify(emitter.Public, exportv1.PayloadTypeReceipt, env.Payload, env.Sig) {
		t.Fatal("the emitter signature does not verify over the spooled payload span")
	}
	var r receipt.Receipt
	if err := json.Unmarshal(env.Payload, &r); err != nil {
		t.Fatal(err)
	}
	if r.Emitter.JKT != emitter.JKT {
		t.Fatal("the receipt names a different emitter than the key that signed it")
	}
}

// TestUnhandledEventIsNotAFailure: Claude Code can add events, and recording
// an unknown one as something it is not would be worse than silence.
func TestUnhandledEventIsNotAFailure(t *testing.T) {
	s := newSession(t)
	_, err := s.open().Handle(golden(t, "unknown_event.json"))
	if !errors.Is(err, ErrUnhandledEvent) {
		t.Fatalf("got %v, want ErrUnhandledEvent", err)
	}
	rs, _ := spooled(t, s.spoolDir())
	if len(rs) != 0 {
		t.Fatalf("an unhandled event produced %d receipts", len(rs))
	}
}

// TestMalformedPayloadsAreRefusedCleanly: no panic, no half-written record.
func TestMalformedPayloadsAreRefusedCleanly(t *testing.T) {
	for _, in := range []string{"", "   ", "not json", "[]", `{"tool_name":"Bash"}`, `{"hook_event_name":`} {
		s := newSession(t)
		if _, err := s.open().Handle([]byte(in)); err == nil {
			t.Fatalf("input %q was accepted", in)
		}
		rs, _ := spooled(t, s.spoolDir())
		if len(rs) != 0 {
			t.Fatalf("input %q produced %d receipts", in, len(rs))
		}
	}
}

// TestCallerRunIDWins: BEHALF_RUN_ID is the top rung and the only thing that
// makes two capture surfaces agree on a run (Q7) — which the cross-surface
// collapse depends on.
func TestCallerRunIDWins(t *testing.T) {
	s := newSession(t)
	s.env[capture.EnvRunID] = "run_week3_demo"
	s.fire(golden(t, "pre_tool_use_mcp.json"))
	s.fire(golden(t, "post_tool_use_mcp.json"))
	rs, _ := spooled(t, s.spoolDir())
	r := findKind(t, rs, KindToolCall)
	if r.RunID != "run_week3_demo" || r.RunIDProvenance != capture.ProvenanceCaller {
		t.Fatalf("run grouping = %q/%q, want the caller rung", r.RunID, r.RunIDProvenance)
	}
	// The session id is still recorded, just not as the grouping key.
	if r.Correlation == nil || r.Correlation.SessionID != goldenSessionID {
		t.Fatal("the session id was lost when the caller rung won")
	}
}

// TestStepKeyOrdinalAdvancesAcrossProcesses: the causal ordinal is durable per
// run, because each hook event is a separate process and step_key would
// otherwise be identical for every call in a session (Q85).
func TestStepKeyOrdinalAdvancesAcrossProcesses(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "pre_tool_use_bash.json"))
	s.fire(golden(t, "post_tool_use_bash.json"))
	s.fire(golden(t, "pre_tool_use_mcp.json"))
	s.fire(golden(t, "post_tool_use_mcp.json"))

	rs, _ := spooled(t, s.spoolDir())
	if len(rs) != 2 {
		t.Fatalf("got %d receipts", len(rs))
	}
	if rs[0].StepKey == rs[1].StepKey {
		t.Fatal("two calls in one run share a step_key: the ordinal did not advance")
	}
	// And the value is reproducible from the inputs.
	want := capture.StepKey("refund_issue", []byte(`{"order_id":"ord_5518","amount":"1200.00"}`), 1)
	if rs[1].StepKey != want {
		t.Fatalf("step_key = %q, want %q (tool, arg schema, ordinal 1)", rs[1].StepKey, want)
	}
}

// TestPermissionRequestFindsTheIntentWithoutAToolUseID pins the fix for the
// second-sharpest ENG-33 finding: `PermissionRequest` carries no `tool_use_id`,
// while `PreToolUse` does, so the intent was filed under a key the permission
// event could not compute and the consent-to-action join silently never
// matched. It failed as a blank, not as an error, which is why it survived to
// be found by reading the client's schemas rather than by a test.
func TestPermissionRequestFindsTheIntentWithoutAToolUseID(t *testing.T) {
	req := golden(t, "permission_request.json")
	if strings.Contains(string(req), "tool_use_id") {
		t.Fatal("the golden carries a tool_use_id: Claude Code 2.1.250 does not send one on PermissionRequest")
	}

	s := newSession(t)
	s.fire(golden(t, "pre_tool_use_mcp.json")) // files the intent under the id key
	s.fire(req)                                // can only compute the content key
	s.fire(golden(t, "post_tool_use_mcp.json"))

	rs, _ := spooled(t, s.spoolDir())
	approval := findKind(t, rs, KindApproval)
	toolCall := findKind(t, rs, KindToolCall)

	if approval.Attempt.IntentDigest != toolCall.Attempt.IntentDigest {
		t.Fatalf("consent and action carry different intent digests (%q vs %q): the Q5 join a reader is told to use does not match",
			approval.Attempt.IntentDigest, toolCall.Attempt.IntentDigest)
	}
	if approval.StepKey == "" || approval.StepKey != toolCall.StepKey {
		t.Fatalf("consent and action carry different step keys (%q vs %q): `behalf diff` cannot align the consent with the step",
			approval.StepKey, toolCall.StepKey)
	}
	// And the approval PEEKED rather than claimed: the tool call still closed
	// the crossing with the counter the intent allocated.
	if approval.Emitter.Counter == toolCall.Emitter.Counter {
		t.Fatal("the approval consumed the crossing's counter: PostToolUse must be the record that closes it")
	}
}

func anchorOf(t *testing.T, r receipt.Receipt) receipt.Anchor {
	t.Helper()
	for _, l := range r.Links {
		if l.Rel == "anchor" && l.Anchor != nil {
			return *l.Anchor
		}
	}
	t.Fatalf("receipt %s carries no anchor link", r.Kind)
	return receipt.Anchor{}
}
