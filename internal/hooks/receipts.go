package hooks

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/capture"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// One handler per hook event. What each mints, and why:
//
//	PreToolUse          a durable pending intent, NO receipt (Q4)
//	PostToolUse         the single `tool_call` receipt, merging that intent
//	PostToolUseFailure  the same receipt, for a call that failed — a failed
//	                    call produces NO PostToolUse (ENG-33)
//	PermissionRequest  an `approval` receipt (Q24)
//	PermissionDenied   a `denial` receipt, claiming the intent (Q5, Q24)
//	SubagentStart      a `delegation` receipt — the delegation edge (Q1, Q5)
//	SubagentStop       a `delegation` receipt closing that edge
//	SessionEnd         the run-completeness marker (Q82), and an orphan sweep
//	Stop               a turn-boundary marker; no sweep, the session continues

// handlePreToolUse records the intent and emits nothing.
//
// This is Q4's contract: durable before the action. The hook returns before
// the tool runs, so an fsync here is the same guarantee the proxy gets by
// spooling before it forwards. The counter is allocated now and carried by
// whichever receipt records this crossing — the completion normally, the
// denial if the human refuses, the orphan_intent if neither ever arrives — so
// appended receipts have no counter gaps for Q48's detector to trip over.
func (c *Capture) handlePreToolUse(e *Event) (*Result, error) {
	op, server := e.Operation()
	if op == "" {
		return &Result{Event: e.Name}, errors.New("hooks: PreToolUse carries no tool_name")
	}
	input := e.ToolInput()
	capturedAt := c.now()

	runID, provenance, _ := c.resolveRunID(e)
	ordinal, err := c.nextOrdinal(runID)
	if err != nil {
		return nil, err
	}
	counter, err := capture.NextCounter(c.state)
	if err != nil {
		return nil, err
	}
	inputDigest, err := c.blobs.Put(input)
	if err != nil {
		return nil, err
	}
	frameDigest, err := c.blobs.Put(e.Raw)
	if err != nil {
		return nil, err
	}
	class, targetArg := c.policy.Classify(op)
	target := ""
	if targetArg != "" {
		target = stringField(input, targetArg)
	}

	p := Pending{
		IntentID:        c.ids.ULIDAt(capturedAt),
		IntentDigest:    capture.IntentDigest(op, input),
		SessionID:       e.SessionID,
		ToolUseID:       e.ToolUseID,
		Operation:       op,
		RawToolName:     e.ToolName,
		MCPServer:       server,
		Target:          target,
		AgentID:         e.AgentID,
		AgentType:       e.AgentType,
		CapturedAt:      capture.RFC3339(capturedAt),
		EmitterJKT:      c.emitter.JKT,
		EmitterCounter:  counter,
		RunID:           runID,
		RunIDProvenance: provenance,
		StepKey:         capture.StepKey(op, input, ordinal),
		RiskClass:       class,
		RiskPolicyDig:   c.policy.Digest(),
		InputDigest:     inputDigest,
		InputSize:       len(input),
		FrameDigest:     frameDigest,
		FrameSize:       len(e.Raw),
		ChainRef:        c.chainRef,
	}
	if err := c.pending.Put(e, p); err != nil {
		return nil, err
	}
	return &Result{
		Event:   e.Name,
		Counter: counter,
		Pending: true,
		Note:    "intent recorded durably before the tool ran; the receipt closes on PostToolUse",
	}, nil
}

// handlePostToolUse mints the single `tool_call` receipt for a call that
// succeeded.
func (c *Capture) handlePostToolUse(e *Event) (*Result, error) {
	return c.completeToolCall(e, outcomeFromToolResponse(e.ToolResponseRaw))
}

// handlePostToolUseFailure mints the same `tool_call` receipt for a call that
// failed.
//
// This event was missing from the surface entirely until ENG-33 checked the
// payloads against a running client. The assumption it replaces was that a
// failed tool call arrives as a `PostToolUse` whose `tool_response` carries
// `isError` — it does not. Claude Code 2.1.250 emits `PostToolUseFailure`
// with a top-level string `error`, and emits NO `PostToolUse` for that call.
//
// What that cost while it was missing is specific and worth stating: every
// failed tool call left a durable intent that nothing ever claimed, so the
// crossing surfaced as an `orphan_intent` at session end — "no completion
// observed" — when the completion had in fact been observed and was a failure.
// A recorder that reports a known failure as an unknown silence is the exact
// failure mode this product exists to remove.
func (c *Capture) handlePostToolUseFailure(e *Event) (*Result, error) {
	msg := e.Error
	if msg == "" {
		msg = "the tool call failed; the payload carried no error text"
	}
	evidence := "PostToolUseFailure.error"
	if e.IsInterrupt {
		evidence = "PostToolUseFailure.is_interrupt"
	}
	return c.completeToolCall(e, receipt.Outcome{
		Status: "error",
		Error:  msg,
		Extra:  map[string]any{"status_evidence": evidence},
	})
}

// completeToolCall closes the crossing a PreToolUse intent opened, with the
// outcome the closing event established.
func (c *Capture) completeToolCall(e *Event, outcome receipt.Outcome) (*Result, error) {
	op, server := e.Operation()
	if op == "" {
		return &Result{Event: e.Name}, errors.New("hooks: " + e.Name + " carries no tool_name")
	}
	input := e.ToolInput()
	capturedAt := c.now()

	p, err := c.pending.Claim(e)
	if err != nil {
		return nil, err
	}
	postOnly := p == nil
	if postOnly {
		// No intent behind this crossing: the hook was installed mid-session,
		// PreToolUse is not installed, or another input-modifying hook changed
		// `tool_input` between the two events so the bucket key missed (D4).
		// The crossing is still evidence and is recorded — what is not true of
		// it is the durable-intent-before-the-action property, and KindExtPostOnly
		// is how a reader tells the difference.
		built, err := c.mintPending(e, op, server, input, capturedAt)
		if err != nil {
			return nil, err
		}
		p = &built
	}

	slots := make([]receipt.Slot, 0, 3)
	inputSlot, err := capture.Slot(c.blobs, "input", input, "application/json")
	if err != nil {
		return nil, err
	}
	slots = append(slots, inputSlot)
	if len(e.ToolResponseRaw) > 0 {
		outputSlot, err := capture.Slot(c.blobs, "output", e.ToolResponseRaw, "application/json")
		if err != nil {
			return nil, err
		}
		slots = append(slots, outputSlot)
	}
	frame, err := c.frameSlot(e)
	if err != nil {
		return nil, err
	}
	slots = append(slots, frame)

	auth, attribution := c.authority()
	r := c.base(KindToolCall, capturedAt, p.EmitterCounter)
	r.CapturedAt = p.CapturedAt // the crossing began when the intent was recorded
	r.RiskClass = p.RiskClass
	r.RiskPolicyDigest = p.RiskPolicyDig
	r.Actor = capture.Actor(auth, labelsFor(e, server))
	r.Operation = receipt.Operation{
		Name:    p.Operation,
		Target:  p.Target,
		Outcome: outcome,
	}
	r.Attempt = &receipt.Attempt{IntentDigest: p.IntentDigest}
	r.RunID = p.RunID
	r.RunIDProvenance = p.RunIDProvenance
	r.Correlation = correlationFor(e)
	r.StepKey = p.StepKey
	r.Authority = auth
	r.Attribution = attribution
	r.Payload = slots
	r.RawFrameRef = frame.Digest
	if postOnly {
		r.KindExt = KindExtPostOnly
	}
	if link := crossSurfaceLink(e, inputSlot.Digest); link != nil {
		r.Links = append(r.Links, *link)
	}

	id, err := c.emit(e.SessionID, p.IntentID, r)
	if err != nil {
		return nil, err
	}
	res := &Result{Event: e.Name, Kind: r.Kind, KindExt: r.KindExt, ReceiptID: id, Counter: p.EmitterCounter}
	if postOnly {
		res.Note = "no PreToolUse intent was found for this call: recorded post-only"
	}
	return res, nil
}

// handlePermission mints the `approval` or `denial` receipt: the human's
// consent decision as a first-class event (Q24, D4), anchored to the
// delegation token `jti` plus the intent digest (Q5).
//
// # A click is not cryptography
//
// This receipt records that a person clicked. It does not record that a person
// authenticated, that a key signed anything, or that the click can be
// attributed to a named human. `human_in_loop.marked` is the const `asserted`
// and the frozen schema allows it no other value, which is the schema saying
// the same thing (§9-adjacent, Q24).
//
// `attribution.verification` is NOT touched by the click, in either direction.
// That field describes the delegation chain and is the weakest hop of it
// (Q12); a linked approval is recorded and joined but never reclassifies the
// stored attribution (Q14). So an approval on a chainless install reads
// `asserted`/`unattributed` — because that is what the evidence is — and an
// approval on a verified chain reads `verified` because the CHAIN verified,
// never because someone clicked.
//
// # What PermissionRequest actually proves
//
// The hook fires when consent is SOUGHT. The corpus maps it to an `approval`
// receipt (Q24, D4) and this follows the corpus, but the inference is one step
// wide and the receipt says so: `outcome.consent_evidence` records that
// approval is inferred from a `PermissionRequest` with no matching
// `PermissionDenied`, and from the tool subsequently producing a `tool_call`
// receipt. A reader who wants only refusals has the `denial` records, which
// are direct.
func (c *Capture) handlePermission(e *Event, kind string) (*Result, error) {
	op, server := e.Operation()
	if op == "" {
		op = "claude-code.permission"
	}
	input := e.ToolInput()
	capturedAt := c.now()

	// A denial means the tool will not run, so the pending intent has no
	// completion coming and this receipt is what records that crossing: it
	// CLAIMS the intent and takes its counter, digest and step key. An
	// approval only PEEKS — the tool is about to run and PostToolUse will
	// close the crossing, so taking the intent here would strand it.
	var known *Pending
	var claimed bool
	if kind == KindDenial {
		p, err := c.pending.Claim(e)
		if err != nil {
			return nil, err
		}
		known, claimed = p, p != nil
	} else {
		p, err := c.pending.Peek(e)
		if err != nil {
			return nil, err
		}
		known = p
	}

	intentDigest := capture.IntentDigest(op, input)
	counter := 0
	stepKey := ""
	riskClass, _ := c.policy.Classify(op)
	riskDigest := c.policy.Digest()
	runID, provenance, _ := c.resolveRunID(e)
	capturedAtStr := capture.RFC3339(capturedAt)
	if known != nil {
		// Anchor to the intent the tool call actually recorded, so the consent
		// and the action share a digest a reader can join on without a log
		// index (Q5).
		intentDigest = known.IntentDigest
		stepKey = known.StepKey
		riskClass, riskDigest = known.RiskClass, known.RiskPolicyDig
		runID, provenance = known.RunID, known.RunIDProvenance
	}
	if claimed {
		// The denial IS the record of this crossing: one crossing, one
		// counter, no gap for Q48's detector to trip over.
		counter = known.EmitterCounter
		capturedAtStr = known.CapturedAt
	} else {
		n, err := capture.NextCounter(c.state)
		if err != nil {
			return nil, err
		}
		counter = n
	}

	frame, err := c.frameSlot(e)
	if err != nil {
		return nil, err
	}
	slots := []receipt.Slot{frame}
	if len(e.ToolInputRaw) > 0 {
		inputSlot, err := capture.Slot(c.blobs, "input", input, "application/json")
		if err != nil {
			return nil, err
		}
		slots = append([]receipt.Slot{inputSlot}, slots...)
	}

	auth, attribution := c.authority()
	outcome := receipt.Outcome{Status: "ok", Extra: map[string]any{
		"consent_evidence": "the Claude Code PermissionRequest hook fired: approval is inferred from " +
			"the absence of a matching PermissionDenied, not observed directly",
	}}
	satisfiedBy := "claude-code:PermissionRequest"
	if kind == KindDenial {
		outcome = receipt.Outcome{Status: "error", Error: e.DenialReason(), Extra: map[string]any{
			"consent_evidence": "the Claude Code PermissionDenied hook fired: the refusal is observed directly",
		}}
		satisfiedBy = "claude-code:PermissionDenied"
	}

	r := c.base(kind, capturedAt, counter)
	r.CapturedAt = capturedAtStr
	r.RiskClass = riskClass
	r.RiskPolicyDigest = riskDigest
	r.Actor = capture.Actor(auth, labelsFor(e, server))
	r.Operation = receipt.Operation{Name: op, Outcome: outcome}
	r.Attempt = &receipt.Attempt{IntentDigest: intentDigest}
	r.RunID = runID
	r.RunIDProvenance = provenance
	r.Correlation = correlationFor(e)
	r.StepKey = stepKey
	r.Authority = auth
	r.Attribution = attribution
	r.Payload = slots
	r.RawFrameRef = frame.Digest
	// A click, marked as one. The schema's const is the point.
	r.HumanInLoop = &receipt.HumanInLoop{
		SatisfiedBy:          satisfiedBy,
		BindingMessageDigest: frame.Digest,
		Marked:               "asserted",
	}
	jti, parHash := c.leafAnchor()
	r.Links = append(r.Links, receipt.Link{
		Rel: "anchor",
		Anchor: &receipt.Anchor{
			JTI:          jti,
			ParHash:      parHash,
			IntentDigest: intentDigest,
		},
	})
	if link := crossSurfaceLink(e, argumentsDigest(input)); link != nil {
		r.Links = append(r.Links, *link)
	}

	intentID := c.ids.ULIDAt(capturedAt)
	if claimed {
		intentID = known.IntentID
	}
	id, err := c.emit(e.SessionID, intentID, r)
	if err != nil {
		return nil, err
	}
	note := ""
	if known == nil {
		note = "no PreToolUse intent was found for this " + kind +
			": the anchor digest is computed from the permission payload"
	}
	return &Result{Event: e.Name, Kind: r.Kind, ReceiptID: id, Counter: counter, Note: note}, nil
}

// handleSubagent mints the `delegation` receipts for the sub-agent edge.
//
// A sub-agent invocation is a delegation (Q1): the human delegated to Claude
// Code, and Claude Code delegated to this sub-agent. What the hook hands us is
// the EDGE, not a token — there is no sub-agent key and no minted hop, so the
// receipt records the edge honestly as a delegation event carrying the chain
// that was in force, rather than inventing a hop that nothing signed.
//
// Start and stop carry the same `attempt.intent_digest`, computed from the
// session and agent ids, which is what joins the pair on read. It is the only
// value both payloads can be relied on to share.
func (c *Capture) handleSubagent(e *Event, start bool) (*Result, error) {
	capturedAt := c.now()
	digest := subagentDigest(e.SessionID, e.AgentID, e.AgentType)

	counter, err := capture.NextCounter(c.state)
	if err != nil {
		return nil, err
	}
	runID, provenance, _ := c.resolveRunID(e)
	frame, err := c.frameSlot(e)
	if err != nil {
		return nil, err
	}

	name := "claude-code.subagent_stop"
	kindExt := KindExtSubagentStop
	evidence := "the SubagentStop hook fired; the sub-agent's own outcome is not carried by the hook payload"
	if start {
		name = "claude-code.subagent_start"
		kindExt = KindExtSubagentStart
		evidence = "the SubagentStart hook fired; the delegation edge is asserted by Claude Code, not signed"
	}
	class, _ := c.policy.Classify(name)

	auth, attribution := c.authority()
	r := c.base(KindDelegation, capturedAt, counter)
	r.KindExt = kindExt
	r.RiskClass = class
	r.RiskPolicyDigest = c.policy.Digest()
	r.Actor = capture.Actor(auth, labelsFor(e, ""))
	r.Operation = receipt.Operation{
		Name:   name,
		Target: e.AgentType,
		Outcome: receipt.Outcome{Status: "ok", Extra: map[string]any{
			"delegation_evidence": evidence,
		}},
	}
	r.Attempt = &receipt.Attempt{IntentDigest: digest}
	r.RunID = runID
	r.RunIDProvenance = provenance
	r.Correlation = correlationFor(e)
	r.Authority = auth
	r.Attribution = attribution
	r.Payload = []receipt.Slot{frame}
	r.RawFrameRef = frame.Digest
	jti, parHash := c.leafAnchor()
	r.Links = append(r.Links, receipt.Link{
		Rel:    "anchor",
		Anchor: &receipt.Anchor{JTI: jti, ParHash: parHash, IntentDigest: digest},
	})

	id, err := c.emit(e.SessionID, c.ids.ULIDAt(capturedAt), r)
	if err != nil {
		return nil, err
	}
	return &Result{Event: e.Name, Kind: r.Kind, KindExt: r.KindExt, ReceiptID: id, Counter: counter}, nil
}

// handleSessionBoundary mints the completeness marker.
//
// Reconstruction is "the complete ordered sequence" only if something says
// where it ended; Q82 marks completeness with a session-end receipt "where the
// surface can emit one", and this surface can. `SessionEnd` is that record.
// `Stop` is a turn boundary — the main agent finished a turn and the session
// continues — so it is recorded as a weaker marker and does NOT sweep pending
// intents, because more tool calls are coming.
func (c *Capture) handleSessionBoundary(e *Event) (*Result, error) {
	capturedAt := c.now()
	sessionEnd := e.Name == EventSessionEnd

	// The session is over: nothing will claim these intents, and a crossing
	// that got an intent and never a receipt is exactly what orphan_intent is
	// for (Q4, Q5).
	var orphans []string
	if sessionEnd {
		ids, err := c.Recover(e.SessionID, 0)
		if err != nil {
			return nil, err
		}
		orphans = ids
	}

	counter, err := capture.NextCounter(c.state)
	if err != nil {
		return nil, err
	}
	runID, provenance, _ := c.resolveRunID(e)
	frame, err := c.frameSlot(e)
	if err != nil {
		return nil, err
	}

	name, kindExt := "claude-code.stop", KindExtStop
	if sessionEnd {
		name, kindExt = "claude-code.session_end", KindExtSessionEnd
	}
	class, _ := c.policy.Classify(name)
	extra := map[string]any{
		"completeness": "this record marks where the capture surface stopped observing; " +
			"it does not assert that nothing else happened",
	}
	if r := e.DenialReasonRaw(); r != "" {
		extra["reason"] = r
	}
	if len(orphans) > 0 {
		extra["orphan_intents_flushed"] = len(orphans)
	}

	auth, attribution := c.authority()
	r := c.base(KindAction, capturedAt, counter)
	r.KindExt = kindExt
	r.RiskClass = class
	r.RiskPolicyDigest = c.policy.Digest()
	r.Actor = capture.Actor(auth, labelsFor(e, ""))
	r.Operation = receipt.Operation{Name: name, Outcome: receipt.Outcome{Status: "ok", Extra: extra}}
	r.RunID = runID
	r.RunIDProvenance = provenance
	r.Correlation = correlationFor(e)
	r.Authority = auth
	r.Attribution = attribution
	r.Payload = []receipt.Slot{frame}
	r.RawFrameRef = frame.Digest

	id, err := c.emit(e.SessionID, c.ids.ULIDAt(capturedAt), r)
	if err != nil {
		return nil, err
	}
	return &Result{Event: e.Name, Kind: r.Kind, KindExt: r.KindExt, ReceiptID: id, Counter: counter, Orphans: orphans}, nil
}

// emitOrphan mints the `orphan_intent` receipt for an intent nothing claimed:
// the tool call was recorded as durable intent and no completion ever arrived
// (Q4, Q5). It reuses the counter the intent already consumed — one crossing,
// one counter, no gap for the Q48 detector to trip over.
func (c *Capture) emitOrphan(p Pending) (string, error) {
	auth, attribution := c.authorityForRef(p.ChainRef)
	var slots []receipt.Slot
	if p.InputDigest != "" {
		slots = append(slots, c.recoveredSlot("input", p.InputDigest, p.InputSize))
	}
	if p.FrameDigest != "" {
		slots = append(slots, c.recoveredSlot("hook_event", p.FrameDigest, p.FrameSize))
	}

	r := c.base(KindOrphanIntent, c.now(), p.EmitterCounter)
	r.CapturedAt = p.CapturedAt
	r.RiskClass = p.RiskClass
	r.RiskPolicyDigest = p.RiskPolicyDig
	r.Actor = capture.Actor(auth, map[string]string{
		"mcp_server":       p.MCPServer,
		"claude_code_tool": p.RawToolName,
		"agent_id":         p.AgentID,
		"agent_type":       p.AgentType,
		"session_id":       p.SessionID,
	})
	r.Operation = receipt.Operation{
		Name:   p.Operation,
		Target: p.Target,
		Outcome: receipt.Outcome{
			Status: "error",
			Error:  "no completion observed: the tool call was recorded as intent and no PostToolUse, denial or session end ever closed it",
		},
	}
	r.Attempt = &receipt.Attempt{IntentDigest: p.IntentDigest}
	r.RunID = p.RunID
	r.RunIDProvenance = p.RunIDProvenance
	r.StepKey = p.StepKey
	r.Authority = auth
	r.Attribution = attribution
	r.Payload = slots
	r.RawFrameRef = p.FrameDigest
	if p.SessionID != "" {
		r.Correlation = &receipt.Correlation{SessionID: p.SessionID}
	}
	return c.emit(p.SessionID, p.IntentID, r)
}

// recoveredSlot rebuilds a payload slot from the CAS. If the blob is still
// there the manifest is recomputed from the same bytes it was computed from at
// capture; if the customer deleted it, the slot says `missing` rather than
// pretending — three findings, not one (Q36, Q83).
func (c *Capture) recoveredSlot(role, digest string, size int) receipt.Slot {
	slot := receipt.Slot{
		Role:        role,
		Digest:      digest,
		Custody:     "customer-held",
		ContentType: "application/json",
		Size:        size,
		Ref:         "sha256:" + digest,
		State:       "present",
	}
	raw, err := c.blobs.Get(digest)
	switch {
	case err == nil:
		slot.Manifest = capture.FieldDigests(raw)
	case errors.Is(err, cas.ErrMissing):
		slot.State = "missing"
	default:
		slot.State = "unreadable"
	}
	return slot
}

// authorityForRef embeds the chain that was in force when the intent was
// recorded, fetched from the CAS by the digest the intent kept — not whatever
// chain this recovering process happens to be configured with.
func (c *Capture) authorityForRef(ref string) (*receipt.Authority, receipt.Attribution) {
	unattributed := receipt.Attribution{Verification: "asserted", Class: "unattributed"}
	if ref == "" {
		return nil, unattributed
	}
	if ref == c.chainRef {
		return c.authority()
	}
	raw, err := c.blobs.Get(ref)
	if err != nil {
		// The chain material is gone; the crossing is still evidence, and
		// `unattributed` is the honest reading of what survives.
		return nil, unattributed
	}
	parsed, err := proxy.ParseChain(raw)
	if err != nil || parsed == nil {
		return nil, unattributed
	}
	// The recovered chain gets its own verification pass against the same root
	// material: what is recorded is what THIS process could check about the
	// chain that was in force then (Q18, Q29).
	return capture.Authority(parsed.Hops, aat.Verify(parsed.Hops, c.root), CarriageRouteLocal)
}

// mintPending builds the capture-time facts a post-only receipt needs, for the
// case where no PreToolUse intent exists to supply them.
func (c *Capture) mintPending(e *Event, op, server string, input []byte, at time.Time) (Pending, error) {
	runID, provenance, _ := c.resolveRunID(e)
	ordinal, err := c.nextOrdinal(runID)
	if err != nil {
		return Pending{}, err
	}
	counter, err := capture.NextCounter(c.state)
	if err != nil {
		return Pending{}, err
	}
	class, targetArg := c.policy.Classify(op)
	target := ""
	if targetArg != "" {
		target = stringField(input, targetArg)
	}
	return Pending{
		IntentID:        c.ids.ULIDAt(at),
		IntentDigest:    capture.IntentDigest(op, input),
		SessionID:       e.SessionID,
		Operation:       op,
		RawToolName:     e.ToolName,
		MCPServer:       server,
		Target:          target,
		CapturedAt:      capture.RFC3339(at),
		EmitterJKT:      c.emitter.JKT,
		EmitterCounter:  counter,
		RunID:           runID,
		RunIDProvenance: provenance,
		StepKey:         capture.StepKey(op, input, ordinal),
		RiskClass:       class,
		RiskPolicyDig:   c.policy.Digest(),
		ChainRef:        c.chainRef,
	}, nil
}

// correlationFor carries the session id, which is the correlation key this
// surface uniquely knows. The other four correlation keys are indexed but not
// required at ingest (Q7).
func correlationFor(e *Event) *receipt.Correlation {
	if e.SessionID == "" {
		return nil
	}
	return &receipt.Correlation{SessionID: e.SessionID}
}

// subagentDigest is the join key for a SubagentStart/SubagentStop pair. It is
// computed from what both payloads carry and nothing else.
func subagentDigest(sessionID, agentID, agentType string) string {
	return capture.IntentDigest("claude-code.subagent", []byte(sessionID+"\x00"+agentID+"\x00"+agentType))
}

// argumentsDigest is the plain SHA-256 of the raw argument bytes — the value
// the cross-surface collapse joins on (dedup.go).
func argumentsDigest(input []byte) string { return cas.Digest(input) }

// outcomeFromToolResponse maps a hook `tool_response` to the receipt's
// outcome.
//
// # What a real client puts here (ENG-33, Claude Code 2.1.250)
//
// A `PostToolUse` payload is only ever emitted for a call that SUCCEEDED. A
// failing tool call produces a `PostToolUseFailure` instead, carrying a plain
// string `error` — and no `PostToolUse` at all. That was checked live: an MCP
// tool returning `isError: true` produced `PreToolUse` and then nothing.
//
// So `tool_response` is not where failure is signalled, and this function's
// honest job is narrower than it was written to be. Two shapes were observed:
//
//   - MCP tools: a bare JSON ARRAY of content blocks,
//     `[{"type":"text","text":"…"}]`. It has no top-level members at all, so
//     none of the signals below can appear in it.
//   - built-in tools: an object, e.g. Bash's
//     `{"stdout":…,"stderr":…,"interrupted":false,…}`. No status member either.
//
// The `isError` / `success` / `error` readers are kept because `tool_response`
// is an untyped passthrough and other producers (the Agent SDK, a future
// client) may put one there — but they are marked here as NOT OBSERVED against
// Claude Code, so nobody reads a passing test as evidence that a real client
// emits them. The raw response is committed by digest either way, so any
// finding is recomputable from the record.
func outcomeFromToolResponse(raw []byte) receipt.Outcome {
	if len(raw) == 0 {
		return receipt.Outcome{Status: "ok", Extra: map[string]any{
			"status_evidence": "absent: the hook payload carried no tool_response",
		}}
	}
	if isJSONArray(raw) {
		// The MCP shape. Nothing in a content-block array states an outcome,
		// and a failing MCP call never reaches this event anyway.
		return receipt.Outcome{Status: "ok", Extra: map[string]any{
			"status_evidence": "none: the tool_response is an MCP content-block array, which carries no status member; " +
				"a failed call arrives as PostToolUseFailure instead",
		}}
	}
	if b, ok := boolField(raw, "isError"); ok && b {
		return receipt.Outcome{Status: "error", Error: "tool result reported isError", Extra: map[string]any{
			"status_evidence": "isError",
		}}
	}
	if b, ok := boolField(raw, "success"); ok && !b {
		return receipt.Outcome{Status: "error", Error: "tool result reported success:false", Extra: map[string]any{
			"status_evidence": "success",
		}}
	}
	if msg := stringField(raw, "error"); msg != "" {
		return receipt.Outcome{Status: "error", Error: msg, Extra: map[string]any{
			"status_evidence": "error",
		}}
	}
	return receipt.Outcome{Status: "ok", Extra: map[string]any{
		"status_evidence": "none: the tool_response carried no error signal this surface reads",
	}}
}

// isJSONArray reports whether the value begins with `[`.
func isJSONArray(raw []byte) bool {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '[':
			return true
		default:
			return false
		}
	}
	return false
}

func boolField(obj []byte, key string) (bool, bool) {
	raw, err := jsonspan.ExtractTopLevelValue(obj, key)
	if err != nil {
		return false, false
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, false
	}
	return b, true
}

// DenialReasonRaw returns whatever reason string the payload carried, or "".
// Unlike DenialReason it does not substitute a sentence of its own: a session
// boundary with no reason should record no reason.
func (e *Event) DenialReasonRaw() string { return e.Reason }
