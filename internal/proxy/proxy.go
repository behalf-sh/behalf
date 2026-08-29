// Package proxy is the behalf MCP stdio interposer — the canonical v1
// capture surface and reference implementation (D4, Q44).
//
// It sits between an MCP client and a real MCP server over stdio and
// forwards newline-delimited JSON-RPC in both directions VERBATIM, with one
// exception: on client->server `tools/call` requests it splices the two
// legal keys into `params._meta` (the chain under `sh.behalf/chain`, W3C
// trace context under `baggage` — Q15, Q50, D4). Nothing else is reordered,
// rewritten or re-serialized; a JSON diff of any forwarded line against the
// line that arrived differs only inside `params._meta`, and only on
// tools/call.
//
// MCP revision 2026-07-28 is stateless over stdio, so there is no
// initialize session to track: each line stands alone and responses are
// matched to requests by JSON-RPC id.
//
// # What gets recorded
//
// Q2's closed rule: every `tools/call` through the proxy is a receipt,
// reads included. Server->client requests, notifications, unmatched ids and
// all other traffic cross byte-verbatim and produce no receipts.
//
// Per call, in this order (Q4, Q48):
//
//  1. allocate the per-emitter monotonic counter;
//  2. write the raw params bytes into the customer-held CAS;
//  3. durably spool the INTENT (fsync) — before anything is forwarded;
//  4. forward the request;
//  5. on the matching response, build the completion receipt, sign it with
//     the emitter key (DSSE/PAE) and durably spool it;
//  6. forward the response.
//
// The proxy never appends to the log: one appender per log (Q57). A drain
// moves the spool into the log at-least-once, safe because ingest dedups on
// receipt_id (Q46). A crash between steps 3 and 5 leaves an intent with no
// completion, and the next Open flushes it as an `orphan_intent` receipt
// carrying the spooled intent digest (Q4, Q5).
//
// # Failure posture
//
// A capture failure — spool, CAS or signing — aborts the proxy rather than
// forwarding an unrecorded call. behalf's own premise is that a silent gap
// is indistinguishable from tampering (Q45), so a recorder that cannot
// record must not pretend to. This is stricter than Q47's observe-mode
// default, which concerns log backpressure, not a broken capture surface.
//
// # Verification at capture
//
// The proxy verifies the chain it forwards (Q18): the D5 root predicate at
// depth 0, the AAT signature chain and its invariants above it, and the
// attenuation comparison over the raw RFC 9396 grants — all offline, all in
// customer territory, all in internal/aat. The per-hop `{status, method,
// evidence_ref}` in the receipt is that result; the receipt-level rollup is
// the weakest hop (Q12). A carried hop's own claim about its verification
// status is discarded on the way in.
//
// The chain and the login material are both fixed for the life of the
// process, so verification runs once at startup rather than per receipt.
//
// # Not in Week 3
//
// This is observe mode only: the proxy records what it checked, and does not
// enforce leaf scope before forwarding (Q47's opt-in enforcement mode). A
// chain that verifies as `broken` is recorded as broken and forwarded, per
// Q45 — append and flag, never gate.
package proxy

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/behalf-sh/behalf/internal/aat"
	// Aliased: this package has its own unexported `capture` type. The import
	// is the first step of the lift internal/capture's doc comment describes.
	capturelib "github.com/behalf-sh/behalf/internal/capture"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
)

// DefaultSpoolDirName is the capture spool under the state directory.
const DefaultSpoolDirName = "proxy-spool"

// Config configures Run.
type Config struct {
	// StateDir is the resolved behalf state directory (identity.ResolveDir).
	// It holds the emitter key, the monotonic counter and, by default, the
	// spool and the CAS. Required.
	StateDir string
	// SpoolDir defaults to <StateDir>/proxy-spool.
	SpoolDir string
	// CASDir defaults to <StateDir>/blobs — the customer-held payload store.
	CASDir string
	// PolicyPath is the tool-policy config; empty uses DefaultPolicyJSON.
	PolicyPath string
	// ChainPath is the chain material; empty means no injection and
	// `unattributed` receipts.
	ChainPath string
	// Command is the real MCP server command and its arguments. Required.
	Command []string
	// Env is the server's environment; nil inherits the proxy's.
	Env []string
	// Getenv resolves the run_id precedence rungs; nil uses os.Getenv.
	Getenv func(string) string
	// Now overrides the clock; nil uses time.Now. Set by tests and by
	// cmd/behalf-record's deterministic recording mode (see
	// deterministic.go); production leaves it nil.
	Now func() time.Time
	// Entropy overrides the ULID entropy source that mints receipt_id and
	// intent_id; nil uses crypto/rand. Set by deterministic recordings, and
	// only ever alongside Now — the two together are what make a recording
	// byte-reproducible (see deterministic.go).
	Entropy io.Reader
}

func (c Config) spoolDir() string {
	if c.SpoolDir != "" {
		return c.SpoolDir
	}
	return filepath.Join(c.StateDir, DefaultSpoolDirName)
}

func (c Config) casDir() string {
	if c.CASDir != "" {
		return c.CASDir
	}
	return identity.BlobsDir(c.StateDir)
}

// Run spawns the server command and interposes on the stdio streams until
// the server's stdout closes, then returns the server's exit status.
func Run(cfg Config, stdin io.Reader, stdout, stderr io.Writer) error {
	if len(cfg.Command) == 0 {
		return errors.New("proxy: no server command given")
	}
	c, err := newCapture(cfg)
	if err != nil {
		return err
	}
	defer c.spool.Close()

	cmd := exec.Command(cfg.Command[0], cfg.Command[1:]...)
	cmd.Env = cfg.Env
	cmd.Stderr = stderr
	srvIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("proxy: server stdin: %w", err)
	}
	srvOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("proxy: server stdout: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("proxy: start %s: %w", cfg.Command[0], err)
	}

	var reqErr error
	var once sync.Once
	reqDone := make(chan struct{})
	go func() {
		defer close(reqDone)
		reqErr = c.pumpRequests(stdin, srvIn)
		once.Do(func() { srvIn.Close() })
	}()

	// The response pump owns stdout, so responses reach the client in the
	// order the server produced them even when receipts are built in
	// between.
	respErr := c.pumpResponses(srvOut, stdout)
	// The server is finished writing: close its stdin so it can exit even
	// if the client is still holding its own stdin open.
	once.Do(func() { srvIn.Close() })
	waitErr := cmd.Wait()

	select {
	case <-reqDone:
	case <-time.After(50 * time.Millisecond):
		// The request pump is blocked reading a client stdin nobody will
		// write to again. Leave it; the process is on its way out.
	}

	switch {
	case respErr != nil:
		return respErr
	case reqErr != nil:
		return reqErr
	default:
		return waitErr
	}
}

// newCapture loads the emitter key, policy and chain, opens the CAS and the
// spool, resolves the run id, and flushes any orphaned intents the last
// process left behind.
func newCapture(cfg Config) (*capture, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("proxy: state dir is required")
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	getenv := os.Getenv
	if cfg.Getenv != nil {
		getenv = cfg.Getenv
	}
	if err := identity.EnsureDir(cfg.StateDir); err != nil {
		return nil, err
	}
	emitter, err := identity.LoadOrGenerateEmitter(cfg.StateDir)
	if err != nil {
		return nil, err
	}
	policy, err := LoadPolicy(cfg.PolicyPath)
	if err != nil {
		return nil, err
	}
	chain, err := LoadChain(cfg.ChainPath)
	if err != nil {
		return nil, err
	}
	blobs := cas.New(cfg.casDir())
	if err := blobs.Ensure(); err != nil {
		return nil, err
	}

	ids := newIDSource(cfg.Entropy)
	// One clock read, used for both the run id and the chain's freshness
	// check. A deterministic recording's clock advances on every read, so an
	// extra read here would shift every captured_at in the recording (see
	// deterministic.go).
	startedAt := now()
	runID, provenance, traceID := resolveRunID(getenv, startedAt, ids)

	// Verification at capture (Q18): the D5 root predicate and the AAT
	// invariants, offline, against the login material in this state
	// directory. Absent material is not an error — it is the day-zero state
	// (Q21) — and yields an asserted root with a reason.
	root := aat.LoadRootMaterial(cfg.StateDir)
	root.At = startedAt
	var chainResults []aat.HopResult
	if chain != nil && len(chain.Hops) > 0 {
		chainResults = aat.Verify(chain.Hops, root)
	}

	c := &capture{
		emitter:      emitter,
		state:        cfg.StateDir,
		blobs:        blobs,
		policy:       policy,
		chain:        chain,
		root:         root,
		chainResults: chainResults,
		runID:        runID,
		provenance:   provenance,
		traceID:      traceID,
		now:          now,
		ids:          ids,
		pending:      map[string]*pending{},
	}
	if len(cfg.Command) > 0 {
		c.serverLabel = filepath.Base(cfg.Command[0])
	}
	// The carried chain material is itself customer-held evidence: storing
	// it by digest lets a recovered orphan_intent embed the chain that was
	// in force at capture rather than whatever a later process loads.
	if chain != nil && len(chain.Raw) > 0 {
		ref, err := blobs.Put(chain.Raw)
		if err != nil {
			return nil, err
		}
		c.chainRef = ref
	}
	// And each hop's own token, at the address its `evidence_ref` already
	// names, so that reference resolves to bytes a sceptic can re-check
	// rather than into an empty store (capture.RetainHopTokens).
	if chain != nil {
		if err := capturelib.RetainHopTokens(blobs, chain.Hops); err != nil {
			return nil, err
		}
	}

	sp, recovery, err := spool.Open(cfg.spoolDir())
	if err != nil {
		return nil, err
	}
	c.spool = sp
	if _, err := c.flushOrphans(recovery); err != nil {
		sp.Close()
		return nil, err
	}
	return c, nil
}

// pending is one tools/call awaiting its response.
type pending struct {
	intent    spool.Intent
	paramsRaw []byte // the params bytes as forwarded (Q44)
	argsRaw   []byte
}

// pumpRequests forwards client->server traffic, receipting tools/call.
func (c *capture) pumpRequests(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	for {
		line, readErr := br.ReadBytes('\n')
		if len(line) > 0 {
			out, err := c.onClientLine(line)
			if err != nil {
				return err
			}
			if _, err := w.Write(out); err != nil {
				return nil // the server is gone; stop forwarding, quietly
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("proxy: read client: %w", readErr)
		}
	}
}

// pumpResponses forwards server->client traffic, closing receipts.
func (c *capture) pumpResponses(r io.Reader, w io.Writer) error {
	br := bufio.NewReader(r)
	for {
		line, readErr := br.ReadBytes('\n')
		if len(line) > 0 {
			if err := c.onServerLine(line); err != nil {
				return err
			}
			// Verbatim: the response reaches the client exactly as the
			// server wrote it.
			if _, err := w.Write(line); err != nil {
				return fmt.Errorf("proxy: write client: %w", err)
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return fmt.Errorf("proxy: read server: %w", readErr)
		}
	}
}

// onClientLine returns the bytes to forward. Only a tools/call request is
// touched, and only inside params._meta.
func (c *capture) onClientLine(line []byte) ([]byte, error) {
	f := splitFrame(line)
	m := parseMessage(f.body)
	if !m.isToolsCallRequest() {
		return line, nil
	}
	var chainRaw []byte
	if c.chain != nil {
		chainRaw = c.chain.Raw
	}
	body, err := injectMeta(f.body, chainRaw, c.runID)
	if err != nil {
		return nil, err
	}
	if err := c.spoolIntent(body, m.matchKey()); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+len(f.term))
	out = append(out, body...)
	out = append(out, f.term...)
	return out, nil
}

// spoolIntent stamps the counter, stores the params blob and durably spools
// the intent — everything that must be true before the request is
// forwarded (Q4, Q48).
func (c *capture) spoolIntent(body []byte, matchKey string) error {
	params, err := jsonspan.ExtractTopLevelValue(body, "params")
	if err != nil {
		// A tools/call with no params: nothing to capture, and the proxy
		// does not correct the client's message.
		return nil
	}
	tool := stringField(params, "name")
	if tool == "" {
		return nil
	}
	args, _ := jsonspan.ExtractTopLevelValue(params, "arguments")

	counter, err := c.nextCounter()
	if err != nil {
		return err
	}
	inputDigest, err := c.blobs.Put(params)
	if err != nil {
		return err
	}
	class, targetArg := c.policy.Classify(tool)
	target := ""
	if targetArg != "" {
		target = stringField(args, targetArg)
	}

	capturedAt := c.now()
	in := spool.Intent{
		IntentID:        c.ids.ulidAt(capturedAt),
		IntentDigest:    intentDigest(tool, params),
		Tool:            tool,
		Target:          target,
		CapturedAt:      rfc3339(capturedAt),
		Emitter:         spool.Emitter{JKT: c.emitter.JKT, Counter: counter},
		RunID:           c.runID,
		RunIDProvenance: c.provenance,
		StepKey:         stepKey(tool, args, c.ordinal),
		RiskClass:       class,
		RiskPolicyDig:   c.policy.Digest(),
		InputDigest:     inputDigest,
		InputSize:       len(params),
		ChainRef:        c.chainRef,
	}
	c.ordinal++

	// Durable before forwarding: this is the whole intent contract.
	if err := c.spool.AppendIntent(in); err != nil {
		return err
	}

	c.mu.Lock()
	c.pending[matchKey] = &pending{
		intent:    in,
		paramsRaw: append([]byte(nil), params...),
		argsRaw:   append([]byte(nil), args...),
	}
	c.mu.Unlock()
	return nil
}

// onServerLine closes the receipt for a matching response. Anything with no
// match — a server->client request, a notification, a response to a call
// this proxy never saw — produces no receipt (Q2's closed rule).
func (c *capture) onServerLine(line []byte) error {
	f := splitFrame(line)
	m := parseMessage(f.body)
	if !m.isResponse() {
		return nil
	}
	key := m.matchKey()
	c.mu.Lock()
	p := c.pending[key]
	delete(c.pending, key)
	c.mu.Unlock()
	if p == nil {
		return nil
	}
	r, err := c.completionReceipt(p, f.body)
	if err != nil {
		return err
	}
	receiptID, env, err := c.emit(r)
	if err != nil {
		return err
	}
	return c.spool.AppendCompletion(p.intent.IntentID, receiptID, env)
}

// completionReceipt merges the spooled intent and the observed response
// into the single completion receipt of the common case (Q4).
func (c *capture) completionReceipt(p *pending, respBody []byte) (*receipt.Receipt, error) {
	in := p.intent
	outcome, outputRaw := readOutcome(respBody)
	recordOutcomeFields(&outcome, outputRaw, c.policy.OutcomeFields(in.Tool))

	slots := make([]receipt.Slot, 0, 2)
	inputSlot, err := c.slotFor("input", p.paramsRaw)
	if err != nil {
		return nil, err
	}
	slots = append(slots, inputSlot)
	if len(outputRaw) > 0 {
		outputSlot, err := c.slotFor("output", outputRaw)
		if err != nil {
			return nil, err
		}
		slots = append(slots, outputSlot)
	}

	auth, attribution := c.authorityFor()
	return &receipt.Receipt{
		SchemaVersion:      receipt.SchemaVersion,
		OtelConventionsVer: OtelConventionsVersion,
		ReceiptID:          c.ids.ulidAt(c.now()),
		Kind:               KindToolCall,
		RiskClass:          in.RiskClass,
		RiskPolicyDigest:   in.RiskPolicyDig,
		CapturedAt:         in.CapturedAt,
		Emitter: receipt.Emitter{
			JKT:     in.Emitter.JKT,
			Surface: Surface,
			Counter: in.Emitter.Counter,
		},
		Actor: c.actorFor(auth),
		Operation: receipt.Operation{
			Name:    in.Tool,
			Target:  in.Target,
			Outcome: outcome,
		},
		Attempt:         &receipt.Attempt{IntentDigest: in.IntentDigest},
		RunID:           in.RunID,
		RunIDProvenance: in.RunIDProvenance,
		Correlation:     c.correlationFor(),
		StepKey:         in.StepKey,
		Authority:       auth,
		Attribution:     attribution,
		Payload:         slots,
		Provenance:      receipt.Provenance{Source: "native"},
	}, nil
}

// readOutcome maps a JSON-RPC response to the receipt's outcome and returns
// the raw bytes that become the output payload slot. A JSON-RPC error is an
// error outcome; so is a result whose `isError` is true, which is how MCP
// reports a tool that failed inside a successful call (Q4: outcome covers
// failure of the attempted operation).
func readOutcome(respBody []byte) (receipt.Outcome, []byte) {
	if raw, err := jsonspan.ExtractTopLevelValue(respBody, "error"); err == nil {
		var e struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		}
		_ = json.Unmarshal(raw, &e)
		msg := e.Message
		if msg == "" {
			msg = "jsonrpc error"
		}
		out := receipt.Outcome{Status: "error", Error: msg}
		if e.Code != 0 {
			out.Extra = map[string]any{"jsonrpc_error_code": e.Code}
		}
		return out, raw
	}
	raw, err := jsonspan.ExtractTopLevelValue(respBody, "result")
	if err != nil {
		return receipt.Outcome{Status: "error", Error: "response carried neither result nor error"}, nil
	}
	if isErrorResult(raw) {
		return receipt.Outcome{Status: "error", Error: "tool result reported isError"}, raw
	}
	return receipt.Outcome{Status: "ok"}, raw
}

func isErrorResult(result []byte) bool {
	raw, err := jsonspan.ExtractTopLevelValue(result, "isError")
	if err != nil {
		return false
	}
	var b bool
	return json.Unmarshal(raw, &b) == nil && b
}

// stringField reads a top-level string member without re-serializing
// anything around it.
func stringField(obj []byte, key string) string {
	raw, err := jsonspan.ExtractTopLevelValue(obj, key)
	if err != nil {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}
