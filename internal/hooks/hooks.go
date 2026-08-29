package hooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/capture"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// Surface is the emitter.surface value for this capture surface (schema §5,
// Q44, D4). The enum already had it: the hooks companion was designed into the
// frozen schema, not bolted on.
const Surface = "claude-code-hook"

// OtelConventionsVersion is the gen_ai.* semantic-conventions version in force
// at capture, stamped per record so old receipts can be re-normalised when the
// still-Development conventions move (Q8, Q49). It matches the proxy's: both
// surfaces are recording against the same conventions at the same moment, and
// two different values would be a lie about one of them.
const OtelConventionsVersion = "1.29.0"

// CarriageRouteLocal records how a delegation chain reached this surface.
//
// The proxy's hops arrive beside the request in `params._meta` and say so. A
// hook has no request to ride beside: the chain is read from local
// configuration. That is a materially weaker carriage story — nothing tied
// this chain to this particular tool call — and the hop records it rather than
// borrowing the proxy's route string (Q15).
const CarriageRouteLocal = "local-file:sh.behalf/chain"

// Record kinds this surface mints (§3).
const (
	KindToolCall     = "tool_call"
	KindApproval     = "approval"
	KindDenial       = "denial"
	KindDelegation   = "delegation"
	KindOrphanIntent = "orphan_intent"
	KindAction       = "action"
)

// kind_ext values. The frozen `kind` enum is closed on purpose, so surface
// vocabulary that is not a new record type rides the verbatim,
// non-load-bearing `kind_ext` namespace (Q6).
const (
	KindExtSubagentStart = "sh.behalf/claude-code/subagent_start"
	KindExtSubagentStop  = "sh.behalf/claude-code/subagent_stop"
	KindExtSessionEnd    = "sh.behalf/claude-code/session_end"
	KindExtStop          = "sh.behalf/claude-code/stop"
	// KindExtPostOnly marks a tool_call receipt built from PostToolUse alone,
	// with no PreToolUse intent behind it. The crossing is recorded; what is
	// NOT true of it is Q4's durable-intent-before-the-action property, and a
	// reader must be able to tell those apart.
	KindExtPostOnly = "sh.behalf/claude-code/post-only"
)

// Config configures a Capture.
type Config struct {
	// StateDir is the resolved behalf state directory (identity.ResolveDir).
	// It holds the emitter key, the shared monotonic counter, the pending
	// intents, the per-run ordinals and, by default, the spool and the CAS.
	// Required.
	StateDir string
	// SpoolDir defaults to <StateDir>/hook-spool.
	SpoolDir string
	// CASDir defaults to <StateDir>/blobs — the customer-held payload store,
	// shared with every other surface so a blob both surfaces commit to is
	// stored once (Q38's free dedup).
	CASDir string
	// PolicyPath is the tool-policy config; empty uses DefaultPolicyJSON.
	PolicyPath string
	// ChainPath is the delegation chain material; empty means `unattributed`
	// receipts, which is the honest day-zero state.
	ChainPath string
	// Getenv resolves the run_id precedence rungs; nil uses os.Getenv.
	Getenv func(string) string
	// Now overrides the clock; nil uses time.Now.
	Now func() time.Time
	// Entropy overrides the ULID entropy source; nil uses crypto/rand.
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

// Capture is an open hook capture surface: everything a single hook
// invocation needs, loaded once.
type Capture struct {
	cfg     Config
	state   string
	emitter *identity.Key
	blobs   *cas.Store
	policy  *proxy.Policy
	pending *PendingStore
	ids     *capture.IDSource

	// chain is the delegation material and chainResults is aat.Verify over it,
	// computed once. Verification runs at capture, in customer territory,
	// entirely offline (Q18); a carried hop's own claim about its verification
	// status is discarded on the way in, because a token that grades itself is
	// not evidence (Q29).
	chain        *proxy.Chain
	chainResults []aat.HopResult
	chainRef     string
	root         aat.RootMaterial

	now    func() time.Time
	getenv func(string) string
}

// Open loads the emitter key, policy and chain, and prepares the CAS and the
// pending store. It does not scan the spool: a hook process must not pay for
// the whole directory on the agent's hot path (spoolwriter.go).
func Open(cfg Config) (*Capture, error) {
	if cfg.StateDir == "" {
		return nil, errors.New("hooks: state dir is required")
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
	policy, err := loadPolicy(cfg.StateDir, cfg.PolicyPath)
	if err != nil {
		return nil, err
	}
	chain, err := proxy.LoadChain(cfg.ChainPath)
	if err != nil {
		return nil, err
	}
	blobs := cas.New(cfg.casDir())
	if err := blobs.Ensure(); err != nil {
		return nil, err
	}

	c := &Capture{
		cfg:     cfg,
		state:   cfg.StateDir,
		emitter: emitter,
		blobs:   blobs,
		policy:  policy,
		pending: NewPendingStore(cfg.StateDir),
		ids:     capture.NewIDSource(cfg.Entropy),
		chain:   chain,
		now:     now,
		getenv:  getenv,
	}

	// Verification at capture (Q18): D5's root predicate at depth 0, the AAT
	// signature chain and its invariants above it, offline, against the login
	// material in this state directory. Absent material is not an error — it
	// is the day-zero state (Q21) — and yields an asserted root with a reason.
	c.root = aat.LoadRootMaterial(cfg.StateDir)
	c.root.At = now()
	if chain != nil && len(chain.Hops) > 0 {
		c.chainResults = aat.Verify(chain.Hops, c.root)
	}
	// The carried chain material is customer-held evidence in its own right:
	// storing it by digest lets a recovered orphan embed the chain that was in
	// force at capture rather than whatever a later process loads.
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
		if err := capture.RetainHopTokens(blobs, chain.Hops); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// PolicyDirName holds the materialised built-in policy.
const PolicyDirName = "policy"

// loadPolicy reads the tool policy, defaulting to this surface's built-in.
// proxy.LoadPolicy owns the format, the matcher and the digest — one policy
// engine, two surfaces — and it reads from a file, so the built-in has to
// become one.
//
// It is materialised under the state directory with its own content digest in
// the file name. That makes it immutable by construction (a changed constant
// is a different file, so an upgrade can never keep classifying against last
// version's rules), auditable (the operator can read exactly what classified
// their receipts), owner-only, and free after the first call — which matters,
// because this runs once per tool call on the agent's hot path.
func loadPolicy(stateDir, path string) (*proxy.Policy, error) {
	if path != "" {
		return proxy.LoadPolicy(path)
	}
	dir := filepath.Join(stateDir, PolicyDirName)
	name := filepath.Join(dir, "hook-policy-"+cas.Digest([]byte(DefaultPolicyJSON))[:16]+".json")
	if _, err := os.Stat(name); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("hooks: stat built-in policy: %w", err)
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("hooks: create policy dir: %w", err)
		}
		if err := writeSync(name, []byte(DefaultPolicyJSON)); err != nil {
			return nil, fmt.Errorf("hooks: materialise built-in policy: %w", err)
		}
	}
	return proxy.LoadPolicy(name)
}

// Result reports what one hook invocation did. It is what the CLI prints on
// stderr and what the tests assert against; nothing downstream depends on it.
type Result struct {
	Event     string   // the hook event handled
	Kind      string   // the receipt kind minted, "" when none was
	KindExt   string   // the kind_ext stamped, if any
	ReceiptID string   // the minted receipt id
	Counter   int      // the emitter counter the receipt carries
	Pending   bool     // an intent was durably recorded instead of a receipt
	Orphans   []string // receipt ids of orphan_intent records flushed
	Note      string   // a human sentence about anything unusual
}

// Handle captures one hook payload: parse, build the receipt the event calls
// for, sign it with the emitter key and durably spool it.
//
// It returns ErrUnhandledEvent for a well-formed payload this surface does not
// receipt. That is not a failure — Claude Code may add events, and recording
// an unknown one as something it is not would be worse than silence about it.
func (c *Capture) Handle(raw []byte) (*Result, error) {
	e, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	switch e.Name {
	case EventPreToolUse:
		return c.handlePreToolUse(e)
	case EventPostToolUse:
		return c.handlePostToolUse(e)
	case EventPostToolUseFailed:
		return c.handlePostToolUseFailure(e)
	case EventPermissionReq:
		return c.handlePermission(e, KindApproval)
	case EventPermissionDenied:
		return c.handlePermission(e, KindDenial)
	case EventSubagentStart:
		return c.handleSubagent(e, true)
	case EventSubagentStop:
		return c.handleSubagent(e, false)
	case EventSessionEnd, EventStop:
		return c.handleSessionBoundary(e)
	default:
		return &Result{Event: e.Name}, fmt.Errorf("%w: %s", ErrUnhandledEvent, e.Name)
	}
}

// Recover flushes unclaimed pending intents as `orphan_intent` receipts (Q4,
// Q5): the crossing was recorded as durable intent, the completion never
// arrived, and the record says exactly that. sessionID limits the sweep to one
// session; olderThan skips intents younger than the given age, so a sweep run
// beside a live session does not steal calls that are merely in flight.
func (c *Capture) Recover(sessionID string, olderThan time.Duration) ([]string, error) {
	orphans, err := c.pending.Sweep(sessionID, olderThan, c.now())
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(orphans))
	for _, p := range orphans {
		id, err := c.emitOrphan(p)
		if err != nil {
			return ids, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// emit signs a receipt with the emitter key and durably spools it. The
// envelope is the signed bytes; nothing downstream re-marshals the payload.
func (c *Capture) emit(sessionID, intentID string, r *receipt.Receipt) (string, error) {
	receiptID, env, err := capture.Emit(c.emitter, r)
	if err != nil {
		return "", err
	}
	w := newSpoolWriter(c.cfg.spoolDir(), sessionID)
	if err := w.appendCompletion(intentID, receiptID, env); err != nil {
		return "", err
	}
	return receiptID, nil
}

// base builds the fields every receipt from this surface carries.
func (c *Capture) base(kind string, capturedAt time.Time, counter int) *receipt.Receipt {
	return &receipt.Receipt{
		SchemaVersion:      receipt.SchemaVersion,
		OtelConventionsVer: OtelConventionsVersion,
		ReceiptID:          c.ids.ULIDAt(capturedAt),
		Kind:               kind,
		CapturedAt:         capture.RFC3339(capturedAt),
		Emitter: receipt.Emitter{
			JKT:     c.emitter.JKT,
			Surface: Surface,
			Counter: counter,
		},
		Provenance: receipt.Provenance{Source: "native"},
	}
}

// authority returns the embedded chain and the attribution axes for this
// process's loaded chain.
func (c *Capture) authority() (*receipt.Authority, receipt.Attribution) {
	var hops []aat.Hop
	if c.chain != nil {
		hops = c.chain.Hops
	}
	return capture.Authority(hops, c.chainResults, CarriageRouteLocal)
}

// leafAnchor returns the delegation token identity a denial, an approval or a
// failed delegation anchors to when there is no action record to point at
// (Q5): the deepest hop's `jti` and `par_hash`.
//
// `par_hash` is dropped unless it is a well-formed digest. The frozen schema
// types it as one, and a chain file carrying something else would otherwise
// turn every consent record in the session into a schema violation — losing
// the whole anchor to salvage a field that was never usable.
func (c *Capture) leafAnchor() (jti, parHash string) {
	if c.chain == nil || len(c.chain.Hops) == 0 {
		return "", ""
	}
	leaf := c.chain.Hops[len(c.chain.Hops)-1]
	if !isSHA256Hex(leaf.Claims.ParHash) {
		return leaf.Claims.JTI, ""
	}
	return leaf.Claims.JTI, leaf.Claims.ParHash
}

// isSHA256Hex reports whether s is 64 lowercase hex characters — the schema's
// sha256 pattern.
func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// labelsFor gathers the self-reported names Claude Code hands us. They are
// stored verbatim as asserted labels and never used for security decisions
// (Q16, D4).
func labelsFor(e *Event, server string) map[string]string {
	l := map[string]string{}
	if server != "" {
		l["mcp_server"] = server
	}
	if e.ToolName != "" {
		l["claude_code_tool"] = e.ToolName
	}
	if e.AgentID != "" {
		l["agent_id"] = e.AgentID
	}
	if e.AgentType != "" {
		l["agent_type"] = e.AgentType
	}
	if e.SessionID != "" {
		l["session_id"] = e.SessionID
	}
	return l
}

// frameSlot commits the exact stdin bytes of the hook event to the CAS.
//
// This is Q49's optional stronger form, taken rather than skipped: the receipt
// models the fields behalf knows how to read, and the raw frame keeps
// everything else — including fields Claude Code adds after this code was
// written — as customer-held evidence a reader can go and check. It is also
// where the self-reported agent and server names survive when there is no
// chain and therefore no `actor` object to carry labels.
func (c *Capture) frameSlot(e *Event) (receipt.Slot, error) {
	return capture.Slot(c.blobs, "hook_event", e.Raw, "application/json")
}

// stringField reads a top-level string member without re-serializing anything
// around it.
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
