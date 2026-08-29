package hooks

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/behalf-sh/behalf/internal/envelope"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// The whole suite is hermetic: no Claude Code, no network, no MCP server that
// is not this test binary re-executed. The hook payloads are golden files in
// testdata/, pinned to Claude Code's own payloads and schemas — see
// testdata/PROVENANCE.md for which file came from which, what the previous
// hand-written guesses got wrong, and what remains unverified. The tests assert
// against the frozen v1 schema rather than against a snapshot of this code's
// own output.

// Identifiers the goldens share. A UUID session id and a hex agent id are what
// the client actually emits; they are constants here so a golden refresh
// changes one line rather than nine assertions.
const (
	goldenSessionID = "0c7f4d21-9a3e-4f18-b8d0-31c4a7e55b62"
	goldenAgentID   = "a442fcbac7e633f52"
	goldenAgentType = "code-reviewer"
)

// session scripts a run of hook events against one state directory.
type session struct {
	t        *testing.T
	stateDir string
	env      map[string]string
	chain    string
	clock    time.Time
}

func newSession(t *testing.T) *session {
	t.Helper()
	return &session{
		t:        t,
		stateDir: t.TempDir(),
		env:      map[string]string{},
		clock:    time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC),
	}
}

// open builds a Capture over the session's state dir with a clock that
// advances a second per read, so captured_at values are ordered and stable.
func (s *session) open() *Capture {
	s.t.Helper()
	cfg := Config{
		StateDir: s.stateDir,
		Getenv:   func(k string) string { return s.env[k] },
		Now:      s.tick,
	}
	if s.chain != "" {
		cfg.ChainPath = writeTemp(s.t, s.t.TempDir(), "chain.json", s.chain)
	}
	c, err := Open(cfg)
	if err != nil {
		s.t.Fatalf("open capture: %v", err)
	}
	return c
}

func (s *session) tick() time.Time {
	out := s.clock
	s.clock = s.clock.Add(time.Second)
	return out
}

// fire runs one hook event through a freshly opened Capture — one process per
// event, which is the shape the real binary has.
func (s *session) fire(payload []byte) *Result {
	s.t.Helper()
	res, err := s.open().Handle(payload)
	if err != nil {
		s.t.Fatalf("handle %s: %v", string(payload[:min(len(payload), 80)]), err)
	}
	return res
}

// golden reads a golden hook payload.
func golden(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func (s *session) spoolDir() string { return filepath.Join(s.stateDir, DefaultSpoolDirName) }

// spooled returns the receipts sitting in the spool, decoded from their stored
// envelopes, alongside the raw payload bytes the emitter signed.
func spooled(t *testing.T, spoolDir string) ([]receipt.Receipt, [][]byte) {
	t.Helper()
	completions, err := spool.ReadAll(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	var rs []receipt.Receipt
	var payloads [][]byte
	for _, c := range completions {
		env, err := envelope.Parse(c.Envelope)
		if err != nil {
			t.Fatalf("parse spooled envelope: %v", err)
		}
		var r receipt.Receipt
		if err := json.Unmarshal(env.Payload, &r); err != nil {
			t.Fatalf("decode receipt payload: %v", err)
		}
		rs = append(rs, r)
		payloads = append(payloads, env.Payload)
	}
	return rs, payloads
}

// readCompletions returns the parsed DSSE envelopes sitting in the spool.
func readCompletions(spoolDir string) ([]*envelope.Envelope, error) {
	completions, err := spool.ReadAll(spoolDir)
	if err != nil {
		return nil, err
	}
	out := make([]*envelope.Envelope, 0, len(completions))
	for _, c := range completions {
		env, err := envelope.Parse(c.Envelope)
		if err != nil {
			return nil, err
		}
		out = append(out, env)
	}
	return out, nil
}

// schemaValidate checks a receipt payload against the frozen v1 schema.
func schemaValidate(t *testing.T, payload []byte) {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := compiledSchema(t).Validate(v); err != nil {
		t.Fatalf("receipt violates the frozen v1 schema: %v\npayload: %s", err, payload)
	}
}

var schemaCache *jsonschema.Schema

func compiledSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	if schemaCache != nil {
		return schemaCache
	}
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("../../docs/receipt-schema-v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	schemaCache = sch
	return sch
}

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// testChainJSON is a two-hop chain in the receipt-authority shape: a depth-0
// root and one agent hop. Unsigned, so every hop verifies as `asserted` with
// the caller-asserted reason — which is the honest reading of a chain nobody
// signed, and is what a day-zero install actually produces.
func testChainJSON() string {
	root := testkeys.ActorRoot()
	hop1 := testkeys.ActorHop1()
	const rootParHash = "0000000000000000000000000000000000000000000000000000000000000000"
	const hop1ParHash = "1111111111111111111111111111111111111111111111111111111111111111"

	chain := map[string]any{
		"chain": []any{
			map[string]any{
				"del_depth":     0,
				"del_max_depth": 4,
				"par_hash":      rootParHash,
				"cnf":           map[string]any{"jwk": map[string]any{"kty": root.JWK.Kty, "crv": root.JWK.Crv, "x": root.JWK.X}},
				"authorization_details": []any{
					map[string]any{"type": "sh.behalf/root-delegation/v1"},
				},
				"exp": 4102444800,
				"jti": "behalf-root-01hzzzzzzzzzzzzzzzzzzzzzzz",
				"credential": map[string]any{
					"issuer": "https://idp.example",
					"kind":   "oidc-id-token",
					"id":     "oidc-sub-digest:" + rootParHash,
					"exp":    4102444800,
					"jkt":    root.JKT,
				},
				"root_principal_binding": map[string]any{
					"nonce":      root.JKT,
					"device_jkt": root.JKT,
				},
				"verification": map[string]any{"status": "verified", "method": "oidc-nonce-binding"},
			},
			map[string]any{
				"del_depth":     1,
				"del_max_depth": 4,
				"par_hash":      hop1ParHash,
				"cnf":           map[string]any{"jwk": map[string]any{"kty": hop1.JWK.Kty, "crv": hop1.JWK.Crv, "x": hop1.JWK.X}},
				"authorization_details": []any{
					map[string]any{"type": "sh.behalf/tool-scope/v1", "actions": []any{"orders.search", "refund.issue"}},
				},
				"exp": 4102444800,
				"jti": "behalf-hop-01hzzzzzzzzzzzzzzzzzzzzzzz",
				"credential": map[string]any{
					"issuer": "https://idp.example",
					"kind":   "oauth-jti",
					"id":     "aat:hop-1",
					"exp":    4102444800,
					"jkt":    hop1.JKT,
				},
				"verification": map[string]any{"status": "asserted", "method": "aat-chain"},
			},
		},
	}
	b, err := json.Marshal(chain)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// findKind returns the single receipt of a kind, failing if there is not
// exactly one.
func findKind(t *testing.T, rs []receipt.Receipt, kind string) receipt.Receipt {
	t.Helper()
	var out []receipt.Receipt
	for _, r := range rs {
		if r.Kind == kind {
			out = append(out, r)
		}
	}
	if len(out) != 1 {
		t.Fatalf("found %d receipts of kind %q, want 1", len(out), kind)
	}
	return out[0]
}

// outcomeExtra reads one of the surface-specific fields the receipt flattens
// into `operation.outcome`.
//
// It reads the raw signed payload rather than the decoded struct on purpose:
// receipt.Outcome.Extra is write-only by design (it is `json:"-"` and
// MarshalJSON splices it in), so a decoded receipt never carries it back. What
// a reader of the log actually sees is the JSON, and that is what this checks.
func outcomeExtra(t *testing.T, payload []byte, key string) any {
	t.Helper()
	var doc struct {
		Operation struct {
			Outcome map[string]any `json:"outcome"`
		} `json:"operation"`
	}
	if err := json.Unmarshal(payload, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Operation.Outcome[key]
}

// payloadOf returns the signed payload bytes of the single receipt of a kind.
func payloadOf(t *testing.T, rs []receipt.Receipt, payloads [][]byte, kind string) []byte {
	t.Helper()
	var out []byte
	n := 0
	for i, r := range rs {
		if r.Kind == kind {
			out, n = payloads[i], n+1
		}
	}
	if n != 1 {
		t.Fatalf("found %d receipts of kind %q, want 1", n, kind)
	}
	return out
}

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

// argsDigestOf is the value the cross-surface join compares: the plain
// SHA-256 of raw argument bytes. Computed here from crypto/sha256 rather than
// borrowed from the production helper, so the test checks the number and not
// just that one function agrees with itself.
func argsDigestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
