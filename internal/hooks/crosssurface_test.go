package hooks

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/capture"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
)

// These tests run the REAL MCP proxy beside the hook surface, against a fake
// MCP server that is this test binary re-executed. Nothing here is a stand-in
// for the proxy: the receipts the cross-surface rule is checked against are
// the ones internal/proxy actually wrote.
//
// That matters twice over. It is the only honest way to test a rule about two
// surfaces agreeing, and it is what closes the drift risk internal/capture
// documents: the lifted digest functions are asserted against the proxy's own
// output, so moving one copy fails the build.

const envFakeServer = "BEHALF_HOOKS_FAKE_MCP"

func TestMain(m *testing.M) {
	if os.Getenv(envFakeServer) == "1" {
		os.Exit(runFakeServer())
	}
	os.Exit(m.Run())
}

// runFakeServer speaks newline-delimited JSON-RPC over stdio the way MCP
// revision 2026-07-28 does — stateless, no session to track.
func runFakeServer() int {
	r := bufio.NewReader(os.Stdin)
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 {
			var req struct {
				Method string          `json:"method"`
				ID     json.RawMessage `json:"id"`
				Params struct {
					Name      string         `json:"name"`
					Arguments map[string]any `json:"arguments"`
				} `json:"params"`
			}
			if json.Unmarshal(line, &req) == nil && len(req.ID) > 0 && req.Method == "tools/call" {
				body := fmt.Sprintf(
					`{"content":[{"type":"text","text":"ok %s"}],"structuredContent":{"tool":%q}}`,
					req.Params.Name, req.Params.Name)
				fmt.Printf(`{"jsonrpc":"2.0","id":%s,"result":%s}`+"\n", req.ID, body)
			}
		}
		if err != nil {
			return 0
		}
	}
}

// runProxySession drives one proxy session over the given tools/call lines and
// returns its spool directory.
func runProxySession(t *testing.T, stateDir string, env map[string]string, lines []string) string {
	t.Helper()
	var stdout, stderr bytes.Buffer
	cfg := proxy.Config{
		StateDir: stateDir,
		Command:  []string{os.Args[0]},
		Env:      []string{envFakeServer + "=1"},
		Getenv:   func(k string) string { return env[k] },
	}
	if err := proxy.Run(cfg, strings.NewReader(strings.Join(lines, "")), &stdout, &stderr); err != nil {
		t.Fatalf("proxy: %v (stderr %s)", err, stderr.String())
	}
	return filepath.Join(stateDir, proxy.DefaultSpoolDirName)
}

func toolsCall(id, name, args string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}` + "\n"
}

// proxyReceipts decodes what the proxy spooled.
func proxyReceipts(t *testing.T, spoolDir string) []receipt.Receipt {
	t.Helper()
	completions, err := spool.ReadAll(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	var out []receipt.Receipt
	for _, c := range completions {
		env, err := envelopeParse(c.Envelope)
		if err != nil {
			t.Fatal(err)
		}
		var r receipt.Receipt
		if err := json.Unmarshal(env, &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	return out
}

func envelopeParse(env []byte) ([]byte, error) { return jsonspan.ExtractTopLevelValue(env, "payload") }

// The exact argument bytes both surfaces see. The hook payload in
// testdata/*_mcp.json carries these as `tool_input`; the proxy line below
// carries them as `params.arguments`.
const sharedArgs = `{"order_id":"ord_5518","amount":"1200.00"}`

// TestCrossSurfaceDuplicateRule is the rule, end to end: one crossing seen by
// both surfaces produces two appended receipts, the hook one flags itself, and
// a read surface collapses them onto the proxy's.
func TestCrossSurfaceDuplicateRule(t *testing.T) {
	state := t.TempDir()
	const runID = "run_week3_demo"

	// The proxy sees the wire call.
	proxySpool := runProxySession(t, state, map[string]string{proxy.EnvRunID: runID},
		[]string{toolsCall(`1`, "refund.issue", sharedArgs)})
	proxyRs := proxyReceipts(t, proxySpool)
	if len(proxyRs) != 1 {
		t.Fatalf("the proxy spooled %d receipts, want 1", len(proxyRs))
	}

	// The hook sees the same call from inside the client, in the same run.
	s := newSession(t)
	s.stateDir = state
	s.env[capture.EnvRunID] = runID
	s.fire(golden(t, "pre_tool_use_mcp.json"))
	s.fire(golden(t, "post_tool_use_mcp.json"))
	hookRs, _ := spooled(t, filepath.Join(state, DefaultSpoolDirName))
	if len(hookRs) != 1 {
		t.Fatalf("the hook spooled %d receipts, want 1", len(hookRs))
	}

	proxyR, hookR := proxyRs[0], hookRs[0]

	// The two surfaces CANNOT name the operation the same way: the proxy
	// records the name on the wire and Claude Code sanitises it before the hook
	// ever sees it. Each records what it saw, and the join reconciles them
	// under the client's own substitution (ENG-33).
	if proxyR.Operation.Name != "refund.issue" {
		t.Fatalf("the proxy did not record the wire name: %q", proxyR.Operation.Name)
	}
	if hookR.Operation.Name != "refund_issue" {
		t.Fatalf("the hook did not record the client's name: %q", hookR.Operation.Name)
	}
	if !sameOperation(proxyR.Operation.Name, hookR.Operation.Name) {
		t.Fatalf("the two names do not reconcile: %q vs %q",
			proxyR.Operation.Name, hookR.Operation.Name)
	}
	// And each says which surface it is.
	if proxyR.Emitter.Surface != proxy.Surface || hookR.Emitter.Surface != Surface {
		t.Fatalf("surfaces = %q / %q", proxyR.Emitter.Surface, hookR.Emitter.Surface)
	}
	// The receipts are NOT the same record: two ids, two counters, two leaves.
	if proxyR.ReceiptID == hookR.ReceiptID {
		t.Fatal("the two surfaces minted the same receipt_id: they must be independent leaves (Q46)")
	}

	// The join value: the arguments digest, which both surfaces provably
	// commit to.
	want := argsDigestOf([]byte(sharedArgs))
	if got := ProxyArgumentsDigest(&proxyR); got != want {
		t.Fatalf("the proxy's $.arguments field digest = %q, want %q", got, want)
	}
	if got := CrossSurfaceDigest(&hookR); got != want {
		t.Fatalf("the hook's attests-anchor digest = %q, want %q", got, want)
	}
	if !SameCrossing(&proxyR, &hookR) {
		t.Fatal("SameCrossing said no: the collapse rule cannot recognise its own pair")
	}

	// Append and flag: both are in the record, and the read side collapses
	// them onto the canonical proxy receipt without dropping either.
	crossings := Collapse([]*receipt.Receipt{&proxyR, &hookR})
	if len(crossings) != 1 {
		t.Fatalf("Collapse produced %d crossings, want 1", len(crossings))
	}
	if !crossings[0].Duplicated() {
		t.Fatal("the collapsed crossing does not report itself as duplicated")
	}
	if crossings[0].Canonical != &proxyR {
		t.Fatal("the canonical observation is not the proxy's: it records the request actually forwarded (Q44)")
	}
	if len(crossings[0].Observations) != 2 {
		t.Fatal("an observation was dropped: the rule is append-and-flag, never suppress (Q45)")
	}
	if got := crossings[0].Surfaces(); len(got) != 2 {
		t.Fatalf("surfaces = %v, want both", got)
	}
}

// TestCollapseRefusesWhenTheSurfacesSawDifferentBytes: the join is allowed to
// miss, and when it does the correct answer is two crossings, not one. This is
// the D4 pre-rewrite case — another input-modifying hook changed the input
// between what the hook saw and what the proxy forwarded — and collapsing
// there would merge two records that describe genuinely different bytes.
func TestCollapseRefusesWhenTheSurfacesSawDifferentBytes(t *testing.T) {
	state := t.TempDir()
	const runID = "run_week3_demo"

	proxySpool := runProxySession(t, state, map[string]string{proxy.EnvRunID: runID},
		[]string{toolsCall(`1`, "refund.issue", `{"order_id":"ord_5518","amount":"9999.00"}`)})
	proxyR := proxyReceipts(t, proxySpool)[0]

	s := newSession(t)
	s.stateDir = state
	s.env[capture.EnvRunID] = runID
	s.fire(golden(t, "pre_tool_use_mcp.json")) // amount 1200.00
	s.fire(golden(t, "post_tool_use_mcp.json"))
	hookR := mustOne(t, spooledReceipts(t, filepath.Join(state, DefaultSpoolDirName)))

	if SameCrossing(&proxyR, &hookR) {
		t.Fatal("two different argument payloads were collapsed into one crossing")
	}
	crossings := Collapse([]*receipt.Receipt{&proxyR, &hookR})
	if len(crossings) != 2 {
		t.Fatalf("Collapse produced %d crossings, want 2 — a miss must never delete a record", len(crossings))
	}
}

// TestLocalToolsCarryNoCrossSurfaceFlag: a Bash call has no second surface
// that could have seen it, so flagging one would be noise claiming to be a
// finding.
func TestLocalToolsCarryNoCrossSurfaceFlag(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "pre_tool_use_bash.json"))
	s.fire(golden(t, "post_tool_use_bash.json"))
	rs, _ := spooled(t, s.spoolDir())
	if d := CrossSurfaceDigest(&rs[0]); d != "" {
		t.Fatalf("a local tool receipt carries a cross-surface flag: %q", d)
	}
}

// TestCountersAreMonotonicAcrossInterleavedSurfaces is Q48's whole point: two
// capture surfaces sharing one state directory must allocate one strictly
// increasing counter sequence with no gaps and no repeats, or the "prove
// nothing was deleted" claim rebounds on behalf's own transit window.
//
// The flock is what makes it true, and the lock file name is what makes the
// flock shared. If internal/capture's CounterLockFile ever stops matching
// internal/proxy's, this test is what notices.
func TestCountersAreMonotonicAcrossInterleavedSurfaces(t *testing.T) {
	state := t.TempDir()
	const runID = "run_interleaved"

	var counters []int
	collect := func(rs []receipt.Receipt) {
		for _, r := range rs {
			counters = append(counters, r.Emitter.Counter)
		}
	}

	s := newSession(t)
	s.stateDir = state
	s.env[capture.EnvRunID] = runID

	// Interleave: hook, proxy, hook, proxy, hook — each in its own process
	// pass, which is exactly how they run in the field.
	s.fire(golden(t, "pre_tool_use_bash.json"))
	s.fire(golden(t, "post_tool_use_bash.json"))

	proxySpool := runProxySession(t, state, map[string]string{proxy.EnvRunID: runID},
		[]string{toolsCall(`1`, "orders.search", `{"query":"acme"}`)})

	s.fire(golden(t, "pre_tool_use_mcp.json"))
	s.fire(golden(t, "permission_request.json"))
	s.fire(golden(t, "post_tool_use_mcp.json"))

	runProxySession(t, state, map[string]string{proxy.EnvRunID: runID},
		[]string{toolsCall(`2`, "refund.issue", sharedArgs), toolsCall(`3`, "orders.search", `{"query":"done"}`)})

	s.fire(golden(t, "subagent_start.json"))
	s.fire(golden(t, "session_end.json"))

	hookRs, _ := spooled(t, filepath.Join(state, DefaultSpoolDirName))
	collect(hookRs)
	collect(proxyReceipts(t, proxySpool))

	seen := map[int]bool{}
	max := -1
	for _, c := range counters {
		if seen[c] {
			t.Fatalf("counter %d was allocated twice across the two surfaces: the flock is not shared", c)
		}
		seen[c] = true
		if c > max {
			max = c
		}
	}
	// Every counter from 0 to the highest must be accounted for. Nothing was
	// suppressed, and nothing was skipped.
	if len(counters) != max+1 {
		missing := []int{}
		for i := 0; i <= max; i++ {
			if !seen[i] {
				missing = append(missing, i)
			}
		}
		t.Fatalf("%d receipts span counters 0..%d with gaps at %v", len(counters), max, missing)
	}
	if len(counters) < 8 {
		t.Fatalf("only %d receipts: the interleaving did not exercise both surfaces", len(counters))
	}
}

// TestLiftedPrimitivesMatchTheProxy closes the drift risk internal/capture
// names in its own package doc. The lifted functions are checked against what
// internal/proxy ACTUALLY wrote, not against a second copy of the same
// arithmetic.
func TestLiftedPrimitivesMatchTheProxy(t *testing.T) {
	state := t.TempDir()
	proxySpool := runProxySession(t, state, map[string]string{proxy.EnvRunID: "run_lift"},
		[]string{
			toolsCall(`1`, "orders.search", `{"query":"acme"}`),
			toolsCall(`2`, "refund.issue", sharedArgs),
		})
	rs := proxyReceipts(t, proxySpool)
	if len(rs) != 2 {
		t.Fatalf("the proxy spooled %d receipts, want 2", len(rs))
	}
	store := cas.New(identity.BlobsDir(state))

	for ordinal, r := range rs {
		params, err := store.Get(slotByRole(t, r.Payload, "input").Digest)
		if err != nil {
			t.Fatal(err)
		}
		// capture.IntentDigest must reproduce the proxy's attempt digest from
		// the tool name and the exact params bytes it forwarded.
		if got := capture.IntentDigest(r.Operation.Name, params); got != r.Attempt.IntentDigest {
			t.Fatalf("capture.IntentDigest drifted from internal/proxy:\n  got  %s\n  want %s", got, r.Attempt.IntentDigest)
		}
		// capture.StepKey must reproduce the proxy's step key from the tool
		// name, the raw arguments bytes and the causal ordinal.
		args, err := jsonspan.ExtractTopLevelValue(params, "arguments")
		if err != nil {
			t.Fatal(err)
		}
		if got := capture.StepKey(r.Operation.Name, args, ordinal); got != r.StepKey {
			t.Fatalf("capture.StepKey drifted from internal/proxy:\n  got  %s\n  want %s", got, r.StepKey)
		}
	}

	// The counter lock file name is the cross-process contract. If the proxy
	// ever renames it, this file exists and the name below is stale.
	if _, err := os.Stat(filepath.Join(state, capture.CounterLockFile)); err != nil {
		t.Fatalf("the proxy did not use %s as its counter lock: %v", capture.CounterLockFile, err)
	}
}

// TestHookPolicySharesTheProxyRulesFirst: an MCP tool name must classify
// identically on both surfaces, or a tool captured twice disagrees with itself
// about its own risk.
func TestHookPolicySharesTheProxyRulesFirst(t *testing.T) {
	var hook, proxied struct {
		Default string `json:"default"`
		Rules   []struct {
			Pattern string `json:"pattern"`
			Class   string `json:"class"`
		} `json:"rules"`
	}
	if err := json.Unmarshal([]byte(DefaultPolicyJSON), &hook); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(proxy.DefaultPolicyJSON), &proxied); err != nil {
		t.Fatal(err)
	}
	if hook.Default != proxied.Default {
		t.Fatalf("default class differs: %q vs %q", hook.Default, proxied.Default)
	}
	if len(hook.Rules) <= len(proxied.Rules) {
		t.Fatal("the hook policy adds no local-tool rules")
	}
	for i, want := range proxied.Rules {
		got := hook.Rules[i]
		if got.Pattern != want.Pattern || got.Class != want.Class {
			t.Fatalf("rule %d diverges: hook %q/%q, proxy %q/%q — first match wins, so the shared rules must come first and unchanged",
				i, got.Pattern, got.Class, want.Pattern, want.Class)
		}
	}
}

// TestCollapsePairsRepeatedCallsInOrder: the same tool called twice with the
// same arguments in one run is a normal thing to do, and the two hook
// observations must land on the two proxy receipts one each rather than piling
// onto whichever came last.
func TestCollapsePairsRepeatedCallsInOrder(t *testing.T) {
	const run = "run_repeat"
	args := []byte(`{"query":"acme"}`)
	digest := argsDigestOf(args)

	// The proxy records the wire name; the hook records the client's sanitised
	// spelling of it. Pairing has to survive that (ENG-33).
	proxyOne := proxyStub(run, "orders.search", digest)
	proxyTwo := proxyStub(run, "orders.search", digest)
	hookOne := hookStub(run, "orders_search", digest)
	hookTwo := hookStub(run, "orders_search", digest)

	crossings := Collapse([]*receipt.Receipt{proxyOne, proxyTwo, hookOne, hookTwo})
	if len(crossings) != 2 {
		t.Fatalf("Collapse produced %d crossings, want 2", len(crossings))
	}
	for i, c := range crossings {
		if len(c.Observations) != 2 {
			t.Fatalf("crossing %d has %d observations, want 2 — one hook observation piled onto the wrong record",
				i, len(c.Observations))
		}
	}
	if crossings[0].Observations[1] != hookOne || crossings[1].Observations[1] != hookTwo {
		t.Fatal("the hook observations paired out of order")
	}
}

func proxyStub(run, name, argsDigest string) *receipt.Receipt {
	return &receipt.Receipt{
		Emitter:   receipt.Emitter{Surface: proxy.Surface},
		RunID:     run,
		Operation: receipt.Operation{Name: name},
		Payload: []receipt.Slot{{
			Role:     "input",
			Manifest: &receipt.Manifest{Fields: []receipt.ManifestField{{Path: ArgumentsPath, Digest: argsDigest}}},
		}},
	}
}

func hookStub(run, name, argsDigest string) *receipt.Receipt {
	return &receipt.Receipt{
		Emitter:   receipt.Emitter{Surface: Surface},
		RunID:     run,
		Operation: receipt.Operation{Name: name},
		Links:     []receipt.Link{{Rel: CrossSurfaceRel, Anchor: &receipt.Anchor{IntentDigest: argsDigest}}},
	}
}

func spooledReceipts(t *testing.T, dir string) []receipt.Receipt {
	t.Helper()
	rs, _ := spooled(t, dir)
	return rs
}

func mustOne(t *testing.T, rs []receipt.Receipt) receipt.Receipt {
	t.Helper()
	if len(rs) != 1 {
		t.Fatalf("got %d receipts, want 1", len(rs))
	}
	return rs[0]
}
