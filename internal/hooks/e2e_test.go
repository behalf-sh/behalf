package hooks

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/behalf-sh/behalf/internal/capture"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// TestEndToEndHookDrainLogExport is the whole Week-3 hook path: a scripted
// Claude Code session, drained into the Tessera log by the SHIPPED drain
// (spool.Drain, unchanged — nothing about this spool is special to it), then
// exported and read back with an independent span scanner the way the Rust
// verifier must.
//
// The claim under test is the span rule: what the export commits to must be
// the exact bytes the emitter signed, and the payload digests must still
// address the exact hook JSON Claude Code wrote.
func TestEndToEndHookDrainLogExport(t *testing.T) {
	const runID = "run_week3_hooks"
	s := newSession(t)
	s.chain = testChainJSON()
	s.env[capture.EnvRunID] = runID

	script := []string{
		"pre_tool_use_bash.json",
		"post_tool_use_bash.json",
		"pre_tool_use_mcp.json",
		"permission_request.json",
		"post_tool_use_mcp.json",
		"pre_tool_use_denied.json",
		"permission_denied.json",
		"subagent_start.json",
		"subagent_stop.json",
		"session_end.json",
	}
	for _, name := range script {
		s.fire(golden(t, name))
	}
	// 2 tool_call + 1 approval + 1 denial + 2 delegation + 1 session_end.
	const wantLeaves = 7

	// The shipped `behalf-log drain` runs the PROXY's orphan recovery over
	// whatever spool it is pointed at, before it drains. Over the hook spool
	// that must mint nothing: hook intents live in the pending store, not
	// here, precisely so this cannot produce mcp-proxy-surface receipts for
	// crossings the proxy never saw.
	flushed, err := proxy.RecoverOrphans(proxy.Config{StateDir: s.stateDir, SpoolDir: s.spoolDir()})
	if err != nil {
		t.Fatalf("the shipped drain's recovery pass failed over the hook spool: %v", err)
	}
	if flushed != 0 {
		t.Fatalf("the proxy's recovery minted %d receipts from the hook spool", flushed)
	}

	logDir := t.TempDir()
	ctx := context.Background()
	key, err := tlog.GenerateCheckpointKey("behalf.sh/log/week3-hooks-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.SaveCheckpointKey(logDir, key); err != nil {
		t.Fatal(err)
	}
	l, err := tlog.Open(ctx, logDir, key, tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	emitter, err := identity.LoadKey(identity.EmitterKeyPath(s.stateDir))
	if err != nil {
		t.Fatal(err)
	}
	jwkJSON, err := json.Marshal(emitter.JWK)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterKey(emitter.JKT, string(jwkJSON)); err != nil {
		t.Fatal(err)
	}

	appended := 0
	if _, err := spool.Drain(s.spoolDir(), func(c spool.Completion) error {
		res, aerr := l.Append(ctx, c.Envelope)
		if aerr != nil {
			return aerr
		}
		if res.Duplicate {
			return errors.New("unexpected duplicate on a first drain")
		}
		appended++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if appended != wantLeaves {
		t.Fatalf("drained %d receipts, want %d", appended, wantLeaves)
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// A second drain re-delivers nothing.
	replayed := 0
	if _, err := spool.Drain(s.spoolDir(), func(spool.Completion) error { replayed++; return nil }); err != nil {
		t.Fatal(err)
	}
	if replayed != 0 {
		t.Fatalf("a second drain re-delivered %d receipts", replayed)
	}

	out := filepath.Join(t.TempDir(), "hooks.jsonl")
	f, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.ExportRun(ctx, logDir, runID, f); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	exported, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}

	leaves := exportLeaves(t, exported)
	if len(leaves) != wantLeaves {
		t.Fatalf("the export carries %d leaves, want %d", len(leaves), wantLeaves)
	}
	store := cas.New(identity.BlobsDir(s.stateDir))
	kinds := map[string]int{}
	for i, leaf := range leaves {
		// The emitter's original signature still verifies over the exported
		// span: nothing between capture and export re-serialized it.
		if !dsse.Verify(emitter.Public, exportv1.PayloadTypeReceipt, leaf.payload, leaf.sig) {
			t.Fatalf("leaf %d: the emitter signature does not verify over the exported payload span", i)
		}
		schemaValidate(t, leaf.payload)
		var r receipt.Receipt
		if err := json.Unmarshal(leaf.payload, &r); err != nil {
			t.Fatal(err)
		}
		kinds[r.Kind]++
		if r.RunID != runID || r.RunIDProvenance != capture.ProvenanceCaller {
			t.Fatalf("leaf %d: run grouping = %q/%q", i, r.RunID, r.RunIDProvenance)
		}
		if r.Emitter.Surface != Surface {
			t.Fatalf("leaf %d: surface = %q", i, r.Emitter.Surface)
		}
		// The raw hook frame the receipt references is still addressable and
		// still hashes to its name.
		if _, err := store.Get(r.RawFrameRef); err != nil {
			t.Fatalf("leaf %d: raw hook frame: %v", i, err)
		}
	}
	want := map[string]int{KindToolCall: 2, KindApproval: 1, KindDenial: 1, KindDelegation: 2, KindAction: 1}
	for kind, n := range want {
		if kinds[kind] != n {
			t.Fatalf("exported kinds %v, want %v", kinds, want)
		}
	}

	// The refund the demo turns on is in the record, and the export commits to
	// the exact hook JSON that carried it.
	if !bytes.Contains(exported, []byte(`"refund.issue"`)) {
		t.Fatal("the export carries no refund.issue receipt")
	}

	verifyWithShippedVerifier(t, out)
}

// verifyWithShippedVerifier runs the Rust verifier over the export when it is
// built. The Go suite must stay runnable without a Rust toolchain, so a
// missing binary skips this half loudly rather than failing; `make ci` builds
// it, and the tamper suite exercises the same path.
func verifyWithShippedVerifier(t *testing.T, exportPath string) {
	t.Helper()
	bin := os.Getenv("BEHALF_VERIFY")
	if bin == "" {
		bin = filepath.Join("..", "..", "verifier", "target", "release", "behalf-verify")
	}
	if _, err := os.Stat(bin); err != nil {
		t.Logf("skipping the shipped verifier: %s is not built (cargo build --release in verifier/)", bin)
		return
	}
	cmd := exec.Command(bin, exportPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the shipped verifier rejected an intact hook export: %v\n%s", err, out)
	}
	t.Logf("shipped verifier: %s", bytes.TrimSpace(out))
}

// exportLeaf is one leaf line read back out of an export file.
type exportLeaf struct {
	payload []byte
	sig     []byte
}

// exportLeaves reads the export with a scanner that walks JSON syntax rather
// than parsing and re-serializing, which is the contract the offline verifier
// works under (export-format-v1.md §1.2).
func exportLeaves(t *testing.T, file []byte) []exportLeaf {
	t.Helper()
	var out []exportLeaf
	for _, line := range bytes.Split(file, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		kindRaw, err := jsonspan.ExtractTopLevelValue(line, "kind")
		if err != nil {
			t.Fatalf("export line has no kind: %s", line)
		}
		if string(kindRaw) != `"leaf"` {
			continue
		}
		payload, err := jsonspan.ExtractTopLevelValue(line, "payload")
		if err != nil {
			t.Fatal(err)
		}
		sigRaw, err := jsonspan.ExtractTopLevelValue(line, "sig")
		if err != nil {
			t.Fatal(err)
		}
		var sig struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}
		if err := json.Unmarshal(sigRaw, &sig); err != nil {
			t.Fatal(err)
		}
		raw, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, exportLeaf{payload: payload, sig: raw})
	}
	return out
}
