package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// TestEndToEndProxyDrainLogExport is the whole Week-3 path: a scripted
// five-call session through the proxy, drained into the Tessera log, then
// exported — and the payload the export commits to must still be the exact
// bytes the real MCP server saw. Every hop in between (spool, envelope,
// log entry bundle, export leaf) has to preserve the span or this fails.
func TestEndToEndProxyDrainLogExport(t *testing.T) {
	state := t.TempDir()
	logDir := t.TempDir()

	// A five-call refund scenario — the shape ENG-14's demo recording drives.
	script := []string{
		initializeLine(`1`),
		initializedLine(),
		toolsListLine(`2`),
		toolsCallLine(`3`, "orders.search", `{"query":"acme refund"}`),
		toolsCallLine(`4`, "orders.search", `{"query":"ord_5518"}`),
		toolsCallLine(`5`, "refund.issue", `{"order_id":"ord_5518","amount":"1200.00"}`),
		toolsCallLine(`6`, "orders.search", `{"query":"ord_5518 status"}`),
		toolsCallLine(`7`, "refund.issue", `{"order_id":"ord_5512","amount":"12.00"}`),
	}
	res := runSession(t, sessionOpts{
		stateDir: state,
		lines:    script,
		chain:    testChainJSON(),
		env:      map[string]string{EnvRunID: "run_week3_demo"},
	})
	if res.err != nil {
		t.Fatalf("proxy: %v (stderr %s)", res.err, res.stderr)
	}

	// What the server actually saw, per tools/call, in order.
	var sawParams [][]byte
	for _, line := range splitLines(res.inWitness) {
		if methodOf(line) != MethodToolsCall {
			continue
		}
		span, err := indieExtract(bytes.TrimRight(line, "\n"), "params")
		if err != nil {
			t.Fatalf("scan witness line: %v", err)
		}
		sawParams = append(sawParams, append([]byte(nil), span...))
	}
	if len(sawParams) != 5 {
		t.Fatalf("the server saw %d tools/call, want 5", len(sawParams))
	}

	// Drain the spool into the log — the proxy never appends itself (Q57).
	ctx := context.Background()
	key, err := tlog.GenerateCheckpointKey("behalf.sh/log/week3-test")
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
	emitter, err := identity.LoadKey(identity.EmitterKeyPath(state))
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
	stats, err := spool.Drain(res.spoolDir, func(c spool.Completion) error {
		r, aerr := l.Append(ctx, c.Envelope)
		if aerr != nil {
			return aerr
		}
		if r.Duplicate {
			return errors.New("unexpected duplicate on a first drain")
		}
		appended++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if appended != 5 {
		t.Fatalf("drained %d receipts, want 5 (%+v)", appended, stats)
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// Draining again is a no-op, and even a forced replay of the same
	// envelopes dedups on receipt_id rather than double-appending (Q46).
	replayed := 0
	if _, err := spool.Drain(res.spoolDir, func(spool.Completion) error {
		replayed++
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if replayed != 0 {
		t.Fatalf("a second drain re-delivered %d receipts", replayed)
	}

	// Export the run and read it with an INDEPENDENT span scanner, the way
	// the Rust verifier must (export-format-v1.md §1.2).
	var exported bytes.Buffer
	if err := tlog.ExportRun(ctx, logDir, "run_week3_demo", &exported); err != nil {
		t.Fatal(err)
	}
	leaves := exportLeaves(t, exported.Bytes())
	if len(leaves) != 5 {
		t.Fatalf("export carries %d leaves, want 5", len(leaves))
	}

	store := cas.New(identity.BlobsDir(state))
	for i, leaf := range leaves {
		// The emitter's original signature still verifies over the exported
		// span: nothing between capture and export re-serialized it.
		if !dsse.Verify(emitter.Public, exportv1.PayloadTypeReceipt, leaf.payload, leaf.sig) {
			t.Fatalf("leaf %d: emitter signature does not verify over the exported payload span", i)
		}
		var r receipt.Receipt
		if err := json.Unmarshal(leaf.payload, &r); err != nil {
			t.Fatal(err)
		}
		schemaValidate(t, leaf.payload)
		if r.Kind != KindToolCall || r.RunID != "run_week3_demo" || r.RunIDProvenance != ProvenanceCaller {
			t.Fatalf("leaf %d: kind=%q run=%q provenance=%q", i, r.Kind, r.RunID, r.RunIDProvenance)
		}
		if r.Emitter.Counter != i {
			t.Fatalf("leaf %d carries counter %d: log order and capture order disagree", i, r.Emitter.Counter)
		}

		input := slotByRole(t, r.Payload, "input")
		blob, err := store.Get(input.Digest)
		if err != nil {
			t.Fatalf("leaf %d: input blob: %v", i, err)
		}
		if !bytes.Equal(blob, sawParams[i]) {
			t.Fatalf("leaf %d: the exported receipt commits to params the server never saw:\n  server %s\n  blob   %s", i, sawParams[i], blob)
		}
		if input.Digest != cas.Digest(sawParams[i]) {
			t.Fatalf("leaf %d: payload digest does not commit to the bytes the server saw", i)
		}
	}

	// The refund the demo turns on is in the record, with its amount intact.
	if !bytes.Contains(exported.Bytes(), []byte(`"refund.issue"`)) {
		t.Fatal("the export carries no refund.issue receipt")
	}
	refundBlob := findBlobContaining(t, store, leaves, `"amount":"1200.00"`)
	if refundBlob == "" {
		t.Fatal("no payload blob carries the 1200.00 refund the cover-up demo edits")
	}
}

// exportLeaf is one leaf line read back out of an export file.
type exportLeaf struct {
	payload []byte
	sig     []byte
}

func exportLeaves(t *testing.T, file []byte) []exportLeaf {
	t.Helper()
	var out []exportLeaf
	for _, line := range splitLines(file) {
		line = bytes.TrimRight(line, "\n")
		if len(line) == 0 {
			continue
		}
		kindRaw, err := indieExtract(line, "kind")
		if err != nil {
			t.Fatalf("export line has no kind: %s", line)
		}
		if string(kindRaw) != `"leaf"` {
			continue
		}
		payload, err := indieExtract(line, "payload")
		if err != nil {
			t.Fatal(err)
		}
		sigRaw, err := indieExtract(line, "sig")
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

func findBlobContaining(t *testing.T, store *cas.Store, leaves []exportLeaf, needle string) string {
	t.Helper()
	for _, leaf := range leaves {
		var r receipt.Receipt
		if err := json.Unmarshal(leaf.payload, &r); err != nil {
			t.Fatal(err)
		}
		for _, slot := range r.Payload {
			blob, err := store.Get(slot.Digest)
			if err != nil {
				continue
			}
			if bytes.Contains(blob, []byte(needle)) {
				return slot.Digest
			}
		}
	}
	return ""
}

// Below is an INDEPENDENT span scanner, deliberately not sharing code with
// internal/jsonspan: the writer builds lines by concatenation, and this
// re-derives the value span from the raw bytes by walking JSON syntax, per
// the verifier contract ("a scanner that respects JSON strings and escapes
// — it MUST NOT parse-and-reserialize"). internal/exportv1's tests carry
// the same scanner for the same reason.

func indieExtract(line []byte, key string) ([]byte, error) {
	if len(line) == 0 || line[0] != '{' {
		return nil, errors.New("line is not a JSON object")
	}
	i := 1
	for i < len(line) {
		if line[i] == '}' {
			break
		}
		k, next, err := indieString(line, i)
		if err != nil {
			return nil, fmt.Errorf("key at %d: %w", i, err)
		}
		if next >= len(line) || line[next] != ':' {
			return nil, fmt.Errorf("expected ':' at %d", next)
		}
		start := next + 1
		end, err := indieValue(line, start)
		if err != nil {
			return nil, fmt.Errorf("value of %q: %w", k, err)
		}
		if string(k) == key {
			return line[start:end], nil
		}
		i = end
		if i < len(line) && line[i] == ',' {
			i++
			continue
		}
	}
	return nil, fmt.Errorf("key %q not found", key)
}

func indieString(line []byte, i int) ([]byte, int, error) {
	if i >= len(line) || line[i] != '"' {
		return nil, 0, fmt.Errorf("expected '\"' at %d", i)
	}
	j := i + 1
	for j < len(line) {
		switch line[j] {
		case '\\':
			j += 2
		case '"':
			return line[i+1 : j], j + 1, nil
		default:
			j++
		}
	}
	return nil, 0, errors.New("unterminated string")
}

func indieValue(line []byte, i int) (int, error) {
	if i >= len(line) {
		return 0, errors.New("unexpected end of line")
	}
	switch line[i] {
	case '"':
		_, end, err := indieString(line, i)
		return end, err
	case '{', '[':
		depth := 0
		j := i
		for j < len(line) {
			switch line[j] {
			case '"':
				_, next, err := indieString(line, j)
				if err != nil {
					return 0, err
				}
				j = next
			case '{', '[':
				depth++
				j++
			case '}', ']':
				depth--
				j++
				if depth == 0 {
					return j, nil
				}
			default:
				j++
			}
		}
		return 0, errors.New("unbalanced brackets")
	default:
		j := i
		for j < len(line) {
			switch line[j] {
			case ',', '}', ']':
				return j, nil
			default:
				j++
			}
		}
		return 0, errors.New("unterminated scalar")
	}
}
