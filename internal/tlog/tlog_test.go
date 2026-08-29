package tlog

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/transparency-dev/tessera/api/layout"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// openTestLog creates a fresh log dir with a generated checkpoint key and
// opens it with the production defaults (1 s checkpoint, 250 ms batch).
func openTestLog(t *testing.T, dir string) (*Log, *CheckpointKey) {
	t.Helper()
	key, err := LoadCheckpointKey(dir)
	if err != nil {
		key, err = GenerateCheckpointKey("behalf.sh/log/test")
		if err != nil {
			t.Fatal(err)
		}
		if err := SaveCheckpointKey(dir, key); err != nil {
			t.Fatal(err)
		}
	}
	l, err := Open(context.Background(), dir, key, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return l, key
}

// fixtureEnvelopes generates the run's sealed payloads and wraps each in a
// stored envelope signed by the fixture emitter key.
func fixtureEnvelopes(t *testing.T, spec fixture.Spec) (envs [][]byte, payloads [][]byte) {
	t.Helper()
	res, err := fixture.Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	emitter := testkeys.Emitter()
	for _, payload := range res.Payloads {
		sig := dsse.Sign(emitter.Private, exportv1.PayloadTypeReceipt, payload)
		envs = append(envs, BuildEnvelope(exportv1.PayloadTypeReceipt, payload, emitter.JKT, sig))
	}
	return envs, res.Payloads
}

func registerEmitter(t *testing.T, l *Log) {
	t.Helper()
	emitter := testkeys.Emitter()
	jwk, err := json.Marshal(emitter.JWK)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterKey(emitter.JKT, string(jwk)); err != nil {
		t.Fatal(err)
	}
}

// TestAppendAckDurable: a resolved Append means the entry bundle and tile
// files are already on disk and the tree has advanced (Q75: on the POSIX
// driver, durable commit includes integration).
func TestAppendAckDurable(t *testing.T) {
	dir := t.TempDir()
	l, _ := openTestLog(t, dir)
	defer l.Close(context.Background())

	envs, _ := fixtureEnvelopes(t, fixture.Run9F2A())
	res, err := l.Append(context.Background(), envs[0])
	if err != nil {
		t.Fatal(err)
	}
	if res.Index != 0 || res.Duplicate {
		t.Fatalf("first append: %+v", res)
	}
	if res.Promise == nil {
		t.Fatal("append ack carried no promise")
	}

	// The ack has returned: the tree state must already reflect the entry...
	size, err := l.TreeSize(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if size != 1 {
		t.Fatalf("tree size after ack = %d, want 1", size)
	}

	// ...and the entry bundle and tile files must already exist on disk.
	bundlePath := filepath.Join(dir, layout.EntriesPath(0, 1))
	raw, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("entry bundle not on disk after ack: %v", err)
	}
	// Bundle framing per tlog-tiles: 2-byte big-endian length + data.
	if len(raw) < 2 {
		t.Fatalf("bundle too short: %d bytes", len(raw))
	}
	n := binary.BigEndian.Uint16(raw[:2])
	if int(n) != len(envs[0]) || !bytes.Equal(raw[2:2+n], envs[0]) {
		t.Fatal("entry bundle does not contain the exact envelope bytes")
	}
	tilePath := filepath.Join(dir, layout.TilePath(0, 0, 1))
	if _, err := os.Stat(tilePath); err != nil {
		t.Fatalf("level-0 tile not on disk after ack: %v", err)
	}

	// The promise must verify under the checkpoint key and name this leaf.
	p, err := VerifyPromise(l.Key().Public, res.Promise)
	if err != nil {
		t.Fatal(err)
	}
	if p.LeafHash != fmtHex(res.LeafHash[:]) {
		t.Fatalf("promise leaf_hash %s != ack leaf hash %s", p.LeafHash, fmtHex(res.LeafHash[:]))
	}
	if p.MMDSec != PromiseMMDSeconds {
		t.Fatalf("promise mmd_s = %d", p.MMDSec)
	}
}

func fmtHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 0, len(b)*2)
	for _, c := range b {
		out = append(out, hexdigits[c>>4], hexdigits[c&0xf])
	}
	return string(out)
}

// TestDedup: a duplicate receipt_id returns the original index, flagged,
// and is never appended twice — including across process restarts (the
// window is persistent, Q46).
func TestDedup(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	l, _ := openTestLog(t, dir)

	envs, _ := fixtureEnvelopes(t, fixture.Run9F2A())
	first, err := l.Append(ctx, envs[0])
	if err != nil {
		t.Fatal(err)
	}
	dup, err := l.Append(ctx, envs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !dup.Duplicate {
		t.Fatal("second append of same receipt_id not flagged duplicate")
	}
	if dup.Index != first.Index || dup.LeafHash != first.LeafHash {
		t.Fatalf("duplicate returned %d/%x, original %d/%x", dup.Index, dup.LeafHash, first.Index, first.LeafHash)
	}
	if size, _ := l.TreeSize(ctx); size != 1 {
		t.Fatalf("tree size after duplicate = %d, want 1 (appended twice?)", size)
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}

	// Reopen: the dedup window survives restart.
	l2, _ := openTestLog(t, dir)
	defer l2.Close(ctx)
	dup2, err := l2.Append(ctx, envs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !dup2.Duplicate || dup2.Index != first.Index {
		t.Fatalf("post-restart duplicate: %+v", dup2)
	}
	if size, _ := l2.TreeSize(ctx); size != 1 {
		t.Fatalf("tree size after restart duplicate = %d, want 1", size)
	}
}

// TestCheckpointPublishes: a signed checkpoint covering an append appears
// within ~2 s (1 s interval plus slack); it verifies under the log's note
// verifier key.
func TestCheckpointPublishes(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	l, key := openTestLog(t, dir)
	defer l.Close(ctx)

	envs, _ := fixtureEnvelopes(t, fixture.Run9F2A())
	if _, err := l.Append(ctx, envs[0]); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for {
		cp, err := ParseLogCheckpoint(ctx, dir)
		if err == nil && cp.Size >= 1 {
			if cp.Origin != key.Origin {
				t.Fatalf("checkpoint origin %q, want %q", cp.Origin, key.Origin)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no checkpoint covering the append within deadline (last: cp=%+v err=%v)", cp, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestEpochFencing: once a newer epoch is recorded, the stale holder is
// refused (Q57: the epoch file fences superseded appenders; only the
// current lock-holder signs promises).
func TestEpochFencing(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	l, _ := openTestLog(t, dir)
	defer l.Close(ctx)

	envs, _ := fixtureEnvelopes(t, fixture.Run9F2A())
	if _, err := l.Append(ctx, envs[0]); err != nil {
		t.Fatal(err)
	}

	// A newer claimant appears.
	newer := EpochRecord{Epoch: l.Epoch().Epoch + 1, PID: os.Getpid(), StartedAt: time.Now().UTC().Format(time.RFC3339)}
	if err := writeEpoch(dir, newer); err != nil {
		t.Fatal(err)
	}

	if _, err := l.Append(ctx, envs[1]); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale-epoch append: err = %v, want ErrFenced", err)
	}
	// Duplicates are refused too: a fenced holder must not sign promises.
	if _, err := l.Append(ctx, envs[0]); !errors.Is(err, ErrFenced) {
		t.Fatalf("stale-epoch duplicate append: err = %v, want ErrFenced", err)
	}
}

// TestExportFromLog ingests both fixture runs into the ONE log and derives
// a Week-1 export for run_c71e from the stored envelope bytes. Every leaf
// payload span must byte-match the fixture original (the span rule via the
// span scanner), the chain must recompute, and the head must verify under
// the checkpoint key.
func TestExportFromLog(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	l, key := openTestLog(t, dir)
	registerEmitter(t, l)

	specs := []fixture.Spec{fixture.Run9F2A(), fixture.RunC71E()}
	payloadsByRun := map[string][][]byte{}
	var pendings []*Pending
	for _, spec := range specs {
		envs, payloads := fixtureEnvelopes(t, spec)
		payloadsByRun[spec.RunID] = payloads
		for i, env := range envs {
			p, err := l.BeginAppend(ctx, env)
			if err != nil {
				t.Fatalf("%s %d: %v", spec.RunID, i, err)
			}
			pendings = append(pendings, p)
		}
	}
	for i, p := range pendings {
		res, err := p.Wait(ctx)
		if err != nil {
			t.Fatalf("pending %d: %v", i, err)
		}
		if res.Duplicate {
			t.Fatalf("pending %d unexpectedly duplicate", i)
		}
		if res.Index != uint64(i) {
			t.Fatalf("pending %d assigned index %d: sequential BeginAppend must preserve order", i, res.Index)
		}
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := ExportRun(ctx, dir, "run_c71e", &buf); err != nil {
		t.Fatal(err)
	}
	verifyExport(t, buf.Bytes(), key, payloadsByRun["run_c71e"])

	// The other run exports from the same log too.
	var buf2 bytes.Buffer
	if err := ExportRun(ctx, dir, "run_9f2a", &buf2); err != nil {
		t.Fatal(err)
	}
	verifyExport(t, buf2.Bytes(), key, payloadsByRun["run_9f2a"])
}

// verifyExport is the Go mirror of the Rust verifier's checks for a
// log-derived export, using the span scanner throughout (never
// parse-and-reserialize): span byte-equality against the fixture originals,
// leaf hash and signature per leaf, chain recomputation, and the head
// signature under the checkpoint key.
func verifyExport(t *testing.T, export []byte, key *CheckpointKey, wantPayloads [][]byte) {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(export, []byte("\n")), []byte("\n"))
	if len(lines) != len(wantPayloads)+2 {
		t.Fatalf("export has %d lines, want %d", len(lines), len(wantPayloads)+2)
	}

	var hdr struct {
		Kind      string `json:"kind"`
		Format    string `json:"format"`
		LogOrigin string `json:"log_origin"`
		Keys      []struct {
			JKT string   `json:"jkt"`
			JWK dsse.JWK `json:"jwk"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(lines[0], &hdr); err != nil {
		t.Fatal(err)
	}
	if hdr.Kind != "header" || hdr.Format != exportv1.Format {
		t.Fatalf("bad header: %+v", hdr)
	}
	if hdr.LogOrigin != key.Origin {
		t.Fatalf("export log_origin %q, want the log origin %q", hdr.LogOrigin, key.Origin)
	}
	pubs := map[string][]byte{}
	for _, k := range hdr.Keys {
		if k.JWK.Thumbprint() != k.JKT {
			t.Fatalf("header jkt %s does not match jwk thumbprint", k.JKT)
		}
		raw, err := base64.RawURLEncoding.DecodeString(k.JWK.X)
		if err != nil || len(raw) != 32 {
			t.Fatalf("bad jwk x for %s", k.JKT)
		}
		pubs[k.JKT] = raw
	}
	if _, ok := pubs[key.JKT]; !ok {
		t.Fatal("checkpoint key missing from export header")
	}
	if _, ok := pubs[testkeys.Emitter().JKT]; !ok {
		t.Fatal("emitter key missing from export header")
	}

	chain := exportv1.ChainStart(hdr.LogOrigin)
	for i, want := range wantPayloads {
		line := lines[i+1]
		span, err := jsonspan.ExtractTopLevelValue(line, "payload")
		if err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
		if !bytes.Equal(span, want) {
			t.Fatalf("leaf %d: exported payload span differs from the fixture original", i)
		}
		var sig struct {
			KeyID string `json:"keyid"`
			Sig   string `json:"sig"`
		}
		sigRaw, err := jsonspan.ExtractTopLevelValue(line, "sig")
		if err != nil {
			t.Fatalf("leaf %d sig: %v", i, err)
		}
		if err := json.Unmarshal(sigRaw, &sig); err != nil {
			t.Fatalf("leaf %d sig: %v", i, err)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
		if err != nil {
			t.Fatalf("leaf %d sig b64: %v", i, err)
		}
		pub, ok := pubs[sig.KeyID]
		if !ok {
			t.Fatalf("leaf %d keyid %s not in header", i, sig.KeyID)
		}
		if !dsse.Verify(pub, exportv1.PayloadTypeReceipt, span, sigBytes) {
			t.Fatalf("leaf %d: signature does not verify over the exported span", i)
		}
		chain = exportv1.ChainNext(chain, dsse.LeafHash(exportv1.PayloadTypeReceipt, span))
	}

	headLine := lines[len(lines)-1]
	headSpan, err := jsonspan.ExtractTopLevelValue(headLine, "head")
	if err != nil {
		t.Fatal(err)
	}
	var head struct {
		Format    string `json:"format"`
		LogOrigin string `json:"log_origin"`
		Count     int    `json:"count"`
		Chain     string `json:"chain"`
	}
	if err := json.Unmarshal(headSpan, &head); err != nil {
		t.Fatal(err)
	}
	if head.Format != exportv1.Format || head.LogOrigin != hdr.LogOrigin || head.Count != len(wantPayloads) {
		t.Fatalf("bad head: %+v", head)
	}
	if head.Chain != fmtHex(chain[:]) {
		t.Fatalf("head.chain = %s, recomputed %s", head.Chain, fmtHex(chain[:]))
	}
	var hsig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	hsigRaw, err := jsonspan.ExtractTopLevelValue(headLine, "sig")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(hsigRaw, &hsig); err != nil {
		t.Fatal(err)
	}
	if hsig.KeyID != key.JKT {
		t.Fatalf("head signed by %s, want the checkpoint key %s", hsig.KeyID, key.JKT)
	}
	hsigBytes, err := base64.StdEncoding.DecodeString(hsig.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !dsse.Verify(key.Public, exportv1.PayloadTypeChainHead, headSpan, hsigBytes) {
		t.Fatal("head signature does not verify under the checkpoint key")
	}
}
