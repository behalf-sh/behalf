package tlog

import (
	"context"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"

	"github.com/behalf-sh/behalf/internal/witness"
)

// testWitness starts a real witness (real key, real durable state, real
// HTTP surface) trusting the given log verifier keys, and returns it with
// the policy a log needs to submit to it.
func testWitness(t *testing.T, logVKeys ...string) (*witness.Witness, *httptest.Server, *WitnessPolicy) {
	t.Helper()
	key, err := witness.GenerateKey("test.witness/tlog")
	if err != nil {
		t.Fatal(err)
	}
	store, err := witness.OpenStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	w, err := witness.New(key, store, logVKeys)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(witness.NewServer(w, nil).Handler())
	t.Cleanup(srv.Close)
	return w, srv, &WitnessPolicy{
		TimeoutMS: 5000,
		Witnesses: []witness.Ref{{Name: "w1", VKey: key.VKey, URL: srv.URL}},
	}
}

// appendN appends n distinct envelopes and waits for their durability acks.
func appendN(t *testing.T, l *Log, spec specFn, from, n int) {
	t.Helper()
	ctx := context.Background()
	for i := from; i < from+n; i++ {
		if _, err := l.Append(ctx, spec(i)); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}
}

type specFn func(i int) []byte

// distinctEnvelopes builds envelopes that differ per index and per tag, so
// two logs with the same key and the same length have different roots.
func distinctEnvelopes(tag string) specFn {
	return func(i int) []byte {
		payload := fmt.Appendf(nil,
			`{"schema_version":"behalf.sh/receipt/v1","receipt_id":"%s-%08d","run_id":"%s","kind":"tool_call","captured_at":"2026-08-27T00:00:00Z"}`,
			tag, i, tag)
		return BuildEnvelope("application/vnd.behalf.receipt+json", payload, "test-jkt", make([]byte, 64))
	}
}

// Consistency proofs read out of the log's own tiles, which is what the
// witness verifies against (Q29/Q76).
func TestConsistencyProofFromTiles(t *testing.T) {
	dir := t.TempDir()
	l, key := openTestLog(t, dir)
	ctx := context.Background()
	appendN(t, l, distinctEnvelopes("a"), 0, 40)
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
	_ = key

	cp, err := ParseLogCheckpoint(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if cp.Size != 40 {
		t.Fatalf("tree size = %d, want 40", cp.Size)
	}
	// Every prefix root must be carried forward to the published root by a
	// proof built from the stored tiles.
	for _, from := range []uint64{1, 2, 3, 7, 8, 16, 31, 39} {
		pf, err := ConsistencyProof(ctx, dir, from, cp.Size)
		if err != nil {
			t.Fatalf("proof %d->%d: %v", from, cp.Size, err)
		}
		fromRoot := prefixRoot(t, ctx, dir, from)
		if err := VerifyConsistency(from, cp.Size, pf, fromRoot, cp.Root); err != nil {
			t.Fatalf("proof %d->%d does not verify: %v", from, cp.Size, err)
		}
		// The same proof against a wrong prefix root must fail: the proof is
		// doing work, not being ignored.
		wrong := append([]byte{}, fromRoot...)
		wrong[0] ^= 0xff
		if err := VerifyConsistency(from, cp.Size, pf, wrong, cp.Root); err == nil {
			t.Fatalf("proof %d->%d verified against a wrong root", from, cp.Size)
		}
	}
	if _, err := ConsistencyProof(ctx, dir, 41, 40); err == nil {
		t.Fatal("a backwards proof request must be refused")
	}
}

// prefixRoot recomputes the root of the first n leaves from the log dir.
func prefixRoot(t *testing.T, ctx context.Context, dir string, n uint64) []byte {
	t.Helper()
	// A consistency proof from n to n is empty and self-verifying, so the
	// prefix root has to come from somewhere else: rebuild it from the
	// inclusion proof of leaf n-1 in a tree of size n.
	r, err := NewBundleReader(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	env, err := r.Envelope(ctx, n-1)
	if err != nil {
		t.Fatal(err)
	}
	pf, err := InclusionProof(ctx, dir, n-1, n)
	if err != nil {
		t.Fatal(err)
	}
	leaf := rfc6962.DefaultHasher.HashLeaf(env)
	root, err := proof.RootFromInclusionProof(rfc6962.DefaultHasher, n-1, n, leaf, pf)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyInclusion(n-1, n, leaf, pf, root); err != nil {
		t.Fatal(err)
	}
	return root
}

// The happy path, end to end through the log: growth is cosigned, the
// outcome is recorded per checkpoint, and the cosignature is persisted
// beside the checkpoint so an export can carry it.
func TestWitnessCosignsAndRecordsOutcome(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateCheckpointKey("behalf.sh/log/witnessed")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCheckpointKey(dir, key); err != nil {
		t.Fatal(err)
	}
	w, srv, policy := testWitness(t, key.VKey)
	ctx := context.Background()

	l, err := Open(ctx, dir, key, Options{Witness: policy, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, distinctEnvelopes("a"), 0, 12)
	// The explicit programmatic pass, on an open handle.
	if rec, err := l.WitnessCheckpoint(ctx); err != nil {
		t.Fatalf("WitnessCheckpoint: %v", err)
	} else if rec.Outcome != "cosigned" {
		t.Fatalf("WitnessCheckpoint outcome = %q: %+v", rec.Outcome, rec)
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}

	recs, err := ReadWitnessRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("no per-checkpoint witness record was written")
	}
	last := recs[len(recs)-1]
	if last.Outcome != "cosigned" || last.Cosigned != 1 {
		t.Fatalf("last record = %+v; want cosigned", last)
	}
	if !last.FailOpen || last.TimeoutMS != 5000 || last.Quorum != 1 {
		t.Fatalf("the record must be self-describing about the policy: %+v", last)
	}
	if len(last.Cosignatures()) != 1 {
		t.Fatalf("the cosignature must be persisted with the record: %+v", last.Witnesses)
	}

	// The witness holds the head it cosigned.
	held, ok := w.Held(key.Origin)
	if !ok || held.Size != last.Size {
		t.Fatalf("witness holds %+v (%v); the log published size %d", held, ok, last.Size)
	}

	// checkpoint.witnessed is the published checkpoint plus the
	// cosignature: it must still verify under the log key alone (the extra
	// line is grease to anyone who does not know the witness), and under
	// the witness key.
	raw, err := os.ReadFile(WitnessedCheckpointPath(dir))
	if err != nil {
		t.Fatalf("checkpoint.witnessed: %v", err)
	}
	logVerifier, err := key.NoteVerifier()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(raw, note.VerifierList(logVerifier)); err != nil {
		t.Fatalf("checkpoint.witnessed does not verify under the log key: %v", err)
	}
	n, err := note.Open(raw, note.VerifierList(w.Key().Verifier()))
	if err != nil {
		t.Fatalf("checkpoint.witnessed does not carry a verifiable cosignature: %v", err)
	}
	if len(n.Sigs) != 1 {
		t.Fatalf("want exactly one witness signature, got %d", len(n.Sigs))
	}
}

// Fail-open (Q96): an unreachable witness never blocks publication, and the
// gap is recorded with a reason rather than silently skipped.
func TestWitnessFailOpenWhenUnreachable(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateCheckpointKey("behalf.sh/log/failopen")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCheckpointKey(dir, key); err != nil {
		t.Fatal(err)
	}
	// A witness key that is well-formed but points at a closed port.
	wkey, err := witness.GenerateKey("test.witness/dead")
	if err != nil {
		t.Fatal(err)
	}
	dead := httptest.NewServer(nil)
	deadURL := dead.URL
	dead.Close() // nothing is listening now

	policy := &WitnessPolicy{
		TimeoutMS: 500,
		Witnesses: []witness.Ref{{Name: "dead", VKey: wkey.VKey, URL: deadURL}},
	}
	ctx := context.Background()
	start := time.Now()
	l, err := Open(ctx, dir, key, Options{Witness: policy})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, distinctEnvelopes("a"), 0, 5)
	if err := l.Close(ctx); err != nil {
		t.Fatalf("a dead witness must not fail Close under fail-open: %v", err)
	}

	// Publication happened.
	cp, err := ParseLogCheckpoint(ctx, dir)
	if err != nil {
		t.Fatalf("the checkpoint must publish regardless of the witness: %v", err)
	}
	if cp.Size != 5 {
		t.Fatalf("published tree size = %d, want 5", cp.Size)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("witnessing blocked the write path for %v", elapsed)
	}

	recs, err := ReadWitnessRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("a failed witnessing pass must still be recorded")
	}
	last := recs[len(recs)-1]
	if last.Outcome != "not-cosigned" {
		t.Fatalf("outcome = %q, want not-cosigned: %+v", last.Outcome, last)
	}
	if !last.FailOpen {
		t.Fatalf("the record must say it published under fail-open: %+v", last)
	}
	if last.Detail == "" || last.Witnesses[0].Outcome != witness.OutcomeUnreachable ||
		last.Witnesses[0].Detail == "" {
		t.Fatalf("the record must carry the reason: %+v", last)
	}
	// No cosignature, so no cosigned checkpoint file.
	if _, err := os.Stat(WitnessedCheckpointPath(dir)); err == nil {
		t.Fatal("checkpoint.witnessed must not exist without a cosignature")
	}
}

// A fork submitted to a witness that already holds the real history is
// recorded as a refusal, in the verifier's class vocabulary.
func TestWitnessRefusalsAreRecorded(t *testing.T) {
	ctx := context.Background()
	key, err := GenerateCheckpointKey("behalf.sh/log/refused")
	if err != nil {
		t.Fatal(err)
	}
	_, srv, policy := testWitness(t, key.VKey)

	// The real log: 20 entries, cosigned.
	real := t.TempDir()
	if err := SaveCheckpointKey(real, key); err != nil {
		t.Fatal(err)
	}
	l, err := Open(ctx, real, key, Options{Witness: policy, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, distinctEnvelopes("a"), 0, 20)
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
	firstCheckpoint, err := os.ReadFile(filepath.Join(real, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}

	// The fork: a second log dir, same checkpoint key, same length,
	// different entries.
	forked := t.TempDir()
	if err := SaveCheckpointKey(forked, key); err != nil {
		t.Fatal(err)
	}
	f, err := Open(ctx, forked, key, Options{Witness: &WitnessPolicy{Witnesses: nil}})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, f, distinctEnvelopes("b"), 0, 20)
	if err := f.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := SaveWitnessPolicy(forked, policy); err != nil {
		t.Fatal(err)
	}

	rec, err := WitnessDir(ctx, forked, policy)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != "refused" || rec.Reason != string(witness.ReasonForkAtSize) || rec.Class != "chain" {
		t.Fatalf("fork record = %+v; want refused/same-size-different-root/chain", rec)
	}

	// And the stale restore: put the real log's earlier checkpoint back
	// over a tree the witness has already seen grow past it. Re-open the
	// real log and grow it, so the witness moves to 40.
	l2, err := Open(ctx, real, key, Options{Witness: policy, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l2, distinctEnvelopes("a"), 20, 20)
	if err := l2.Close(ctx); err != nil {
		t.Fatal(err)
	}
	// Roll the checkpoint back to the size-20 one.
	if err := os.WriteFile(filepath.Join(real, "checkpoint"), firstCheckpoint, 0o644); err != nil {
		t.Fatal(err)
	}
	rec, err = WitnessDir(ctx, real, policy)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Outcome != "refused" || rec.Reason != string(witness.ReasonSmallerSize) || rec.Class != "truncation" {
		t.Fatalf("stale restore record = %+v; want refused/smaller-size/truncation", rec)
	}
}

// Fail-closed engages Tessera's own blocking publication path, and
// behalf's pass records the cosignature that is already on the note rather
// than asking for a second one.
func TestFailClosedPublishesCosignedCheckpoints(t *testing.T) {
	dir := t.TempDir()
	key, err := GenerateCheckpointKey("behalf.sh/log/failclosed")
	if err != nil {
		t.Fatal(err)
	}
	if err := SaveCheckpointKey(dir, key); err != nil {
		t.Fatal(err)
	}
	w, srv, policy := testWitness(t, key.VKey)
	failClosed := false
	policy.FailOpen = &failClosed

	ctx := context.Background()
	l, err := Open(ctx, dir, key, Options{Witness: policy, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	appendN(t, l, distinctEnvelopes("a"), 0, 6)
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := note.Open(raw, note.VerifierList(w.Key().Verifier())); err != nil {
		t.Fatalf("under fail-closed the published checkpoint itself must carry the cosignature: %v", err)
	}
	recs, err := ReadWitnessRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("fail-closed still records the per-checkpoint outcome")
	}
	last := recs[len(recs)-1]
	if last.Outcome != "cosigned" || last.FailOpen {
		t.Fatalf("record = %+v; want cosigned with fail_open=false", last)
	}
	if !strings.Contains(last.Witnesses[0].Detail, "already on the published checkpoint") {
		t.Fatalf("behalf must observe rather than re-submit under fail-closed: %+v", last.Witnesses[0])
	}
}

func TestWitnessPolicyDefaultsAndFile(t *testing.T) {
	var nilPolicy *WitnessPolicy
	if !nilPolicy.FailOpenValue() {
		t.Fatal("the documented default is fail-open (Q96)")
	}
	if nilPolicy.Timeout() != DefaultWitnessTimeout {
		t.Fatalf("default timeout = %v, want %v", nilPolicy.Timeout(), DefaultWitnessTimeout)
	}
	if nilPolicy.Enabled() {
		t.Fatal("no policy means no witnesses")
	}

	dir := t.TempDir()
	if p, err := LoadWitnessPolicy(dir); err != nil || p != nil {
		t.Fatalf("a missing witnesses.json is not an error: %v, %v", p, err)
	}
	want := &WitnessPolicy{
		TimeoutMS: 250,
		Witnesses: []witness.Ref{{Name: "w", VKey: "k+00000000+AAAA", URL: "http://example.invalid"}},
	}
	if err := SaveWitnessPolicy(dir, want); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWitnessPolicy(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got.Timeout() != 250*time.Millisecond || !got.FailOpenValue() || got.QuorumValue() != 1 {
		t.Fatalf("policy = %+v (timeout %v, quorum %d)", got, got.Timeout(), got.QuorumValue())
	}
	if err := os.WriteFile(WitnessConfigPath(dir), []byte(`{"witnesses":[{"name":"x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadWitnessPolicy(dir); err == nil {
		t.Fatal("a witness without a url or vkey must be refused at load")
	}
}
