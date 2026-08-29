package witness

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/merkle/testonly"
	"golang.org/x/mod/sumdb/note"
)

// A stand-in log: a real RFC 6962 tree plus a note signing key, so the
// checkpoints and consistency proofs the witness sees in these tests are
// the ones a real log would produce. (internal/tlog cannot be imported
// here — it imports this package — so the log-integration tests live over
// there, in internal/tlog/witness_test.go.)
type fakeLog struct {
	origin string
	skey   string
	vkey   string
	signer note.Signer
	tree   *testonly.Tree
}

func newFakeLog(t *testing.T, origin string) *fakeLog {
	t.Helper()
	skey, vkey, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		t.Fatalf("generate log key: %v", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("log signer: %v", err)
	}
	return &fakeLog{origin: origin, skey: skey, vkey: vkey, signer: signer, tree: testonly.New(rfc6962.DefaultHasher)}
}

// grow appends n entries whose contents depend on tag, so two logs with
// different tags fork at the same size.
func (l *fakeLog) grow(n int, tag string) {
	for i := 0; i < n; i++ {
		l.tree.AppendData([]byte(fmt.Sprintf("%s-%d", tag, l.tree.Size())))
	}
}

// checkpoint signs the tree head at the given size.
func (l *fakeLog) checkpoint(t *testing.T, size uint64) []byte {
	t.Helper()
	body := fmt.Sprintf("%s\n%d\n%s\n", l.origin, size,
		base64.StdEncoding.EncodeToString(l.tree.HashAt(size)))
	signed, err := note.Sign(&note.Note{Text: body}, l.signer)
	if err != nil {
		t.Fatalf("sign checkpoint: %v", err)
	}
	return signed
}

func (l *fakeLog) proof(t *testing.T, from, to uint64) [][]byte {
	t.Helper()
	if from == 0 || from == to {
		return nil
	}
	pf, err := l.tree.ConsistencyProof(from, to)
	if err != nil {
		t.Fatalf("consistency proof %d->%d: %v", from, to, err)
	}
	return pf
}

func newWitness(t *testing.T, dir string, logs ...*fakeLog) *Witness {
	t.Helper()
	key, err := GenerateKey("test.witness/1")
	if err != nil {
		t.Fatalf("generate witness key: %v", err)
	}
	return newWitnessWithKey(t, dir, key, logs...)
}

func newWitnessWithKey(t *testing.T, dir string, key *Key, logs ...*fakeLog) *Witness {
	t.Helper()
	store, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	vkeys := make([]string, 0, len(logs))
	for _, l := range logs {
		vkeys = append(vkeys, l.vkey)
	}
	w, err := New(key, store, vkeys)
	if err != nil {
		t.Fatalf("new witness: %v", err)
	}
	return w
}

// mustCosign asserts the witness accepts and returns a verifiable
// cosignature line.
func mustCosign(t *testing.T, w *Witness, cp []byte, pf [][]byte) []byte {
	t.Helper()
	sig, err := w.Cosign(cp, pf)
	if err != nil {
		t.Fatalf("expected a cosignature, got: %v", err)
	}
	signed := append(append([]byte{}, cp...), sig...)
	if _, err := note.Open(signed, note.VerifierList(w.Key().Verifier())); err != nil {
		t.Fatalf("cosignature does not verify: %v", err)
	}
	return sig
}

func mustRefuse(t *testing.T, w *Witness, cp []byte, pf [][]byte, want Reason) *Refusal {
	t.Helper()
	_, err := w.Cosign(cp, pf)
	if err == nil {
		t.Fatalf("expected refusal %q, got a cosignature", want)
	}
	r, ok := AsRefusal(err)
	if !ok {
		t.Fatalf("expected a *Refusal, got %T: %v", err, err)
	}
	if r.Reason != want {
		t.Fatalf("refusal reason = %q, want %q (%v)", r.Reason, want, err)
	}
	return r
}

// A witness that has never seen an origin accepts the first checkpoint it
// is shown: it has nothing to be inconsistent with.
func TestFirstCheckpointForUnseenOriginIsAccepted(t *testing.T) {
	l := newFakeLog(t, "test.log/first")
	l.grow(7, "a")
	w := newWitness(t, t.TempDir(), l)

	if _, ok := w.Held(l.origin); ok {
		t.Fatal("a fresh witness must hold nothing")
	}
	mustCosign(t, w, l.checkpoint(t, 7), nil)

	held, ok := w.Held(l.origin)
	if !ok || held.Size != 7 {
		t.Fatalf("held = %+v, %v; want size 7", held, ok)
	}
}

// The happy path: normal growth, with the consistency proof the log built
// from its own tiles.
func TestGrowthWithValidProofIsAccepted(t *testing.T) {
	l := newFakeLog(t, "test.log/growth")
	l.grow(5, "a")
	w := newWitness(t, t.TempDir(), l)
	mustCosign(t, w, l.checkpoint(t, 5), nil)

	for _, to := range []uint64{6, 11, 12, 40} {
		from, _ := w.Held(l.origin)
		l.grow(int(to-l.tree.Size()), "a")
		mustCosign(t, w, l.checkpoint(t, to), l.proof(t, from.Size, to))
		held, _ := w.Held(l.origin)
		if held.Size != to {
			t.Fatalf("after growth to %d, witness holds %d", to, held.Size)
		}
	}
}

// Re-offering the head already held is idempotent, not a fork.
func TestSameSizeSameRootIsIdempotent(t *testing.T) {
	l := newFakeLog(t, "test.log/idem")
	l.grow(9, "a")
	w := newWitness(t, t.TempDir(), l)
	cp := l.checkpoint(t, 9)
	first := mustCosign(t, w, cp, nil)
	second := mustCosign(t, w, cp, nil)
	// The cosignature/v1 construction embeds a timestamp, so the bytes may
	// differ; both must verify, and the head must not move.
	if len(first) == 0 || len(second) == 0 {
		t.Fatal("both cosignatures must be non-empty")
	}
	st, _ := w.Store().Get(l.origin)
	if st.Size != 9 || st.Cosignatures != 2 {
		t.Fatalf("state = %+v; want size 9 with 2 cosignatures", st)
	}
}

// Split view (Q29): two histories at the same size.
func TestRefusesSameSizeDifferentRoot(t *testing.T) {
	real := newFakeLog(t, "test.log/fork")
	real.grow(20, "a")
	w := newWitness(t, t.TempDir(), real)
	mustCosign(t, w, real.checkpoint(t, 20), nil)

	// The same log key over a different history of the same length.
	forged := &fakeLog{origin: real.origin, skey: real.skey, vkey: real.vkey,
		signer: real.signer, tree: testonly.New(rfc6962.DefaultHasher)}
	forged.grow(20, "b")

	r := mustRefuse(t, w, forged.checkpoint(t, 20), nil, ReasonForkAtSize)
	if got := r.Reason.Class(); got != "chain" {
		t.Fatalf("fork class = %q, want chain", got)
	}
	// And the held head is untouched.
	held, _ := w.Held(real.origin)
	if held.RootHex() != fmt.Sprintf("%x", real.tree.HashAt(20)) {
		t.Fatal("a refused submission must not move the held head")
	}
}

// Restore-as-truncation (Q76): an older tree offered after a newer one.
func TestRefusesSmallerSize(t *testing.T) {
	l := newFakeLog(t, "test.log/restore")
	l.grow(50, "a")
	w := newWitness(t, t.TempDir(), l)
	mustCosign(t, w, l.checkpoint(t, 50), nil)

	r := mustRefuse(t, w, l.checkpoint(t, 20), nil, ReasonSmallerSize)
	if r.Reason.Class() != "truncation" {
		t.Fatalf("stale restore class = %q, want truncation", r.Reason.Class())
	}
	if r.Held.Size != 50 || r.Offered.Size != 20 {
		t.Fatalf("refusal = %+v; want held 50, offered 20", r)
	}
	held, _ := w.Held(l.origin)
	if held.Size != 50 {
		t.Fatalf("held size moved to %d after a refusal", held.Size)
	}
}

// A larger tree that does not carry the held root forward.
func TestRefusesInconsistentProof(t *testing.T) {
	real := newFakeLog(t, "test.log/inconsistent")
	real.grow(16, "a")
	w := newWitness(t, t.TempDir(), real)
	mustCosign(t, w, real.checkpoint(t, 16), nil)

	// A different history that happens to be longer: its own proof from 16
	// to 24 is internally valid but does not start from the held root.
	other := &fakeLog{origin: real.origin, skey: real.skey, vkey: real.vkey,
		signer: real.signer, tree: testonly.New(rfc6962.DefaultHasher)}
	other.grow(24, "b")
	mustRefuse(t, w, other.checkpoint(t, 24), other.proof(t, 16, 24), ReasonInconsistentProof)

	// Growth on the real tree with a missing proof is refused too.
	real.grow(8, "a")
	mustRefuse(t, w, real.checkpoint(t, 24), nil, ReasonInconsistentProof)
	// Garbage proof hashes: same class.
	bad := [][]byte{make([]byte, 32), make([]byte, 32)}
	mustRefuse(t, w, real.checkpoint(t, 24), bad, ReasonInconsistentProof)

	// And the correct proof is still accepted afterwards: a refusal is not
	// a poisoned state.
	mustCosign(t, w, real.checkpoint(t, 24), real.proof(t, 16, 24))
}

// A proof supplied for an origin the witness has never seen is a client
// bug, and it is refused rather than ignored.
func TestRefusesProofOnFirstCheckpoint(t *testing.T) {
	l := newFakeLog(t, "test.log/firstproof")
	l.grow(8, "a")
	w := newWitness(t, t.TempDir(), l)
	mustRefuse(t, w, l.checkpoint(t, 8), [][]byte{make([]byte, 32)}, ReasonInconsistentProof)
}

// A witness with amnesia is not a witness: the head must survive a
// restart, and the restarted witness must still refuse the fork.
func TestHeadSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	l := newFakeLog(t, "test.log/restart")
	l.grow(31, "a")

	key, err := GenerateKey("test.witness/restart")
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	w := newWitnessWithKey(t, dir, key, l)
	mustCosign(t, w, l.checkpoint(t, 31), nil)

	// A completely fresh witness over the same state dir — a process
	// restart, as far as the on-disk state is concerned.
	reloaded := newWitnessWithKey(t, dir, key, l)
	held, ok := reloaded.Held(l.origin)
	if !ok || held.Size != 31 {
		t.Fatalf("after restart, held = %+v, %v; want size 31", held, ok)
	}
	st, _ := reloaded.Store().Get(l.origin)
	if st.Cosignatures != 1 || st.CosignedAt == "" {
		t.Fatalf("after restart, state = %+v", st)
	}
	if cp, err := st.CosignedCheckpoint(); err != nil || len(cp) == 0 {
		t.Fatalf("the cosigned checkpoint must survive the restart: %v", err)
	}

	forged := &fakeLog{origin: l.origin, skey: l.skey, vkey: l.vkey,
		signer: l.signer, tree: testonly.New(rfc6962.DefaultHasher)}
	forged.grow(31, "b")
	mustRefuse(t, reloaded, forged.checkpoint(t, 31), nil, ReasonForkAtSize)
	mustRefuse(t, reloaded, l.checkpoint(t, 12), nil, ReasonSmallerSize)
}

// Concurrent submissions of two different histories at the same size: at
// most one may be cosigned, and the loser must be a fork refusal. This is
// the race the whole split-view defence rests on.
func TestConcurrentForkSubmissions(t *testing.T) {
	a := newFakeLog(t, "test.log/race")
	a.grow(13, "a")
	b := &fakeLog{origin: a.origin, skey: a.skey, vkey: a.vkey,
		signer: a.signer, tree: testonly.New(rfc6962.DefaultHasher)}
	b.grow(13, "b")
	w := newWitness(t, t.TempDir(), a)

	cpA, cpB := a.checkpoint(t, 13), b.checkpoint(t, 13)
	const n = 32
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cp := cpA
			if i%2 == 1 {
				cp = cpB
			}
			_, results[i] = w.Cosign(cp, nil)
		}()
	}
	wg.Wait()

	var cosigned, refused int
	for i, err := range results {
		switch {
		case err == nil:
			cosigned++
		default:
			r, ok := AsRefusal(err)
			if !ok || r.Reason != ReasonForkAtSize {
				t.Fatalf("result %d: want a fork refusal, got %v", i, err)
			}
			refused++
		}
	}
	if cosigned == 0 || refused == 0 {
		t.Fatalf("expected both outcomes across %d racing submissions; got %d cosigned, %d refused", n, cosigned, refused)
	}
	// Whichever history won, exactly one root is now held, and every
	// submission of the other one was refused.
	held, _ := w.Held(a.origin)
	wantA := fmt.Sprintf("%x", a.tree.HashAt(13))
	wantB := fmt.Sprintf("%x", b.tree.HashAt(13))
	if held.RootHex() != wantA && held.RootHex() != wantB {
		t.Fatalf("held root %s is neither history's root", held.RootHex())
	}
	if cosigned+refused != n {
		t.Fatalf("accounted %d of %d submissions", cosigned+refused, n)
	}
}

// Concurrent growth submissions must leave the held head monotonic.
func TestConcurrentGrowthIsMonotonic(t *testing.T) {
	l := newFakeLog(t, "test.log/monotonic")
	l.grow(64, "a")
	w := newWitness(t, t.TempDir(), l)
	mustCosign(t, w, l.checkpoint(t, 1), nil)

	var wg sync.WaitGroup
	for _, size := range []uint64{8, 16, 32, 64, 8, 16, 32, 64} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Proofs are built from the size the witness held when this
			// goroutine started; many will be stale and refused, which is
			// the point — none of them may corrupt the head.
			held, _ := w.Held(l.origin)
			if held.Size > size {
				return
			}
			_, _ = w.Cosign(l.checkpoint(t, size), l.proof(t, held.Size, size))
		}()
	}
	wg.Wait()

	held, _ := w.Held(l.origin)
	if got := fmt.Sprintf("%x", l.tree.HashAt(held.Size)); got != held.RootHex() {
		t.Fatalf("held head (%d, %s) is not a real tree head of this log", held.Size, held.RootHex())
	}
	// Anything smaller than what is held must now be refused.
	if held.Size > 1 {
		mustRefuse(t, w, l.checkpoint(t, held.Size-1), nil, ReasonSmallerSize)
	}
}

// Neither an unknown origin nor a bad log signature is a refusal: the
// safety rule never ran, and calling them refusals would put noise in the
// one channel that must stay meaningful.
func TestUnknownOriginAndBadSignatureAreNotRefusals(t *testing.T) {
	known := newFakeLog(t, "test.log/known")
	known.grow(3, "a")
	stranger := newFakeLog(t, "test.log/stranger")
	stranger.grow(3, "a")
	w := newWitness(t, t.TempDir(), known)

	if _, err := w.Cosign(stranger.checkpoint(t, 3), nil); err == nil {
		t.Fatal("an unknown origin must not be cosigned")
	} else if _, isRefusal := AsRefusal(err); isRefusal {
		t.Fatalf("unknown origin classified as a refusal: %v", err)
	} else if !strings.Contains(err.Error(), "unknown checkpoint origin") {
		t.Fatalf("unknown origin error = %v", err)
	}

	// Same origin, a different key: the signature does not verify.
	impostor := newFakeLog(t, known.origin)
	impostor.grow(3, "a")
	if _, err := w.Cosign(impostor.checkpoint(t, 3), nil); err == nil {
		t.Fatal("a checkpoint signed by the wrong key must not be cosigned")
	} else if _, isRefusal := AsRefusal(err); isRefusal {
		t.Fatalf("bad log signature classified as a refusal: %v", err)
	}

	// Garbage.
	for _, bad := range [][]byte{nil, []byte("x"), []byte("origin\n"), []byte("origin\nnot-a-number\nAAAA\n\n")} {
		if _, err := w.Cosign(bad, nil); err == nil {
			t.Fatalf("garbage %q must not be cosigned", bad)
		}
	}
}

func TestKeyRoundTripAndFiles(t *testing.T) {
	dir := t.TempDir()
	k, err := GenerateKey("test.witness/files")
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	path := dir + "/witness.skey"
	if err := SaveKey(path, k); err != nil {
		t.Fatalf("save: %v", err)
	}
	loaded, err := LoadKey(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.VKey != k.VKey || loaded.Name != k.Name {
		t.Fatalf("round trip changed the key: %q/%q vs %q/%q", loaded.Name, loaded.VKey, k.Name, k.VKey)
	}
	// The published vkey is a cosignature/v1 key: a verifier built from it
	// must accept a signature made by the loaded signer.
	body := "some.origin\n4\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	sig, err := loaded.CosignText([]byte(body))
	if err != nil {
		t.Fatalf("cosign: %v", err)
	}
	if _, err := note.Open(append([]byte(body+"\n"), sig...), note.VerifierList(k.Verifier())); err != nil {
		t.Fatalf("cosignature from the loaded key does not verify against the saved vkey: %v", err)
	}
	if _, err := ParseKey("PRIVATE+KEY+bogus"); err == nil {
		t.Fatal("a malformed skey must not parse")
	}
}

// The HTTP surface: every status code the C2SP protocol assigns, plus the
// behalf refusal header.
func TestServerStatusCodes(t *testing.T) {
	l := newFakeLog(t, "test.log/http")
	l.grow(10, "a")
	w := newWitness(t, t.TempDir(), l)
	srv := httptest.NewServer(NewServer(w, nil).Handler())
	defer srv.Close()

	post := func(req Request) (*http.Response, string) {
		t.Helper()
		resp, err := http.Post(srv.URL+AddCheckpointPath, "text/plain", strings.NewReader(string(EncodeRequest(req))))
		if err != nil {
			t.Fatalf("post: %v", err)
		}
		buf := make([]byte, 4096)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		return resp, string(buf[:n])
	}

	// First checkpoint: 200.
	resp, body := post(Request{OldSize: 0, Checkpoint: l.checkpoint(t, 10)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("first submission: HTTP %d (%s)", resp.StatusCode, body)
	}

	// Wrong `old`: 409 with the witness's size, no refusal header.
	resp, body = post(Request{OldSize: 3, Checkpoint: l.checkpoint(t, 10)})
	if resp.StatusCode != http.StatusConflict || resp.Header.Get("Content-Type") != SizeContentType {
		t.Fatalf("stale old size: HTTP %d ct=%q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if strings.TrimSpace(body) != "10" {
		t.Fatalf("409 body = %q, want the held size 10", body)
	}
	if got := resp.Header.Get(RefusalHeader); got != "" {
		t.Fatalf("a calibration 409 must not claim a refusal, got %q", got)
	}

	// Smaller tree: 409 with the refusal header.
	resp, _ = post(Request{OldSize: 10, Checkpoint: l.checkpoint(t, 4)})
	if resp.StatusCode != http.StatusConflict || resp.Header.Get(RefusalHeader) != string(ReasonSmallerSize) {
		t.Fatalf("stale restore: HTTP %d refusal=%q", resp.StatusCode, resp.Header.Get(RefusalHeader))
	}

	// Fork: 409, same-size-different-root.
	forged := &fakeLog{origin: l.origin, skey: l.skey, vkey: l.vkey,
		signer: l.signer, tree: testonly.New(rfc6962.DefaultHasher)}
	forged.grow(10, "b")
	resp, _ = post(Request{OldSize: 10, Checkpoint: forged.checkpoint(t, 10)})
	if resp.StatusCode != http.StatusConflict || resp.Header.Get(RefusalHeader) != string(ReasonForkAtSize) {
		t.Fatalf("fork: HTTP %d refusal=%q", resp.StatusCode, resp.Header.Get(RefusalHeader))
	}

	// Bad proof: 422.
	l.grow(6, "a")
	resp, _ = post(Request{OldSize: 10, Proof: [][]byte{make([]byte, 32)}, Checkpoint: l.checkpoint(t, 16)})
	if resp.StatusCode != http.StatusUnprocessableEntity ||
		resp.Header.Get(RefusalHeader) != string(ReasonInconsistentProof) {
		t.Fatalf("bad proof: HTTP %d refusal=%q", resp.StatusCode, resp.Header.Get(RefusalHeader))
	}

	// Unknown origin: 404.
	stranger := newFakeLog(t, "test.log/nobody")
	stranger.grow(2, "a")
	resp, _ = post(Request{Checkpoint: stranger.checkpoint(t, 2)})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown origin: HTTP %d", resp.StatusCode)
	}

	// Wrong key for a known origin: 403.
	impostor := newFakeLog(t, l.origin)
	impostor.grow(2, "a")
	resp, _ = post(Request{Checkpoint: impostor.checkpoint(t, 2)})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong log key: HTTP %d", resp.StatusCode)
	}

	// Malformed body: 400.
	resp, err := http.Post(srv.URL+AddCheckpointPath, "text/plain", strings.NewReader("not a submission"))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed body: HTTP %d", resp.StatusCode)
	}
}

// The log-side client against the real server: outcomes, not errors.
func TestClientOutcomes(t *testing.T) {
	l := newFakeLog(t, "test.log/client")
	l.grow(9, "a")
	w := newWitness(t, t.TempDir(), l)
	srv := httptest.NewServer(NewServer(w, nil).Handler())
	defer srv.Close()

	c, err := NewClient(Ref{Name: "w1", VKey: w.Key().VKey, URL: srv.URL}, srv.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	proofFn := func(_ context.Context, from, to uint64) ([][]byte, error) {
		return l.proof(t, from, to), nil
	}
	ctx := context.Background()

	res := c.Submit(ctx, l.checkpoint(t, 9), proofFn)
	if res.Outcome != OutcomeCosigned || res.Cosignature == "" {
		t.Fatalf("first submission: %+v", res)
	}

	// Growth: the client remembers 9 and builds the proof itself.
	l.grow(11, "a")
	res = c.Submit(ctx, l.checkpoint(t, 20), proofFn)
	if res.Outcome != OutcomeCosigned {
		t.Fatalf("growth: %+v", res)
	}

	// A fresh client has no memory and must recalibrate through the 409.
	fresh, err := NewClient(Ref{Name: "w2", VKey: w.Key().VKey, URL: srv.URL}, srv.Client())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	l.grow(5, "a")
	res = fresh.Submit(ctx, l.checkpoint(t, 25), proofFn)
	if res.Outcome != OutcomeCosigned {
		t.Fatalf("recalibrated submission: %+v", res)
	}

	// A fork, surfaced through the wire as a refusal with its reason.
	forged := &fakeLog{origin: l.origin, skey: l.skey, vkey: l.vkey,
		signer: l.signer, tree: testonly.New(rfc6962.DefaultHasher)}
	forged.grow(25, "b")
	res = fresh.Submit(ctx, forged.checkpoint(t, 25), proofFn)
	if res.Outcome != OutcomeRefused || res.Reason != string(ReasonForkAtSize) || res.Class != "chain" {
		t.Fatalf("fork over the wire: %+v", res)
	}

	// A stale restore, likewise.
	res = fresh.Submit(ctx, l.checkpoint(t, 9), proofFn)
	if res.Outcome != OutcomeRefused || res.Reason != string(ReasonSmallerSize) || res.Class != "truncation" {
		t.Fatalf("stale restore over the wire: %+v", res)
	}

	// An unreachable witness is an outcome, never an error.
	srv.Close()
	res = fresh.Submit(ctx, l.checkpoint(t, 25), proofFn)
	if res.Outcome != OutcomeUnreachable || res.Detail == "" {
		t.Fatalf("unreachable witness: %+v", res)
	}
}

func TestRequestRoundTrip(t *testing.T) {
	req := Request{
		OldSize:    42,
		Proof:      [][]byte{make([]byte, 32), make([]byte, 32)},
		Checkpoint: []byte("origin\n43\nAAAA\n\n— origin sig\n"),
	}
	got, err := DecodeRequest(EncodeRequest(req))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.OldSize != req.OldSize || len(got.Proof) != 2 || string(got.Checkpoint) != string(req.Checkpoint) {
		t.Fatalf("round trip changed the request: %+v", got)
	}
	for _, bad := range []string{"", "old 1\n", "nope\n\ncp", "old x\n\ncp", "old 1\nnotb64!\n\ncp", "old 1\n\n"} {
		if _, err := DecodeRequest([]byte(bad)); err == nil {
			t.Fatalf("malformed body %q must not decode", bad)
		}
	}
}

func TestStoreRejectsUnknownVersion(t *testing.T) {
	dir := t.TempDir()
	if err := writeFile(dir+"/"+StateFileName, `{"version":"nope","origins":{}}`); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenStore(dir); err == nil {
		t.Fatal("an unknown state version must be refused, not reinterpreted")
	}
}

func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}
