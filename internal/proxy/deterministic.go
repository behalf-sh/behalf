package proxy

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"
)

// Deterministic recording mode (D9.2, Q92).
//
// The demo is a recorded session pair produced by shipped code paths, and
// recordings are product artifacts: they ship, they are re-verified in CI on
// every commit, and a diff of yesterday's recording against today's must
// mean "the capture surface changed", never "the clock moved". That requires
// two injections and nothing more, because everything else in a receipt is
// already a function of the captured bytes:
//
//	the clock          captured_at, and the timestamp half of every ULID
//	the ULID entropy   the low 80 bits of receipt_id and intent_id
//
// Both default to production behaviour — time.Now and crypto/rand — and a
// recorder overrides them explicitly. Nothing about the capture path
// branches on whether they were overridden: a deterministic recording runs
// the same code as a live session, which is the entire point of recording
// through the real proxy rather than hand-authoring bytes.
//
// The remaining inputs a reproducible recording must pin are not the
// proxy's to inject, and the recorder owns them: a fresh state directory
// (so the per-emitter counter starts at zero), a fixed emitter key (so the
// DSSE signatures over identical bytes are identical — Ed25519 is
// deterministic), a fixed run id via BEHALF_RUN_ID, and a server whose
// responses are a pure function of the request.
//
// # What determinism does NOT extend to
//
// The spool's segment file names are wall-clock derived and the Tessera log
// directory carries a checkpoint signed by a per-install key. Neither is a
// receipt. The claim this mode makes is exactly: the DSSE-signed envelope
// bytes, and the CAS blobs they commit to, are byte-identical across
// recordings. That is the claim the tests assert.

// idSource mints ULIDs from an injectable clock and entropy source. Both
// pumps mint ids — the request pump for intents, the response pump for
// receipts — so the source is mutex-guarded: an entropy reader shared
// across goroutines without one produces interleaved, unreproducible reads,
// which is a data race in production and a flaky recording in CI.
type idSource struct {
	mu      sync.Mutex
	entropy io.Reader
}

func newIDSource(entropy io.Reader) *idSource {
	if entropy == nil {
		entropy = rand.Reader
	}
	return &idSource{entropy: entropy}
}

// ulidAt mints a ULID whose timestamp is t. receipt_id is client-minted at
// capture so a retried send can never occupy two chain positions (Q46).
func (s *idSource) ulidAt(t time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := ulid.New(ulid.Timestamp(t.UTC()), s.entropy)
	if err != nil {
		// crypto/rand does not fail, and a recorder's fixed stream is
		// infinite by construction. A panic here means the injected source
		// ran dry, which would silently produce colliding ids if swallowed.
		panic(fmt.Sprintf("proxy: mint ulid: %v", err))
	}
	return id.String()
}

// FixedClock returns a clock that starts at t and advances by step on every
// read. A recorder wants a clock that moves — receipts carry captured_at,
// and a run whose 47 steps share one timestamp reads as a lie about what
// happened — but moves by a fixed amount, so the same script produces the
// same timeline every time.
//
// A zero step returns a frozen clock, which is what a test that only cares
// about ordering wants.
func FixedClock(t time.Time, step time.Duration) func() time.Time {
	var mu sync.Mutex
	cur := t.UTC()
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		out := cur
		cur = cur.Add(step)
		return out
	}
}

// FixedEntropy returns a reproducible entropy stream seeded by seed —
// SHA-256 in counter mode, which is deterministic, endless, and has no
// short cycles the way a small LCG would.
//
// Seed it with something run-scoped. Two runs recorded with the same seed
// and the same clock mint the same receipt_ids, and the log dedups on
// receipt_id (Q46): the second run would be swallowed as duplicates of the
// first. Seeding per run id is what keeps two recordings of the same script
// distinguishable while keeping each one reproducible.
func FixedEntropy(seed string) io.Reader { return &counterStream{seed: []byte(seed)} }

type counterStream struct {
	seed  []byte
	n     uint64
	block []byte
}

func (c *counterStream) Read(p []byte) (int, error) {
	for i := range p {
		if len(c.block) == 0 {
			h := sha256.New()
			h.Write(c.seed)
			var ctr [8]byte
			binary.BigEndian.PutUint64(ctr[:], c.n)
			h.Write(ctr[:])
			c.n++
			c.block = h.Sum(nil)
		}
		p[i] = c.block[0]
		c.block = c.block[1:]
	}
	return len(p), nil
}
