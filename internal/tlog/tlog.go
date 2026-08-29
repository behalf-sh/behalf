// Package tlog is the behalf log service: a Tessera tiled transparency log
// on the POSIX driver (architecture D1), one appender per log dir (Q57),
// with receipt-id dedup in front of the log (Q46) and an SCT-style receipt
// promise returned with every ack (D2).
//
// Durability contract (Q75, verified from Tessera source at v1.0.4): the
// POSIX driver resolves the Add future only after the entry bundle, tiles
// and tree state are durably written (O_SYNC temp files, atomic renames,
// directory fsyncs) — so a resolved ack means the entry is durably
// committed AND integrated into the on-disk tiles. The signed checkpoint
// covering it publishes asynchronously (1 s interval). The promise returned
// with the ack is not an inclusion proof — it is redeemable at checkpoint
// publication.
//
// Backpressure (Q47): WithPushback is a silent no-op on the POSIX driver
// and integration runs inline, so overload surfaces as Append latency
// growth, not a pushback error. No pushback option is configured here.
package tlog

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/storage/posix"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/index"
)

// IndexFileName is the SQLite index file inside the log dir: the follower
// index (internal/index) — a derived, rebuildable projection of the log
// (Q55, Q56, Q76) whose persistent receipt_id window is also the ingest
// dedup window (Q46).
const IndexFileName = index.FileName

// jwkJSON renders a JWK as its canonical JSON for the index keys table.
func jwkJSON(j dsse.JWK) string {
	b, err := json.Marshal(j)
	if err != nil {
		panic(fmt.Sprintf("tlog: marshal jwk: %v", err))
	}
	return string(b)
}

// Defaults per architecture Q30/D3.3.
const (
	DefaultCheckpointInterval = 1 * time.Second
	DefaultBatchMaxAge        = 250 * time.Millisecond
	DefaultBatchMaxSize       = 256
)

// Options configures Open. Zero values take the defaults above.
type Options struct {
	CheckpointInterval time.Duration
	BatchMaxAge        time.Duration
	BatchMaxSize       uint

	// Witness overrides the witness policy read from
	// <dir>/witnesses.json. Nil means "use the file, or no witnesses if
	// there is no file"; a non-nil policy with no witnesses disables
	// witnessing for this handle. See witness.go for the availability
	// mode (Q96): fail-open by default, and never blocking publication.
	Witness *WitnessPolicy

	// HTTPClient is used for witness submissions. Nil takes
	// http.DefaultClient.
	HTTPClient *http.Client
}

func (o Options) withDefaults() Options {
	if o.CheckpointInterval == 0 {
		o.CheckpointInterval = DefaultCheckpointInterval
	}
	if o.BatchMaxAge == 0 {
		o.BatchMaxAge = DefaultBatchMaxAge
	}
	if o.BatchMaxSize == 0 {
		o.BatchMaxSize = DefaultBatchMaxSize
	}
	return o
}

// Log is an open, appendable behalf log. One Log handle per process per
// dir; the newest Open fences all older holders (Q57).
type Log struct {
	dir   string
	key   *CheckpointKey
	epoch EpochRecord

	appender *tessera.Appender
	reader   tessera.LogReader
	shutdown func(context.Context) error
	cancel   context.CancelFunc

	idx *index.DB

	// Witnessing (Q96). wit is nil when no witness is configured; the
	// loop runs only while the handle is open and never blocks the write
	// path — see witness.go.
	wit         *witnessSubmitter
	witInterval time.Duration
	witCancel   context.CancelFunc
	witDone     chan struct{}

	mu      sync.Mutex
	pending map[string]*Pending // receipt_id -> in-flight append
	closed  bool
}

// Open claims a new epoch for dir, opens the SQLite index, and starts the
// Tessera POSIX appender with checkpointSigner as the checkpoint key.
// Single-appender discipline rests on Tessera's in-process mutex plus POSIX
// lock file; the epoch file adds behalf's product-level fence on top: an
// older holder whose epoch has been superseded is refused (ErrFenced) on
// its next Append.
//
// The caller must Close the log; Close flushes and waits for a checkpoint
// covering everything appended by this handle.
func Open(ctx context.Context, dir string, checkpointSigner *CheckpointKey, opts Options) (*Log, error) {
	opts = opts.withDefaults()
	if checkpointSigner == nil {
		return nil, fmt.Errorf("tlog: nil checkpoint signer")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("tlog: create log dir: %w", err)
	}

	epoch, err := claimEpoch(dir)
	if err != nil {
		return nil, fmt.Errorf("tlog: claim epoch: %w", err)
	}

	idx, err := index.Open(ctx, dir)
	if err != nil {
		return nil, err
	}
	// The export bridge needs the checkpoint key's JWK in the header key
	// set (it signs export heads).
	if err := idx.RegisterKey(checkpointSigner.JKT, jwkJSON(checkpointSigner.JWK)); err != nil {
		idx.Close()
		return nil, fmt.Errorf("tlog: register checkpoint key: %w", err)
	}
	// And every emitter key registered with this log before, replayed out of
	// keys/emitters.jsonl. The index is disposable (Q76) and this is what makes
	// that true of the keys table too: without it, a reindex left a log that
	// `behalf-log export` refused outright until something happened to
	// re-register a key. See EmittersFileName for what this file is, and for
	// the trust claim it deliberately does not make.
	emitters, err := LoadEmitterKeys(dir)
	if err != nil {
		idx.Close()
		return nil, err
	}
	for jkt, jwk := range emitters {
		if err := idx.RegisterKey(jkt, jwk); err != nil {
			idx.Close()
			return nil, fmt.Errorf("tlog: replay emitter key %s: %w", jkt, err)
		}
	}

	signer, err := checkpointSigner.NoteSigner()
	if err != nil {
		idx.Close()
		return nil, err
	}

	// Witness policy: the flag overrides the file; the file is the
	// deployed configuration (Q96 — the availability mode is explicit
	// configuration with documented defaults, not a constant).
	policy := opts.Witness
	if policy == nil {
		policy, err = LoadWitnessPolicy(dir)
		if err != nil {
			idx.Close()
			return nil, err
		}
	}
	var wit *witnessSubmitter
	if policy.Enabled() {
		wit, err = newWitnessSubmitter(dir, policy, opts.HTTPClient)
		if err != nil {
			idx.Close()
			return nil, err
		}
	}

	appCtx, cancel := context.WithCancel(context.Background())
	driver, err := posix.New(appCtx, posix.Config{Path: dir, HTTPClient: opts.HTTPClient})
	if err != nil {
		cancel()
		idx.Close()
		return nil, fmt.Errorf("tlog: posix driver: %w", err)
	}
	tOpts := tessera.NewAppendOptions().
		WithCheckpointSigner(signer).
		WithCheckpointInterval(opts.CheckpointInterval).
		WithBatching(opts.BatchMaxSize, opts.BatchMaxAge)
	if wit != nil && !policy.FailOpenValue() {
		// Fail-closed: publication itself must block on quorum, which only
		// Tessera's own path can do. behalf's pass then observes the
		// cosignature already on the published note and records it.
		group, gerr := tesseraWitnessGroup(policy)
		if gerr != nil {
			cancel()
			idx.Close()
			return nil, gerr
		}
		tOpts = tOpts.WithWitnesses(group, &tessera.WitnessOptions{
			Timeout:  policy.Timeout(),
			FailOpen: false,
		})
	}
	appender, shutdown, reader, err := tessera.NewAppender(appCtx, driver, tOpts)
	if err != nil {
		cancel()
		idx.Close()
		return nil, fmt.Errorf("tlog: new appender: %w", err)
	}

	l := &Log{
		dir:         dir,
		key:         checkpointSigner,
		epoch:       epoch,
		appender:    appender,
		reader:      reader,
		shutdown:    shutdown,
		cancel:      cancel,
		idx:         idx,
		wit:         wit,
		witInterval: opts.CheckpointInterval,
		pending:     map[string]*Pending{},
	}
	if wit != nil {
		witCtx, witCancel := context.WithCancel(context.Background())
		l.witCancel = witCancel
		l.witDone = make(chan struct{})
		go func() {
			defer close(l.witDone)
			l.witnessLoop(witCtx)
		}()
	}
	return l, nil
}

// Close flushes outstanding appends, waits for a checkpoint covering them,
// stops the background tasks, and closes the index.
func (l *Log) Close(ctx context.Context) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	// Stop the background witness loop before the final pass, so the two
	// cannot race on the same checkpoint.
	if l.witCancel != nil {
		l.witCancel()
		<-l.witDone
	}
	err := l.shutdown(ctx)
	// One last pass over the checkpoint the shutdown published. Its outcome
	// is recorded like any other; a witness that is down at close time
	// cannot make Close fail, because that would make witnessing block the
	// write path by the back door (Q96).
	if err == nil && l.wit != nil {
		l.witnessPass(ctx)
	}
	l.cancel()
	if cerr := l.idx.Close(); err == nil {
		err = cerr
	}
	return err
}

// AppendResult is the ack for one envelope.
type AppendResult struct {
	// Index is the leaf index durably assigned to this receipt's envelope
	// (the original index if Duplicate).
	Index uint64
	// Duplicate is true when the receipt_id was already in the log; the
	// envelope was NOT appended again and Index/LeafHash are the original
	// entry's (Q46: duplicates are legal-but-flagged, never appended twice).
	Duplicate bool
	// LeafHash is the RFC 6962 leaf hash of the stored envelope bytes.
	LeafHash [32]byte
	// Promise is the signed receipt promise (the CT SCT analogue). It is
	// returned synchronously with the ack and is not an inclusion proof:
	// it is redeemable against a checkpoint published within mmd_s seconds.
	Promise *SignedPromise
}

// Append durably appends one stored envelope (the DSSE-signed receipt
// bytes, built with BuildEnvelope) to the log and blocks until Tessera's
// future resolves. On the POSIX driver a resolved future means the entry is
// durably committed and integrated into the on-disk tiles (Q75), so a
// non-error return here is the full durability ack: bytes on disk, index
// assigned, receipt promise signed. The returned promise is not an
// inclusion proof.
//
// Before appending, the receipt_id is checked against the persistent dedup
// window (index.db): a duplicate returns the original index, flagged, and
// is never appended twice (Q46).
func (l *Log) Append(ctx context.Context, envelope []byte) (*AppendResult, error) {
	p, err := l.BeginAppend(ctx, envelope)
	if err != nil {
		return nil, err
	}
	return p.Wait(ctx)
}

// Pending is an in-flight append: the entry is queued (order across
// sequential BeginAppend calls is preserved by Tessera) but the durability
// ack has not resolved yet. Call Wait to block for the ack.
type Pending struct {
	l        *Log
	row      index.Row // extracted at BeginAppend; LogIndex assigned at ack
	leafHash [32]byte
	future   tessera.IndexFuture // nil when resolved without an append
	dupRow   *index.Row          // pre-resolved duplicate
	waitOn   *Pending            // duplicate of an in-flight append

	once sync.Once
	res  *AppendResult
	err  error
}

// BeginAppend checks dedup, then queues envelope for sequencing and returns
// immediately. Sequential BeginAppend calls preserve log order; use Wait on
// each returned Pending (in any order) for the durability acks. This is the
// pipelined form of Append for bulk ingest.
func (l *Log) BeginAppend(ctx context.Context, envelope []byte) (*Pending, error) {
	// Extract the full index row up front: a malformed payload is refused
	// here, before anything reaches the log, and the extracted columns are
	// exactly what a later Rebuild would re-derive from the stored bytes.
	row, err := index.Extract(envelope)
	if err != nil {
		return nil, err
	}
	if err := checkEpoch(l.dir, l.epoch.Epoch); err != nil {
		return nil, err
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil, fmt.Errorf("tlog: append after close")
	}
	// In-flight duplicate: same receipt_id queued but not yet acked.
	if inflight, ok := l.pending[row.ReceiptID]; ok {
		return &Pending{l: l, row: row, waitOn: inflight}, nil
	}
	// Persistent dedup window (Q46).
	canonical, err := l.idx.LookupCanonical(row.ReceiptID)
	if err != nil {
		return nil, err
	}
	if canonical != nil {
		return &Pending{l: l, row: row, dupRow: canonical}, nil
	}

	entry := tessera.NewEntry(envelope)
	var leafHash [32]byte
	copy(leafHash[:], entry.LeafHash())
	if hex.EncodeToString(leafHash[:]) != row.LeafHash {
		// Cannot happen while Tessera hashes entries per RFC 6962; guard so
		// the log and the index can never silently disagree on a leaf.
		return nil, fmt.Errorf("tlog: leaf hash mismatch between Tessera entry and index extraction for %s", row.ReceiptID)
	}
	p := &Pending{
		l:        l,
		row:      row,
		leafHash: leafHash,
		future:   l.appender.Add(ctx, entry),
	}
	l.pending[row.ReceiptID] = p
	return p, nil
}

// Wait blocks until the durability ack for this append resolves (durable
// commit + integration on POSIX), records the receipt in the index, and
// signs the receipt promise. Only the current epoch holder signs promises:
// if this handle has been fenced by a newer epoch, Wait returns ErrFenced
// and no ack or promise is produced, even though the entry itself may be
// durably in the log.
func (p *Pending) Wait(ctx context.Context) (*AppendResult, error) {
	p.once.Do(func() { p.res, p.err = p.resolve(ctx) })
	return p.res, p.err
}

func (p *Pending) resolve(ctx context.Context) (*AppendResult, error) {
	switch {
	case p.waitOn != nil:
		// Duplicate of an append still in flight: wait for the original.
		orig, err := p.waitOn.Wait(ctx)
		if err != nil {
			return nil, fmt.Errorf("tlog: duplicate of failed append %s: %w", p.row.ReceiptID, err)
		}
		return p.l.duplicateResult(p.row.ReceiptID, orig.Index, hex.EncodeToString(orig.LeafHash[:]))
	case p.dupRow != nil:
		return p.l.duplicateResult(p.row.ReceiptID, p.dupRow.LogIndex, p.dupRow.LeafHash)
	}

	// The Tessera future: on POSIX it resolves only after the entry bundle,
	// tiles and tree state are durably written — durable commit includes
	// integration (Q75).
	idx, err := p.future()
	p.l.removePending(p.row.ReceiptID)
	if err != nil {
		return nil, fmt.Errorf("tlog: append %s: %w", p.row.ReceiptID, err)
	}

	// Fenced holders must not ack or sign promises (Q57).
	if err := checkEpoch(p.l.dir, p.l.epoch.Epoch); err != nil {
		return nil, err
	}

	row := p.row
	row.LogIndex = idx.Index
	canonical, err := p.l.idx.Record(row)
	if err != nil {
		return nil, err
	}
	if canonical != nil {
		// Crash-race duplicate (Q46): the entry reached the log twice; the
		// index collapses on receipt_id — the new leaf is recorded with
		// duplicate_of pointing at the first — and the result is flagged.
		return p.l.duplicateResult(row.ReceiptID, canonical.LogIndex, canonical.LeafHash)
	}

	promise, err := p.l.signPromise(row.ReceiptID, p.leafHash[:])
	if err != nil {
		return nil, err
	}
	return &AppendResult{Index: idx.Index, LeafHash: p.leafHash, Promise: promise}, nil
}

func (l *Log) removePending(receiptID string) {
	l.mu.Lock()
	delete(l.pending, receiptID)
	l.mu.Unlock()
}

// duplicateResult builds the flagged ack for a deduped receipt: the
// original index and leaf hash, plus a freshly signed promise for the
// original leaf.
func (l *Log) duplicateResult(receiptID string, logIndex uint64, leafHashHex string) (*AppendResult, error) {
	if err := checkEpoch(l.dir, l.epoch.Epoch); err != nil {
		return nil, err
	}
	var leafHash [32]byte
	raw, err := hex.DecodeString(leafHashHex)
	if err != nil || len(raw) != 32 {
		return nil, fmt.Errorf("tlog: index leaf_hash for %s is corrupt", receiptID)
	}
	copy(leafHash[:], raw)
	promise, err := l.signPromise(receiptID, leafHash[:])
	if err != nil {
		return nil, err
	}
	return &AppendResult{
		Index:     logIndex,
		Duplicate: true,
		LeafHash:  leafHash,
		Promise:   promise,
	}, nil
}

// signPromise signs the receipt promise with the checkpoint key (only the
// current lock-holder signs promises — Q57). The result is not an inclusion
// proof.
func (l *Log) signPromise(receiptID string, leafHash []byte) (*SignedPromise, error) {
	return SignPromise(l.key.Private, l.key.JKT, NewPromise(receiptID, leafHash, time.Now()))
}

// RegisterKey records a public key JWK (JSON) under its RFC 7638
// thumbprint so the export bridge can embed it in export headers.
func (l *Log) RegisterKey(jkt, jwkJSON string) error {
	// Durably first, then the index. The index is the cache; the file is what
	// survives it being deleted, which is the whole point (Q76).
	if err := saveEmitterKey(l.dir, jkt, jwkJSON); err != nil {
		return err
	}
	return l.idx.RegisterKey(jkt, jwkJSON)
}

// TreeSize returns the current integrated tree size.
func (l *Log) TreeSize(ctx context.Context) (uint64, error) {
	return l.reader.IntegratedSize(ctx)
}

// ReadCheckpoint returns the latest published checkpoint bytes.
func (l *Log) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	return l.reader.ReadCheckpoint(ctx)
}

// Epoch returns the epoch record this handle claimed at Open.
func (l *Log) Epoch() EpochRecord { return l.epoch }

// Key returns the checkpoint key this handle signs with.
func (l *Log) Key() *CheckpointKey { return l.key }
