package tlog

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
)

// BundleReader is a read-only view over one log dir's entry bundles: it
// serves the stored envelope bytes (and their payload spans) by log index,
// caching each bundle it touches. No appender is started and no epoch is
// claimed, so a reader never fences the running log service (Q57) — this is
// the read path `behalf why` and `behalf runs` sit on, alongside ExportRun
// and index.Reconstruct.
//
// The published checkpoint bounds what is readable: an index at or beyond
// the signed tree size is refused rather than served from a partially
// written tile, so nothing is ever rendered that a checkpoint does not
// commit to.
type BundleReader struct {
	dir     string
	cp      *LogCheckpoint
	fetcher client.FileFetcher
	bundles map[uint64]api.EntryBundle
}

// NewBundleReader opens dir for reading and parses (signature-verifying) its
// published checkpoint.
func NewBundleReader(ctx context.Context, dir string) (*BundleReader, error) {
	cp, err := ParseLogCheckpoint(ctx, dir)
	if err != nil {
		return nil, err
	}
	return &BundleReader{
		dir:     dir,
		cp:      cp,
		fetcher: client.FileFetcher{Root: dir},
		bundles: map[uint64]api.EntryBundle{},
	}, nil
}

// Checkpoint returns the published checkpoint this reader is bounded by.
func (r *BundleReader) Checkpoint() *LogCheckpoint { return r.cp }

// Envelope returns the stored envelope bytes at logIndex — the exact bytes
// the Merkle leaf covers.
func (r *BundleReader) Envelope(ctx context.Context, logIndex uint64) ([]byte, error) {
	if logIndex >= r.cp.Size {
		return nil, fmt.Errorf("tlog: log index %d is beyond the published checkpoint (size %d); wait for the next checkpoint",
			logIndex, r.cp.Size)
	}
	bIdx := logIndex / layout.EntryBundleWidth
	bundle, ok := r.bundles[bIdx]
	if !ok {
		var err error
		bundle, err = client.GetEntryBundle(ctx, r.fetcher.ReadEntryBundle, bIdx, r.cp.Size)
		if err != nil {
			return nil, fmt.Errorf("tlog: read entry bundle %d: %w", bIdx, err)
		}
		r.bundles[bIdx] = bundle
	}
	off := int(logIndex % layout.EntryBundleWidth)
	if off >= len(bundle.Entries) {
		return nil, fmt.Errorf("tlog: entry bundle %d has %d entries, need offset %d", bIdx, len(bundle.Entries), off)
	}
	return bundle.Entries[off], nil
}

// Payload returns the exact stored payload span at logIndex — the signed
// bytes, spliced out with a span scanner and never re-serialized (the span
// rule). When wantLeafHash is non-empty (hex, as the index stores it) the
// envelope is re-hashed and checked against it first, so a caller never
// reads bytes the index does not vouch for.
func (r *BundleReader) Payload(ctx context.Context, logIndex uint64, wantLeafHash string) ([]byte, error) {
	envelope, err := r.Envelope(ctx, logIndex)
	if err != nil {
		return nil, err
	}
	if wantLeafHash != "" {
		if got := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(envelope)); got != wantLeafHash {
			return nil, fmt.Errorf("tlog: envelope at log index %d does not match the indexed leaf hash — reindex", logIndex)
		}
	}
	env, err := ParseEnvelope(envelope)
	if err != nil {
		return nil, fmt.Errorf("tlog: log index %d: %w", logIndex, err)
	}
	return env.Payload, nil
}
