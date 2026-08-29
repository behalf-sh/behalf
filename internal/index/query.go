package index

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"strconv"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"

	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// RunSummary is one row of ListRuns: a run's receipt count, capture-time
// range, and attribution rollup (the stored receipt-level verification
// state, Q12/Q86). Duplicates are excluded (Q46).
type RunSummary struct {
	RunID           string
	Receipts        int64
	FirstCapturedAt string
	LastCapturedAt  string
	Verified        int64
	Asserted        int64
	Broken          int64
}

// ListRuns summarises every run in the index, ordered by each run's first
// log index — the log's own order (Q58), not alphabetical.
func ListRuns(db *DB) ([]RunSummary, error) {
	rows, err := db.sql.Query(`
SELECT run_id, COUNT(*),
       MIN(captured_at), MAX(captured_at),
       SUM(CASE WHEN attribution_verification = 'verified' THEN 1 ELSE 0 END),
       SUM(CASE WHEN attribution_verification = 'asserted' THEN 1 ELSE 0 END),
       SUM(CASE WHEN attribution_verification = 'broken' THEN 1 ELSE 0 END)
FROM receipts
WHERE duplicate_of IS NULL
GROUP BY run_id
ORDER BY MIN(log_index)`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RunSummary
	for rows.Next() {
		var (
			s           RunSummary
			runID       sql.NullString
			first, last sql.NullString
		)
		if err := rows.Scan(&runID, &s.Receipts, &first, &last, &s.Verified, &s.Asserted, &s.Broken); err != nil {
			return nil, err
		}
		s.RunID = runID.String
		s.FirstCapturedAt = first.String
		s.LastCapturedAt = last.String
		out = append(out, s)
	}
	return out, rows.Err()
}

// Reconstruct streams one run as NDJSON in log-index order (Q82): the
// global total order filtered to the run view, duplicates excluded (Q46).
// Each line is
//
//	{"log_index":N,"leaf_hash":"<hex>","payload":<verbatim receipt JSON>}
//
// where payload is the exact stored payload span spliced out of the entry
// bundle — the signed bytes, never re-serialized (the span rule). Assembly
// is byte concatenation.
//
// after is the pagination cursor: only rows with log_index > after are
// emitted (pass a negative value for the start of the run; the last line's
// log_index is the next cursor). An unknown run errors only on an
// uncursored call — a cursor past the end of a run legitimately yields
// nothing.
//
// Before splicing, every envelope is re-hashed and checked against the
// indexed leaf hash, so a reconstruction never emits bytes the index does
// not vouch for.
func Reconstruct(ctx context.Context, db *DB, logDir, runID string, after int64, w io.Writer) error {
	rows, err := db.runRowsAfter(runID, after)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		if after < 0 {
			return fmt.Errorf("index: no receipts indexed for run %q", runID)
		}
		return nil
	}

	// The published checkpoint bounds what is reconstructable: only
	// entries a signed checkpoint commits to.
	_, size, err := readCheckpoint(ctx, logDir)
	if err != nil {
		return err
	}
	fetcher := client.FileFetcher{Root: logDir}
	bundles := map[uint64]api.EntryBundle{}
	for _, row := range rows {
		if row.LogIndex >= size {
			return fmt.Errorf("index: receipt %s at log index %d is beyond the published checkpoint (size %d); wait for the next checkpoint",
				row.ReceiptID, row.LogIndex, size)
		}
		bIdx := row.LogIndex / layout.EntryBundleWidth
		bundle, ok := bundles[bIdx]
		if !ok {
			bundle, err = client.GetEntryBundle(ctx, fetcher.ReadEntryBundle, bIdx, size)
			if err != nil {
				return fmt.Errorf("index: read entry bundle %d: %w", bIdx, err)
			}
			bundles[bIdx] = bundle
		}
		off := int(row.LogIndex % layout.EntryBundleWidth)
		if off >= len(bundle.Entries) {
			return fmt.Errorf("index: entry bundle %d has %d entries, need offset %d", bIdx, len(bundle.Entries), off)
		}
		envelope := bundle.Entries[off]

		// Integrity: the stored bytes must still hash to the indexed leaf.
		if got := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(envelope)); got != row.LeafHash {
			return fmt.Errorf("index: envelope at log index %d does not match the indexed leaf hash — reindex", row.LogIndex)
		}
		payload, err := jsonspan.ExtractTopLevelValue(envelope, "payload")
		if err != nil {
			return fmt.Errorf("index: log index %d: %w", row.LogIndex, err)
		}

		line := make([]byte, 0, len(payload)+len(row.LeafHash)+48)
		line = append(line, `{"log_index":`...)
		line = strconv.AppendUint(line, row.LogIndex, 10)
		line = append(line, `,"leaf_hash":"`...)
		line = append(line, row.LeafHash...)
		line = append(line, `","payload":`...)
		line = append(line, payload...) // the span rule: stored bytes, verbatim
		line = append(line, "}\n"...)
		if _, err := w.Write(line); err != nil {
			return err
		}
	}
	return nil
}
