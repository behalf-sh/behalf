package index

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// Stats describes one replay pass over the entry bundles.
type Stats struct {
	Origin string // checkpoint origin of the log
	From   uint64 // first log index this pass walked
	To     uint64 // checkpoint tree size: the pass covered [From, To)
	// Indexed is the number of rows written by this pass (To - From).
	Indexed int
	// Duplicates is how many of those rows were duplicate leaves,
	// recorded with duplicate_of pointing at the first occurrence (Q46).
	Duplicates int
}

// Rebuild wipes the receipts table and reconstructs the entire index by
// streaming the entry bundles from log index 0 to the published checkpoint
// tree size. This is the Q76 restore path in its entirety: the index is
// never restored from backup, always rebuilt from the log. Deterministic —
// two rebuilds of the same log produce byte-identical table contents.
//
// The keys table is preserved: registered JWKs are the one thing the entry
// bundles do not carry (envelopes name keys by thumbprint only).
func Rebuild(ctx context.Context, logDir string) (*Stats, error) {
	db, err := Open(ctx, logDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	return followDB(ctx, db, logDir, 0, true)
}

// Follow runs one incremental catch-up pass: from tree_size_indexed to the
// current published checkpoint size, over the same code path as Rebuild's
// loop. Rows the ingest path already wrote are re-derived idempotently
// (identical bytes), so following after live ingest is safe.
func Follow(ctx context.Context, logDir string) (*Stats, error) {
	db, err := Open(ctx, logDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	from, err := db.TreeSizeIndexed()
	if err != nil {
		return nil, err
	}
	return followDB(ctx, db, logDir, from, false)
}

// readCheckpoint reads and signature-verifies the log's published
// checkpoint, returning its origin and tree size. The verifier key is the
// log's own (logDir/keys/checkpoint.vkey) — the same convention the log
// service writes.
func readCheckpoint(ctx context.Context, logDir string) (origin string, size uint64, err error) {
	vkeyRaw, err := os.ReadFile(filepath.Join(logDir, "keys", "checkpoint.vkey"))
	if err != nil {
		return "", 0, fmt.Errorf("index: read verifier key: %w", err)
	}
	verifier, err := note.NewVerifier(strings.TrimSpace(string(vkeyRaw)))
	if err != nil {
		return "", 0, fmt.Errorf("index: verifier key: %w", err)
	}
	raw, err := (&client.FileFetcher{Root: logDir}).ReadCheckpoint(ctx)
	if err != nil {
		return "", 0, fmt.Errorf("index: read checkpoint: %w", err)
	}
	cp, _, _, err := f_log.ParseCheckpoint(raw, verifier.Name(), verifier)
	if err != nil {
		return "", 0, fmt.Errorf("index: parse checkpoint: %w", err)
	}
	return cp.Origin, cp.Size, nil
}

// followDB walks the entry bundles for log indices [from, checkpoint size)
// inside one transaction, recording a row per leaf, then advances the meta
// markers. With wipe set it deletes all receipts rows first (Rebuild);
// wipe and the walk commit atomically, so a failed rebuild never leaves a
// half-empty index behind.
func followDB(ctx context.Context, db *DB, logDir string, from uint64, wipe bool) (*Stats, error) {
	origin, size, err := readCheckpoint(ctx, logDir)
	if err != nil {
		return nil, err
	}
	if !wipe {
		cur, err := db.LogOrigin()
		if err != nil {
			return nil, err
		}
		if cur != "" && cur != origin {
			return nil, fmt.Errorf("index: index.db was built from log origin %q but the checkpoint says %q — reindex", cur, origin)
		}
		if from > size {
			return nil, fmt.Errorf("index: tree_size_indexed %d exceeds the checkpoint tree size %d — the log went backwards; verify the restore, then reindex (Q76)", from, size)
		}
	}
	stats := &Stats{Origin: origin, From: from, To: size}

	tx, err := db.sql.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if wipe {
		if _, err := tx.Exec(`DELETE FROM receipts`); err != nil {
			return nil, fmt.Errorf("index: wipe receipts: %w", err)
		}
	}

	fetcher := client.FileFetcher{Root: logDir}
	var (
		bundle     api.EntryBundle
		bundleIdx  uint64
		haveBundle bool
	)
	for i := from; i < size; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		bIdx := i / layout.EntryBundleWidth
		if !haveBundle || bIdx != bundleIdx {
			bundle, err = client.GetEntryBundle(ctx, fetcher.ReadEntryBundle, bIdx, size)
			if err != nil {
				return nil, fmt.Errorf("index: read entry bundle %d: %w", bIdx, err)
			}
			bundleIdx, haveBundle = bIdx, true
		}
		off := int(i % layout.EntryBundleWidth)
		if off >= len(bundle.Entries) {
			return nil, fmt.Errorf("index: entry bundle %d has %d entries, need offset %d", bIdx, len(bundle.Entries), off)
		}
		row, err := Extract(bundle.Entries[off])
		if err != nil {
			return nil, fmt.Errorf("index: log index %d: %w", i, err)
		}
		row.LogIndex = i
		canonical, err := record(tx, row)
		if err != nil {
			return nil, err
		}
		stats.Indexed++
		if canonical != nil {
			stats.Duplicates++
		}
	}

	if err := metaSet(tx, metaLogOrigin, origin); err != nil {
		return nil, err
	}
	if err := metaSet(tx, metaTreeSizeIndexed, strconv.FormatUint(size, 10)); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("index: commit replay: %w", err)
	}
	return stats, nil
}
