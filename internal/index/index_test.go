// Tests for the follower index. External test package: internal/tlog
// imports internal/index (the dedup window), so the log-driven tests here
// must sit outside package index to avoid an import cycle.
package index_test

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/transparency-dev/merkle/rfc6962"
	_ "modernc.org/sqlite"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// envelopesFor generates the run's sealed payloads and wraps each in a
// stored envelope signed by the fixture emitter key (deterministic:
// Ed25519 signatures are deterministic, so equal specs give equal bytes).
func envelopesFor(t *testing.T, spec fixture.Spec) (envs, payloads [][]byte) {
	t.Helper()
	res, err := fixture.Generate(spec)
	if err != nil {
		t.Fatal(err)
	}
	emitter := testkeys.Emitter()
	for _, payload := range res.Payloads {
		sig := dsse.Sign(emitter.Private, exportv1.PayloadTypeReceipt, payload)
		envs = append(envs, tlog.BuildEnvelope(exportv1.PayloadTypeReceipt, payload, emitter.JKT, sig))
	}
	return envs, res.Payloads
}

// ingest appends the given fixture runs to the log at dir (creating it on
// first use) through the production ingest path, then closes the log —
// which waits for a checkpoint covering everything appended.
func ingest(t *testing.T, dir string, specs ...fixture.Spec) {
	t.Helper()
	ctx := context.Background()
	key, err := tlog.LoadCheckpointKey(dir)
	if err != nil {
		key, err = tlog.GenerateCheckpointKey("behalf.sh/log/index-test")
		if err != nil {
			t.Fatal(err)
		}
		if err := tlog.SaveCheckpointKey(dir, key); err != nil {
			t.Fatal(err)
		}
	}
	l, err := tlog.Open(ctx, dir, key, tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	emitter := testkeys.Emitter()
	jwk, err := json.Marshal(emitter.JWK)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterKey(emitter.JKT, string(jwk)); err != nil {
		t.Fatal(err)
	}
	for _, spec := range specs {
		envs, _ := envelopesFor(t, spec)
		var pendings []*tlog.Pending
		for i, env := range envs {
			p, err := l.BeginAppend(ctx, env)
			if err != nil {
				t.Fatalf("%s %d: %v", spec.RunID, i, err)
			}
			pendings = append(pendings, p)
		}
		for i, p := range pendings {
			if _, err := p.Wait(ctx); err != nil {
				t.Fatalf("%s %d: %v", spec.RunID, i, err)
			}
		}
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func openDB(t *testing.T, dir string) *index.DB {
	t.Helper()
	db, err := index.Open(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// dump opens the index, renders the canonical dump, and closes it again.
func dump(t *testing.T, dir string) string {
	t.Helper()
	db := openDB(t, dir)
	defer db.Close()
	d, err := index.CanonicalDump(db)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// rawExec runs raw SQL against index.db directly — the tests' stand-in for
// external states (a stale follower, a pre-v1 seed schema).
func rawExec(t *testing.T, dir string, stmts ...string) {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(dir, "index.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
}

// TestRebuildDeterminism: two rebuilds of the same log produce
// byte-identical table contents (and identical meta).
func TestRebuildDeterminism(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	ingest(t, dir, fixture.Run9F2A(), fixture.RunC71E())

	stats1, err := index.Rebuild(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	dump1 := dump(t, dir)
	stats2, err := index.Rebuild(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	dump2 := dump(t, dir)

	if stats1.To != 94 || stats1.Indexed != 94 || stats1.Duplicates != 0 {
		t.Fatalf("first rebuild stats: %+v", stats1)
	}
	if *stats1 != *stats2 {
		t.Fatalf("rebuild stats differ: %+v vs %+v", stats1, stats2)
	}
	if dump1 == "" || strings.Count(dump1, "\n") != 94 {
		t.Fatalf("dump has %d lines, want 94", strings.Count(dump1, "\n"))
	}
	if dump1 != dump2 {
		t.Fatal("two rebuilds of the same log produced different canonical dumps")
	}

	db := openDB(t, dir)
	defer db.Close()
	size, err := db.TreeSizeIndexed()
	if err != nil {
		t.Fatal(err)
	}
	if size != 94 {
		t.Fatalf("tree_size_indexed = %d, want 94", size)
	}
	origin, err := db.LogOrigin()
	if err != nil {
		t.Fatal(err)
	}
	if origin != "behalf.sh/log/index-test" {
		t.Fatalf("log_origin = %q", origin)
	}
}

// TestRebuildEqualsIngest: the index built incrementally during ingest is
// byte-identical (modulo meta) to the index rebuilt from scratch, because
// both derive every row from the same stored envelope bytes.
func TestRebuildEqualsIngest(t *testing.T) {
	dir := t.TempDir()
	ingest(t, dir, fixture.Run9F2A(), fixture.RunC71E())

	ingestDump := dump(t, dir)
	if _, err := index.Rebuild(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	rebuildDump := dump(t, dir)
	if ingestDump != rebuildDump {
		t.Fatal("ingest-built index differs from rebuilt index")
	}
}

// TestReconstruct: NDJSON in strictly ascending log-index order, payload
// spans byte-equal to the fixture originals, leaf hashes matching the
// envelopes, and the ?after cursor honoured.
func TestReconstruct(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	ingest(t, dir, fixture.Run9F2A(), fixture.RunC71E())
	envs, payloads := envelopesFor(t, fixture.RunC71E())

	db := openDB(t, dir)
	defer db.Close()

	var buf bytes.Buffer
	if err := index.Reconstruct(ctx, db, dir, "run_c71e", -1, &buf); err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(buf.Bytes(), []byte("\n")), []byte("\n"))
	if len(lines) != 47 {
		t.Fatalf("reconstruction has %d lines, want 47", len(lines))
	}
	prev := int64(-1)
	for i, line := range lines {
		idxSpan, err := jsonspan.ExtractTopLevelValue(line, "log_index")
		if err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		logIdx, err := strconv.ParseInt(string(idxSpan), 10, 64)
		if err != nil {
			t.Fatalf("line %d log_index: %v", i, err)
		}
		if logIdx <= prev {
			t.Fatalf("line %d: log_index %d not strictly ascending after %d", i, logIdx, prev)
		}
		prev = logIdx
		// run_c71e was ingested second: its receipts occupy indices 47..93.
		if logIdx != int64(47+i) {
			t.Fatalf("line %d: log_index %d, want %d", i, logIdx, 47+i)
		}
		span, err := jsonspan.ExtractTopLevelValue(line, "payload")
		if err != nil {
			t.Fatalf("line %d payload: %v", i, err)
		}
		if !bytes.Equal(span, payloads[i]) {
			t.Fatalf("line %d: reconstructed payload span differs from the fixture original", i)
		}
		lhSpan, err := jsonspan.ExtractTopLevelValue(line, "leaf_hash")
		if err != nil {
			t.Fatalf("line %d leaf_hash: %v", i, err)
		}
		var lh string
		if err := json.Unmarshal(lhSpan, &lh); err != nil {
			t.Fatalf("line %d leaf_hash: %v", i, err)
		}
		if want := hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(envs[i])); lh != want {
			t.Fatalf("line %d: leaf_hash %s, want %s", i, lh, want)
		}
	}

	// Cursor: after the 10th line's log index, exactly the remaining 37
	// lines come back, starting one past the cursor.
	var buf2 bytes.Buffer
	if err := index.Reconstruct(ctx, db, dir, "run_c71e", 47+9, &buf2); err != nil {
		t.Fatal(err)
	}
	rest := bytes.Split(bytes.TrimSuffix(buf2.Bytes(), []byte("\n")), []byte("\n"))
	if len(rest) != 37 {
		t.Fatalf("cursored reconstruction has %d lines, want 37", len(rest))
	}
	if !bytes.HasPrefix(rest[0], []byte(`{"log_index":57,`)) {
		t.Fatalf("cursored reconstruction starts %q, want log_index 57", rest[0][:24])
	}
	// A cursor past the end of the run yields nothing, without error.
	var buf3 bytes.Buffer
	if err := index.Reconstruct(ctx, db, dir, "run_c71e", 93, &buf3); err != nil {
		t.Fatal(err)
	}
	if buf3.Len() != 0 {
		t.Fatalf("cursor at end returned %d bytes", buf3.Len())
	}
	// An unknown run errors on an uncursored call.
	if err := index.Reconstruct(ctx, db, dir, "run_nope", -1, &bytes.Buffer{}); err == nil {
		t.Fatal("reconstructing an unknown run did not error")
	}
}

// TestListRuns: 47/47 receipt counts, capture-time ranges, and the
// attribution rollup — the stored receipt-level state, which is the weakest
// hop of the chain (Q12). run_9f2a's three hops all verify; run_c71e's leaf
// hop is caller-asserted, so every receipt of that run rolls up to
// 'asserted'.
func TestListRuns(t *testing.T) {
	dir := t.TempDir()
	ingest(t, dir, fixture.Run9F2A(), fixture.RunC71E())

	db := openDB(t, dir)
	defer db.Close()
	runs, err := index.ListRuns(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 {
		t.Fatalf("ListRuns returned %d runs, want 2", len(runs))
	}
	want := []index.RunSummary{
		{RunID: "run_9f2a", Receipts: 47, FirstCapturedAt: "2026-08-25T22:04:00Z", LastCapturedAt: "2026-08-25T22:07:50Z", Verified: 47, Asserted: 0, Broken: 0},
		{RunID: "run_c71e", Receipts: 47, FirstCapturedAt: "2026-08-26T02:17:00Z", LastCapturedAt: "2026-08-26T02:20:50Z", Verified: 0, Asserted: 47, Broken: 0},
	}
	for i, w := range want {
		if runs[i] != w {
			t.Fatalf("run %d = %+v, want %+v", i, runs[i], w)
		}
	}
}

// TestFollowCatchUp: a follower whose index stopped at an earlier tree
// size catches up incrementally from the entry bundles, landing on exactly
// the state a full rebuild produces; a second pass is a no-op.
func TestFollowCatchUp(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	ingest(t, dir, fixture.Run9F2A())
	if _, err := index.Rebuild(ctx, dir); err != nil {
		t.Fatal(err)
	}

	// The log grows after the rebuild...
	ingest(t, dir, fixture.RunC71E())
	want := dump(t, dir)
	// ...and the follower goes stale: drop the rows the ingest path wrote
	// beyond the last replay watermark, leaving tree_size_indexed at 47.
	rawExec(t, dir, `DELETE FROM receipts WHERE log_index >= 47`)
	if got := strings.Count(dump(t, dir), "\n"); got != 47 {
		t.Fatalf("stale index has %d rows, want 47", got)
	}

	stats, err := index.Follow(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if stats.From != 47 || stats.To != 94 || stats.Indexed != 47 || stats.Duplicates != 0 {
		t.Fatalf("follow stats: %+v", stats)
	}
	if got := dump(t, dir); got != want {
		t.Fatal("follow catch-up differs from the ingest-built index")
	}

	// Idempotent: nothing new to index.
	again, err := index.Follow(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if again.From != 94 || again.To != 94 || again.Indexed != 0 {
		t.Fatalf("second follow stats: %+v", again)
	}
}

// TestRebuildRecoversDeletedIndex is the Q76 claim as a test: delete
// index.db entirely, rebuild from the log, and everything queryable — the
// rows, the run views, the dedup window — is recovered.
func TestRebuildRecoversDeletedIndex(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()
	ingest(t, dir, fixture.Run9F2A(), fixture.RunC71E())
	want := dump(t, dir)

	if err := os.Remove(filepath.Join(dir, tlog.IndexFileName)); err != nil {
		t.Fatal(err)
	}
	stats, err := index.Rebuild(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Indexed != 94 {
		t.Fatalf("rebuild stats: %+v", stats)
	}
	if got := dump(t, dir); got != want {
		t.Fatal("rebuilt index differs from the index before deletion")
	}

	db := openDB(t, dir)
	runs, err := index.ListRuns(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 2 || runs[0].Receipts != 47 || runs[1].Receipts != 47 {
		t.Fatalf("ListRuns after rebuild: %+v", runs)
	}
	db.Close()

	// The dedup window is part of what came back: re-appending an already
	// logged receipt is flagged duplicate against the original index.
	key, err := tlog.LoadCheckpointKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	l, err := tlog.Open(ctx, dir, key, tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close(ctx)
	envs, _ := envelopesFor(t, fixture.Run9F2A())
	res, err := l.Append(ctx, envs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !res.Duplicate || res.Index != 0 {
		t.Fatalf("post-rebuild duplicate append: %+v", res)
	}
}

// TestDuplicateCollapse: the index collapses on receipt_id (Q46) — a
// duplicate leaf records duplicate_of pointing at the first occurrence,
// and run views exclude duplicates by default.
func TestDuplicateCollapse(t *testing.T) {
	dir := t.TempDir()
	db := openDB(t, dir)
	defer db.Close()

	mk := func(logIdx uint64, receiptID string) index.Row {
		return index.Row{
			LogIndex:                logIdx,
			ReceiptID:               receiptID,
			LeafHash:                fmt.Sprintf("%064x", logIdx),
			Kind:                    "tool_call",
			RunID:                   "run_x",
			CapturedAt:              "2026-08-27T00:00:00Z",
			AttributionVerification: "asserted",
		}
	}
	if canonical, err := db.Record(mk(0, "r1")); err != nil || canonical != nil {
		t.Fatalf("first record: canonical=%v err=%v", canonical, err)
	}
	canonical, err := db.Record(mk(5, "r1"))
	if err != nil {
		t.Fatal(err)
	}
	if canonical == nil || canonical.LogIndex != 0 {
		t.Fatalf("duplicate record returned canonical %+v, want log index 0", canonical)
	}

	lk, err := db.LookupCanonical("r1")
	if err != nil {
		t.Fatal(err)
	}
	if lk == nil || lk.LogIndex != 0 {
		t.Fatalf("LookupCanonical = %+v, want log index 0", lk)
	}
	rows, err := db.RunRows("run_x")
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].LogIndex != 0 {
		t.Fatalf("RunRows includes duplicates: %+v", rows)
	}
	runs, err := index.ListRuns(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Receipts != 1 {
		t.Fatalf("ListRuns counts duplicates: %+v", runs)
	}
	d, err := index.CanonicalDump(db)
	if err != nil {
		t.Fatal(err)
	}
	var dupLine string
	for _, line := range strings.Split(strings.TrimSuffix(d, "\n"), "\n") {
		if strings.HasPrefix(line, "5\t") {
			dupLine = line
		}
	}
	if dupLine == "" || !strings.HasSuffix(dupLine, "\t0") {
		t.Fatalf("duplicate row does not carry duplicate_of=0: %q", dupLine)
	}
}

// TestMigrateSeedSchema: an index.db carrying the Week-2 minimal seed
// schema is migrated in place — the dedup window survives, and every other
// column is re-derived by replaying the log.
func TestMigrateSeedSchema(t *testing.T) {
	dir := t.TempDir()
	ingest(t, dir, fixture.Run9F2A())
	want := dump(t, dir)

	// Reshape index.db to the seed schema the log service used to write:
	// receipts(receipt_id PRIMARY KEY, log_index, run_id, leaf_hash), no meta.
	rawExec(t, dir,
		`CREATE TABLE seed(receipt_id TEXT PRIMARY KEY, log_index INTEGER NOT NULL, run_id TEXT, leaf_hash TEXT)`,
		`INSERT INTO seed(receipt_id, log_index, run_id, leaf_hash) SELECT receipt_id, log_index, run_id, leaf_hash FROM receipts`,
		`DROP TABLE receipts`,
		`DROP TABLE meta`,
		`ALTER TABLE seed RENAME TO receipts`,
	)

	db := openDB(t, dir) // migrates + replays
	defer db.Close()
	got, err := index.CanonicalDump(db)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatal("migrated index differs from the pre-migration index")
	}
	size, err := db.TreeSizeIndexed()
	if err != nil {
		t.Fatal(err)
	}
	if size != 47 {
		t.Fatalf("tree_size_indexed after migration = %d, want 47", size)
	}
	// The keys table survived the migration (it is not derivable from the
	// entry bundles): checkpoint key + fixture emitter key.
	_, order, err := db.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 {
		t.Fatalf("keys after migration: %v", order)
	}
}
