// Package index is the SQLite follower index of the behalf log: a derived,
// rebuildable projection of the Tessera tile directory (D1, Q55, Q56). The
// log is the source of truth; everything here is a materialised view
// replayable from the entry bundles, which is Tessera's own follower
// pattern. The index is never restored from backup — always rebuilt from
// the log (Q76) — and the authoritative order everywhere is the log index
// (Q58, Q82).
//
// Column discipline (Q26, receipt-schema-v1.md §1): every receipts column
// is an ingest-side projection of fields read out of the stored envelope's
// payload span. The payload bytes themselves are never re-serialized — the
// read path extracts scalar fields and, for reconstruction, splices the
// exact stored span back out (the span rule).
//
// Duplicate collapse (Q46): the index collapses on receipt_id. A duplicate
// leaf — the same receipt_id appearing again at a later log index, which
// only the crash race can produce — is recorded with duplicate_of pointing
// at the first occurrence, and run views exclude duplicates by default. The
// canonical row for a receipt_id is always its lowest log index.
package index

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, no cgo
)

// FileName is the SQLite index file inside the log dir.
const FileName = "index.db"

// SchemaVersion is the follower index schema this package reads and
// writes. An index.db carrying an unknown version is refused: the fix is
// always to delete it and rebuild from the log (Q76), never to migrate
// data forward by hand.
const SchemaVersion = "behalf.sh/index/v1"

// Meta table keys.
const (
	metaSchemaVersion   = "schema_version"
	metaLogOrigin       = "log_origin"
	metaTreeSizeIndexed = "tree_size_indexed"
)

// receiptsTableSQL renders the v1 receipts table DDL under name (the
// migration path creates it under a temporary name before renaming).
func receiptsTableSQL(name string) string {
	return `CREATE TABLE IF NOT EXISTS ` + name + `(
	log_index                INTEGER PRIMARY KEY,
	receipt_id               TEXT NOT NULL,
	leaf_hash                TEXT,
	kind                     TEXT,
	run_id                   TEXT,
	run_id_provenance        TEXT,
	trace_id                 TEXT,
	session_id               TEXT,
	txn                      TEXT,
	acti                     TEXT,
	conversation_id          TEXT,
	captured_at              TEXT,
	emitter_jkt              TEXT,
	emitter_counter          INTEGER,
	actor_jkt                TEXT,
	operation_name           TEXT,
	operation_target         TEXT,
	outcome_status           TEXT,
	attribution_verification TEXT,
	attribution_class        TEXT,
	step_key                 TEXT,
	duplicate_of             INTEGER NULL
)`
}

// schemaSQL is the complete v1 schema. receipt_id uniqueness is enforced as
// a partial unique index over canonical rows only: a duplicate leaf gets its
// own row (log_index is the primary key) with duplicate_of set, so declaring
// the column UNIQUE outright would make the Q46 crash-race duplicate
// unrepresentable.
var schemaSQL = receiptsTableSQL("receipts") + `;
CREATE UNIQUE INDEX IF NOT EXISTS receipts_by_receipt_id_canonical ON receipts(receipt_id) WHERE duplicate_of IS NULL;
CREATE INDEX IF NOT EXISTS receipts_by_receipt_id ON receipts(receipt_id);
CREATE INDEX IF NOT EXISTS receipts_by_run_id ON receipts(run_id);
CREATE INDEX IF NOT EXISTS receipts_by_step_key ON receipts(step_key);
CREATE INDEX IF NOT EXISTS receipts_by_captured_at ON receipts(captured_at);
CREATE TABLE IF NOT EXISTS keys(
	jkt TEXT PRIMARY KEY,
	jwk TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta(
	k TEXT PRIMARY KEY,
	v TEXT NOT NULL
);`

// rowCols is the receipts column list, in schema order — the single source
// of truth for every SELECT and INSERT in this package.
const rowCols = "log_index, receipt_id, leaf_hash, kind, run_id, run_id_provenance, " +
	"trace_id, session_id, txn, acti, conversation_id, captured_at, " +
	"emitter_jkt, emitter_counter, actor_jkt, operation_name, operation_target, " +
	"outcome_status, attribution_verification, attribution_class, step_key, duplicate_of"

// Row is one receipts-table row: the indexed projection of one log leaf.
// All six correlation keys are columns; only run_id is required at ingest
// (Q7). String fields are stored as written by Extract — empty string for
// an absent optional field.
type Row struct {
	LogIndex  uint64
	ReceiptID string
	LeafHash  string // hex, RFC 6962 leaf hash of the stored envelope bytes

	Kind            string
	RunID           string
	RunIDProvenance string // which Q7 fallback produced run_id — grouping stays honest

	TraceID        string
	SessionID      string
	Txn            string
	Acti           string
	ConversationID string

	CapturedAt     string
	EmitterJKT     string
	EmitterCounter int64
	ActorJKT       string

	OperationName   string
	OperationTarget string
	OutcomeStatus   string

	AttributionVerification string
	AttributionClass        string
	StepKey                 string

	// DuplicateOf is nil for a canonical row; for a duplicate leaf it is
	// the log index of the first occurrence of this receipt_id (Q46).
	DuplicateOf *uint64
}

// DB is an open follower index.
type DB struct {
	sql *sql.DB
	dir string
}

// Open opens (creating or migrating as needed) the follower index inside
// the log dir. A pre-existing minimal seed schema (the Week-2 log
// service's dedup window) is migrated in place: the dedup columns are
// carried over so the Q46 window is never lost, and the remaining columns
// are re-derived by replaying the log up to the published checkpoint —
// rebuilt, not restored (Q76).
func Open(ctx context.Context, dir string) (*DB, error) {
	sqldb, err := sql.Open("sqlite", filepath.Join(dir, FileName))
	if err != nil {
		return nil, fmt.Errorf("index: open: %w", err)
	}
	// One connection: the index has a single writer and modernc/sqlite
	// handles its own locking; this avoids SQLITE_BUSY noise and keeps
	// row iteration from deadlocking against concurrent statements.
	sqldb.SetMaxOpenConns(1)
	db := &DB{sql: sqldb, dir: dir}
	if err := db.initSchema(ctx); err != nil {
		sqldb.Close()
		return nil, err
	}
	return db, nil
}

// Close closes the underlying database.
func (db *DB) Close() error { return db.sql.Close() }

func (db *DB) initSchema(ctx context.Context) error {
	seed, err := db.isSeedSchema()
	if err != nil {
		return err
	}
	if seed {
		return db.migrateSeed(ctx)
	}
	if _, err := db.sql.Exec(schemaSQL); err != nil {
		return fmt.Errorf("index: init schema: %w", err)
	}
	v, err := metaGet(db.sql, metaSchemaVersion)
	if err != nil {
		return err
	}
	switch v {
	case "":
		return metaSet(db.sql, metaSchemaVersion, SchemaVersion)
	case SchemaVersion:
		return nil
	default:
		return fmt.Errorf("index: index.db has schema version %q, this build supports %q — delete index.db and reindex (the index is always rebuilt, never restored: Q76)", v, SchemaVersion)
	}
}

// isSeedSchema reports whether index.db holds the pre-v1 minimal schema the
// log service seeded (receipts with four columns, no meta table). Detection
// is by column shape, not table presence, so a partially created v1 schema
// is never misread as the seed.
func (db *DB) isSeedSchema() (bool, error) {
	var n int
	err := db.sql.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'receipts'`).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("index: inspect schema: %w", err)
	}
	if n == 0 {
		return false, nil
	}
	rows, err := db.sql.Query(`PRAGMA table_info(receipts)`)
	if err != nil {
		return false, fmt.Errorf("index: inspect receipts: %w", err)
	}
	defer rows.Close()
	hasDuplicateOf := false
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    any
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == "duplicate_of" {
			hasDuplicateOf = true
		}
	}
	return !hasDuplicateOf, rows.Err()
}

// migrateSeed rebuilds the seed schema into v1 in place. The four seed
// columns (receipt_id, log_index, run_id, leaf_hash) are copied so the
// persistent dedup window survives even for entries newer than the last
// published checkpoint; every other column is then re-derived by replaying
// the log from index 0 — the same code path as Rebuild.
func (db *DB) migrateSeed(ctx context.Context) error {
	tx, err := db.sql.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmts := []string{
		receiptsTableSQL("receipts_v1_migration"),
		`INSERT INTO receipts_v1_migration(log_index, receipt_id, run_id, leaf_hash)
		 SELECT log_index, receipt_id, run_id, leaf_hash FROM receipts`,
		`DROP TABLE receipts`,
		`ALTER TABLE receipts_v1_migration RENAME TO receipts`,
		schemaSQL, // indexes, keys, meta — receipts already exists
	}
	for _, s := range stmts {
		if _, err := tx.Exec(s); err != nil {
			return fmt.Errorf("index: migrate seed schema: %w", err)
		}
	}
	if err := metaSet(tx, metaSchemaVersion, SchemaVersion); err != nil {
		return err
	}
	if err := metaSet(tx, metaTreeSizeIndexed, "0"); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("index: migrate seed schema: %w", err)
	}
	// Enrich the copied rows from the log. A dir without a published
	// checkpoint has nothing to replay yet; the next Follow catches up.
	if _, err := followDB(ctx, db, db.dir, 0, false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("index: replay after migration: %w", err)
	}
	return nil
}

// execQueryer is satisfied by both *sql.DB and *sql.Tx.
type execQueryer interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
	Query(query string, args ...any) (*sql.Rows, error)
}

type rowScanner interface{ Scan(dest ...any) error }

// scanRow scans one receipts row in rowCols order. NULL text columns (only
// possible on migrated rows not yet re-derived) scan as empty strings.
func scanRow(sc rowScanner) (*Row, error) {
	var (
		r        Row
		logIdx   int64
		counter  sql.NullInt64
		dup      sql.NullInt64
		nullable [18]sql.NullString
	)
	if err := sc.Scan(
		&logIdx, &r.ReceiptID, &nullable[0], &nullable[1], &nullable[2], &nullable[3],
		&nullable[4], &nullable[5], &nullable[6], &nullable[7], &nullable[8], &nullable[9],
		&nullable[10], &counter, &nullable[11], &nullable[12], &nullable[13],
		&nullable[14], &nullable[15], &nullable[16], &nullable[17], &dup,
	); err != nil {
		return nil, err
	}
	r.LogIndex = uint64(logIdx)
	r.LeafHash = nullable[0].String
	r.Kind = nullable[1].String
	r.RunID = nullable[2].String
	r.RunIDProvenance = nullable[3].String
	r.TraceID = nullable[4].String
	r.SessionID = nullable[5].String
	r.Txn = nullable[6].String
	r.Acti = nullable[7].String
	r.ConversationID = nullable[8].String
	r.CapturedAt = nullable[9].String
	r.EmitterJKT = nullable[10].String
	r.EmitterCounter = counter.Int64
	r.ActorJKT = nullable[11].String
	r.OperationName = nullable[12].String
	r.OperationTarget = nullable[13].String
	r.OutcomeStatus = nullable[14].String
	r.AttributionVerification = nullable[15].String
	r.AttributionClass = nullable[16].String
	r.StepKey = nullable[17].String
	if dup.Valid {
		v := uint64(dup.Int64)
		r.DuplicateOf = &v
	}
	return &r, nil
}

// lookupCanonical returns the canonical (duplicate_of IS NULL) row for
// receiptID, or nil if none. A non-negative before bounds the search to
// rows below that log index, which is what makes replay idempotent: a row
// being re-derived never resolves itself as its own canonical.
func lookupCanonical(q execQueryer, receiptID string, before int64) (*Row, error) {
	query := `SELECT ` + rowCols + ` FROM receipts WHERE receipt_id = ? AND duplicate_of IS NULL`
	args := []any{receiptID}
	if before >= 0 {
		query += ` AND log_index < ?`
		args = append(args, before)
	}
	query += ` ORDER BY log_index LIMIT 1`
	r, err := scanRow(q.QueryRow(query, args...))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("index: lookup %s: %w", receiptID, err)
	}
	return r, nil
}

// record writes one extracted row, collapsing on receipt_id (Q46): if a
// canonical row with the same receipt_id exists at a lower log index, the
// new row is recorded with duplicate_of pointing at it and the canonical
// row is returned; a nil canonical means this row is itself canonical.
// Re-recording the same log index is an idempotent overwrite (replay).
func record(q execQueryer, row Row) (*Row, error) {
	canonical, err := lookupCanonical(q, row.ReceiptID, int64(row.LogIndex))
	if err != nil {
		return nil, err
	}
	var dup any
	if canonical != nil {
		dup = int64(canonical.LogIndex)
	}
	_, err = q.Exec(`INSERT INTO receipts(`+rowCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
ON CONFLICT(log_index) DO UPDATE SET
	receipt_id = excluded.receipt_id, leaf_hash = excluded.leaf_hash, kind = excluded.kind,
	run_id = excluded.run_id, run_id_provenance = excluded.run_id_provenance,
	trace_id = excluded.trace_id, session_id = excluded.session_id, txn = excluded.txn,
	acti = excluded.acti, conversation_id = excluded.conversation_id,
	captured_at = excluded.captured_at, emitter_jkt = excluded.emitter_jkt,
	emitter_counter = excluded.emitter_counter, actor_jkt = excluded.actor_jkt,
	operation_name = excluded.operation_name, operation_target = excluded.operation_target,
	outcome_status = excluded.outcome_status,
	attribution_verification = excluded.attribution_verification,
	attribution_class = excluded.attribution_class, step_key = excluded.step_key,
	duplicate_of = excluded.duplicate_of`,
		int64(row.LogIndex), row.ReceiptID, row.LeafHash, row.Kind, row.RunID, row.RunIDProvenance,
		row.TraceID, row.SessionID, row.Txn, row.Acti, row.ConversationID, row.CapturedAt,
		row.EmitterJKT, row.EmitterCounter, row.ActorJKT, row.OperationName, row.OperationTarget,
		row.OutcomeStatus, row.AttributionVerification, row.AttributionClass, row.StepKey, dup)
	if err != nil {
		return nil, fmt.Errorf("index: record log index %d: %w", row.LogIndex, err)
	}
	return canonical, nil
}

// LookupCanonical returns the canonical row for receiptID, or (nil, nil)
// if the receipt_id has never been indexed. This is the ingest dedup
// lookup (Q46).
func (db *DB) LookupCanonical(receiptID string) (*Row, error) {
	return lookupCanonical(db.sql, receiptID, -1)
}

// Record writes one extracted row (see record). The ingest path calls this
// as each durability ack resolves, so the follower stays current without a
// replay; Rebuild and Follow produce byte-identical rows from the log.
func (db *DB) Record(row Row) (*Row, error) {
	return record(db.sql, row)
}

// RunRows returns the canonical rows for runID in log-index order — the
// run view, excluding duplicates by default (Q46, Q82).
func (db *DB) RunRows(runID string) ([]Row, error) {
	return db.runRowsAfter(runID, -1)
}

func (db *DB) runRowsAfter(runID string, after int64) ([]Row, error) {
	rows, err := db.sql.Query(
		`SELECT `+rowCols+` FROM receipts
		 WHERE run_id = ? AND duplicate_of IS NULL AND log_index > ?
		 ORDER BY log_index`, runID, after)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Row
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *r)
	}
	return out, rows.Err()
}

// RegisterKey stores (or refreshes) a public key JWK by its RFC 7638
// thumbprint, for the export bridge's header. Note: the keys table is the
// one part of index.db that is NOT reconstructible from the entry bundles
// (envelopes carry only thumbprints); keys are re-registered by the log
// service and ingest paths on next use after a rebuild.
func (db *DB) RegisterKey(jkt, jwkJSON string) error {
	_, err := db.sql.Exec(`INSERT OR REPLACE INTO keys(jkt, jwk) VALUES(?,?)`, jkt, jwkJSON)
	return err
}

// Keys returns all registered keys as jkt -> JWK JSON, plus the jkts in
// ascending order (deterministic header order for exports).
func (db *DB) Keys() (map[string]string, []string, error) {
	rows, err := db.sql.Query(`SELECT jkt, jwk FROM keys ORDER BY jkt`)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	m := map[string]string{}
	var order []string
	for rows.Next() {
		var jkt, jwk string
		if err := rows.Scan(&jkt, &jwk); err != nil {
			return nil, nil, err
		}
		m[jkt] = jwk
		order = append(order, jkt)
	}
	return m, order, rows.Err()
}

func metaGet(q execQueryer, k string) (string, error) {
	var v string
	err := q.QueryRow(`SELECT v FROM meta WHERE k = ?`, k).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("index: meta %s: %w", k, err)
	}
	return v, nil
}

func metaSet(q execQueryer, k, v string) error {
	_, err := q.Exec(`INSERT INTO meta(k, v) VALUES(?,?) ON CONFLICT(k) DO UPDATE SET v = excluded.v`, k, v)
	if err != nil {
		return fmt.Errorf("index: set meta %s: %w", k, err)
	}
	return nil
}

// TreeSizeIndexed returns the tree size the last Rebuild/Follow pass
// covered: every log index below it is indexed. Ingest-time Record calls
// do not advance it — only a replay pass does, after walking the bundles.
func (db *DB) TreeSizeIndexed() (uint64, error) {
	v, err := metaGet(db.sql, metaTreeSizeIndexed)
	if err != nil || v == "" {
		return 0, err
	}
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("index: meta tree_size_indexed %q: %w", v, err)
	}
	return n, nil
}

// LogOrigin returns the checkpoint origin of the log this index follows
// ("" until the first Rebuild/Follow pass records it).
func (db *DB) LogOrigin() (string, error) {
	return metaGet(db.sql, metaLogOrigin)
}

// CanonicalDump renders the receipts table as deterministic text, ordered
// by log index, one row per line with columns tab-separated in schema
// order (duplicate_of renders as "-" when NULL). This is the comparison
// form for the rebuild-determinism guarantee: two rebuilds of the same log
// must produce byte-identical dumps.
func CanonicalDump(db *DB) (string, error) {
	rows, err := db.sql.Query(`SELECT ` + rowCols + ` FROM receipts ORDER BY log_index`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return "", err
		}
		dup := "-"
		if r.DuplicateOf != nil {
			dup = strconv.FormatUint(*r.DuplicateOf, 10)
		}
		fmt.Fprintf(&b, "%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.LogIndex, r.ReceiptID, r.LeafHash, r.Kind, r.RunID, r.RunIDProvenance,
			r.TraceID, r.SessionID, r.Txn, r.Acti, r.ConversationID, r.CapturedAt,
			r.EmitterJKT, r.EmitterCounter, r.ActorJKT, r.OperationName, r.OperationTarget,
			r.OutcomeStatus, r.AttributionVerification, r.AttributionClass, r.StepKey, dup)
	}
	return b.String(), rows.Err()
}
