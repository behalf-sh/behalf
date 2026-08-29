// Licensed under the Functional Source License, Version 1.1, ALv2 Future
// License (FSL-1.1-ALv2) — NOT Apache-2.0 like the rest of this repository.
// See ../../LICENSE-FSL, the copy in this directory, and LICENSING.md.
// This version converts to Apache-2.0 two years after it is made available.

package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// `behalf-log rehydrate` streams one run with its payloads joined back on
// from the customer's own store (Q83, Q84).
//
// `reconstruct` streams the receipts. Receipts do not contain tool
// arguments — payloads are customer-held, and behalf's record holds the
// digest and the reference, never the content (Q34, Q35) — so a
// reconstruction on its own cannot show what the agent actually did. This
// command performs the join: for every receipt, look each payload digest up
// in the CAS and emit the content when the blob is there and hashes to its
// commitment, and a typed placeholder when it is not.
//
// Rehydration executes where the CAS lives (Q84): the v1 CLI reads the
// customer's local store directly. behalf sees none of this.
//
// # Exit status
//
//	0  every slot resolved, no slot contradicted its commitment
//	1  at least one payload no longer matches the digest committed in its
//	   signed receipt — the payload cover-up
//	2  usage
//
// A run whose blobs are entirely absent exits 0. Absence is a state, not a
// failure: a reconstruction full of placeholders is still verifiable
// evidence because the receipts carry the digests regardless (Q83). What
// exits 1 is a contradiction — bytes that are present and wrong.
//
// The failure line is machine-readable and uses the verifier's class
// vocabulary (docs/export-format-v1.md §5), extended with one class:
//
//	class=payload index=78 run=rec_c71e step=31 receipt=01K… role=input
//	  committed=sha256:… actual=sha256:… fields=$.arguments
//
// `index` is the log index, matching the verifier's `behalf-verify log`
// mode, so a payload finding and a content finding name the same leaf the
// same way.

// exitTamper is returned when a payload contradicts its commitment. main
// maps it to exit 1, the same status the verifier uses for a detected,
// classified mutation.
var errPayloadTampered = errors.New("payload no longer matches the digest committed in its signed receipt")

func cmdRehydrate(args []string) error {
	fs := flag.NewFlagSet("rehydrate", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	run := fs.String("run", "", "run id to rehydrate (required)")
	state := fs.String("state", "", "behalf state directory holding the CAS (default: $BEHALF_HOME or ~/.behalf)")
	casDir := fs.String("cas", "", "payload store directory (default: <state>/blobs)")
	after := fs.Int64("after", -1, "pagination cursor: emit only receipts with log_index > this")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *run == "" {
		return fmt.Errorf("rehydrate: --run is required")
	}
	if err := mustDir(dir, "rehydrate"); err != nil {
		return err
	}
	store, err := openStore(*state, *casDir)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	findings, err := rehydrate(context.Background(), *dir, *run, store, *after, w, os.Stderr)
	if err != nil {
		return err
	}
	if err := w.Flush(); err != nil {
		return err
	}
	if findings > 0 {
		return fmt.Errorf("%w: %d slot(s) in run %s", errPayloadTampered, findings, *run)
	}
	return nil
}

// openStore resolves the CAS the way every other behalf command resolves
// the state directory, so `rehydrate` finds the store the proxy wrote to
// without being told twice.
func openStore(state, casDir string) (*cas.Store, error) {
	if casDir != "" {
		return cas.New(casDir), nil
	}
	dir, err := identity.ResolveDir(state)
	if err != nil {
		return nil, err
	}
	return cas.New(identity.BlobsDir(dir)), nil
}

// rehydrate streams the run and returns how many slots contradicted their
// commitment. Findings are reported on report as they are found — one
// machine-readable line each — so a long run names the bad receipt even if
// the caller is piping stdout somewhere else.
func rehydrate(ctx context.Context, logDir, runID string, store *cas.Store, after int64, out, report io.Writer) (int, error) {
	db, err := index.Open(ctx, logDir)
	if err != nil {
		return 0, err
	}
	defer db.Close()

	rows, err := db.RunRows(runID)
	if err != nil {
		return 0, err
	}
	if len(rows) == 0 {
		return 0, fmt.Errorf("rehydrate: no receipts indexed for run %q", runID)
	}
	reader, err := tlog.NewBundleReader(ctx, logDir)
	if err != nil {
		return 0, err
	}
	erasures, err := erasureLookup(ctx, db, reader)
	if err != nil {
		return 0, err
	}

	findings := 0
	for step, row := range rows {
		// The run-relative step is the reconstruction coordinate (Q82), so
		// the cursor filters after the step is known: paging must not
		// renumber the steps it emits.
		if int64(row.LogIndex) <= after {
			continue
		}
		// Payload is checked against the indexed leaf hash before anything
		// is read out of it, so a rehydration never joins against bytes the
		// index does not vouch for.
		receiptBytes, err := reader.Payload(ctx, row.LogIndex, row.LeafHash)
		if err != nil {
			return findings, err
		}
		slots, err := payload.Resolve(receiptBytes, store, erasures)
		if err != nil {
			return findings, fmt.Errorf("rehydrate: log index %d: %w", row.LogIndex, err)
		}
		line, err := renderLine(row, step, slots)
		if err != nil {
			return findings, err
		}
		if _, err := out.Write(line); err != nil {
			return findings, err
		}
		for _, s := range payload.Findings(slots) {
			findings++
			fmt.Fprintln(report, findingLine(row, step, s))
		}
	}
	return findings, nil
}

// findingLine is the machine-readable classification, in the verifier's
// `class=… index=…` vocabulary. `payload` is a new class alongside
// content/drop/reorder/truncation/head/chain because it is a genuinely
// different finding: the log is intact, the receipt's signature verifies,
// and the customer's own bytes no longer match what that receipt commits
// to.
func findingLine(row index.Row, step int, s payload.Slot) string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "class=payload index=%d run=%s step=%d receipt=%s role=%s",
		row.LogIndex, row.RunID, step, row.ReceiptID, s.Label())
	if s.Mismatch != nil {
		fmt.Fprintf(b, " committed=sha256:%s actual=sha256:%s", s.Mismatch.Committed, s.Mismatch.Actual)
		if len(s.Mismatch.ChangedFields) > 0 {
			fmt.Fprintf(b, " fields=%s", strings.Join(s.Mismatch.ChangedFields, ","))
		}
	}
	fmt.Fprintf(b, " operation=%s target=%s", row.OperationName, row.OperationTarget)
	return b.String()
}

// slotLine is one resolved slot as NDJSON. It carries the committed half
// verbatim, the resolved state, and exactly one of content or placeholder —
// content only when the blob is present and hashes to its commitment.
type slotLine struct {
	Role           string            `json:"role,omitempty"`
	Digest         string            `json:"digest"`
	Custody        string            `json:"custody,omitempty"`
	ContentType    string            `json:"content_type,omitempty"`
	Size           int               `json:"size,omitempty"`
	Ref            string            `json:"ref,omitempty"`
	CommittedState string            `json:"committed_state"`
	State          string            `json:"state"`
	CauseRef       string            `json:"cause_ref,omitempty"`
	Content        json.RawMessage   `json:"content,omitempty"`
	ContentBase64  string            `json:"content_base64,omitempty"`
	Placeholder    string            `json:"placeholder,omitempty"`
	Mismatch       *payload.Mismatch `json:"mismatch,omitempty"`
	Error          string            `json:"error,omitempty"`
}

type receiptLine struct {
	LogIndex  uint64     `json:"log_index"`
	LeafHash  string     `json:"leaf_hash"`
	RunID     string     `json:"run_id"`
	Step      int        `json:"step"`
	ReceiptID string     `json:"receipt_id"`
	Kind      string     `json:"kind"`
	Captured  string     `json:"captured_at"`
	Operation opLine     `json:"operation"`
	Payload   []slotLine `json:"payload"`
}

type opLine struct {
	Name    string `json:"name"`
	Target  string `json:"target,omitempty"`
	Outcome string `json:"outcome,omitempty"`
}

func renderLine(row index.Row, step int, slots []payload.Slot) ([]byte, error) {
	rec := receiptLine{
		LogIndex:  row.LogIndex,
		LeafHash:  row.LeafHash,
		RunID:     row.RunID,
		Step:      step,
		ReceiptID: row.ReceiptID,
		Kind:      row.Kind,
		Captured:  row.CapturedAt,
		Operation: opLine{Name: row.OperationName, Target: row.OperationTarget, Outcome: row.OutcomeStatus},
		Payload:   make([]slotLine, 0, len(slots)),
	}
	for _, s := range slots {
		sl := slotLine{
			Role:           s.Role,
			Digest:         s.Digest,
			Custody:        s.Custody,
			ContentType:    s.ContentType,
			Size:           s.Size,
			Ref:            s.Ref,
			CommittedState: string(s.Committed),
			State:          string(s.State),
			CauseRef:       s.CauseRef,
			Mismatch:       s.Mismatch,
		}
		switch {
		case s.State != payload.StatePresent:
			sl.Placeholder = s.Placeholder()
			if s.Err != nil {
				sl.Error = s.Err.Error()
			}
		case json.Valid(s.Content):
			// The payload is JSON: emit it as JSON, spliced in whole, so a
			// consumer reads structure rather than a quoted string.
			sl.Content = json.RawMessage(s.Content)
		default:
			sl.ContentBase64 = base64.StdEncoding.EncodeToString(s.Content)
		}
		rec.Payload = append(rec.Payload, sl)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// erasureLookup builds the digest → cause-reference map from the log's own
// `erasure_notice` receipts (Q5, Q39), so a blob the customer deliberately
// deleted resolves `deleted` rather than `missing` — three findings, not
// one (Q36, D7).
//
// It walks the index by kind, which is a column, and reads the payload of
// only the notices themselves. In v1 nothing mints erasure notices yet —
// erasure is the customer deleting their own blob and receipting it — so
// this map is normally empty, and that is the correct empty: `missing` is
// the honest answer for an absence nothing accounts for.
func erasureLookup(ctx context.Context, db *index.DB, reader *tlog.BundleReader) (payload.ErasureLookup, error) {
	runs, err := index.ListRuns(db)
	if err != nil {
		return nil, err
	}
	erased := map[string]string{}
	for _, r := range runs {
		rows, err := db.RunRows(r.RunID)
		if err != nil {
			return nil, err
		}
		for step, row := range rows {
			if row.Kind != "erasure_notice" {
				continue
			}
			body, err := reader.Payload(ctx, row.LogIndex, row.LeafHash)
			if err != nil {
				return nil, err
			}
			// The notice references what it destroyed by digest; its own
			// slots are the reference. Resolving with a nil store keeps this
			// a read of the record, not of the disk.
			slots, err := payload.Resolve(body, nil, nil)
			if err != nil {
				return nil, err
			}
			ref := fmt.Sprintf("%s:%d", row.RunID, step)
			for _, s := range slots {
				if s.Digest != "" {
					erased[s.Digest] = ref
				}
			}
		}
	}
	if len(erased) == 0 {
		return nil, nil
	}
	return func(digest string) (string, bool) {
		ref, ok := erased[digest]
		return ref, ok
	}, nil
}
