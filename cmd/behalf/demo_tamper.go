package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/tlog"
	"github.com/behalf-sh/behalf/internal/why"
)

// The two stage commands the byte-level scenarios need: `demo blob`, which
// shows what behalf's record holds about one receipt's payloads and whether
// those bytes are on this disk, and `demo tamper`, which performs the edit.
//
// `demo tamper` is the attacker's half and only the attacker's half. It
// writes bytes and says what it wrote. Every finding in both tamper beats
// comes from `behalf-verify` and `behalf-log rehydrate` — the shipped
// tooling, running the code paths scripts/tamper_suite.sh drives on every
// commit. A demo command that both broke the artifact and diagnosed the
// break would be proving nothing except that it can print.

// The two literals the demo edits.
//
//	amountLiteral      lives in the customer's payload blob: the tool
//	                   arguments, which behalf never holds.
//	amountCentsLiteral lives inside the signed receipt: the outcome behalf
//	                   does hold, and cannot be edited without breaking a
//	                   signature.
//
// Editing one and then the other is the whole tamper scenario, because the
// two produce genuinely different findings.
const (
	amountLiteral      = `"amount":"1200.00"`
	amountReplacement  = `"amount":"12.00"`
	amountCentsLiteral = `"amount_cents":120000`
	amountCentsReplace = `"amount_cents":12000`
)

// demoReceipt is one addressed receipt out of the demo log, with its
// payload slots resolved against the customer's store — the same
// payload.Resolve `behalf-log rehydrate` calls, so a slot this command
// calls present is a slot rehydration calls present.
type demoReceipt struct {
	Root      string
	RunID     string
	Step      int
	LogIndex  uint64
	ReceiptID string
	Operation string
	Target    string
	Outcome   string
	Slots     []payload.Slot
	Store     *cas.Store
}

// Input is the slot holding the tool arguments — what the agent asked for,
// which is where the refund amount lives.
func (d *demoReceipt) Input() *payload.Slot {
	for i := range d.Slots {
		if d.Slots[i].Role == "input" {
			return &d.Slots[i]
		}
	}
	return nil
}

func loadDemoReceipt(root string, addr why.Address) (*demoReceipt, error) {
	ctx := context.Background()
	db, err := index.Open(ctx, demoLogPath(root))
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.RunRows(addr.RunID)
	if err != nil {
		return nil, err
	}
	if addr.Step < 0 || addr.Step >= len(rows) {
		return nil, fmt.Errorf("run %s has %d steps; there is no step %d", addr.RunID, len(rows), addr.Step)
	}
	row := rows[addr.Step]

	reader, err := tlog.NewBundleReader(ctx, demoLogPath(root))
	if err != nil {
		return nil, err
	}
	body, err := reader.Payload(ctx, row.LogIndex, row.LeafHash)
	if err != nil {
		return nil, err
	}
	store := cas.New(identity.BlobsDir(root))
	slots, err := payload.Resolve(body, store, nil)
	if err != nil {
		return nil, err
	}
	return &demoReceipt{
		Root: root, RunID: row.RunID, Step: addr.Step, LogIndex: row.LogIndex,
		ReceiptID: row.ReceiptID, Operation: row.OperationName, Target: row.OperationTarget,
		Outcome: row.OutcomeStatus, Slots: slots, Store: store,
	}, nil
}

// findRefundPayload locates the one refund in the recording, and insists it
// is one. Both byte-level scenarios index a fixed receipt; if the scenario
// script ever grows a second refund, everything downstream of that — the
// finding's log index, the "exactly one blob" claim, the sentence the
// operator says — quietly stops being true. This fails instead.
func findRefundPayload(root string) (*demoReceipt, error) {
	ctx := context.Background()
	db, err := index.Open(ctx, demoLogPath(root))
	if err != nil {
		return nil, err
	}
	rows, err := db.RunRows(demoRunB)
	db.Close()
	if err != nil {
		return nil, err
	}
	var steps []int
	for i, r := range rows {
		if r.OperationName == "refund.issue" {
			steps = append(steps, i)
		}
	}
	if len(steps) != 1 {
		return nil, fmt.Errorf("recording layout drift: run %s has %d refund.issue receipts, want exactly 1 — "+
			"the demo indexes a fixed receipt and cannot pick between several", demoRunB, len(steps))
	}
	rec, err := loadDemoReceipt(root, why.Address{RunID: demoRunB, Step: steps[0]})
	if err != nil {
		return nil, err
	}
	if rec.Input() == nil {
		return nil, fmt.Errorf("recording layout drift: %s:%d has no input payload slot", rec.RunID, rec.Step)
	}
	return rec, nil
}

func demoBlob(args []string, stdout, stderr io.Writer) int {
	pathOnly := false
	addr := why.Address{RunID: demoRunB, Step: -1}
	for _, a := range args {
		switch {
		case a == "--path":
			pathOnly = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "behalf demo blob: unknown flag %q\n", a)
			return 2
		default:
			parsed, err := why.ParseAddress(a)
			if err != nil {
				fmt.Fprintln(stderr, "behalf demo blob:", err)
				return 2
			}
			addr = parsed
		}
	}
	root, err := openDemo()
	if err != nil {
		fmt.Fprintln(stderr, "behalf demo blob:", err)
		return 1
	}

	var rec *demoReceipt
	if addr.Step < 0 {
		rec, err = findRefundPayload(root.Root)
	} else {
		rec, err = loadDemoReceipt(root.Root, addr)
	}
	if err != nil {
		fmt.Fprintln(stderr, "behalf demo blob:", err)
		return 1
	}
	in := rec.Input()
	if in == nil {
		fmt.Fprintf(stderr, "behalf demo blob: %s:%d has no input payload\n", rec.RunID, rec.Step)
		return 1
	}
	if pathOnly {
		fmt.Fprintln(stdout, rec.Store.Path(in.Digest))
		return 0
	}
	renderBlobView(stdout, rec)
	return 0
}

// renderBlobView is the custody beat in one screen: the whole of what
// behalf's record holds about these payloads on the left of the colon, and
// where the bytes themselves are on the right. Run it again after deleting
// a blob and the second half changes while the first half does not — which
// is the claim.
func renderBlobView(out io.Writer, rec *demoReceipt) {
	fmt.Fprintf(out, "%s:%d  %s  target=%s  → %s        log index %d\n\n",
		rec.RunID, rec.Step, rec.Operation, rec.Target, rec.Outcome, rec.LogIndex)

	fmt.Fprintf(out, "what behalf's signed record holds about the payloads — all of it:\n\n")
	for _, s := range rec.Slots {
		fmt.Fprintf(out, "  %-8s digest        sha256:%s\n", s.Role, s.Digest)
		fmt.Fprintf(out, "  %-8s content type  %s\n", "", s.ContentType)
		fmt.Fprintf(out, "  %-8s size          %d bytes\n", "", s.Size)
		fmt.Fprintf(out, "  %-8s custody       %s\n", "", s.Custody)
		fmt.Fprintf(out, "\n")
	}
	fmt.Fprintf(out, "No arguments, no results, no customer content — a digest, a size and a\n")
	fmt.Fprintf(out, "content type. That is the entire payload half of the receipt.\n\n")

	// The store directory is printed once, above the slots, and each slot
	// names only the file. Concatenated they were 115 columns on an ordinary
	// home directory — a 64-hex file name leaves no room for a path — and this
	// view is on screen during the custody scenario at the runbook's
	// documented 100 columns, where it wrapped into noise (ENG-21). Nothing is
	// abbreviated: the whole path is still on the page, and `--path` prints it
	// on one line for `rm $(behalf demo blob --path)`.
	fmt.Fprintf(out, "where the bytes are — your disk, resolved just now:\n\n")
	fmt.Fprintf(out, "  under    %s\n\n", filepath.Dir(rec.Store.Path(rec.Slots[0].Digest)))
	for _, s := range rec.Slots {
		fmt.Fprintf(out, "  %-8s %s\n", s.Role, filepath.Base(rec.Store.Path(s.Digest)))
		switch s.State {
		case payload.StatePresent:
			fmt.Fprintf(out, "  %-8s present, %d bytes, hashes to its commitment\n", "", len(s.Content))
		default:
			fmt.Fprintf(out, "  %-8s %s\n", "", s.Placeholder())
		}
		fmt.Fprintf(out, "\n")
	}
}

func demoTamper(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "behalf demo tamper: what should it edit? `payload` (the customer's blob) or `export <file>` (a receipt)")
		return 2
	}
	root, err := openDemo()
	if err != nil {
		fmt.Fprintln(stderr, "behalf demo tamper:", err)
		return 1
	}
	switch args[0] {
	case "payload":
		if len(args) > 1 {
			fmt.Fprintf(stderr, "behalf demo tamper payload: unexpected argument %q\n", args[1])
			return 2
		}
		if err := tamperPayload(root.Root, stdout); err != nil {
			fmt.Fprintln(stderr, "behalf demo tamper payload:", err)
			return 1
		}
	case "export":
		if len(args) != 2 {
			fmt.Fprintln(stderr, "behalf demo tamper export: one export file, e.g. behalf demo tamper export $BEHALF_HOME/refund.jsonl")
			return 2
		}
		if err := tamperExport(args[1], stdout); err != nil {
			fmt.Fprintln(stderr, "behalf demo tamper export:", err)
			return 1
		}
	default:
		fmt.Fprintf(stderr, "behalf demo tamper: no target %q — want `payload` or `export <file>`\n", args[0])
		return 2
	}
	return 0
}

// tamperPayload is the cover-up where a real one would happen: in the
// customer's own store, which they own outright, rather than in a receipt
// they cannot forge. The blob keeps its filename, which is the digest it no
// longer hashes to.
func tamperPayload(root string, out io.Writer) error {
	rec, err := findRefundPayload(root)
	if err != nil {
		return err
	}
	in := rec.Input()
	path := rec.Store.Path(in.Digest)

	// Reading raw, not through Get: Get verifies the digest and would
	// refuse an already-edited blob. Here the raw bytes are the subject.
	before, err := rec.Store.ReadRaw(in.Digest)
	if err != nil {
		return fmt.Errorf("read the payload blob: %w", err)
	}
	n := bytes.Count(before, []byte(amountLiteral))
	if n == 0 {
		if bytes.Contains(before, []byte(amountReplacement)) {
			return fmt.Errorf("%s already carries the edit — this demo has already run.\n  Run `behalf demo reset` to put it back", path)
		}
		return fmt.Errorf("recording layout drift: %s does not contain %s", path, amountLiteral)
	}
	if n != 1 {
		return fmt.Errorf("recording layout drift: %s contains %s %d times, want 1", path, amountLiteral, n)
	}
	after := bytes.Replace(before, []byte(amountLiteral), []byte(amountReplacement), 1)
	if err := os.WriteFile(path, after, 0o600); err != nil {
		return err
	}

	fmt.Fprintf(out, "edited the customer's own payload store — not behalf's record.\n\n")
	fmt.Fprintf(out, "  file    %s\n", path)
	fmt.Fprintf(out, "  step    %s:%d  %s  target=%s  (log index %d)\n", rec.RunID, rec.Step, rec.Operation, rec.Target, rec.LogIndex)
	fmt.Fprintf(out, "  edit    %s  →  %s\n", amountLiteral, amountReplacement)
	fmt.Fprintf(out, "  size    %d bytes  →  %d bytes\n", len(before), len(after))
	fmt.Fprintf(out, "  now     sha256:%s\n", cas.Digest(after))
	fmt.Fprintf(out, "  named   sha256:%s   ← the filename it still has\n\n", in.Digest)
	fmt.Fprintf(out, "Nothing in behalf's log changed: no receipt, no signature, no checkpoint.\n")
	fmt.Fprintf(out, "The refund now reads as $12.00 in the only place the arguments exist.\n")
	return nil
}

// tamperExport edits a receipt inside an export — behalf's own record this
// time, which is the case the verifier is built for. The edit is the same
// cover-up, moved from the customer's blob into the signed outcome.
func tamperExport(path string, out io.Writer) error {
	before, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	n := bytes.Count(before, []byte(amountCentsLiteral))
	if n == 0 {
		if bytes.Contains(before, []byte(amountCentsReplace)) {
			return fmt.Errorf("%s already carries the edit.\n  Write a fresh one:  behalf-log export --run %s --out %s", path, demoRunB, path)
		}
		return fmt.Errorf("%s does not contain %s — is it an export of run %s?", path, amountCentsLiteral, demoRunB)
	}
	if n != 1 {
		return fmt.Errorf("export layout drift: %s contains %s %d times, want 1", path, amountCentsLiteral, n)
	}
	after := bytes.Replace(before, []byte(amountCentsLiteral), []byte(amountCentsReplace), 1)
	if err := os.WriteFile(path, after, 0o600); err != nil {
		return err
	}

	leaf, op := locateLeaf(before, amountCentsLiteral)
	fmt.Fprintf(out, "edited a receipt inside the export — behalf's own record this time.\n\n")
	fmt.Fprintf(out, "  file    %s\n", path)
	if leaf >= 0 {
		fmt.Fprintf(out, "  leaf    %d  %s  (run %s)\n", leaf, op, demoRunB)
	}
	fmt.Fprintf(out, "  edit    %s  →  %s\n", amountCentsLiteral, amountCentsReplace)
	fmt.Fprintf(out, "  size    %d bytes  →  %d bytes\n\n", len(before), len(after))
	fmt.Fprintf(out, "The DSSE signature over that receipt was not re-made — it cannot be, without\n")
	fmt.Fprintf(out, "the emitter key. Hand the file to the verifier and see what it says.\n")
	return nil
}

// locateLeaf finds which exported leaf carries a literal, for the printout.
// Best effort: a file it cannot parse still gets edited and still gets
// caught, and the operator loses one line of narration, not the beat.
func locateLeaf(export []byte, literal string) (int, string) {
	for _, line := range bytes.Split(export, []byte("\n")) {
		if !bytes.Contains(line, []byte(literal)) {
			continue
		}
		var leaf struct {
			Kind    string `json:"kind"`
			Index   int    `json:"index"`
			Payload struct {
				Operation struct {
					Name string `json:"name"`
				} `json:"operation"`
			} `json:"payload"`
		}
		if err := json.Unmarshal(line, &leaf); err != nil || leaf.Kind != "leaf" {
			return -1, ""
		}
		return leaf.Index, leaf.Payload.Operation.Name
	}
	return -1, ""
}
