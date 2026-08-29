package why

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// RunRow is one line of `behalf runs`: a run, and how much of it is
// attributable.
type RunRow struct {
	RunID   string
	Started string // the first captured_at in the run, verbatim
	// Status is the run's outcome: `ok` unless some receipt records a
	// failed operation. Two successful runs both reading `ok` is the
	// point of the listing, not a gap in it — an error tracker shows
	// nothing here, and the divergence that matters is only visible to
	// `behalf diff`.
	//
	// Run *completeness* (Q82) is deliberately not this column: it is
	// marked by a session-end receipt, the frozen kind enum has no such
	// kind yet, so on v1 data every run would read `open` forever. That
	// belongs in the listing once the kind exists, not before.
	Status string
	// Actions counts the action-family receipts — the denominator of the
	// attribution metric (Q86).
	Actions int64
	// Actor names the human at the root of the delegation chain — who the
	// run was carried out on behalf of, which is the question the product
	// exists to answer. It is a display label off the local alias map
	// (Q16): asserted, never evidence.
	Actor string
	// Attribution is the run's weakest attribution, rendered from the
	// stored per-hop verification states (Q12, Q86).
	Attribution string
}

// actionKinds is the action family: the receipt kinds that record a
// trust-boundary crossing, which is what the attribution metric counts
// (Q6, Q86).
var actionKinds = map[string]bool{
	"action": true, "tool_call": true, "resource_read": true, "message": true,
}

// ListRuns builds the `behalf runs` table from the index, reading receipt
// payloads only where the stored rollup already says something is
// unverified — that is the only case that needs the per-hop detail behind
// the summary.
func ListRuns(ctx context.Context, logDir string, aliases Aliases) ([]RunRow, error) {
	db, err := index.Open(ctx, logDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	summaries, err := index.ListRuns(db)
	if err != nil {
		return nil, err
	}
	if aliases == nil {
		aliases = demoAliases()
	}

	var reader *tlog.BundleReader
	out := make([]RunRow, 0, len(summaries))
	for _, s := range summaries {
		rows, err := db.RunRows(s.RunID)
		if err != nil {
			return nil, err
		}
		if reader == nil {
			if reader, err = tlog.NewBundleReader(ctx, logDir); err != nil {
				return nil, err
			}
		}
		actor, err := runPrincipal(ctx, reader, rows, aliases)
		if err != nil {
			return nil, err
		}
		row := RunRow{
			RunID:   s.RunID,
			Started: s.FirstCapturedAt,
			Status:  runStatus(rows),
			Actions: countActions(rows),
			Actor:   actor,
		}

		if s.Asserted == 0 && s.Broken == 0 {
			row.Attribution = "verified"
			out = append(out, row)
			continue
		}
		// Something in this run is not verified. The receipt-level rollup
		// is the weakest hop (Q12); to say how many hops that is, read the
		// chains behind the receipts that are not verified.
		asserted, broken, err := unverifiedHops(ctx, reader, rows)
		if err != nil {
			return nil, err
		}
		row.Attribution = attributionLabel(asserted, broken)
		out = append(out, row)
	}
	return out, nil
}

// runStatus reports the run's outcome from the stored operation outcomes.
func runStatus(rows []index.Row) string {
	for _, r := range rows {
		if r.OutcomeStatus != "" && r.OutcomeStatus != "ok" {
			return "error"
		}
	}
	return "ok"
}

func countActions(rows []index.Row) int64 {
	var n int64
	for _, r := range rows {
		if actionKinds[r.Kind] {
			n++
		}
	}
	return n
}

// runPrincipal names the human the run was carried out on behalf of: the
// depth-0 hop of the delegation chain, keyed by its confirmation key
// thumbprint and rendered through the local alias map. A run whose
// receipts carry no chain has no principal to name, and falls back to the
// acting key — an honest "this is all we know" rather than a blank.
//
// It reads one receipt per run, not all of them: the root is the same hop
// for every receipt in a run by construction, and a run whose receipts
// disagree about their root is a finding for `behalf why`, not something
// to average away in a listing.
func runPrincipal(ctx context.Context, reader *tlog.BundleReader, rows []index.Row, aliases Aliases) (string, error) {
	for _, r := range rows {
		payload, err := reader.Payload(ctx, r.LogIndex, r.LeafHash)
		if err != nil {
			return "", err
		}
		var v struct {
			Authority *struct {
				Chain []struct {
					Cnf *struct {
						JWK json.RawMessage `json:"jwk"`
					} `json:"cnf"`
				} `json:"chain"`
			} `json:"authority"`
		}
		if err := json.Unmarshal(payload, &v); err != nil {
			return "", fmt.Errorf("why: parse receipt at log index %d: %w", r.LogIndex, err)
		}
		if v.Authority == nil || len(v.Authority.Chain) == 0 || v.Authority.Chain[0].Cnf == nil {
			break
		}
		if jkt := thumbprint(v.Authority.Chain[0].Cnf.JWK); jkt != "" {
			return aliases.Label(jkt), nil
		}
		break
	}
	return runActor(rows, aliases), nil
}

// runActor names the acting key. A run whose receipts carry more than one
// actor key says so rather than picking one.
func runActor(rows []index.Row, aliases Aliases) string {
	seen := map[string]bool{}
	first := ""
	for _, r := range rows {
		if r.ActorJKT == "" {
			continue
		}
		if !seen[r.ActorJKT] {
			seen[r.ActorJKT] = true
			if first == "" {
				first = r.ActorJKT
			}
		}
	}
	switch len(seen) {
	case 0:
		return "(none)"
	case 1:
		return aliases.Label(first)
	default:
		return fmt.Sprintf("%d actors", len(seen))
	}
}

// unverifiedHops returns the worst per-receipt count of asserted and broken
// hops across the rows whose stored rollup is not `verified`.
func unverifiedHops(ctx context.Context, reader *tlog.BundleReader, rows []index.Row) (asserted, broken int, err error) {
	for _, r := range rows {
		if r.AttributionVerification == "verified" {
			continue
		}
		payload, err := reader.Payload(ctx, r.LogIndex, r.LeafHash)
		if err != nil {
			return 0, 0, err
		}
		var v struct {
			Authority *struct {
				Chain []struct {
					Verification Verification `json:"verification"`
				} `json:"chain"`
			} `json:"authority"`
		}
		if err := json.Unmarshal(payload, &v); err != nil {
			return 0, 0, fmt.Errorf("why: parse receipt at log index %d: %w", r.LogIndex, err)
		}
		if v.Authority == nil {
			continue
		}
		var a, b int
		for _, h := range v.Authority.Chain {
			switch h.Verification.Status {
			case "verified":
			case "broken":
				b++
			default:
				a++
			}
		}
		if a > asserted {
			asserted = a
		}
		if b > broken {
			broken = b
		}
	}
	return asserted, broken, nil
}

// attributionLabel names what is missing, in hops.
func attributionLabel(asserted, broken int) string {
	switch {
	case broken > 0:
		return fmt.Sprintf("%d hop%s broken", broken, plural(broken))
	case asserted > 0:
		return fmt.Sprintf("%d hop%s unverified", asserted, plural(asserted))
	default:
		// The rollup says something is not verified but no chain does: an
		// unattributed receipt (no chain at all).
		return "unattributed"
	}
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

// RenderRuns writes the runs table.
func RenderRuns(w io.Writer, rows []RunRow, opt Options) error {
	p := painter{on: opt.Color}
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 2, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "RUN\tSTARTED\tSTATUS\tACTIONS\tACTOR\tATTRIBUTION")
	for _, r := range rows {
		attribution := r.Attribution
		if attribution == "verified" {
			attribution = p.paint(ansiGreen, attribution)
		} else {
			attribution = p.paint(ansiYellow, attribution)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n",
			r.RunID, r.Started, r.Status, r.Actions, r.Actor, attribution)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	_, err := io.WriteString(w, b.String())
	return err
}
