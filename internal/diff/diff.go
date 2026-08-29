// Package diff answers "which step caused it".
//
// Two runs of the same agent, side by side, is a spot-the-difference puzzle:
// a 47-step trace against a 47-step trace, most of which differ in ways
// nobody cares about. This package does the three things that turn that into
// an answer — it ALIGNS the runs step by step (align.go), COMPARES each
// aligned pair through an explicit noise filter (compare.go), and names the
// FIRST divergence plus the one later step whose arguments carry that
// divergence forward, suppressing everything else (causality.go).
//
// Three disciplines govern it, inherited from the sibling `behalf why`:
//
//   - Nothing is written back. Alignment, classification and the causal
//     reading are computed from the stored bytes on every run. A comparison
//     bug can never freeze into evidence (Q11, schema §1).
//   - Nothing is invented. Every value on screen comes out of a stored
//     payload span, and every name comes from the local alias map, which is
//     an asserted label rather than a cryptographic claim (Q16, Q40). Where
//     the causal link cannot be shown by value equality the output says
//     "later difference", not "consequence".
//   - The suppression rule is a heuristic and says so, on screen, with
//     `--all` as the escape hatch. A diff that hides a difference without
//     admitting it is worse than one that shows all 47.
//
// # What is compared, and what is not
//
// The unit of comparison is the ACTION: the operation (name, target,
// arguments) and what came back (result, outcome).
//
// "Arguments" means the semantically meaningful cut — the tool's own
// arguments — and NOT the params blob as the proxy forwarded it. The
// forwarded blob carries `_meta`: the delegation chain, and W3C baggage
// holding `behalf-run-id`. The run id is by definition different between
// the two runs being compared, so anything covering `_meta` differs at
// every single step, and a diff built on it reports 47 of 47 steps as
// changed while explaining none of them. `_meta` is therefore filtered by
// construction (NoisyPathSegments), and the digest that covers the whole
// forwarded blob is not compared at all (NotCompared).
//
// NotCompared lists the receipt fields deliberately outside the scope.
// Three of them are worth naming here because they are not noise:
//
//   - authority.* and attribution.* — a run whose delegation chain is
//     verified and a run whose leaf hop is merely asserted differ on every
//     single receipt, at every step, including step 0. Counting that as a
//     step difference would make step 0 the "first divergence" of every such
//     pair and bury the step that actually caused the outcome. It is a real
//     finding and it is `behalf why`'s finding; diff surfaces it as the
//     attribution warning on the step it features, and hands off.
//   - step_key — the alignment key (Q85), not a difference. It embeds the
//     causal ordinal, so it changes whenever a step moves; that is
//     alignment's input, and reporting it would report every insertion twice.
//   - emitter.counter — a custody primitive, not a step number. Two runs
//     recorded through one proxy share one monotonic counter, so run A is
//     0..46 and run B is 47..93. A diff that indexed steps by it would work
//     on hand-built fixtures and silently misalign every recorded pair. The
//     step number here is always Step.Ordinal: the receipt's position in the
//     run view, which is log-index order filtered to the run (Q82), exactly
//     the coordinate `behalf why <run>:<step>` takes.
//
// # Step identity (Q85)
//
// The primary key is the stored step_key — hash of tool name, normalized
// argument schema and causal ordinal — with sequence alignment as the
// documented fallback for runs whose keys do not line up (agent-version
// changes, inserted or removed steps). See align.go.
package diff

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// NotCompared documents the receipt fields that never enter the compared
// view, with the reason each is out of scope. It exists as data so a test
// can assert the list rather than trusting a comment, and so the reason is
// written down next to the field it excuses.
//
// This is the coarse half of the noise filter: these fields differ by
// construction between any two runs, or belong to a different question.
// The fine half — field names and value shapes inside a compared value —
// lives in compare.go as NoisyFields and the volatile-value shapes.
var NotCompared = map[string]string{
	"schema_version":           "the writer's schema version, not the action",
	"otel_conventions_version": "the conventions version, not the action",
	"receipt_id":               "a client-minted ULID, unique per receipt by construction (Q46)",
	"captured_at":              "wall-clock capture time; two runs never share one",
	"run_id":                   "the thing being compared; equal by definition of the query",
	"run_id_provenance":        "how run_id was derived (Q7), not what the agent did",
	"correlation":              "run-scoped keys — session, trace, txn, acti, conversation (Q7)",
	"emitter":                  "the capture surface and its per-emitter counter, not the action",
	"step_key":                 "the alignment key (Q85), not a difference — see align.go",
	"risk_class": "capture-time policy assignment (Q6), not the action. It is READ — to " +
		"choose which linked downstream step is featured as the consequence (causality.go) — " +
		"but never compared: two runs of one script under one policy agree on it, and a pair " +
		"that did not would be reporting a policy change as an agent difference",
	"risk_policy_digest": "which policy was in force, not what the agent did",
	"authority":          "the delegation chain — `behalf why`'s question; surfaced as the attribution warning",
	"attribution":        "the stored verification rollup (Q12) — same, and see the package doc",
	"provenance":         "native vs imported (Q93), a property of the record",
	"log_index":          "a log coordinate, assigned at append",
	"leaf_hash":          "a log coordinate, derived from the stored bytes",
	"payload[input].digest": "a digest of the params object AS FORWARDED, which carries `_meta` " +
		"(delegation chain, and W3C baggage holding behalf-run-id) — so it differs at every step " +
		"of any two runs and is not a digest of the action. The per-field manifest is the comparable cut",
}

// Step is one receipt as the diff reads it: the log coordinates, the
// alignment key, and the projected argument / result / outcome views the
// comparison runs over. Payload is the exact stored payload span, kept
// verbatim — nothing here is ever re-serialized back into the log.
type Step struct {
	RunID string
	// Ordinal is the receipt's position in the RUN VIEW — log-index order
	// filtered to the run (Q82) — counting from 0, which is the coordinate
	// `behalf why <run>:<step>` takes. It is deliberately never
	// emitter.counter: that counter is per-emitter and monotonic across
	// runs, so two runs recorded through one proxy would number 0..46 and
	// 47..93 and every recorded pair would misalign.
	Ordinal  int
	LogIndex uint64
	LeafHash string
	Payload  []byte

	StepKey    string
	Operation  string
	Target     string
	CapturedAt string
	ActorJKT   string
	// RiskClass is the capture-time tool policy's assignment (Q6), read and
	// never recomputed. It is NOT compared — see NotCompared — and is used
	// for one thing: choosing which of several linked downstream steps the
	// render features as the consequence (causality.go).
	RiskClass string

	// Attribution is the stored receipt-level rollup (Q12); LeafHopStatus is
	// the stored verification state of the acting hop; RootJKT is the
	// confirmation-key thumbprint of the depth-0 hop — the human the run was
	// carried out on behalf of. All three are read, never recomputed.
	Attribution   string
	LeafHopStatus string
	RootJKT       string
	HopCount      int

	// The compared views, built once at projection time.
	args    fields // operation, target, idempotency key, per-argument digests
	result  fields // the outcome's result fields
	outcome fields // outcome status and error
	// The output slot's own digest, held apart from the views above: it is
	// fallback evidence, compared only when the result view is otherwise
	// identical (see compareOne and Difference.Opaque). The input slot's
	// digest is not compared at all — see NotCompared.
	outputSlot fields

	// argShape is the sorted argument path set, the fallback aligner's
	// "same shape of call" signal.
	argShape string
}

// Address renders the step's product-level address, the coordinate
// `behalf why` takes.
func (s *Step) Address() string { return fmt.Sprintf("%s:%d", s.RunID, s.Ordinal) }

// Result is everything one `behalf diff` render needs.
type Result struct {
	RunA, RunB     string
	CountA, CountB int
	// StartA and StartB are each run's first captured_at, verbatim — the
	// origin the "t+412ms" coordinate is measured from.
	StartA, StartB string
	// WeakestA and WeakestB are each run's weakest stored attribution
	// rollup (Q12). They are not compared as a step difference — see the
	// package doc — but the render states it when they disagree, because a
	// diff that says "2 differ" while one run cannot prove its authority at
	// all has answered the smaller question.
	WeakestA, WeakestB string

	// Aligner names which tier produced Pairs, for the record and for tests:
	// AlignerStepKey or AlignerSequence.
	Aligner string
	Pairs   []Pair

	// Differences are the aligned pairs that differ in a way the receipt can
	// explain, in aligned order. This is the number the headline counts.
	Differences []Difference
	// Opaque are the aligned pairs whose only difference is a payload-slot
	// digest — see Difference.Opaque. They are reported as their own line
	// and listed by --all, and they are never named as a cause.
	Opaque []Difference

	// First is the first divergence in aligned order — the step this feature
	// exists to name. Nil when nothing differs.
	First *Difference
	// Featured is the step shown under the first divergence. When
	// FeaturedIsConsequence it is the highest-risk differing step whose
	// differing argument values are traceable to First's differing result
	// values by value equality (ties to the latest), and Link carries that
	// evidence; otherwise it is simply the last differing step, and the
	// render labels it "later difference" rather than claiming a causal link
	// it cannot show.
	Featured              *Difference
	FeaturedIsConsequence bool
	Link                  *Link

	// SuppressedCount is how many differences the downstream heuristic hid.
	SuppressedCount int
}

// Link is the value-equality evidence behind a consequence claim: a value
// that appears in the first divergence's differing result on one run's side
// and again in the featured step's differing arguments on that same side,
// differing between the runs. Index is the element position when the link
// came from a reordered array (the demo's results[0]), and -1 otherwise.
type Link struct {
	Path   string
	Index  int
	ValueA string
	ValueB string
}

// Load reads two runs out of the log in logDir and analyses them.
//
// Both runs are read through the index (which supplies the run view in
// log-index order, Q82) and the log's own entry bundles, with every payload
// checked against its indexed leaf hash before anything is read out of it.
func Load(ctx context.Context, logDir, runA, runB string) (*Result, error) {
	db, err := index.Open(ctx, logDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	reader, err := tlog.NewBundleReader(ctx, logDir)
	if err != nil {
		return nil, err
	}
	a, err := loadRun(ctx, db, reader, runA)
	if err != nil {
		return nil, err
	}
	b, err := loadRun(ctx, db, reader, runB)
	if err != nil {
		return nil, err
	}
	return Analyze(a, b), nil
}

func loadRun(ctx context.Context, db *index.DB, reader *tlog.BundleReader, runID string) ([]Step, error) {
	rows, err := db.RunRows(runID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("diff: no receipts indexed for run %q", runID)
	}
	steps := make([]Step, 0, len(rows))
	for i, row := range rows {
		payload, err := reader.Payload(ctx, row.LogIndex, row.LeafHash)
		if err != nil {
			return nil, err
		}
		step, err := NewStep(runID, i, row.LogIndex, row.LeafHash, payload)
		if err != nil {
			return nil, err
		}
		steps = append(steps, step)
	}
	return steps, nil
}

// Analyze is the whole engine over two already-projected runs: align,
// compare, then read causality. It is pure, which is what lets each of the
// three pieces be tested on its own.
func Analyze(a, b []Step) *Result {
	res := &Result{CountA: len(a), CountB: len(b)}
	if len(a) > 0 {
		res.RunA, res.StartA, res.WeakestA = a[0].RunID, a[0].CapturedAt, weakest(a)
	}
	if len(b) > 0 {
		res.RunB, res.StartB, res.WeakestB = b[0].RunID, b[0].CapturedAt, weakest(b)
	}
	res.Pairs, res.Aligner = Align(a, b)
	for _, d := range Compare(res.Pairs) {
		if d.Opaque {
			res.Opaque = append(res.Opaque, d)
			continue
		}
		res.Differences = append(res.Differences, d)
	}
	analyzeCausality(res)
	return res
}

// weakest rolls a run's stored per-receipt attribution up to the run, by
// the same rule the receipt uses for its hops: the weakest link wins (Q12).
// It reads the stored rollup and never recomputes a chain.
func weakest(steps []Step) string {
	rank := map[string]int{"verified": 0, "asserted": 1, "broken": 2}
	worst := ""
	for _, s := range steps {
		if s.Attribution == "" {
			continue
		}
		if worst == "" || rank[s.Attribution] > rank[worst] {
			worst = s.Attribution
		}
	}
	return worst
}

// NewStep projects one stored receipt payload into the diff's read model.
// It reads; it never writes.
func NewStep(runID string, ordinal int, logIndex uint64, leafHash string, payload []byte) (Step, error) {
	var v receiptView
	if err := json.Unmarshal(payload, &v); err != nil {
		return Step{}, fmt.Errorf("diff: parse receipt at log index %d: %w", logIndex, err)
	}
	s := Step{
		RunID:       runID,
		Ordinal:     ordinal,
		LogIndex:    logIndex,
		LeafHash:    leafHash,
		Payload:     payload,
		StepKey:     v.StepKey,
		Operation:   v.Operation.Name,
		Target:      v.Operation.Target,
		CapturedAt:  v.CapturedAt,
		RiskClass:   v.RiskClass,
		Attribution: v.Attribution.Verification,
	}
	if v.Actor != nil {
		s.ActorJKT = v.Actor.JKT
	}
	if v.Authority != nil && len(v.Authority.Chain) > 0 {
		chain := v.Authority.Chain
		s.HopCount = len(chain)
		s.RootJKT = thumbprint(chain[0].Cnf.JWK)
		s.LeafHopStatus = chain[len(chain)-1].Verification.Status
	}
	s.args, s.result, s.outcome, s.outputSlot = projectViews(&v)
	s.argShape = shapeOf(s.args)
	return s, nil
}

// receiptView is the read-only projection of the stored payload. Reading
// fields is fine; the payload bytes themselves are never re-serialized.
type receiptView struct {
	Kind       string `json:"kind"`
	CapturedAt string `json:"captured_at"`
	StepKey    string `json:"step_key"`
	RiskClass  string `json:"risk_class"`
	Actor      *struct {
		JKT string `json:"jkt"`
	} `json:"actor"`
	Operation struct {
		Name           string                     `json:"name"`
		Target         string                     `json:"target"`
		IdempotencyKey string                     `json:"idempotency_key"`
		Outcome        map[string]json.RawMessage `json:"outcome"`
	} `json:"operation"`
	Payload   []slotView `json:"payload"`
	Authority *struct {
		Chain []struct {
			DelDepth int `json:"del_depth"`
			Cnf      struct {
				JWK json.RawMessage `json:"jwk"`
			} `json:"cnf"`
			Verification struct {
				Status string `json:"status"`
			} `json:"verification"`
		} `json:"chain"`
	} `json:"authority"`
	Attribution struct {
		Verification string `json:"verification"`
		Class        string `json:"class"`
	} `json:"attribution"`
}

type slotView struct {
	Role     string `json:"role"`
	Digest   string `json:"digest"`
	Size     int    `json:"size"`
	State    string `json:"state"`
	Manifest *struct {
		Fields []struct {
			Path   string `json:"path"`
			Digest string `json:"digest"`
		} `json:"fields"`
	} `json:"field_digest_manifest"`
}
