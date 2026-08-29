package htmlexport

import (
	"context"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/behalf-sh/behalf/internal/diff"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/tlog"
	"github.com/behalf-sh/behalf/internal/why"
)

// actionKinds is the action family: the receipt kinds that record a
// trust-boundary crossing, which is what the attribution metric counts
// (schema §3, Q6, Q86). It is the denominator of the Q86 rollup and is
// named here so the page can state it.
var actionKinds = map[string]bool{
	"action": true, "tool_call": true, "resource_read": true, "message": true,
}

// stateUnrecorded is what the page says for a field the schema requires and
// this receipt does not carry. It is deliberately not one of the enum's
// words: filling an absent verification rollup in with "unattributed", or
// an absent outcome with "ok", would be the renderer inventing a fact the
// record does not contain — and inventing facts is the failure this whole
// product exists to correct.
const stateUnrecorded = "not recorded"

// Build assembles the page model. It reads: the index for the run views
// (log-index order filtered to the run — the authoritative reconstruction
// order, Q82), the log's own entry bundles for the receipt bytes, and the
// customer's CAS for the payloads. Every payload is checked against its
// indexed leaf hash before anything is read out of it, so nothing on the
// page comes from bytes the index does not vouch for.
//
// Nothing is written. This is a read path over the log dir: no appender is
// started and no epoch is claimed, so exporting never fences a running log
// service (Q57).
func Build(ctx context.Context, opt Options) (*Page, error) {
	opt = opt.withDefaults()
	if opt.LogDir == "" {
		return nil, fmt.Errorf("htmlexport: a log directory is required")
	}
	switch len(opt.Runs) {
	case 1, 2:
	default:
		return nil, fmt.Errorf("htmlexport: one or two run ids are required, got %d", len(opt.Runs))
	}
	aliases := opt.Aliases
	if aliases == nil {
		aliases = why.Aliases{}
	}

	db, err := index.Open(ctx, opt.LogDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	reader, err := tlog.NewBundleReader(ctx, opt.LogDir)
	if err != nil {
		return nil, err
	}
	erasures, err := erasureLookup(ctx, db, reader)
	if err != nil {
		return nil, err
	}

	page := &Page{
		GeneratedAt: opt.Now.UTC().Format(time.RFC3339),
		Pair:        len(opt.Runs) == 2,
		Trust:       trustBlock(),
		Log:         logIdentity(reader, opt),
	}

	// Steps are kept per run so the diff can be analysed from the same
	// bytes the receipt cards were built from — one read of the log, not
	// two, and no possibility of the two halves of the page disagreeing.
	steps := map[string][]diff.Step{}
	anchors := map[string]map[int]string{}
	for _, runID := range opt.Runs {
		rv, runSteps, err := loadRun(ctx, db, reader, runID, opt, aliases, erasures)
		if err != nil {
			return nil, err
		}
		page.Runs = append(page.Runs, rv)
		page.Findings += rv.Findings
		steps[runID] = runSteps
		anchors[runID] = map[int]string{}
		for _, r := range rv.Receipts {
			anchors[runID][r.Step] = r.Anchor
		}
	}

	if page.Pair {
		res := diff.Analyze(steps[opt.Runs[0]], steps[opt.Runs[1]])
		page.Diff = buildDiffView(res, aliases, anchors)
		markDiffering(page, res)
		page.Title = fmt.Sprintf("%s vs %s", opt.Runs[0], opt.Runs[1])
		page.Subtitle = "Two runs compared, led by the first step that diverged."
	} else {
		page.Title = opt.Runs[0]
		page.Subtitle = "One run, receipt by receipt, with the delegation chain that authorised each step."
	}
	if !page.Log.Available {
		page.Notes = append(page.Notes,
			"The log's signed checkpoint could not be read, so this page cannot state the chain head it was "+
				"rendered against. The receipt bytes below still came out of the log's entry bundles and were "+
				"checked against their indexed leaf hashes, but a reader should treat the identity of the log "+
				"itself as unestablished here and run the verifier against the directory.")
	}
	// Absence is a property of THIS rendering, and the page has to say which
	// kind of absence it is. A reader six months from now must be able to
	// tell "behalf never had these payloads" from "this export was produced
	// somewhere the payload store is not" (Q83, Q84).
	switch {
	case opt.Store == nil:
		page.Notes = append(page.Notes,
			"No payload store was given, so every payload slot resolves to a placeholder. That is a property of "+
				"this rendering, not of the record: the receipts carry the digests regardless, and the same export "+
				"produced where the store lives will show the content.")
	case !anyPresent(page.Runs):
		page.Notes = append(page.Notes,
			"The payload store at "+opt.Store.Dir()+" held none of the blobs these receipts commit to, so every "+
				"slot renders as its typed placeholder. That is still evidence — the digests are in the signed "+
				"receipts either way — but it is not the same finding as content that contradicts its commitment, "+
				"and the page distinguishes them.")
	}
	return page, nil
}

// anyPresent reports whether any slot on the page resolved to content.
func anyPresent(runs []*RunView) bool {
	for _, rv := range runs {
		for _, r := range rv.Receipts {
			for _, s := range r.Slots {
				if s.State == string(payload.StatePresent) {
					return true
				}
			}
		}
	}
	return false
}

// loadRun builds one run's view and, alongside it, the diff engine's
// projection of the same receipts.
func loadRun(ctx context.Context, db *index.DB, reader *tlog.BundleReader, runID string,
	opt Options, aliases why.Aliases, erasures payload.ErasureLookup) (*RunView, []diff.Step, error) {

	rows, err := db.RunRows(runID)
	if err != nil {
		return nil, nil, err
	}
	if len(rows) == 0 {
		return nil, nil, fmt.Errorf("htmlexport: no receipts indexed for run %q", runID)
	}

	rv := &RunView{
		ID:      runID,
		Started: rows[0].CapturedAt,
		Ended:   rows[len(rows)-1].CapturedAt,
		Status:  "ok",
		Anchor:  "run-" + safeID(runID),
	}
	var steps []diff.Step
	stateCounts := map[payload.State]int{}
	attrCounts := map[string]int{}
	weakest := ""

	for step, row := range rows {
		body, err := reader.Payload(ctx, row.LogIndex, row.LeafHash)
		if err != nil {
			return nil, nil, err
		}
		res, err := why.FromPayload(why.Address{RunID: runID, Step: step}, row.LogIndex, row.LeafHash, body)
		if err != nil {
			return nil, nil, err
		}
		slots, err := payload.Resolve(body, opt.Store, erasures)
		if err != nil {
			return nil, nil, fmt.Errorf("htmlexport: log index %d: %w", row.LogIndex, err)
		}
		ds, err := diff.NewStep(runID, step, row.LogIndex, row.LeafHash, body)
		if err != nil {
			return nil, nil, err
		}
		steps = append(steps, ds)

		view := receiptView(res, row, step, runID, rv.Started, slots, aliases, opt)
		rv.Receipts = append(rv.Receipts, view)
		rv.Findings += view.Findings

		if row.OutcomeStatus != "" && row.OutcomeStatus != "ok" {
			rv.Status = "error"
		}
		if actionKinds[row.Kind] {
			rv.Actions++
			attrCounts[orDefault(row.AttributionVerification, stateUnrecorded)]++
		}
		weakest = weakerOf(weakest, row.AttributionVerification)
		for _, s := range slots {
			stateCounts[s.State]++
		}
	}

	rv.Attribution = orDefault(weakest, stateUnrecorded)
	rv.Rollup = rollup(attrCounts, rv.Actions)
	rv.PayloadSummary = payloadSummary(stateCounts)
	rv.ActorJKT, rv.Actor = runPrincipal(rv.Receipts, aliases)
	return rv, steps, nil
}

// receiptView projects one receipt into the page model.
func receiptView(res *why.Result, row index.Row, step int, runID, runStart string,
	slots []payload.Slot, aliases why.Aliases, opt Options) *ReceiptView {

	v := &ReceiptView{
		Step:         step,
		Anchor:       fmt.Sprintf("%s-step-%d", safeID(runID), step),
		LogIndex:     row.LogIndex,
		LeafHash:     row.LeafHash,
		ReceiptID:    res.ReceiptID,
		Kind:         res.Kind,
		RunID:        runID,
		CapturedAt:   res.CapturedAt,
		Elapsed:      elapsed(runStart, res.CapturedAt),
		Operation:    res.Operation,
		Target:       res.Target,
		Outcome:      orDefault(res.Outcome, stateUnrecorded),
		Amount:       res.Amount,
		Currency:     res.Currency,
		ActorJKT:     res.ActorJKT,
		Actor:        aliases.Label(res.ActorJKT),
		Attribution:  orDefault(res.StoredAttribution, stateUnrecorded),
		Class:        res.AttributionClass,
		VerifiedHops: res.VerifiedHops,
		TotalHops:    res.TotalHops,
		Excess:       res.Excess,
	}
	if v.Class == "" {
		v.Class = stateUnrecorded
	}
	v.OutcomeOK = res.Outcome == "ok"

	rootLabel := "the chain's root principal"
	if len(res.Chain) > 0 {
		rootLabel = aliases.Label(res.Chain[0].JKT)
	}
	for _, h := range res.Chain {
		v.Hops = append(v.Hops, hopView(h, rootLabel, aliases))
	}
	for _, s := range slots {
		sv := slotView(s, opt)
		if sv.Tampered {
			v.Findings++
		}
		v.Slots = append(v.Slots, sv)
	}
	return v
}

func hopView(h why.Hop, rootLabel string, aliases why.Aliases) HopView {
	v := HopView{
		Depth:       h.Depth,
		MaxDepth:    h.MaxDepth,
		Label:       aliases.Label(h.JKT),
		JKT:         h.JKT,
		Status:      orDefault(h.Verification.Status, "asserted"),
		Method:      h.Verification.Method,
		EvidenceRef: h.Verification.EvidenceRef,
		Credential:  h.Credential,
		RootBinding: h.RootBinding,
		Carriage:    h.Carriage,
		JTI:         h.JTI,
		ParHash:     h.ParHash,
		Exp:         expiryText(h.Exp),
	}
	switch v.Status {
	case "verified":
		v.StatusWord = "verified"
	case "broken":
		v.StatusWord = "broken"
	default:
		v.StatusWord = "asserted"
	}
	v.Evidence = hopEvidence(h)
	v.Checked, v.NotChecked = hopChecks(h, rootLabel)
	v.Intent = intentOf(h.Grants)
	v.Scope = scopeLine(h.Grants)
	switch h.Computed {
	case why.AttenuationUnknown, why.AttenuationBroadened:
		v.Attenuation = string(h.Computed)
		v.AttenuationReason = h.ComputedReason
	}
	return v
}

// hopEvidence names what actually makes a hop verified, and nothing at all
// when nothing does.
func hopEvidence(h why.Hop) string {
	if h.Verification.Status != "verified" {
		return ""
	}
	m := strings.ToLower(h.Verification.Method)
	switch {
	case strings.Contains(m, "oidc"):
		out := "OIDC / " + provider(h.Credential.Issuer)
		if h.Credential.AuthTime > 0 {
			out += ", authenticated " + time.Unix(h.Credential.AuthTime, 0).UTC().Format(time.RFC3339)
		}
		return out
	case h.Verification.Method == "":
		return ""
	default:
		return h.Verification.Method
	}
}

// provider shortens an issuer URL to the name a human recognises. It is a
// display convenience; the full issuer is shown beside it.
func provider(issuer string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	host = strings.TrimPrefix(host, "accounts.")
	host = strings.TrimPrefix(host, "login.")
	if name, _, ok := strings.Cut(host, "."); ok && name != "" {
		return name
	}
	return host
}

// intentOf is the human's words for what was delegated, from the hop's
// grants.
func intentOf(grants []why.Grant) string {
	for _, g := range grants {
		if g.Intent != "" {
			return g.Intent
		}
	}
	return ""
}

// scopeLine renders a grant set as the delegated scope, with each
// operation's ceiling appended: "tickets.*, orders.read, refund.issue ≤ 100.00".
func scopeLine(grants []why.Grant) string {
	var parts []string
	seen := map[string]bool{}
	for _, g := range grants {
		for _, a := range g.Actions {
			if seen[a] {
				continue
			}
			seen[a] = true
			if lim, cur, ok := limitFor(grants, a); ok {
				part := a + " ≤ " + lim
				if cur != "" {
					part += " " + cur
				}
				parts = append(parts, part)
				continue
			}
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, ", ")
}

// limitFor is the tightest ceiling a grant set places on one action,
// verbatim. Comparison is left to internal/why, which owns it; this only
// picks the value out for display, and a set with more than one ceiling on
// the same action shows the first rather than silently choosing.
func limitFor(grants []why.Grant, action string) (amount, currency string, ok bool) {
	for _, g := range grants {
		for _, p := range g.Privileges {
			if p.Operation == action && p.Limit != nil {
				return p.Limit.Amount, p.Limit.Currency, true
			}
		}
	}
	return "", "", false
}

func slotView(s payload.Slot, opt Options) SlotView {
	v := SlotView{
		Label:       s.Label(),
		Role:        s.Role,
		State:       stateBadge(s.State),
		Committed:   stateBadge(s.Committed),
		Custody:     orDefault(s.Custody, "custody unrecorded"),
		ContentType: s.ContentType,
		Size:        s.Size,
		SizeText:    sizeText(s.Size),
		Digest:      s.Digest,
		Ref:         s.Ref,
		CauseRef:    s.CauseRef,
		Subjects:    s.Subjects,
		Tampered:    s.Tampered(),
		Mismatch:    s.Mismatch,
	}
	if s.Manifest != nil {
		v.ManifestFields = len(s.Manifest.Fields)
	}
	if s.Err != nil {
		v.Err = s.Err.Error()
	}
	if s.State != payload.StatePresent {
		v.Placeholder = s.Placeholder()
		return v
	}
	v.Content, v.Language, v.Truncated, v.Omitted = renderContent(s.Content, s.ContentType, opt.MaxInlineBytes)
	v.Collapsed = len(v.Content) > opt.CollapseBytes
	return v
}

// runPrincipal names the human the run was carried out on behalf of: the
// depth-0 hop of the delegation chain, rendered through the local alias map.
// A run whose receipts carry no chain has no principal to name and falls
// back to the acting key — an honest "this is all we know" rather than a
// blank.
//
// It reads the first receipt that carries a chain, not all of them: the root
// is the same hop for every receipt in a run by construction, and a run
// whose receipts disagree about their root is a finding for `behalf why`,
// not something to average away in a header.
func runPrincipal(receipts []*ReceiptView, aliases why.Aliases) (jkt, label string) {
	for _, r := range receipts {
		if len(r.Hops) > 0 && r.Hops[0].JKT != "" {
			return r.Hops[0].JKT, r.Hops[0].Label
		}
	}
	seen := map[string]bool{}
	first := ""
	for _, r := range receipts {
		if r.ActorJKT == "" || seen[r.ActorJKT] {
			continue
		}
		seen[r.ActorJKT] = true
		if first == "" {
			first = r.ActorJKT
		}
	}
	switch len(seen) {
	case 0:
		return "", "(no key)"
	case 1:
		return first, aliases.Label(first)
	default:
		return "", fmt.Sprintf("%d actors", len(seen))
	}
}

// rollup is the Q86 metric: the share of action receipts at each
// verification state, over a denominator the page states so a reader can
// reproduce the number from their own receipts.
func rollup(counts map[string]int, denominator int) Rollup {
	r := Rollup{
		Denominator: denominator,
		Note: "Numerator: action-family receipts (action, tool_call, resource_read, message) at each stored " +
			"verification state. Denominator: all action-family receipts in this run. Both are read off the " +
			"stored per-receipt rollup, which is the weakest hop of that receipt's chain.",
	}
	if denominator == 0 {
		return r
	}
	for _, state := range []string{"verified", "asserted", "broken", stateUnrecorded} {
		n := counts[state]
		if n == 0 {
			continue
		}
		pct := float64(n) * 100 / float64(denominator)
		r.Rows = append(r.Rows, RollupRow{
			State:   state,
			Count:   n,
			Percent: fmt.Sprintf("%.0f%%", pct),
			Width:   template.CSS(fmt.Sprintf("%.4f%%", pct)),
		})
	}
	return r
}

// weakerOf keeps the weakest stored rollup seen so far, by the receipt's own
// rule: the weakest link wins (Q12).
func weakerOf(worst, candidate string) string {
	if candidate == "" {
		return worst
	}
	rank := map[string]int{"verified": 0, "asserted": 1, stateUnrecorded: 2, "broken": 3}
	if worst == "" || rank[candidate] > rank[worst] {
		return candidate
	}
	return worst
}

// payloadSummary counts the resolved slots by state, in the schema's enum
// order. States with no slots are omitted.
func payloadSummary(counts map[payload.State]int) string {
	order := []payload.State{
		payload.StatePresent, payload.StateMissing, payload.StateDeleted,
		payload.StateUnreadable, payload.StateDroppedAtCapture,
	}
	var parts []string
	for _, st := range order {
		if n := counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, st))
		}
	}
	if len(parts) == 0 {
		return "no payload slots"
	}
	return strings.Join(parts, ", ")
}

// markDiffering flags the receipts the diff named, so each run's timeline
// can point at them rather than making the reader hold two lists in their
// head.
func markDiffering(page *Page, res *diff.Result) {
	byRun := map[string]*RunView{}
	for _, rv := range page.Runs {
		byRun[rv.ID] = rv
	}
	mark := func(runID string, ordinal int) {
		rv := byRun[runID]
		if rv == nil || ordinal < 0 || ordinal >= len(rv.Receipts) {
			return
		}
		rv.Receipts[ordinal].Differs = true
	}
	for _, d := range res.Differences {
		if d.Pair.A != nil {
			mark(res.RunA, d.Pair.A.Ordinal)
		}
		if d.Pair.B != nil {
			mark(res.RunB, d.Pair.B.Ordinal)
		}
	}
}

// logIdentity reads the chain head this page is a rendering of: the signed
// checkpoint's origin, size and root. A checkpoint that will not parse or
// will not verify is reported as unavailable, never guessed at.
func logIdentity(reader *tlog.BundleReader, opt Options) LogIdentity {
	id := LogIdentity{Dir: opt.LogDir, Commands: verifyCommands(opt.LogDir, opt.Runs)}
	cp := reader.Checkpoint()
	if cp == nil {
		return id
	}
	id.Available = true
	id.Origin = cp.Origin
	id.TreeSize = cp.Size
	id.RootHex = fmt.Sprintf("%x", cp.Root)
	id.Checkpoint = string(cp.Raw)
	return id
}

// erasureLookup builds the digest → cause-reference map from the log's own
// erasure_notice receipts (Q5, Q39), so a blob the customer deliberately
// deleted resolves `deleted` rather than `missing` — three findings, not one
// (Q36, D7).
//
// In v1 nothing mints erasure notices yet, so this map is normally empty,
// and that is the correct empty: `missing` is the honest answer for an
// absence nothing accounts for.
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

// safeID makes a run id usable as an HTML fragment identifier without
// losing which run it names.
func safeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "run"
	}
	return b.String()
}
