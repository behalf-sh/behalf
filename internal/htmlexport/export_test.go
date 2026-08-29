// Tests for the HTML export, driven end to end: receipts are ingested
// through the production log path, read back out of the entry bundles, and
// rendered.
//
// The assertions are STRUCTURAL, never byte-for-byte. The page is stamped
// with data- attributes naming each section, state and count, and the tests
// read those. Pinning the whole file would churn on every design change and
// would stop saying anything about the thing that matters: that the states
// and counts on the page are the states and counts in the record.
package htmlexport

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
	"github.com/behalf-sh/behalf/internal/why"
)

// ---------------------------------------------------------------- helpers

// ingest writes payloads into a fresh log dir through the real append path.
func ingest(t *testing.T, payloads [][]byte) string {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	key, err := tlog.GenerateCheckpointKey("behalf.sh/log/html-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.SaveCheckpointKey(dir, key); err != nil {
		t.Fatal(err)
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
	var pendings []*tlog.Pending
	for i, body := range payloads {
		sig := dsse.Sign(emitter.Private, exportv1.PayloadTypeReceipt, body)
		env := tlog.BuildEnvelope(exportv1.PayloadTypeReceipt, body, emitter.JKT, sig)
		p, err := l.BeginAppend(ctx, env)
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		pendings = append(pendings, p)
	}
	for i, p := range pendings {
		if _, err := p.Wait(ctx); err != nil {
			t.Fatalf("wait %d: %v", i, err)
		}
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
	return dir
}

// demoLog is the fixture pair, ingested. It is the real demo data: 47
// receipts per run, diverging at step 12 with the consequence at step 31.
func demoLog(t *testing.T, specs ...fixture.Spec) string {
	t.Helper()
	var all [][]byte
	for _, spec := range specs {
		res, err := fixture.Generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		all = append(all, res.Payloads...)
	}
	return ingest(t, all)
}

func render(t *testing.T, opt Options) (string, *Page) {
	t.Helper()
	var b strings.Builder
	page, err := Write(context.Background(), &b, opt)
	if err != nil {
		t.Fatal(err)
	}
	return b.String(), page
}

// attrValues pulls every value of a data- attribute out of the document.
// This is the structural read the tests assert on.
func attrValues(doc, name string) []string {
	re := regexp.MustCompile(`\b` + regexp.QuoteMeta(name) + `="([^"]*)"`)
	var out []string
	for _, m := range re.FindAllStringSubmatch(doc, -1) {
		out = append(out, m[1])
	}
	return out
}

func countAttr(doc, name, value string) int {
	n := 0
	for _, v := range attrValues(doc, name) {
		if v == value {
			n++
		}
	}
	return n
}

func hasAttr(doc, name, value string) bool { return countAttr(doc, name, value) > 0 }

func mustContain(t *testing.T, doc string, wants ...string) {
	t.Helper()
	// Text assertions read the page as a reader sees it. Everything on this
	// page is escaped in context — that is the point of TestUntrustedReceipt
	// ContentIsEscaped — so a content assertion has to unescape first, or it
	// would only ever be asserting the escaping.
	text := html.UnescapeString(doc)
	for _, w := range wants {
		if !strings.Contains(doc, w) && !strings.Contains(text, w) {
			t.Errorf("page is missing %q", w)
		}
	}
}

// ---------------------------------------------------------------- the demo

func TestSingleRunPageHasTheSectionsAnIncidentReaderNeeds(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A())
	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_9f2a"}, Aliases: demoAliases(t, dir)})

	for _, section := range []string{"document-head", "trust", "run", "timeline", "receipts", "verify"} {
		if !hasAttr(doc, "data-section", section) {
			t.Errorf("no section %q on the page", section)
		}
	}
	if hasAttr(doc, "data-section", "diff") {
		t.Error("a single-run page must not carry a diff section")
	}

	// The run header: id, started, status, action count, actor, attribution.
	if !hasAttr(doc, "data-run", "run_9f2a") {
		t.Error("the run section does not name the run")
	}
	if got := attrValues(doc, "data-actions"); len(got) != 1 || got[0] != "47" {
		t.Errorf("action count = %v, want [47]", got)
	}
	if got := attrValues(doc, "data-status"); len(got) != 1 || got[0] != "ok" {
		t.Errorf("run status = %v, want [ok]", got)
	}
	mustContain(t, doc, "2026-08-25T22:04:00Z", "alice@acme.com", "On behalf of")

	// The timeline carries every receipt, and every receipt has a card.
	if n := len(attrValues(doc, "data-step")); n != 47 {
		t.Errorf("%d timeline rows, want 47", n)
	}
	if n := len(attrValues(doc, "data-receipt")); n != 47 {
		t.Errorf("%d receipt cards, want 47", n)
	}
	if len(page.Runs[0].Receipts) != 47 {
		t.Fatalf("model has %d receipts", len(page.Runs[0].Receipts))
	}

	// The delegation chain: three hops per receipt, each in one of the three
	// states, each stating what it did and did not establish.
	if n := countAttr(doc, "data-hop", "0"); n != 47 {
		t.Errorf("%d depth-0 hops, want one per receipt", n)
	}
	if n := len(attrValues(doc, "data-hop-status")); n != 47*3 {
		t.Errorf("%d hops, want 3 per receipt", n)
	}
	// run_9f2a's leaf hop is signature-verified, so every hop is verified.
	if n := countAttr(doc, "data-hop-status", "verified"); n != 47*3 {
		t.Errorf("%d verified hops in run_9f2a, want all %d", n, 47*3)
	}
	if n := len(attrValues(doc, "data-checks")); n != 47*3*2 {
		t.Errorf("%d checked/not-checked lists, want two per hop", n)
	}
	mustContain(t, doc, "Checked", "Not checked")

	// Verifiability from the page itself.
	if !hasAttr(doc, "data-checkpoint", "available") {
		t.Error("the page does not state the checkpoint it was rendered against")
	}
	mustContain(t, doc,
		"behalf-verify log ",
		"behalf-verify run_9f2a.jsonl",
		"behalf-log export --dir ",
		"Chain head",
	)
	if page.Log.RootHex == "" || page.Log.Origin == "" {
		t.Errorf("log identity is empty: %+v", page.Log)
	}
	if !strings.Contains(doc, page.Log.RootHex) {
		t.Error("the chain head is not printed on the page")
	}

	// The honesty furniture.
	if n := countAttr(doc, "data-claim", "proves"); n < 3 {
		t.Errorf("%d 'what this proves' claims, want at least 3", n)
	}
	if n := countAttr(doc, "data-claim", "not-proves"); n < 4 {
		t.Errorf("%d 'what it does not prove' claims, want at least 4", n)
	}
	mustContain(t, doc,
		"That the agent did what the receipt says",
		"A compromised or prompt-injected agent",
		"Custody begins when the capture surface signs",
		"asserted",
		"This page is a rendering",
	)
}

func TestPairPageLeadsWithTheDiff(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	doc, page := render(t, Options{
		LogDir:  dir,
		Runs:    []string{"run_9f2a", "run_c71e"},
		Aliases: demoAliases(t, dir),
	})

	if !hasAttr(doc, "data-mode", "pair") {
		t.Error("a two-run export must render in pair mode")
	}
	if !hasAttr(doc, "data-section", "diff") {
		t.Fatal("no diff section")
	}
	if page.Diff == nil {
		t.Fatal("no diff in the model")
	}
	if got := page.Diff.Aligner; got != "step_key" {
		t.Errorf("aligner %q: the fixture pair has a perfect step_key bijection", got)
	}
	// The selection at step 12 propagates through every later step that
	// references the chosen order, which is the point: one cause, many
	// downstream differences, all but the featured one suppressed.
	if n := len(page.Diff.All); n != 22 {
		t.Fatalf("%d differences, want 22 (step 12 and the steps its selection reaches)", n)
	}
	if page.Diff.First == nil || page.Diff.First.StepA != 12 {
		t.Fatalf("first divergence = %+v, want step 12", page.Diff.First)
	}
	if !page.Diff.FeaturedIsConsequence || page.Diff.Featured.StepB != 31 {
		t.Fatalf("featured = %+v (consequence=%v), want step 31 as a consequence",
			page.Diff.Featured, page.Diff.FeaturedIsConsequence)
	}

	// The blocks are on the page, in their roles, and they carry the values
	// out of the stored receipts.
	if !hasAttr(doc, "data-role", "first") || !hasAttr(doc, "data-role", "featured") {
		t.Error("the first divergence and its consequence are not both rendered")
	}
	mustContain(t, doc,
		"47 actions in both runs. 22 differ. 1 caused the rest.",
		"ord_5512", "ord_5518", "1200.00", "$1,200.00",
		"returned in a different order",
		"The agent used orders[0] in both runs",
		"first difference in aligned order",
		"behalf why run_c71e:31",
	)
	// The attribution handoff, from the stored rollup.
	if !hasAttr(doc, "data-warning", "attribution") {
		t.Error("the diff does not hand off to `behalf why` for the unverified hop")
	}
	if !hasAttr(doc, "data-note", "run-attribution") {
		t.Error("the run-wide attribution difference is not stated")
	}
	// Both runs are still rendered in full, and cross-linked from the diff.
	if n := len(attrValues(doc, "data-receipt")); n != 94 {
		t.Errorf("%d receipt cards, want 94 (both runs)", n)
	}
	// 22 differing steps, flagged in both runs' timelines.
	if n := countAttr(doc, "data-differs", "true"); n != 44 {
		t.Errorf("%d timeline rows flagged as differing, want 44 (22 steps in both runs)", n)
	}
}

// TestSuppressionIsLabelledAHeuristic: the fixture pair has nothing
// downstream to suppress, so the rule is exercised on a pair built for it.
// The page may never print a suppression count without the heuristic note
// beside it — that is the whole discipline of the feature.
func TestSuppressionIsLabelledAHeuristic(t *testing.T) {
	a := syntheticRun(t, "run_a", []string{"alpha", "beta", "gamma", "delta"}, map[int]string{})
	b := syntheticRun(t, "run_b", []string{"alpha", "beta", "gamma", "delta"},
		map[int]string{1: "one", 2: "two", 3: "three"})
	dir := ingest(t, append(a, b...))

	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_a", "run_b"}})
	if page.Diff.SuppressedCount == 0 {
		t.Fatalf("expected downstream differences to be suppressed, got %d differences and 0 suppressed",
			len(page.Diff.All))
	}
	if !hasAttr(doc, "data-note", "suppression") {
		t.Fatal("a suppressed count was rendered without the heuristic note")
	}
	mustContain(t, doc,
		"Heuristic, not a finding",
		"presumed downstream",
		"no dataflow tracer",
	)
	// And nothing is actually hidden: the escape hatch is on the page.
	if !hasAttr(doc, "data-section", "all-differences") {
		t.Error("the suppressed differences are not listed anywhere")
	}
	if n := countAttr(doc, "data-role", "all"); n != len(page.Diff.All) {
		t.Errorf("%d differences listed under 'every difference', want %d", n, len(page.Diff.All))
	}
}

// -------------------------------------------------------- no external refs

// TestNothingIsLoadedRemotely is the load-bearing test for this package's
// central promise. It does not merely grep for "http": receipts legitimately
// carry issuer URLs as DATA (https://accounts.google.com is a stored
// credential field and must render). What must not exist is any construct
// that would cause a fetch.
func TestNothingIsLoadedRemotely(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A(), fixture.RunC71E())
	doc, _ := render(t, Options{LogDir: dir, Runs: []string{"run_9f2a", "run_c71e"}, Aliases: demoAliases(t, dir)})

	// 1. No element that loads anything.
	for _, banned := range []string{
		"<link", "<script src", "<img", "<iframe", "<object", "<embed",
		"<audio", "<video", "<source", "<track", "<use ", "srcset=", " src=",
		"@import", "url(", "@font-face", "integrity=", "crossorigin",
	} {
		if strings.Contains(doc, banned) {
			t.Errorf("the page contains %q — it must load nothing", banned)
		}
	}
	// 2. No network API in the script.
	for _, banned := range []string{
		"fetch(", "XMLHttpRequest", "WebSocket", "EventSource", "navigator.sendBeacon",
		"importScripts", "import(",
	} {
		if strings.Contains(doc, banned) {
			t.Errorf("the page's script reaches for %q", banned)
		}
	}
	// 3. Every href is a fragment, and every fragment resolves to something
	//    on this page. A cross-link that goes nowhere is the sort of rot a
	//    self-contained document cannot afford.
	ids := map[string]bool{}
	for _, id := range attrValues(doc, "id") {
		ids[id] = true
	}
	for _, href := range attrValues(doc, "href") {
		if !strings.HasPrefix(href, "#") {
			t.Errorf("href %q is not a document fragment", href)
			continue
		}
		if !ids[strings.TrimPrefix(href, "#")] {
			t.Errorf("href %q points at no element on the page", href)
		}
	}
	// 4. Every URL-shaped string that survives is inside text content, not
	//    inside an attribute or a stylesheet. Locate each one and prove it.
	for _, m := range regexp.MustCompile(`https?://[^\s"'<>)]+`).FindAllStringIndex(doc, -1) {
		if inMarkup(doc, m[0]) {
			t.Errorf("URL %q appears in markup, not in text: %s", doc[m[0]:m[1]], snippet(doc, m[0]))
		}
	}
	// 5. The document enforces it too.
	mustContain(t, doc, `http-equiv="Content-Security-Policy"`, "default-src 'none'")
	if strings.Contains(doc, "connect-src") {
		t.Error("the CSP must not name a connect-src: default-src 'none' already denies every fetch")
	}
}

// inMarkup reports whether the byte at i sits inside a tag, a <style> block
// or a <script> block — the three places a URL could actually be loaded
// from. Text content is where a stored issuer URL legitimately lands.
func inMarkup(doc string, i int) bool {
	openTag := strings.LastIndexByte(doc[:i], '<')
	closeTag := strings.LastIndexByte(doc[:i], '>')
	if openTag > closeTag {
		return true // inside a tag's attribute list
	}
	for _, block := range []struct{ open, close string }{{"<style>", "</style>"}, {"<script>", "</script>"}} {
		start := strings.LastIndex(doc[:i], block.open)
		if start < 0 {
			continue
		}
		if end := strings.Index(doc[start:], block.close); end < 0 || start+end > i {
			return true
		}
	}
	return false
}

func snippet(doc string, i int) string {
	lo, hi := i-60, i+60
	if lo < 0 {
		lo = 0
	}
	if hi > len(doc) {
		hi = len(doc)
	}
	return "…" + doc[lo:hi] + "…"
}

// ------------------------------------------------------------ payload states

// TestEveryPayloadStateRenders walks the five schema states through the
// page. A run full of placeholders must read as evidence, not as a broken
// document (Q83), so every state gets a typed rendering and none of them is
// silently blank.
func TestEveryPayloadStateRenders(t *testing.T) {
	store := cas.New(t.TempDir())
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	present := []byte(`{"tool":"orders.read","target":"ord_4437"}`)
	presentDigest, err := store.Put(present)
	if err != nil {
		t.Fatal(err)
	}
	// The cover-up: a blob whose bytes were edited after the receipt
	// committed to them.
	original := []byte(`{"amount":"12.00","currency":"USD"}`)
	tamperedDigest := cas.Digest(original)
	if _, err := store.Put(original); err != nil {
		t.Fatal(err)
	}
	edited := []byte(`{"amount":"1200.00","currency":"USD"}`)
	if err := os.WriteFile(store.Path(tamperedDigest), edited, 0o600); err != nil {
		t.Fatal(err)
	}

	slots := []receipt.Slot{
		{Role: "present", Digest: presentDigest, Custody: "customer-held", ContentType: "application/json",
			Size: len(present), Ref: "sha256:" + presentDigest, State: "present"},
		{Role: "missing", Digest: strings.Repeat("a", 64), Custody: "customer-held", State: "present"},
		{Role: "deleted", Digest: strings.Repeat("b", 64), Custody: "customer-held", State: "deleted",
			CauseRef: "run_states:0"},
		{Role: "dropped", Digest: strings.Repeat("c", 64), Custody: payload.CustodyDropped, State: "dropped-at-capture"},
		{Role: "unreadable", Digest: tamperedDigest, Custody: "customer-held", ContentType: "application/json",
			Size: len(original), Ref: "sha256:" + tamperedDigest, State: "present",
			Manifest: payload.FieldDigests(original)},
	}
	dir := ingest(t, [][]byte{synthReceipt(t, "run_states", 0, "refund.issue", "ord_5512", nil, slots)})

	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_states"}, Store: store})

	for _, state := range []string{"present", "missing", "deleted", "dropped-at-capture", "unreadable"} {
		if !hasAttr(doc, "data-slot-state", state) {
			t.Errorf("no slot rendered in state %q", state)
		}
	}
	// The placeholders are typed and carry the commitment, so an absent
	// payload still reads as evidence.
	mustContain(t, doc,
		"[missing: sha256:aaaaaaaaaaaa… (customer-held)]",
		"[deleted: sha256:bbbbbbbbbbbb… (customer-held) — erasure_notice run_states:0]",
		"[dropped-at-capture: sha256:cccccccccccc… (dropped-with-digest)]",
	)
	// The present slot shows its content, pretty-printed.
	mustContain(t, doc, `"tool": "orders.read"`)

	// The tamper finding is visible, with its evidence.
	if !hasAttr(doc, "data-tampered", "true") {
		t.Fatal("the payload cover-up is not marked as a finding")
	}
	if page.Findings != 1 {
		t.Errorf("page.Findings = %d, want 1", page.Findings)
	}
	mustContain(t, doc,
		"This payload no longer matches its commitment",
		"sha256:"+tamperedDigest,
		"sha256:"+cas.Digest(edited),
		"$.amount",
		"You hold the bytes, behalf holds the commitment",
	)
	// And the content of a contradicted slot is never served as though it
	// were the record.
	if strings.Contains(doc, `"amount": "1200.00"`) {
		t.Error("the altered bytes were rendered as content; only the finding may quote them")
	}
	// The run header rolls the finding up so it is not buried 40 receipts down.
	if !hasAttr(doc, "data-run-finding", "true") {
		t.Error("the run header does not surface the payload finding")
	}
}

// TestNoStoreStillReadsAsEvidence: exporting where the CAS is not is the
// normal path, not the edge case.
func TestNoStoreStillReadsAsEvidence(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A())
	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_9f2a"}})
	if page.Findings != 0 {
		t.Errorf("findings = %d with no store; absence is not a finding", page.Findings)
	}
	if n := countAttr(doc, "data-slot-state", "missing"); n != 94 {
		t.Errorf("%d missing slots, want 94 (two per receipt)", n)
	}
	mustContain(t, doc, "No payload store was given", "the receipts carry the digests regardless")
	if !hasAttr(doc, "data-section", "notes") {
		t.Error("the page does not say what this rendering could not show")
	}
}

// TestAnEmptyStoreSaysWhichKindOfAbsenceItIs: "we were not given a store"
// and "the store did not have these blobs" are different facts about the
// rendering, and a reader six months from now needs to be told which.
func TestAnEmptyStoreSaysWhichKindOfAbsenceItIs(t *testing.T) {
	empty := cas.New(t.TempDir())
	if err := empty.Ensure(); err != nil {
		t.Fatal(err)
	}
	dir := demoLog(t, fixture.Run9F2A())
	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_9f2a"}, Store: empty})
	if page.Findings != 0 {
		t.Errorf("findings = %d; an empty store is absence, not a finding", page.Findings)
	}
	mustContain(t, doc, "held none of the blobs these receipts commit to", empty.Dir())
	if strings.Contains(doc, "No payload store was given") {
		t.Error("a store WAS given; the page must not say otherwise")
	}
}

// TestDigestOnlyDifferencesAreReportedAndNeverBlamed: when the only thing
// that differs is a payload digest, the receipt records that customer-held
// content changed but not what changed in it. That has to be on the page,
// and it has to be kept out of the causal reading.
func TestDigestOnlyDifferencesAreReportedAndNeverBlamed(t *testing.T) {
	slotsA := []receipt.Slot{{Role: "output", Digest: strings.Repeat("1", 64), Custody: "customer-held", Size: 100, State: "present"}}
	slotsB := []receipt.Slot{{Role: "output", Digest: strings.Repeat("2", 64), Custody: "customer-held", Size: 100, State: "present"}}
	a := [][]byte{synthReceipt(t, "run_da", 0, "kb.search", "refunds", nil, slotsA)}
	b := [][]byte{synthReceipt(t, "run_db", 0, "kb.search", "refunds", nil, slotsB)}
	dir := ingest(t, append(a, b...))

	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_da", "run_db"}})
	if len(page.Diff.All) != 0 {
		t.Fatalf("%d explained differences, want 0", len(page.Diff.All))
	}
	if len(page.Diff.Opaque) != 1 {
		t.Fatalf("%d digest-only differences, want 1", len(page.Diff.Opaque))
	}
	if page.Diff.First != nil {
		t.Error("a digest-only difference must never be named the first divergence")
	}
	if !hasAttr(doc, "data-opaque", "true") {
		t.Error("the digest-only difference is not on the page at all")
	}
	mustContain(t, doc,
		"differ only in a payload digest",
		"not what changed in it",
		"never named as a cause",
	)
}

// TestLargePayloadStaysCollapsed: 40 KB blobs are the normal case, and the
// page has to stay usable with them.
func TestLargePayloadStaysCollapsed(t *testing.T) {
	store := cas.New(t.TempDir())
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	rows := make([]map[string]any, 0, 460)
	for i := 0; i < 460; i++ {
		rows = append(rows, map[string]any{
			"order_id": fmt.Sprintf("ord_%04d", i),
			"note":     strings.Repeat("x", 40),
			"status":   "delivered",
		})
	}
	big, err := json.Marshal(map[string]any{"orders": rows})
	if err != nil {
		t.Fatal(err)
	}
	if len(big) < 40<<10 {
		t.Fatalf("test blob is %d bytes, wanted at least 40 KB", len(big))
	}
	digest, err := store.Put(big)
	if err != nil {
		t.Fatal(err)
	}
	small := []byte(`{"tool":"orders.search"}`)
	smallDigest, err := store.Put(small)
	if err != nil {
		t.Fatal(err)
	}
	slots := []receipt.Slot{
		{Role: "input", Digest: smallDigest, Custody: "customer-held", ContentType: "application/json",
			Size: len(small), State: "present"},
		{Role: "output", Digest: digest, Custody: "customer-held", ContentType: "application/json",
			Size: len(big), State: "present"},
	}
	dir := ingest(t, [][]byte{synthReceipt(t, "run_big", 0, "orders.search", "cus_2291", nil, slots)})
	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_big"}, Store: store})

	var out, in *SlotView
	for i := range page.Runs[0].Receipts[0].Slots {
		s := &page.Runs[0].Receipts[0].Slots[i]
		switch s.Role {
		case "output":
			out = s
		case "input":
			in = s
		}
	}
	if out == nil || in == nil {
		t.Fatal("both slots should be in the model")
	}
	if !out.Collapsed {
		t.Error("a 40 KB payload must start collapsed")
	}
	if in.Collapsed {
		t.Error("a 24-byte payload should not be hidden behind a disclosure control")
	}
	if out.Truncated {
		t.Error("40 KB is under the inline bound and must be shown whole")
	}
	// The collapsed <details> carries no `open`, the small one does, and the
	// summary states the size so a reader knows what is behind it.
	if !regexp.MustCompile(`<details data-payload="present">`).MatchString(doc) {
		t.Error("the large payload's disclosure control is not closed by default")
	}
	if !regexp.MustCompile(`<details open data-payload="present">`).MatchString(doc) {
		t.Error("the small payload should be open")
	}
	// The summary states the size, so a reader knows what is behind the
	// control before opening it.
	mustContain(t, doc, out.SizeText, "copy", `class="payload"`)
	if !strings.HasSuffix(out.SizeText, "KB") {
		t.Errorf("size text %q should read in KB for a 40 KB blob", out.SizeText)
	}
	if !hasAttr(doc, "data-collapsed", "true") {
		t.Error("the collapsed slot is not marked as such")
	}
	// It is pretty-printed, not one 40 KB line.
	if !strings.Contains(doc, "\n      &#34;order_id&#34;: &#34;ord_0000&#34;") &&
		!strings.Contains(doc, `"order_id": "ord_0000"`) {
		t.Error("the payload is not pretty-printed")
	}
	// And print never lets a collapsed section read as an absence.
	mustContain(t, doc, "collapsed; expand before printing", "@media print")
}

// TestMegabytePayloadIsTruncatedAndSaysSo: collapsing keeps 40 KB usable;
// megabytes need a bound, and the bound has to be visible.
func TestMegabytePayloadIsTruncatedAndSaysSo(t *testing.T) {
	store := cas.New(t.TempDir())
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	huge := []byte(`{"blob":"` + strings.Repeat("y", 2<<20) + `"}`)
	digest, err := store.Put(huge)
	if err != nil {
		t.Fatal(err)
	}
	slots := []receipt.Slot{{Role: "output", Digest: digest, Custody: "customer-held",
		ContentType: "application/json", Size: len(huge), State: "present"}}
	dir := ingest(t, [][]byte{synthReceipt(t, "run_huge", 0, "kb.read", "kb_310", nil, slots)})
	doc, page := render(t, Options{LogDir: dir, Runs: []string{"run_huge"}, Store: store})

	s := page.Runs[0].Receipts[0].Slots[0]
	if !s.Truncated || s.Omitted == 0 {
		t.Fatalf("a 2 MB payload must be truncated: %+v", s)
	}
	if len(doc) > 4<<20 {
		t.Errorf("the document is %d bytes: a payload bound that does not bound the file is no bound", len(doc))
	}
	if !hasAttr(doc, "data-truncated", "true") {
		t.Error("the truncation is not marked")
	}
	mustContain(t, doc, "further bytes were left out", "The digest above commits to")
}

// ------------------------------------------------------------- safety, style

// TestUntrustedReceiptContentIsEscaped: everything on this page came out of
// a receipt, and a receipt records what an agent said. A prompt-injected
// agent naming its tool `<script>` must not get a script.
func TestUntrustedReceiptContentIsEscaped(t *testing.T) {
	nasty := `<script>alert(1)</script>`
	slots := []receipt.Slot{{Role: `"><img onerror=x>`, Digest: strings.Repeat("d", 64),
		Custody: "customer-held", State: "present"}}
	dir := ingest(t, [][]byte{synthReceipt(t, "run_xss", 0, nasty, `" onmouseover="x`, nil, slots)})
	doc, _ := render(t, Options{LogDir: dir, Runs: []string{"run_xss"}})

	if strings.Contains(doc, "<script>alert(1)</script>") {
		t.Fatal("a receipt's operation name was interpolated as markup")
	}
	if strings.Contains(doc, "<img onerror") {
		t.Fatal("a slot role was interpolated as markup")
	}
	if strings.Contains(doc, `onmouseover="x`) {
		t.Fatal("a target escaped its attribute")
	}
	mustContain(t, doc, "&lt;script&gt;alert(1)&lt;/script&gt;")
}

// TestThemeAndPrintStyles: both palettes are complete, no colour is defined
// only inside a media query, and the print rules exist.
func TestThemeAndPrintStyles(t *testing.T) {
	css := string(styles)
	if !strings.Contains(css, "@media (prefers-color-scheme: dark)") {
		t.Fatal("no dark palette")
	}
	dark := css[strings.Index(css, "@media (prefers-color-scheme: dark)"):]
	dark = dark[:strings.Index(dark, "/* ---- base")]
	root := css[:strings.Index(css, "@media (prefers-color-scheme: dark)")]

	tokenRE := regexp.MustCompile(`(--[a-z0-9-]+):`)
	for _, m := range tokenRE.FindAllStringSubmatch(dark, -1) {
		if !strings.Contains(root, m[1]+":") {
			t.Errorf("token %s is defined only inside the dark media query", m[1])
		}
	}
	if n := len(tokenRE.FindAllString(dark, -1)); n < 10 {
		t.Errorf("the dark palette overrides only %d tokens; it must be complete", n)
	}
	for _, want := range []string{
		"@media print", "@page", "break-inside: avoid", "page-break-inside: avoid",
		"break-after: avoid", ".no-print { display: none !important; }",
		"details:not([open]) > summary::after",
	} {
		if !strings.Contains(css, want) {
			t.Errorf("print stylesheet is missing %q", want)
		}
	}
	// No emoji as section markers: the marks are geometric glyphs or nothing.
	for _, r := range css {
		if r >= 0x1F300 && r <= 0x1FAFF {
			t.Errorf("emoji %q in the stylesheet", string(r))
		}
	}
}

// TestArgumentSurface: the model refuses what it cannot render honestly.
func TestArgumentSurface(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A())
	for _, tc := range []struct {
		name string
		opt  Options
	}{
		{"no runs", Options{LogDir: dir}},
		{"three runs", Options{LogDir: dir, Runs: []string{"a", "b", "c"}}},
		{"no log dir", Options{Runs: []string{"run_9f2a"}}},
		{"unknown run", Options{LogDir: dir, Runs: []string{"run_nope"}}},
	} {
		if _, err := Build(context.Background(), tc.opt); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestWriteFileIsAtomicAndSelfContained(t *testing.T) {
	dir := demoLog(t, fixture.Run9F2A())
	out := filepath.Join(t.TempDir(), "export.html")
	page, err := WriteFile(context.Background(), out, Options{LogDir: dir, Runs: []string{"run_9f2a"}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(b), "<!doctype html>") || !strings.HasSuffix(strings.TrimSpace(string(b)), "</html>") {
		t.Error("the written file is not a complete document")
	}
	if page.Title != "run_9f2a" {
		t.Errorf("title = %q", page.Title)
	}
	// No temporary file left behind.
	entries, err := os.ReadDir(filepath.Dir(out))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Errorf("%d files in the output dir, want 1", len(entries))
	}
}

// ------------------------------------------------------------ test fixtures

func demoAliases(t *testing.T, dir string) why.Aliases {
	t.Helper()
	a, err := why.LoadAliases(dir)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// syntheticRun builds a run of receipts with a controllable per-step result,
// for the cases the demo fixtures deliberately do not encode.
func syntheticRun(t *testing.T, runID string, ops []string, results map[int]string) [][]byte {
	t.Helper()
	var out [][]byte
	for i, op := range ops {
		var extra map[string]any
		if v, ok := results[i]; ok {
			extra = map[string]any{"result": v}
		}
		out = append(out, synthReceipt(t, runID, i, op, "tgt_"+strconv.Itoa(i), extra, nil))
	}
	return out
}

// synthReceipt builds one schema-valid receipt with a two-hop chain: a
// verified root and an asserted leaf, which is the day-zero-with-login shape
// the product is honest about (Q21, Q86).
func synthReceipt(t *testing.T, runID string, step int, op, target string,
	extra map[string]any, slots []receipt.Slot) []byte {
	t.Helper()
	root, leaf := testkeys.ActorRoot(), testkeys.ActorHop2()
	at := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC).Add(time.Duration(step) * 5 * time.Second)
	r := &receipt.Receipt{
		SchemaVersion:      receipt.SchemaVersion,
		OtelConventionsVer: fixture.OtelConventionsVersion,
		ReceiptID:          fmt.Sprintf("01SYNTH%s%03d", strings.ToUpper(safeID(runID)), step),
		Kind:               "tool_call",
		RiskClass:          "low",
		RiskPolicyDigest:   strings.Repeat("0", 64),
		CapturedAt:         at.Format(time.RFC3339),
		Emitter:            receipt.Emitter{JKT: testkeys.Emitter().JKT, Surface: "mcp-proxy", Counter: step},
		Actor:              &receipt.Actor{JKT: leaf.JKT, EmitterToActor: "asserted"},
		Operation:          receipt.Operation{Name: op, Target: target, Outcome: receipt.Outcome{Status: "ok", Extra: extra}},
		RunID:              runID,
		RunIDProvenance:    "caller",
		StepKey:            fmt.Sprintf("%064x", step*7919+len(op)),
		Attribution:        receipt.Attribution{Verification: "asserted", Class: "delegated"},
		Payload:            slots,
		Provenance:         receipt.Provenance{Source: "native"},
		Authority: &receipt.Authority{Chain: []receipt.Hop{
			{
				DelDepth: 0, DelMaxDepth: 2,
				ParHash: strings.Repeat("1", 64),
				Cnf:     receipt.Cnf{JWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": root.JWK.X}},
				AuthorizationDetails: []map[string]any{{
					"type": "behalf.sh/tool", "actions": []string{op, "refund.issue"},
					"intent":     "resolve ticket 4417",
					"privileges": []any{map[string]any{"operation": "refund.issue", "limit": map[string]any{"amount": "100.00", "currency": "USD"}}},
				}},
				Exp: 1787788800, JTI: "aat-" + runID + "-hop0",
				Credential:           receipt.Credential{Issuer: "https://accounts.google.com", Kind: "oidc-id-token", ID: "idt_1", Exp: 1787788800, AuthTime: at.Unix() - 2},
				RootPrincipalBinding: &receipt.RootBinding{Nonce: root.JKT, DeviceJKT: root.JKT, IDTokenRef: strings.Repeat("2", 64)},
				Verification:         receipt.Verification{Status: "verified", Method: "oidc-nonce-thumbprint", EvidenceRef: "jkt:" + root.JKT},
				AttenuationFlag:      "unchanged",
			},
			{
				DelDepth: 1, DelMaxDepth: 2,
				ParHash: strings.Repeat("3", 64),
				Cnf:     receipt.Cnf{JWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": leaf.JWK.X}},
				AuthorizationDetails: []map[string]any{{
					"type": "behalf.sh/tool", "actions": []string{op},
				}},
				Exp: 1787788800, JTI: "aat-" + runID + "-hop1",
				Credential:      receipt.Credential{Issuer: "https://desk.demo.internal", Kind: "aat", ID: "aat_1", Exp: 1787788800},
				Verification:    receipt.Verification{Status: "asserted", Method: "", EvidenceRef: ""},
				CarriageRoute:   "params._meta/sh.behalf/chain",
				AttenuationFlag: "attenuated",
			},
		}},
	}
	sealed, err := receipt.Seal(r)
	if err != nil {
		t.Fatal(err)
	}
	return sealed.Bytes()
}
