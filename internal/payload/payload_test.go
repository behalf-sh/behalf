package payload_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// newStore returns an empty CAS in a temp dir.
func newStore(t *testing.T) *cas.Store {
	t.Helper()
	s := cas.New(t.TempDir())
	if err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	return s
}

// put writes content and returns a committed slot describing it, the way
// the capture surface would have written one.
func put(t *testing.T, s *cas.Store, role string, content []byte) receipt.Slot {
	t.Helper()
	d, err := s.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	return receipt.Slot{
		Role:        role,
		Digest:      d,
		Custody:     "customer-held",
		ContentType: "application/json",
		Size:        len(content),
		Ref:         "sha256:" + d,
		State:       "present",
		Manifest:    payload.FieldDigests(content),
	}
}

// receiptWith wraps slots in a minimal receipt payload, so the tests
// exercise Resolve's own span extraction rather than only ResolveSlots.
func receiptWith(t *testing.T, slots []receipt.Slot) []byte {
	t.Helper()
	b, err := json.Marshal(map[string]any{
		"schema_version": receipt.SchemaVersion,
		"receipt_id":     "01TESTTESTTESTTESTTESTTESTT",
		"kind":           "tool_call",
		"payload":        slots,
	})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestPresent: a blob in the store that hashes to its committed digest
// resolves present, and is the only state that returns content.
func TestPresent(t *testing.T) {
	store := newStore(t)
	content := []byte(`{"amount":"12.00","currency":"USD","order_id":"ord_5512"}`)
	slot := put(t, store, "input", content)

	got, err := payload.Resolve(receiptWith(t, []receipt.Slot{slot}), store, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("resolved %d slots, want 1", len(got))
	}
	s := got[0]
	if s.State != payload.StatePresent {
		t.Fatalf("state %q, want present", s.State)
	}
	if string(s.Content) != string(content) {
		t.Fatalf("content %q, want %q", s.Content, content)
	}
	if s.Tampered() {
		t.Fatal("a present slot must not be a tamper finding")
	}
	if s.Render() != string(content) {
		t.Fatalf("Render() = %q, want the content", s.Render())
	}
	if s.Placeholder() != "" {
		t.Fatalf("a present slot has no placeholder, got %q", s.Placeholder())
	}
}

// TestMissing: no blob, no erasure notice — the honest answer is `missing`,
// and it renders as a typed placeholder naming the digest and the custody
// mode rather than as nothing at all (Q83).
func TestMissing(t *testing.T) {
	store := newStore(t)
	content := []byte(`{"order_id":"ord_5512"}`)
	slot := put(t, store, "input", content)
	if err := os.Remove(store.Path(slot.Digest)); err != nil {
		t.Fatal(err)
	}

	got := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)
	s := got[0]
	if s.State != payload.StateMissing {
		t.Fatalf("state %q, want missing", s.State)
	}
	if s.Content != nil {
		t.Fatal("a missing slot must carry no content")
	}
	if s.Tampered() {
		t.Fatal("absence is not tampering")
	}
	ph := s.Placeholder()
	if !strings.HasPrefix(ph, "[missing: sha256:") || !strings.Contains(ph, "(customer-held)") {
		t.Fatalf("placeholder %q, want [missing: sha256:… (customer-held)]", ph)
	}
	if !strings.Contains(ph, slot.Digest[:12]) {
		t.Fatalf("placeholder %q does not name the committed digest", ph)
	}
	if s.Render() != ph {
		t.Fatal("Render must fall back to the placeholder")
	}
}

// TestDeleted: the same absence, but an erasure_notice accounts for it. The
// lookup is injected — this package never invents one (Q39, Q83).
func TestDeleted(t *testing.T) {
	store := newStore(t)
	content := []byte(`{"order_id":"ord_5512"}`)
	slot := put(t, store, "input", content)
	if err := os.Remove(store.Path(slot.Digest)); err != nil {
		t.Fatal(err)
	}

	erasures := func(digest string) (string, bool) {
		if digest == slot.Digest {
			return "run_c71e:44", true
		}
		return "", false
	}
	s := payload.ResolveSlots([]receipt.Slot{slot}, store, erasures)[0]
	if s.State != payload.StateDeleted {
		t.Fatalf("state %q, want deleted", s.State)
	}
	if s.CauseRef != "run_c71e:44" {
		t.Fatalf("cause_ref %q, want the erasure notice reference", s.CauseRef)
	}
	if !strings.Contains(s.Placeholder(), "erasure_notice run_c71e:44") {
		t.Fatalf("placeholder %q does not name the cause", s.Placeholder())
	}

	// The same slot with no lookup must stay `missing`: behalf does not
	// guess that a customer meant to delete something.
	if got := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)[0]; got.State != payload.StateMissing {
		t.Fatalf("without a lookup, state %q, want missing", got.State)
	}
}

// TestDroppedAtCapture: recorded as never-stored at write time. No lookup
// happens — only the capture surface could know this (Q36).
func TestDroppedAtCapture(t *testing.T) {
	store := newStore(t)
	slot := receipt.Slot{
		Role:     "input",
		Digest:   "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
		Custody:  payload.CustodyDropped,
		Ref:      "sha256:4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
		State:    string(payload.StateDroppedAtCapture),
		CauseRef: "run_c71e:2",
	}
	s := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)[0]
	if s.State != payload.StateDroppedAtCapture {
		t.Fatalf("state %q, want dropped-at-capture", s.State)
	}
	if s.CauseRef != "run_c71e:2" {
		t.Fatalf("cause_ref %q must be carried through", s.CauseRef)
	}
	if !strings.Contains(s.Placeholder(), "[dropped-at-capture: sha256:4355a46b19d3…") {
		t.Fatalf("placeholder %q", s.Placeholder())
	}
}

// TestUnreadableTamperDetection is the load-bearing case: flip a byte in a
// stored blob and the slot must classify as `unreadable` with the digest
// mismatch reported — never `present`, never swallowed into `missing`, and
// never returned as content.
//
// This is the payload cover-up in miniature. The receipt is untouched: the
// attacker edits only the bytes they hold, in their own store, and behalf
// still catches it because the blob no longer hashes to the digest
// committed inside a signed receipt.
func TestUnreadableTamperDetection(t *testing.T) {
	store := newStore(t)
	content := []byte(`{"amount":"1200.00","currency":"USD","order_id":"ord_5518"}`)
	slot := put(t, store, "input", content)

	// The cover-up: the refund amount, edited in place. The file keeps its
	// name — the name is the committed digest — so the mismatch is between
	// the name and the content.
	altered := []byte(`{"amount":"0012.00","currency":"USD","order_id":"ord_5518"}`)
	if err := os.WriteFile(store.Path(slot.Digest), altered, 0o600); err != nil {
		t.Fatal(err)
	}

	s := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)[0]
	if s.State != payload.StateUnreadable {
		t.Fatalf("state %q, want unreadable — the tamper finding must not be swallowed", s.State)
	}
	if !s.Tampered() {
		t.Fatal("a digest mismatch must report as a tamper finding")
	}
	if s.Content != nil {
		t.Fatal("altered bytes must never be served as content")
	}
	if s.Mismatch == nil {
		t.Fatal("the mismatch must be reported")
	}
	if s.Mismatch.Committed != slot.Digest {
		t.Fatalf("committed digest %q, want %q", s.Mismatch.Committed, slot.Digest)
	}
	if s.Mismatch.Actual == slot.Digest || s.Mismatch.Actual != cas.Digest(altered) {
		t.Fatalf("actual digest %q, want %q", s.Mismatch.Actual, cas.Digest(altered))
	}
	if s.Mismatch.StoredSize != len(altered) {
		t.Fatalf("stored size %d, want %d", s.Mismatch.StoredSize, len(altered))
	}
	// The field-digest manifest captured at write is what turns "something
	// changed" into "the amount changed" (Q37).
	if got := s.Mismatch.ChangedFields; len(got) != 1 || got[0] != "$.amount" {
		t.Fatalf("changed fields %v, want [$.amount]", got)
	}
	ph := s.Placeholder()
	for _, want := range []string{"[unreadable: sha256:", "stored bytes hash to", "$.amount"} {
		if !strings.Contains(ph, want) {
			t.Fatalf("placeholder %q missing %q", ph, want)
		}
	}
	if len(payload.Findings([]payload.Slot{s})) != 1 {
		t.Fatal("Findings must return the tampered slot")
	}
}

// TestUnreadableWithoutManifest: a payload with no field-digest manifest
// still detects the tamper — the manifest sharpens the finding, it does not
// enable it. Absent manifest means an empty ChangedFields, which the
// renderer must not present as "nothing changed".
func TestUnreadableWithoutManifest(t *testing.T) {
	store := newStore(t)
	content := []byte(`["ord_5512","ord_5518"]`) // a JSON array: no manifest
	slot := put(t, store, "output", content)
	if slot.Manifest != nil {
		t.Fatal("a non-object payload must get no manifest")
	}
	if err := os.WriteFile(store.Path(slot.Digest), []byte(`["ord_5512"]`), 0o600); err != nil {
		t.Fatal(err)
	}

	s := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)[0]
	if s.State != payload.StateUnreadable || !s.Tampered() {
		t.Fatalf("state %q tampered=%v, want unreadable + tampered", s.State, s.Tampered())
	}
	if len(s.Mismatch.ChangedFields) != 0 {
		t.Fatalf("no manifest means no field detail, got %v", s.Mismatch.ChangedFields)
	}
	if strings.Contains(s.Placeholder(), "changed:") {
		t.Fatalf("placeholder must not claim field detail it does not have: %q", s.Placeholder())
	}
}

// TestChangedFieldsAddedAndRemoved: a field the attacker added, and one
// they removed, both count as departures from what was committed.
func TestChangedFieldsAddedAndRemoved(t *testing.T) {
	store := newStore(t)
	content := []byte(`{"amount":"1200.00","order_id":"ord_5518"}`)
	slot := put(t, store, "input", content)
	altered := []byte(`{"amount":"1200.00","note":"approved"}`)
	if err := os.WriteFile(store.Path(slot.Digest), altered, 0o600); err != nil {
		t.Fatal(err)
	}
	s := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)[0]
	got := s.Mismatch.ChangedFields
	if len(got) != 2 || got[0] != "$.note" || got[1] != "$.order_id" {
		t.Fatalf("changed fields %v, want [$.note $.order_id]", got)
	}
}

// TestEntirelyAbsentRunResolvesCleanly: the normal path. A reconstruction
// on a machine whose CAS holds none of the run's blobs must resolve without
// error, render entirely as placeholders, and report no tamper findings —
// a run full of placeholders is still verifiable evidence (Q83).
func TestEntirelyAbsentRunResolvesCleanly(t *testing.T) {
	written := newStore(t)
	var slots []receipt.Slot
	for i := range 47 {
		in := []byte(`{"step":` + string(rune('0'+i%10)) + `,"tool":"orders.read"}`)
		slots = append(slots, put(t, written, "input", in))
	}
	// A different machine: same receipts, an empty store.
	empty := newStore(t)

	got, err := payload.Resolve(receiptWith(t, slots), empty, nil)
	if err != nil {
		t.Fatalf("an absent CAS must not be an error: %v", err)
	}
	if len(got) != len(slots) {
		t.Fatalf("resolved %d slots, want %d", len(got), len(slots))
	}
	for i, s := range got {
		if s.State != payload.StateMissing {
			t.Fatalf("slot %d: state %q, want missing", i, s.State)
		}
		if s.Render() == "" {
			t.Fatalf("slot %d rendered as nothing; absence must render", i)
		}
	}
	if n := len(payload.Findings(got)); n != 0 {
		t.Fatalf("%d tamper findings on an absent store, want 0", n)
	}
	if s := payload.Summary(got); s != "47 missing" {
		t.Fatalf("summary %q, want %q", s, "47 missing")
	}
}

// TestNilStoreAndNoPayload: the degenerate inputs a caller can reach.
func TestNilStoreAndNoPayload(t *testing.T) {
	slot := receipt.Slot{Role: "input", Digest: "abc", Custody: "customer-held", State: "present"}
	if s := payload.ResolveSlots([]receipt.Slot{slot}, nil, nil)[0]; s.State != payload.StateMissing {
		t.Fatalf("nil store: state %q, want missing", s.State)
	}

	// A receipt kind that carries no payload member at all (an approval, a
	// policy_change) is not an error; it has no slots.
	got, err := payload.Resolve([]byte(`{"receipt_id":"x","kind":"approval"}`), nil, nil)
	if err != nil {
		t.Fatalf("a receipt with no payload member: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("resolved %d slots, want 0", len(got))
	}
	if payload.Summary(got) != "no payload slots" {
		t.Fatalf("summary %q", payload.Summary(got))
	}
}

// TestVendorHeldIsNotLookedUpLocally: the reserved custody mode. v1 never
// writes it, and a local lookup for it would report a falsehood.
func TestVendorHeldIsNotLookedUpLocally(t *testing.T) {
	store := newStore(t)
	slot := receipt.Slot{
		Role:    "input",
		Digest:  "4355a46b19d348dc2f57c046f8ef63d4538ebb936000f3c9ee954a27460dd865",
		Custody: payload.CustodyVendor,
		State:   "present",
	}
	s := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)[0]
	if s.State != payload.StatePresent || s.Content != nil {
		t.Fatalf("vendor-held: state %q content=%v, want the committed state and no content", s.State, s.Content != nil)
	}
}

// TestRenderAllAndLabels covers the reconstruction-line helpers.
func TestRenderAllAndLabels(t *testing.T) {
	store := newStore(t)
	in := put(t, store, "input", []byte(`{"order_id":"ord_5512"}`))
	out := put(t, store, "output", []byte(`{"status":"ok"}`))
	if err := os.Remove(store.Path(out.Digest)); err != nil {
		t.Fatal(err)
	}
	got := payload.ResolveSlots([]receipt.Slot{in, out}, store, nil)
	rendered := payload.RenderAll(got)
	lines := strings.Split(rendered, "\n")
	if len(lines) != 2 {
		t.Fatalf("rendered %d lines, want 2:\n%s", len(lines), rendered)
	}
	if !strings.HasPrefix(lines[0], "input: {") {
		t.Fatalf("line 0 %q", lines[0])
	}
	if !strings.HasPrefix(lines[1], "output: [missing:") {
		t.Fatalf("line 1 %q", lines[1])
	}
	if s := payload.Summary(got); s != "1 present, 1 missing" {
		t.Fatalf("summary %q", s)
	}
}

// TestBinaryContentRendersTyped: non-UTF-8 content is summarised, not
// spilled as mojibake into a reconstruction.
func TestBinaryContentRendersTyped(t *testing.T) {
	store := newStore(t)
	content := []byte{0xff, 0xfe, 0x00, 0x01}
	d, err := store.Put(content)
	if err != nil {
		t.Fatal(err)
	}
	slot := receipt.Slot{
		Role: "output", Digest: d, Custody: "customer-held",
		ContentType: "application/octet-stream", Size: len(content),
		Ref: "sha256:" + d, State: "present",
	}
	s := payload.ResolveSlots([]receipt.Slot{slot}, store, nil)[0]
	r := s.Render()
	if !strings.HasPrefix(r, "[present: sha256:") || !strings.Contains(r, "4 bytes of application/octet-stream") {
		t.Fatalf("render %q", r)
	}
}

// TestShort keeps the placeholder digest form stable — it is what a reader
// matches against a store listing by eye.
func TestShort(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"", "sha256:?"},
		{"abc", "sha256:abc"},
		{"0123456789abcdef0123", "sha256:0123456789ab…"},
		{"sha256:0123456789abcdef0123", "sha256:0123456789ab…"},
	} {
		if got := payload.Short(tc.in); got != tc.want {
			t.Errorf("Short(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
