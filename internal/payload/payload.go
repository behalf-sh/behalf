// Package payload is the rehydration and verification read path for
// customer-held payloads (Q83, Q84, D7).
//
// Receipts do not carry tool arguments. Payloads are customer-held
// everywhere — in local-first v1, the customer's own disk — and behalf's
// record holds the digest, the custody mode, the content type, the size and
// the content-address reference, never the content (Q34, Q35). Rehydration
// is therefore a join performed where the CAS lives (Q84): take the payload
// slots out of a signed receipt, look each digest up in the customer's
// store, and report what was found.
//
// # The four ways a lookup can end, and why they are four
//
// Every slot resolves to one of the schema's five states (Q83):
//
//	present             the blob is in the store AND hashes to the digest
//	                    the signed receipt commits to
//	unreadable          the blob is in the store and does NOT hash to that
//	                    digest — the bytes changed after they were committed
//	missing             no blob under that digest
//	deleted             no blob, and an erasure_notice explains why (Q39)
//	dropped-at-capture  recorded as never-stored at write time (Q36)
//
// A verifier reading a receipt years later must be able to tell "never
// here" from "deleted" from "altered" — three different findings, which is
// exactly why the custody enum and the state enum were frozen into the
// schema rather than collapsed into a boolean (Q36, D7).
//
// `unreadable` is the load-bearing one. It is the payload cover-up: the
// bytes are the customer's, so an attacker who holds them can edit them —
// and behalf still detects it, because the blob no longer hashes to the
// digest committed inside a DSSE-signed, log-committed receipt. You hold
// the bytes, we hold the commitment, and we can still prove your bytes
// changed. Resolve classifies that case; it never swallows it into
// "missing" or into an error return.
//
// # Placeholders are the normal path
//
// A reconstruction full of placeholders is still verifiable evidence,
// because the receipts carry digests regardless (Q83, D7 ratification).
// Render and Placeholder exist so a caller shows
//
//	[missing: sha256:9f2ac71e0a4b… (customer-held)]
//
// rather than nothing at all. Absence renders; it does not error.
//
// # What this package will not do
//
// Content is returned only for `present` slots. For every other state the
// bytes on disk — if there are any — are not the bytes the receipt commits
// to, and handing them to a caller as though they were the record would be
// the whole failure this package exists to prevent. What a non-present slot
// carries instead is evidence about the discrepancy: the committed digest,
// what the stored bytes actually hash to, and (for JSON payloads with a
// field-digest manifest) which fields moved.
package payload

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// State is a resolved payload-slot state — the schema's `state` enum
// (receipt-schema-v1.md §9-adjacent, Q83).
type State string

// The five states. These are the schema's exact strings: they are written
// into receipts at capture and read back here, so they may not drift.
const (
	// StatePresent: the blob was found and re-hashes to its committed digest.
	StatePresent State = "present"
	// StateMissing: no blob under the committed digest, and nothing explains
	// its absence.
	StateMissing State = "missing"
	// StateDeleted: no blob, and an erasure_notice accounts for it (Q39).
	StateDeleted State = "deleted"
	// StateUnreadable: a blob exists and does not hash to the committed
	// digest. The tamper finding.
	StateUnreadable State = "unreadable"
	// StateDroppedAtCapture: the capture surface recorded the digest without
	// storing the bytes (Q36's `dropped-with-digest` custody).
	StateDroppedAtCapture State = "dropped-at-capture"
)

// CustodyDropped is the custody mode that means the bytes were never
// stored, only committed to (Q36).
const CustodyDropped = "dropped-with-digest"

// CustodyVendor is the reserved custody mode for payloads held by the
// vendor. v1 never writes it — payloads are customer-held everywhere (D7) —
// and a local CAS lookup would be meaningless for a slot that claims it, so
// Resolve reports the committed state unchanged.
const CustodyVendor = "vendor-held"

// ErasureLookup answers "is there an erasure_notice for this digest?" and,
// if so, returns the reference that explains the deletion — the value that
// lands in the slot's `cause_ref` (Q83).
//
// Resolve takes this as a function rather than reaching for a receipt store
// of its own: erasure notices are ordinary leaves in the one log (Q5), and
// which of them are in scope is a question about the caller's log and index,
// not about the CAS. A nil lookup means "nothing is known to be erased",
// which reports honest `missing` rather than a guessed `deleted`.
type ErasureLookup func(digest string) (causeRef string, ok bool)

// Mismatch is the evidence behind an `unreadable` slot: the digest the
// signed receipt commits to, and what the bytes now sitting in the store
// actually hash to.
type Mismatch struct {
	// Committed is the digest inside the signed, log-committed receipt.
	Committed string `json:"committed"`
	// Actual is the SHA-256 of the bytes found in the store.
	Actual string `json:"actual"`
	// StoredSize is how many bytes are in the store now; compare against the
	// slot's committed Size.
	StoredSize int `json:"stored_size"`
	// ChangedFields lists the manifest paths whose field digests no longer
	// match, when the receipt captured a field-digest manifest and the stored
	// bytes are still a JSON object (Q37). Empty when there is no manifest to
	// compare against — which is a gap in the evidence, not a clean bill.
	ChangedFields []string `json:"changed_fields,omitempty"`
}

func (m *Mismatch) String() string {
	s := fmt.Sprintf("stored bytes hash to %s, not the committed %s", Short(m.Actual), Short(m.Committed))
	if len(m.ChangedFields) > 0 {
		s += " (changed: " + strings.Join(m.ChangedFields, ", ") + ")"
	}
	return s
}

// Slot is one payload slot of a receipt, joined against the customer's
// store. The committed half — everything from Role through Subjects, plus
// Committed — is read verbatim out of the signed receipt and is never
// recomputed. The resolved half — State, CauseRef, Content, Mismatch, Err —
// is this read's finding and is never written back (the same
// stored-not-derived discipline `why` keeps for attenuation).
type Slot struct {
	Role        string            `json:"role,omitempty"`
	Digest      string            `json:"digest"`
	Custody     string            `json:"custody,omitempty"`
	ContentType string            `json:"content_type,omitempty"`
	Size        int               `json:"size,omitempty"`
	Ref         string            `json:"ref,omitempty"`
	Manifest    *receipt.Manifest `json:"field_digest_manifest,omitempty"`
	Subjects    []string          `json:"subjects,omitempty"`

	// Committed is the `state` the capture surface recorded at write time.
	// It is an input to resolution, not its output: a slot committed as
	// `present` may resolve to any of the five states, and a slot committed
	// as `dropped-at-capture` stays there because no lookup could improve on
	// what the capture surface already knew (Q36).
	Committed State `json:"committed_state"`

	// State is this read's finding.
	State State `json:"state"`

	// CauseRef points at the receipt that explains a non-present state —
	// the erasure_notice or policy_change (Q83). Carried through from the
	// receipt when it recorded one, else supplied by the erasure lookup.
	CauseRef string `json:"cause_ref,omitempty"`

	// Content is the blob's bytes. Non-nil only when State is present: for
	// every other state the bytes on disk are not the bytes the receipt
	// commits to.
	Content []byte `json:"-"`

	// Mismatch is set exactly when the store held bytes that do not hash to
	// the committed digest — the tamper finding.
	Mismatch *Mismatch `json:"mismatch,omitempty"`

	// Err records a lookup that failed for a reason that is neither absence
	// nor a digest mismatch — an unreadable file, a permission denial. Such
	// a slot also resolves `unreadable` (the schema has no state for "the
	// disk said no"), so Tampered, not the state alone, is what distinguishes
	// a cover-up from a broken mount.
	Err error `json:"-"`
}

// Tampered reports whether this slot is the payload cover-up: bytes present
// in the store that do not hash to the digest committed in the signed
// receipt. An `unreadable` slot whose Mismatch is nil failed to read for
// some other reason and is not a tamper finding — saying otherwise would
// cry wolf at a bad mount.
func (s Slot) Tampered() bool { return s.Mismatch != nil }

// Resolve joins a receipt's payload slots against the customer's store.
//
// receiptPayload is the exact stored payload span — the signed receipt
// bytes, as they come out of the log's entry bundles. Only the `payload`
// member is read; the bytes are never re-serialized.
//
// A store that holds none of the run's blobs is not an error: every slot
// resolves `missing` and the reconstruction renders as placeholders, which
// is the normal path, not the edge case (Q83). Resolve errors only when the
// receipt's own `payload` member cannot be read, which is a broken receipt,
// not a missing payload.
func Resolve(receiptPayload []byte, store *cas.Store, erasures ErasureLookup) ([]Slot, error) {
	raw, err := jsonspan.ExtractTopLevelValue(receiptPayload, "payload")
	if err != nil {
		// A receipt with no payload member has no slots. `payload` is
		// optional in the schema (an approval or a policy_change carries
		// none), so absence is a legal, empty answer.
		return nil, nil
	}
	var slots []receipt.Slot
	if err := json.Unmarshal(raw, &slots); err != nil {
		return nil, fmt.Errorf("payload: parse receipt payload slots: %w", err)
	}
	return ResolveSlots(slots, store, erasures), nil
}

// ResolveSlots is Resolve for a caller that has already decoded the slots —
// the shape `why` and `diff` want, since they parse the receipt anyway.
func ResolveSlots(committed []receipt.Slot, store *cas.Store, erasures ErasureLookup) []Slot {
	out := make([]Slot, 0, len(committed))
	for _, c := range committed {
		out = append(out, resolveOne(c, store, erasures))
	}
	return out
}

func resolveOne(c receipt.Slot, store *cas.Store, erasures ErasureLookup) Slot {
	s := Slot{
		Role:        c.Role,
		Digest:      c.Digest,
		Custody:     c.Custody,
		ContentType: c.ContentType,
		Size:        c.Size,
		Ref:         c.Ref,
		Manifest:    c.Manifest,
		Subjects:    c.Subjects,
		Committed:   State(c.State),
		CauseRef:    c.CauseRef,
	}
	if s.Committed == "" {
		s.Committed = StatePresent
	}

	// Nothing the capture surface stored, so nothing to look up. The
	// capture surface is the only party that knows this (Q36's K3
	// unbackfillable field); a later reader can only carry it through.
	if s.Committed == StateDroppedAtCapture || c.Custody == CustodyDropped {
		s.State = StateDroppedAtCapture
		return s
	}
	// Already accounted for as erased at write time.
	if s.Committed == StateDeleted {
		s.State = StateDeleted
		return s
	}
	// Reserved custody: the blob was never on this disk to begin with, so a
	// local lookup would report a falsehood.
	if c.Custody == CustodyVendor {
		s.State = s.Committed
		return s
	}
	// A slot with no digest commits to nothing and cannot be looked up. The
	// schema requires one; treating a violation as `missing` keeps a
	// malformed record readable instead of failing the whole run.
	if s.Digest == "" || store == nil {
		s.State = StateMissing
		s.applyErasure(erasures)
		return s
	}

	content, err := store.Get(s.Digest)
	switch {
	case err == nil:
		s.State = StatePresent
		s.Content = content
		return s

	case errors.Is(err, cas.ErrTampered):
		// The cover-up. Never collapsed into `missing`, never returned as a
		// plain error: it is a classified finding with its evidence attached.
		s.State = StateUnreadable
		s.Mismatch = mismatchFor(s, store, err)
		return s

	case errors.Is(err, cas.ErrMissing):
		s.State = StateMissing
		s.applyErasure(erasures)
		return s

	default:
		// The disk said no for some third reason. `unreadable` is the
		// closest state the schema has; Mismatch stays nil so this never
		// reads as a tamper finding.
		s.State = StateUnreadable
		s.Err = err
		return s
	}
}

// applyErasure upgrades `missing` to `deleted` when the caller's lookup
// accounts for the absence. Without a lookup the honest answer is `missing`:
// behalf does not guess that a customer meant to delete something.
func (s *Slot) applyErasure(erasures ErasureLookup) {
	if erasures == nil {
		return
	}
	if ref, ok := erasures(s.Digest); ok {
		s.State = StateDeleted
		if ref != "" {
			s.CauseRef = ref
		}
	}
}

// mismatchFor characterises a blob the store has already refused. The
// digests come from the refusal itself — the store computed them over the
// bytes it actually read — and the second, deliberately unverified read
// only adds detail: how big the altered blob is now, and which manifest
// fields moved. If that read fails, the finding still stands with less
// evidence attached; a mismatch is never downgraded for want of detail.
func mismatchFor(s Slot, store *cas.Store, refusal error) *Mismatch {
	m := &Mismatch{Committed: s.Digest}
	var te *cas.TamperError
	if errors.As(refusal, &te) {
		m.Committed = te.Want
		m.Actual = te.Got
	}
	raw, err := store.ReadRaw(s.Digest)
	if err != nil {
		return m
	}
	m.StoredSize = len(raw)
	m.ChangedFields = changedFields(s.Manifest, raw)
	if m.Actual == "" {
		m.Actual = cas.Digest(raw)
	}
	return m
}

// changedFields compares the receipt's field-digest manifest against the
// bytes now in the store and names the paths that moved (Q37). This is what
// the manifest was captured at write time for: whole-blob tamper detection
// says "something changed", the manifest says "the amount changed".
//
// A path present in the manifest and absent from the stored bytes counts as
// changed; a path the stored bytes added that the manifest never had also
// counts, since either direction is a departure from what was committed.
func changedFields(manifest *receipt.Manifest, stored []byte) []string {
	if manifest == nil || len(manifest.Fields) == 0 {
		return nil
	}
	now := map[string]string{}
	if m := FieldDigests(stored); m != nil {
		for _, f := range m.Fields {
			now[f.Path] = f.Digest
		}
	}
	seen := map[string]bool{}
	var changed []string
	for _, f := range manifest.Fields {
		seen[f.Path] = true
		if now[f.Path] != f.Digest {
			changed = append(changed, f.Path)
		}
	}
	for path := range now {
		if !seen[path] {
			changed = append(changed, path)
		}
	}
	sort.Strings(changed)
	return changed
}

// FieldDigests is the field-digest manifest for a JSON payload: one entry
// per top-level field, each carrying the SHA-256 of that field's exact raw
// value bytes (Q37).
//
// This is the single implementation. The capture surface calls it to write
// the manifest into the receipt and this package calls it to compare against
// stored bytes; two implementations would drift, and a drifted comparison
// would report field changes that never happened.
//
// `root` is deliberately left empty. A Merkle root over canonicalized fields
// would require a canonicalization step — the very thing DSSE/PAE removes
// (Q27) — so filling it with a number no verifier could reproduce would be
// worse than leaving it out. Non-object payloads get no manifest at all,
// which is the schema's "non-JSON gets whole-blob only" rule extended to
// JSON with no fields to manifest.
func FieldDigests(raw []byte) *receipt.Manifest {
	if len(raw) == 0 || raw[0] != '{' {
		return nil
	}
	fields, err := jsonspan.TopLevelKeys(raw)
	if err != nil || len(fields) == 0 {
		return nil
	}
	out := make([]receipt.ManifestField, 0, len(fields))
	for _, f := range fields {
		sum := sha256.Sum256(raw[f.Start:f.End])
		out = append(out, receipt.ManifestField{
			Path:   "$." + f.Name,
			Digest: hex.EncodeToString(sum[:]),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return &receipt.Manifest{Fields: out}
}

// Findings returns the slots that are the payload cover-up — present bytes
// that do not match their commitment. The caller's exit code hangs off
// len(Findings) != 0.
func Findings(slots []Slot) []Slot {
	var out []Slot
	for _, s := range slots {
		if s.Tampered() {
			out = append(out, s)
		}
	}
	return out
}
