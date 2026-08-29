package diff

import (
	"bytes"
	"encoding/json"
	"regexp"
	"sort"
	"strings"
)

// Class is what kind of difference one aligned pair carries. A pair may
// carry several at once (the demo's step 31 differs in both `arguments` and
// `result`), which is why Difference holds a set.
type Class string

const (
	// ClassArguments — the call the agent made differs: its target, its
	// idempotency key, or the digest evidence for its (customer-held) input.
	ClassArguments Class = "arguments"
	// ClassResult — what came back differs.
	ClassResult Class = "result"
	// ClassOutcome — the operation's status or error differs. An `ok` in one
	// run and an `error` in the other is the loudest thing a diff can find.
	ClassOutcome Class = "outcome"
	// ClassOnlyInA — the step exists in the first run and has no counterpart
	// in the second: a deletion.
	ClassOnlyInA Class = "only-in-A"
	// ClassOnlyInB — the step exists only in the second run: an insertion.
	// A retry storm shows up as a run of these.
	ClassOnlyInB Class = "only-in-B"
	// ClassOrder — the same values came back in a different sequence. This
	// is a deliberately separate class from ClassResult because it is the
	// divergence that reads as "nothing changed" to every other tool: same
	// data, same count, same everything, and the agent picks a different
	// element.
	ClassOrder Class = "order"
)

// classOrder is the display order of the class set.
var classOrder = []Class{ClassOutcome, ClassArguments, ClassResult, ClassOrder, ClassOnlyInA, ClassOnlyInB}

// ChangeKind is what happened to one field.
type ChangeKind string

const (
	KindChanged   ChangeKind = "changed"
	KindOnlyInA   ChangeKind = "only-in-A"
	KindOnlyInB   ChangeKind = "only-in-B"
	KindReordered ChangeKind = "reordered"
)

// Change is one field-level finding inside an aligned pair. A and B are the
// stored bytes at that path — never re-serialized, only sliced.
type Change struct {
	Class Class
	Path  string
	Kind  ChangeKind
	A, B  json.RawMessage
	// Count is the element count for a reordered array.
	Count int
}

// Difference is one aligned pair that is not identical.
type Difference struct {
	// Index is the pair's position in Result.Pairs — the aligned order the
	// causality rule reads.
	Index   int
	Pair    Pair
	Classes []Class
	Changes []Change
	// NoiseFiltered names the paths the noise filter dropped, so a reader
	// can audit the filter instead of trusting it. `--all` prints them.
	NoiseFiltered []string
	// Opaque marks a pair whose ONLY evidence is a payload-slot digest: the
	// receipt records that customer-held content diverged, but not what
	// changed in it (Q34–Q38 keep the content out of the record).
	//
	// These are reported and never named as a cause, because a hash cannot
	// answer "which step caused it" — and because a digest is the signal
	// most likely to fire for reasons that have nothing to do with the
	// action. A response blob routinely carries a session id, a cursor or a
	// timestamp the receipt's outcome never records, so counting these as
	// result differences turns a perfect alignment into a wall of findings
	// that cannot be explained — the exact failure this feature exists to
	// avoid. Only the OUTPUT slot can land here; the input slot's digest is
	// not compared at all (NotCompared).
	Opaque bool
	// Truncated is set when a pair carried more field-level changes than
	// maxChangesPerPair; the pair is still counted once, and the render says
	// how many were kept.
	Truncated bool
	// Suppressed is the downstream heuristic's verdict (causality.go).
	Suppressed bool
}

// Has reports whether the difference carries class c.
func (d *Difference) Has(c Class) bool {
	for _, got := range d.Classes {
		if got == c {
			return true
		}
	}
	return false
}

// maxChangesPerPair bounds the field-level findings kept for one pair. A
// 40 KB result blob that differs everywhere is a real input; walking all of
// it and printing all of it is not a diff, it is the noise failure this
// feature exists to avoid.
const maxChangesPerPair = 64

// NoisyFields are field names ignored wherever they appear inside a
// compared value, because two runs differ in them by construction. This is
// the fine half of the noise filter — the coarse half, whole receipt fields
// that never enter the compared view at all, is NotCompared in diff.go.
//
// The list is deliberately short and deliberately boring. Every entry here
// is a field that a correct system re-mints per run; a field that merely
// often changes (an amount, an order id, a status) is not on it, because
// hiding one of those is exactly the failure that would make the answer
// wrong rather than merely noisy. Volatile values under names not on this
// list are caught by shape instead — see volatileValue.
var NoisyFields = []string{
	// log and receipt coordinates
	"receipt_id", "log_index", "leaf_hash", "run_id",
	// capture and wall-clock time
	"captured_at", "created_at", "updated_at", "started_at",
	"finished_at", "completed_at", "expires_at", "timestamp", "ts",
	// elapsed time
	"duration_ms", "latency_ms", "elapsed_ms", "took_ms",
	// per-request identifiers minted by the transport
	"request_id", "trace_id", "span_id", "session_id", "correlation_id",
	"nonce", "etag", "cursor",
}

var noisyField = func() map[string]bool {
	m := make(map[string]bool, len(NoisyFields))
	for _, f := range NoisyFields {
		m[f] = true
	}
	return m
}()

// NoisyPathSegments are path components that make everything BENEATH them
// noise, not just a leaf of that name.
//
// `_meta` is the MCP envelope the proxy forwards alongside a tool call's
// real arguments: it carries the delegation chain and the W3C baggage
// header, and that baggage carries `behalf-run-id`. The run id is the one
// thing guaranteed to differ between any two runs, so every field under
// `_meta` differs at every step by construction. Comparing them would report
// a whole run as changed and explain nothing — the precise failure this
// filter exists to prevent.
//
// This is why the comparison reaches for `params.arguments` and the tool
// name and target rather than the params blob as forwarded. See also the
// input-slot digest entry in NotCompared, which is the same problem one
// level up: a digest over the whole forwarded blob covers `_meta` too, and
// is therefore not a digest of the action.
var NoisyPathSegments = []string{"_meta"}

var noisySegment = func() map[string]bool {
	m := make(map[string]bool, len(NoisyPathSegments))
	for _, s := range NoisyPathSegments {
		m[s] = true
	}
	return m
}()

// Volatile value shapes. A value that differs between two runs but is a
// ULID, a UUID or an RFC 3339 timestamp on both sides is machinery, not a
// finding — whatever field name it hides under.
var (
	ulidRE      = regexp.MustCompile(`^[0-9A-HJKMNP-TV-Z]{26}$`)
	uuidRE      = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	rfc3339RE   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$`)
	volatileREs = []*regexp.Regexp{ulidRE, uuidRE, rfc3339RE}
)

// volatileValue reports whether a differing pair of values is machinery by
// shape: both sides are the same kind of per-run identifier or timestamp.
// Both sides must match the same shape — a ULID against a null is a real
// difference (something is missing), not noise.
func volatileValue(a, b json.RawMessage) bool {
	sa, oka := jsonString(a)
	sb, okb := jsonString(b)
	if !oka || !okb {
		return false
	}
	for _, re := range volatileREs {
		if re.MatchString(sa) && re.MatchString(sb) {
			return true
		}
	}
	return false
}

// isNoise is the whole fine filter, in one place so a test can drive it.
func isNoise(path string, a, b json.RawMessage) bool {
	if noisyField[leafKey(path)] {
		return true
	}
	for _, seg := range pathSegments(path) {
		if noisySegment[seg] {
			return true
		}
	}
	return volatileValue(a, b)
}

// leafKey is the last named segment of a path: "orders[0].created_at" ->
// "created_at". Array indices are not names, so they are stepped over.
func leafKey(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.IndexByte(path, '['); i >= 0 {
		path = path[:i]
	}
	return path
}

// pathSegments splits a path into its components, treating array indices as
// segments of their own: "input.$._meta.baggage" -> [input $ _meta baggage],
// "rows[0]._meta.x" -> [rows 0 _meta x].
func pathSegments(path string) []string {
	if path == "" {
		return nil
	}
	flat := strings.NewReplacer("[", ".", "]", "").Replace(path)
	return strings.Split(flat, ".")
}

// field is one entry of a compared view: a path and the stored bytes at it.
type field struct {
	path  string
	value json.RawMessage
}

// fields is a compared view, kept ordered so the render is stable and the
// most useful field leads.
type fields []field

func (f fields) get(path string) (json.RawMessage, bool) {
	for _, e := range f {
		if e.path == path {
			return e.value, true
		}
	}
	return nil, false
}

func shapeOf(f fields) string {
	paths := make([]string, 0, len(f))
	for _, e := range f {
		paths = append(paths, e.path)
	}
	sort.Strings(paths)
	return strings.Join(paths, ",")
}

// projectViews builds the three compared views out of one receipt.
//
// Arguments are thin on purpose: a receipt never carries the raw argument
// bytes (payload content is customer-held and referenced by digest, Q34–Q38),
// so what can be compared is the operation name, its target, the idempotency
// key, and whatever the field-digest manifest pins per argument field (Q37).
// The manifest is the useful cut precisely because it is per-field: a
// difference under `$.arguments` names which argument changed, while
// anything under `$._meta` is the forwarding envelope and is filtered.
//
// The INPUT slot's own digest is deliberately absent — see NotCompared. It
// covers the params object as forwarded, `_meta` included, so it differs at
// every step of any two runs and can never be evidence about the action.
//
// The OUTPUT slot's digest survives as FALLBACK evidence: it covers what
// came back from the tool, which behalf does not decorate. It is a hash of
// bytes the result view mostly already compares, so reporting both would
// report every result difference twice; it earns its place only when it is
// the only thing that differs, which is exactly when the customer-held
// response diverged without the receipt showing how. See compareOne and
// Difference.Opaque.
func projectViews(v *receiptView) (args, result, outcome, outputSlot fields) {
	args = append(args, field{"operation", jsonOf(v.Operation.Name)})
	if v.Operation.Target != "" {
		args = append(args, field{"target", jsonOf(v.Operation.Target)})
	}
	if v.Operation.IdempotencyKey != "" {
		args = append(args, field{"idempotency_key", jsonOf(v.Operation.IdempotencyKey)})
	}

	for _, slot := range v.Payload {
		switch slot.Role {
		case "input":
			if slot.Manifest != nil {
				for _, mf := range slot.Manifest.Fields {
					args = append(args, field{"input." + mf.Path, jsonOf(mf.Digest)})
				}
			}
			if slot.State != "" && slot.State != "present" {
				args = append(args, field{"input.state", jsonOf(slot.State)})
			}
		case "output":
			if slot.State != "" && slot.State != "present" {
				result = append(result, field{"output.state", jsonOf(slot.State)})
			}
			outputSlot = slotEvidence("output", slot)
		}
	}

	// The outcome object carries status and error (the outcome view) and any
	// number of surface-specific result fields (the result view), flattened
	// into the same object by the schema.
	keys := make([]string, 0, len(v.Operation.Outcome))
	for k := range v.Operation.Outcome {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		switch k {
		case "status", "error":
			outcome = append(outcome, field{k, v.Operation.Outcome[k]})
		default:
			result = append(result, field{k, v.Operation.Outcome[k]})
		}
	}
	return args, result, outcome, outputSlot
}

// slotEvidence is the digest and size of one payload slot: the fallback
// comparison, kept out of the main views so it can only ever corroborate.
func slotEvidence(role string, slot slotView) fields {
	var out fields
	if slot.Digest != "" {
		out = append(out, field{role + ".digest", jsonOf(slot.Digest)})
	}
	if slot.Size != 0 {
		out = append(out, field{role + ".size", jsonOf(slot.Size)})
	}
	return out
}

// Compare runs the structural comparison over every aligned pair and
// returns the pairs that are not identical, in aligned order.
func Compare(pairs []Pair) []Difference {
	var out []Difference
	for i, p := range pairs {
		if d, ok := compareOne(i, p); ok {
			out = append(out, d)
		}
	}
	return out
}

func compareOne(index int, p Pair) (Difference, bool) {
	d := Difference{Index: index, Pair: p}
	switch {
	case p.A == nil && p.B == nil:
		return d, false
	case p.B == nil:
		d.Classes = []Class{ClassOnlyInA}
		return d, true
	case p.A == nil:
		d.Classes = []Class{ClassOnlyInB}
		return d, true
	}

	budget := maxChangesPerPair
	var noise []string
	diffFields(ClassOutcome, p.A.outcome, p.B.outcome, &d.Changes, &noise, &budget)
	diffFields(ClassArguments, p.A.args, p.B.args, &d.Changes, &noise, &budget)
	diffFields(ClassResult, p.A.result, p.B.result, &d.Changes, &noise, &budget)

	// Fallback evidence: a payload slot digest is compared only when the
	// structured evidence in its class found nothing. See projectViews.
	structural := len(d.Changes)
	if !hasClass(d.Changes, ClassResult) {
		diffFields(ClassResult, p.A.outputSlot, p.B.outputSlot, &d.Changes, &noise, &budget)
	}
	d.Opaque = structural == 0 && len(d.Changes) > 0

	d.NoiseFiltered = noise
	d.Truncated = budget <= 0
	if len(d.Changes) == 0 {
		return d, false
	}
	d.Classes = classesOf(d.Changes)
	return d, true
}

func hasClass(changes []Change, c Class) bool {
	for _, ch := range changes {
		if ch.Class == c {
			return true
		}
	}
	return false
}

// classesOf collapses the field-level changes into the pair's class set, in
// display order. A reordered array contributes ClassOrder as well as
// ClassResult: it is a result difference, and it is the particular result
// difference worth its own name.
func classesOf(changes []Change) []Class {
	seen := map[Class]bool{}
	for _, ch := range changes {
		seen[ch.Class] = true
		if ch.Kind == KindReordered {
			seen[ClassOrder] = true
		}
	}
	var out []Class
	for _, c := range classOrder {
		if seen[c] {
			out = append(out, c)
		}
	}
	return out
}

// diffFields walks two views path by path.
func diffFields(class Class, a, b fields, out *[]Change, noise *[]string, budget *int) {
	seen := map[string]bool{}
	for _, e := range a {
		seen[e.path] = true
		bv, ok := b.get(e.path)
		if !ok {
			appendChange(out, noise, budget, Change{Class: class, Path: e.path, Kind: KindOnlyInA, A: e.value})
			continue
		}
		diffValue(class, e.path, e.value, bv, out, noise, budget)
	}
	for _, e := range b {
		if !seen[e.path] {
			appendChange(out, noise, budget, Change{Class: class, Path: e.path, Kind: KindOnlyInB, B: e.value})
		}
	}
}

// diffValue is the recursive structural comparison of two stored values.
//
// Equality is decided on canonical bytes (sorted object keys, numbers kept
// as their literal source text through json.Number) so that a key-order
// difference is not a finding and a decimal like 1200.00 is never
// round-tripped through a float.
func diffValue(class Class, path string, a, b json.RawMessage, out *[]Change, noise *[]string, budget *int) {
	if *budget <= 0 {
		return
	}
	ca, errA := canon(a)
	cb, errB := canon(b)
	if errA != nil || errB != nil {
		if !bytes.Equal(a, b) {
			appendChange(out, noise, budget, Change{Class: class, Path: path, Kind: KindChanged, A: a, B: b})
		}
		return
	}
	if bytes.Equal(ca, cb) {
		return
	}

	ka, kb := jsonKind(ca), jsonKind(cb)
	switch {
	case ka == kindObject && kb == kindObject:
		var oa, ob map[string]json.RawMessage
		if json.Unmarshal(ca, &oa) == nil && json.Unmarshal(cb, &ob) == nil {
			keys := unionKeys(oa, ob)
			for _, k := range keys {
				sub := k
				if path != "" {
					sub = path + "." + k
				}
				va, okA := oa[k]
				vb, okB := ob[k]
				switch {
				case okA && okB:
					diffValue(class, sub, va, vb, out, noise, budget)
				case okA:
					appendChange(out, noise, budget, Change{Class: class, Path: sub, Kind: KindOnlyInA, A: va})
				default:
					appendChange(out, noise, budget, Change{Class: class, Path: sub, Kind: KindOnlyInB, B: vb})
				}
			}
			return
		}
	case ka == kindArray && kb == kindArray:
		var aa, ab []json.RawMessage
		if json.Unmarshal(ca, &aa) == nil && json.Unmarshal(cb, &ab) == nil {
			// Same elements, different sequence: one finding at the container,
			// not one per element. This is the demo's step 12 and the whole
			// reason ClassOrder exists.
			if sameMultiset(aa, ab) {
				appendChange(out, noise, budget, Change{
					Class: class, Path: path, Kind: KindReordered,
					A: a, B: b, Count: len(aa),
				})
				return
			}
			n := len(aa)
			if len(ab) > n {
				n = len(ab)
			}
			for i := 0; i < n; i++ {
				sub := indexPath(path, i)
				switch {
				case i < len(aa) && i < len(ab):
					diffValue(class, sub, aa[i], ab[i], out, noise, budget)
				case i < len(aa):
					appendChange(out, noise, budget, Change{Class: class, Path: sub, Kind: KindOnlyInA, A: aa[i]})
				default:
					appendChange(out, noise, budget, Change{Class: class, Path: sub, Kind: KindOnlyInB, B: ab[i]})
				}
			}
			return
		}
	}
	appendChange(out, noise, budget, Change{Class: class, Path: path, Kind: KindChanged, A: a, B: b})
}

func appendChange(out *[]Change, noise *[]string, budget *int, c Change) {
	if isNoise(c.Path, c.A, c.B) {
		*noise = append(*noise, c.Path)
		return
	}
	if *budget <= 0 {
		return
	}
	*budget--
	*out = append(*out, c)
}

func indexPath(path string, i int) string {
	if path == "" {
		return "[" + itoa(i) + "]"
	}
	return path + "[" + itoa(i) + "]"
}

func unionKeys(a, b map[string]json.RawMessage) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(a)+len(b))
	for k := range a {
		seen[k] = true
		out = append(out, k)
	}
	for k := range b {
		if !seen[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

// sameMultiset reports whether two arrays hold the same elements in a
// different sequence.
func sameMultiset(a, b []json.RawMessage) bool {
	if len(a) != len(b) || len(a) == 0 {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, e := range a {
		counts[string(e)]++
	}
	for _, e := range b {
		counts[string(e)]--
		if counts[string(e)] < 0 {
			return false
		}
	}
	return true
}
