// Package capture holds the receipt-building primitives every behalf capture
// surface needs: the cross-process monotonic counter, the intent and step-key
// digests, the payload-slot builder, the authority/attribution rollup, and the
// seal-sign-envelope step.
//
// # The lift, stated plainly
//
// Every function here is a lift of an unexported function in
// internal/proxy/capture.go, byte-for-byte in behaviour. The proxy was NOT
// edited to call this package: the Week-3 hooks work that needed these
// primitives was scoped to leave the canonical capture surface alone, so for
// now there are two copies of each computation. That is a drift risk and it is
// named here rather than hidden.
//
// The risk is contained by test, not by discipline: internal/hooks runs the
// real MCP proxy against a fake server and asserts that the proxy's own
// `attempt.intent_digest`, `step_key` and `emitter.counter` are exactly what
// this package computes for the same inputs (see
// internal/hooks/crosssurface_test.go). If a future change moves one copy, that
// test fails. The follow-up is to point internal/proxy at this package and
// delete its private copies.
//
// One constant here is load-bearing across processes rather than merely
// duplicated: CounterLockFile MUST match the proxy's `counterLockFile`, or the
// two surfaces will allocate the same counter value concurrently and Q48's
// gap detector will report loss that never happened.
package capture

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/envelope"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/flock"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/jsonspan"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// CounterLockFile serializes the read-increment-write of the per-emitter
// monotonic counter across every process sharing one state dir (Q48).
//
// This exact name is also spelled in internal/proxy. Two surfaces may run
// concurrently against one state directory — a Claude Code session driving
// both the hook binary and an MCP server wrapped in behalf-proxy is the normal
// case, not an exotic one — and a lock file with a different name is no lock at
// all.
const CounterLockFile = "emitter.counter.lock"

// NextCounter allocates the next per-emitter monotonic counter under stateDir,
// atomically across processes. Stamped before spooling so loss or reordering
// between capture and append is detectable (Q48).
func NextCounter(stateDir string) (int, error) {
	var n int
	err := flock.With(filepath.Join(stateDir, CounterLockFile), func() error {
		var ferr error
		n, ferr = identity.NextEmitterCounter(stateDir)
		return ferr
	})
	return n, err
}

// IntentDigest is sha256 over an operation name, a newline, and the raw
// argument bytes — the anchor an orphan_intent, a denial or a failed
// delegation points at when there is no action to reference (Q4, Q5).
//
// The proxy feeds it the MCP tool name and the raw `params` bytes as
// forwarded. A hook feeds it the normalised operation name and the raw
// `tool_input` bytes. The construction is the same; the inputs are what each
// surface could actually see, which is why the two surfaces' digests do not
// collide and cannot be compared (see internal/hooks/dedup.go).
func IntentDigest(name string, args []byte) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write(args)
	return hex.EncodeToString(h.Sum(nil))
}

// StepKey is sha256 over the operation name, the normalized argument schema
// and the causal ordinal, each newline-separated (Q85). Identical calls hash
// the same across runs; a call whose argument shape changed hashes
// differently, which is what makes `behalf diff` work on day-one data.
func StepKey(name string, args []byte, ordinal int) string {
	h := sha256.New()
	h.Write([]byte(name))
	h.Write([]byte("\n"))
	h.Write([]byte(NormalizedArgSchema(args)))
	h.Write([]byte("\n"))
	h.Write([]byte(strconv.Itoa(ordinal)))
	return hex.EncodeToString(h.Sum(nil))
}

// NormalizedArgSchema renders the sorted top-level key paths of an arguments
// object. Absent or non-object arguments normalize to "".
func NormalizedArgSchema(args []byte) string {
	names := topLevelNames(args)
	if len(names) == 0 {
		return ""
	}
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ","
		}
		out += "$." + n
	}
	return out
}

func topLevelNames(obj []byte) []string {
	if len(obj) == 0 || obj[0] != '{' {
		return nil
	}
	fields, err := jsonspan.TopLevelKeys(obj)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, f.Name)
	}
	sort.Strings(names)
	return names
}

// FieldDigests is the Q37 field-digest manifest: one entry per top-level JSON
// field, each carrying the SHA-256 of that field's exact raw value bytes. The
// computation lives in internal/payload, which also reads it back at
// rehydration time — one implementation, because two would drift and a drifted
// comparison would report field changes that never happened (Q83).
func FieldDigests(raw []byte) *receipt.Manifest { return payload.FieldDigests(raw) }

// Slot writes raw into the customer-held CAS and returns the payload slot
// describing it: digest, custody, content type, size, content-address ref,
// state, and — for JSON — the field-digest manifest (Q34–Q38, Q83). The bytes
// are the customer's; behalf's record holds the digest and the reference,
// never the content (Q35).
func Slot(store *cas.Store, role string, raw []byte, contentType string) (receipt.Slot, error) {
	digest, err := store.Put(raw)
	if err != nil {
		return receipt.Slot{}, err
	}
	if contentType == "" {
		contentType = "application/json"
	}
	slot := receipt.Slot{
		Role:        role,
		Digest:      digest,
		Custody:     "customer-held",
		ContentType: contentType,
		Size:        len(raw),
		Ref:         "sha256:" + digest,
		State:       "present",
	}
	if contentType == "application/json" {
		slot.Manifest = FieldDigests(raw)
	}
	return slot, nil
}

// Authority builds the receipt's embedded chain and the two attribution axes
// from a verified chain (Q10, Q12, Q18).
//
// A carried hop's own claim about its verification status is discarded: what
// is recorded is what this surface checked, because a token that grades itself
// is not evidence (Q29). A hop with no result records `asserted` with a
// reason — never an empty status, which the frozen schema rejects and a reader
// would misread.
//
// carriageRoute is stamped on every hop: how the chain reached this surface.
// It is metadata, since verification comes from the signatures regardless
// (Q15).
func Authority(hops []aat.Hop, results []aat.HopResult, carriageRoute string) (*receipt.Authority, receipt.Attribution) {
	if len(hops) == 0 {
		return nil, receipt.Attribution{Verification: "asserted", Class: "unattributed"}
	}
	out := make([]receipt.Hop, 0, len(hops))
	for i, h := range hops {
		res := aat.HopResult{Status: aat.StatusAsserted, Method: aat.MethodNotVerifiedAtCapture}
		if i < len(results) && results[i].Status != "" {
			res = results[i]
		}
		hop := h.ReceiptHop(res)
		hop.CarriageRoute = carriageRoute
		out = append(out, hop)
	}
	class := "delegated"
	switch {
	case out[0].Trigger != nil:
		class = "autonomous"
	case len(out) == 1:
		class = "direct"
	}
	return &receipt.Authority{Chain: out}, receipt.Attribution{
		Verification: aat.Weakest(results),
		Class:        class,
	}
}

// Actor names who acted, when the chain proves a key. The canonical actor
// identity is the deepest hop's key thumbprint — keys are what the
// cryptography proves — and self-reported names ride as verbatim asserted
// labels, per MCP's own warning that they are not verified by the protocol
// (Q16).
//
// The frozen schema requires `actor.jkt` whenever `actor` is present, so a
// receipt with no chain has no actor object and therefore nowhere to put its
// labels. That is a real loss and the callers here handle it by also writing
// the raw source frame to the CAS, where the self-reported names survive as
// customer-held evidence rather than as receipt fields (Q49).
func Actor(auth *receipt.Authority, labels map[string]string) *receipt.Actor {
	if auth == nil || len(auth.Chain) == 0 {
		return nil
	}
	leaf := auth.Chain[len(auth.Chain)-1]
	jkt := leaf.Credential.JKT
	if jkt == "" {
		jkt = JWKThumbprint(leaf.Cnf.JWK)
	}
	if jkt == "" {
		return nil
	}
	a := &receipt.Actor{JKT: jkt, EmitterToActor: "asserted"}
	if len(labels) > 0 {
		a.Labels = map[string]string{}
		for k, v := range labels {
			if v != "" {
				a.Labels[k] = v
			}
		}
		if len(a.Labels) == 0 {
			a.Labels = nil
		}
	}
	return a
}

// JWKThumbprint returns the RFC 7638 thumbprint of an OKP/Ed25519 JWK, or ""
// for anything else — v1 proves Ed25519 keys and says nothing about the rest
// (Q17).
func JWKThumbprint(jwk map[string]any) string {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	if kty != "OKP" || crv != "Ed25519" || x == "" {
		return ""
	}
	return dsse.JWK{Kty: kty, Crv: crv, X: x}.Thumbprint()
}

// Emit seals the receipt once, signs those exact bytes with the emitter key
// (DSSE/PAE), and returns the stored envelope bytes. Seal is the single
// serialization point: nothing downstream re-marshals the payload
// (export-format-v1.md §1.2).
func Emit(key *identity.Key, r *receipt.Receipt) (receiptID string, env []byte, err error) {
	sealed, err := receipt.Seal(r)
	if err != nil {
		return "", nil, fmt.Errorf("capture: seal receipt: %w", err)
	}
	sig := dsse.Sign(key.Private, exportv1.PayloadTypeReceipt, sealed.Bytes())
	return r.ReceiptID, envelope.Build(exportv1.PayloadTypeReceipt, sealed.Bytes(), key.JKT, sig), nil
}

// RFC3339 renders a capture timestamp the way the schema's `captured_at`
// wants it.
func RFC3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// TraceIDFromTraceparent extracts the 32-hex trace-id from a W3C traceparent
// header value ("00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>"). It
// is the `traceparent` rung of the Q7 run_id precedence, shared because both
// surfaces read the same header. Anything that does not parse yields "",
// which drops the rung.
func TraceIDFromTraceparent(tp string) string {
	parts := strings.Split(strings.TrimSpace(tp), "-")
	if len(parts) < 4 || len(parts[1]) != 32 {
		return ""
	}
	if strings.Trim(parts[1], "0123456789abcdef") != "" || parts[1] == strings.Repeat("0", 32) {
		return ""
	}
	return parts[1]
}

// The Q7 run_id precedence rungs, matching the schema's `run_id_provenance`
// enum. `hook-session` is the Claude Code rung; `proxy-session` is the
// last-resort "this capture process's own session", which the hook surface
// also falls back to when a payload carries no session id.
const (
	ProvenanceCaller       = "caller"
	ProvenanceHookSession  = "hook-session"
	ProvenanceTraceparent  = "traceparent"
	ProvenanceProxySession = "proxy-session"
)

// Environment variables the run_id precedence reads.
const (
	// EnvRunID is the caller/SDK-supplied key — the top rung, and the one
	// thing that makes two capture surfaces agree on a run_id (Q7).
	EnvRunID = "BEHALF_RUN_ID"
	// EnvTraceparent is the W3C traceparent the caller exported.
	EnvTraceparent = "TRACEPARENT"
)

// IDSource mints ULIDs from an injectable clock and entropy source.
// receipt_id is client-minted at capture so a retried send can never occupy
// two immutable chain positions (Q46). Both defaults are production
// behaviour — crypto/rand — and a deterministic recording overrides them.
type IDSource struct {
	mu      sync.Mutex
	entropy io.Reader
}

// NewIDSource returns an ID source over entropy; nil means crypto/rand.
func NewIDSource(entropy io.Reader) *IDSource {
	if entropy == nil {
		entropy = rand.Reader
	}
	return &IDSource{entropy: entropy}
}

// ULIDAt mints a ULID whose timestamp is t.
func (s *IDSource) ULIDAt(t time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, err := ulid.New(ulid.Timestamp(t.UTC()), s.entropy)
	if err != nil {
		// crypto/rand does not fail, and an injected stream is infinite by
		// construction. Swallowing this would silently mint colliding ids.
		panic(fmt.Sprintf("capture: mint ulid: %v", err))
	}
	return id.String()
}

// RetainHopTokens writes every signed hop's compact JWS to the customer-held
// CAS, so that the `evidence_ref` each hop already carries resolves to
// something.
//
// # Why this had to exist
//
// The frozen schema types a hop's `verification.evidence_ref` as "what a reader
// should fetch": `sha256:<digest of the hop's compact JWS>`. Every capture
// surface wrote that value from the first record. Nothing wrote the blob. So the
// reference pointed into an empty store, and the delegation chain's signatures
// — the property that makes behalf different from a transparency log — were
// checked exactly once, at capture, by behalf's own code, with the evidence then
// discarded.
//
// That is the self-graded exam this codebase refuses everywhere else (see
// aat.Mint's doc on why `verification` is not a claim). The receipt says
// `verified`; a receipt is not evidence of its own verification; and until this
// call there was nothing left for a sceptic to re-run the check against. It is
// also the reason the offline verifier cannot check chains at all (ENG-38): the
// tokens never reached an export because they never reached the store.
//
// The digest is the same function on both sides — `cas.Digest` and
// `aat.ParHash` are both lowercase-hex SHA-256 over the same bytes — so the blob
// lands at exactly the address the receipt already names. No receipt byte
// changes, which is what lets this be a fix rather than a schema migration.
//
// Unsigned hops have no token and no evidence, and are skipped: the receipt
// records no `evidence_ref` for them either, because there is nothing to fetch.
//
// Failure to store is returned rather than swallowed. A capture surface that
// cannot write to the customer's own store has a problem the caller needs to
// know about, and silently emitting a receipt whose evidence reference dangles
// is the state this function exists to end.
func RetainHopTokens(blobs *cas.Store, hops []aat.Hop) error {
	for _, h := range hops {
		if !h.Signed() {
			continue
		}
		if _, err := blobs.Put([]byte(h.JWS)); err != nil {
			return fmt.Errorf("capture: retain hop token: %w", err)
		}
	}
	return nil
}
