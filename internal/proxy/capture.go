package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

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
	"github.com/behalf-sh/behalf/internal/spool"
)

// OtelConventionsVersion is the gen_ai.* semantic-conventions version in
// force at capture, stamped per record so old receipts can be re-normalised
// when the still-Development conventions move (Q8, Q49).
const OtelConventionsVersion = "1.29.0"

// Surface is the emitter.surface value for this capture surface — the
// canonical v1 surface (Q44, D4).
const Surface = "mcp-proxy"

// KindToolCall is the record kind for a tools/call crossing (Q6).
const KindToolCall = "tool_call"

// KindOrphanIntent is the record kind recovery flushes (Q4, Q5).
const KindOrphanIntent = "orphan_intent"

// CarriageRouteMeta records that a hop arrived beside the request in
// params._meta rather than in band (Q15, D4).
const CarriageRouteMeta = "mcp-_meta:" + MetaKeyChain

// counterLockFile serializes the read-increment-write of the per-emitter
// monotonic counter across proxy processes sharing one state dir (Q48).
const counterLockFile = "emitter.counter.lock"

// capture holds everything the two pumps need to turn a tools/call pair
// into one signed, spooled receipt.
type capture struct {
	emitter *identity.Key
	state   string
	blobs   *cas.Store
	spool   *spool.Spool
	policy  *Policy
	chain   *Chain

	// root is the login material the depth-0 predicate runs against, loaded
	// once per process; chainResults is aat.Verify over the carried chain,
	// computed once because the chain and the material are both fixed for
	// the life of the process. Verifying per receipt would produce the same
	// answer 47 times and read the injected clock while doing it.
	root         aat.RootMaterial
	chainResults []aat.HopResult

	runID       string
	provenance  string
	traceID     string
	serverLabel string
	chainRef    string

	now func() time.Time

	// ids mints receipt_id and intent_id. Injectable so a recording is
	// byte-reproducible (deterministic.go); crypto/rand by default.
	ids *idSource

	// flushed counts the orphan_intent receipts minted at startup.
	flushed int

	// ordinal is the causal ordinal in step_key: the position of this call
	// in the run (Q85). Minted only on the request pump's goroutine.
	ordinal int

	// pending holds tools/call requests awaiting a response, keyed by the
	// JSON-RPC id's exact byte span. The two pumps run concurrently and a
	// server may answer out of order, so responses match by id, never by
	// arrival order.
	mu      sync.Mutex
	pending map[string]*pending
}

// nextCounter allocates the per-emitter monotonic counter, stamped before
// spooling so loss or reordering between capture and append is detectable
// (Q48). The file lock makes the allocation atomic across processes; the
// counter is consumed by the intent and carried by whichever receipt
// records that crossing, so appended receipts have no counter gaps.
func (c *capture) nextCounter() (int, error) {
	var n int
	err := flock.With(filepath.Join(c.state, counterLockFile), func() error {
		var ferr error
		n, ferr = identity.NextEmitterCounter(c.state)
		return ferr
	})
	return n, err
}

// intentDigest is sha256 over the tool name, a newline, and the raw params
// bytes as forwarded — the anchor an orphan_intent, a denial or a failed
// delegation points at when there is no action to reference (Q4, Q5).
func intentDigest(tool string, params []byte) string {
	h := sha256.New()
	h.Write([]byte(tool))
	h.Write([]byte("\n"))
	h.Write(params)
	return hex.EncodeToString(h.Sum(nil))
}

// stepKey is sha256 over the tool name, the normalized argument schema and
// the causal ordinal, each newline-separated (Q85). The normalized argument
// schema is the sorted list of top-level `params.arguments` key paths,
// comma-joined: identical calls hash the same across runs, and a call whose
// argument shape changed hashes differently, which is what makes the diff
// demo work on day-one data.
func stepKey(tool string, args []byte, ordinal int) string {
	h := sha256.New()
	h.Write([]byte(tool))
	h.Write([]byte("\n"))
	h.Write([]byte(normalizedArgSchema(args)))
	h.Write([]byte("\n"))
	h.Write([]byte(strconv.Itoa(ordinal)))
	return hex.EncodeToString(h.Sum(nil))
}

// normalizedArgSchema renders the sorted top-level key paths of an
// arguments object. Absent or non-object arguments normalize to "".
func normalizedArgSchema(args []byte) string {
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

// slotFor writes raw into the customer-held CAS and returns the payload
// slot describing it: digest, custody, content type, size, content-address
// ref, state, and — for JSON objects — the field-digest manifest (Q34–Q38,
// Q83). The bytes are the customer's; behalf's record holds the digest and
// the reference, never the content (Q35).
func (c *capture) slotFor(role string, raw []byte) (receipt.Slot, error) {
	digest, err := c.blobs.Put(raw)
	if err != nil {
		return receipt.Slot{}, err
	}
	slot := receipt.Slot{
		Role:        role,
		Digest:      digest,
		Custody:     "customer-held",
		ContentType: "application/json",
		Size:        len(raw),
		Ref:         "sha256:" + digest,
		State:       "present",
		Manifest:    fieldDigestManifest(raw),
	}
	return slot, nil
}

// fieldDigestManifest is the schema's Q37 slot: one entry per top-level
// JSON field, each carrying the SHA-256 of that field's exact raw value
// bytes — what keeps verifiable redaction, per-field retention and
// selective disclosure reachable for v1-era records.
//
// The computation lives in internal/payload, which is also what reads the
// manifest back at rehydration time to say *which field* an altered blob
// changed (Q83). One implementation, because two would drift and a drifted
// comparison would report field changes that never happened.
func fieldDigestManifest(raw []byte) *receipt.Manifest { return payload.FieldDigests(raw) }

// recordOutcomeFields records, beside the outcome's status, the scalars the
// capture-time tool policy named for this tool (Policy.OutcomeFields).
//
// Why this exists at all. A receipt says what crossed the boundary, and for
// a refund the number that crossed is the amount — it is what the delegated
// ceiling in the chain constrains, so a receipt without it cannot be read
// against that ceiling and `behalf why` has nothing to compute a scope
// excess from (ENG-29, Q11, Q13). The alternative was a new receipt field;
// the outcome object already exists for exactly this ("result or failure of
// the attempted operation", Q4) and the schema already allows a surface's
// own result fields in it, so nothing needs widening.
//
// Three constraints, each of them a boundary rather than a nicety:
//
//   - Only what the operator named. There is no sniffing for amount-shaped
//     fields: the policy file says which ones, its digest rides the receipt,
//     and the choice is auditable like the risk class beside it (Q6).
//   - Only scalars, and only from the tool's own `structuredContent`. A
//     response body is customer-held and referenced by digest (Q34–Q38);
//     lifting an object or an array would quietly turn the receipt into a
//     copy of it.
//   - Verbatim bytes. The value is spliced out of the response and stored as
//     it arrived — no re-encoding, so a decimal or a large integer is
//     never round-tripped through a float. Any formatting (cents to
//     currency, say) is the read path's job, not the record's.
func recordOutcomeFields(out *receipt.Outcome, result []byte, names []string) {
	if len(names) == 0 || len(result) == 0 || out.Status != "ok" {
		return
	}
	structured, err := jsonspan.ExtractTopLevelValue(result, "structuredContent")
	if err != nil {
		return
	}
	for _, name := range names {
		// status and error are the outcome's own fields; a policy that named
		// one would be asking the tool to overwrite behalf's verdict.
		if name == "status" || name == "error" {
			continue
		}
		raw, err := jsonspan.ExtractTopLevelValue(structured, name)
		if err != nil || !isRecordableScalar(raw) {
			continue
		}
		if out.Extra == nil {
			out.Extra = map[string]any{}
		}
		out.Extra[name] = json.RawMessage(append([]byte(nil), raw...))
	}
}

// isRecordableScalar reports whether a stored value is a string, number or
// boolean. Objects and arrays are content; null is an absent value, and
// recording it would assert something the response did not say.
func isRecordableScalar(raw []byte) bool {
	for _, ch := range raw {
		switch ch {
		case ' ', '\t', '\n', '\r':
			continue
		case '{', '[':
			return false
		case 'n': // null
			return false
		default:
			return true
		}
	}
	return false
}

// authorityFor returns the embedded chain and the attribution axes, with
// the per-hop verification the proxy actually performed (Q18).
//
// Verification runs at capture, in customer territory, entirely offline:
// depth 0 is D5's three checks by way of oidclogin, every hop above it is
// the AAT signature chain plus its invariants, and attenuation is
// internal/why's comparator over the raw RFC 9396 grants (Q17, Q13). The
// per-hop `{status, method, evidence_ref}` written here is that result and
// nothing else — a carried hop's own claim about its verification status is
// discarded on the way in, because a token that grades itself is not
// evidence (Q29).
//
// There is no `asserted` floor any more, and there does not need to be: the
// floor existed because nothing was checked. What survives it is the
// principle it stood for — record exactly what was checked. A chain with no
// root material behind it still reads `asserted` at every hop, and says why.
//
// The receipt-level rollup is the weakest hop (Q12, §8), and
// attribution.class comes from chain shape.
func (c *capture) authorityFor() (*receipt.Authority, receipt.Attribution) {
	return c.authorityForChain(c.chain, c.chainResults)
}

// authorityForChain builds the authority block for one chain and its
// verification results.
func (c *capture) authorityForChain(chain *Chain, results []aat.HopResult) (*receipt.Authority, receipt.Attribution) {
	if chain == nil || len(chain.Hops) == 0 {
		return nil, receipt.Attribution{Verification: "asserted", Class: "unattributed"}
	}
	hops := make([]receipt.Hop, 0, len(chain.Hops))
	for i, h := range chain.Hops {
		// A hop with no result is a hop nothing ran against. That cannot
		// happen on either path into here, and if it ever did, the honest
		// record is `asserted` with a reason — never an empty status, which
		// the frozen schema would reject and a reader would misread.
		res := aat.HopResult{Status: "asserted", Method: aat.MethodNotVerifiedAtCapture}
		if i < len(results) && results[i].Status != "" {
			res = results[i]
		}
		hop := h.ReceiptHop(res)
		hop.CarriageRoute = CarriageRouteMeta
		hops = append(hops, hop)
	}
	class := "delegated"
	switch {
	case hops[0].Trigger != nil:
		class = "autonomous"
	case len(hops) == 1:
		class = "direct"
	}
	return &receipt.Authority{Chain: hops}, receipt.Attribution{
		Verification: aat.Weakest(results),
		Class:        class,
	}
}

// actorFor names who acted, when the chain proves a key. The canonical
// actor identity is the deepest hop's key thumbprint — keys are what the
// cryptography proves — and the MCP server name rides as a verbatim
// asserted label, per MCP's own warning that names are self-reported (Q16).
func (c *capture) actorFor(auth *receipt.Authority) *receipt.Actor {
	if auth == nil || len(auth.Chain) == 0 {
		return nil
	}
	leaf := auth.Chain[len(auth.Chain)-1]
	jkt := leaf.Credential.JKT
	if jkt == "" {
		jkt = jwkThumbprint(leaf.Cnf.JWK)
	}
	if jkt == "" {
		return nil
	}
	a := &receipt.Actor{JKT: jkt, EmitterToActor: "asserted"}
	if c.serverLabel != "" {
		a.Labels = map[string]string{"mcp_server": c.serverLabel}
	}
	return a
}

// jwkThumbprint returns the RFC 7638 thumbprint of an OKP/Ed25519 JWK, or
// "" for anything else — v1 proves Ed25519 keys and says nothing about the
// rest (Q17).
func jwkThumbprint(jwk map[string]any) string {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	if kty != "OKP" || crv != "Ed25519" || x == "" {
		return ""
	}
	return dsse.JWK{Kty: kty, Crv: crv, X: x}.Thumbprint()
}

// emit seals the receipt once, signs those exact bytes with the emitter key
// (DSSE/PAE), and returns the stored envelope bytes. Seal is the single
// serialization point: nothing downstream re-marshals the payload.
func (c *capture) emit(r *receipt.Receipt) (receiptID string, env []byte, err error) {
	sealed, err := receipt.Seal(r)
	if err != nil {
		return "", nil, fmt.Errorf("proxy: seal receipt: %w", err)
	}
	sig := dsse.Sign(c.emitter.Private, exportv1.PayloadTypeReceipt, sealed.Bytes())
	return r.ReceiptID, envelope.Build(exportv1.PayloadTypeReceipt, sealed.Bytes(), c.emitter.JKT, sig), nil
}

// correlationFor carries the trace id when one was observed; the other four
// correlation keys are indexed but not required at ingest.
func (c *capture) correlationFor() *receipt.Correlation {
	if c.traceID == "" {
		return nil
	}
	return &receipt.Correlation{TraceID: c.traceID}
}

func rfc3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }
