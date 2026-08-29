// Package fixture generates the deterministic Week-1 fixture runs
// (docs/export-format-v1.md §4): run_9f2a.jsonl and run_c71e.jsonl, 47
// receipts each, plus a tiny 3-receipt export for the vector corpus.
//
// Everything here is fixed: seeds, timestamps, ULID entropy, the step
// script. Two invocations must produce byte-identical files. Every receipt
// embeds the full three-hop delegation chain whole (Q10, schema §7), and the
// chain diverges at the leaf hop, which is signature-verified in run_9f2a
// and caller-asserted in run_c71e — so run_9f2a rolls up to `verified` and
// run_c71e to `asserted` (Q12).
//
// # The action divergence, and how far it travels
//
// The runs diverge in the world at step 12: `orders.search` returns the same
// two refundable orders in a different sequence, and the agent takes
// results[0]. Everything the agent does afterwards that a support agent
// would hang off the order it chose is about that order — it reads the
// order, the card that paid for it, its shipment and its SKU, prechecks the
// refund against its amount, raises an approval for it, issues the refund at
// step 31, and then records what it refunded on the ticket, in the CRM, in
// the customer's mail and in the audit note. The steps that would not depend
// on the selection — the refund policy, the knowledge base, verifying the
// customer, closing the ticket — do not.
//
// This mirrors cmd/behalf-record's script step for step, because the two
// exist to be the same session: one recorded through the real proxy, one
// built by hand for the export-format tests and the tamper suite.
//
// # One decimal string in the file
//
// The literal "1200.00" appears exactly once in run_c71e.jsonl — in the
// step-31 payload — because the cover-up demo runs sed 's/1200.00/12.00/'
// over that file and the verifier must report the break at index 31 and
// nowhere else. Every other amount in the run, at every later step that
// mentions the refund, is integer `amount_cents`, and the later steps name
// the order and the refund by id. Nothing else in the file may even match
// the demo's unescaped /1200.00/ (see TestCoverUpTargetIsUnique).
package fixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// OtelConventionsVersion is the gen_ai.* conventions version stamped on
// every fixture receipt (Q8, Q49).
const OtelConventionsVersion = "1.29.0"

// Variant selects which side of the step-12/step-31 divergence a run takes.
type Variant int

const (
	// VariantA is run_9f2a: ord_5512 ($12.00, 1200 cents) first at step 12,
	// refund amount "12.00" at step 31.
	VariantA Variant = iota
	// VariantB is run_c71e: ord_5518 (120000 cents) first at step 12, refund
	// amount "1200.00" at step 31.
	VariantB
)

// Spec describes one deterministic run.
type Spec struct {
	RunID     string
	LogOrigin string
	Start     time.Time
	StepEvery time.Duration
	Count     int
	Variant   Variant
	// HeadSigner, if non-nil, signs the head line with a key distinct from
	// the emitter (used by the tiny vector export to exercise multi-key
	// headers). Nil means the emitter signs the head.
	HeadSigner *testkeys.Key
}

// Run9F2A is the baseline run: the agent sees ord_5512 first and refunds
// $12.00.
func Run9F2A() Spec {
	return Spec{
		RunID:     "run_9f2a",
		LogOrigin: "behalf.sh/demo/run_9f2a",
		Start:     time.Date(2026, 8, 25, 22, 4, 0, 0, time.UTC),
		StepEvery: 5 * time.Second,
		Count:     47,
		Variant:   VariantA,
	}
}

// RunC71E is the divergent run: ord_5518 first, refund "1200.00".
func RunC71E() Spec {
	return Spec{
		RunID:     "run_c71e",
		LogOrigin: "behalf.sh/demo/run_c71e",
		Start:     time.Date(2026, 8, 26, 2, 17, 0, 0, time.UTC),
		StepEvery: 5 * time.Second,
		Count:     47,
		Variant:   VariantB,
	}
}

// Tiny is the 3-receipt export used by the vector corpus, with a head key
// distinct from the emitter key.
func Tiny() Spec {
	head := testkeys.HeadSigner()
	return Spec{
		RunID:      "run_tiny",
		LogOrigin:  "behalf.sh/demo/tiny",
		Start:      time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC),
		StepEvery:  5 * time.Second,
		Count:      3,
		Variant:    VariantA,
		HeadSigner: &head,
	}
}

// Result is a generated export plus the intermediate values tests and the
// vector generator need.
type Result struct {
	Bytes      []byte     // the complete .jsonl file
	Payloads   [][]byte   // the sealed payload bytes, per leaf, exactly as spliced
	LeafHashes [][32]byte // per-leaf hashes
	Chain      [32]byte   // final chain value
	LogOrigin  string
}

// Generate builds the export for spec. Deterministic: equal specs produce
// byte-identical output.
func Generate(spec Spec) (*Result, error) {
	emitter := testkeys.Emitter()
	keys := []exportv1.HeaderKey{{JKT: emitter.JKT, JWK: emitter.JWK}}
	headSigner := exportv1.Signer{Private: emitter.Private, KeyID: emitter.JKT}
	if spec.HeadSigner != nil {
		keys = append(keys, exportv1.HeaderKey{JKT: spec.HeadSigner.JKT, JWK: spec.HeadSigner.JWK})
		headSigner = exportv1.Signer{Private: spec.HeadSigner.Private, KeyID: spec.HeadSigner.JKT}
	}

	var buf bytes.Buffer
	w, err := exportv1.NewWriter(&buf, spec.LogOrigin, keys)
	if err != nil {
		return nil, err
	}
	leafSigner := exportv1.Signer{Private: emitter.Private, KeyID: emitter.JKT}

	res := &Result{LogOrigin: spec.LogOrigin}
	for i := 0; i < spec.Count; i++ {
		r, err := buildReceipt(spec, i, emitter.JKT)
		if err != nil {
			return nil, fmt.Errorf("step %d: %w", i, err)
		}
		sealed, err := receipt.Seal(r)
		if err != nil {
			return nil, fmt.Errorf("seal step %d: %w", i, err)
		}
		if err := w.Append(sealed.Bytes(), leafSigner); err != nil {
			return nil, err
		}
		res.Payloads = append(res.Payloads, sealed.Bytes())
	}
	if err := w.Close(headSigner); err != nil {
		return nil, err
	}
	res.Bytes = buf.Bytes()
	res.LeafHashes = w.LeafHashes()
	res.Chain = w.Chain()
	return res, nil
}

// The ids the script addresses. The customer and the ticket are fixed; the
// order is whichever one the search put first, and the desk's records for it
// — its shipment, the card that paid for it, its SKU, the approval raised
// against it, the refund minted for it — are derived from its id, the way a
// desk's records hang off the order they belong to.
const (
	fixCustomer = "cus_2291"
	fixTicket   = "tk_4437"
	// fixTicketOrder is the order the TICKET names, read before the search
	// happens. It is deliberately not either refundable order: the agent's
	// mistake is to act on what the search put first rather than on what the
	// ticket was about.
	fixTicketOrder    = "ord_4437"
	fixTicketShipment = "shp_8814"
	smallOrder        = "ord_5512"
	largeOrder        = "ord_5518"
	smallCents        = 1200
	largeCents        = 120000
)

// selection is what the agent carried forward from step 12 (the order it
// took) and from step 31 (the refund the desk minted for it).
type selection struct {
	Order  string
	Cents  int
	Refund string
}

func selectionFor(v Variant) selection {
	order, cents := smallOrder, smallCents
	if v == VariantB {
		order, cents = largeOrder, largeCents
	}
	return selection{Order: order, Cents: cents, Refund: refundIDFor(order)}
}

func orderSuffix(order string) string { return order[len("ord_"):] }
func shipmentFor(order string) string { return "shp_" + orderSuffix(order) }
func paymentFor(order string) string  { return "pm_" + orderSuffix(order) }
func skuFor(order string) string      { return "sku_" + orderSuffix(order) }
func approvalFor(order string) string { return "apr_" + orderSuffix(order) + "_01" }
func refundIDFor(order string) string { return "rf_" + orderSuffix(order) + "_01" }
func amountFor(cents int) string      { return fmt.Sprintf("%d.%02d", cents/100, cents%100) }
func idempotencyFor(o string) string  { return "refund-" + o + "-a1" }

// step is one entry in the fixed 47-step support-agent script: the tool it
// calls, the argument that supplies operation.target (the capture-time
// policy's `target_arg`, Q6), and the arguments themselves.
//
// A step whose args ignore the selection is a step that cannot differ
// between the runs, and the two facts are one fact: there is no separate
// list of "steps that differ".
type step struct {
	name      string
	targetArg string
	args      func(s selection) map[string]any
}

// script is the fixed step script, mirroring cmd/behalf-record's. Index 12
// is the divergent orders.search; index 31 is the consequent refund.issue.
var script = [47]step{
	// ---- work the ticket as it arrived ---------------------------------
	0: {"tickets.claim", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket}
	}},
	1: {"tickets.read", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket}
	}},
	2: {"customers.lookup", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer}
	}},
	3: {"crm.notes.read", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer}
	}},
	4: {"kb.search", "query", func(selection) map[string]any {
		return map[string]any{"query": "refund policy"}
	}},
	5: {"kb.read", "article_id", func(selection) map[string]any {
		return map[string]any{"article_id": "kb_310"}
	}},
	6: {"policies.read", "policy_id", func(selection) map[string]any {
		return map[string]any{"policy_id": "pol_refunds_v3"}
	}},
	7: {"orders.list", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer}
	}},
	8: {"orders.read", "order_id", func(selection) map[string]any {
		return map[string]any{"order_id": fixTicketOrder}
	}},
	9: {"shipping.track", "shipment_id", func(selection) map[string]any {
		return map[string]any{"shipment_id": fixTicketShipment}
	}},
	10: {"payments.history", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer}
	}},
	11: {"tickets.comment", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket, "body": "Looking into the refund now."}
	}},

	// ---- the divergence: identical request, both runs -------------------
	12: {"orders.search", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer, "status": "refundable"}
	}},

	// ---- work the order the search put first ----------------------------
	13: {"orders.read", "order_id", func(s selection) map[string]any {
		return map[string]any{"order_id": s.Order}
	}},
	14: {"payments.method.read", "payment_method", func(s selection) map[string]any {
		return map[string]any{"payment_method": paymentFor(s.Order), "order_id": s.Order}
	}},
	15: {"payments.history", "customer", func(s selection) map[string]any {
		return map[string]any{"customer": fixCustomer, "order_id": s.Order}
	}},
	16: {"shipping.track", "shipment_id", func(s selection) map[string]any {
		return map[string]any{"shipment_id": shipmentFor(s.Order), "order_id": s.Order}
	}},
	17: {"inventory.check", "sku", func(s selection) map[string]any {
		return map[string]any{"sku": skuFor(s.Order), "order_id": s.Order}
	}},
	18: {"kb.search", "query", func(selection) map[string]any {
		return map[string]any{"query": "refund limits"}
	}},
	19: {"policies.read", "policy_id", func(selection) map[string]any {
		return map[string]any{"policy_id": "pol_refunds_v3"}
	}},
	20: {"customers.verify", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer}
	}},
	21: {"orders.read", "order_id", func(s selection) map[string]any {
		return map[string]any{"order_id": s.Order}
	}},
	22: {"refund.precheck", "order_id", func(s selection) map[string]any {
		return map[string]any{"order_id": s.Order, "amount_cents": s.Cents}
	}},
	23: {"tickets.comment", "ticket_id", func(s selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket, "order_id": s.Order, "amount_cents": s.Cents,
			"body": "Refund eligibility confirmed for this order."}
	}},
	24: {"crm.notes.append", "customer", func(s selection) map[string]any {
		return map[string]any{"customer": fixCustomer, "order_id": s.Order, "amount_cents": s.Cents,
			"note": "Refund prepared against the order below."}
	}},
	25: {"kb.read", "article_id", func(selection) map[string]any {
		return map[string]any{"article_id": "kb_311"}
	}},

	// ---- raise the approval, re-check, issue ----------------------------
	26: {"approvals.request", "approval_id", func(s selection) map[string]any {
		return map[string]any{"approval_id": approvalFor(s.Order), "order_id": s.Order, "amount_cents": s.Cents}
	}},
	27: {"approvals.poll", "approval_id", func(s selection) map[string]any {
		return map[string]any{"approval_id": approvalFor(s.Order)}
	}},
	28: {"policies.read", "policy_id", func(selection) map[string]any {
		return map[string]any{"policy_id": "pol_refunds_v3"}
	}},
	29: {"orders.read", "order_id", func(s selection) map[string]any {
		return map[string]any{"order_id": s.Order}
	}},
	30: {"refund.precheck", "order_id", func(s selection) map[string]any {
		return map[string]any{"order_id": s.Order, "amount_cents": s.Cents}
	}},
	// The consequence. `amount` is the one decimal string in the session.
	31: {"refund.issue", "order_id", func(s selection) map[string]any {
		return map[string]any{"order_id": s.Order, "amount": amountFor(s.Cents), "currency": "USD"}
	}},

	// ---- record what was done, then wrap the ticket up ------------------
	32: {"payments.history", "customer", func(s selection) map[string]any {
		return map[string]any{"customer": fixCustomer, "order_id": s.Order}
	}},
	33: {"orders.read", "order_id", func(s selection) map[string]any {
		return map[string]any{"order_id": s.Order}
	}},
	34: {"tickets.comment", "ticket_id", func(s selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket, "refund_id": s.Refund, "amount_cents": s.Cents,
			"body": "Refund issued."}
	}},
	35: {"crm.notes.append", "customer", func(s selection) map[string]any {
		return map[string]any{"customer": fixCustomer, "refund_id": s.Refund, "amount_cents": s.Cents,
			"note": "Refund processed."}
	}},
	36: {"notifications.email.send", "customer", func(s selection) map[string]any {
		return map[string]any{"customer": fixCustomer, "template": "refund_confirmation",
			"refund_id": s.Refund, "amount_cents": s.Cents}
	}},
	37: {"tickets.status.set", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket, "status": "pending_customer"}
	}},
	38: {"metrics.emit", "metric", func(s selection) map[string]any {
		return map[string]any{"metric": "refund.issued", "amount_cents": s.Cents}
	}},
	39: {"kb.search", "query", func(selection) map[string]any {
		return map[string]any{"query": "closing template"}
	}},
	40: {"tickets.read", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket}
	}},
	41: {"crm.notes.read", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer}
	}},
	42: {"tickets.comment", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket, "body": "Anything else we can help with?"}
	}},
	43: {"surveys.send", "customer", func(selection) map[string]any {
		return map[string]any{"customer": fixCustomer, "survey": "csat_v2"}
	}},
	44: {"tickets.status.set", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket, "status": "resolved"}
	}},
	45: {"session.summary", "session", func(s selection) map[string]any {
		return map[string]any{"session": "sess_desk_1", "refund_id": s.Refund, "amount_cents": s.Cents}
	}},
	46: {"tickets.close", "ticket_id", func(selection) map[string]any {
		return map[string]any{"ticket_id": fixTicket}
	}},
}

// outcomeExtra is what the desk returned, for the steps that return
// something other than an acknowledgement. It is the fixture's half of
// internal/deskmcp's answers, and like them it never carries a decimal
// amount outside step 31.
func outcomeExtra(i int, s selection, v Variant) map[string]any {
	switch i {
	case 12:
		// The search result order is the divergence: which order the agent
		// sees first. Amounts are integer cents so the literal "1200.00"
		// never appears here (the sed cover-up must hit step 31 only).
		small := map[string]any{"order_id": smallOrder, "amount_cents": smallCents, "currency": "USD", "status": "delivered"}
		large := map[string]any{"order_id": largeOrder, "amount_cents": largeCents, "currency": "USD", "status": "delivered"}
		if v == VariantA {
			return map[string]any{"orders": []any{small, large}}
		}
		return map[string]any{"orders": []any{large, small}}
	case 22, 30:
		return map[string]any{"order_id": s.Order, "amount_cents": s.Cents, "currency": "USD", "eligible": true}
	case 26:
		return map[string]any{"approval_id": approvalFor(s.Order), "state": "pending"}
	case 27:
		return map[string]any{"approval_id": approvalFor(s.Order), "state": "granted"}
	case 31:
		return map[string]any{"amount": amountFor(s.Cents), "currency": "USD", "refund_id": s.Refund}
	default:
		return nil
	}
}

// riskClassFor is the fixed capture-time policy assignment (Q6), the same
// assignment cmd/behalf-record's DemoPolicyJSON makes.
func riskClassFor(name string) string {
	switch name {
	case "refund.issue":
		return "high"
	case "refund.precheck", "payments.method.read", "approvals.request", "approvals.poll",
		"notifications.email.send", "surveys.send", "crm.notes.append":
		return "medium"
	default:
		return "low"
	}
}

func buildReceipt(spec Spec, i int, emitterJKT string) (*receipt.Receipt, error) {
	st := script[i%len(script)]
	sel := selectionFor(spec.Variant)
	args := st.args(sel)
	target, _ := args[st.targetArg].(string)

	t := spec.Start.Add(time.Duration(i) * spec.StepEvery)

	outcome := receipt.Outcome{Status: "ok", Extra: outcomeExtra(i, sel, spec.Variant)}

	// Payload slots: digests of the (customer-held) raw input and output
	// bytes. The content itself never enters the receipt (Q34, Q35) — what
	// does is the per-field manifest, computed by the same code the capture
	// path uses so the hand-built pair and a recording agree on what a
	// manifest is (Q37, Q83).
	argsJSON, err := json.Marshal(args)
	if err != nil {
		return nil, err
	}
	outJSON, err := json.Marshal(outcome)
	if err != nil {
		return nil, err
	}
	inSlot := slotFor("input", argsJSON)
	inSlot.Manifest = payload.FieldDigests(argsJSON)
	outSlot := slotFor("output", outJSON)

	authority := demoAuthority(spec)
	r := &receipt.Receipt{
		SchemaVersion:      receipt.SchemaVersion,
		OtelConventionsVer: OtelConventionsVersion,
		ReceiptID:          receiptID(spec.RunID, i, t),
		Kind:               "tool_call",
		RiskClass:          riskClassFor(st.name),
		RiskPolicyDigest:   sha256Hex([]byte("behalf.sh/demo/risk-policy/v1")),
		CapturedAt:         t.Format(time.RFC3339),
		Emitter: receipt.Emitter{
			JKT:     emitterJKT,
			Surface: "mcp-proxy",
			Counter: i,
		},
		Actor:           demoActor(),
		Operation:       operationFor(i, st.name, target, outcome, sel),
		RunID:           spec.RunID,
		RunIDProvenance: "caller",
		Correlation:     &receipt.Correlation{SessionID: "sess-" + spec.RunID},
		StepKey:         stepKey(st.name, args, i),
		Authority:       authority,
		Attribution:     receipt.Attribution{Verification: weakestHop(authority), Class: "delegated"},
		Payload:         []receipt.Slot{inSlot, outSlot},
		Provenance:      receipt.Provenance{Source: "native"},
	}
	return r, nil
}

// stepKey mirrors the proxy's (internal/proxy, Q85): the tool name, the
// normalized argument schema — the sorted top-level argument paths — and the
// causal ordinal. Two runs of one script hash the same key at every step,
// which is what lets `behalf diff` align them on the primary key rather than
// falling back to sequence alignment.
func stepKey(name string, args map[string]any, ordinal int) string {
	paths := make([]string, 0, len(args))
	for k := range args {
		paths = append(paths, "$."+k)
	}
	sort.Strings(paths)
	return sha256Hex([]byte(name + "\n" + strings.Join(paths, ",") + "\n" + strconv.Itoa(ordinal)))
}

func operationFor(i int, name, target string, outcome receipt.Outcome, sel selection) receipt.Operation {
	op := receipt.Operation{Name: name, Target: target, Outcome: outcome}
	if i == 31 {
		op.IdempotencyKey = idempotencyFor(sel.Order)
	}
	return op
}

func slotFor(role string, content []byte) receipt.Slot {
	d := sha256Hex(content)
	return receipt.Slot{
		Role:        role,
		Digest:      d,
		Custody:     "customer-held",
		ContentType: "application/json",
		Size:        len(content),
		Ref:         "sha256:" + d,
		State:       "present",
	}
}

// receiptID mints the deterministic ULID for step i: the ULID timestamp is
// the capture time, the 10 entropy bytes are the first 10 bytes of
// SHA-256(runID + "/receipt/" + i).
func receiptID(runID string, i int, t time.Time) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s/receipt/%d", runID, i)))
	id := ulid.MustNew(ulid.Timestamp(t), bytes.NewReader(sum[:10]))
	return id.String()
}

// demoActor is the leaf actor: the depth-2 sub-agent that performs the
// operation. The canonical actor identity is the hop's key thumbprint (Q16);
// labels are stored verbatim as asserted, self-reported strings and are
// never used for a security decision.
func demoActor() *receipt.Actor {
	hop2 := testkeys.ActorHop2()
	return &receipt.Actor{
		JKT: hop2.JKT,
		Labels: map[string]string{
			"client_name": "billing-agent",
			"mcp_server":  "desk-tools",
		},
		EmitterToActor: "asserted",
	}
}

// chainExp is the fixed per-hop expiry on every demo hop: 2026-08-27T00:00:00Z.
const chainExp = int64(1787788800)

// demoSubDigest is the pseudonymous human principal: issuer + digest of the
// subject, never the subject itself (Q40). The display name that belongs to
// it ("alice@acme.com") lives only in the CLI's local alias map (Q16) — no
// human-readable identity ever enters a receipt.
var demoSubDigest = sha256Hex([]byte("https://accounts.google.com#sub:104729318824119552817"))

// demoAuthority is the fixed three-hop delegation chain, embedded whole in
// every receipt of the run (Q10, schema §7): a human root verified through
// the OIDC nonce-thumbprint binding (D5), a signature-verified orchestrator
// hop, and a leaf sub-agent hop whose verification state is the divergence
// between the two demo runs (Q12).
//
//	depth 0  device key, OIDC nonce binding      verified in both runs
//	depth 1  orchestrator, AAT JWS (ed25519)     verified in both runs
//	depth 2  sub-agent                           verified in run_9f2a,
//	                                             asserted in run_c71e
//
// Every hop carries the AAT draft field set verbatim plus the two named
// behalf extensions — per-hop jti and the root principal binding (Q11,
// D8.6). The per-hop authorization_details are the RAW RFC 9396 grants: the
// attenuation delta and any scope excess are computed at read time from
// these bytes and never stamped back into the record (Q11, Q13).
func demoAuthority(spec Spec) *receipt.Authority {
	root := testkeys.ActorRoot()
	hop1 := testkeys.ActorHop1()
	hop2 := testkeys.ActorHop2()

	// The human authenticated two seconds before the run started; the ID
	// token blob stays in customer custody and is referenced by digest
	// (Q22, Q40).
	authTime := spec.Start.Add(-2 * time.Second).Unix()
	idTokenRef := sha256Hex([]byte("behalf.sh/demo/id-token/" + spec.RunID))
	par := func(depth int) string {
		return sha256Hex([]byte(fmt.Sprintf("behalf.sh/demo/aat/%s/par/%d", spec.RunID, depth)))
	}
	jti := func(depth int) string {
		return fmt.Sprintf("aat-%s-hop%d", spec.RunID, depth)
	}

	// The leaf hop is where the runs diverge: signed in run_9f2a,
	// caller-asserted (no signature) in run_c71e.
	leafVerification := receipt.Verification{
		Status:      "verified",
		Method:      "aat-jws-ed25519",
		EvidenceRef: "jkt:" + hop2.JKT,
	}
	leafCredential := receipt.Credential{
		Issuer: "https://desk.demo.internal",
		Kind:   "aat-jws",
		ID:     "aat-jws:" + jti(2),
		Exp:    chainExp,
		JKT:    hop2.JKT,
	}
	leafCarriage := "in-band"
	if spec.Variant == VariantB {
		leafVerification = receipt.Verification{Status: "asserted", Method: "caller-asserted"}
		// No jkt: nothing proves this key signed anything on this hop.
		leafCredential = receipt.Credential{
			Issuer: "https://desk.demo.internal",
			Kind:   "caller-asserted",
			ID:     "caller-asserted:" + jti(2),
			Exp:    chainExp,
		}
		leafCarriage = "out-of-band"
	}

	return &receipt.Authority{
		Chain: []receipt.Hop{
			{
				DelDepth:    0,
				DelMaxDepth: 3,
				ParHash:     par(0),
				Cnf:         receipt.Cnf{JWK: jwkMap(root)},
				AuthorizationDetails: []map[string]any{{
					"type":      "sh.behalf/support-desk",
					"intent":    "resolve ticket 4417",
					"actions":   []any{"tickets.*", "orders.read", "refund.issue"},
					"locations": []any{"https://desk.demo.internal"},
					"privileges": []any{map[string]any{
						"operation": "refund.issue",
						"limit":     map[string]any{"amount": "100.00", "currency": "USD"},
					}},
				}},
				Exp: chainExp,
				JTI: jti(0),
				Credential: receipt.Credential{
					Issuer:   "https://accounts.google.com",
					Kind:     "oidc-id-token",
					ID:       "oidc-sub-digest:" + demoSubDigest,
					Exp:      chainExp,
					JKT:      root.JKT,
					AuthTime: authTime,
					AMR:      []string{"pwd", "mfa"},
				},
				RootPrincipalBinding: &receipt.RootBinding{
					Nonce:      root.JKT, // nonce == jkt(device_pubkey) (D5)
					DeviceJKT:  root.JKT,
					IDTokenRef: idTokenRef,
				},
				Verification: receipt.Verification{
					Status:      "verified",
					Method:      "oidc-nonce-binding",
					EvidenceRef: "sha256:" + idTokenRef,
				},
				CarriageRoute:   "in-band",
				AttenuationFlag: "unchanged",
			},
			{
				DelDepth:    1,
				DelMaxDepth: 3,
				ParHash:     par(1),
				Cnf:         receipt.Cnf{JWK: jwkMap(hop1)},
				AuthorizationDetails: []map[string]any{{
					"type":      "sh.behalf/support-desk",
					"actions":   []any{"orders.read", "refund.issue"},
					"locations": []any{"https://desk.demo.internal"},
					"privileges": []any{map[string]any{
						"operation": "refund.issue",
						"limit":     map[string]any{"amount": "100.00", "currency": "USD"},
					}},
				}},
				Exp: chainExp,
				JTI: jti(1),
				Credential: receipt.Credential{
					Issuer: "https://desk.demo.internal",
					Kind:   "aat-jws",
					ID:     "aat-jws:" + jti(1),
					Exp:    chainExp,
					JKT:    hop1.JKT,
				},
				Verification: receipt.Verification{
					Status:      "verified",
					Method:      "aat-jws-ed25519",
					EvidenceRef: "jkt:" + hop1.JKT,
				},
				CarriageRoute:   "in-band",
				AttenuationFlag: "attenuated",
			},
			{
				DelDepth:    2,
				DelMaxDepth: 3,
				ParHash:     par(2),
				Cnf:         receipt.Cnf{JWK: jwkMap(hop2)},
				AuthorizationDetails: []map[string]any{{
					"type":      "sh.behalf/support-desk",
					"actions":   []any{"refund.issue"},
					"locations": []any{"https://desk.demo.internal"},
					"privileges": []any{map[string]any{
						"operation": "refund.issue",
						"limit":     map[string]any{"amount": "100.00", "currency": "USD"},
					}},
				}},
				Exp:             chainExp,
				JTI:             jti(2),
				Credential:      leafCredential,
				Verification:    leafVerification,
				CarriageRoute:   leafCarriage,
				AttenuationFlag: "attenuated",
			},
		},
	}
}

// weakestHop is the receipt-level verification rollup: the weakest hop in
// the chain (Q12, schema §8). Stored at write, never derived at query time.
func weakestHop(a *receipt.Authority) string {
	rank := map[string]int{"verified": 0, "asserted": 1, "broken": 2}
	worst := "verified"
	for _, h := range a.Chain {
		if rank[h.Verification.Status] > rank[worst] {
			worst = h.Verification.Status
		}
	}
	return worst
}

func jwkMap(k testkeys.Key) map[string]any {
	return map[string]any{"kty": k.JWK.Kty, "crv": k.JWK.Crv, "x": k.JWK.X}
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
