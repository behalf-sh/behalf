// Package deskmcp is the in-repo fake MCP server the demo recording runs
// against: a support desk with the two dozen tools a refund flow touches.
//
// It exists because ENG-14 requires the shipped demo recordings to come out
// of shipped code paths — the real MCP proxy, the real spool, the real CAS,
// the real log — rather than from hand-authored bytes. That needs something
// on the far side of the proxy to be a real MCP server, and it must not be
// a network service: recordings run in CI, offline, and must produce the
// same bytes every time.
//
// # Determinism
//
// Every response is a pure function of the request. No clock, no
// randomness, no accumulated state between calls: ask the same tool the
// same arguments and you get the same bytes, in the same key order,
// forever. The one input that is *not* the request is Variant, and that is
// deliberate — it is the entire demo.
//
// # The variant, and why it lives here
//
// The two demo runs differ in the world, not in the agent. The agent's
// script is byte-identical across both runs; what differs is that
// `orders.search` returns the same two refundable orders in a different
// order, and the agent — like every agent — takes `results[0]`. One run
// refunds $12.00, the other $1200.00, from identical instructions.
//
// That asymmetry belongs to the server because that is where it belongs in
// reality: a search index reordered between two Tuesdays. Putting it in the
// agent would make the demo a lie about what went wrong.
//
// # Amounts are integer cents
//
// The search results carry `amount_cents`, never a decimal string. The
// cover-up demo greps the customer's CAS for the literal `1200.00` and
// edits it, and that literal must appear in exactly one blob of the whole
// store — the refund request the agent composed — or the demo would be
// editing several records while claiming to edit one. The agent formats
// cents into the decimal string the refund API wants; the refund response
// converts straight back to cents.
//
// That rule survives the propagation of the selected order through the rest
// of the script (ENG-30): every later step that mentions money mentions
// `amount_cents`, and the one decimal string in the whole session is the
// argument of step 31.
//
// # Ids derived from the order
//
// A desk's records hang off the order: the shipment that carried it, the
// card that paid for it, the SKU it contained, the approval raised against
// it, the refund issued for it. Those ids are derived here, in one place, so
// the recorder's script and this server agree on them without either one
// spelling them out twice — and so a run that selected the wrong order
// addresses the wrong shipment, the wrong card and the wrong approval, which
// is what a wrong selection actually looks like.
package deskmcp

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ProtocolVersion is the MCP revision this server speaks — the one the
// proxy is written against, stateless over stdio (D4, Q44).
const ProtocolVersion = "2026-07-28"

// Variant selects which side of the step-12 divergence the world is on.
type Variant string

const (
	// VariantA lists ord_5512 ($12.00) first, so an agent taking results[0]
	// refunds twelve dollars.
	VariantA Variant = "a"
	// VariantB lists ord_5518 ($1200.00) first, so the same agent, on the
	// same script, refunds twelve hundred.
	VariantB Variant = "b"
)

// EnvVariant is how the recorder tells a spawned server which world it is.
const EnvVariant = "BEHALF_DESK_VARIANT"

// Customer, ticket and order ids the demo script addresses. They are
// exported because the recorder's script and this server must agree, and a
// shared constant is cheaper to keep in step than two string literals.
const (
	Customer      = "c_8831"
	Ticket        = "tk_4437"
	SmallOrder    = "ord_5512" // 1200 cents — the refund that should happen
	LargeOrder    = "ord_5518" // 120000 cents — the refund that should not
	SmallCents    = 1200
	LargeCents    = 120000
	ServerName    = "desk-tools"
	ServerVersion = "0.1.0"
)

// Order is one row of an orders.search result.
type Order struct {
	ID     string
	Cents  int
	Status string
}

// The desk's records for an order, derived from its id. Deriving them keeps
// the recorder's script and this server in step, and makes "the agent picked
// the wrong order" reach the shipment, the card, the SKU, the approval and
// the refund — because in a real desk those records hang off the order.

func orderSuffix(order string) string { return strings.TrimPrefix(order, "ord_") }

// ShipmentFor is the shipment that carried the order.
func ShipmentFor(order string) string { return "shp_" + orderSuffix(order) }

// PaymentMethodFor is the card the order was paid with.
func PaymentMethodFor(order string) string { return "pm_" + orderSuffix(order) }

// SKUFor is the item the order contained.
func SKUFor(order string) string { return "sku_" + orderSuffix(order) }

// ApprovalFor is the manager approval raised against the order.
func ApprovalFor(order string) string { return "apr_" + orderSuffix(order) + "_01" }

// RefundIDFor is the refund the desk mints for the order. The server returns
// it and the agent carries it forward, so both must agree on its shape.
func RefundIDFor(order string) string { return "rf_" + orderSuffix(order) + "_01" }

// Refundable returns the two refundable orders in the order this variant's
// search index reports them. This one function is the whole difference
// between the two recorded runs.
func Refundable(v Variant) []Order {
	small := Order{ID: SmallOrder, Cents: SmallCents, Status: "refundable"}
	large := Order{ID: LargeOrder, Cents: LargeCents, Status: "refundable"}
	if v == VariantB {
		return []Order{large, small}
	}
	return []Order{small, large}
}

// Serve reads newline-delimited JSON-RPC from in and writes responses to
// out until in reaches EOF. Notifications get no reply, matching MCP.
func Serve(v Variant, in io.Reader, out io.Writer) error {
	r := bufio.NewReader(in)
	w := bufio.NewWriter(out)
	defer w.Flush()
	for {
		line, readErr := r.ReadBytes('\n')
		if len(line) > 0 {
			if resp := handle(v, line); resp != nil {
				if _, err := w.Write(resp); err != nil {
					return err
				}
				if err := w.Flush(); err != nil {
					return err
				}
			}
		}
		if readErr == io.EOF {
			return nil
		}
		if readErr != nil {
			return readErr
		}
	}
}

type request struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"params"`
}

func handle(v Variant, line []byte) []byte {
	// UseNumber so a numeric argument keeps its literal source text: an
	// `amount_cents` that went out as 120000 must come back as 120000 and
	// never as 1.2e+05, which is what a float round-trip would make of it.
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var req request
	if err := dec.Decode(&req); err != nil {
		return nil
	}
	if len(req.ID) == 0 || req.Method == "" {
		return nil // a notification, or a reply to one of our own requests
	}
	switch req.Method {
	case "initialize":
		return result(req.ID, fmt.Sprintf(
			`{"protocolVersion":%q,"capabilities":{"tools":{}},"serverInfo":{"name":%q,"version":%q}}`,
			ProtocolVersion, ServerName, ServerVersion))
	case "tools/list":
		return result(req.ID, toolsListJSON())
	case "tools/call":
		body, err := call(v, req.Params.Name, req.Params.Arguments)
		if err != nil {
			return rpcError(req.ID, -32602, err.Error())
		}
		return result(req.ID, body)
	default:
		return rpcError(req.ID, -32601, "method not found: "+req.Method)
	}
}

// call dispatches one tool. Unknown tools are a JSON-RPC error, not a
// cheerful default: a recorder whose script drifts from this server must
// fail loudly rather than record 47 shrugs.
func call(v Variant, name string, args map[string]any) (string, error) {
	switch name {
	case "orders.search":
		return ordersSearch(v, args), nil
	case "refund.issue":
		return refundIssue(args)
	case "refund.precheck":
		return structured(
			fmt.Sprintf("refund precheck passed for %s", str(args["order_id"])),
			fmt.Sprintf(`{"order_id":%q,"amount_cents":%s,"currency":"USD","eligible":true,"reason":"within policy pol_refunds_v3"}`,
				str(args["order_id"]), num(args["amount_cents"]))), nil
	case "approvals.request":
		return structured(
			fmt.Sprintf("approval %s requested", str(args["approval_id"])),
			fmt.Sprintf(`{"approval_id":%q,"state":"pending"}`, str(args["approval_id"]))), nil
	case "approvals.poll":
		return structured(
			fmt.Sprintf("approval %s granted", str(args["approval_id"])),
			fmt.Sprintf(`{"approval_id":%q,"state":"granted","approver":"mgr_221"}`, str(args["approval_id"]))), nil
	}
	if _, ok := knownTools[name]; !ok {
		return "", fmt.Errorf("unknown tool: %s", name)
	}
	// Every other desk tool is an acknowledgement echoing what it was asked
	// about. Deterministic by construction: the echo is the request.
	return structured(
		fmt.Sprintf("%s ok", name),
		fmt.Sprintf(`{"tool":%q,"ok":true,"subject":%q}`, name, subject(args))), nil
}

func ordersSearch(v Variant, args map[string]any) string {
	customer := str(args["customer"])
	status := str(args["status"])
	orders := Refundable(v)
	var rows []string
	for _, o := range orders {
		rows = append(rows, fmt.Sprintf(
			`{"order_id":%q,"amount_cents":%d,"currency":"USD","status":%q}`, o.ID, o.Cents, o.Status))
	}
	return structured(
		fmt.Sprintf("%d %s orders for %s", len(orders), status, customer),
		fmt.Sprintf(`{"results":[%s]}`, strings.Join(rows, ",")))
}

// refundIssue answers in cents, not in the decimal string it was asked
// with, so the literal the cover-up demo edits lives in exactly one blob:
// the request the agent composed.
func refundIssue(args map[string]any) (string, error) {
	order := str(args["order_id"])
	amount := str(args["amount"])
	cents, err := parseAmountCents(amount)
	if err != nil {
		return "", fmt.Errorf("refund.issue: amount %q: %w", amount, err)
	}
	if order == "" {
		return "", fmt.Errorf("refund.issue: order_id is required")
	}
	return structured(
		fmt.Sprintf("refund issued for %s", order),
		fmt.Sprintf(`{"refund_id":%q,"order_id":%q,"amount_cents":%d,"currency":"USD","state":"issued"}`,
			RefundIDFor(order), order, cents)), nil
}

// parseAmountCents reads a "1200.00"-shaped decimal without float
// arithmetic — a recorded refund amount that rounds differently on a
// different machine would break reproducibility for the dullest possible
// reason.
func parseAmountCents(s string) (int, error) {
	whole, frac, hasFrac := strings.Cut(s, ".")
	if whole == "" {
		return 0, fmt.Errorf("not a decimal amount")
	}
	w, err := strconv.Atoi(whole)
	if err != nil {
		return 0, err
	}
	if !hasFrac {
		return w * 100, nil
	}
	if len(frac) != 2 {
		return 0, fmt.Errorf("want exactly two decimal places")
	}
	f, err := strconv.Atoi(frac)
	if err != nil {
		return 0, err
	}
	return w*100 + f, nil
}

// FormatAmount is the inverse: cents to the decimal string the refund API
// wants. It lives here so the agent and the server agree on the format, and
// so the demo's target literal has exactly one definition.
func FormatAmount(cents int) string {
	return fmt.Sprintf("%d.%02d", cents/100, cents%100)
}

// subject picks the argument a generic acknowledgement echoes, in a fixed
// precedence so the response is a pure function of the arguments.
//
// The precedence puts the ids a desk record hangs off — the shipment, the
// card, the SKU, the refund — ahead of the customer and the ticket, because
// an acknowledgement that echoed `c_8831` for every call would say nothing
// about which order the agent was working.
func subject(args map[string]any) string {
	for _, k := range []string{"shipment_id", "payment_method", "sku", "approval_id",
		"refund_id", "order_id", "article_id", "policy_id", "ticket_id", "customer",
		"query", "metric", "session"} {
		if v := str(args[k]); v != "" {
			return v
		}
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// num renders a numeric argument by its literal source text — json.Number,
// never a float. An absent or non-numeric argument renders as JSON null,
// which is a truthful "the caller sent none".
func num(v any) string {
	n, ok := v.(json.Number)
	if !ok {
		return "null"
	}
	return n.String()
}

// knownTools is the desk's tool surface. It doubles as the tools/list
// response and as the guard that turns a script typo into a loud failure.
var knownTools = map[string]string{
	"approvals.poll":           "poll an approval request",
	"approvals.request":        "request manager approval",
	"crm.notes.append":         "append a note to the customer record",
	"crm.notes.read":           "read customer notes",
	"customers.lookup":         "look a customer up",
	"customers.verify":         "verify a customer's identity",
	"inventory.check":          "check stock for a sku",
	"kb.read":                  "read a knowledge-base article",
	"kb.search":                "search the knowledge base",
	"metrics.emit":             "emit a desk metric",
	"notifications.email.send": "send a templated email",
	"orders.list":              "list a customer's orders",
	"orders.read":              "read one order",
	"orders.search":            "search orders",
	"payments.history":         "read payment history",
	"payments.method.read":     "read a stored payment method",
	"policies.read":            "read a policy document",
	"refund.issue":             "issue a refund",
	"refund.precheck":          "check refund eligibility",
	"session.summary":          "summarise the session",
	"shipping.track":           "track a shipment",
	"surveys.send":             "send a satisfaction survey",
	"tickets.claim":            "claim a ticket",
	"tickets.close":            "close a ticket",
	"tickets.comment":          "comment on a ticket",
	"tickets.read":             "read a ticket",
	"tickets.status.set":       "set a ticket's status",
}

// toolsListJSON renders the tool surface in sorted name order — MCP does
// not require an order, and a stable one keeps the response deterministic.
func toolsListJSON() string {
	names := make([]string, 0, len(knownTools))
	for n := range knownTools {
		names = append(names, n)
	}
	sortStrings(names)
	var b strings.Builder
	b.WriteString(`{"tools":[`)
	for i, n := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, `{"name":%q,"description":%q,"inputSchema":{"type":"object"}}`, n, knownTools[n])
	}
	b.WriteString(`]}`)
	return b.String()
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}

// structured builds the MCP tool result: a text block for a human plus the
// structured content the agent actually reads.
func structured(text, structuredContent string) string {
	return fmt.Sprintf(`{"content":[{"type":"text","text":%q}],"structuredContent":%s}`, text, structuredContent)
}

func result(id json.RawMessage, body string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"result":%s}`, id, body) + "\n")
}

func rpcError(id json.RawMessage, code int, msg string) []byte {
	return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":%d,"message":%q}}`, id, code, msg) + "\n")
}
