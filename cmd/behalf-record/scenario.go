package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/behalf-sh/behalf/internal/deskmcp"
)

// The demo scenario: a support-desk refund flow, 47 tool calls, driven
// through the real MCP proxy against the real (fake) desk server.
//
// The script is one script. It is the same tools in the same order for both
// recorded runs, and the world differs in exactly one place: at step 12 the
// desk's search index returns the same two refundable orders in a different
// sequence, the agent takes `results[0]` as agents do, and everything it
// does afterwards is about the order it took.
//
//	step 12  orders.search(customer=c_8831, status=refundable)   the divergence
//	step 31  refund.issue(order_id=…, amount=…)                  the consequence
//
// # Why the selection propagates
//
// An earlier version of this script diverged at step 12 and then addressed
// fixed ids for the remaining 34 calls, so the wrongly-selected order was
// chosen and never mentioned again. That is not what a support agent does
// and it is not what a wrong selection costs. A real agent fetches the order
// it picked, reads the card that paid for it, tracks its shipment, prechecks
// the refund against its amount, raises an approval for it, issues the
// refund, annotates the ticket and the customer record with what it refunded,
// mails the customer about it, and files the audit note — and every one of
// those calls carries the order, its amount, or the refund minted for it.
//
// So the steps below that would naturally reference the selection do
// reference it, through the builders, and the steps that would not — reading
// the refund policy, searching the knowledge base, verifying the customer,
// closing the ticket — do not. The count of differing steps is whatever that
// division produces; it is not a target. The ceiling is 35, because a
// divergence at step 12 of 47 leaves 35 steps that can possibly differ.
//
// The arguments a step derives from the selection are the ones this file
// does not spell out, because spelling them out would be the lie. The agent
// reads the order off the wire at step 12 and the refund id off the wire at
// step 31, the way it would if it were a model.
//
// # One decimal string in the whole session
//
// Money travels as integer `amount_cents` everywhere except the one place
// the refund API insists on a decimal: step 31's `amount`. That is what
// keeps the literal `1200.00` in exactly one blob of the customer's store,
// which is the cover-up demo's whole premise (see internal/deskmcp).

// selection is what the agent carried forward from the two steps that told
// it something: the order it took from step 12's search, and the refund the
// desk minted for that order at step 31.
type selection struct {
	OrderID string
	Cents   int
	Refund  string
}

// step is one scripted tool call. A step with a builder composes its
// arguments from what the agent carried forward; a step with constant
// arguments does not depend on the selection at all, and says so by not
// having one.
type step struct {
	tool  string
	args  string
	build func(sel selection) string
}

// DivergenceStep and ConsequenceStep are the two indices the demo talks
// about, exported as constants so the tests and the tamper suite assert
// against one definition rather than three magic numbers.
const (
	DivergenceStep  = 12
	ConsequenceStep = 31
	ScriptLen       = 47
)

// script is the fixed 47-step support-desk flow.
//
// Steps 0..11 work the ticket as it arrived: the customer, the notes, the
// policy, the order the ticket names (ord_4437) and its shipment. None of
// them can depend on a selection that has not happened yet.
//
// Step 12 is the search. Everything from 13 on that a desk agent would hang
// off the order it chose does — and the steps that would not, do not.
func script() []step {
	cust := `"customer":"` + deskmcp.Customer + `"`
	tick := `"ticket_id":"` + deskmcp.Ticket + `"`
	return []step{
		// ---- work the ticket as it arrived ------------------------------
		0:  {tool: "tickets.claim", args: `{` + tick + `}`},
		1:  {tool: "tickets.read", args: `{` + tick + `}`},
		2:  {tool: "customers.lookup", args: `{` + cust + `}`},
		3:  {tool: "crm.notes.read", args: `{` + cust + `}`},
		4:  {tool: "kb.search", args: `{"query":"refund policy"}`},
		5:  {tool: "kb.read", args: `{"article_id":"kb_310"}`},
		6:  {tool: "policies.read", args: `{"policy_id":"pol_refunds_v3"}`},
		7:  {tool: "orders.list", args: `{` + cust + `}`},
		8:  {tool: "orders.read", args: `{"order_id":"ord_4437"}`},
		9:  {tool: "shipping.track", args: `{"shipment_id":"shp_8814"}`},
		10: {tool: "payments.history", args: `{` + cust + `}`},
		11: {tool: "tickets.comment", args: `{` + tick + `,"body":"Looking into the refund now."}`},

		// ---- the divergence: identical request, both runs ----------------
		DivergenceStep: {tool: "orders.search", args: `{` + cust + `,"status":"refundable"}`},

		// ---- work the order the search put first -------------------------
		13: {tool: "orders.read", build: func(s selection) string {
			return fmt.Sprintf(`{"order_id":%q}`, s.OrderID)
		}},
		14: {tool: "payments.method.read", build: func(s selection) string {
			return fmt.Sprintf(`{"payment_method":%q,"order_id":%q}`,
				deskmcp.PaymentMethodFor(s.OrderID), s.OrderID)
		}},
		15: {tool: "payments.history", build: func(s selection) string {
			return fmt.Sprintf(`{%s,"order_id":%q}`, cust, s.OrderID)
		}},
		16: {tool: "shipping.track", build: func(s selection) string {
			return fmt.Sprintf(`{"shipment_id":%q,"order_id":%q}`,
				deskmcp.ShipmentFor(s.OrderID), s.OrderID)
		}},
		17: {tool: "inventory.check", build: func(s selection) string {
			return fmt.Sprintf(`{"sku":%q,"order_id":%q}`, deskmcp.SKUFor(s.OrderID), s.OrderID)
		}},
		18: {tool: "kb.search", args: `{"query":"refund limits"}`},
		19: {tool: "policies.read", args: `{"policy_id":"pol_refunds_v3"}`},
		20: {tool: "customers.verify", args: `{` + cust + `}`},
		21: {tool: "orders.read", build: func(s selection) string {
			return fmt.Sprintf(`{"order_id":%q}`, s.OrderID)
		}},
		22: {tool: "refund.precheck", build: func(s selection) string {
			return fmt.Sprintf(`{"order_id":%q,"amount_cents":%d}`, s.OrderID, s.Cents)
		}},
		23: {tool: "tickets.comment", build: func(s selection) string {
			return fmt.Sprintf(`{%s,"body":"Refund eligibility confirmed for this order.","order_id":%q,"amount_cents":%d}`,
				tick, s.OrderID, s.Cents)
		}},
		24: {tool: "crm.notes.append", build: func(s selection) string {
			return fmt.Sprintf(`{%s,"note":"Refund prepared against the order below.","order_id":%q,"amount_cents":%d}`,
				cust, s.OrderID, s.Cents)
		}},
		25: {tool: "kb.read", args: `{"article_id":"kb_311"}`},

		// ---- raise the approval, re-check, issue -------------------------
		26: {tool: "approvals.request", build: func(s selection) string {
			return fmt.Sprintf(`{"approval_id":%q,"order_id":%q,"amount_cents":%d}`,
				deskmcp.ApprovalFor(s.OrderID), s.OrderID, s.Cents)
		}},
		27: {tool: "approvals.poll", build: func(s selection) string {
			return fmt.Sprintf(`{"approval_id":%q}`, deskmcp.ApprovalFor(s.OrderID))
		}},
		28: {tool: "policies.read", args: `{"policy_id":"pol_refunds_v3"}`},
		29: {tool: "orders.read", build: func(s selection) string {
			return fmt.Sprintf(`{"order_id":%q}`, s.OrderID)
		}},
		30: {tool: "refund.precheck", build: func(s selection) string {
			return fmt.Sprintf(`{"order_id":%q,"amount_cents":%d}`, s.OrderID, s.Cents)
		}},

		// The consequence. The agent composes this from what it saw at
		// step 12 — the amount is formatted from the selected order's cents,
		// which is why the literal "1200.00" exists in exactly one blob of
		// the customer's store when the divergence went the wrong way.
		ConsequenceStep: {tool: "refund.issue", build: func(s selection) string {
			return fmt.Sprintf(`{"order_id":%q,"amount":%q,"currency":"USD","idempotency_key":%q}`,
				s.OrderID, deskmcp.FormatAmount(s.Cents), "refund-"+s.OrderID+"-a1")
		}},

		// ---- record what was done, then wrap the ticket up ---------------
		32: {tool: "payments.history", build: func(s selection) string {
			return fmt.Sprintf(`{%s,"order_id":%q}`, cust, s.OrderID)
		}},
		33: {tool: "orders.read", build: func(s selection) string {
			return fmt.Sprintf(`{"order_id":%q}`, s.OrderID)
		}},
		34: {tool: "tickets.comment", build: func(s selection) string {
			return fmt.Sprintf(`{%s,"body":"Refund issued.","refund_id":%q,"amount_cents":%d}`,
				tick, s.Refund, s.Cents)
		}},
		35: {tool: "crm.notes.append", build: func(s selection) string {
			return fmt.Sprintf(`{%s,"note":"Refund processed.","refund_id":%q,"amount_cents":%d}`,
				cust, s.Refund, s.Cents)
		}},
		36: {tool: "notifications.email.send", build: func(s selection) string {
			return fmt.Sprintf(`{%s,"template":"refund_confirmation","refund_id":%q,"amount_cents":%d}`,
				cust, s.Refund, s.Cents)
		}},
		37: {tool: "tickets.status.set", args: `{` + tick + `,"status":"pending_customer"}`},
		38: {tool: "metrics.emit", build: func(s selection) string {
			return fmt.Sprintf(`{"metric":"refund.issued","amount_cents":%d}`, s.Cents)
		}},
		39: {tool: "kb.search", args: `{"query":"closing template"}`},
		40: {tool: "tickets.read", args: `{` + tick + `}`},
		41: {tool: "crm.notes.read", args: `{` + cust + `}`},
		42: {tool: "tickets.comment", args: `{` + tick + `,"body":"Anything else we can help with?"}`},
		43: {tool: "surveys.send", args: `{` + cust + `,"survey":"csat_v2"}`},
		44: {tool: "tickets.status.set", args: `{` + tick + `,"status":"resolved"}`},
		45: {tool: "session.summary", build: func(s selection) string {
			return fmt.Sprintf(`{"session":"sess_desk_1","refund_id":%q,"amount_cents":%d}`,
				s.Refund, s.Cents)
		}},
		46: {tool: "tickets.close", args: `{` + tick + `}`},
	}
}

// DemoPolicyJSON is the capture-time tool policy the recording runs under.
// Its digest rides every receipt, so the risk assignment is auditable
// rather than free-floating self-report (Q6). `target_arg` is what puts
// `ord_5518` into the refund receipt's operation.target — the field the
// demo points at.
//
// `outcome_fields` is the same idea on the way back: the operator names the
// scalars of the tool's own result that belong in `operation.outcome`. The
// refund's amount is named here because it is the number the delegated
// ceiling is about — without it a recorded receipt says a refund happened
// and not for how much, and `behalf why`'s scope line has nothing to
// compare (ENG-29). Nothing else is lifted: response content is
// customer-held and referenced by digest (Q34–Q38).
//
// Rule order is load-bearing: path.Match's `*` spans dots, so the specific
// patterns must come before the family ones.
const DemoPolicyJSON = `{"version":"behalf.sh/demo/tool-policy/v1","default":"low","rules":[` +
	`{"pattern":"refund.issue","class":"high","target_arg":"order_id",` +
	`"outcome_fields":["amount_cents","currency","refund_id"]},` +
	`{"pattern":"refund.*","class":"medium","target_arg":"order_id"},` +
	`{"pattern":"payments.method.*","class":"medium","target_arg":"payment_method"},` +
	`{"pattern":"approvals.*","class":"medium","target_arg":"approval_id"},` +
	`{"pattern":"notifications.*","class":"medium","target_arg":"customer"},` +
	`{"pattern":"surveys.send","class":"medium","target_arg":"customer"},` +
	`{"pattern":"crm.notes.append","class":"medium","target_arg":"customer"},` +
	`{"pattern":"crm.notes.read","class":"low","target_arg":"customer"},` +
	`{"pattern":"tickets.*","class":"low","target_arg":"ticket_id"},` +
	`{"pattern":"orders.read","class":"low","target_arg":"order_id"},` +
	`{"pattern":"orders.*","class":"low","target_arg":"customer"},` +
	`{"pattern":"customers.*","class":"low","target_arg":"customer"},` +
	`{"pattern":"payments.*","class":"low","target_arg":"customer"},` +
	`{"pattern":"shipping.*","class":"low","target_arg":"shipment_id"},` +
	`{"pattern":"kb.read","class":"low","target_arg":"article_id"},` +
	`{"pattern":"kb.search","class":"low","target_arg":"query"},` +
	`{"pattern":"policies.read","class":"low","target_arg":"policy_id"},` +
	`{"pattern":"inventory.check","class":"low","target_arg":"sku"},` +
	`{"pattern":"session.summary","class":"low","target_arg":"session"}` +
	`]}`

// agent drives the script over one MCP stdio session. It is deliberately
// dumb: send, wait, read one field. An agent that reasoned would make the
// recording depend on a model, and a recording that depends on a model is
// not a fixture.
type agent struct {
	out io.Writer     // the proxy's stdin — where requests go
	in  *bufio.Reader // the proxy's stdout — where responses come back

	sel     selection
	selSeen bool
}

// run executes the whole session: MCP handshake, then the 47 calls.
func (a *agent) run(steps []step) error {
	if err := a.handshake(); err != nil {
		return err
	}
	for i, st := range steps {
		args := st.args
		if st.build != nil {
			if !a.selSeen {
				return fmt.Errorf("record: step %d builds its arguments from step %d, which has not run",
					i, DivergenceStep)
			}
			if i > ConsequenceStep && a.sel.Refund == "" {
				return fmt.Errorf("record: step %d builds its arguments from step %d's refund, which produced none",
					i, ConsequenceStep)
			}
			args = st.build(a.sel)
		}
		res, err := a.call(i, st.tool, args)
		if err != nil {
			return fmt.Errorf("record: step %d (%s): %w", i, st.tool, err)
		}
		switch i {
		case DivergenceStep:
			if err := a.observeSearch(res); err != nil {
				return fmt.Errorf("record: step %d (%s): %w", i, st.tool, err)
			}
		case ConsequenceStep:
			if err := a.observeRefund(res); err != nil {
				return fmt.Errorf("record: step %d (%s): %w", i, st.tool, err)
			}
		}
	}
	return nil
}

// handshake is the ordinary MCP opening. None of it is a trust-boundary
// crossing, so none of it is receipted (Q2) — which is exactly why a run
// of 47 tool calls produces 47 receipts and not 49.
func (a *agent) handshake() error {
	if _, err := a.request("init", "initialize", fmt.Sprintf(
		`{"protocolVersion":%q,"capabilities":{},"clientInfo":{"name":"behalf-record","version":"0.1.0"}}`,
		deskmcp.ProtocolVersion)); err != nil {
		return err
	}
	if err := a.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`); err != nil {
		return err
	}
	_, err := a.request("tools", "tools/list", `{}`)
	return err
}

// call issues one tools/call and returns its `result`.
func (a *agent) call(i int, tool, args string) (json.RawMessage, error) {
	id := fmt.Sprintf("call-%02d", i)
	params := fmt.Sprintf(`{"name":%q,"arguments":%s}`, tool, args)
	return a.request(id, "tools/call", params)
}

func (a *agent) request(id, method, params string) (json.RawMessage, error) {
	if err := a.send(fmt.Sprintf(`{"jsonrpc":"2.0","id":%q,"method":%q,"params":%s}`, id, method, params)); err != nil {
		return nil, err
	}
	line, err := a.in.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read response to %s: %w", id, err)
	}
	var resp struct {
		ID     string          `json:"id"`
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("parse response to %s: %w (line %s)", id, err, strings.TrimSpace(string(line)))
	}
	if resp.ID != id {
		return nil, fmt.Errorf("response id %q, want %q — the session desynchronised", resp.ID, id)
	}
	if len(resp.Error) > 0 {
		return nil, fmt.Errorf("server error: %s", resp.Error)
	}
	return resp.Result, nil
}

func (a *agent) send(line string) error {
	_, err := io.WriteString(a.out, line+"\n")
	return err
}

// observeSearch is the agent's one decision: take results[0]. Both runs make
// the same decision on differently-ordered evidence, which is the whole story
// the recording tells.
func (a *agent) observeSearch(result json.RawMessage) error {
	var r struct {
		Structured struct {
			Results []struct {
				OrderID string `json:"order_id"`
				Cents   int    `json:"amount_cents"`
			} `json:"results"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		return fmt.Errorf("parse search result: %w", err)
	}
	if len(r.Structured.Results) == 0 {
		return fmt.Errorf("search returned no refundable orders")
	}
	first := r.Structured.Results[0]
	a.sel.OrderID, a.sel.Cents = first.OrderID, first.Cents
	a.selSeen = true
	return nil
}

// observeRefund reads the refund id the desk minted back off the wire, so
// the steps that record what was refunded name the refund the server
// created rather than one the script guessed. Same discipline as
// observeSearch: the agent carries forward what it was told.
func (a *agent) observeRefund(result json.RawMessage) error {
	var r struct {
		Structured struct {
			RefundID string `json:"refund_id"`
			OrderID  string `json:"order_id"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(result, &r); err != nil {
		return fmt.Errorf("parse refund result: %w", err)
	}
	if r.Structured.RefundID == "" {
		return fmt.Errorf("refund.issue returned no refund_id")
	}
	if r.Structured.OrderID != a.sel.OrderID {
		return fmt.Errorf("refund.issue answered for %s, but the agent asked about %s",
			r.Structured.OrderID, a.sel.OrderID)
	}
	a.sel.Refund = r.Structured.RefundID
	return nil
}
