package why

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/index"
)

// grants is a test helper: RFC 9396 objects from their JSON, the way they
// arrive out of a stored hop.
func grants(t *testing.T, objs ...string) []Grant {
	t.Helper()
	raw := make([]json.RawMessage, 0, len(objs))
	for _, o := range objs {
		if !json.Valid([]byte(o)) {
			t.Fatalf("invalid test grant: %s", o)
		}
		raw = append(raw, json.RawMessage(o))
	}
	return grantsFor(raw)
}

const (
	deskRoot = `{"type":"sh.behalf/support-desk","actions":["tickets.*","orders.read","refund.issue"],
	             "privileges":[{"operation":"refund.issue","limit":{"amount":"100.00","currency":"USD"}}]}`
	deskHop = `{"type":"sh.behalf/support-desk","actions":["orders.read","refund.issue"],
	            "privileges":[{"operation":"refund.issue","limit":{"amount":"100.00","currency":"USD"}}]}`
)

// TestCompareGrants covers the four outcomes of the read-time comparison.
// `unknown` is a real answer, not a failure to answer: vocabularies the AAT
// invariants cannot compare are recorded and flagged, never swallowed (Q13),
// and the hop that carries one is held at `asserted` (D8.7, pinned in
// internal/aat).
func TestCompareGrants(t *testing.T) {
	cases := []struct {
		name           string
		parent, child  []Grant
		want           Attenuation
		reasonContains string
	}{
		{
			name:   "dropping an action attenuates",
			parent: grants(t, deskRoot),
			child:  grants(t, deskHop),
			want:   AttenuationAttenuated,
		},
		{
			name:   "an identical grant is unchanged",
			parent: grants(t, deskHop),
			child:  grants(t, deskHop),
			want:   AttenuationUnchanged,
		},
		{
			name:   "a tighter ceiling attenuates",
			parent: grants(t, deskHop),
			child: grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read","refund.issue"],
			                   "privileges":[{"operation":"refund.issue","limit":{"amount":"25.00","currency":"USD"}}]}`),
			want: AttenuationAttenuated,
		},
		{
			name:   "a raised ceiling broadens",
			parent: grants(t, deskHop),
			child: grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read","refund.issue"],
			                   "privileges":[{"operation":"refund.issue","limit":{"amount":"5000.00","currency":"USD"}}]}`),
			want:           AttenuationBroadened,
			reasonContains: "rises from 100.00 to 5000.00",
		},
		{
			name:           "an undelegated action broadens",
			parent:         grants(t, deskHop),
			child:          grants(t, `{"type":"sh.behalf/support-desk","actions":["orders.read","payouts.send"]}`),
			want:           AttenuationBroadened,
			reasonContains: `"payouts.send" was never delegated`,
		},
		{
			// The AAT draft cannot compare wildcard grants, so a child that
			// leans on one is unknown — never quietly "covered".
			name:           "leaning on a parent wildcard is unknown",
			parent:         grants(t, deskRoot),
			child:          grants(t, `{"type":"sh.behalf/support-desk","actions":["tickets.read"]}`),
			want:           AttenuationUnknown,
			reasonContains: `wildcard grant "tickets.*"`,
		},
		{
			// Entra roles: a vocabulary with no RFC 9396 actions at all.
			name:           "a non-comparable vocabulary is unknown",
			parent:         grants(t, deskRoot),
			child:          grants(t, `{"type":"entra-roles","roles":["Directory.ReadWrite.All"]}`),
			want:           AttenuationUnknown,
			reasonContains: `grant type "entra-roles"`,
		},
		{
			name:           "a dropped ceiling broadens",
			parent:         grants(t, deskRoot),
			child:          grants(t, `{"type":"sh.behalf/support-desk","actions":["refund.issue"]}`),
			want:           AttenuationBroadened,
			reasonContains: "dropped at this hop",
		},
		{
			name:   "a currency change is unknown",
			parent: grants(t, deskHop),
			child: grants(t, `{"type":"sh.behalf/support-desk","actions":["refund.issue"],
			                   "privileges":[{"operation":"refund.issue","limit":{"amount":"50.00","currency":"EUR"}}]}`),
			want:           AttenuationUnknown,
			reasonContains: "changes currency",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := CompareGrants(tc.parent, tc.child)
			if got != tc.want {
				t.Fatalf("CompareGrants = %q (%s), want %q", got, reason, tc.want)
			}
			if tc.reasonContains != "" && !strings.Contains(reason, tc.reasonContains) {
				t.Fatalf("reason %q does not mention %q", reason, tc.reasonContains)
			}
		})
	}
}

// TestCheckScopeIsExactDecimal: the comparison is an exact rational over the
// captured decimal strings, never a float, and the rendered values are the
// captured ones verbatim.
func TestCheckScopeIsExactDecimal(t *testing.T) {
	hops := []Hop{{Grants: grants(t, deskRoot)}}
	if e := CheckScope(hops, "refund.issue", "100.00"); e != nil {
		t.Fatalf("an amount exactly at the ceiling is not an excess: %+v", e)
	}
	if e := CheckScope(hops, "refund.issue", "100.01"); e == nil {
		t.Fatal("a cent over the ceiling is an excess")
	}
	e := CheckScope(hops, "refund.issue", "1200.00")
	if e == nil {
		t.Fatal("1200.00 exceeds a 100.00 ceiling")
	}
	if e.Limit != "100.00" || e.Amount != "1200.00" {
		t.Fatalf("the finding must carry the captured decimals verbatim: %+v", e)
	}
	if e := CheckScope(hops, "orders.read", "1200.00"); e != nil {
		t.Fatal("an operation with no delegated ceiling is not an excess")
	}
	if e := CheckScope(hops, "refund.issue", "not-a-number"); e != nil {
		t.Fatal("an uncomparable amount must not produce a finding")
	}
}

// TestAmountReadsMinorUnits covers the second surface an amount arrives on
// (ENG-29). A proxy-recorded refund receipt carries what the desk returned,
// and desks return money in integer minor units; the decimal the delegated
// ceiling is written in is produced here, on the read path, from those
// stored bytes. A record that reported a decimal keeps it verbatim and this
// conversion never runs.
func TestAmountReadsMinorUnits(t *testing.T) {
	outcome := func(pairs string) map[string]json.RawMessage {
		t.Helper()
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte("{"+pairs+"}"), &m); err != nil {
			t.Fatal(err)
		}
		return m
	}
	cases := []struct {
		pairs, want string
	}{
		{`"status":"ok","amount":"1200.00"`, "1200.00"},                   // reported as a decimal: verbatim
		{`"status":"ok","amount_cents":120000`, "1200.00"},                // reported in cents
		{`"status":"ok","amount_cents":1200`, "12.00"},                    // ...and the small one
		{`"status":"ok","amount_cents":7`, "0.07"},                        // under a unit
		{`"status":"ok","amount_cents":-250`, "-2.50"},                    // a reversal
		{`"status":"ok","amount":"12.00","amount_cents":120000`, "12.00"}, // the decimal wins
		{`"status":"ok","amount_cents":"lots"`, ""},                       // uncomparable: no amount
		{`"status":"ok","amount_cents":12.5`, ""},                         // not integer minor units
		{`"status":"ok"`, ""},                                             // the ordinary case
	}
	for _, tc := range cases {
		if got := amountOf(outcome(tc.pairs)); got != tc.want {
			t.Errorf("amountOf({%s}) = %q, want %q", tc.pairs, got, tc.want)
		}
	}

	// And the whole point: an amount read out of minor units is comparable
	// against the ceiling the chain delegated.
	hops := []Hop{{Grants: grants(t, deskRoot)}}
	if e := CheckScope(hops, "refund.issue", amountOf(outcome(`"amount_cents":120000`))); e == nil {
		t.Fatal("a recorded 120000-cent refund must exceed a 100.00 ceiling")
	} else if e.Amount != "1200.00" {
		t.Fatalf("the finding reports %q, want 1200.00", e.Amount)
	}
	if e := CheckScope(hops, "refund.issue", amountOf(outcome(`"amount_cents":1200`))); e != nil {
		t.Fatalf("a recorded 1200-cent refund is inside the ceiling: %+v", e)
	}
}

// syntheticReceipt is a minimal stored payload carrying a three-hop chain
// whose middle hop leans on the root's wildcard and whose leaf uses a
// vocabulary the AAT invariants cannot compare.
const syntheticReceipt = `{
 "schema_version":"behalf.sh/receipt/v1",
 "receipt_id":"01J000000000000000000TEST",
 "kind":"tool_call",
 "captured_at":"2026-08-26T02:19:35Z",
 "operation":{"name":"tickets.read","target":"tk_4437","outcome":{"status":"ok"}},
 "run_id":"run_synth",
 "authority":{"chain":[
   {"del_depth":0,"del_max_depth":3,"par_hash":"aa","cnf":{"jwk":{}},
    "authorization_details":[` + deskRoot + `],
    "exp":1787788800,"jti":"t0","credential":{"issuer":"https://accounts.google.com","kind":"oidc-id-token","id":"x","exp":1787788800},
    "verification":{"status":"verified","method":"oidc-nonce-binding"},"attenuation_flag":"unchanged"},
   {"del_depth":1,"del_max_depth":3,"par_hash":"bb","cnf":{"jwk":{}},
    "authorization_details":[{"type":"sh.behalf/support-desk","actions":["tickets.read"]}],
    "exp":1787788800,"jti":"t1","credential":{"issuer":"https://desk.demo.internal","kind":"aat-jws","id":"y","exp":1787788800},
    "verification":{"status":"verified","method":"aat-jws-ed25519"},"attenuation_flag":"attenuated"},
   {"del_depth":2,"del_max_depth":3,"par_hash":"cc","cnf":{"jwk":{}},
    "authorization_details":[{"type":"entra-roles","roles":["Directory.ReadWrite.All"]}],
    "exp":1787788800,"jti":"t2","credential":{"issuer":"https://login.microsoftonline.com","kind":"entra-uti","id":"z","exp":1787788800},
    "verification":{"status":"asserted","method":"caller-asserted"},"attenuation_flag":"unknown"}
 ]},
 "attribution":{"verification":"asserted","class":"delegated"},
 "provenance":{"source":"native"}
}`

// TestRenderAttenuationUnknown: a chain the comparator cannot compare says
// so on screen, per hop, rather than rendering a confident tree that quietly
// guessed (Q13).
func TestRenderAttenuationUnknown(t *testing.T) {
	res, err := build(Address{RunID: "run_synth", Step: 3}, index.Row{LogIndex: 3}, []byte(syntheticReceipt))
	if err != nil {
		t.Fatal(err)
	}
	if got := res.Chain[1].Computed; got != AttenuationUnknown {
		t.Fatalf("hop 1 leans on the root wildcard: computed %q, want unknown", got)
	}
	if got := res.Chain[2].Computed; got != AttenuationUnknown {
		t.Fatalf("hop 2 uses a non-comparable vocabulary: computed %q, want unknown", got)
	}
	var b bytes.Buffer
	if err := Render(&b, res, Options{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if n := strings.Count(out, "attenuation: unknown"); n != 2 {
		t.Fatalf("want two `attenuation: unknown` lines, got %d:\n%s", n, out)
	}
	if !strings.Contains(out, `wildcard grant "tickets.*"`) {
		t.Fatalf("the wildcard reason is missing:\n%s", out)
	}
	if !strings.Contains(out, `grant type "entra-roles"`) {
		t.Fatalf("the vocabulary reason is missing:\n%s", out)
	}
	if !strings.Contains(out, "chain intact for 2 of 3 hops.") {
		t.Fatalf("two of three hops verified:\n%s", out)
	}
}

// TestRenderColorIsOptional: colour is escape codes around the same text,
// and plain rendering carries none — tests and pipes read plain.
func TestRenderColorIsOptional(t *testing.T) {
	res, err := build(Address{RunID: "run_synth", Step: 3}, index.Row{LogIndex: 3}, []byte(syntheticReceipt))
	if err != nil {
		t.Fatal(err)
	}
	var plain, colored bytes.Buffer
	if err := Render(&plain, res, Options{}); err != nil {
		t.Fatal(err)
	}
	if err := Render(&colored, res, Options{Color: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(plain.String(), "\033[") {
		t.Fatal("plain output must carry no ANSI escapes")
	}
	if !strings.Contains(colored.String(), "\033[") {
		t.Fatal("colour output must carry ANSI escapes")
	}
	// Stripping the escapes must give back exactly the plain rendering:
	// colour never moves a column.
	if got := stripANSI(colored.String()); got != plain.String() {
		t.Fatalf("colour changed the layout.\n--- stripped ---\n%s\n--- plain ---\n%s", got, plain.String())
	}
}

func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\033' {
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
