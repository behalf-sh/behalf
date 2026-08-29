package receipt

import (
	"bytes"
	"testing"
)

// TestOutcomeMarshalFlattensExtraDeterministically pins the custom
// MarshalJSON: status/error first, then Extra keys in sorted order, all in
// one flat object (the schema allows extra outcome properties).
func TestOutcomeMarshalFlattensExtraDeterministically(t *testing.T) {
	o := Outcome{
		Status: "ok",
		Extra: map[string]any{
			"b_second": 2,
			"a_first":  []any{1, 2},
		},
	}
	want := `{"status":"ok","a_first":[1,2],"b_second":2}`
	for i := 0; i < 3; i++ {
		got, err := o.MarshalJSON()
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatalf("outcome = %s, want %s", got, want)
		}
	}

	// No extras: plain object, no trailing comma damage.
	plain := Outcome{Status: "error", Error: "boom"}
	got, err := plain.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != `{"status":"error","error":"boom"}` {
		t.Fatalf("outcome = %s", got)
	}
}

// TestSealFreezesBytes: Seal serializes once; the frozen bytes do not change
// when the source receipt is mutated afterwards, and equal receipts seal to
// equal bytes.
func TestSealFreezesBytes(t *testing.T) {
	mk := func() *Receipt {
		return &Receipt{
			SchemaVersion:      SchemaVersion,
			OtelConventionsVer: "1.29.0",
			ReceiptID:          "01ARZ3NDEKTSV4RRFFQ69G5FAV",
			Kind:               "tool_call",
			RiskClass:          "low",
			RiskPolicyDigest:   "0000000000000000000000000000000000000000000000000000000000000000",
			CapturedAt:         "2026-08-25T22:04:00Z",
			Emitter:            Emitter{JKT: "x", Surface: "mcp-proxy", Counter: 0},
			Operation:          Operation{Name: "t", Outcome: Outcome{Status: "ok"}},
			RunID:              "run_x",
			RunIDProvenance:    "caller",
			Attribution:        Attribution{Verification: "asserted", Class: "delegated"},
			Provenance:         Provenance{Source: "native"},
		}
	}

	r := mk()
	s1, err := Seal(r)
	if err != nil {
		t.Fatal(err)
	}
	frozen := append([]byte(nil), s1.Bytes()...)

	r.RiskClass = "high" // mutate after sealing
	if !bytes.Equal(s1.Bytes(), frozen) {
		t.Fatal("sealed bytes changed after mutating the source receipt")
	}

	s2, err := Seal(mk())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s2.Bytes(), frozen) {
		t.Fatal("equal receipts sealed to different bytes")
	}
}
