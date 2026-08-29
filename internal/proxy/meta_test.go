package proxy

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

// TestInjectMetaSplicesOnlyMeta pins the one legal modification: whatever
// the client wrote outside params._meta survives byte-for-byte, and what
// was already inside _meta survives too.
func TestInjectMetaSplicesOnlyMeta(t *testing.T) {
	chain := []byte(`{"chain":[{"del_depth":0}]}`)
	cases := []struct {
		name string
		line string
		want func(t *testing.T, meta map[string]any)
	}{
		{
			name: "no _meta at all",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","arguments":{"a":1}}}`,
			want: func(t *testing.T, meta map[string]any) {
				if meta[MetaKeyBaggage] != BaggageRunKey+"=run-7" {
					t.Fatalf("baggage = %v", meta[MetaKeyBaggage])
				}
				if _, ok := meta[MetaKeyChain]; !ok {
					t.Fatal("chain not injected")
				}
			},
		},
		{
			name: "empty params",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`,
			want: func(t *testing.T, meta map[string]any) {
				if _, ok := meta[MetaKeyBaggage]; !ok {
					t.Fatal("baggage not injected into empty params")
				}
			},
		},
		{
			name: "existing _meta with unrelated keys",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","_meta":{"progressToken":"p1"}}}`,
			want: func(t *testing.T, meta map[string]any) {
				if meta["progressToken"] != "p1" {
					t.Fatalf("existing _meta key lost: %v", meta)
				}
				if _, ok := meta[MetaKeyChain]; !ok {
					t.Fatal("chain not injected alongside existing keys")
				}
			},
		},
		{
			name: "existing baggage is merged, not replaced",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","_meta":{"baggage":"tenant=acme"}}}`,
			want: func(t *testing.T, meta map[string]any) {
				got, _ := meta[MetaKeyBaggage].(string)
				if got != "tenant=acme,"+BaggageRunKey+"=run-7" {
					t.Fatalf("baggage = %q, want the caller's member kept and ours appended", got)
				}
			},
		},
		{
			name: "caller's own chain is never overwritten",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","_meta":{"sh.behalf/chain":{"chain":[{"del_depth":9}]}}}}`,
			want: func(t *testing.T, meta map[string]any) {
				got, _ := json.Marshal(meta[MetaKeyChain])
				if !bytes.Contains(got, []byte(`"del_depth":9`)) {
					t.Fatalf("the caller's chain was replaced: %s", got)
				}
			},
		},
		{
			name: "baggage we already contributed is left alone",
			line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t","_meta":{"baggage":"behalf-run-id=upstream"}}}`,
			want: func(t *testing.T, meta map[string]any) {
				if meta[MetaKeyBaggage] != "behalf-run-id=upstream" {
					t.Fatalf("baggage = %v, want the upstream member untouched", meta[MetaKeyBaggage])
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := injectMeta([]byte(tc.line), chain, "run-7")
			if err != nil {
				t.Fatal(err)
			}
			var before, after map[string]any
			if err := json.Unmarshal([]byte(tc.line), &before); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(got, &after); err != nil {
				t.Fatalf("injection produced invalid JSON: %v (%s)", err, got)
			}
			meta, _ := after["params"].(map[string]any)["_meta"].(map[string]any)
			if meta == nil {
				t.Fatalf("no params._meta: %s", got)
			}
			tc.want(t, meta)

			// Everything outside params._meta is unchanged.
			delete(after["params"].(map[string]any), "_meta")
			if bp, ok := before["params"].(map[string]any); ok {
				delete(bp, "_meta")
			}
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("injection changed something outside params._meta:\n  before %#v\n  after  %#v", before, after)
			}
		})
	}
}

// TestInjectMetaLeavesMalformedRequestsAlone: the proxy is transparent, not
// a validator. A tools/call with no params object crosses untouched.
func TestInjectMetaLeavesMalformedRequestsAlone(t *testing.T) {
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"tools/call"}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[1,2]}`,
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":null}`,
	} {
		got, err := injectMeta([]byte(line), []byte(`{}`), "run-7")
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if !bytes.Equal(got, []byte(line)) {
			t.Fatalf("%s was rewritten to %s", line, got)
		}
	}
}

// TestMessageRouting pins which lines are receipts and which are not.
func TestMessageRouting(t *testing.T) {
	cases := []struct {
		line     string
		isCall   bool
		isResp   bool
		matchKey string
	}{
		{line: `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{}}`, isCall: true, matchKey: "1"},
		{line: `{"jsonrpc":"2.0","id":"1","method":"tools/call","params":{}}`, isCall: true, matchKey: `"1"`},
		{line: `{"jsonrpc":"2.0","method":"notifications/initialized"}`},
		{line: `{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}`},
		// A server->client request also carries an id; it is not a response.
		{line: `{"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage","params":{}}`},
		{line: `{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`, isResp: true, matchKey: "1"},
		{line: `{"jsonrpc":"2.0","id":1,"error":{"code":-1,"message":"x"}}`, isResp: true, matchKey: "1"},
		{line: `[{"jsonrpc":"2.0","id":1,"method":"tools/call"}]`},
		{line: `not json at all`},
	}
	for _, tc := range cases {
		m := parseMessage([]byte(tc.line))
		if got := m.isToolsCallRequest(); got != tc.isCall {
			t.Fatalf("%s: isToolsCallRequest = %v, want %v", tc.line, got, tc.isCall)
		}
		if got := m.isResponse(); got != tc.isResp {
			t.Fatalf("%s: isResponse = %v, want %v", tc.line, got, tc.isResp)
		}
		if tc.matchKey != "" && m.matchKey() != tc.matchKey {
			t.Fatalf("%s: matchKey = %q, want %q", tc.line, m.matchKey(), tc.matchKey)
		}
	}

	// The numeric id 1 and the string id "1" are different JSON-RPC ids and
	// must not collide in the pending map.
	num := parseMessage([]byte(`{"id":1,"result":{}}`))
	str := parseMessage([]byte(`{"id":"1","result":{}}`))
	if num.matchKey() == str.matchKey() {
		t.Fatal("numeric and string ids collide")
	}
}

// TestSplitFrameKeepsTerminator: pass-through must reassemble the exact
// bytes that arrived, terminator included.
func TestSplitFrameKeepsTerminator(t *testing.T) {
	for _, line := range []string{"{}\n", "{}\r\n", "{}"} {
		f := splitFrame([]byte(line))
		if string(f.body)+string(f.term) != line {
			t.Fatalf("%q split into %q + %q", line, f.body, f.term)
		}
	}
}

// TestNormalizedArgSchema: the step_key's middle term is the sorted list of
// top-level argument key paths, so key order and values never move it, and
// a new key does (Q85).
func TestNormalizedArgSchema(t *testing.T) {
	a := normalizedArgSchema([]byte(`{"b":1,"a":"x"}`))
	b := normalizedArgSchema([]byte(`{"a":"different","b":99}`))
	if a != b || a != "$.a,$.b" {
		t.Fatalf("schemas differ or are wrong: %q vs %q", a, b)
	}
	if normalizedArgSchema([]byte(`{"a":1,"b":2,"c":3}`)) == a {
		t.Fatal("an added argument did not change the normalized schema")
	}
	if normalizedArgSchema(nil) != "" || normalizedArgSchema([]byte(`[1]`)) != "" {
		t.Fatal("absent or non-object arguments must normalize to the empty schema")
	}
}
