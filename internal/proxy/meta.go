package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// The one legal injection. MCP revision 2026-07-28 reserves `params._meta`
// for out-of-band metadata under vendor-prefixed keys whose second label is
// not "mcp", which is exactly what D4/Q15 rely on: the delegation chain
// travels beside the request under `sh.behalf/chain`, and W3C trace context
// travels under `baggage`. Verification comes from the chain's own
// signatures, so out-of-band carriage costs nothing (Q15).
const (
	// MetaKeyChain carries the AAT chain material (D4, Q15).
	MetaKeyChain = "sh.behalf/chain"
	// MetaKeyBaggage carries W3C baggage (D4, Q50).
	MetaKeyBaggage = "baggage"
	// BaggageRunKey is the baggage member the proxy contributes.
	BaggageRunKey = "behalf-run-id"
)

// injectMeta splices the behalf keys into a tools/call request's
// `params._meta`, touching nothing else. Every other byte of the line is
// copied through unmodified — the line is rebuilt around the spliced span,
// never re-serialized — so a JSON diff of before and after differs only
// inside params._meta.
//
// Keys already present are left alone, with one merge: an existing
// `baggage` string gains a `behalf-run-id` member if it has none, per W3C
// baggage's list semantics. A caller that supplies its own
// `sh.behalf/chain` keeps it — the proxy never overwrites a chain someone
// else asserted.
func injectMeta(body []byte, chain []byte, runID string) ([]byte, error) {
	ps, pe, err := jsonspan.TopLevelSpan(body, "params")
	if err != nil {
		// A tools/call with no params is malformed for MCP, but the proxy
		// is not the validator: pass it through untouched.
		return body, nil //nolint:nilerr // transparency beats correction here
	}
	params := body[ps:pe]
	if len(params) == 0 || params[0] != '{' {
		return body, nil
	}
	newParams, err := injectIntoParams(params, chain, runID)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(body)+len(newParams)-len(params))
	out = append(out, body[:ps]...)
	out = append(out, newParams...)
	out = append(out, body[pe:]...)
	return out, nil
}

func injectIntoParams(params []byte, chain []byte, runID string) ([]byte, error) {
	baggage := BaggageRunKey + "=" + runID
	ms, me, err := jsonspan.TopLevelSpan(params, "_meta")
	if err != nil {
		// No _meta: append one at the end of params, so every existing
		// member keeps its exact position and bytes.
		meta := buildMeta(chain, baggage)
		out := make([]byte, 0, len(params)+len(meta)+10)
		out = append(out, params[:len(params)-1]...) // drop the closing '}'
		if hasMembers(params) {
			out = append(out, ',')
		}
		out = append(out, `"_meta":`...)
		out = append(out, meta...)
		out = append(out, '}')
		return out, nil
	}

	meta := params[ms:me]
	if len(meta) == 0 || meta[0] != '{' {
		return nil, fmt.Errorf("proxy: params._meta is not an object")
	}
	fields, err := jsonspan.TopLevelKeys(meta)
	if err != nil {
		return nil, fmt.Errorf("proxy: params._meta: %w", err)
	}
	existing := map[string]jsonspan.Field{}
	for _, f := range fields {
		existing[f.Name] = f
	}

	newMeta := append([]byte(nil), meta...)
	// baggage: merge into the caller's list rather than replacing it.
	if f, ok := existing[MetaKeyBaggage]; ok {
		var cur string
		if err := json.Unmarshal(meta[f.Start:f.End], &cur); err == nil && !hasBaggageKey(cur, BaggageRunKey) {
			merged := cur
			if merged != "" {
				merged += ","
			}
			merged += baggage
			var buf []byte
			buf = append(buf, meta[:f.Start]...)
			buf = appendJSONString(buf, merged)
			buf = append(buf, meta[f.End:]...)
			newMeta = buf
		}
	}
	// Append whatever is still missing, at the end, so existing members
	// keep their bytes.
	var add []byte
	if _, ok := existing[MetaKeyChain]; !ok && len(chain) > 0 {
		add = append(add, `"`+MetaKeyChain+`":`...)
		add = append(add, chain...)
	}
	if _, ok := existing[MetaKeyBaggage]; !ok {
		if len(add) > 0 {
			add = append(add, ',')
		}
		add = append(add, `"`+MetaKeyBaggage+`":`...)
		add = appendJSONString(add, baggage)
	}
	if len(add) > 0 {
		var buf []byte
		buf = append(buf, newMeta[:len(newMeta)-1]...)
		if hasMembers(newMeta) {
			buf = append(buf, ',')
		}
		buf = append(buf, add...)
		buf = append(buf, '}')
		newMeta = buf
	}

	out := make([]byte, 0, len(params)+len(newMeta)-len(meta))
	out = append(out, params[:ms]...)
	out = append(out, newMeta...)
	out = append(out, params[me:]...)
	return out, nil
}

// buildMeta renders a fresh _meta object.
func buildMeta(chain []byte, baggage string) []byte {
	var b []byte
	b = append(b, '{')
	if len(chain) > 0 {
		b = append(b, `"`+MetaKeyChain+`":`...)
		b = append(b, chain...)
		b = append(b, ',')
	}
	b = append(b, `"`+MetaKeyBaggage+`":`...)
	b = appendJSONString(b, baggage)
	b = append(b, '}')
	return b
}

// hasMembers reports whether a JSON object literal has at least one member.
func hasMembers(obj []byte) bool {
	return len(bytes.TrimSpace(obj)) > 2
}

// hasBaggageKey reports whether a W3C baggage string already carries key.
func hasBaggageKey(baggage, key string) bool {
	for _, member := range bytes.Split([]byte(baggage), []byte(",")) {
		name, _, found := bytes.Cut(bytes.TrimSpace(member), []byte("="))
		if found && string(bytes.TrimSpace(name)) == key {
			return true
		}
	}
	return false
}

func appendJSONString(dst []byte, s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("proxy: marshal string: %v", err))
	}
	return append(dst, b...)
}

func unmarshalString(raw []byte, out *string) error { return json.Unmarshal(raw, out) }
