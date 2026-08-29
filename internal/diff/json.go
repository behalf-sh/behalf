package diff

import (
	"bytes"
	"encoding/json"
	"strconv"

	"github.com/behalf-sh/behalf/internal/dsse"
)

// The JSON handling here obeys one rule from the sibling `behalf why`: a
// captured value is never round-tripped through a float. Every decode uses
// json.Number, so a decimal stored as 1200.00 renders as 1200.00 and hashes
// as the same bytes it was stored as.

type jsonType int

const (
	kindOther jsonType = iota
	kindObject
	kindArray
	kindString
)

func jsonKind(raw []byte) jsonType {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return kindObject
		case '[':
			return kindArray
		case '"':
			return kindString
		default:
			return kindOther
		}
	}
	return kindOther
}

// canon re-encodes a stored value with object keys sorted and numbers kept
// as their literal source text, so equality is structural rather than
// textual. The result is used for comparison only — never written anywhere,
// and never shown: the render always reaches for the stored bytes.
func canon(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("null"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// jsonOf marshals a Go value into the compared view. It is only ever used
// for values the projection lifts out of the receipt (a name, a target, a
// digest), never for stored payload spans, which are sliced not rebuilt.
func jsonOf(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage("null")
	}
	return b
}

// jsonString unquotes a stored JSON string, reporting whether the value was
// one at all.
func jsonString(raw json.RawMessage) (string, bool) {
	if jsonKind(raw) != kindString {
		return "", false
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

// scalarText renders a captured JSON scalar as text without reformatting
// it: a string is unquoted, anything else keeps its verbatim source bytes.
// Containers render as "", which callers read as "not a scalar".
func scalarText(raw json.RawMessage) string {
	switch jsonKind(raw) {
	case kindObject, kindArray:
		return ""
	case kindString:
		s, _ := jsonString(raw)
		return s
	default:
		return string(bytes.TrimSpace(raw))
	}
}

// leaves collects every scalar value reachable inside a stored value, as
// text. It is the raw material of the value-equality link in causality.go.
func leaves(raw json.RawMessage, out map[string]bool) {
	switch jsonKind(raw) {
	case kindObject:
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			return
		}
		for _, v := range m {
			leaves(v, out)
		}
	case kindArray:
		var a []json.RawMessage
		if json.Unmarshal(raw, &a) != nil {
			return
		}
		for _, v := range a {
			leaves(v, out)
		}
	default:
		if s := scalarText(raw); s != "" {
			out[s] = true
		}
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// thumbprint computes the RFC 7638 thumbprint of a stored cnf.jwk, the same
// way `behalf why` does. Only Ed25519 OKP keys exist in v1 (Q69); anything
// else yields "", which the render shows as an unnamed key rather than
// guessing.
func thumbprint(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var jwk dsse.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return ""
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		return ""
	}
	return jwk.Thumbprint()
}
