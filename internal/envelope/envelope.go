// Package envelope assembles and reads the stored log-entry bytes: the
// DSSE-signed receipt envelope whose complete bytes the log's Merkle leaf
// covers (receipt-schema-v1.md §2).
//
// It was lifted out of internal/tlog in Week 3 so the MCP proxy can build
// the envelope it signs and spools without linking the appender. That is
// not just binary weight: one appender process per log is an architectural
// constraint (Q57), and a capture surface that cannot import the appender
// cannot accidentally become one. internal/tlog re-exports this package's
// API unchanged.
package envelope

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// Version is the version string stamped on every stored envelope.
const Version = "behalf.sh/envelope/v1"

// Build assembles the stored log-entry bytes, with the payload spliced
// verbatim (the span rule, docs/export-format-v1.md §1.2 — the signed bytes
// are the stored bytes). Assembly is byte concatenation, never re-marshaling
// of a structure containing the payload.
//
//	{"v":"behalf.sh/envelope/v1","payloadType":<t>,"payload":<verbatim>,"sig":{"keyid":<jkt>,"sig":"<b64std>"}}
func Build(payloadType string, payload []byte, keyid string, sig []byte) []byte {
	var b []byte
	b = append(b, `{"v":`...)
	b = appendJSONString(b, Version)
	b = append(b, `,"payloadType":`...)
	b = appendJSONString(b, payloadType)
	b = append(b, `,"payload":`...)
	b = append(b, payload...) // the span rule: signed bytes, verbatim
	b = append(b, `,"sig":{"keyid":`...)
	b = appendJSONString(b, keyid)
	b = append(b, `,"sig":"`...)
	b = append(b, base64.StdEncoding.EncodeToString(sig)...)
	b = append(b, `"}}`...)
	return b
}

// Envelope is the parsed view of a stored envelope. Payload aliases the
// original envelope bytes — it is the exact signed span, never
// re-serialized.
type Envelope struct {
	PayloadType string
	Payload     []byte // exact byte span, aliases the envelope bytes
	KeyID       string
	Sig         []byte
}

// Parse extracts the payloadType, the exact payload byte span, and the
// signature from stored envelope bytes using a span scanner — it never
// parse-and-reserializes the payload.
func Parse(env []byte) (*Envelope, error) {
	ptRaw, err := jsonspan.ExtractTopLevelValue(env, "payloadType")
	if err != nil {
		return nil, fmt.Errorf("tlog: envelope payloadType: %w", err)
	}
	var pt string
	if err := json.Unmarshal(ptRaw, &pt); err != nil {
		return nil, fmt.Errorf("tlog: envelope payloadType: %w", err)
	}
	payload, err := jsonspan.ExtractTopLevelValue(env, "payload")
	if err != nil {
		return nil, fmt.Errorf("tlog: envelope payload: %w", err)
	}
	sigRaw, err := jsonspan.ExtractTopLevelValue(env, "sig")
	if err != nil {
		return nil, fmt.Errorf("tlog: envelope sig: %w", err)
	}
	var sig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		return nil, fmt.Errorf("tlog: envelope sig: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		return nil, fmt.Errorf("tlog: envelope sig b64: %w", err)
	}
	return &Envelope{
		PayloadType: pt,
		Payload:     payload,
		KeyID:       sig.KeyID,
		Sig:         sigBytes,
	}, nil
}

// appendJSONString appends s as a JSON string literal using encoding/json,
// so escaping is always correct regardless of content.
func appendJSONString(dst []byte, s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string cannot fail on valid UTF-8. Guard anyway.
		panic(fmt.Sprintf("envelope: marshal string: %v", err))
	}
	return append(dst, b...)
}
