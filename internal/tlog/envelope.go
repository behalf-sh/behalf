package tlog

import (
	"encoding/json"
	"fmt"

	"github.com/behalf-sh/behalf/internal/envelope"
)

// The envelope construction moved to internal/envelope in Week 3 so the MCP
// proxy — the capture surface — can build and read the stored form without
// linking the appender (one appender process per log, Q57). The API here is
// unchanged; these are aliases, not a second implementation.

// EnvelopeVersion is the version string stamped on every stored envelope.
const EnvelopeVersion = envelope.Version

// Envelope is the parsed view of a stored envelope. Payload aliases the
// original envelope bytes — it is the exact signed span, never
// re-serialized.
type Envelope = envelope.Envelope

// BuildEnvelope assembles the stored log-entry bytes: the DSSE-signed
// receipt envelope, with the payload spliced verbatim (the span rule,
// docs/export-format-v1.md §1.2 — the signed bytes are the stored bytes).
// The log's Merkle leaf covers these exact envelope bytes
// (receipt-schema-v1.md §2).
func BuildEnvelope(payloadType string, payload []byte, keyid string, sig []byte) []byte {
	return envelope.Build(payloadType, payload, keyid, sig)
}

// ParseEnvelope extracts the payloadType, the exact payload byte span, and
// the signature from stored envelope bytes using a span scanner — it never
// parse-and-reserializes the payload.
func ParseEnvelope(env []byte) (*Envelope, error) { return envelope.Parse(env) }

// appendJSONString appends s as a JSON string literal using encoding/json,
// so escaping is always correct regardless of content.
func appendJSONString(dst []byte, s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string cannot fail on valid UTF-8. Guard anyway.
		panic(fmt.Sprintf("tlog: marshal string: %v", err))
	}
	return append(dst, b...)
}
