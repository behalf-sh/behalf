package spool

import (
	"fmt"

	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// envelopeSpan returns the exact byte span of a completion record's
// `envelope` value. The drain hands those bytes straight to the appender,
// so extracting them with a span scanner — never parse-and-reserialize — is
// what keeps the emitter's signature valid across the spool
// (export-format-v1.md §1.2).
func envelopeSpan(rec []byte) ([]byte, error) {
	env, err := jsonspan.ExtractTopLevelValue(rec, "envelope")
	if err != nil {
		return nil, fmt.Errorf("spool: completion envelope: %w", err)
	}
	return env, nil
}
