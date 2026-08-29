package receipt

import "encoding/json"

// Sealed is a receipt payload serialized exactly once. Its bytes are what
// gets signed, hashed, and spliced verbatim into the export line — the
// contract's span rule (export-format-v1.md §1.2). Nothing may re-marshal a
// Sealed payload; the raw bytes are the payload from here on.
type Sealed struct {
	bytes []byte
}

// Seal serializes r once and freezes the bytes.
func Seal(r *Receipt) (Sealed, error) {
	b, err := json.Marshal(r)
	if err != nil {
		return Sealed{}, err
	}
	return Sealed{bytes: b}, nil
}

// Bytes returns the frozen payload bytes. Callers must not modify the
// returned slice.
func (s Sealed) Bytes() []byte { return s.bytes }
