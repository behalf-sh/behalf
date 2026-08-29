// Package dsse implements the DSSE pre-authentication encoding (PAE),
// Ed25519 signing over PAE bytes, and the Week-1 leaf hash, exactly per
// docs/export-format-v1.md §1.2:
//
//	pae = "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload
//
// where LEN is the decimal ASCII byte length and SP is a single 0x20. The
// payload is framed as opaque length-prefixed bytes: no canonicalization step
// exists (receipt-schema-v1.md §2, Q27).
package dsse

import (
	"crypto/ed25519"
	"crypto/sha256"
	"strconv"
)

// PAE returns the DSSE v1 pre-authentication encoding of payloadType and
// payload. Lengths are byte lengths, written in decimal ASCII; separators are
// single 0x20 bytes; nothing is escaped or canonicalized.
func PAE(payloadType string, payload []byte) []byte {
	// "DSSEv1" + SP + len + SP + type + SP + len + SP + payload
	b := make([]byte, 0, 6+1+20+1+len(payloadType)+1+20+1+len(payload))
	b = append(b, "DSSEv1 "...)
	b = strconv.AppendInt(b, int64(len(payloadType)), 10)
	b = append(b, ' ')
	b = append(b, payloadType...)
	b = append(b, ' ')
	b = strconv.AppendInt(b, int64(len(payload)), 10)
	b = append(b, ' ')
	b = append(b, payload...)
	return b
}

// Sign returns the Ed25519 signature over PAE(payloadType, payload).
func Sign(priv ed25519.PrivateKey, payloadType string, payload []byte) []byte {
	return ed25519.Sign(priv, PAE(payloadType, payload))
}

// Verify reports whether sig is a valid Ed25519 signature by pub over
// PAE(payloadType, payload).
func Verify(pub ed25519.PublicKey, payloadType string, payload, sig []byte) bool {
	return ed25519.Verify(pub, PAE(payloadType, payload), sig)
}

// LeafHash returns the Week-1 leaf hash: SHA-256 over the PAE bytes
// (export-format-v1.md §1.2).
func LeafHash(payloadType string, payload []byte) [32]byte {
	return sha256.Sum256(PAE(payloadType, payload))
}
