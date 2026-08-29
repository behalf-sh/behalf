// Package exportv1 writes the behalf.sh/export/v1 run export file per
// docs/export-format-v1.md: one header line with embedded JWK keys, one leaf
// line per receipt with the plaintext payload spliced byte-exactly, and a
// signed head line.
//
// The span rule governs everything: the payload bytes handed to Append are
// the bytes that were signed, and they are copied into the emitted line
// verbatim — no re-serialization, no re-indentation. Leaf and head lines are
// therefore assembled by direct byte concatenation, never by re-marshaling a
// structure that contains the payload.
package exportv1

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/behalf-sh/behalf/internal/dsse"
)

const (
	// Format is the export format string (header and head lines).
	Format = "behalf.sh/export/v1"
	// PayloadTypeReceipt is the DSSE payloadType for receipt leaves.
	PayloadTypeReceipt = "application/vnd.behalf.receipt+json"
	// PayloadTypeChainHead is the DSSE payloadType for the head line.
	PayloadTypeChainHead = "application/vnd.behalf.chain-head+json"
	// chainDomain is the chain_start domain prefix (§1.3).
	chainDomain = "behalf.sh/chain/v1\n"
)

// ChainStart returns SHA-256("behalf.sh/chain/v1\n" + logOrigin).
func ChainStart(logOrigin string) [32]byte {
	return sha256.Sum256([]byte(chainDomain + logOrigin))
}

// ChainNext folds one leaf hash into the chain:
// chain_i = SHA-256(chain_{i-1} || leaf_hash_raw_32_bytes).
func ChainNext(prev, leaf [32]byte) [32]byte {
	var buf [64]byte
	copy(buf[:32], prev[:])
	copy(buf[32:], leaf[:])
	return sha256.Sum256(buf[:])
}

// HeaderKey is one entry in the header's keys array: an Ed25519 public key
// in JWK form, keyed by its RFC 7638 thumbprint.
type HeaderKey struct {
	JKT string   `json:"jkt"`
	JWK dsse.JWK `json:"jwk"`
}

// TokenRef is the key form used by the header's `tokens` section: exactly
// the string a hop's `verification.evidence_ref` carries, `sha256:<hex>`.
//
// Keying by the whole reference rather than by the bare digest is deliberate.
// A reader looks a hop's token up by the value the receipt already holds, with
// no string surgery in between, so there is no opportunity to reconstruct the
// key slightly differently on one side and miss.
func TokenRef(jws string) string {
	sum := sha256.Sum256([]byte(jws))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// Signer signs leaves or the head. KeyID must be the RFC 7638 thumbprint of
// the corresponding public key, and that key must appear in the header.
type Signer struct {
	Private ed25519.PrivateKey
	KeyID   string
}

// Writer emits one export file. Use NewWriter (writes the header), Append
// for each receipt in order, then Close (writes the head).
type Writer struct {
	w          io.Writer
	logOrigin  string
	chain      [32]byte
	count      int
	leafHashes [][32]byte
	closed     bool
}

// NewWriter writes the header line and returns a Writer whose chain is
// initialized to ChainStart(logOrigin). keys must contain every public key
// referenced by any signature in the file.
func NewWriter(w io.Writer, logOrigin string, keys []HeaderKey) (*Writer, error) {
	return NewWriterWithTokens(w, logOrigin, keys, nil)
}

// NewWriterWithTokens is NewWriter carrying the delegation hop tokens the
// receipts reference (ENG-38).
//
// tokens maps a hop's `verification.evidence_ref` — `sha256:<hex>`, see
// TokenRef — to that hop's compact JWS. Without it an export states that a
// chain was verified and carries nothing to re-verify it against: the hop
// signatures were checked once, at capture, by behalf's own code, and a
// receipt is not evidence of its own verification.
//
// It goes in the header rather than in a new line kind or a sidecar for three
// reasons. The export stays one self-contained artefact, which the browser
// verifier and `behalf export --html` both rest on. Hops deduplicate — a run's
// 47 receipts typically share three hops, so the section grows with distinct
// hops rather than with receipts. And §2 of the format already requires
// unknown members to be ignored, so a verifier that predates this section
// reads the file exactly as before and the format string does not move.
//
// A nil or empty map writes no `tokens` member at all, which is what keeps
// every existing vector byte-identical.
func NewWriterWithTokens(w io.Writer, logOrigin string, keys []HeaderKey, tokens map[string]string) (*Writer, error) {
	if len(keys) == 0 {
		return nil, errors.New("exportv1: header requires at least one key")
	}
	for ref, jws := range tokens {
		// The writer refuses to emit a token at an address that is not its
		// own digest. A reader has to check this anyway — it is handed the
		// file by someone it does not trust — but a writer that can produce
		// such a file makes the check a bug hunt rather than a finding.
		if got := TokenRef(jws); got != ref {
			return nil, fmt.Errorf("exportv1: token keyed %s digests to %s", ref, got)
		}
	}
	line, err := headerLine(logOrigin, keys, tokens)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(line); err != nil {
		return nil, err
	}
	return &Writer{
		w:         w,
		logOrigin: logOrigin,
		chain:     ChainStart(logOrigin),
	}, nil
}

func headerLine(logOrigin string, keys []HeaderKey, tokens map[string]string) ([]byte, error) {
	// The header carries no signed span, so ordinary JSON marshaling of a
	// fixed-order struct is fine (and deterministic). encoding/json sorts map
	// keys, so the tokens section is deterministic too — which it must be, or
	// the conformance vectors would differ run to run.
	hdr := struct {
		Kind      string            `json:"kind"`
		Format    string            `json:"format"`
		LogOrigin string            `json:"log_origin"`
		Keys      []HeaderKey       `json:"keys"`
		Tokens    map[string]string `json:"tokens,omitempty"`
	}{"header", Format, logOrigin, keys, tokens}
	b, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Append signs payload (the exact sealed receipt bytes), splices it verbatim
// into a leaf line, writes the line, and folds the leaf hash into the chain.
func (wr *Writer) Append(payload []byte, s Signer) error {
	sig := dsse.Sign(s.Private, PayloadTypeReceipt, payload)
	return wr.AppendSigned(payload, s.KeyID, sig)
}

// AppendSigned is Append for a payload that already carries its signature
// (the Week-2 log bridge: the emitter signed the payload at capture time
// and the stored envelope carries that signature — the bridge must splice
// the original bytes and the original signature, never re-sign). sig must
// be the Ed25519 signature over PAE(PayloadTypeReceipt, payload) by the
// header key with thumbprint keyid.
func (wr *Writer) AppendSigned(payload []byte, keyid string, sig []byte) error {
	if wr.closed {
		return errors.New("exportv1: append after close")
	}
	leafHash := dsse.LeafHash(PayloadTypeReceipt, payload)

	var line []byte
	line = append(line, `{"kind":"leaf","index":`...)
	line = strconv.AppendInt(line, int64(wr.count), 10)
	line = append(line, `,"payloadType":`...)
	line = appendJSONString(line, PayloadTypeReceipt)
	line = append(line, `,"payload":`...)
	line = append(line, payload...) // the span rule: signed bytes, verbatim
	line = append(line, `,"sig":{"keyid":`...)
	line = appendJSONString(line, keyid)
	line = append(line, `,"sig":"`...)
	line = append(line, base64.StdEncoding.EncodeToString(sig)...)
	line = append(line, `"},"leaf_hash":"`...)
	line = append(line, hex.EncodeToString(leafHash[:])...)
	line = append(line, `"}`...)
	line = append(line, '\n')

	if _, err := wr.w.Write(line); err != nil {
		return err
	}
	wr.chain = ChainNext(wr.chain, leafHash)
	wr.leafHashes = append(wr.leafHashes, leafHash)
	wr.count++
	return nil
}

// Close writes the signed head line. The head value's exact byte span is
// what gets signed (PAE with the chain-head payloadType) and it is spliced
// verbatim into the line, same rule as leaves.
func (wr *Writer) Close(s Signer) error {
	if wr.closed {
		return errors.New("exportv1: double close")
	}
	wr.closed = true

	var head []byte
	head = append(head, `{"format":`...)
	head = appendJSONString(head, Format)
	head = append(head, `,"log_origin":`...)
	head = appendJSONString(head, wr.logOrigin)
	head = append(head, `,"count":`...)
	head = strconv.AppendInt(head, int64(wr.count), 10)
	head = append(head, `,"chain":"`...)
	head = append(head, hex.EncodeToString(wr.chain[:])...)
	head = append(head, `"}`...)

	sig := dsse.Sign(s.Private, PayloadTypeChainHead, head)

	var line []byte
	line = append(line, `{"kind":"head","head":`...)
	line = append(line, head...) // head_bytes, verbatim
	line = append(line, `,"sig":{"keyid":`...)
	line = appendJSONString(line, s.KeyID)
	line = append(line, `,"sig":"`...)
	line = append(line, base64.StdEncoding.EncodeToString(sig)...)
	line = append(line, `"}}`...)
	line = append(line, '\n')

	_, err := wr.w.Write(line)
	return err
}

// Count returns the number of leaves appended so far.
func (wr *Writer) Count() int { return wr.count }

// Chain returns the current chain value (after the last appended leaf).
func (wr *Writer) Chain() [32]byte { return wr.chain }

// LeafHashes returns the leaf hashes appended so far, in order.
func (wr *Writer) LeafHashes() [][32]byte { return wr.leafHashes }

// appendJSONString appends s as a JSON string literal using encoding/json,
// so escaping is always correct regardless of content.
func appendJSONString(dst []byte, s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		// json.Marshal of a string cannot fail on valid UTF-8; invalid UTF-8
		// is replaced, not errored. Guard anyway.
		panic(fmt.Sprintf("exportv1: marshal string: %v", err))
	}
	return append(dst, b...)
}
