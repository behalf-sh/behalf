package exportv1

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// Reading an export back, for the one thing an export is not otherwise good
// for: rebuilding a log from it.
//
// `behalf verify <file>` reads exports too, in Rust, and that reader is the
// one a sceptic runs. This one is not a second verifier and must not be
// mistaken for one — it is deliberately narrower. It parses structure and
// checks that each leaf's `leaf_hash` is the hash of the payload span it sits
// beside, because an importer that ingested a line whose own self-description
// is inconsistent would be laundering a broken record into a fresh log. It
// does NOT check signatures, the chain, the head, or the ordering rules. The
// import path runs `behalf-verify` over the file first and refuses to import
// one that does not pass; keeping the two separate is what stops this becoming
// a third implementation of the verification contract that could quietly drift
// from the other two.
//
// The span rule is the whole reason this file exists rather than a
// `json.Unmarshal` into a struct. `payload` is the exact byte span the emitter
// signed (docs/export-format-v1.md §1.2), so it is extracted with a scanner and
// never round-tripped through a decoder — a re-serialization that reordered a
// key or renumbered a float would invalidate a valid signature and the
// resulting log would be quietly unverifiable.

// Leaf is one receipt as it appears in an export.
type Leaf struct {
	Index int
	// PayloadType and Payload are what the signature covers. Payload aliases
	// the line's own bytes: the exact span, never re-serialized.
	PayloadType string
	Payload     []byte
	KeyID       string
	Sig         []byte
	// LeafHash is the value the line carries, already checked against the
	// payload span.
	LeafHash [32]byte
}

// Head is the export's trailing signed head.
type Head struct {
	// Bytes is the exact span the head signature covers.
	Bytes     []byte
	LogOrigin string
	Count     int
	Chain     string // hex
	KeyID     string
	Sig       []byte
}

// Export is a parsed export file.
type Export struct {
	LogOrigin string
	Keys      []HeaderKey
	Leaves    []Leaf
	Head      *Head
	// Tokens is the header's delegation hop tokens, keyed by the
	// `evidence_ref` the receipts carry (ENG-38). Nil when the export
	// predates the section or carries no signed hops.
	//
	// Every entry has already been checked to digest to the key it sits
	// under, so a caller may look a hop's token up by its `evidence_ref` and
	// use the bytes without re-hashing. A file whose token does not match its
	// address does not parse at all: substituting the evidence for a
	// verification claim is the one thing this section must not permit
	// silently.
	Tokens map[string]string
}

// ErrNotExport marks a file that is not a behalf export at all, so a caller
// can say so plainly rather than reporting a parse error from line one.
var ErrNotExport = errors.New("exportv1: not a behalf export file")

// maxLine bounds one export line. A receipt is a few kilobytes; the demo's
// largest is under 20 KB. A megabyte is generous and finite, which is the
// point: a reader with no bound is a denial-of-service surface for a format
// whose whole purpose is being handed a file by someone you do not trust.
const maxLine = 1 << 20

// Read parses an export file.
func Read(r io.Reader) (*Export, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), maxLine)

	var ex Export
	line := 0
	for sc.Scan() {
		line++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		// The scanner reuses its buffer, so anything kept past this iteration
		// is copied. Payload spans are kept.
		kind, err := stringMember(raw, "kind")
		if err != nil {
			if line == 1 {
				return nil, ErrNotExport
			}
			return nil, fmt.Errorf("exportv1: line %d: %w", line, err)
		}
		switch kind {
		case "header":
			if line != 1 {
				return nil, fmt.Errorf("exportv1: line %d: a header must be the first line", line)
			}
			if err := readHeader(raw, &ex); err != nil {
				return nil, err
			}
		case "leaf":
			leaf, err := readLeaf(raw)
			if err != nil {
				return nil, fmt.Errorf("exportv1: line %d: %w", line, err)
			}
			ex.Leaves = append(ex.Leaves, *leaf)
		case "head":
			head, err := readHead(raw)
			if err != nil {
				return nil, fmt.Errorf("exportv1: line %d: %w", line, err)
			}
			ex.Head = head
		default:
			// Unknown line kinds are not tolerated the way unknown *fields*
			// are. A field this reader ignores is data it does not use; a line
			// it ignores is a record it silently drops, and dropping records
			// is the failure this whole format exists to make detectable.
			return nil, fmt.Errorf("exportv1: line %d: unknown line kind %q", line, kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("exportv1: read: %w", err)
	}
	if line == 0 {
		return nil, ErrNotExport
	}
	if ex.LogOrigin == "" && len(ex.Keys) == 0 {
		return nil, ErrNotExport
	}
	if ex.Head == nil {
		return nil, errors.New("exportv1: the file carries no head line: it is truncated")
	}
	return &ex, nil
}

func readHeader(raw []byte, ex *Export) error {
	format, err := stringMember(raw, "format")
	if err != nil {
		return fmt.Errorf("exportv1: header: %w", err)
	}
	if format != Format {
		return fmt.Errorf("exportv1: header declares format %q, this build reads %q", format, Format)
	}
	origin, err := stringMember(raw, "log_origin")
	if err != nil {
		return fmt.Errorf("exportv1: header: %w", err)
	}
	keysRaw, err := jsonspan.ExtractTopLevelValue(raw, "keys")
	if err != nil {
		return fmt.Errorf("exportv1: header carries no keys: %w", err)
	}
	var keys []HeaderKey
	if err := json.Unmarshal(keysRaw, &keys); err != nil {
		return fmt.Errorf("exportv1: header keys: %w", err)
	}
	if len(keys) == 0 {
		return errors.New("exportv1: header carries an empty key set")
	}
	ex.LogOrigin, ex.Keys = origin, keys

	// The tokens section is optional: §2 requires unknown members to be
	// ignored, and an export written before ENG-38 simply has none.
	//
	// Absent and malformed must not collapse into each other. jsonspan has no
	// not-found sentinel — every failure is one generic error — so probing
	// with it would read a corrupt `tokens` member as "this export has none"
	// and verify the file happily. The header carries no signed span, so
	// unlike a leaf it can be unmarshaled whole: a missing member leaves the
	// map nil without error, and a member of the wrong shape is an error.
	var probe struct {
		Tokens map[string]string `json:"tokens"`
	}
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("exportv1: header tokens: %w", err)
	}
	tokens := probe.Tokens
	for ref, jws := range tokens {
		if got := TokenRef(jws); got != ref {
			return fmt.Errorf("exportv1: header token keyed %s digests to %s: "+
				"the token at this address is not the one the receipts reference", short(ref), short(got))
		}
	}
	ex.Tokens = tokens
	return nil
}

func readLeaf(raw []byte) (*Leaf, error) {
	idxRaw, err := jsonspan.ExtractTopLevelValue(raw, "index")
	if err != nil {
		return nil, fmt.Errorf("leaf carries no index: %w", err)
	}
	var idx int
	if err := json.Unmarshal(idxRaw, &idx); err != nil {
		return nil, fmt.Errorf("leaf index: %w", err)
	}
	pt, err := stringMember(raw, "payloadType")
	if err != nil {
		return nil, err
	}
	span, err := jsonspan.ExtractTopLevelValue(raw, "payload")
	if err != nil {
		return nil, fmt.Errorf("leaf carries no payload: %w", err)
	}
	keyid, sig, err := readSig(raw)
	if err != nil {
		return nil, err
	}
	want, err := stringMember(raw, "leaf_hash")
	if err != nil {
		return nil, err
	}
	payload := append([]byte(nil), span...)
	got := dsse.LeafHash(pt, payload)
	if hex.EncodeToString(got[:]) != want {
		// Self-inconsistent before any signature is considered. Importing this
		// would put a record into a fresh log under a hash that does not
		// describe it.
		return nil, fmt.Errorf("leaf %d: leaf_hash %s does not describe its own payload (computed %s)",
			idx, short(want), short(hex.EncodeToString(got[:])))
	}
	return &Leaf{Index: idx, PayloadType: pt, Payload: payload, KeyID: keyid, Sig: sig, LeafHash: got}, nil
}

func readHead(raw []byte) (*Head, error) {
	span, err := jsonspan.ExtractTopLevelValue(raw, "head")
	if err != nil {
		return nil, fmt.Errorf("head line carries no head: %w", err)
	}
	bytesCopy := append([]byte(nil), span...)
	origin, err := stringMember(bytesCopy, "log_origin")
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	chain, err := stringMember(bytesCopy, "chain")
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	countRaw, err := jsonspan.ExtractTopLevelValue(bytesCopy, "count")
	if err != nil {
		return nil, fmt.Errorf("head carries no count: %w", err)
	}
	var count int
	if err := json.Unmarshal(countRaw, &count); err != nil {
		return nil, fmt.Errorf("head count: %w", err)
	}
	keyid, sig, err := readSig(raw)
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	return &Head{Bytes: bytesCopy, LogOrigin: origin, Count: count, Chain: chain, KeyID: keyid, Sig: sig}, nil
}

func readSig(raw []byte) (keyid string, sig []byte, err error) {
	sigRaw, err := jsonspan.ExtractTopLevelValue(raw, "sig")
	if err != nil {
		return "", nil, fmt.Errorf("carries no sig: %w", err)
	}
	keyid, err = stringMember(sigRaw, "keyid")
	if err != nil {
		return "", nil, fmt.Errorf("sig: %w", err)
	}
	b64, err := stringMember(sigRaw, "sig")
	if err != nil {
		return "", nil, fmt.Errorf("sig: %w", err)
	}
	sig, err = base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", nil, fmt.Errorf("sig is not standard base64: %w", err)
	}
	return keyid, sig, nil
}

func stringMember(obj []byte, key string) (string, error) {
	raw, err := jsonspan.ExtractTopLevelValue(obj, key)
	if err != nil {
		return "", fmt.Errorf("no %s member: %w", key, err)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("%s is not a string: %w", key, err)
	}
	return s, nil
}

func short(hexDigest string) string {
	if len(hexDigest) <= 12 {
		return hexDigest
	}
	return hexDigest[:12] + "…"
}
