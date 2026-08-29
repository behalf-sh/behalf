package tlog

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// PayloadTypePromise is the DSSE payloadType for receipt promises.
const PayloadTypePromise = "application/vnd.behalf.promise+json"

// PromiseVersion is the promise statement version string.
const PromiseVersion = "behalf.sh/promise/v1"

// PromiseMMDSeconds is the maximum merge delay carried in every promise:
// the window within which the promised entry must be covered by a published
// checkpoint (architecture Q57: checkpoint cadence plus witness timeouts).
const PromiseMMDSeconds = 10

// Promise is the receipt promise statement — the CT SCT analogue
// (architecture D2/Q57). It is a signed commitment, returned synchronously
// with the append ack, that the log has durably committed the leaf and that
// a checkpoint covering it will publish within mmd_s seconds.
//
// A promise is NOT an inclusion proof. It is redeemable against a published
// checkpoint: a verifier that holds a promise checks that a checkpoint of
// sufficient size exists and that the leaf is included under it. A promise
// that never becomes redeemable within the MMD is capture loss, receipted on
// recovery (Q57).
type Promise struct {
	V         string `json:"v"`          // PromiseVersion
	ReceiptID string `json:"receipt_id"` // the promised receipt's ULID
	LeafHash  string `json:"leaf_hash"`  // hex, RFC 6962 leaf hash of the stored envelope bytes
	IssuedAt  string `json:"issued_at"`  // RFC 3339 UTC
	MMDSec    int    `json:"mmd_s"`      // PromiseMMDSeconds
}

// SignedPromise carries the exact signed promise bytes plus the signature.
// Statement is the byte span that was signed (the span rule); it is never
// re-serialized.
type SignedPromise struct {
	Statement []byte // the promise JSON, exactly as signed
	KeyID     string // RFC 7638 thumbprint of the checkpoint key's JWK
	Sig       []byte // Ed25519 over PAE(PayloadTypePromise, Statement)
}

// NewPromise builds the promise statement for a committed leaf.
func NewPromise(receiptID string, leafHash []byte, issuedAt time.Time) Promise {
	return Promise{
		V:         PromiseVersion,
		ReceiptID: receiptID,
		LeafHash:  fmt.Sprintf("%x", leafHash),
		IssuedAt:  issuedAt.UTC().Format(time.RFC3339),
		MMDSec:    PromiseMMDSeconds,
	}
}

// SignPromise serializes p exactly once and signs those bytes with the
// checkpoint key (only the current lock-holder signs promises — Q57). The
// returned SignedPromise is not an inclusion proof; it is an SCT-style
// commitment redeemable at checkpoint publication.
func SignPromise(priv ed25519.PrivateKey, keyid string, p Promise) (*SignedPromise, error) {
	if p.V != PromiseVersion {
		return nil, fmt.Errorf("tlog: promise version %q, want %q", p.V, PromiseVersion)
	}
	stmt, err := json.Marshal(p)
	if err != nil {
		return nil, fmt.Errorf("tlog: marshal promise: %w", err)
	}
	sig := dsse.Sign(priv, PayloadTypePromise, stmt)
	return &SignedPromise{Statement: stmt, KeyID: keyid, Sig: sig}, nil
}

// VerifyPromise checks sp's signature against pub over the exact statement
// bytes and returns the parsed promise. It verifies only the promise
// signature — a valid promise is not an inclusion proof and says nothing
// about checkpoint coverage; redeem it against a published checkpoint.
func VerifyPromise(pub ed25519.PublicKey, sp *SignedPromise) (Promise, error) {
	var p Promise
	if sp == nil {
		return p, errors.New("tlog: nil promise")
	}
	if !dsse.Verify(pub, PayloadTypePromise, sp.Statement, sp.Sig) {
		return p, errors.New("tlog: promise signature does not verify")
	}
	if err := json.Unmarshal(sp.Statement, &p); err != nil {
		return p, fmt.Errorf("tlog: parse promise statement: %w", err)
	}
	if p.V != PromiseVersion {
		return Promise{}, fmt.Errorf("tlog: promise version %q, want %q", p.V, PromiseVersion)
	}
	return p, nil
}

// Encode renders the signed promise as one JSON line, splicing the signed
// statement bytes verbatim (the span rule):
//
//	{"promise":<statement verbatim>,"sig":{"keyid":<jkt>,"sig":"<b64std>"}}
func (sp *SignedPromise) Encode() []byte {
	var b []byte
	b = append(b, `{"promise":`...)
	b = append(b, sp.Statement...)
	b = append(b, `,"sig":{"keyid":`...)
	b = appendJSONString(b, sp.KeyID)
	b = append(b, `,"sig":"`...)
	b = append(b, base64.StdEncoding.EncodeToString(sp.Sig)...)
	b = append(b, `"}}`...)
	return b
}

// DecodeSignedPromise parses an encoded signed promise, extracting the
// statement byte span with a span scanner (never parse-and-reserialize).
func DecodeSignedPromise(line []byte) (*SignedPromise, error) {
	stmt, err := jsonspan.ExtractTopLevelValue(line, "promise")
	if err != nil {
		return nil, fmt.Errorf("tlog: promise span: %w", err)
	}
	sigRaw, err := jsonspan.ExtractTopLevelValue(line, "sig")
	if err != nil {
		return nil, fmt.Errorf("tlog: promise sig: %w", err)
	}
	var sig struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	}
	if err := json.Unmarshal(sigRaw, &sig); err != nil {
		return nil, fmt.Errorf("tlog: promise sig: %w", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		return nil, fmt.Errorf("tlog: promise sig b64: %w", err)
	}
	return &SignedPromise{Statement: stmt, KeyID: sig.KeyID, Sig: sigBytes}, nil
}
