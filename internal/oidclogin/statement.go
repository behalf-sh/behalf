package oidclogin

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/identity"
)

// The root delegation statement: the depth-0 delegation, signed by the
// device key (D5 check 3). It carries the full root-principal binding —
// issuer, sub_digest, nonce_jkt, id_token_digest, jwks_digest — and is
// stored as a customer-held blob in the content-addressed store, referenced
// by digest from the root receipt's payload slots (Q22; receipt-schema
// §9-adjacent). The receipt's own hop.root_principal_binding carries the
// frozen-schema subset {nonce, device_jkt, id_token_ref}.

// StatementSchemaVersion is the root delegation statement's projection key.
const StatementSchemaVersion = "behalf.sh/root-delegation/v1"

// PayloadTypeStatement is the DSSE payloadType for root delegation
// statements.
const PayloadTypeStatement = "application/vnd.behalf.root-delegation+json"

// Statement is the root delegation statement payload. Field order is
// serialization order; it is sealed once and the bytes are frozen (the
// span rule, export-format-v1.md §1.2).
type Statement struct {
	SchemaVersion string   `json:"schema_version"`
	JTI           string   `json:"jti"` // per-hop token id, behalf extension (Q11)
	Issuer        string   `json:"issuer"`
	SubDigest     string   `json:"sub_digest"` // sha256(issuer "\n" sub), never the raw sub (Q40)
	NonceJKT      string   `json:"nonce_jkt"`  // = jkt(device_pubkey) = the OIDC nonce (D5)
	IDTokenDigest string   `json:"id_token_digest"`
	JWKSDigest    string   `json:"jwks_digest"`
	DeviceJWK     dsse.JWK `json:"device_jwk"`
	DelegatedAt   string   `json:"delegated_at"` // RFC 3339
	Exp           int64    `json:"exp"`          // unix seconds
}

// statementEnvelope is the stored blob: a DSSE-style envelope whose payload
// is the statement's sealed bytes spliced verbatim (never re-marshaled) and
// whose signature is the device key's Ed25519 over
// PAE(PayloadTypeStatement, payload).
type statementEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     json.RawMessage `json:"payload"`
	Sig         envelopeSig     `json:"sig"`
}

type envelopeSig struct {
	KeyID string `json:"keyid"` // device key RFC 7638 thumbprint
	Sig   string `json:"sig"`   // base64 std
}

// sealStatement serializes st exactly once and signs the bytes with the
// device key, returning the envelope blob bytes.
func sealStatement(st *Statement, device *identity.Key) ([]byte, error) {
	payload, err := json.Marshal(st)
	if err != nil {
		return nil, fmt.Errorf("oidclogin: seal statement: %w", err)
	}
	sig := dsse.Sign(device.Private, PayloadTypeStatement, payload)
	env := statementEnvelope{
		PayloadType: PayloadTypeStatement,
		Payload:     payload, // RawMessage: spliced verbatim
		Sig: envelopeSig{
			KeyID: device.JKT,
			Sig:   base64.StdEncoding.EncodeToString(sig),
		},
	}
	return json.Marshal(env)
}

// openStatement parses an envelope blob and verifies the device-key
// signature over the payload bytes. The signing key is taken from the
// statement's own embedded device_jwk; the caller cross-checks that key's
// thumbprint against the ID token's nonce (D5 check 2), which is what
// anchors it to the IdP-signed evidence.
func openStatement(blob []byte) (*Statement, error) {
	var env statementEnvelope
	if err := json.Unmarshal(blob, &env); err != nil {
		return nil, fmt.Errorf("oidclogin: parse statement envelope: %w", err)
	}
	if env.PayloadType != PayloadTypeStatement {
		return nil, fmt.Errorf("oidclogin: statement payloadType %q, want %q", env.PayloadType, PayloadTypeStatement)
	}
	var st Statement
	if err := json.Unmarshal(env.Payload, &st); err != nil {
		return nil, fmt.Errorf("oidclogin: parse statement payload: %w", err)
	}
	if st.SchemaVersion != StatementSchemaVersion {
		return nil, fmt.Errorf("oidclogin: statement schema_version %q, want %q", st.SchemaVersion, StatementSchemaVersion)
	}
	pub, err := publicFromJWK(st.DeviceJWK)
	if err != nil {
		return nil, err
	}
	sig, err := base64.StdEncoding.DecodeString(env.Sig.Sig)
	if err != nil {
		return nil, fmt.Errorf("oidclogin: decode statement sig: %w", err)
	}
	if !dsse.Verify(pub, env.PayloadType, env.Payload, sig) {
		return nil, errors.New("oidclogin: root delegation statement signature invalid for the embedded device key")
	}
	if env.Sig.KeyID != st.DeviceJWK.Thumbprint() {
		return nil, fmt.Errorf("oidclogin: statement sig keyid %q does not match device_jwk thumbprint %q", env.Sig.KeyID, st.DeviceJWK.Thumbprint())
	}
	return &st, nil
}

// publicFromJWK decodes an OKP/Ed25519 JWK's public key.
func publicFromJWK(j dsse.JWK) (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("oidclogin: unsupported device_jwk %q/%q", j.Kty, j.Crv)
	}
	raw, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("oidclogin: decode device_jwk x: %w", err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("oidclogin: device_jwk x is %d bytes, want %d", len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// SubDigest returns the pseudonymous principal identifier: lowercase-hex
// SHA-256 over issuer, a single 0x0A, and the raw OIDC sub (Q40). The raw
// sub never leaves the customer-held ID-token blob.
func SubDigest(issuer, sub string) string {
	return digestHex([]byte(issuer + "\n" + sub))
}

// nowRFC3339 formats t the way receipts do.
func nowRFC3339(t time.Time) string { return t.UTC().Format(time.RFC3339) }
