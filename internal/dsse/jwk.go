package dsse

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
)

// JWK is an Ed25519 public key in JWK form (RFC 8037): kty OKP, crv Ed25519,
// x = base64url(raw 32-byte public key), no padding.
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
}

// JWKFromPublic returns the JWK for an Ed25519 public key.
func JWKFromPublic(pub ed25519.PublicKey) JWK {
	return JWK{
		Kty: "OKP",
		Crv: "Ed25519",
		X:   base64.RawURLEncoding.EncodeToString(pub),
	}
}

// Thumbprint returns the RFC 7638 JWK thumbprint: SHA-256 over the JSON
// object containing exactly the required members (crv, kty, x for OKP keys)
// in lexicographic order with no whitespace, base64url-encoded without
// padding.
//
// The construction string is built by hand rather than via encoding/json so
// the member order and absence of escaping are explicit; base64url values
// never need JSON escaping.
func (j JWK) Thumbprint() string {
	s := `{"crv":"` + j.Crv + `","kty":"` + j.Kty + `","x":"` + j.X + `"}`
	sum := sha256.Sum256([]byte(s))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
