package dsse

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// Known-answer PAE tests. The expected byte strings are written out by hand
// per docs/export-format-v1.md §1.2, and the expected SHA-256 values were
// computed independently with `shasum -a 256`, not with this package.

func TestPAEKnownAnswer(t *testing.T) {
	cases := []struct {
		name        string
		payloadType string
		payload     []byte
		wantPAE     []byte
		wantSHA256  string
	}{
		{
			name:        "simple_object",
			payloadType: "application/vnd.behalf.receipt+json",
			payload:     []byte(`{"a":1}`),
			wantPAE:     []byte("DSSEv1 35 application/vnd.behalf.receipt+json 7 {\"a\":1}"),
			wantSHA256:  "bfb4d4aa37e8b2c5431f7b7bfed5d896b4748144ade560955935e6b5c65d9c74",
		},
		{
			name:        "empty_payload",
			payloadType: "application/vnd.behalf.receipt+json",
			payload:     []byte{},
			wantPAE:     []byte("DSSEv1 35 application/vnd.behalf.receipt+json 0 "),
			wantSHA256:  "730500826f98217bdac4b8499b435c4898144e052a73471eae3070c5fad6ae1a",
		},
		{
			// Byte lengths, not rune counts: {"s":"héllo"} is 14 bytes.
			name:        "multibyte_utf8",
			payloadType: "application/vnd.behalf.receipt+json",
			payload:     []byte(`{"s":"héllo"}`),
			wantPAE:     []byte("DSSEv1 35 application/vnd.behalf.receipt+json 14 {\"s\":\"héllo\"}"),
			wantSHA256:  "bf2935b1aa17e639c117738ef30806dc2a2149c0ba173c623b16f583bfc3e8cf",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := PAE(c.payloadType, c.payload)
			if !bytes.Equal(got, c.wantPAE) {
				t.Fatalf("PAE mismatch:\n got  %q\n want %q", got, c.wantPAE)
			}
			sum := sha256.Sum256(got)
			if hex.EncodeToString(sum[:]) != c.wantSHA256 {
				t.Fatalf("PAE sha256 = %x, want %s", sum, c.wantSHA256)
			}
			leaf := LeafHash(c.payloadType, c.payload)
			if hex.EncodeToString(leaf[:]) != c.wantSHA256 {
				t.Fatalf("LeafHash = %x, want %s", leaf, c.wantSHA256)
			}
		})
	}
}

func TestPAELengthIsDecimalASCIIByteLength(t *testing.T) {
	// Crossing a digit boundary must widen the decimal length field.
	nine := PAE("t", bytes.Repeat([]byte("x"), 9))
	ten := PAE("t", bytes.Repeat([]byte("x"), 10))
	if want := []byte("DSSEv1 1 t 9 xxxxxxxxx"); !bytes.Equal(nine, want) {
		t.Fatalf("PAE(9) = %q, want %q", nine, want)
	}
	if want := []byte("DSSEv1 1 t 10 xxxxxxxxxx"); !bytes.Equal(ten, want) {
		t.Fatalf("PAE(10) = %q, want %q", ten, want)
	}
}

func TestSignVerifyRoundTrip(t *testing.T) {
	seed := sha256.Sum256([]byte("dsse test seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)

	payload := []byte(`{"hello":"world"}`)
	sig := Sign(priv, "application/vnd.behalf.receipt+json", payload)
	if !Verify(pub, "application/vnd.behalf.receipt+json", payload, sig) {
		t.Fatal("signature did not verify")
	}
	// A different payloadType must not verify: the type is inside the PAE.
	if Verify(pub, "application/vnd.behalf.chain-head+json", payload, sig) {
		t.Fatal("signature verified under a different payloadType")
	}
	// A single payload byte change must not verify.
	mutated := append([]byte(nil), payload...)
	mutated[2] ^= 1
	if Verify(pub, "application/vnd.behalf.receipt+json", mutated, sig) {
		t.Fatal("signature verified over mutated payload")
	}
}

// TestJWKThumbprintRFC8037 pins the RFC 7638 thumbprint computation to the
// published Ed25519 example in RFC 8037 appendix A.3 (value independently
// reproduced with openssl).
func TestJWKThumbprintRFC8037(t *testing.T) {
	j := JWK{Kty: "OKP", Crv: "Ed25519", X: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}
	const want = "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k"
	if got := j.Thumbprint(); got != want {
		t.Fatalf("thumbprint = %s, want %s", got, want)
	}
}

func TestJWKFromPublic(t *testing.T) {
	seed := sha256.Sum256([]byte("jwk test seed"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	j := JWKFromPublic(priv.Public().(ed25519.PublicKey))
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		t.Fatalf("unexpected JWK header: %+v", j)
	}
	if len(j.Thumbprint()) != 43 {
		t.Fatalf("thumbprint length = %d, want 43 (base64url of 32 bytes, no padding)", len(j.Thumbprint()))
	}
}
