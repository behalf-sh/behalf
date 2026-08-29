package tlog

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/behalf-sh/behalf/internal/testkeys"
)

func TestPromiseSignVerifyRoundTrip(t *testing.T) {
	key := testkeys.New("promise-signer-1")
	leaf := sha256.Sum256([]byte("some envelope"))
	issued := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)

	p := NewPromise("01K3D6ZDAJRZWD1JBHMFC5EXAMPLE", leaf[:], issued)
	if p.V != PromiseVersion || p.MMDSec != PromiseMMDSeconds {
		t.Fatalf("bad promise defaults: %+v", p)
	}
	sp, err := SignPromise(key.Private, key.JKT, p)
	if err != nil {
		t.Fatal(err)
	}
	if sp.KeyID != key.JKT {
		t.Fatalf("keyid = %s, want %s", sp.KeyID, key.JKT)
	}

	got, err := VerifyPromise(key.Public, sp)
	if err != nil {
		t.Fatal(err)
	}
	if got != p {
		t.Fatalf("verified promise %+v differs from signed %+v", got, p)
	}
	if got.LeafHash != hex.EncodeToString(leaf[:]) {
		t.Fatalf("leaf_hash = %s", got.LeafHash)
	}

	// Encode / decode round trip preserves the exact statement bytes.
	enc := sp.Encode()
	dec, err := DecodeSignedPromise(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec.Statement, sp.Statement) {
		t.Fatalf("decoded statement differs:\n%s\n%s", dec.Statement, sp.Statement)
	}
	if _, err := VerifyPromise(key.Public, dec); err != nil {
		t.Fatalf("decoded promise does not verify: %v", err)
	}
}

func TestPromiseWrongKeyRejected(t *testing.T) {
	key := testkeys.New("promise-signer-1")
	wrong := testkeys.New("promise-signer-2")
	leaf := sha256.Sum256([]byte("x"))
	sp, err := SignPromise(key.Private, key.JKT, NewPromise("rid", leaf[:], time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPromise(wrong.Public, sp); err == nil {
		t.Fatal("promise verified under the wrong key")
	}

	// A tampered statement must not verify either.
	tampered := &SignedPromise{
		Statement: []byte(strings.Replace(string(sp.Statement), `"rid"`, `"other"`, 1)),
		KeyID:     sp.KeyID,
		Sig:       sp.Sig,
	}
	if _, err := VerifyPromise(key.Public, tampered); err == nil {
		t.Fatal("tampered promise statement verified")
	}
}
