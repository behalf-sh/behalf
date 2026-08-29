package exportv1

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/dsse"
)

// The header's token section is the carriage ENG-38 turns on: an export that
// says a chain verified, carrying the material to re-verify it.

func testKeys(t *testing.T) ([]HeaderKey, Signer) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	jwk := dsse.JWKFromPublic(pub)
	jkt := jwk.Thumbprint()
	return []HeaderKey{{JKT: jkt, JWK: jwk}}, Signer{Private: priv, KeyID: jkt}
}

func TestTokenRefIsTheEvidenceRefForm(t *testing.T) {
	// The whole point of the key form: what a receipt already carries is what
	// a reader looks the token up by, with no string surgery in between.
	ref := TokenRef("eyJhbGciOiJFZERTQSJ9.e30.sig")
	if !strings.HasPrefix(ref, "sha256:") {
		t.Fatalf("token ref %q is not in evidence_ref form", ref)
	}
	if len(ref) != len("sha256:")+64 {
		t.Fatalf("token ref %q is not sha256:<64 hex>", ref)
	}
}

func TestTokensRoundTripThroughAnExport(t *testing.T) {
	keys, signer := testKeys(t)
	jws := "eyJhbGciOiJFZERTQSJ9.eyJkZWxfZGVwdGgiOjB9.sig"
	tokens := map[string]string{TokenRef(jws): jws}

	var buf bytes.Buffer
	wr, err := NewWriterWithTokens(&buf, "example.log", keys, tokens)
	if err != nil {
		t.Fatal(err)
	}
	if err := wr.Append([]byte(`{"receipt_id":"a"}`), signer); err != nil {
		t.Fatal(err)
	}
	if err := wr.Close(signer); err != nil {
		t.Fatal(err)
	}

	ex, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if got := ex.Tokens[TokenRef(jws)]; got != jws {
		t.Fatalf("token did not round-trip: got %q want %q", got, jws)
	}
}

func TestNoTokensLeavesTheHeaderByteIdentical(t *testing.T) {
	// Every vector written before ENG-38 must stay valid and unchanged, which
	// is what `omitempty` on the section buys. If this fails, the conformance
	// corpus has to be regenerated for no reason.
	keys, signer := testKeys(t)

	var withNil, withEmpty bytes.Buffer
	for _, c := range []struct {
		w      *bytes.Buffer
		tokens map[string]string
	}{{&withNil, nil}, {&withEmpty, map[string]string{}}} {
		wr, err := NewWriterWithTokens(c.w, "example.log", keys, c.tokens)
		if err != nil {
			t.Fatal(err)
		}
		if err := wr.Close(signer); err != nil {
			t.Fatal(err)
		}
	}
	if !bytes.Equal(withNil.Bytes(), withEmpty.Bytes()) {
		t.Fatal("an empty token map changed the bytes; it must be indistinguishable from none")
	}
	if bytes.Contains(withNil.Bytes(), []byte(`"tokens"`)) {
		t.Fatal("header carries a tokens member when there are no tokens")
	}
}

func TestWriterRefusesATokenAtTheWrongAddress(t *testing.T) {
	keys, _ := testKeys(t)
	var buf bytes.Buffer
	_, err := NewWriterWithTokens(&buf, "example.log", keys,
		map[string]string{"sha256:" + strings.Repeat("0", 64): "not-the-token"})
	if err == nil {
		t.Fatal("writer emitted a token at an address that is not its digest")
	}
}

func TestSwappedTokenIsAFindingNotASubstitution(t *testing.T) {
	// The attack this closes: keep the receipt's `verified` claim, swap the
	// evidence underneath it for a token that says something else. The address
	// is the digest, so the swap cannot be silent.
	keys, signer := testKeys(t)
	jws := "eyJhbGciOiJFZERTQSJ9.eyJkZWxfZGVwdGgiOjB9.sig"
	ref := TokenRef(jws)

	var buf bytes.Buffer
	wr, err := NewWriterWithTokens(&buf, "example.log", keys, map[string]string{ref: jws})
	if err != nil {
		t.Fatal(err)
	}
	if err := wr.Close(signer); err != nil {
		t.Fatal(err)
	}

	tampered := bytes.Replace(buf.Bytes(), []byte(jws), []byte("eyJhbGciOiJFZERTQSJ9.eyJkZWxfZGVwdGgiOjl9.sig"), 1)
	if bytes.Equal(tampered, buf.Bytes()) {
		t.Fatal("test did not actually swap the token")
	}
	if _, err := Read(bytes.NewReader(tampered)); err == nil {
		t.Fatal("a token that does not match its address parsed cleanly")
	}
}

func TestMalformedTokensSectionIsReportedNotIgnored(t *testing.T) {
	// Absent and malformed must not collapse into each other: reading a
	// corrupt section as "this export has no tokens" would verify the file
	// happily and check nothing.
	keys, signer := testKeys(t)
	var buf bytes.Buffer
	wr, err := NewWriterWithTokens(&buf, "example.log", keys, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := wr.Close(signer); err != nil {
		t.Fatal(err)
	}
	lines := bytes.SplitN(buf.Bytes(), []byte("\n"), 2)

	var hdr map[string]json.RawMessage
	if err := json.Unmarshal(lines[0], &hdr); err != nil {
		t.Fatal(err)
	}
	hdr["tokens"] = json.RawMessage(`12345`) // not an object
	bad, err := json.Marshal(hdr)
	if err != nil {
		t.Fatal(err)
	}
	rebuilt := append(append(bad, '\n'), lines[1]...)

	if _, err := Read(bytes.NewReader(rebuilt)); err == nil {
		t.Fatal("a malformed tokens section was silently ignored")
	}
}
