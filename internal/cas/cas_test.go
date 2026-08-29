package cas

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestPutGetRoundTrip: the digest is the address, writing twice is a no-op,
// and reading re-verifies the content address.
func TestPutGetRoundTrip(t *testing.T) {
	s := New(t.TempDir())
	if err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	payload := []byte(`{"order_id":"ord_5518","amount":"1200.00"}`)
	d, err := s.Put(payload)
	if err != nil {
		t.Fatal(err)
	}
	if d != Digest(payload) {
		t.Fatalf("Put returned %s, Digest says %s", d, Digest(payload))
	}
	again, err := s.Put(payload)
	if err != nil || again != d {
		t.Fatalf("re-putting the same bytes returned (%s, %v)", again, err)
	}
	got, err := s.Get(d)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("read back %s", got)
	}
	if fi, err := os.Stat(s.Path(d)); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Fatalf("blob mode %v, want 0600 (blobs can carry identity material)", fi.Mode().Perm())
	}
}

// TestMissingAndTamperedAreDifferentFindings: a verifier must tell "the
// customer deleted it" from "the bytes changed" (Q22, Q36, D7).
func TestMissingAndTamperedAreDifferentFindings(t *testing.T) {
	dir := t.TempDir()
	s := New(dir)
	if err := s.Ensure(); err != nil {
		t.Fatal(err)
	}
	d, err := s.Put([]byte("original"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := s.Get(Digest([]byte("never stored"))); !errors.Is(err, ErrMissing) {
		t.Fatalf("absent blob returned %v, want ErrMissing", err)
	}

	if err := os.WriteFile(filepath.Join(dir, d), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s.Get(d)
	if !errors.Is(err, ErrTampered) {
		t.Fatalf("altered blob returned %v, want ErrTampered", err)
	}
	var te *TamperError
	if !errors.As(err, &te) || te.Want != d || te.Got != Digest([]byte("tampered")) {
		t.Fatalf("TamperError = %+v", te)
	}
}
