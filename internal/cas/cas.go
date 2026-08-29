// Package cas is the customer-held content-addressed payload store
// (architecture Q34–Q38, D7): blobs live under a store directory named by
// the lowercase-hex SHA-256 of their raw plaintext bytes, so the commitment
// recorded in a receipt and the storage address are one value.
//
// Salting is deliberately absent: the store is customer-side, so a salt
// would break third-party verification and dedup while defending against
// nobody; the residual low-entropy-digest re-identification risk is
// accepted and documented (Q36, Q38).
//
// This package was lifted out of internal/oidclogin/cas.go in Week 3 so the
// MCP proxy and the login flow write into the same store with the same
// rules; oidclogin now delegates here and keeps its own error sentinels.
package cas

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ErrMissing marks a blob that is not in the store — the customer deleted
// it, or never had it. Distinct from ErrTampered because a verifier must
// tell "deleted" apart from "altered" (Q22, Q36, D7).
var ErrMissing = errors.New("cas: blob missing from store")

// ErrTampered marks a blob whose bytes no longer hash to their name.
var ErrTampered = errors.New("cas: blob content does not match its digest")

// TamperError is the concrete ErrTampered, carrying both digests so a
// caller can report what the content actually hashes to.
type TamperError struct {
	Want string // the name the blob is stored under
	Got  string // what its current bytes hash to
}

func (e *TamperError) Error() string {
	return fmt.Sprintf("%s: named %s, content hashes to %s", ErrTampered.Error(), e.Want, e.Got)
}

// Is makes errors.Is(err, ErrTampered) true for a *TamperError.
func (e *TamperError) Is(target error) bool { return target == ErrTampered }

// Digest returns the lowercase-hex SHA-256 of b — the commitment and the
// store address in one value (Q36).
func Digest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Store is one content-addressed store rooted at a directory.
type Store struct{ dir string }

// New returns a Store over dir without touching the filesystem.
func New(dir string) *Store { return &Store{dir: dir} }

// Dir returns the store's root directory.
func (s *Store) Dir() string { return s.dir }

// Ensure creates the store directory with owner-only permissions.
func (s *Store) Ensure() error {
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return fmt.Errorf("cas: create store dir: %w", err)
	}
	return nil
}

// Path returns the store path for a digest.
func (s *Store) Path(digest string) string { return filepath.Join(s.dir, digest) }

// Put writes b into the store and returns its digest. Blobs may carry
// identity material (the ID token) or tool arguments, so files are mode
// 0600. Writing an already-present digest is a no-op.
func (s *Store) Put(b []byte) (string, error) {
	d := Digest(b)
	path := s.Path(d)
	if _, err := os.Stat(path); err == nil {
		return d, nil
	}
	// The store creates its own directory. Every earlier caller happened to
	// run after `behalf login`, which creates <state>/blobs — until
	// `behalf-log import` on a fresh state directory tried to retain the hop
	// tokens from an export header and failed on the first blob. A
	// content-addressed store that cannot be written to before something
	// else has made its directory is a trap for every future caller too.
	if err := os.MkdirAll(s.dir, 0o700); err != nil {
		return "", fmt.Errorf("cas: create store: %w", err)
	}
	tmp, err := os.CreateTemp(s.dir, ".blob-*")
	if err != nil {
		return "", fmt.Errorf("cas: write blob: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return "", err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return "", err
	}
	return d, nil
}

// ReadRaw reads the blob for digest WITHOUT re-verifying the content
// address. It exists for exactly one job: characterising a blob that Get
// has already refused, so a reader can report what the altered bytes are
// rather than only that they are altered (Q83's `unreadable` state).
//
// Callers must not serve these bytes as the payload. They are, by
// construction, not the bytes the receipt commits to — that is what Get
// just said — so treating them as the record would defeat the commitment.
// Use Get everywhere else.
func (s *Store) ReadRaw(digest string) ([]byte, error) {
	b, err := os.ReadFile(s.Path(digest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrMissing, digest)
	}
	return b, err
}

// Get reads the blob for digest and re-verifies the content address.
// Returns ErrMissing (wrapped) if absent, ErrTampered (wrapped) if the
// bytes do not hash to digest.
func (s *Store) Get(digest string) ([]byte, error) {
	b, err := os.ReadFile(s.Path(digest))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w: %s", ErrMissing, digest)
	}
	if err != nil {
		return nil, err
	}
	if got := Digest(b); got != digest {
		return nil, &TamperError{Want: digest, Got: got}
	}
	return b, nil
}
