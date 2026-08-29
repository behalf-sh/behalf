package oidclogin

import (
	"errors"
	"fmt"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/identity"
)

// The content-addressed store: customer-held payload blobs under
// <state>/blobs/<sha256-hex>, per Q22/Q34–Q38 — commitment and storage
// address are one value, plain SHA-256 over the raw plaintext bytes.
//
// The implementation was lifted into internal/cas in Week 3 so the MCP
// proxy writes into the same store under the same rules. This file keeps
// oidclogin's own error sentinels and messages, unchanged: callers here and
// in verify.go test with errors.Is against ErrBlobMissing/ErrBlobTampered.

// ErrBlobMissing marks a blob that is not in the store — the customer
// deleted it (or never had it). Distinct from ErrBlobTampered because a
// verifier must tell "deleted" apart from "altered" (Q22, Q36, D7).
var ErrBlobMissing = errors.New("oidclogin: blob missing from store")

// ErrBlobTampered marks a blob whose bytes no longer hash to their name.
var ErrBlobTampered = errors.New("oidclogin: blob content does not match its digest")

// blobStore returns the CAS rooted at <stateDir>/blobs.
func blobStore(stateDir string) *cas.Store { return cas.New(identity.BlobsDir(stateDir)) }

// digestHex returns the lowercase-hex SHA-256 of b.
func digestHex(b []byte) string { return cas.Digest(b) }

// putBlob writes b into the store and returns its digest.
func putBlob(stateDir string, b []byte) (string, error) {
	d, err := blobStore(stateDir).Put(b)
	if err != nil {
		return "", fmt.Errorf("oidclogin: %w", err)
	}
	return d, nil
}

// getBlob reads the blob for digest and re-verifies the content address.
// Returns ErrBlobMissing (wrapped) if absent, ErrBlobTampered (wrapped) if
// the bytes do not hash to digest.
func getBlob(stateDir, digest string) ([]byte, error) {
	b, err := blobStore(stateDir).Get(digest)
	var tampered *cas.TamperError
	switch {
	case errors.Is(err, cas.ErrMissing):
		return nil, fmt.Errorf("%w: %s", ErrBlobMissing, digest)
	case errors.As(err, &tampered):
		return nil, fmt.Errorf("%w: named %s, content hashes to %s", ErrBlobTampered, tampered.Want, tampered.Got)
	case err != nil:
		return nil, err
	}
	return b, nil
}
