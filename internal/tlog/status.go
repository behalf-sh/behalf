package tlog

import (
	"context"
	"fmt"

	f_log "github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/tessera/client"
	"golang.org/x/mod/sumdb/note"
)

// LogCheckpoint is the parsed, signature-verified published checkpoint.
type LogCheckpoint struct {
	Origin string
	Size   uint64
	Root   []byte // RFC 6962 root hash
	Raw    []byte // the full signed note, verbatim
}

// ParseLogCheckpoint reads dir/checkpoint, verifies its signature against
// the log's verifier key (dir/keys/checkpoint.vkey), and returns the parsed
// contents. It is a read-only operation.
func ParseLogCheckpoint(ctx context.Context, dir string) (*LogCheckpoint, error) {
	vkey, err := LoadVerifierKey(dir)
	if err != nil {
		return nil, err
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		return nil, fmt.Errorf("tlog: verifier key: %w", err)
	}
	fetcher := client.FileFetcher{Root: dir}
	raw, err := fetcher.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("tlog: read checkpoint: %w", err)
	}
	cp, _, _, err := f_log.ParseCheckpoint(raw, verifier.Name(), verifier)
	if err != nil {
		return nil, fmt.Errorf("tlog: parse checkpoint: %w", err)
	}
	return &LogCheckpoint{Origin: cp.Origin, Size: cp.Size, Root: cp.Hash, Raw: raw}, nil
}
