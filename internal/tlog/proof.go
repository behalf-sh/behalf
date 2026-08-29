package tlog

import (
	"context"
	"fmt"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/client"
)

// Merkle proofs read out of a log directory's hash tiles.
//
// None of the RFC 6962 arithmetic is written here: node selection is
// transparency-dev/merkle's `proof.Consistency`/`proof.Inclusion`, node
// fetching (including the ephemeral nodes a partial tree needs) is
// Tessera's `client.ProofBuilder`, and verification is
// `proof.VerifyConsistency`/`proof.VerifyInclusion`. This file is the
// wiring that points those at a POSIX log dir, and it exists because
// nothing in internal/tlog previously built a proof — the read path
// (BundleReader) serves entries, not proofs.

// ConsistencyProof returns the RFC 6962 consistency proof between two tree
// sizes of the log in dir, read from its stored hash tiles.
//
// This is what a witness needs in order to accept a larger tree without
// trusting the log: the proof carries the root the witness already holds
// forward to the root the new checkpoint declares (architecture Q29/Q76).
//
// `to` must not exceed the size the published checkpoint commits to — the
// tiles above it may be partially written.
func ConsistencyProof(ctx context.Context, dir string, from, to uint64) ([][]byte, error) {
	if from > to {
		return nil, fmt.Errorf("tlog: consistency proof from %d to %d runs backwards", from, to)
	}
	if from == 0 || from == to {
		// Any tree is consistent with the empty tree, and with itself.
		return nil, nil
	}
	fetcher := client.FileFetcher{Root: dir}
	pb, err := client.NewProofBuilder(ctx, to, fetcher.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("tlog: proof builder at size %d: %w", to, err)
	}
	pf, err := pb.ConsistencyProof(ctx, from, to)
	if err != nil {
		return nil, fmt.Errorf("tlog: consistency proof %d->%d: %w", from, to, err)
	}
	return pf, nil
}

// VerifyConsistency checks a consistency proof between two tree heads. It
// is the read-side counterpart of ConsistencyProof, offered here so callers
// do not have to reach for the merkle package (and its hasher) themselves.
func VerifyConsistency(fromSize, toSize uint64, pf [][]byte, fromRoot, toRoot []byte) error {
	return proof.VerifyConsistency(rfc6962.DefaultHasher, fromSize, toSize, pf, fromRoot, toRoot)
}

// InclusionProof returns the RFC 6962 inclusion proof for one leaf index in
// a tree of the given size, read from the log dir's hash tiles.
func InclusionProof(ctx context.Context, dir string, index, size uint64) ([][]byte, error) {
	if index >= size {
		return nil, fmt.Errorf("tlog: leaf %d is not inside a tree of size %d", index, size)
	}
	fetcher := client.FileFetcher{Root: dir}
	pb, err := client.NewProofBuilder(ctx, size, fetcher.ReadTile)
	if err != nil {
		return nil, fmt.Errorf("tlog: proof builder at size %d: %w", size, err)
	}
	pf, err := pb.InclusionProof(ctx, index)
	if err != nil {
		return nil, fmt.Errorf("tlog: inclusion proof for leaf %d at size %d: %w", index, size, err)
	}
	return pf, nil
}

// VerifyInclusion checks an inclusion proof for leafHash at index in a tree
// of the given size and root.
func VerifyInclusion(index, size uint64, leafHash []byte, pf [][]byte, root []byte) error {
	return proof.VerifyInclusion(rfc6962.DefaultHasher, index, size, leafHash, pf, root)
}
