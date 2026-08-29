// Command behalf-vectors writes the Week-1 test-vector corpus
// (docs/export-format-v1.md §3) into testdata/vectors:
//
//	pae/*.json          — PAE known-answer cases
//	sig/*.json          — deterministic Ed25519 signature cases
//	chain/*.json        — chain computation cases
//	exports/intact_*.jsonl      — exports that must verify (exit 0)
//	exports/tampered_*/          — file.jsonl + expected.json per tamper case
//
// The Rust verifier's conformance test consumes this directory. Output is
// deterministic. testdata/ is gitignored; regenerated in CI.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

func main() {
	out := flag.String("out", filepath.Join("testdata", "vectors"), "output directory")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "behalf-vectors:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	r9, err := fixture.Generate(fixture.Run9F2A())
	if err != nil {
		return err
	}
	rc, err := fixture.Generate(fixture.RunC71E())
	if err != nil {
		return err
	}
	tiny, err := fixture.Generate(fixture.Tiny())
	if err != nil {
		return err
	}

	if err := writePAE(filepath.Join(dir, "pae"), r9); err != nil {
		return err
	}
	if err := writeSig(filepath.Join(dir, "sig"), r9); err != nil {
		return err
	}
	if err := writeChain(filepath.Join(dir, "chain"), r9); err != nil {
		return err
	}
	if err := writeDelegation(filepath.Join(dir, "exports")); err != nil {
		return err
	}
	if err := writeExports(filepath.Join(dir, "exports"), r9, rc, tiny); err != nil {
		return err
	}
	fmt.Println("wrote", dir)
	return nil
}

// ---- pae/ ----------------------------------------------------------------

// paeVector is one PAE known-answer case: the expected value is the SHA-256
// of PAE(payload_type, payload).
type paeVector struct {
	PayloadType       string `json:"payload_type"`
	PayloadB64        string `json:"payload_b64"`
	ExpectedPAESHA256 string `json:"expected_pae_sha256_hex"`
}

func writePAE(dir string, r9 *fixture.Result) error {
	cases := []struct {
		name        string
		payloadType string
		payload     []byte
	}{
		{"empty_payload", exportv1.PayloadTypeReceipt, []byte{}},
		{"simple_object", exportv1.PayloadTypeReceipt, []byte(`{"a":1}`)},
		{"multibyte_utf8", exportv1.PayloadTypeReceipt, []byte(`{"s":"héllo"}`)},
		{"len_9", exportv1.PayloadTypeReceipt, []byte(`{"n":123}`)},
		{"len_10", exportv1.PayloadTypeReceipt, []byte(`{"n":1234}`)},
		{"chain_head_type", exportv1.PayloadTypeChainHead, []byte(`{"format":"behalf.sh/export/v1","log_origin":"behalf.sh/demo/tiny","count":3,"chain":"00"}`)},
		{"receipt_step0", exportv1.PayloadTypeReceipt, r9.Payloads[0]},
	}
	for _, c := range cases {
		sum := dsse.LeafHash(c.payloadType, c.payload)
		v := paeVector{
			PayloadType:       c.payloadType,
			PayloadB64:        base64.StdEncoding.EncodeToString(c.payload),
			ExpectedPAESHA256: hex.EncodeToString(sum[:]),
		}
		if err := writeJSON(filepath.Join(dir, c.name+".json"), v); err != nil {
			return err
		}
	}
	return nil
}

// ---- sig/ ----------------------------------------------------------------

// sigVector is one deterministic-signature case. Beyond the contract's four
// fields it also carries payload_type and payload_b64 so the case is
// self-contained (Ed25519 verifies over the full PAE, not its hash; unknown
// extra fields must be ignored per the contract's greased-checkpoint rule).
type sigVector struct {
	SeedB64        string `json:"seed_b64"`
	JKT            string `json:"jkt"`
	PAESHA256Hex   string `json:"pae_sha256_hex"`
	ExpectedSigB64 string `json:"expected_sig_b64"`
	PayloadType    string `json:"payload_type"`
	PayloadB64     string `json:"payload_b64"`
}

func writeSig(dir string, r9 *fixture.Result) error {
	cases := []struct {
		name        string
		key         testkeys.Key
		payloadType string
		payload     []byte
	}{
		{"emitter_simple", testkeys.Emitter(), exportv1.PayloadTypeReceipt, []byte(`{"a":1}`)},
		{"emitter_receipt_step0", testkeys.Emitter(), exportv1.PayloadTypeReceipt, r9.Payloads[0]},
		{"head_signer_head", testkeys.HeadSigner(), exportv1.PayloadTypeChainHead, []byte(`{"format":"behalf.sh/export/v1","log_origin":"behalf.sh/demo/tiny","count":3,"chain":"00"}`)},
	}
	for _, c := range cases {
		paeSum := dsse.LeafHash(c.payloadType, c.payload)
		sig := dsse.Sign(c.key.Private, c.payloadType, c.payload)
		v := sigVector{
			SeedB64:        base64.StdEncoding.EncodeToString(c.key.Seed[:]),
			JKT:            c.key.JKT,
			PAESHA256Hex:   hex.EncodeToString(paeSum[:]),
			ExpectedSigB64: base64.StdEncoding.EncodeToString(sig),
			PayloadType:    c.payloadType,
			PayloadB64:     base64.StdEncoding.EncodeToString(c.payload),
		}
		if err := writeJSON(filepath.Join(dir, c.name+".json"), v); err != nil {
			return err
		}
	}
	return nil
}

// ---- chain/ --------------------------------------------------------------

type chainVector struct {
	LogOrigin        string   `json:"log_origin"`
	LeafHashesHex    []string `json:"leaf_hashes_hex"`
	ExpectedChainHex string   `json:"expected_chain_hex"`
}

func writeChain(dir string, r9 *fixture.Result) error {
	l0 := sha256.Sum256([]byte("leaf-0"))
	l1 := sha256.Sum256([]byte("leaf-1"))
	cases := []struct {
		name   string
		origin string
		leaves [][32]byte
	}{
		{"empty", "example.org/log", nil},
		{"one_leaf", "example.org/log", [][32]byte{l0}},
		{"two_leaves", "example.org/log", [][32]byte{l0, l1}},
		{"run_9f2a_47", r9.LogOrigin, r9.LeafHashes},
	}
	for _, c := range cases {
		chain := exportv1.ChainStart(c.origin)
		hexes := make([]string, 0, len(c.leaves))
		for _, lh := range c.leaves {
			chain = exportv1.ChainNext(chain, lh)
			hexes = append(hexes, hex.EncodeToString(lh[:]))
		}
		v := chainVector{
			LogOrigin:        c.origin,
			LeafHashesHex:    hexes,
			ExpectedChainHex: hex.EncodeToString(chain[:]),
		}
		if err := writeJSON(filepath.Join(dir, c.name+".json"), v); err != nil {
			return err
		}
	}
	return nil
}

// ---- exports/ ------------------------------------------------------------

type expectedClass struct {
	Class string `json:"class"`
	Index int    `json:"index"`
}

type expectedResult struct {
	ExitCode int             `json:"exit_code"`
	Classes  []expectedClass `json:"classes"`
}

func writeExports(dir string, r9, rc, tiny *fixture.Result) error {
	intact := []struct {
		name string
		data []byte
	}{
		{"intact_run_9f2a.jsonl", r9.Bytes},
		{"intact_run_c71e.jsonl", rc.Bytes},
		{"intact_tiny.jsonl", tiny.Bytes},
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, f := range intact {
		if err := os.WriteFile(filepath.Join(dir, f.name), f.data, 0o644); err != nil {
			return err
		}
	}

	tampered := []struct {
		name     string
		data     []byte
		expected expectedResult
	}{
		{
			// The demo cover-up: sed 's/1200.00/12.00/' on run_c71e. The
			// literal occurs exactly once, in the step-31 payload, so the
			// break is at index 31; receipts 32..46 become unverifiable.
			name:     "tampered_coverup",
			data:     bytes.Replace(rc.Bytes, []byte("1200.00"), []byte("12.00"), 1),
			expected: expectedResult{1, []expectedClass{{"content", 31}}},
		},
		{
			name:     "tampered_drop",
			data:     dropLeaf(r9.Bytes, 20),
			expected: expectedResult{1, []expectedClass{{"drop", 20}}},
		},
		{
			name:     "tampered_reorder",
			data:     swapLeaves(r9.Bytes, 10, 11),
			expected: expectedResult{1, []expectedClass{{"reorder", 10}}},
		},
		{
			// Remove the last 5 leaf lines, keep the head: head.count says
			// 47, the file has 42; first missing index is 42.
			name:     "tampered_truncate",
			data:     truncateLeaves(r9.Bytes, 5),
			expected: expectedResult{1, []expectedClass{{"truncation", 42}}},
		},
		{
			name:     "tampered_sigflip",
			data:     flipSigByte(r9.Bytes, 7),
			expected: expectedResult{1, []expectedClass{{"content", 7}}},
		},
		{
			// Editing head.chain: the chain recompute mismatch (verifier
			// check 4) fires before the head-signature check (check 6), so
			// the classification is "chain". Index -1 = no leaf index.
			name:     "tampered_headedit",
			data:     editHeadChain(r9.Bytes),
			expected: expectedResult{1, []expectedClass{{"chain", -1}}},
		},
		{
			name:     "tampered_garbage",
			data:     garbage(128),
			expected: expectedResult{2, []expectedClass{}},
		},
	}
	for _, t := range tampered {
		tdir := filepath.Join(dir, t.name)
		if err := os.MkdirAll(tdir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(tdir, "file.jsonl"), t.data, 0o644); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(tdir, "expected.json"), t.expected); err != nil {
			return err
		}
	}
	return nil
}

// ---- tamper helpers ------------------------------------------------------

// splitLines splits an export into its lines, without trailing newlines.
// Line 0 is the header, lines 1..n are leaves, the last line is the head.
func splitLines(data []byte) [][]byte {
	trimmed := bytes.TrimSuffix(data, []byte("\n"))
	return bytes.Split(trimmed, []byte("\n"))
}

func joinLines(lines [][]byte) []byte {
	var out []byte
	for _, l := range lines {
		out = append(out, l...)
		out = append(out, '\n')
	}
	return out
}

// dropLeaf removes the leaf line with the given index (leaf i is line i+1).
func dropLeaf(data []byte, index int) []byte {
	lines := splitLines(data)
	pos := index + 1
	return joinLines(append(lines[:pos:pos], lines[pos+1:]...))
}

// swapLeaves swaps the lines of two leaves.
func swapLeaves(data []byte, a, b int) []byte {
	lines := splitLines(data)
	lines[a+1], lines[b+1] = lines[b+1], lines[a+1]
	return joinLines(lines)
}

// truncateLeaves removes the last n leaf lines but keeps the head line.
func truncateLeaves(data []byte, n int) []byte {
	lines := splitLines(data)
	head := lines[len(lines)-1]
	kept := lines[: len(lines)-1-n : len(lines)-1-n]
	return joinLines(append(kept, head))
}

// flipSigByte changes one base64 character inside the signature of leaf
// `index`, keeping the string valid base64 so the failure is signature
// verification, not parsing.
func flipSigByte(data []byte, index int) []byte {
	lines := splitLines(data)
	line := append([]byte(nil), lines[index+1]...)
	// The inner signature string: `"sig":"` (the sig *object* is `"sig":{`).
	marker := []byte(`"sig":"`)
	i := bytes.Index(line, marker)
	if i < 0 {
		panic("behalf-vectors: leaf line has no sig string")
	}
	p := i + len(marker)
	if line[p] == 'A' {
		line[p] = 'B'
	} else {
		line[p] = 'A'
	}
	lines[index+1] = line
	return joinLines(lines)
}

// editHeadChain changes the first hex digit of head.chain.
func editHeadChain(data []byte) []byte {
	lines := splitLines(data)
	head := append([]byte(nil), lines[len(lines)-1]...)
	marker := []byte(`"chain":"`)
	i := bytes.Index(head, marker)
	if i < 0 {
		panic("behalf-vectors: head line has no chain field")
	}
	p := i + len(marker)
	if head[p] == '0' {
		head[p] = '1'
	} else {
		head[p] = '0'
	}
	lines[len(lines)-1] = head
	return joinLines(lines)
}

// garbage returns n deterministic pseudo-random bytes (a SHA-256 stream) —
// not a readable export, must classify as unverifiable (exit 2).
func garbage(n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		block := sha256.Sum256([]byte(fmt.Sprintf("behalf.sh/demo/garbage/%d", i)))
		out = append(out, block[:]...)
	}
	return out[:n]
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}
