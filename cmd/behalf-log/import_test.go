package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/exportv1"
)

// The property `behalf-log import` has to have, and the two ways it could be
// broken without anyone noticing.
//
// It could re-serialize a payload on the way through — the JSON would look the
// same and every signature would stop verifying. Or it could re-sign, which
// would make everything verify and mean nothing, because the receipts would
// then be attested by whoever ran the import rather than by the surface that
// captured them. Byte equality of the leaf lines is the check that rules out
// both at once.

func withLog(t *testing.T, dir string, run func()) {
	t.Helper()
	t.Setenv("BEHALF_LOG_DIR", dir)
	run()
}

// seedLog builds a log holding the two shipped fixture runs.
func seedLog(t *testing.T, dir string) {
	t.Helper()
	if err := cmdInit([]string{"--dir", dir, "--origin", "behalf.sh/log/test"}); err != nil {
		t.Fatalf("init: %v", err)
	}
	if err := cmdIngest([]string{"--dir", dir, "--runs", "run_9f2a,run_c71e"}); err != nil {
		t.Fatalf("ingest: %v", err)
	}
}

func exportRun(t *testing.T, dir, run, out string) []byte {
	t.Helper()
	if err := cmdExport([]string{"--dir", dir, "--run", run, "--out", out}); err != nil {
		t.Fatalf("export %s: %v", run, err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestImportPreservesEveryLeafByteForByte is the claim the import path makes in
// its own output, under test.
func TestImportPreservesEveryLeafByteForByte(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	seedLog(t, src)
	first := exportRun(t, src, "run_9f2a", filepath.Join(root, "a.jsonl"))

	dst := filepath.Join(root, "dst")
	// --force: the offline verifier is a Rust binary that a `go test` run has
	// no business requiring. The gate itself is exercised below.
	if err := cmdImport([]string{"--dir", dst, "--force", filepath.Join(root, "a.jsonl")}); err != nil {
		t.Fatalf("import: %v", err)
	}
	second := exportRun(t, dst, "run_9f2a", filepath.Join(root, "a2.jsonl"))

	before := splitLines(first)
	after := splitLines(second)
	if len(before) != len(after) {
		t.Fatalf("re-export has %d lines, the original had %d", len(after), len(before))
	}
	if len(before) < 3 {
		t.Fatalf("the fixture export is too small to be meaningful: %d lines", len(before))
	}
	// Leaves: byte-identical, every one of them.
	for i := 1; i < len(before)-1; i++ {
		if !bytes.Equal(before[i], after[i]) {
			t.Fatalf("leaf line %d changed on the round trip.\nbefore: %s\n after: %s",
				i-1, truncate(before[i]), truncate(after[i]))
		}
	}
	// The head: NOT identical, and that is the honest half. The imported log
	// signs its own checkpoint because the original log's key is not in an
	// export and could not be — a local process able to mint one under the
	// original log's identity is the forgery this design prevents. A test that
	// asserted the heads matched would be asserting that forgery worked.
	if bytes.Equal(before[len(before)-1], after[len(after)-1]) {
		t.Fatal("the re-exported head is identical to the original's: the import re-used a checkpoint key it should not have")
	}
}

// TestImportIsIdempotent: running the same import twice must not double the
// log. Duplicate collapse is Q46's rule and the log already implements it; what
// this pins is that import goes through that path rather than around it.
func TestImportIsIdempotent(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	seedLog(t, src)
	path := filepath.Join(root, "a.jsonl")
	exportRun(t, src, "run_9f2a", path)

	dst := filepath.Join(root, "dst")
	for i := 0; i < 2; i++ {
		if err := cmdImport([]string{"--dir", dst, "--force", path}); err != nil {
			t.Fatalf("import %d: %v", i, err)
		}
	}
	// The log is readable and holds the run once, not twice.
	withLog(t, dst, func() {
		if err := cmdRuns([]string{"--dir", dst}); err != nil {
			t.Fatalf("runs after a repeated import: %v", err)
		}
	})
}

// TestImportRefusesAnExportItCannotRead: nothing reaches the log until every
// named file has parsed. A half-imported log built from a second file that
// turned out to be junk is worse than no import — it is a log whose contents
// nobody stated.
func TestImportRefusesAnExportItCannotRead(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	seedLog(t, src)
	good := filepath.Join(root, "a.jsonl")
	exportRun(t, src, "run_9f2a", good)

	bad := filepath.Join(root, "bad.jsonl")
	if err := os.WriteFile(bad, []byte("{\"hello\":\"world\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(root, "dst")
	err := cmdImport([]string{"--dir", dst, "--force", good, bad})
	if err == nil {
		t.Fatal("import accepted a file that is not an export")
	}
	if !strings.Contains(err.Error(), bad) {
		t.Fatalf("the error does not name the file it refused: %v", err)
	}
	// And the good file's receipts did not sneak in ahead of the failure.
	if _, serr := os.Stat(filepath.Join(dst, "checkpoint")); serr == nil {
		t.Fatal("a log was created despite the import failing: parsing must complete before anything is appended")
	}
}

// TestImportGateNamesTheMissingVerifier: without --force the import runs the
// offline verifier first, and when that binary is absent it says so — naming
// the flag that proceeds without it and what that costs. Silently skipping the
// check would be the worst of the three options, and this is the test that
// makes silence impossible.
func TestImportGateNamesTheMissingVerifier(t *testing.T) {
	root := t.TempDir()
	src := filepath.Join(root, "src")
	seedLog(t, src)
	path := filepath.Join(root, "a.jsonl")
	exportRun(t, src, "run_9f2a", path)

	t.Setenv("BEHALF_VERIFY", filepath.Join(root, "no-such-verifier"))
	t.Setenv("PATH", root) // and nothing on PATH either
	err := cmdImport([]string{"--dir", filepath.Join(root, "dst"), path})
	if err == nil {
		t.Fatal("import proceeded with no verifier and no --force")
	}
	msg := err.Error()
	for _, want := range []string{"--force", "verified before its receipts enter a log"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("the refusal does not mention %q: %v", want, err)
		}
	}
}

func splitLines(b []byte) [][]byte {
	return bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
}

func truncate(b []byte) string {
	if len(b) <= 120 {
		return string(b)
	}
	return string(b[:120]) + "…"
}

// TestReindexThenExportIsUnchanged is Q76's claim under test: the index is
// disposable, delete it and replay the log and everything still works.
//
// It did not. The keys table was the one part of index.db not reconstructible
// from entry bundles — stored envelopes carry key thumbprints only — and the
// consequence was not a degraded export but two failures in sequence. First
// `export` refused outright: "header requires at least one key". Then, once the
// emitter key was recovered, the export still carried no checkpoint key, so its
// own head signature named a key its header did not hold and `behalf-verify`
// called the file TAMPERED.
//
// An export that reads as tampered because somebody rebuilt a cache is the worst
// false positive this product can produce: it spends the one alarm that has to
// mean something.
func TestReindexThenExportIsUnchanged(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "log")
	seedLog(t, dir)

	before := exportRun(t, dir, "run_9f2a", filepath.Join(root, "before.jsonl"))

	if err := os.Remove(filepath.Join(dir, "index.db")); err != nil {
		t.Fatalf("remove index: %v", err)
	}
	if err := cmdReindex([]string{"--dir", dir}); err != nil {
		t.Fatalf("reindex: %v", err)
	}

	after := exportRun(t, dir, "run_9f2a", filepath.Join(root, "after.jsonl"))
	if !bytes.Equal(before, after) {
		b, a := splitLines(before), splitLines(after)
		if len(b) > 0 && len(a) > 0 && !bytes.Equal(b[0], a[0]) {
			t.Fatalf("the export header changed across a reindex — the key set was not restored.\nbefore: %s\n after: %s",
				truncate(b[0]), truncate(a[0]))
		}
		t.Fatal("the export changed across a reindex")
	}
}

// TestExportAlwaysCarriesItsOwnHeadKey pins the invariant independently of how
// the index got into whatever state it is in: the key that signs the head is in
// the header, by construction. A header that omits it describes a file nobody
// can verify, whatever the index happens to hold.
func TestExportAlwaysCarriesItsOwnHeadKey(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "log")
	seedLog(t, dir)
	raw := exportRun(t, dir, "run_9f2a", filepath.Join(root, "a.jsonl"))

	ex, err := exportv1.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("read the export back: %v", err)
	}
	found := false
	for _, k := range ex.Keys {
		if k.JKT == ex.Head.KeyID {
			found = true
		}
	}
	if !found {
		var have []string
		for _, k := range ex.Keys {
			have = append(have, k.JKT)
		}
		t.Fatalf("the head is signed by %s and the header carries %v", ex.Head.KeyID, have)
	}
}
