package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/behalf-sh/behalf/internal/fixture"
)

// TestVectorCorpusShape generates the corpus into a temp dir and checks the
// structural properties each tamper case relies on, so a refactor of the
// mutation helpers cannot silently ship a broken CI corpus.
func TestVectorCorpusShape(t *testing.T) {
	dir := t.TempDir()
	if err := run(dir); err != nil {
		t.Fatal(err)
	}

	read := func(parts ...string) []byte {
		b, err := os.ReadFile(filepath.Join(append([]string{dir}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	countLines := func(b []byte) int {
		return len(bytes.Split(bytes.TrimSuffix(b, []byte("\n")), []byte("\n")))
	}

	intact9 := read("exports", "intact_run_9f2a.jsonl")
	intactC := read("exports", "intact_run_c71e.jsonl")
	if countLines(intact9) != 49 || countLines(intactC) != 49 {
		t.Fatalf("intact runs must have 49 lines (header+47+head), got %d/%d",
			countLines(intact9), countLines(intactC))
	}
	res, err := fixture.Generate(fixture.Run9F2A())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(intact9, res.Bytes) {
		t.Fatal("intact_run_9f2a.jsonl differs from a fresh generation")
	}

	// coverup: same line count as intact c71e, exactly one line differs, the
	// literal is gone.
	coverup := read("exports", "tampered_coverup", "file.jsonl")
	if countLines(coverup) != 49 {
		t.Fatalf("coverup has %d lines", countLines(coverup))
	}
	if bytes.Contains(coverup, []byte("1200.00")) {
		t.Fatal("coverup still contains 1200.00")
	}
	ci, cc := bytes.Split(intactC, []byte("\n")), bytes.Split(coverup, []byte("\n"))
	diff := 0
	diffLine := -1
	for i := range ci {
		if !bytes.Equal(ci[i], cc[i]) {
			diff++
			diffLine = i
		}
	}
	if diff != 1 || diffLine != 32 {
		t.Fatalf("coverup differs from intact on %d lines (last diff line %d), want exactly line 32 (leaf 31)", diff, diffLine)
	}

	// drop: one fewer line, and no line carries "index":20.
	drop := read("exports", "tampered_drop", "file.jsonl")
	if countLines(drop) != 48 {
		t.Fatalf("drop has %d lines, want 48", countLines(drop))
	}
	if bytes.Contains(drop, []byte(`"index":20,`)) {
		t.Fatal("drop still contains leaf 20")
	}

	// reorder: same lines as intact, but leaf 11 now precedes leaf 10.
	reorder := read("exports", "tampered_reorder", "file.jsonl")
	if countLines(reorder) != 49 {
		t.Fatalf("reorder has %d lines", countLines(reorder))
	}
	p10 := bytes.Index(reorder, []byte(`"index":10,`))
	p11 := bytes.Index(reorder, []byte(`"index":11,`))
	if p10 < 0 || p11 < 0 || p11 > p10 {
		t.Fatalf("reorder should place leaf 11 before leaf 10 (pos 10=%d, 11=%d)", p10, p11)
	}

	// truncate: header + 42 leaves + head, head still says count 47.
	trunc := read("exports", "tampered_truncate", "file.jsonl")
	if countLines(trunc) != 44 {
		t.Fatalf("truncate has %d lines, want 44", countLines(trunc))
	}
	if !bytes.Contains(trunc, []byte(`"count":47`)) {
		t.Fatal("truncate head should still claim count 47")
	}
	if bytes.Contains(trunc, []byte(`"index":42,`)) {
		t.Fatal("truncate should have removed leaf 42")
	}

	// sigflip: exactly one line differs from intact, at leaf 7, payload intact.
	sigflip := read("exports", "tampered_sigflip", "file.jsonl")
	si, sf := bytes.Split(intact9, []byte("\n")), bytes.Split(sigflip, []byte("\n"))
	diff, diffLine = 0, -1
	for i := range si {
		if !bytes.Equal(si[i], sf[i]) {
			diff++
			diffLine = i
		}
	}
	if diff != 1 || diffLine != 8 {
		t.Fatalf("sigflip differs on %d lines (line %d), want exactly line 8 (leaf 7)", diff, diffLine)
	}

	// headedit: only the head line differs.
	headedit := read("exports", "tampered_headedit", "file.jsonl")
	hi, he := bytes.Split(intact9, []byte("\n")), bytes.Split(headedit, []byte("\n"))
	diff, diffLine = 0, -1
	for i := range hi {
		if !bytes.Equal(hi[i], he[i]) {
			diff++
			diffLine = i
		}
	}
	if diff != 1 || diffLine != 48 {
		t.Fatalf("headedit differs on %d lines (line %d), want exactly the head line 48", diff, diffLine)
	}

	// garbage: must not parse as JSON lines.
	garbage := read("exports", "tampered_garbage", "file.jsonl")
	var v any
	if json.Unmarshal(bytes.Split(garbage, []byte("\n"))[0], &v) == nil {
		t.Fatal("garbage first line unexpectedly parses as JSON")
	}

	// every expected.json parses and carries a valid exit code.
	entries, err := os.ReadDir(filepath.Join(dir, "exports"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		tampered++
		var exp struct {
			ExitCode *int `json:"exit_code"`
			Classes  []struct {
				Class string `json:"class"`
				Index *int   `json:"index"`
			} `json:"classes"`
		}
		b := read("exports", e.Name(), "expected.json")
		if err := json.Unmarshal(b, &exp); err != nil {
			t.Fatalf("%s/expected.json: %v", e.Name(), err)
		}
		if exp.ExitCode == nil || (*exp.ExitCode != 1 && *exp.ExitCode != 2) {
			t.Fatalf("%s/expected.json: bad exit_code", e.Name())
		}
		if exp.Classes == nil {
			t.Fatalf("%s/expected.json: classes must be present (empty array allowed)", e.Name())
		}
		for _, c := range exp.Classes {
			if c.Class == "" || c.Index == nil {
				t.Fatalf("%s/expected.json: class entries need class and index", e.Name())
			}
		}
	}
	// 7 record-integrity cases, plus one per delegation invariant the offline
	// verifier checks (ENG-38: I1, I2, I3, I5).
	if tampered != 11 {
		t.Fatalf("expected 11 tampered cases, found %d", tampered)
	}
}
