// Command behalf-fixtures writes the deterministic Week-1 fixture pair
// (docs/export-format-v1.md §4) into testdata/fixtures:
//
//	run_9f2a.jsonl — 47 receipts, ord_5512 first at step 12, refund "12.00"
//	run_c71e.jsonl — 47 receipts, ord_5518 first at step 12, refund "1200.00"
//
// Output is byte-identical across invocations. testdata/ is gitignored; the
// files are regenerated in CI.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/behalf-sh/behalf/internal/fixture"
)

func main() {
	out := flag.String("out", filepath.Join("testdata", "fixtures"), "output directory")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintln(os.Stderr, "behalf-fixtures:", err)
		os.Exit(1)
	}
}

func run(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, spec := range []fixture.Spec{fixture.Run9F2A(), fixture.RunC71E()} {
		res, err := fixture.Generate(spec)
		if err != nil {
			return fmt.Errorf("generate %s: %w", spec.RunID, err)
		}
		path := filepath.Join(dir, spec.RunID+".jsonl")
		if err := os.WriteFile(path, res.Bytes, 0o644); err != nil {
			return err
		}
		fmt.Printf("wrote %s (%d receipts, %d bytes)\n", path, spec.Count, len(res.Bytes))
	}
	return nil
}
