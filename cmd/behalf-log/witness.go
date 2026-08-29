// Licensed under the Functional Source License, Version 1.1, ALv2 Future
// License (FSL-1.1-ALv2) — NOT Apache-2.0 like the rest of this repository.
// See ../../LICENSE-FSL, the copy in this directory, and LICENSING.md.
// This version converts to Apache-2.0 two years after it is made available.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/behalf-sh/behalf/internal/tlog"
	"github.com/behalf-sh/behalf/internal/witness"
)

// cmdWitness submits the log's published checkpoint to its configured
// witnesses and prints the per-checkpoint outcome (architecture Q29, Q76,
// Q96). It opens no appender, so it never fences a running log service
// (Q57) — an operator can run it against a live log.
//
// Exit codes follow the verifier's vocabulary (docs/export-format-v1.md
// §5): 0 when the checkpoint was cosigned, and also when it was not but the
// policy is fail-open — under FailOpen the checkpoint has already published
// and a missing cosignature is a recorded gap, not a finding. 1 when a
// witness *refused*, which is a finding about the log: the machine-readable
// line goes to stderr as `class=<truncation|chain> reason=<…> index=-1`,
// the same shape `behalf-verify` emits.
func cmdWitness(args []string) error {
	fs := flag.NewFlagSet("witness", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (required)")
	asJSON := fs.Bool("json", false, "emit the per-checkpoint witness record as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("witness: --dir is required")
	}

	rec, err := tlog.WitnessDir(context.Background(), *dir, nil)
	if err != nil {
		return err
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rec); err != nil {
			return err
		}
	} else {
		printWitnessRecord(rec)
	}

	switch rec.Outcome {
	case "cosigned":
		return nil
	case "refused":
		// The single most important signal the system can produce. Say it
		// in the verifier's own vocabulary so CI can assert on it.
		fmt.Fprintf(os.Stderr, "class=%s reason=%s index=-1\n", rec.Class, rec.Reason)
		fmt.Fprintf(os.Stderr, "witness refused checkpoint size=%d root=%s: %s\n", rec.Size, rec.Root, rec.Detail)
		return fmt.Errorf("witness: refused (%s)", rec.Reason)
	default:
		if rec.FailOpen {
			// Fail-open, stated as the availability mode it is (Q96).
			fmt.Fprintf(os.Stderr,
				"witness: %s (%s) — published anyway: fail_open=true is the v1 policy (Q96); the gap is recorded in %s\n",
				rec.Outcome, rec.Detail, tlog.WitnessOutcomesPath(*dir))
			return nil
		}
		fmt.Fprintf(os.Stderr, "witness: %s (%s) and fail_open=false\n", rec.Outcome, rec.Detail)
		return fmt.Errorf("witness: policy not satisfied")
	}
}

func printWitnessRecord(rec *tlog.WitnessRecord) {
	fmt.Printf("checkpoint %s size %d\n", rec.Origin, rec.Size)
	fmt.Printf("  root       %s\n", rec.Root)
	fmt.Printf("  policy     fail_open=%v timeout=%dms quorum=%d\n", rec.FailOpen, rec.TimeoutMS, rec.Quorum)
	fmt.Printf("  outcome    %s", rec.Outcome)
	if rec.Reason != "" {
		fmt.Printf(" (class=%s reason=%s)", rec.Class, rec.Reason)
	}
	fmt.Println()
	if rec.Detail != "" {
		fmt.Printf("  detail     %s\n", rec.Detail)
	}
	for _, w := range rec.Witnesses {
		fmt.Printf("  witness    %s %s", w.Witness, w.Outcome)
		if w.Reason != "" {
			fmt.Printf(" %s", w.Reason)
		}
		fmt.Println()
		if w.Outcome == witness.OutcomeCosigned && w.Cosignature != "" {
			fmt.Printf("             %s\n", w.Cosignature)
		} else if w.Detail != "" {
			fmt.Printf("             %s\n", w.Detail)
		}
	}
}
