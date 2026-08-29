// Copyright 2026 the behalf authors.
//
// This file is licensed under the Functional Source License, Version 1.1,
// ALv2 Future License (FSL-1.1-ALv2). See LICENSE-FSL in this directory and
// LICENSING.md at the repository root.

package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/behalf-sh/behalf/internal/envelope"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/tlog"
	"k8s.io/klog/v2"
)

// `behalf-log import` rebuilds a local log from export files.
//
// # Why this exists
//
// `npx onbehalf demo` has to put two recorded runs on a machine that has never
// seen behalf, with no network, no key and no tokens spent (Q92, D9.8). The
// obvious shape — ship a built log directory — does not survive contact with
// the size: the demo's tile directory is 23 MB on disk and 2.3 MB compressed,
// against 452 KB for the two exports it was made from. `npx` downloads the
// package every time somebody runs it, so the download IS the feature, and a
// five-fold difference in it is not a detail.
//
// So the package ships the exports and this rebuilds the log locally. The
// asymmetry is not accidental: an export is the run's evidence, and the tile
// directory is a data structure built over that evidence. Shipping the
// evidence and rebuilding the structure is the right way round, and it is the
// same direction Q76 already takes about the index — always rebuilt, never
// restored.
//
// # What is preserved, and what is not
//
// **Preserved: every receipt byte, and its signature.** The envelope is
// reassembled from the export's payload span and the emitter's original
// signature, both verbatim. `envelope.Build` is byte-for-byte the assembly the
// capture surface performed, so the rebuilt envelope is identical to the one
// the original log stored and the Merkle leaf over it is the same leaf. Export
// the imported log again and **every leaf line comes back byte-identical** —
// all 47 of them for a demo run. That is what makes this an import rather than
// a re-signing, and `TestImportPreservesEveryLeafByteForByte` pins it.
//
// **Not preserved: the head, and therefore the header's key list.** The
// imported log is a new log with its own checkpoint key, so a re-export's head
// line is signed by that key and its header lists it. That is not a rough edge
// to be smoothed: the checkpoint signing key belongs to the log service that
// wrote the original, it is not in the export, and a local process able to mint
// a checkpoint under the original log's identity is precisely the forgery this
// design exists to prevent. So the round trip is exact where it can be —
// receipts, which the emitter signed — and honestly different where it cannot
// be. The export file remains the artefact `behalf-verify` checks against the
// head that was actually signed, and the imported log stands on the emitter
// signatures each receipt still carries.
//
// # The verification gate
//
// An export is imported only after `behalf-verify` has passed over it. This
// package's reader checks structure and each leaf's self-consistency, and
// deliberately stops there (see internal/exportv1/reader.go) — the verification
// contract has two implementations already, pinned to each other by the
// conformance corpus, and a third one growing quietly inside an importer is how
// they would come to disagree. `--force` skips the gate, exists for the case
// where the verifier is not installed, and says what it is giving up.

func cmdImport(args []string) error {
	fs := flag.NewFlagSet("import", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	origin := fs.String("origin", "", "log origin for a directory that does not exist yet (default: the first export's own origin)")
	force := fs.Bool("force", false, "import without running behalf-verify over the files first")
	quiet := fs.Bool("quiet", false, "suppress the log service's own operational logging")
	state := fs.String("state", "", "behalf state directory holding the CAS (default: $BEHALF_HOME or ~/.behalf)")
	casDir := fs.String("cas", "", "hop token store directory (default: <state>/blobs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	files := fs.Args()
	if len(files) == 0 {
		return fmt.Errorf("import: name at least one export file")
	}
	if err := mustDir(dir, "import"); err != nil {
		return err
	}

	// Parse everything before touching the log. A half-imported log from a
	// second file that turned out to be malformed is worse than no import: it
	// is a log whose contents nobody stated.
	exports := make([]*exportv1.Export, 0, len(files))
	for _, name := range files {
		ex, err := readExportFile(name)
		if err != nil {
			return err
		}
		if !*force {
			if err := verifyExportFile(name); err != nil {
				return err
			}
		}
		exports = append(exports, ex)
	}

	if *quiet {
		// The Tessera library logs its own lifecycle through klog, including a
		// line reading "this should only happen ONCE per log!" on first use.
		// That is correct and useful to an operator running a log service, and
		// it is the wrong first thing a stranger sees from `npx onbehalf demo`
		// — it reads like a warning about something they did. The launcher
		// passes --quiet; a human running `behalf-log import` by hand does not,
		// and keeps the logging.
		klogFlags := flag.NewFlagSet("klog", flag.ContinueOnError)
		klog.InitFlags(klogFlags)
		_ = klogFlags.Set("logtostderr", "false")
		_ = klogFlags.Set("alsologtostderr", "false")
		_ = klogFlags.Set("stderrthreshold", "FATAL")
		klog.SetOutput(io.Discard)
		defer klog.Flush()
	}

	if err := ensureLog(*dir, importOrigin(*origin, exports)); err != nil {
		return err
	}
	key, err := tlog.LoadCheckpointKey(*dir)
	if err != nil {
		return err
	}
	ctx := context.Background()
	l, err := tlog.Open(ctx, *dir, key, tlog.Options{})
	if err != nil {
		return err
	}
	defer l.Close(ctx)

	// Every append is begun before any is waited on.
	//
	// This is not a micro-optimisation. `l.Append` is begin-then-wait, so a
	// loop over it serialises each receipt against the log's batching interval:
	// importing 94 receipts that way measured 28 seconds, against 1.7 for the
	// same 94 through this shape. `npx onbehalf demo` is the first thing anyone
	// runs and half a minute of apparently-hung terminal is the wrong first
	// impression for a tool whose pitch is that it stays out of the way.
	type pendingLeaf struct {
		p    *tlog.Pending
		file string
		idx  int
	}
	pendings := make([]pendingLeaf, 0, 128)
	// The delegation hop tokens travel in the export header too, and they
	// have to land in the customer-held store for the same reason the keys
	// land in the index: a later `behalf-log export` of this log looks them
	// up there, by the digest each receipt's evidence_ref names. Without this
	// the round trip import → export silently dropped them, and the offline
	// verifier told the first user of the npm demo "0 delegation hop(s)
	// checked" about a file whose source carried every token (ENG-42). The
	// store is content-addressed and Put is idempotent, so re-importing
	// costs nothing and a token that does not hash to its key is refused by
	// the reader before it gets here.
	if blobs, err := openStore(*state, *casDir); err == nil {
		for i, ex := range exports {
			for _, jws := range ex.Tokens {
				if _, err := blobs.Put([]byte(jws)); err != nil {
					return fmt.Errorf("import: %s: retain hop token: %w", files[i], err)
				}
			}
		}
	}

	for i, ex := range exports {
		// The emitter keys travel in the export header, which is what lets a
		// later `behalf-log export` of this log carry them forward and verify
		// its own leaves.
		for _, k := range ex.Keys {
			jwk, merr := json.Marshal(k.JWK)
			if merr != nil {
				return fmt.Errorf("import: %s: header key %s: %w", files[i], k.JKT, merr)
			}
			if err := l.RegisterKey(k.JKT, string(jwk)); err != nil {
				return fmt.Errorf("import: %s: register key %s: %w", files[i], k.JKT, err)
			}
		}
		for _, leaf := range ex.Leaves {
			env := envelope.Build(leaf.PayloadType, leaf.Payload, leaf.KeyID, leaf.Sig)
			p, aerr := l.BeginAppend(ctx, env)
			if aerr != nil {
				return fmt.Errorf("import: %s: leaf %d: %w", files[i], leaf.Index, aerr)
			}
			pendings = append(pendings, pendingLeaf{p: p, file: files[i], idx: leaf.Index})
		}
	}
	var appended, dups int
	for _, pl := range pendings {
		res, werr := pl.p.Wait(ctx)
		if werr != nil {
			return fmt.Errorf("import: %s: leaf %d: %w", pl.file, pl.idx, werr)
		}
		appended++
		if res.Duplicate {
			dups++
		}
	}
	if err := l.Close(ctx); err != nil {
		return err
	}

	fmt.Printf("imported %d receipt(s) from %d file(s) into %s (%d already present)\n",
		appended, len(files), *dir, dups)
	fmt.Printf("every receipt keeps the emitter signature it was captured with; the checkpoint over them\n" +
		"is this log's own, because the original log's checkpoint key is not in an export and could\n" +
		"not be — verify the export file itself against the head that signed it\n")
	return nil
}

// importOrigin picks the origin for a log directory that has to be created.
// Every export carries the origin of the log it came from, and reusing it keeps
// the imported log describing the same history rather than renaming it.
func importOrigin(flagValue string, exports []*exportv1.Export) string {
	if flagValue != "" {
		return flagValue
	}
	for _, ex := range exports {
		if ex.LogOrigin != "" {
			return ex.LogOrigin
		}
	}
	return ""
}

func readExportFile(name string) (*exportv1.Export, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("import: %w", err)
	}
	defer f.Close()
	ex, err := exportv1.Read(f)
	if err != nil {
		return nil, fmt.Errorf("import: %s: %w", name, err)
	}
	if len(ex.Leaves) == 0 {
		return nil, fmt.Errorf("import: %s: the export carries no receipts", name)
	}
	return ex, nil
}

// ensureLog creates and initialises the log directory when it does not already
// hold one, so `import` works on a machine that has never run `behalf-log init`
// — which is the whole point of the entry point it serves.
func ensureLog(dir, origin string) error {
	if _, err := os.Stat(filepath.Join(dir, "checkpoint")); err == nil {
		return nil
	}
	if origin == "" {
		return fmt.Errorf("import: %s does not hold a log and the export names no origin: pass --origin", dir)
	}
	return initLog(dir, origin)
}

// verifyExportFile runs the offline verifier over one export before its
// receipts are allowed into a log.
//
// The gate is the point of the whole entry point. `npx onbehalf demo` unpacks
// files that arrived over a network from a registry, and the product's own
// argument is that you do not have to take anyone's word for what is in them.
// Importing first and verifying later would invert that: the receipts would be
// in the log, indexed and rendered by `behalf runs`, before anything checked
// them.
//
// The verifier is a separate binary — the Rust one, deliberately, because it is
// the implementation a sceptic runs and the one the conformance corpus pins.
// Looking it up here rather than linking a Go verifier keeps the number of
// implementations of the verification contract at two.
//
// A missing verifier is reported as a missing verifier, with the flag that
// proceeds without it and what that costs. Silently skipping the check would be
// the worst of the three options.
func verifyExportFile(path string) error {
	bin, err := verifierBinary()
	if err != nil {
		return fmt.Errorf("import: %w\n"+
			"  Every export is verified before its receipts enter a log: these files arrived\n"+
			"  over a network and the point of this product is that you need not take anyone's\n"+
			"  word for what is in them.\n"+
			"  Build it with `cargo build --release --manifest-path verifier/Cargo.toml`, or\n"+
			"  pass --force to import unverified — which means the log will hold receipts\n"+
			"  nothing has checked", err)
	}
	cmd := exec.Command(bin, path)
	out, runErr := cmd.CombinedOutput()
	if runErr == nil {
		return nil
	}
	return fmt.Errorf("import: %s did not verify, so nothing was imported:\n%s",
		path, indentLines(string(out)))
}

// verifierBinary finds the offline verifier: the explicit override first, then
// beside this binary, then PATH. Same precedence and same environment variable
// as `behalf demo` and scripts/tamper_suite.sh, so a machine set up for one is
// set up for all three.
func verifierBinary() (string, error) {
	if p := os.Getenv("BEHALF_VERIFY"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("BEHALF_VERIFY names %s, which is not there", p)
		}
		return p, nil
	}
	if self, err := os.Executable(); err == nil {
		cand := filepath.Join(filepath.Dir(self), verifierName)
		if _, serr := os.Stat(cand); serr == nil {
			return cand, nil
		}
	}
	p, err := exec.LookPath(verifierName)
	if err != nil {
		return "", fmt.Errorf("the offline verifier (%s) is not beside this binary or on PATH", verifierName)
	}
	return p, nil
}

const verifierName = "behalf-verify"

func indentLines(s string) string {
	if s == "" {
		return "  (no output)"
	}
	return "  | " + strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  | ")
}
