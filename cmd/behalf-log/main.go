// Licensed under the Functional Source License, Version 1.1, ALv2 Future
// License (FSL-1.1-ALv2) — NOT Apache-2.0 like the rest of this repository.
// See ../../LICENSE-FSL, the copy in this directory, and LICENSING.md.
// This version converts to Apache-2.0 two years after it is made available.

// Command behalf-log operates the Week-2 Tessera-backed behalf log
// (architecture D1): a tiled transparency log on the POSIX driver, one
// appender per log dir, with receipt-id dedup (Q46), SCT-style receipt
// promises (D2 — a promise is not an inclusion proof), and the SQLite
// follower index — a derived, rebuildable projection of the log (Q55, Q56)
// that is never restored from backup, always rebuilt (Q76).
//
//	behalf-log init        --dir DIR [--origin ORIGIN]  create the log dir, checkpoint key, epoch file
//	behalf-log ingest      [--dir DIR] [--runs a,b]     append the Week-1 fixture runs into the one log
//	behalf-log drain       --spool DIR [--dir DIR]      move the MCP proxy's capture spool into the log (Q46, Q57)
//	behalf-log status      [--dir DIR]                  checkpoint contents, tree size, epoch
//	behalf-log witness     [--dir DIR]                  submit the published checkpoint to the configured witnesses (Q29, Q76, Q96)
//	behalf-log export      [--dir DIR] --run RUN --out F  write a Week-1 export-format-v1 file from the log
//	behalf-log reindex     [--dir DIR]                  wipe and rebuild the follower index from the entry bundles (Q76)
//	behalf-log follow      [--dir DIR]                  one incremental index catch-up pass to the published checkpoint
//	behalf-log runs        [--dir DIR]                  table of indexed runs with attribution rollups (Q82, Q86)
//	behalf-log reconstruct [--dir DIR] --run RUN [--after N]  stream a run as NDJSON in log-index order (Q82)
//	behalf-log rehydrate   [--dir DIR] --run RUN [--state DIR] [--after N]  the same stream with customer-held payloads joined back on (Q83, Q84)
//
// Every subcommand but init defaults --dir to $BEHALF_LOG_DIR, else
// <state dir>/log — the same resolution cmd/behalf uses, so one exported
// variable points the whole toolchain at one log.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/spool"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "init":
		err = cmdInit(args)
	case "ingest":
		err = cmdIngest(args)
	case "drain":
		err = cmdDrain(args)
	case "status":
		err = cmdStatus(args)
	case "witness":
		err = cmdWitness(args)
	case "export":
		err = cmdExport(args)
	case "import":
		err = cmdImport(os.Args[2:])
	case "reindex":
		err = cmdReindex(args)
	case "follow":
		err = cmdFollow(args)
	case "runs":
		err = cmdRuns(args)
	case "reconstruct":
		err = cmdReconstruct(args)
	case "rehydrate":
		err = cmdRehydrate(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "behalf-log:", err)
		// A detected, classified payload mutation exits 1 like any other
		// error here; the machine-readable `class=payload index=N` line has
		// already gone to stderr. The status vocabulary is the verifier's
		// (docs/export-format-v1.md §5): 1 is "found and classified", 2 is
		// "could not read it at all".
		os.Exit(1)
	}
}

// EnvLogDir names the log directory when --dir is not given. It is the
// variable cmd/behalf's read-only subcommands already read, so one exported
// value points the whole toolchain at one log — which is what makes the
// demo commands short enough to type on a call (ENG-25).
const EnvLogDir = "BEHALF_LOG_DIR"

// resolveDir picks the log directory: --dir, else $BEHALF_LOG_DIR, else
// <state dir>/log. Identical resolution to cmd/behalf's resolveLogDir, on
// purpose: `behalf why` and `behalf-log rehydrate` disagreeing about which
// log they mean would be a bug with no symptom until it produced two
// different answers about the same run.
//
// `init` does not use this. Creating a log is not a read of an existing
// one, and defaulting the destination of a directory-creating command to an
// environment variable is how you initialise something you meant to leave
// alone.
func resolveDir(explicit, cmd string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv(EnvLogDir); env != "" {
		return env, nil
	}
	state, err := identity.ResolveDir("")
	if err != nil {
		return "", fmt.Errorf("%s: %w", cmd, err)
	}
	dir := filepath.Join(state, "log")
	if _, err := os.Stat(dir); err != nil {
		return "", fmt.Errorf("%s: --dir is required (no $%s, and nothing at %s)", cmd, EnvLogDir, dir)
	}
	return dir, nil
}

// mustDir resolves *dir in place, so a subcommand keeps reading *dir
// afterwards and cannot accidentally use the unresolved flag.
func mustDir(dir *string, cmd string) error {
	d, err := resolveDir(*dir, cmd)
	if err != nil {
		return err
	}
	*dir = d
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: behalf-log <init|ingest|import|drain|status|witness|export|reindex|follow|runs|reconstruct|rehydrate> [flags]
  init        --dir DIR [--origin ORIGIN]
  ingest      [--dir DIR] [--runs run_9f2a,run_c71e]
  drain       --spool DIR [--dir DIR] [--state DIR]
  status      [--dir DIR]
  witness     [--dir DIR] [--json]
  import      [--dir DIR] [--origin ORIGIN] [--force] [--quiet] FILE...
  export      [--dir DIR] --run RUN_ID --out FILE
  reindex     [--dir DIR]
  follow      [--dir DIR]
  runs        [--dir DIR]
  reconstruct [--dir DIR] --run RUN_ID [--after LOG_INDEX]
  rehydrate   [--dir DIR] --run RUN_ID [--state DIR] [--cas DIR] [--after LOG_INDEX]

--dir defaults to $BEHALF_LOG_DIR, else <state dir>/log (init excepted).`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (required)")
	origin := fs.String("origin", "behalf.sh/log/demo", "checkpoint origin (the note key name)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *dir == "" {
		return fmt.Errorf("init: --dir is required")
	}
	if _, err := os.Stat(filepath.Join(*dir, "keys", "checkpoint.skey")); err == nil {
		return fmt.Errorf("init: %s already has a checkpoint key", *dir)
	}
	return initLog(*dir, *origin)
}

// initLog creates a log directory, generates its checkpoint key and publishes
// the empty-tree checkpoint. `init` is one caller; `import` is the other, which
// has to work on a machine that has never run `init` at all.
func initLog(dir, origin string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	key, err := tlog.GenerateCheckpointKey(origin)
	if err != nil {
		return err
	}
	if err := tlog.SaveCheckpointKey(dir, key); err != nil {
		return err
	}
	// Open once: claims the first epoch (writes the epoch file), creates
	// index.db, and publishes the empty-tree checkpoint.
	ctx := context.Background()
	l, err := tlog.Open(ctx, dir, key, tlog.Options{})
	if err != nil {
		return err
	}
	epoch := l.Epoch()
	if err := l.Close(ctx); err != nil {
		return err
	}
	fmt.Printf("initialized log at %s\n  origin  %s\n  key     %s (jkt)\n  epoch   %d (pid %d, started %s)\n",
		dir, key.Origin, key.JKT, epoch.Epoch, epoch.PID, epoch.StartedAt)
	return nil
}

func cmdIngest(args []string) error {
	fs := flag.NewFlagSet("ingest", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	runs := fs.String("runs", "run_9f2a,run_c71e", "comma-separated fixture run ids to ingest")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustDir(dir, "ingest"); err != nil {
		return err
	}

	var specs []fixture.Spec
	for _, name := range strings.Split(*runs, ",") {
		switch strings.TrimSpace(name) {
		case "run_9f2a":
			specs = append(specs, fixture.Run9F2A())
		case "run_c71e":
			specs = append(specs, fixture.RunC71E())
		case "":
		default:
			return fmt.Errorf("ingest: unknown fixture run %q (want run_9f2a and/or run_c71e)", name)
		}
	}
	if len(specs) == 0 {
		return fmt.Errorf("ingest: no runs selected")
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

	start := time.Now()
	for _, spec := range specs {
		res, err := fixture.Generate(spec)
		if err != nil {
			return fmt.Errorf("generate %s: %w", spec.RunID, err)
		}
		results, err := ingestRun(ctx, l, spec.RunID, res.Payloads)
		if err != nil {
			return err
		}
		dups := 0
		lo, hi := results[0].Index, results[0].Index
		for _, r := range results {
			if r.Duplicate {
				dups++
			}
			if r.Index < lo {
				lo = r.Index
			}
			if r.Index > hi {
				hi = r.Index
			}
		}
		fmt.Printf("ingested %s: %d receipts -> log indices %d..%d (%d duplicates)\n",
			spec.RunID, len(results), lo, hi, dups)
	}
	if err := l.Close(ctx); err != nil {
		return err
	}
	fmt.Printf("done in %v\n", time.Since(start).Round(time.Millisecond))
	return nil
}

// ingestRun appends every payload of one run, in order, pipelined: all
// entries are queued first (Tessera preserves the order of sequential
// queueing), then every durability ack is awaited.
func ingestRun(ctx context.Context, l *tlog.Log, runID string, payloads [][]byte) ([]*tlog.AppendResult, error) {
	emitter := testkeys.Emitter()
	jwkBytes := fmt.Sprintf(`{"kty":%q,"crv":%q,"x":%q}`, emitter.JWK.Kty, emitter.JWK.Crv, emitter.JWK.X)
	if err := l.RegisterKey(emitter.JKT, jwkBytes); err != nil {
		return nil, err
	}
	pendings := make([]*tlog.Pending, 0, len(payloads))
	for i, payload := range payloads {
		sig := dsse.Sign(emitter.Private, exportv1.PayloadTypeReceipt, payload)
		env := tlog.BuildEnvelope(exportv1.PayloadTypeReceipt, payload, emitter.JKT, sig)
		p, err := l.BeginAppend(ctx, env)
		if err != nil {
			return nil, fmt.Errorf("%s receipt %d: %w", runID, i, err)
		}
		pendings = append(pendings, p)
	}
	results := make([]*tlog.AppendResult, 0, len(pendings))
	for i, p := range pendings {
		r, err := p.Wait(ctx)
		if err != nil {
			return nil, fmt.Errorf("%s receipt %d: %w", runID, i, err)
		}
		results = append(results, r)
	}
	return results, nil
}

// cmdDrain moves the MCP proxy's capture spool into the log. The proxy
// never appends (one appender per log, Q57); this is the other half.
// Delivery is at-least-once and duplicates are safe: ingest dedups on
// receipt_id and flags the duplicate rather than reading it as tampering
// (Q46).
//
// Orphaned intents — a call the proxy spooled and never closed because the
// process died — are flushed first, as `orphan_intent` receipts carrying
// the spooled intent digest (Q4, Q5), so they drain in the same pass.
func cmdDrain(args []string) error {
	fs := flag.NewFlagSet("drain", flag.ExitOnError)
	spoolDir := fs.String("spool", "", "capture spool directory (required)")
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	state := fs.String("state", "", "behalf state directory holding the emitter key (default: the spool's parent)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *spoolDir == "" {
		return fmt.Errorf("drain: --spool is required")
	}
	if err := mustDir(dir, "drain"); err != nil {
		return err
	}
	stateDir := *state
	if stateDir == "" {
		// The proxy puts its spool at <state>/proxy-spool by default.
		stateDir = filepath.Dir(*spoolDir)
	}

	// Recovery mints, signs and spools the orphan receipts; it needs the
	// emitter key, which is why the drain wants a state dir at all.
	flushed, err := proxy.RecoverOrphans(proxy.Config{StateDir: stateDir, SpoolDir: *spoolDir})
	if err != nil {
		return fmt.Errorf("drain: recover orphaned intents: %w", err)
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

	// The export header must carry the emitter key that signed these
	// receipts, or a later `export` cannot verify its own leaves.
	if emitter, kerr := identity.LoadKey(identity.EmitterKeyPath(stateDir)); kerr == nil {
		jwk, merr := json.Marshal(emitter.JWK)
		if merr != nil {
			return merr
		}
		if err := l.RegisterKey(emitter.JKT, string(jwk)); err != nil {
			return err
		}
	}

	var appended, dups int
	stats, drainErr := spool.Drain(*spoolDir, func(c spool.Completion) error {
		res, err := l.Append(ctx, c.Envelope)
		if err != nil {
			return fmt.Errorf("append %s: %w", c.ReceiptID, err)
		}
		appended++
		if res.Duplicate {
			dups++
		}
		return nil
	})
	if drainErr != nil {
		return drainErr
	}
	if err := l.Close(ctx); err != nil {
		return err
	}
	fmt.Printf("drained %s -> %s: %d receipts appended (%d duplicates), %d orphaned intents flushed, %d segments read (%d consumed)\n",
		*spoolDir, *dir, appended, dups, flushed, stats.Segments, stats.Done)
	return nil
}

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustDir(dir, "status"); err != nil {
		return err
	}
	ctx := context.Background()
	cp, err := tlog.ParseLogCheckpoint(ctx, *dir)
	if err != nil {
		return err
	}
	epoch, err := tlog.ReadEpoch(*dir)
	if err != nil {
		return err
	}
	fmt.Printf("log %s\n", *dir)
	fmt.Printf("  origin     %s\n", cp.Origin)
	fmt.Printf("  tree size  %d\n", cp.Size)
	fmt.Printf("  root       %x\n", cp.Root)
	fmt.Printf("  epoch      %d (pid %d, started %s)\n", epoch.Epoch, epoch.PID, epoch.StartedAt)
	fmt.Printf("checkpoint:\n")
	for _, line := range strings.Split(strings.TrimRight(string(cp.Raw), "\n"), "\n") {
		fmt.Printf("  | %s\n", line)
	}
	return nil
}

func cmdExport(args []string) error {
	fs := flag.NewFlagSet("export", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	run := fs.String("run", "", "run id to export (required)")
	out := fs.String("out", "", "output file (required)")
	state := fs.String("state", "", "behalf state directory holding the CAS (default: $BEHALF_HOME or ~/.behalf)")
	casDir := fs.String("cas", "", "hop token store directory (default: <state>/blobs)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *run == "" || *out == "" {
		return fmt.Errorf("export: --run and --out are required")
	}
	if err := mustDir(dir, "export"); err != nil {
		return err
	}
	f, err := os.Create(*out)
	if err != nil {
		return err
	}
	defer f.Close()
	// The hop tokens live in the customer-held store, not in the log, so the
	// export can only carry them when this process can reach it (ENG-38). A
	// store that is not there is not an error: the export is still a valid
	// export, just one whose delegation chains cannot be re-verified offline.
	var opts []tlog.ExportOption
	if store, err := openStore(*state, *casDir); err == nil {
		opts = append(opts, tlog.WithHopTokens(store))
	}
	if err := tlog.ExportRun(context.Background(), *dir, *run, f, opts...); err != nil {
		os.Remove(*out)
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fi, err := os.Stat(*out)
	if err != nil {
		return err
	}
	fmt.Printf("exported %s -> %s (%d bytes)\n", *run, *out, fi.Size())
	return nil
}

func cmdReindex(args []string) error {
	fs := flag.NewFlagSet("reindex", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustDir(dir, "reindex"); err != nil {
		return err
	}
	start := time.Now()
	stats, err := tlog.Reindex(context.Background(), *dir)
	if err != nil {
		return err
	}
	fmt.Printf("reindexed %s: %d receipts (%d duplicates), log indices [0,%d), origin %s, in %v\n",
		*dir, stats.Indexed, stats.Duplicates, stats.To, stats.Origin, time.Since(start).Round(time.Millisecond))
	return nil
}

func cmdFollow(args []string) error {
	fs := flag.NewFlagSet("follow", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustDir(dir, "follow"); err != nil {
		return err
	}
	stats, err := index.Follow(context.Background(), *dir)
	if err != nil {
		return err
	}
	if stats.From == stats.To {
		fmt.Printf("followed %s: index already at tree size %d\n", *dir, stats.To)
		return nil
	}
	fmt.Printf("followed %s: indexed [%d,%d) — %d receipts (%d duplicates)\n",
		*dir, stats.From, stats.To, stats.Indexed, stats.Duplicates)
	return nil
}

func cmdRuns(args []string) error {
	fs := flag.NewFlagSet("runs", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if err := mustDir(dir, "runs"); err != nil {
		return err
	}
	db, err := index.Open(context.Background(), *dir)
	if err != nil {
		return err
	}
	defer db.Close()
	runs, err := index.ListRuns(db)
	if err != nil {
		return err
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintln(w, "RUN\tRECEIPTS\tFIRST\tLAST\tVERIFIED\tASSERTED\tBROKEN")
	for _, r := range runs {
		fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%d\t%d\t%d\n",
			r.RunID, r.Receipts, r.FirstCapturedAt, r.LastCapturedAt, r.Verified, r.Asserted, r.Broken)
	}
	return w.Flush()
}

func cmdReconstruct(args []string) error {
	fs := flag.NewFlagSet("reconstruct", flag.ExitOnError)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR, else <state>/log)")
	run := fs.String("run", "", "run id to reconstruct (required)")
	after := fs.Int64("after", -1, "pagination cursor: emit only receipts with log_index > this")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *run == "" {
		return fmt.Errorf("reconstruct: --run is required")
	}
	if err := mustDir(dir, "reconstruct"); err != nil {
		return err
	}
	db, err := index.Open(context.Background(), *dir)
	if err != nil {
		return err
	}
	defer db.Close()
	return index.Reconstruct(context.Background(), db, *dir, *run, *after, os.Stdout)
}
