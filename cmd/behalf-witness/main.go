// Licensed under the Functional Source License, Version 1.1, ALv2 Future
// License (FSL-1.1-ALv2) — NOT Apache-2.0 like the rest of this repository.
// See ../../LICENSE-FSL, the copy in this directory, and LICENSING.md.
// This version converts to Apache-2.0 two years after it is made available.

// Command behalf-witness is behalf's independent witness (architecture
// D3.5): the party that holds tree heads the log operator cannot
// retroactively change, run in a separate cloud account from the log.
//
//	behalf-witness init  --key PATH [--name NAME]
//	                     generate the witness signing key; print its vkey
//	behalf-witness serve --state DIR --key PATH --logs FILE [--addr HOST:PORT]
//	                     serve the C2SP tlog-witness add-checkpoint endpoint
//	behalf-witness show  --state DIR [--json]
//	                     print the tree heads this witness currently holds
//
// The surface is three commands on purpose. The witness is the one
// component that must never be hard to operate: a single small VM, one key
// file, one state file, one endpoint.
//
// # What it refuses, and why that is the product
//
// For each log origin the witness holds the highest (size, root) it has
// cosigned, durably. A submission is accepted only if it is consistent with
// that head, and refused otherwise with one of three reasons:
//
//	smaller-size               the log offered an older tree than the one
//	                           already witnessed — restore-as-truncation
//	                           (Q76)
//	same-size-different-root   two histories at the same size — a split
//	                           view (Q29)
//	inconsistent-proof         a larger tree that does not carry the held
//	                           root forward
//
// A refusal is not an error condition to be retried away. It is evidence.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/behalf-sh/behalf/internal/flock"
	"github.com/behalf-sh/behalf/internal/witness"
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
	case "serve":
		err = cmdServe(args)
	case "show":
		err = cmdShow(args)
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "behalf-witness:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage: behalf-witness <init|serve|show> [flags]
  init  --key PATH [--name NAME]
  serve --state DIR --key PATH --logs FILE [--addr HOST:PORT]
  show  --state DIR [--json]`)
}

func cmdInit(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	key := fs.String("key", "", "path to write the witness signing key to (required)")
	name := fs.String("name", witness.DefaultKeyName, "note key name; appears in every cosignature line")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *key == "" {
		return errors.New("init: --key is required")
	}
	if _, err := os.Stat(*key); err == nil {
		return fmt.Errorf("init: %s already exists; refusing to overwrite a witness key", *key)
	}
	k, err := witness.GenerateKey(*name)
	if err != nil {
		return err
	}
	if err := witness.SaveKey(*key, k); err != nil {
		return err
	}
	fmt.Printf("witness key written\n  private  %s (0600 — never in a backup, Q76)\n  public   %s\n  vkey     %s\n",
		*key, witness.VKeyPath(*key), k.VKey)
	fmt.Printf("\nGive that vkey to every log this witness should cosign for:\n")
	fmt.Printf("  %s\n", exampleWitnessConfig(k.VKey))
	return nil
}

func exampleWitnessConfig(vkey string) string {
	b, _ := json.Marshal(map[string]any{
		"fail_open":  true,
		"timeout_ms": 1000,
		"witnesses":  []map[string]string{{"name": "witness-1", "vkey": vkey, "url": "http://127.0.0.1:7777"}},
	})
	return string(b) + "   -> <log dir>/witnesses.json"
}

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	state := fs.String("state", "", "witness state directory (required)")
	key := fs.String("key", "", "witness signing key path (required)")
	logs := fs.String("logs", "", "file of trusted log checkpoint vkeys, one per line (required)")
	addr := fs.String("addr", "127.0.0.1:7777", "listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *state == "" || *key == "" || *logs == "" {
		return errors.New("serve: --state, --key and --logs are required")
	}

	k, err := witness.LoadKey(*key)
	if err != nil {
		return err
	}
	vkeys, err := readVKeys(*logs)
	if err != nil {
		return err
	}
	store, err := witness.OpenStore(*state)
	if err != nil {
		return err
	}
	w, err := witness.New(k, store, vkeys)
	if err != nil {
		return err
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	srv := &http.Server{
		Handler:           witness.NewServer(w, logger).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("serve: listen: %w", err)
	}

	// One writer per state dir: a second witness process sharing this state
	// would have two views of the same head and could cosign a fork between
	// them. Held for the life of the process.
	lockPath := filepath.Join(*state, witness.LockFileName)
	lf, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("serve: open %s: %w", lockPath, err)
	}
	defer lf.Close()
	lock, err := flock.TryLock(lf)
	if err != nil {
		return fmt.Errorf("serve: lock %s: %w", lockPath, err)
	}
	if lock == nil {
		return fmt.Errorf("serve: another witness process is already serving state %s", *state)
	}
	defer lock.Release()

	fmt.Printf("witness %s serving on http://%s%s\n", k.Name, ln.Addr(), witness.AddCheckpointPath)
	fmt.Printf("  state    %s\n", store.Dir())
	fmt.Printf("  vkey     %s\n", k.VKey)
	for _, origin := range w.Origins() {
		held, ok := w.Held(origin)
		if ok {
			fmt.Printf("  log      %s (holding size %d, root %s)\n", origin, held.Size, held.RootHex())
		} else {
			fmt.Printf("  log      %s (nothing held yet)\n", origin)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ln) }()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return srv.Shutdown(shutdownCtx)
	}
}

func cmdShow(args []string) error {
	fs := flag.NewFlagSet("show", flag.ExitOnError)
	state := fs.String("state", "", "witness state directory (required)")
	asJSON := fs.Bool("json", false, "emit the held heads as JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *state == "" {
		return errors.New("show: --state is required")
	}
	store, err := witness.OpenStore(*state)
	if err != nil {
		return err
	}
	entries := store.List()
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)
	}
	if len(entries) == 0 {
		fmt.Printf("witness %s holds nothing yet\n", *state)
		return nil
	}
	fmt.Printf("witness state %s\n", store.Dir())
	w := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ORIGIN\tSIZE\tROOT\tCOSIGNATURES\tLAST COSIGNED")
	for _, e := range entries {
		fmt.Fprintf(w, "%s\t%d\t%s\t%d\t%s\n", e.Origin, e.Size, e.Root, e.Cosignatures, e.CosignedAt)
	}
	return w.Flush()
}

// readVKeys reads trusted log checkpoint verifier keys, one per line;
// blank lines and `#` comments are ignored.
func readVKeys(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read log keys: %w", err)
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s carries no log verifier keys", path)
	}
	return out, nil
}
