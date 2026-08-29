// Command behalf-record produces the demo session pair (ENG-14, D9.2,
// Q92): two support-desk refund runs, 47 tool calls each, driven through
// the real MCP proxy against an in-repo fake MCP server, spooled, drained
// and appended to a real Tessera log.
//
// The point is provenance. The demo artifact must come out of shipped code
// paths — the proxy that customers run, the spool that customers' calls go
// through, the CAS that holds customers' payloads, the log that customers
// verify — because a hand-authored recording proves only that someone can
// author JSON. Every receipt this command produces was signed by the same
// capture surface, over the same bytes, by the same code as a live session.
//
// # The scenario
//
// Two runs of one 47-step script (scenario.go). They are identical except
// that the desk's search index, at step 12, returns the same two refundable
// orders in a different order. The agent takes results[0] in both runs, so
// at step 31 the refund it issues is for a different order and a different
// amount:
//
//	run A   step 12: ord_5512 first   step 31: refund.issue 12.00   / ord_5512
//	run B   step 12: ord_5518 first   step 31: refund.issue 1200.00 / ord_5518
//
// Both runs land in ONE log with distinct run ids, their payloads in one
// CAS, so `behalf diff` has two runs to align and `behalf why` has one
// receipt to explain.
//
// # The delegation chain, and the second divergence
//
// Before either run, the recorder performs a real headless `behalf login`
// against the in-repo fake OIDC provider and mints a three-hop AAT chain
// from what it produced (chain.go). The runs carry two variants of it: run
// A's three hops are all signed and all verify; run B's leaf hop arrives
// caller-asserted with no signature. That difference is cryptographic, not
// typed: the proxy verifies both chains at capture and records what it
// found, so `behalf why` reports "chain intact for 3 of 3 hops" on one run
// and "2 of 3" on the other, from recorded data.
//
// # Determinism
//
// Recordings ship and are re-verified in CI, so two invocations with the
// same flags must produce byte-identical receipts. Seven things are pinned:
// the clock, the ULID entropy, the emitter key, the device key, the fake
// IdP's signing key and clock, the run ids, and a server whose answers are a
// pure function of its questions (see internal/proxy/deterministic.go).
// --live opts out of the clocks and the entropy for a genuinely live
// capture.
//
// What comes out byte-identical, verified by TestDeterministicRecording:
// the DSSE-signed receipt envelopes, the CAS blobs they commit to, and the
// log directory itself — entry bundles, tiles and the signed checkpoint,
// since --seed derives the checkpoint key and Ed25519 signing is
// deterministic.
//
// Two files are excluded, both deliberately: index.db, which is a derived,
// rebuildable projection that is never restored and always rebuilt (Q55,
// Q76), and epoch.json, which records this process's pid and start time.
// Neither is evidence. The spool's segment file names are wall-clock
// derived too, and the spool is consumed and marked done by the drain.
//
// # Usage
//
//	behalf-record --dir LOGDIR --out STATEDIR [flags]
//
//	--dir DIR         the Tessera log directory; initialized if it has no
//	                  checkpoint key yet. Required.
//	--out DIR         the behalf state directory: emitter and device keys,
//	                  CAS (blobs/), capture spool, login material, and the
//	                  generated policy and chain files. Required.
//	--run-a ID        run id for the $12.00 run      (default rec_9f2a)
//	--run-b ID        run id for the $1200.00 run    (default rec_c71e)
//	--start TIME      RFC3339 base for run A's fixed clock
//	                                                 (default 2026-08-26T09:00:00Z)
//	--gap DUR         how much later run B starts    (default 5h30m)
//	--tick DUR        fixed-clock advance per read; the proxy reads the
//	                  clock twice per tool call, so receipts land 2×tick
//	                  apart                          (default 2s)
//	--origin STR      checkpoint origin              (default behalf.sh/log/demo)
//	--seed STR        determinism seed for the ULID entropy and, unless
//	                  --live, the log's checkpoint key
//	                                                 (default behalf.sh/record/v1)
//	--live            use the real clock and crypto/rand entropy, and a
//	                  freshly generated checkpoint key: a real recording,
//	                  not a reproducible one
//	--quiet           suppress the progress lines
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/mod/sumdb/note"

	"github.com/behalf-sh/behalf/internal/deskmcp"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/spool"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// EnvServeDesk makes this binary act as the MCP server instead of the
// recorder. The recorder spawns itself with it set, so the whole demo is
// one binary with no build step in between and no path to a sibling
// executable to get wrong.
const EnvServeDesk = "BEHALF_RECORD_SERVE_DESK"

func main() {
	// The far side of the proxy: this same binary, re-exec'd.
	if os.Getenv(EnvServeDesk) == "1" {
		v := deskmcp.Variant(os.Getenv(deskmcp.EnvVariant))
		if err := deskmcp.Serve(v, os.Stdin, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "behalf-record: desk server:", err)
			os.Exit(1)
		}
		return
	}
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "behalf-record:", err)
		os.Exit(1)
	}
}

// Options is everything a recording needs. It is a struct rather than a
// flag soup so the end-to-end test drives the same entry point the CLI
// does — a recorder tested through a different door is not the recorder.
type Options struct {
	LogDir   string
	StateDir string
	RunA     string
	RunB     string
	Start    time.Time
	Gap      time.Duration
	Tick     time.Duration
	Origin   string
	Seed     string
	Live     bool
	Quiet    bool
}

// Defaults returns the shipped recording's parameters.
func Defaults() Options {
	return Options{
		RunA:   "rec_9f2a",
		RunB:   "rec_c71e",
		Start:  time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC),
		Gap:    5*time.Hour + 30*time.Minute,
		Tick:   2 * time.Second,
		Origin: "behalf.sh/log/demo",
		Seed:   "behalf.sh/record/v1",
	}
}

func run(args []string, stdout io.Writer) error {
	def := Defaults()
	fs := flag.NewFlagSet("behalf-record", flag.ExitOnError)
	opts := Options{}
	fs.StringVar(&opts.LogDir, "dir", "", "log directory (required)")
	fs.StringVar(&opts.StateDir, "out", "", "state directory holding the emitter key, CAS and spool (required)")
	fs.StringVar(&opts.RunA, "run-a", def.RunA, "run id for the $12.00 run")
	fs.StringVar(&opts.RunB, "run-b", def.RunB, "run id for the $1200.00 run")
	start := fs.String("start", def.Start.Format(time.RFC3339), "RFC3339 base for run A's fixed clock")
	fs.DurationVar(&opts.Gap, "gap", def.Gap, "how much later run B starts")
	fs.DurationVar(&opts.Tick, "tick", def.Tick, "fixed-clock advance per read")
	fs.StringVar(&opts.Origin, "origin", def.Origin, "checkpoint origin")
	fs.StringVar(&opts.Seed, "seed", def.Seed, "determinism seed")
	fs.BoolVar(&opts.Live, "live", false, "record live: real clock, real entropy, fresh checkpoint key")
	fs.BoolVar(&opts.Quiet, "quiet", false, "suppress progress output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	t, err := time.Parse(time.RFC3339, *start)
	if err != nil {
		return fmt.Errorf("--start: %w", err)
	}
	opts.Start = t
	if opts.Quiet {
		stdout = io.Discard
	}
	return Record(opts, stdout)
}

// Record performs the whole recording: prepare the state directory, open
// (or initialize) the log, drive both runs through the proxy, drain each
// into the log, and bring the follower index up to the published
// checkpoint.
func Record(opts Options, out io.Writer) error {
	if opts.LogDir == "" || opts.StateDir == "" {
		return errors.New("--dir and --out are both required")
	}
	if opts.RunA == opts.RunB {
		return fmt.Errorf("--run-a and --run-b must differ (both are %q); the demo needs two runs in one log", opts.RunA)
	}
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate this binary to spawn the desk server: %w", err)
	}
	st, err := prepareState(opts)
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "login %s: device key %s bound by %s (headless, in-repo fake IdP)\n",
		st.login.SubDigest[:12], st.login.DeviceJKT, st.login.Issuer)
	key, err := checkpointKey(opts)
	if err != nil {
		return err
	}

	ctx := context.Background()
	for _, r := range []struct {
		id      string
		variant deskmcp.Variant
		start   time.Time
		chain   string
	}{
		{opts.RunA, deskmcp.VariantA, opts.Start, st.chainA},
		{opts.RunB, deskmcp.VariantB, opts.Start.Add(opts.Gap), st.chainB},
	} {
		cfg := proxy.Config{
			StateDir:   opts.StateDir,
			PolicyPath: st.policy,
			ChainPath:  r.chain,
			Command:    []string{self},
			Env: []string{
				EnvServeDesk + "=1",
				deskmcp.EnvVariant + "=" + string(r.variant),
			},
			Getenv: func(k string) string {
				if k == proxy.EnvRunID {
					return r.id
				}
				return ""
			},
		}
		if !opts.Live {
			cfg.Now = proxy.FixedClock(r.start, opts.Tick)
			cfg.Entropy = proxy.FixedEntropy(opts.Seed + "/" + r.id)
		}
		if err := drive(cfg); err != nil {
			return fmt.Errorf("record %s: %w", r.id, err)
		}
		appended, dups, err := drain(ctx, opts, key)
		if err != nil {
			return fmt.Errorf("drain %s: %w", r.id, err)
		}
		fmt.Fprintf(out, "recorded %s (variant %s): %d receipts appended (%d duplicates)\n",
			r.id, r.variant, appended, dups)
	}

	// The append path writes index rows as it goes; this settles the
	// follower's own watermark so `rehydrate`, `runs` and `why` see a
	// complete projection of the published checkpoint (Q55, Q56).
	stats, err := index.Follow(ctx, opts.LogDir)
	if err != nil {
		return fmt.Errorf("follow the index: %w", err)
	}
	fmt.Fprintf(out, "log %s: indexed to tree size %d\n", opts.LogDir, stats.To)
	fmt.Fprintf(out, "payloads %s: the customer's own store — rehydrate with\n"+
		"  behalf-log rehydrate --dir %s --run %s --state %s\n",
		identity.BlobsDir(opts.StateDir), opts.LogDir, opts.RunB, opts.StateDir)
	return nil
}

// state is what prepareState laid down for the runs to use.
type state struct {
	policy string // the capture-time tool-policy file
	chainA string // run A's chain material: three signed hops
	chainB string // run B's: the same claims, leaf hop unsigned
	login  *oidclogin.Result
}

// prepareState prepares the state directory: the emitter key, the
// capture-time tool policy, a real headless login, and the two chain
// variants minted from what that login produced.
//
// The emitter key is the frozen demo key from internal/testkeys, not a
// freshly generated one, because a recording signed by a random key is not
// reproducible and cannot be verified by a checked-in JWKS. That is a
// property of demo artifacts, not of the product: a live install generates
// its own emitter key on first use (identity.LoadOrGenerateEmitter), and
// --live recordings still use this one, because the key is what makes the
// artifact verifiable by anyone. The demo device key is pinned for the same
// reason (see login).
//
// The login's own root receipt lands in `behalf login`'s spool
// (<state>/spool.jsonl), which is where a real login puts it and which this
// recorder does not drain: the demo log holds the two runs, and the drain
// moves the proxy's spool only. What the runs consume from the login is its
// evidence — the device key, the customer-held blobs and login.json.
func prepareState(opts Options) (*state, error) {
	if err := identity.EnsureDir(opts.StateDir); err != nil {
		return nil, err
	}
	emitter := testkeys.Emitter()
	key := &identity.Key{Private: emitter.Private, Public: emitter.Public, JWK: emitter.JWK, JKT: emitter.JKT}
	if err := identity.SaveKey(key, identity.EmitterKeyPath(opts.StateDir)); err != nil {
		return nil, fmt.Errorf("write the demo emitter key: %w", err)
	}

	st := &state{policy: filepath.Join(opts.StateDir, "demo-tool-policy.json")}
	if err := os.WriteFile(st.policy, []byte(DemoPolicyJSON), 0o600); err != nil {
		return nil, err
	}

	res, loginAt, err := login(opts)
	if err != nil {
		return nil, err
	}
	st.login = res

	rawA, rawB, err := chainVariants(res, loginAt)
	if err != nil {
		return nil, err
	}
	st.chainA = filepath.Join(opts.StateDir, "demo-chain-a.json")
	if err := os.WriteFile(st.chainA, rawA, 0o600); err != nil {
		return nil, err
	}
	st.chainB = filepath.Join(opts.StateDir, "demo-chain-b.json")
	if err := os.WriteFile(st.chainB, rawB, 0o600); err != nil {
		return nil, err
	}
	return st, nil
}

// checkpointKey loads the log's checkpoint key, creating the log directory
// and the key on first use.
//
// Outside --live the key is derived from --seed, so a re-recording produces
// the same checkpoint signatures over the same tree and the log directory
// itself is comparable byte for byte. Ed25519 signing is deterministic, so
// nothing else has to be pinned for that to hold.
func checkpointKey(opts Options) (*tlog.CheckpointKey, error) {
	if k, err := tlog.LoadCheckpointKey(opts.LogDir); err == nil {
		return k, nil
	}
	if err := os.MkdirAll(opts.LogDir, 0o755); err != nil {
		return nil, err
	}
	if opts.Live {
		k, err := tlog.GenerateCheckpointKey(opts.Origin)
		if err != nil {
			return nil, err
		}
		return k, tlog.SaveCheckpointKey(opts.LogDir, k)
	}
	skey, _, err := note.GenerateKey(proxy.FixedEntropy(opts.Seed+"/checkpoint"), opts.Origin)
	if err != nil {
		return nil, fmt.Errorf("derive the checkpoint key: %w", err)
	}
	k, err := tlog.ParseCheckpointKey(skey)
	if err != nil {
		return nil, err
	}
	return k, tlog.SaveCheckpointKey(opts.LogDir, k)
}

// drive runs one session: spawn the proxy over a pair of pipes, walk the
// script, then close the client's side so the proxy tears the server down
// and returns.
func drive(cfg proxy.Config) error {
	toProxy := newPipe()   // the agent writes requests; the proxy reads them
	fromProxy := newPipe() // the proxy writes responses; the agent reads them

	done := make(chan error, 1)
	go func() {
		err := proxy.Run(cfg, toProxy.r, fromProxy.w, os.Stderr)
		// Closing the proxy's output unblocks an agent still waiting on a
		// response, so a proxy failure surfaces as that failure rather than
		// as a hang.
		fromProxy.w.Close()
		done <- err
	}()

	a := &agent{out: toProxy.w, in: bufio.NewReader(fromProxy.r)}
	scriptErr := a.run(script())
	toProxy.w.Close()

	proxyErr := <-done
	if proxyErr != nil {
		return fmt.Errorf("proxy: %w", proxyErr)
	}
	return scriptErr
}

// pipe is an os.Pipe pair. An os.Pipe rather than an io.Pipe because the
// proxy hands its reader to a child process's stdin path and reads with a
// bufio.Reader that must see a real EOF when the writer closes.
type pipe struct {
	r *os.File
	w *os.File
}

func newPipe() *pipe {
	r, w, err := os.Pipe()
	if err != nil {
		panic(fmt.Sprintf("behalf-record: pipe: %v", err))
	}
	return &pipe{r: r, w: w}
}

// drainOptions tunes the appender for a bulk offline drain.
//
// The production defaults are a 250 ms batch max age and a 1 s checkpoint
// interval (Q30/D3.3), chosen for a live agent whose call is blocked on the
// durability ack. A recorder draining 94 already-captured receipts one at a
// time would wait out that batch age 94 times — half a minute of sleeping
// for a run that produces the same bytes either way. Nothing in a receipt
// depends on the batching: the entry bundles, tiles and checkpoint are
// functions of the entries and the tree, not of how long the appender
// waited before flushing. The recording is identical; it just finishes.
//
// This is the tunability the measurement run recorded (docs/
// measurement-run-2026-08-27.md: ack latency is dominated by the batch age,
// not fsync), used here for the case it was noted for.
// The checkpoint interval is Tessera's own floor: it refuses anything
// below 100 ms.
var drainOptions = tlog.Options{
	BatchMaxAge:        5 * time.Millisecond,
	CheckpointInterval: 100 * time.Millisecond,
}

// drain moves the capture spool into the log — the same two library calls
// `behalf-log drain` makes, because the proxy never appends (one appender
// per log, Q57) and delivery is at-least-once, deduped on receipt_id (Q46).
func drain(ctx context.Context, opts Options, key *tlog.CheckpointKey) (appended, dups int, err error) {
	l, err := tlog.Open(ctx, opts.LogDir, key, drainOptions)
	if err != nil {
		return 0, 0, err
	}
	defer l.Close(ctx)

	// The export header must carry the key that signed these receipts, or a
	// later `behalf-log export` cannot verify its own leaves.
	emitter, err := identity.LoadKey(identity.EmitterKeyPath(opts.StateDir))
	if err != nil {
		return 0, 0, err
	}
	jwk, err := json.Marshal(emitter.JWK)
	if err != nil {
		return 0, 0, err
	}
	if err := l.RegisterKey(emitter.JKT, string(jwk)); err != nil {
		return 0, 0, err
	}

	spoolDir := filepath.Join(opts.StateDir, proxy.DefaultSpoolDirName)
	if _, err := spool.Drain(spoolDir, func(c spool.Completion) error {
		res, aerr := l.Append(ctx, c.Envelope)
		if aerr != nil {
			return fmt.Errorf("append %s: %w", c.ReceiptID, aerr)
		}
		appended++
		if res.Duplicate {
			dups++
		}
		return nil
	}); err != nil {
		return appended, dups, err
	}
	return appended, dups, l.Close(ctx)
}
