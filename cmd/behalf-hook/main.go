// Command behalf-hook is the executable Claude Code runs on every hook event
// — behalf's demo companion capture surface, scoped to that one client
// (D4, Q44).
//
//	behalf-hook capture   [--state DIR] [--spool DIR] [--policy FILE] [--chain FILE]
//	behalf-hook install   [--settings PATH] [--state DIR] [--print] [--uninstall]
//	behalf-hook uninstall [--settings PATH]
//	behalf-hook recover   [--state DIR] [--session ID] [--older-than 1h]
//
// `capture` reads ONE hook payload on stdin, writes a signed receipt to the
// spool, and exits. It is also what a bare `behalf-hook` with no subcommand
// does, so a hand-written settings entry naming only the binary still works.
//
// The spool is moved into the log by the shipped drain, unchanged:
//
//	behalf-log drain --spool ~/.behalf/hook-spool --dir LOGDIR --state ~/.behalf
//
// # Exit 0, always, on the capture path
//
// This differs from behalf-proxy deliberately, and the difference is the whole
// posture of the surface.
//
// The proxy aborts when it cannot record: it sits between a client and a
// server, it has the forwarded request in its hands, and a recorder that
// cannot record must not let the call through unrecorded (Q45). Failing closed
// there costs one tool call.
//
// A hook is not in that position. Claude Code reads this process's exit
// status: a non-zero exit is an error surfaced to the user, and exit 2 blocks
// the tool outright. Failing closed here does not protect a crossing — the
// crossing happens anyway or does not happen at all — it breaks the user's
// editor session because a spool write failed. behalf is a recorder, not a
// runtime (Q47), and a recorder that takes the editor down with it will be
// uninstalled by lunchtime, which records nothing at all.
//
// So every capture failure exits 0 and says what happened on stderr. The loss
// is not silent: it is silence in the log plus a hole in the per-emitter
// counter sequence, which is precisely what Q48 stamps the counter for. That
// is a worse guarantee than the proxy's and it is the honest one for this
// surface.
//
// The other subcommands are not on the agent's hot path and exit non-zero on
// failure like any ordinary tool.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/behalf-sh/behalf/internal/hooks"
	"github.com/behalf-sh/behalf/internal/identity"
)

func main() {
	args := os.Args[1:]
	cmd := "capture"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		cmd, args = args[0], args[1:]
	}
	switch cmd {
	case "capture":
		// Never non-zero: see the package doc.
		os.Exit(runCapture(args, os.Stdin, os.Stdout, os.Stderr))
	case "install":
		fail(runInstall(args, os.Stdout))
	case "uninstall":
		fail(runUninstall(args, os.Stdout))
	case "recover":
		fail(runRecover(args, os.Stdout))
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		usage(os.Stderr)
		os.Exit(2)
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, `usage: behalf-hook <capture|install|uninstall|recover> [flags]
  capture   [--state DIR] [--spool DIR] [--policy FILE] [--chain FILE]
            read one Claude Code hook payload on stdin and spool a receipt.
            Always exits 0: a capture failure must never break the session.
  install   [--settings PATH] [--state DIR] [--policy FILE] [--chain FILE] [--print] [--uninstall]
            merge behalf's hook entries into a Claude Code settings file,
            preserving every other hook and key. Idempotent.
  uninstall [--settings PATH]
            remove behalf's hook entries and nothing else.
  recover   [--state DIR] [--session ID] [--older-than DURATION]
            flush pending intents nothing closed as orphan_intent receipts.`)
}

func fail(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "behalf-hook:", err)
	os.Exit(1)
}

// runCapture returns the process exit status, which is 0 in every case.
func runCapture(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("capture", flag.ContinueOnError)
	fs.SetOutput(stderr)
	state := fs.String("state", "", "behalf state directory (default $BEHALF_HOME, else ~/.behalf)")
	spoolDir := fs.String("spool", "", "capture spool directory (default <state>/hook-spool)")
	policy := fs.String("policy", "", "tool-policy JSON assigning risk_class (default: built-in policy)")
	chain := fs.String("chain", "", "delegation chain material (default: none, receipts are asserted)")
	verbose := fs.Bool("v", false, "report what was captured on stderr")
	// Written by `install` so `--uninstall` can find exactly our entries.
	// Accepted and ignored here.
	fs.String("installed-by", "", "marker written by `behalf-hook install`; ignored")
	if err := fs.Parse(args); err != nil {
		return swallow(stderr, err)
	}

	raw, err := io.ReadAll(stdin)
	if err != nil {
		return swallow(stderr, fmt.Errorf("read hook payload: %w", err))
	}
	dir, err := identity.ResolveDir(*state)
	if err != nil {
		return swallow(stderr, err)
	}
	c, err := hooks.Open(hooks.Config{
		StateDir:   dir,
		SpoolDir:   *spoolDir,
		PolicyPath: *policy,
		ChainPath:  *chain,
	})
	if err != nil {
		return swallow(stderr, err)
	}
	res, err := c.Handle(raw)
	switch {
	case errors.Is(err, hooks.ErrUnhandledEvent):
		// Not a failure: Claude Code may send events this surface does not
		// receipt, and inventing a record for one would be worse than silence.
		if *verbose {
			fmt.Fprintln(stderr, "behalf-hook:", err)
		}
		return 0
	case err != nil:
		return swallow(stderr, err)
	}
	if *verbose {
		report(stderr, res)
	}
	return 0
}

// swallow is the capture path's failure mode: say what went wrong, then get
// out of the agent's way.
func swallow(stderr io.Writer, err error) int {
	fmt.Fprintln(stderr, "behalf-hook: capture failed, continuing anyway:", err)
	fmt.Fprintln(stderr, "behalf-hook: this crossing has no receipt; the gap is visible in the emitter counter sequence")
	return 0
}

func report(w io.Writer, res *hooks.Result) {
	switch {
	case res == nil:
	case res.Pending:
		fmt.Fprintf(w, "behalf-hook: %s: intent recorded (counter %d)\n", res.Event, res.Counter)
	case res.Kind != "":
		fmt.Fprintf(w, "behalf-hook: %s: %s receipt %s (counter %d)\n", res.Event, res.Kind, res.ReceiptID, res.Counter)
	}
	if res != nil && len(res.Orphans) > 0 {
		fmt.Fprintf(w, "behalf-hook: flushed %d orphaned intent(s)\n", len(res.Orphans))
	}
	if res != nil && res.Note != "" {
		fmt.Fprintln(w, "behalf-hook:", res.Note)
	}
}

func runInstall(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("install", flag.ExitOnError)
	settings := fs.String("settings", "", "Claude Code settings file (default ~/.claude/settings.json)")
	state := fs.String("state", "", "behalf state directory to record into (default $BEHALF_HOME, else ~/.behalf)")
	policy := fs.String("policy", "", "tool-policy JSON to pass to the capture command")
	chain := fs.String("chain", "", "delegation chain material to pass to the capture command")
	binary := fs.String("binary", "", "path to behalf-hook written into the settings file (default: this executable)")
	print := fs.Bool("print", false, "print the JSON snippet instead of editing any file")
	uninstall := fs.Bool("uninstall", false, "remove behalf's hook entries instead of adding them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *uninstall {
		return uninstallTo(*settings, stdout)
	}
	dir, err := identity.ResolveDir(*state)
	if err != nil {
		return err
	}
	bin := *binary
	if bin == "" {
		if bin, err = os.Executable(); err != nil {
			return fmt.Errorf("resolve this executable: %w", err)
		}
	}
	opts := hooks.InstallOptions{Binary: bin, StateDir: dir, PolicyPath: *policy, ChainPath: *chain}
	if *print {
		snippet, err := hooks.Snippet(opts)
		if err != nil {
			return err
		}
		_, err = stdout.Write(snippet)
		return err
	}
	res, err := hooks.Install(*settings, opts)
	if err != nil {
		return err
	}
	verb := "updated"
	if res.Created {
		verb = "created"
	}
	fmt.Fprintf(stdout, "%s %s\n  command  %s\n  added    %s\n  updated  %s\n  left alone %d hook entries belonging to something else\n",
		verb, res.Path, opts.Command(), list(res.Added), list(res.Updated), res.Kept)
	fmt.Fprintln(stdout, "  note     this file is user-scoped: whoever is being recorded can delete these entries (Q74)")
	return nil
}

func runUninstall(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("uninstall", flag.ExitOnError)
	settings := fs.String("settings", "", "Claude Code settings file (default ~/.claude/settings.json)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return uninstallTo(*settings, stdout)
}

func uninstallTo(settings string, stdout io.Writer) error {
	res, err := hooks.Uninstall(settings)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "updated %s\n  removed  %s\n  left alone %d hook entries belonging to something else\n",
		res.Path, list(res.Removed), res.Kept)
	return nil
}

func runRecover(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("recover", flag.ExitOnError)
	state := fs.String("state", "", "behalf state directory (default $BEHALF_HOME, else ~/.behalf)")
	session := fs.String("session", "", "limit the sweep to one Claude Code session id")
	olderThan := fs.Duration("older-than", time.Hour,
		"skip intents younger than this, so a sweep beside a live session does not steal calls in flight")
	if err := fs.Parse(args); err != nil {
		return err
	}
	dir, err := identity.ResolveDir(*state)
	if err != nil {
		return err
	}
	c, err := hooks.Open(hooks.Config{StateDir: dir})
	if err != nil {
		return err
	}
	ids, err := c.Recover(*session, *olderThan)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "flushed %d orphaned intent(s) as orphan_intent receipts\n", len(ids))
	for _, id := range ids {
		fmt.Fprintln(stdout, " ", id)
	}
	return nil
}

func list(v []string) string {
	if len(v) == 0 {
		return "(none)"
	}
	return strings.Join(v, ", ")
}
