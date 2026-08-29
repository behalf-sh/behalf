// Command behalf is the product CLI.
//
//	behalf login  --issuer URL --client-id ID [--no-browser] [--dir DIR]
//	behalf whoami [--dir DIR]
//	behalf why    <run>:<step> [--dir LOGDIR]
//	behalf runs   [--dir LOGDIR]
//	behalf diff   <runA> <runB> [--dir LOGDIR] [--all]
//	behalf export --run ID [--run ID2] --html FILE [--dir LOGDIR] [--state DIR]
//
// login runs the OIDC PKCE flow that mints the verified identity root (D5):
// a fresh device Ed25519 key whose RFC 7638 thumbprint rides the OIDC nonce
// into the IdP-signed ID token. whoami re-runs the three-check root
// predicate offline and prints the result.
//
// why reads one receipt out of the log and renders the delegation chain
// behind it, hop by hop, in the three verification states (Q12); runs lists
// the indexed runs with their attribution rollups (Q82, Q86); diff aligns
// two runs and names the first step that diverged (Q85); export writes the
// same evidence as one self-contained HTML file, which is what actually
// gets attached to a ticket. All four are read-only over the log dir.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/diff"
	"github.com/behalf-sh/behalf/internal/htmlexport"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/why"
)

// EnvLogDir names the log directory `why` and `runs` read.
const EnvLogDir = "BEHALF_LOG_DIR"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "login":
		return runLogin(ctx, args[1:], stdout, stderr)
	case "whoami":
		return runWhoami(args[1:], stdout, stderr)
	case "why":
		return runWhy(ctx, args[1:], stdout, stderr)
	case "runs":
		return runRuns(ctx, args[1:], stdout, stderr)
	case "diff":
		return runDiff(ctx, args[1:], stdout, stderr)
	case "export":
		return runExport(ctx, args[1:], stdout, stderr)
	case "demo":
		return runDemo(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "behalf: unknown command %q\n\n", args[0])
		usage(stderr)
		return 2
	}
}

func usage(w io.Writer) {
	fmt.Fprint(w, `behalf — verifiable receipts for agent actions

Usage:
  behalf login  --issuer URL --client-id ID [--no-browser] [--dir DIR]
  behalf whoami [--dir DIR]
  behalf why    <run>:<step> [--dir LOGDIR]
  behalf runs   [--dir LOGDIR]
  behalf diff   <runA> <runB> [--dir LOGDIR] [--all]
  behalf export --run ID [--run ID2] --html FILE [--dir LOGDIR] [--state DIR]
  behalf demo   <list|reset|setup SCENARIO|blob|tamper>

login   authenticate against an OIDC provider and mint the verified
        identity root (a device key bound through the OIDC nonce).
whoami  show the current identity root and re-verify it offline.
why     show the delegation chain behind one receipt, hop by hop, with each
        hop's verification state. The step is the receipt's position in the
        run, counting from 0: `+"`behalf why run_c71e:31`"+`.
runs    list the indexed runs with their attribution.
diff    align two runs and name the first step that diverged, with the one
        later step that carries the divergence forward. Everything after the
        first divergence is presumed downstream and hidden; --all shows it.
export  write one self-contained HTML file for a run — or, with two --run
        flags, a diff-led comparison of a pair. The file loads nothing: no
        CDN, no font, no script from anywhere, so it opens from file:// on a
        machine with no network and prints to PDF cleanly. --state points at
        the payload store (default $BEHALF_HOME or ~/.behalf); without the
        blobs every payload renders as its typed placeholder, which is
        evidence too.
demo    the live-demo driver: reset to a known state, prepare one scenario
        and print the commands to type. Everything offline and
        deterministic. `+"`behalf demo list`"+` names the four scenarios;
        docs/demo-runbook.md is the operator's script.

login and whoami use the state directory (--dir, $BEHALF_HOME, ~/.behalf).
why, runs, diff and export read the log directory (--dir, $BEHALF_LOG_DIR,
~/.behalf/log).
Names shown for keys come from the local alias map (aliases.json in the log
dir): they are asserted labels, never cryptographic claims.
`)
}

func runLogin(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("login", flag.ContinueOnError)
	fs.SetOutput(stderr)
	issuer := fs.String("issuer", "", "OIDC issuer URL (required)")
	clientID := fs.String("client-id", "", "OAuth client id (required)")
	noBrowser := fs.Bool("no-browser", false, "do not open a browser; print the URL instead")
	dir := fs.String("dir", "", "state directory (default $BEHALF_HOME or ~/.behalf)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *issuer == "" || *clientID == "" {
		fmt.Fprintln(stderr, "behalf login: --issuer and --client-id are required")
		return 2
	}
	stateDir, err := identity.ResolveDir(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf login:", err)
		return 1
	}

	res, err := oidclogin.Login(ctx, oidclogin.Config{
		Issuer:    *issuer,
		ClientID:  *clientID,
		Dir:       stateDir,
		NoBrowser: *noBrowser,
		OnAuthURL: func(url string) {
			if *noBrowser {
				fmt.Fprintf(stdout, "Open this URL to log in:\n\n  %s\n\n", url)
			} else {
				fmt.Fprintf(stdout, "Opening your browser to log in (URL below if it does not open):\n\n  %s\n\n", url)
			}
		},
	})
	if err != nil {
		fmt.Fprintln(stderr, "behalf login:", err)
		return 1
	}

	fmt.Fprintf(stdout, "Logged in.\n")
	fmt.Fprintf(stdout, "  issuer:      %s\n", res.Issuer)
	fmt.Fprintf(stdout, "  sub_digest:  %s\n", res.SubDigest)
	fmt.Fprintf(stdout, "  device jkt:  %s\n", res.DeviceJKT)
	fmt.Fprintf(stdout, "  receipt:     %s (spooled in %s)\n", res.ReceiptID, stateDir)
	fmt.Fprintf(stdout, "\nThis device key is now the verified identity root: the IdP signed its\nthumbprint into the ID token nonce, re-checkable offline with `behalf whoami`.\n")
	return 0
}

// resolveLogDir picks the log directory for the read-only subcommands:
// --dir, else $BEHALF_LOG_DIR, else <state dir>/log.
func resolveLogDir(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv(EnvLogDir); env != "" {
		return env, nil
	}
	state, err := identity.ResolveDir("")
	if err != nil {
		return "", err
	}
	return filepath.Join(state, "log"), nil
}

// splitPositional pulls the non-flag arguments out of args so a positional
// may sit either side of the flags — `behalf why run:31 --dir d` and
// `behalf why --dir d run:31` are the same command. Go's flag package stops
// at the first non-flag argument, so the split happens before parsing.
func splitPositional(args []string) (flags, positional []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			return flags, append(positional, args[i+1:]...)
		case strings.HasPrefix(a, "-") && a != "-":
			flags = append(flags, a)
			// A flag written as "--dir d" consumes the next argument; one
			// written as "--dir=d" does not.
			if !strings.Contains(a, "=") && i+1 < len(args) && !strings.HasPrefix(args[i+1], "-") {
				i++
				flags = append(flags, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}
	return flags, positional
}

func runWhy(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("why", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR or ~/.behalf/log)")
	flags, positional := splitPositional(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positional) != 1 {
		fmt.Fprintln(stderr, "behalf why: one receipt address is required, e.g. behalf why run_c71e:31")
		return 2
	}
	addr, err := why.ParseAddress(positional[0])
	if err != nil {
		fmt.Fprintln(stderr, "behalf why:", err)
		return 2
	}
	logDir, err := resolveLogDir(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf why:", err)
		return 1
	}
	res, err := why.Load(ctx, logDir, addr)
	if err != nil {
		fmt.Fprintln(stderr, "behalf why:", err)
		return 1
	}
	aliases, err := why.LoadAliases(logDir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf why: alias map:", err)
		return 1
	}
	if err := why.Render(stdout, res, why.Options{Color: why.ColorFor(stdout), Aliases: aliases}); err != nil {
		fmt.Fprintln(stderr, "behalf why:", err)
		return 1
	}
	return 0
}

func runRuns(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("runs", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR or ~/.behalf/log)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	logDir, err := resolveLogDir(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf runs:", err)
		return 1
	}
	aliases, err := why.LoadAliases(logDir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf runs: alias map:", err)
		return 1
	}
	rows, err := why.ListRuns(ctx, logDir, aliases)
	if err != nil {
		fmt.Fprintln(stderr, "behalf runs:", err)
		return 1
	}
	if len(rows) == 0 {
		fmt.Fprintf(stdout, "No runs indexed in %s.\n", logDir)
		return 0
	}
	if err := why.RenderRuns(stdout, rows, why.Options{Color: why.ColorFor(stdout), Aliases: aliases}); err != nil {
		fmt.Fprintln(stderr, "behalf runs:", err)
		return 1
	}
	return 0
}

func runDiff(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR or ~/.behalf/log)")
	all := fs.Bool("all", false, "show every difference, with downstream suppression off")
	flags, positional := splitPositional(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positional) != 2 {
		fmt.Fprintln(stderr, "behalf diff: two run ids are required, e.g. behalf diff run_9f2a run_c71e")
		return 2
	}
	logDir, err := resolveLogDir(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf diff:", err)
		return 1
	}
	res, err := diff.Load(ctx, logDir, positional[0], positional[1])
	if err != nil {
		fmt.Fprintln(stderr, "behalf diff:", err)
		return 1
	}
	aliases, err := why.LoadAliases(logDir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf diff: alias map:", err)
		return 1
	}
	opt := diff.Options{Color: diff.ColorFor(stdout), All: *all, Aliases: aliases}
	if err := diff.Render(stdout, res, opt); err != nil {
		fmt.Fprintln(stderr, "behalf diff:", err)
		return 1
	}
	return 0
}

// runList collects a repeated --run flag. Two runs produce the diff-led
// comparison page; one produces the single-run page.
type runList []string

func (r *runList) String() string { return strings.Join(*r, ",") }

func (r *runList) Set(v string) error {
	if v == "" {
		return fmt.Errorf("empty run id")
	}
	*r = append(*r, v)
	return nil
}

func runExport(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var runs runList
	fs.Var(&runs, "run", "run id to export; repeat once to compare two runs")
	out := fs.String("html", "", "output HTML file (required)")
	dir := fs.String("dir", "", "log directory (default $BEHALF_LOG_DIR or ~/.behalf/log)")
	state := fs.String("state", "", "state directory holding the payload store (default $BEHALF_HOME or ~/.behalf)")
	flags, positional := splitPositional(args)
	if err := fs.Parse(flags); err != nil {
		return 2
	}
	if len(positional) > 0 {
		fmt.Fprintf(stderr, "behalf export: unexpected argument %q — runs are named with --run\n", positional[0])
		return 2
	}
	if len(runs) == 0 || len(runs) > 2 || *out == "" {
		fmt.Fprintln(stderr, "behalf export: one or two --run flags and --html are required, e.g.")
		fmt.Fprintln(stderr, "  behalf export --run run_9f2a --run run_c71e --html incident.html")
		return 2
	}
	logDir, err := resolveLogDir(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf export:", err)
		return 1
	}
	aliases, err := why.LoadAliases(logDir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf export: alias map:", err)
		return 1
	}
	// The payload store is the customer's own disk, and rehydration runs
	// where it lives (Q84). A store that holds none of the run's blobs is
	// not an error: every slot renders as its typed placeholder, and a page
	// full of placeholders is still evidence because the receipts carry the
	// digests regardless (Q83).
	stateDir, err := identity.ResolveDir(*state)
	if err != nil {
		fmt.Fprintln(stderr, "behalf export:", err)
		return 1
	}

	page, err := htmlexport.WriteFile(ctx, *out, htmlexport.Options{
		LogDir:  logDir,
		Runs:    runs,
		Store:   cas.New(identity.BlobsDir(stateDir)),
		Aliases: aliases,
	})
	if err != nil {
		fmt.Fprintln(stderr, "behalf export:", err)
		return 1
	}

	fi, err := os.Stat(*out)
	if err != nil {
		fmt.Fprintln(stderr, "behalf export:", err)
		return 1
	}
	fmt.Fprintf(stdout, "wrote %s (%d bytes) — %s, self-contained, no external requests\n",
		*out, fi.Size(), strings.Join(runs, " vs "))
	if page.Findings > 0 {
		// Not an error exit: the document was written, and the finding is
		// IN it. Saying so on stderr means a script that only watches the
		// exit code still gets told.
		fmt.Fprintf(stderr, "behalf export: %d payload slot(s) no longer match the digest committed in their signed receipt; the page shows each finding in full\n",
			page.Findings)
	}
	return 0
}

func runWhoami(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("whoami", flag.ContinueOnError)
	fs.SetOutput(stderr)
	dir := fs.String("dir", "", "state directory (default $BEHALF_HOME or ~/.behalf)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	stateDir, err := identity.ResolveDir(*dir)
	if err != nil {
		fmt.Fprintln(stderr, "behalf whoami:", err)
		return 1
	}

	rep, err := oidclogin.VerifyRoot(stateDir)
	if errors.Is(err, oidclogin.ErrNoLogin) {
		fmt.Fprint(stdout, `Not logged in: no verified identity root.

WARNING: every record emitted from this machine carries asserted attribution
FOREVER — records are immutable, so a later login cannot upgrade them (Q21).
Run:

  behalf login --issuer <url> --client-id <id>
`)
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "behalf whoami:", err)
		return 1
	}

	fmt.Fprintf(stdout, "device jkt:   %s\n", rep.Login.DeviceJKT)
	fmt.Fprintf(stdout, "issuer:       %s\n", rep.Login.Issuer)
	fmt.Fprintf(stdout, "sub_digest:   %s\n", rep.Login.SubDigest)
	fmt.Fprintf(stdout, "logged in at: %s\n", rep.Login.LoggedInAt)
	fmt.Fprintf(stdout, "verification: %s\n", rep.State)
	for _, c := range rep.Checks {
		fmt.Fprintf(stdout, "  [%s] %s: %s\n", c.Status, c.Name, c.Detail)
	}
	for _, r := range rep.Reasons {
		fmt.Fprintf(stdout, "  ! %s\n", r)
	}
	if rep.State == oidclogin.StateBroken {
		return 1
	}
	return 0
}
