// `behalf demo` is the live-demo driver (ENG-25): the commands that put a
// machine into a known state before a scenario and the small amount of
// stage machinery the scenarios need.
//
// The audience for this file is one person typing on a Zoom call. That
// constrains it more than the rest of the CLI:
//
//   - Reset must be one command, idempotent, and it must say what it did.
//     The second scenario on a call otherwise runs against the wreckage of
//     the first, and the failure shows up in front of a customer.
//   - The demo state lives at one default path and the commands find it
//     without --dir, so the operator types `behalf why rec_c71e:31` rather
//     than a line with a directory in it. One exported variable
//     (BEHALF_HOME) is the whole of the configuration, and `setup` prints
//     it.
//   - Nothing here reaches the network or needs a key. The recording is the
//     deterministic one (cmd/behalf-record), driven through the real MCP
//     proxy against the in-repo desk server.
//   - Detection is never done by this file. `demo tamper` performs an edit
//     — that is the attacker's half — and the shipped tooling
//     (`behalf-verify`, `behalf-log rehydrate`) finds it. A demo where the
//     demo command both breaks and diagnoses proves nothing.
//
// This is not `npx onbehalf demo` (self-serve, separate) and not the CI dry
// run. It is the thing that must not fall over live.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/behalf-sh/behalf/internal/identity"
)

// EnvDemoHome overrides where the demo state lives. Unset, it is `demo/`
// under the ordinary state directory, which keeps a demo reset from ever
// pointing at a real install's log.
const EnvDemoHome = "BEHALF_DEMO_HOME"

// EnvDemoBinDir overrides where `behalf demo` looks for its sibling
// binaries (behalf-record, behalf-log, behalf-verify). Unset, it looks
// beside the running `behalf`, then on PATH. Tests set it; so can an
// operator with an unusual layout.
const EnvDemoBinDir = "BEHALF_DEMO_BIN_DIR"

// EnvVerifyBin names the offline verifier explicitly. Same variable
// scripts/tamper_suite.sh uses, so a machine set up for the suite is
// already set up for the demo.
const EnvVerifyBin = "BEHALF_VERIFY"

const (
	demoDirName  = "demo"
	demoMarker   = ".behalf-demo"
	demoRunA     = "rec_9f2a"
	demoRunB     = "rec_c71e"
	demoJWKSName = "emitter.jwks.json"
)

func runDemo(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		demoUsage(stderr)
		return 2
	}
	switch args[0] {
	case "list":
		return demoList(stdout)
	case "reset":
		return demoReset(args[1:], stdout, stderr)
	case "setup":
		return demoSetup(args[1:], stdout, stderr)
	case "tamper":
		return demoTamper(args[1:], stdout, stderr)
	case "blob":
		return demoBlob(args[1:], stdout, stderr)
	case "help", "-h", "--help":
		demoUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "behalf demo: unknown subcommand %q\n\n", args[0])
		demoUsage(stderr)
		return 2
	}
}

func demoUsage(w io.Writer) {
	fmt.Fprint(w, `behalf demo — the live-demo driver

Usage:
  behalf demo list
  behalf demo reset
  behalf demo setup <scenario>
  behalf demo blob [<run>:<step>] [--path]
  behalf demo tamper payload
  behalf demo tamper export <file>

list    the scenarios and what each one proves.
reset   remove the demo state and rebuild it from the deterministic
        recorder. Idempotent; safe to run between scenarios; prints what
        it did.
setup   reset, prepare what one scenario needs, and print the commands to
        type, one per line. --no-reset skips the rebuild.
blob    what behalf's record holds about one receipt's payloads, and
        whether those bytes are on this disk. --path prints only the input
        blob's path, for `+"`rm $(behalf demo blob --path)`"+`.
tamper  perform the demo's edit — a real one, on real bytes. Detection is
        left to `+"`behalf-verify`"+` and `+"`behalf-log rehydrate`"+`, which is the
        point: the tooling that finds it is the tooling that ships.

The demo state lives in `+EnvDemoHome+`, else demo/ under the state
directory ($BEHALF_HOME, ~/.behalf). `+"`setup`"+` prints the one line to
export so every other command finds it without a flag.
`)
}

// demoDir resolves the demo state root.
//
// The middle case matters on the second run of a call: once the operator
// has exported BEHALF_HOME to the demo root, identity.ResolveDir returns
// that root, and appending demo/ again would build a second demo inside the
// first. The marker file settles it — a directory that is already a demo
// root is used as one.
func demoDir() (string, error) {
	if v := os.Getenv(EnvDemoHome); v != "" {
		return v, nil
	}
	base, err := identity.ResolveDir("")
	if err != nil {
		return "", err
	}
	if isDemoDir(base) {
		return base, nil
	}
	return filepath.Join(base, demoDirName), nil
}

func isDemoDir(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, demoMarker))
	return err == nil
}

func demoLogPath(root string) string { return filepath.Join(root, "log") }

// demoBinary finds one of the sibling binaries the demo drives.
//
// Beside the running `behalf` first, because `go install ./cmd/...` puts
// the whole set in one directory and an operator who has two behalf builds
// on a machine should get the one matching the CLI they just ran. PATH is
// the fallback.
func demoBinary(name string) (string, error) {
	var tried []string
	try := func(p string) (string, bool) {
		if p == "" {
			return "", false
		}
		tried = append(tried, p)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, true
		}
		return "", false
	}
	if name == "behalf-verify" {
		if p, ok := try(os.Getenv(EnvVerifyBin)); ok {
			return p, nil
		}
	}
	if dir := os.Getenv(EnvDemoBinDir); dir != "" {
		if p, ok := try(filepath.Join(dir, name)); ok {
			return p, nil
		}
	}
	if exe, err := os.Executable(); err == nil {
		if resolved, rerr := filepath.EvalSymlinks(exe); rerr == nil {
			exe = resolved
		}
		if p, ok := try(filepath.Join(filepath.Dir(exe), name)); ok {
			return p, nil
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	tried = append(tried, "$PATH")
	return "", fmt.Errorf("%s not found (looked in: %s)\n  build and install the set with:  go install ./cmd/...%s",
		name, strings.Join(tried, ", "), verifierHint(name))
}

func verifierHint(name string) string {
	if name != "behalf-verify" {
		return ""
	}
	return "\n  the verifier is Rust:  cargo build --release --manifest-path verifier/Cargo.toml\n" +
		"  then put it on PATH, or set " + EnvVerifyBin + " to it"
}

// demoReset returns the machine to the known clean state: remove the demo
// root, then rebuild it by running the deterministic recorder.
//
// Removal is guarded on the marker file. `behalf demo reset` deletes a
// directory tree; if BEHALF_HOME or BEHALF_DEMO_HOME is pointed at a real
// install by accident, the guard is the only thing between a mistyped
// variable and someone's log. A directory that exists and was not created
// by this command is refused, loudly.
func demoReset(args []string, stdout, stderr io.Writer) int {
	if len(args) > 0 {
		fmt.Fprintf(stderr, "behalf demo reset: unexpected argument %q — reset takes none\n", args[0])
		return 2
	}
	root, err := demoDir()
	if err != nil {
		fmt.Fprintln(stderr, "behalf demo reset:", err)
		return 1
	}
	if err := resetTo(root, stdout); err != nil {
		fmt.Fprintln(stderr, "behalf demo reset:", err)
		return 1
	}
	fmt.Fprintf(stdout, "\n  export BEHALF_HOME=%s\n", root)
	return 0
}

// resetTo does the whole rebuild and narrates it as it goes. It writes to
// out rather than returning a summary because the printout is the product
// here: an operator who cannot see what reset removed cannot tell a clean
// state from a half-cleaned one.
func resetTo(root string, out io.Writer) error {
	recorder, err := demoBinary("behalf-record")
	if err != nil {
		return err
	}
	start := time.Now()

	switch _, statErr := os.Stat(root); {
	case statErr == nil && !isDemoDir(root):
		return fmt.Errorf("refusing to remove %s: it exists and is not a behalf demo directory (no %s marker).\n"+
			"  If that really is the demo root, remove it by hand; if %s or %s is pointing somewhere unintended, fix that first",
			root, demoMarker, EnvDemoHome, identity.EnvHome)
	case statErr == nil:
		before := describeDir(root)
		if err := os.RemoveAll(root); err != nil {
			return err
		}
		fmt.Fprintf(out, "removed   %s (%s)\n", root, before)
	default:
		fmt.Fprintf(out, "removed   nothing — %s did not exist\n", root)
	}

	if err := os.MkdirAll(root, 0o700); err != nil {
		return err
	}

	// Said before the wait, not after it. The recording takes a few seconds
	// and a live operator narrating an empty terminal is exactly the moment
	// a demo feels broken; a line that says what is happening and roughly
	// how long turns the pause into part of the story.
	fmt.Fprintf(out, "recording two 47-step runs through the real MCP proxy… (a few seconds, offline)\n")

	// The recorder is loud on stderr (Tessera's own logger announces the
	// directory initialisation) and that noise is not what anyone is here
	// to read. Captured, and shown only if it failed.
	cmd := exec.Command(recorder, "--dir", demoLogPath(root), "--out", root, "--quiet")
	cmd.Env = append(os.Environ(), identity.EnvHome+"="+root)
	var captured strings.Builder
	cmd.Stdout = &captured
	cmd.Stderr = &captured
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("recording failed: %w\n%s", err, indentLines(captured.String(), "  | "))
	}

	// The marker goes down after a successful recording, never before: a
	// half-built directory must not be something the next reset silently
	// removes as if it were known-good state.
	if err := os.WriteFile(filepath.Join(root, demoMarker), []byte(demoMarkerText), 0o600); err != nil {
		return err
	}
	jwks, err := writeEmitterJWKS(root)
	if err != nil {
		return err
	}

	fmt.Fprintf(out, "recorded  %s and %s — %d receipts in one log\n",
		demoRunA, demoRunB, countLogEntries(demoLogPath(root)))
	fmt.Fprintf(out, "log       %s\n", demoLogPath(root))
	fmt.Fprintf(out, "payloads  %s (%d blobs, customer-held)\n",
		identity.BlobsDir(root), countFiles(identity.BlobsDir(root)))
	fmt.Fprintf(out, "keys      %s (for behalf-verify --emitter-keys)\n", jwks)
	fmt.Fprintf(out, "took      %s, offline, deterministic — same bytes every time\n",
		time.Since(start).Round(100*time.Millisecond))
	return nil
}

const demoMarkerText = `This directory is behalf demo state, rebuilt by ` + "`behalf demo reset`" + `.
Everything in it is generated. Nothing here is anyone's real log.
`

// writeEmitterJWKS writes the recording's emitter public key in the
// verifier's --emitter-keys format, so the tamper scenario can assert
// receipt signatures rather than settling for the checkpoint alone.
func writeEmitterJWKS(root string) (string, error) {
	key, err := identity.LoadKey(identity.EmitterKeyPath(root))
	if err != nil {
		return "", fmt.Errorf("read the recording's emitter key: %w", err)
	}
	doc := struct {
		Keys []struct {
			JKT string `json:"jkt"`
			JWK any    `json:"jwk"`
		} `json:"keys"`
	}{}
	doc.Keys = append(doc.Keys, struct {
		JKT string `json:"jkt"`
		JWK any    `json:"jwk"`
	}{JKT: key.JKT, JWK: key.JWK})
	b, err := json.Marshal(doc)
	if err != nil {
		return "", err
	}
	path := filepath.Join(root, demoJWKSName)
	return path, os.WriteFile(path, append(b, '\n'), 0o600)
}

// describeDir summarises what a reset is about to delete, so the printout
// names the thing removed rather than only its path.
func describeDir(root string) string {
	parts := []string{}
	if n := countLogEntries(demoLogPath(root)); n > 0 {
		parts = append(parts, fmt.Sprintf("log with %d entries", n))
	}
	if n := countFiles(identity.BlobsDir(root)); n > 0 {
		parts = append(parts, fmt.Sprintf("%d payload blobs", n))
	}
	if n := countExports(root); n > 0 {
		parts = append(parts, fmt.Sprintf("%d export file(s)", n))
	}
	if len(parts) == 0 {
		return "empty"
	}
	return strings.Join(parts, ", ")
}

// countLogEntries reads the tree size out of the checkpoint. A log whose
// checkpoint is unreadable counts as zero rather than failing the reset:
// the number is for the printout, and a reset must work on wreckage.
func countLogEntries(logDir string) int {
	b, err := os.ReadFile(filepath.Join(logDir, "checkpoint"))
	if err != nil {
		return 0
	}
	lines := strings.Split(string(b), "\n")
	if len(lines) < 2 {
		return 0
	}
	var n int
	if _, err := fmt.Sscanf(lines[1], "%d", &n); err != nil {
		return 0
	}
	return n
}

func countFiles(dir string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() {
			n++
		}
	}
	return n
}

// countExports counts the artefacts a scenario wrote into the demo root —
// the export files the operator handed to an imaginary third party, and
// which a reset has to take away again. spool.jsonl is not one of them: it
// is the login receipt spool the recorder itself leaves behind.
func countExports(dir string) int {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		name := e.Name()
		if name == "spool.jsonl" {
			continue
		}
		if strings.HasSuffix(name, ".jsonl") || strings.HasSuffix(name, ".html") {
			n++
		}
	}
	return n
}

func indentLines(s, prefix string) string {
	s = strings.TrimRight(s, "\n")
	if s == "" {
		return ""
	}
	return prefix + strings.ReplaceAll(s, "\n", "\n"+prefix)
}

func demoList(stdout io.Writer) int {
	fmt.Fprintf(stdout, "behalf demo — %d scenarios. Each runs about 2–3 minutes and ends on one payoff.\n\n", len(scenarios))
	names := scenarioNames()
	width := 0
	for _, n := range names {
		if len(n) > width {
			width = len(n)
		}
	}
	for _, n := range names {
		s := scenarios[n]
		fmt.Fprintf(stdout, "  %-*s  %s\n", width, s.Name, s.Headline)
		// `proves` is a full sentence and ran to 174 columns unwrapped, against
		// the 100 the runbook documents (ENG-21). This listing is what an
		// operator reads while preparing, so it is the one place in the demo
		// output where reflowing prose is right rather than a layout hack.
		for i, line := range wrapText(s.Proves, 76) {
			label := "proves    "
			if i > 0 {
				label = "          "
			}
			fmt.Fprintf(stdout, "  %-*s  %s %s\n", width, "", label, line)
		}
		fmt.Fprintf(stdout, "  %-*s  pre-empts  %q\n", width, "", s.Objection)
		fmt.Fprintf(stdout, "  %-*s  setup      behalf demo setup %s\n\n", width, "", s.Name)
	}
	fmt.Fprintf(stdout, "The operator's script — what to say at each beat, what the output should look\nlike, and what to do if a command fails live — is docs/demo-runbook.md.\n")
	return 0
}

// writeWrapped prints a labelled sentence inside the runbook's documented
// terminal width, continuing under a blank label.
//
// The width is not cosmetic here. `behalf demo setup` is on screen while the
// operator types the scenario's commands from it, at the 100 columns
// docs/demo-runbook.md tells them to set — and two of its lines ran to 163 and
// 108 before this (ENG-21). A wrapped sentence reads; a sentence the terminal
// folds mid-word does not.
func writeWrapped(out io.Writer, label, text string) {
	for i, line := range wrapText(text, 76) {
		if i > 0 {
			label = strings.Repeat(" ", len(label))
		}
		fmt.Fprintf(out, "%s %s\n", label, line)
	}
}

// wrapText breaks a sentence onto lines of at most n columns, on spaces. A
// single word longer than n is left whole rather than cut: a digest or a
// command is worth an over-long line, and hyphenating one would make it
// uncopyable.
func wrapText(s string, n int) []string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return []string{""}
	}
	lines := []string{words[0]}
	for _, w := range words[1:] {
		last := len(lines) - 1
		if len([]rune(lines[last]))+1+len([]rune(w)) <= n {
			lines[last] += " " + w
			continue
		}
		lines = append(lines, w)
	}
	return lines
}

func scenarioNames() []string {
	names := make([]string, 0, len(scenarios))
	for n := range scenarios {
		names = append(names, n)
	}
	sort.Slice(names, func(i, j int) bool { return scenarios[names[i]].Order < scenarios[names[j]].Order })
	return names
}

func demoSetup(args []string, stdout, stderr io.Writer) int {
	noReset := false
	var name string
	for _, a := range args {
		switch {
		case a == "--no-reset":
			noReset = true
		case strings.HasPrefix(a, "-"):
			fmt.Fprintf(stderr, "behalf demo setup: unknown flag %q\n", a)
			return 2
		case name == "":
			name = a
		default:
			fmt.Fprintf(stderr, "behalf demo setup: one scenario at a time (got %q and %q)\n", name, a)
			return 2
		}
	}
	if name == "" {
		fmt.Fprintf(stderr, "behalf demo setup: which scenario? one of: %s\n", strings.Join(scenarioNames(), ", "))
		return 2
	}
	sc, ok := scenarios[name]
	if !ok {
		fmt.Fprintf(stderr, "behalf demo setup: no scenario %q. Try one of: %s\n", name, strings.Join(scenarioNames(), ", "))
		return 2
	}
	root, err := demoDir()
	if err != nil {
		fmt.Fprintln(stderr, "behalf demo setup:", err)
		return 1
	}

	// Every binary the scenario will reach for is checked here, before the
	// call, not when the operator types the command that needs it. A missing
	// verifier discovered at minute two of a demo is the failure this whole
	// command exists to prevent.
	var missing []string
	for _, bin := range sc.Needs {
		if _, err := demoBinary(bin); err != nil {
			missing = append(missing, "  "+strings.ReplaceAll(err.Error(), "\n", "\n  "))
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "behalf demo setup %s: this scenario needs tools that are not installed:\n%s\n", name, strings.Join(missing, "\n"))
		return 1
	}

	fmt.Fprintf(stdout, "scenario   %s — %s\n", sc.Name, sc.Headline)
	writeWrapped(stdout, "proves    ", sc.Proves)
	fmt.Fprintf(stdout, "pre-empts  %q\n", sc.Objection)
	fmt.Fprintf(stdout, "runtime    %s\n\n", sc.Runtime)

	if noReset {
		if !isDemoDir(root) {
			fmt.Fprintf(stderr, "behalf demo setup: --no-reset, but %s holds no demo state yet. Run `behalf demo reset` first.\n", root)
			return 1
		}
		fmt.Fprintf(stdout, "state     reused as-is (--no-reset)\n")
	} else if err := resetTo(root, stdout); err != nil {
		fmt.Fprintln(stderr, "behalf demo setup:", err)
		return 1
	}

	if sc.Prepare != nil {
		notes, err := sc.Prepare(root)
		if err != nil {
			fmt.Fprintln(stderr, "behalf demo setup:", err)
			return 1
		}
		for _, n := range notes {
			writeWrapped(stdout, "prepared ", n)
		}
	}

	fmt.Fprintf(stdout, "\nFirst, once per shell:\n\n  export BEHALF_HOME=%s\n", root)
	fmt.Fprintf(stdout, "\nThen type these, one at a time:\n\n")
	for _, st := range sc.Steps {
		fmt.Fprintf(stdout, "  %s\n", st.Cmd)
	}
	fmt.Fprintf(stdout, "\nWhat to say at each beat, and the one recovery move if something fails:\n")
	fmt.Fprintf(stdout, "docs/demo-runbook.md, section %q.\n", sc.Name)
	return 0
}

// demoState is the resolved demo root plus the handles the stage commands
// need. Every one of them refuses to run against a directory that is not a
// demo root, so a mistyped BEHALF_HOME cannot get `demo tamper` to edit a
// real store.
type demoState struct {
	Root   string
	LogDir string
}

func openDemo() (*demoState, error) {
	root, err := demoDir()
	if err != nil {
		return nil, err
	}
	if !isDemoDir(root) {
		return nil, fmt.Errorf("%s holds no demo state (no %s marker). Run `behalf demo reset` first", root, demoMarker)
	}
	return &demoState{Root: root, LogDir: demoLogPath(root)}, nil
}
