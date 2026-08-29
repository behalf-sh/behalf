package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The demo is the one artifact whose failure mode is public: it runs live,
// on a call, in front of someone deciding whether to trust a tamper-evidence
// product. So the tests here do not assert that `demo setup` prints a
// plausible-looking list of commands. They take the list it prints, run
// every line of it in a shell, and check the output and the exit status of
// each — because a command list that is correct in the source and wrong on
// the machine is exactly the failure this whole command exists to prevent.
//
// That means these tests build the real binaries and run the real recorder.
// They are the slowest tests in the repo and they are worth it.

// demoBins is the directory TestMain builds the toolchain into. The demo
// resolves siblings through BEHALF_DEMO_BIN_DIR, so the tests drive the
// same lookup an installed `go install ./cmd/...` layout produces.
var (
	demoBins   string
	moduleRoot string
	verifyBin  string // "" when the Rust verifier has not been built
)

func TestMain(m *testing.M) {
	code, err := setupDemoBins()
	if err != nil {
		fmt.Fprintln(os.Stderr, "demo tests: setup:", err)
		os.Exit(1)
	}
	if code == 0 {
		code = m.Run()
	}
	os.RemoveAll(demoBins)
	os.Exit(code)
}

func setupDemoBins() (int, error) {
	root, err := findModuleRoot()
	if err != nil {
		return 1, err
	}
	moduleRoot = root

	dir, err := os.MkdirTemp("", "behalf-demo-bins")
	if err != nil {
		return 1, err
	}
	demoBins = dir

	build := exec.Command("go", "build", "-o", demoBins,
		"./cmd/behalf", "./cmd/behalf-log", "./cmd/behalf-record", "./cmd/otel-attribution")
	build.Dir = moduleRoot
	if out, err := build.CombinedOutput(); err != nil {
		return 1, fmt.Errorf("build the demo toolchain: %w\n%s", err, out)
	}

	// The verifier is Rust and `go test` does not build it. When it is
	// there — `make ci` builds it before running tests — the tamper and
	// custody scenarios run whole; when it is not, the steps that need it
	// are skipped individually and said so.
	for _, cand := range []string{
		os.Getenv(EnvVerifyBin),
		filepath.Join(moduleRoot, "verifier", "target", "release", "behalf-verify"),
	} {
		if cand == "" {
			continue
		}
		if fi, err := os.Stat(cand); err == nil && !fi.IsDir() {
			verifyBin = cand
			break
		}
	}
	if verifyBin != "" {
		// Beside the others, so a printed `behalf-verify …` line runs as
		// written rather than needing a rewritten path.
		if err := copyFile(verifyBin, filepath.Join(demoBins, "behalf-verify")); err != nil {
			return 1, err
		}
	}
	return 0, nil
}

func findModuleRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod above %s", dir)
		}
		dir = parent
	}
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o755)
}

// ---------------------------------------------------------------------------
// driving the printed commands
// ---------------------------------------------------------------------------

// demoHome makes a fresh demo root and runs the first reset into it.
func demoHome(t *testing.T) string {
	t.Helper()
	requireShell(t)
	home := filepath.Join(t.TempDir(), "demo")
	out, code := demoRun(t, home, "behalf demo reset")
	if code != 0 {
		t.Fatalf("behalf demo reset = %d\n%s", code, out)
	}
	return home
}

// demoRun runs one command line in a shell, with the environment an
// operator has after pasting the `export BEHALF_HOME=…` line that `setup`
// prints. Combined output, because half the payoffs in these scenarios are
// on stderr — a tamper finding is not a log line, it is the result.
func demoRun(t *testing.T, home, cmd string) (string, int) {
	t.Helper()
	c := exec.Command("bash", "-c", cmd)
	c.Dir = moduleRoot
	c.Env = append(os.Environ(),
		"PATH="+demoBins+string(os.PathListSeparator)+os.Getenv("PATH"),
		EnvDemoBinDir+"="+demoBins,
		EnvDemoHome+"="+home,
		"BEHALF_HOME="+home,
	)
	var buf bytes.Buffer
	c.Stdout = &buf
	c.Stderr = &buf
	code := 0
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run %q: %v", cmd, err)
		}
		code = ee.ExitCode()
	}
	return buf.String(), code
}

func requireShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the demo driver's printed commands are shell lines")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
}

// printedSteps pulls the command block out of what `demo setup` printed and
// asserts it is exactly the scenario's Steps, in order. Everything below
// drives the parsed block rather than the struct, so a printer that ever
// stopped printing what the driver holds would fail here first.
func printedSteps(t *testing.T, setupOut string, sc scenario) []string {
	t.Helper()
	var cmds []string
	inBlock := false
	for _, line := range strings.Split(setupOut, "\n") {
		if strings.HasPrefix(line, "Then type these") {
			inBlock = true
			continue
		}
		if !inBlock {
			continue
		}
		if strings.HasPrefix(line, "  ") {
			cmds = append(cmds, strings.TrimPrefix(line, "  "))
			continue
		}
		if strings.TrimSpace(line) != "" {
			break
		}
	}
	if len(cmds) != len(sc.Steps) {
		t.Fatalf("scenario %s printed %d commands, the driver holds %d:\n%s", sc.Name, len(cmds), len(sc.Steps), setupOut)
	}
	for i, c := range cmds {
		if c != sc.Steps[i].Cmd {
			t.Fatalf("scenario %s step %d printed %q, driver holds %q", sc.Name, i, c, sc.Steps[i].Cmd)
		}
	}
	return cmds
}

// scenarioExpectations are the substrings each scenario's transcript must
// contain — the payoff of every beat, in the words the runbook tells the
// operator to expect. A scenario that runs clean but stops saying the thing
// it exists to say is a failure, not a pass.
var scenarioExpectations = map[string][]string{
	// The one later step the diff features under the first divergence is
	// deliberately not asserted. On recorded data the values that would
	// prove the causal link are customer-held, so the diff sees digests
	// only, cannot prove a link, and ranks instead — a ranking that is
	// expected to improve. The first divergence is the beat the operator
	// narrates and the only one pinned here.
	"diff": {
		"47 actions in both runs.",
		"1 caused the rest.",
		"first divergence",
		"step 13",
		"downstream differences suppressed",
		"chain intact for 2 of 3 hops",
	},
	"why": {
		"refund.issue(amount=1200.00)",
		"scope: tickets.*, orders.*, refund.issue<=100.00",
		"is caller-asserted. no signature.",
		"refund.issue<=100.00 delegated; 1200.00 issued. (recorded, not enforced)",
		"chain intact for 2 of 3 hops.",
		"chain intact for 3 of 3 hops.",
		"user.email              ceo@corp.com",
		"configuration, not authentication",
	},
	"tamper": {
		"edited the customer's own payload store",
		"class=payload index=78 run=rec_c71e step=31",
		"operation=refund.issue target=ord_5518",
		"edited a receipt inside the export",
		"class=content index=31",
		"unverifiable",
	},
	"custody": {
		"what behalf's signed record holds about the payloads — all of it:",
		"custody       customer-held",
		"[missing: sha256:b29224815eff… (customer-held)]",
		"self-contained, no external requests",
		"47/47 receipts intact",
	},
}

// TestScenarioPrintedCommandsRun is the central test: for each scenario,
// take the commands `demo setup` printed and run every one of them.
func TestScenarioPrintedCommandsRun(t *testing.T) {
	requireShell(t)
	for _, name := range scenarioNames() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			sc := scenarios[name]
			home := filepath.Join(t.TempDir(), "demo")

			setupOut, code := demoRun(t, home, "behalf demo setup "+name)
			if code != 0 {
				t.Fatalf("behalf demo setup %s = %d\n%s", name, code, setupOut)
			}
			if !strings.Contains(setupOut, "export BEHALF_HOME="+home) {
				t.Errorf("setup must print the one line that makes every other command work:\n%s", setupOut)
			}
			cmds := printedSteps(t, setupOut, sc)

			var transcript strings.Builder
			for i, cmd := range cmds {
				step := sc.Steps[i]
				if step.Manual {
					t.Logf("skipped (manual): %s", cmd)
					continue
				}
				if strings.HasPrefix(cmd, "behalf-verify") && verifyBin == "" {
					t.Logf("skipped (no behalf-verify built): %s", cmd)
					continue
				}
				out, got := demoRun(t, home, cmd)
				fmt.Fprintf(&transcript, "$ %s\n%s\n", cmd, out)
				if got != step.Exit {
					t.Fatalf("step %d %q exited %d, want %d\n%s", i, cmd, got, step.Exit, out)
				}
			}

			for _, want := range scenarioExpectations[name] {
				if strings.Contains(want, "47/47 receipts intact") && verifyBin == "" {
					continue
				}
				if !strings.Contains(transcript.String(), want) {
					t.Errorf("scenario %s never printed %q\n%s", name, want, transcript.String())
				}
			}
		})
	}
}

// TestTamperProducesTwoDistinctFindings is the tamper scenario's real
// assertion, pulled out of the transcript so it can be stated precisely:
// the two beats are two different findings, and the first one leaves the
// log perfect.
//
// A tamper demo that only showed the payload break would leave the
// impression that something in the log gave it away. Nothing did.
func TestTamperProducesTwoDistinctFindings(t *testing.T) {
	requireShell(t)
	if verifyBin == "" {
		t.Skip("needs the Rust verifier: cargo build --release --manifest-path verifier/Cargo.toml")
	}
	home := demoHome(t)
	verify := "behalf-verify log $BEHALF_HOME/log --emitter-keys $BEHALF_HOME/emitter.jwks.json"

	if out, code := demoRun(t, home, verify); code != 0 || !strings.Contains(out, "94/94 entries intact") {
		t.Fatalf("the untouched log must verify: exit %d\n%s", code, out)
	}

	// Beat one: the customer's own bytes.
	if out, code := demoRun(t, home, "behalf demo tamper payload"); code != 0 {
		t.Fatalf("demo tamper payload = %d\n%s", code, out)
	}
	out, code := demoRun(t, home, "behalf-log rehydrate --run rec_c71e >/dev/null")
	if code != 1 {
		t.Fatalf("a payload that contradicts its commitment must exit 1, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "class=payload index=78") {
		t.Errorf("finding must classify as payload and name the leaf:\n%s", out)
	}
	if !strings.Contains(out, "run=rec_c71e step=31") || !strings.Contains(out, "operation=refund.issue target=ord_5518") {
		t.Errorf("finding must name the receipt and the operation, not just that something is wrong:\n%s", out)
	}

	// And the log is still perfect. This is the half the scenario is for.
	if out, code := demoRun(t, home, verify); code != 0 || !strings.Contains(out, "94/94 entries intact") {
		t.Fatalf("the log must still verify after a payload edit: exit %d\n%s", code, out)
	}

	// Beat two: behalf's own record, in an export.
	if out, code := demoRun(t, home, "behalf-log export --run rec_c71e --out $BEHALF_HOME/refund.jsonl"); code != 0 {
		t.Fatalf("export = %d\n%s", code, out)
	}
	if out, code := demoRun(t, home, "behalf-verify $BEHALF_HOME/refund.jsonl"); code != 0 {
		t.Fatalf("a fresh export must verify: exit %d\n%s", code, out)
	}
	if out, code := demoRun(t, home, "behalf demo tamper export $BEHALF_HOME/refund.jsonl"); code != 0 {
		t.Fatalf("demo tamper export = %d\n%s", code, out)
	}
	out, code = demoRun(t, home, "behalf-verify $BEHALF_HOME/refund.jsonl")
	if code != 1 {
		t.Fatalf("an edited receipt must exit 1, got %d\n%s", code, out)
	}
	if !strings.Contains(out, "class=content index=31") {
		t.Errorf("the second finding must be a content finding, distinct from the payload one:\n%s", out)
	}
	if !strings.Contains(out, "unverifiable") {
		t.Errorf("everything downstream of a chain break must be called unverifiable:\n%s", out)
	}
}

// TestResetIsIdempotent: running reset twice leaves the same state, and the
// second run removes what the first built rather than failing on it or
// piling a second demo on top.
func TestResetIsIdempotent(t *testing.T) {
	requireShell(t)
	home := demoHome(t)

	second, code := demoRun(t, home, "behalf demo reset")
	if code != 0 {
		t.Fatalf("second reset = %d\n%s", code, second)
	}
	if !strings.Contains(second, "removed   "+home) {
		t.Errorf("the second reset must say it removed the first:\n%s", second)
	}
	// 136, not 133: the three signed hop tokens of the demo chain are kept in
	// the customer's store at the address each hop's `evidence_ref` names, so
	// the delegation signatures can be re-checked rather than taken on the
	// receipt's word. Run B's leaf hop is unsigned and has no token; its other
	// two hops are byte-identical to run A's and dedup to the same blobs.
	if !strings.Contains(second, "log with 94 entries") || !strings.Contains(second, "136 payload blobs") {
		t.Errorf("reset must say what it removed, not just that it removed something:\n%s", second)
	}

	// And the rebuilt state is the state every scenario needs.
	for _, cmd := range []string{
		"behalf runs",
		"behalf why rec_c71e:31",
		"behalf diff rec_9f2a rec_c71e",
		"behalf demo blob",
	} {
		if out, code := demoRun(t, home, cmd); code != 0 {
			t.Errorf("%q after two resets = %d\n%s", cmd, code, out)
		}
	}
}

// TestResetIsDeterministic: reset twice, and everything the operator will
// put on screen is byte-identical. A demo whose output drifts between runs
// cannot be rehearsed, and a recording whose bytes drift is not the
// deterministic artifact the product claims.
func TestResetIsDeterministic(t *testing.T) {
	requireShell(t)
	home := demoHome(t)

	read := []string{
		"behalf runs",
		"behalf diff rec_9f2a rec_c71e",
		"behalf diff rec_9f2a rec_c71e --all",
		"behalf why rec_c71e:31",
		"behalf why rec_9f2a:31",
		"behalf demo blob",
		"otel-attribution",
		"OTEL_RESOURCE_ATTRIBUTES=user.email=ceo@corp.com otel-attribution",
	}
	first := map[string]string{}
	for _, cmd := range read {
		out, code := demoRun(t, home, cmd)
		if code != 0 {
			t.Fatalf("%q = %d\n%s", cmd, code, out)
		}
		first[cmd] = out
	}
	cpBefore, err := os.ReadFile(filepath.Join(home, "log", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}

	if out, code := demoRun(t, home, "behalf demo reset"); code != 0 {
		t.Fatalf("reset = %d\n%s", code, out)
	}

	for _, cmd := range read {
		out, code := demoRun(t, home, cmd)
		if code != 0 {
			t.Fatalf("%q after reset = %d\n%s", cmd, code, out)
		}
		if out != first[cmd] {
			t.Errorf("%q is not reproducible across a reset:\n--- before ---\n%s\n--- after ---\n%s", cmd, first[cmd], out)
		}
	}
	cpAfter, err := os.ReadFile(filepath.Join(home, "log", "checkpoint"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cpBefore, cpAfter) {
		t.Errorf("the signed checkpoint must be identical across a reset:\n%s\n%s", cpBefore, cpAfter)
	}
}

// TestScenarioIsRepeatable runs the most stateful scenario twice, whole,
// with a reset between — which is what a second customer call on the same
// day actually is.
func TestScenarioIsRepeatable(t *testing.T) {
	requireShell(t)
	if verifyBin == "" {
		t.Skip("needs the Rust verifier")
	}
	sc := scenarios["tamper"]
	home := filepath.Join(t.TempDir(), "demo")

	transcripts := make([]string, 2)
	for pass := range transcripts {
		setupOut, code := demoRun(t, home, "behalf demo setup tamper")
		if code != 0 {
			t.Fatalf("pass %d setup = %d\n%s", pass, code, setupOut)
		}
		var b strings.Builder
		for i, cmd := range printedSteps(t, setupOut, sc) {
			out, got := demoRun(t, home, cmd)
			if got != sc.Steps[i].Exit {
				t.Fatalf("pass %d step %d %q exited %d, want %d\n%s", pass, i, cmd, got, sc.Steps[i].Exit, out)
			}
			fmt.Fprintf(&b, "$ %s\n%s\n", cmd, out)
		}
		transcripts[pass] = b.String()
	}
	if transcripts[0] != transcripts[1] {
		t.Errorf("running the tamper scenario twice must print the same bytes:\n--- first ---\n%s\n--- second ---\n%s",
			transcripts[0], transcripts[1])
	}
}

// ---------------------------------------------------------------------------
// the parts that need no subprocess
// ---------------------------------------------------------------------------

// TestResetRefusesAForeignDirectory is the guard that stands between a
// mistyped BEHALF_HOME and someone's real log. `demo reset` deletes a
// directory tree; it must never delete one it did not create.
func TestResetRefusesAForeignDirectory(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "not-a-demo")
	if err := os.MkdirAll(filepath.Join(real, "log"), 0o755); err != nil {
		t.Fatal(err)
	}
	canary := filepath.Join(real, "log", "checkpoint")
	if err := os.WriteFile(canary, []byte("someone's actual log\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvDemoHome, real)
	t.Setenv(EnvDemoBinDir, demoBins)

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"demo", "reset"}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout: %s)", code, out.String())
	}
	if !strings.Contains(errOut.String(), "refusing to remove") || !strings.Contains(errOut.String(), demoMarker) {
		t.Errorf("the refusal must say why and name the marker: %s", errOut.String())
	}
	if _, err := os.Stat(canary); err != nil {
		t.Fatalf("reset destroyed a directory it did not create: %v", err)
	}
}

// TestDemoDirResolution: once the operator has exported BEHALF_HOME to the
// demo root — which is what `setup` tells them to do — a second `demo
// reset` must land on that same root, not build a demo inside the demo.
func TestDemoDirResolution(t *testing.T) {
	base := t.TempDir()
	t.Setenv(EnvDemoHome, "")
	t.Setenv("BEHALF_HOME", base)

	got, err := demoDir()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, demoDirName); got != want {
		t.Fatalf("with no demo state yet: got %s, want %s", got, want)
	}

	if err := os.WriteFile(filepath.Join(base, demoMarker), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err = demoDir()
	if err != nil {
		t.Fatal(err)
	}
	if got != base {
		t.Fatalf("with BEHALF_HOME already at a demo root: got %s, want %s", got, base)
	}
}

// TestStageCommandsRefuseWithoutDemoState: `demo tamper` writes bytes into
// a store. It must not do that anywhere that is not a demo root, whatever
// the environment says.
func TestStageCommandsRefuseWithoutDemoState(t *testing.T) {
	t.Setenv(EnvDemoHome, t.TempDir())
	for _, args := range [][]string{
		{"demo", "tamper", "payload"},
		{"demo", "blob"},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != 1 {
			t.Errorf("%v = %d, want 1", args, code)
		}
		if !strings.Contains(errOut.String(), "behalf demo reset") {
			t.Errorf("%v must say how to fix it: %s", args, errOut.String())
		}
	}
}

func TestDemoListNamesEveryScenario(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"demo", "list"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d: %s", code, errOut.String())
	}
	s := out.String()
	for name, sc := range scenarios {
		if !strings.Contains(s, name) {
			t.Errorf("list omits scenario %q:\n%s", name, s)
		}
		if !strings.Contains(s, sc.Objection) {
			t.Errorf("list omits the objection %q pre-empts:\n%s", name, s)
		}
	}
	if !strings.Contains(s, "docs/demo-runbook.md") {
		t.Errorf("list must point at the operator's script:\n%s", s)
	}
}

func TestDemoSetupRejectsUnknownScenario(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"demo", "setup", "nope"}, &out, &errOut); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	for _, name := range scenarioNames() {
		if !strings.Contains(errOut.String(), name) {
			t.Errorf("the error should list the scenarios that do exist: %s", errOut.String())
		}
	}
}

// TestRunbookCoversEveryStep keeps the operator's script and the driver in
// step. The runbook is what someone reads at 9am before a 10am call; a
// command that changed here and not there is a live failure with a
// paper trail that says it should have worked.
func TestRunbookCoversEveryStep(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(moduleRoot, "docs", "demo-runbook.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	for _, name := range scenarioNames() {
		sc := scenarios[name]
		if !strings.Contains(doc, "behalf demo setup "+name) {
			t.Errorf("the runbook never gives the setup command for %q", name)
		}
		if !strings.Contains(doc, sc.Objection) {
			t.Errorf("the runbook never states the objection %q pre-empts", name)
		}
		for _, st := range sc.Steps {
			if !strings.Contains(doc, st.Cmd) {
				t.Errorf("the runbook is missing scenario %s command: %s", name, st.Cmd)
			}
		}
	}
	// The things an operator needs that are not commands: how to get the
	// machine ready, what the terminal has to be for Zoom to render the
	// fixed-width output, and the single move when something fails live.
	for _, want := range []string{
		"Pre-call checklist",
		"If a command fails live",
		"Columns",
		"Font",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the runbook is missing %q", want)
		}
	}
}
