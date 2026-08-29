package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/hooks"
	"github.com/behalf-sh/behalf/internal/spool"
)

const bashPost = `{"session_id":"ses_cli","hook_event_name":"PostToolUse","tool_name":"Bash",` +
	`"tool_input":{"command":"ls"},"tool_response":{"stdout":"a\n"}}`

// TestCaptureWritesAReceipt: the happy path, through the CLI entry point.
func TestCaptureWritesAReceipt(t *testing.T) {
	state := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runCapture([]string{"--state", state, "-v"}, strings.NewReader(bashPost), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	completions, err := spool.ReadAll(filepath.Join(state, hooks.DefaultSpoolDirName))
	if err != nil {
		t.Fatal(err)
	}
	if len(completions) != 1 {
		t.Fatalf("spooled %d receipts, want 1 (stderr: %s)", len(completions), stderr.String())
	}
	if !strings.Contains(stderr.String(), "tool_call receipt") {
		t.Fatalf("-v said nothing useful: %s", stderr.String())
	}
}

// TestCaptureFailureStillExitsZero is the deliberate inversion of the proxy's
// posture, and the single most important behaviour of this binary.
//
// A hook that fails closed does not protect a crossing — it breaks the user's
// editor session, and a recorder that takes the editor down with it gets
// uninstalled, which records nothing at all. Every one of these is a real
// failure, and every one exits 0 with an explanation on stderr.
func TestCaptureFailureStillExitsZero(t *testing.T) {
	unwritable := filepath.Join(t.TempDir(), "state")
	if err := os.WriteFile(unwritable, []byte("this is a file, not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name  string
		args  []string
		stdin string
	}{
		{"empty stdin", []string{"--state", t.TempDir()}, ""},
		{"not json", []string{"--state", t.TempDir()}, "not json at all"},
		{"no event name", []string{"--state", t.TempDir()}, `{"tool_name":"Bash"}`},
		{"truncated json", []string{"--state", t.TempDir()}, `{"hook_event_name":"PostToolUse"`},
		{"unwritable state dir", []string{"--state", unwritable}, bashPost},
		{"missing policy file", []string{"--state", t.TempDir(), "--policy", "/nope/policy.json"}, bashPost},
		{"unparseable flags", []string{"--not-a-flag"}, bashPost},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			code := runCapture(tc.args, strings.NewReader(tc.stdin), &stdout, &stderr)
			if code != 0 {
				t.Fatalf("exit %d — a capture failure must never break the session\nstderr: %s", code, stderr.String())
			}
			if !strings.Contains(stderr.String(), "behalf-hook") {
				t.Fatalf("the failure was swallowed silently: %q", stderr.String())
			}
		})
	}
}

// TestUnhandledEventExitsZeroQuietly: Claude Code may send events this surface
// does not receipt, and that is not an error.
func TestUnhandledEventExitsZeroQuietly(t *testing.T) {
	state := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runCapture([]string{"--state", state},
		strings.NewReader(`{"hook_event_name":"UserPromptSubmit","session_id":"s","prompt":"hi"}`), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if stderr.Len() != 0 {
		t.Fatalf("an unhandled event was noisy without -v: %q", stderr.String())
	}
	completions, _ := spool.ReadAll(filepath.Join(state, hooks.DefaultSpoolDirName))
	if len(completions) != 0 {
		t.Fatalf("an unhandled event produced %d receipts", len(completions))
	}
}

// TestInstalledByFlagIsAcceptedAndIgnored: the marker `install` writes into the
// command line must not make the capture path choke.
func TestInstalledByFlagIsAcceptedAndIgnored(t *testing.T) {
	state := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runCapture([]string{"--state", state, hooks.InstallMarkerFlag, hooks.InstallMarkerValue},
		strings.NewReader(bashPost), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	completions, _ := spool.ReadAll(filepath.Join(state, hooks.DefaultSpoolDirName))
	if len(completions) != 1 {
		t.Fatalf("spooled %d receipts, want 1 (stderr %s)", len(completions), stderr.String())
	}
}

// TestInstallCommandRoundTrip drives install, --print and uninstall through the
// CLI, against a settings file that already has someone else's hook in it.
func TestInstallCommandRoundTrip(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	const existing = `{"model":"opus","hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"other guard"}]}]}}`
	if err := os.WriteFile(settings, []byte(existing), 0o600); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	args := []string{"--settings", settings, "--state", filepath.Join(dir, "state"), "--binary", "/opt/behalf-hook"}
	if err := runInstall(args, &out); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(b, []byte("other guard")) {
		t.Fatal("install clobbered the other tool's hook")
	}
	if !bytes.Contains(b, []byte(hooks.InstallMarkerValue)) {
		t.Fatal("install wrote no marker")
	}
	if !strings.Contains(out.String(), "user-scoped") {
		t.Fatalf("install did not say the file can be deleted by the observed user (Q74): %s", out.String())
	}

	// --print touches nothing.
	before, _ := os.ReadFile(settings)
	var printed bytes.Buffer
	if err := runInstall(append(args, "--print"), &printed); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(settings)
	if !bytes.Equal(before, after) {
		t.Fatal("--print edited the settings file")
	}
	var doc map[string]any
	if err := json.Unmarshal(printed.Bytes(), &doc); err != nil {
		t.Fatalf("--print emitted invalid JSON: %v\n%s", err, printed.String())
	}

	// --uninstall on the install subcommand, and the standalone subcommand,
	// both remove ours and leave theirs.
	out.Reset()
	if err := runInstall([]string{"--settings", settings, "--uninstall"}, &out); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(settings)
	if bytes.Contains(b, []byte(hooks.InstallMarkerValue)) {
		t.Fatalf("--uninstall left our entries: %s", b)
	}
	if !bytes.Contains(b, []byte("other guard")) {
		t.Fatalf("--uninstall took the other tool's hook: %s", b)
	}
	if err := runUninstall([]string{"--settings", settings}, &out); err != nil {
		t.Fatalf("uninstalling twice should be harmless: %v", err)
	}
}

// TestRecoverCommand flushes a pending intent nothing closed.
func TestRecoverCommand(t *testing.T) {
	state := t.TempDir()
	var stdout, stderr bytes.Buffer
	pre := `{"session_id":"ses_cli","hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"sleep 999"}}`
	if code := runCapture([]string{"--state", state}, strings.NewReader(pre), &stdout, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	var out bytes.Buffer
	if err := runRecover([]string{"--state", state, "--older-than", "0"}, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "flushed 1") {
		t.Fatalf("recover reported: %s", out.String())
	}
	completions, _ := spool.ReadAll(filepath.Join(state, hooks.DefaultSpoolDirName))
	if len(completions) != 1 {
		t.Fatalf("recover spooled %d receipts, want the orphan_intent", len(completions))
	}
}
