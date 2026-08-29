package hooks

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The settings file belongs to the user. These tests are about what the
// install helper must NOT do to it.

// existingSettings is a settings file with everything that makes a merge hard:
// keys this code has never heard of, a hook belonging to another tool on an
// event behalf also wants, a hook group that mixes another tool's entry with
// ours, an event behalf does not touch at all, and integers that a careless
// JSON round trip would turn into floats.
const existingSettings = `{
  "$schema": "https://json.schemastore.org/claude-code-settings.json",
  "model": "opus",
  "cleanupPeriodDays": 20,
  "env": {"FOO": "bar"},
  "permissions": {"allow": ["Bash(git status:*)"], "deny": []},
  "someFutureKey": {"nested": {"count": 1000000, "flag": true, "list": [1, 2, 3]}},
  "hooks": {
    "PreToolUse": [
      {"matcher": "Bash", "hooks": [{"type": "command", "command": "other-tool guard --strict"}]}
    ],
    "SessionStart": [
      {"hooks": [{"type": "command", "command": "someone-elses-notifier"}]}
    ]
  }
}
`

func testOptions(dir string) InstallOptions {
	return InstallOptions{Binary: filepath.Join(dir, "bin", "behalf-hook"), StateDir: filepath.Join(dir, "state")}
}

func parseFile(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("the helper left invalid JSON behind: %v\n%s", err, b)
	}
	return doc
}

// TestInstallUninstallRoundTrip is the whole contract in one test: install
// into a populated file, install again, uninstall, and land back exactly where
// we started.
func TestInstallUninstallRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(existingSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	before := parseFile(t, path)

	res, err := Install(path, testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	if res.Created {
		t.Fatal("an existing file was reported as created")
	}
	if len(res.Added) != len(Events) {
		t.Fatalf("added %v, want all %d events", res.Added, len(Events))
	}
	if res.Kept != 2 {
		t.Fatalf("kept %d foreign hook entries, want the 2 that were there", res.Kept)
	}

	after := parseFile(t, path)

	// Every key the user had is still there, byte-value identical — including
	// the integer that a float round trip would have rewritten as 1e+06.
	for k, v := range before {
		if k == "hooks" {
			continue
		}
		if !reflect.DeepEqual(after[k], v) {
			t.Fatalf("key %q changed: %#v -> %#v", k, v, after[k])
		}
	}
	raw, _ := os.ReadFile(path)
	if !bytes.Contains(raw, []byte("1000000")) {
		t.Fatalf("an integer was rewritten by the merge:\n%s", raw)
	}

	// The other tool's hooks survive: the one that shared an event with us,
	// and the one on an event we never touch.
	hooks := after["hooks"].(map[string]any)
	if !hasCommand(hooks["PreToolUse"], "other-tool guard --strict") {
		t.Fatal("the other tool's PreToolUse hook was clobbered")
	}
	if !hasCommand(hooks["SessionStart"], "someone-elses-notifier") {
		t.Fatal("an event behalf does not touch was modified")
	}
	// And ours are on every event we install.
	for _, event := range Events {
		if !hasCommand(hooks[event], InstallMarkerValue) {
			t.Fatalf("no behalf entry on %s", event)
		}
	}
	// Tool-scoped events get a matcher; the rest do not.
	for _, event := range Events {
		group := ourGroup(t, hooks[event])
		_, hasMatcher := group["matcher"]
		if hasMatcher != ToolMatcherEvents[event] {
			t.Fatalf("%s: matcher present = %v, want %v", event, hasMatcher, ToolMatcherEvents[event])
		}
	}

	// Idempotent: installing again changes nothing at all.
	firstBytes, _ := os.ReadFile(path)
	res2, err := Install(path, testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Updated) != len(Events) || len(res2.Added) != 0 {
		t.Fatalf("a second install reported added=%v updated=%v, want all updated", res2.Added, res2.Updated)
	}
	secondBytes, _ := os.ReadFile(path)
	if !bytes.Equal(firstBytes, secondBytes) {
		t.Fatalf("installing twice is not installing once:\n--- first\n%s\n--- second\n%s", firstBytes, secondBytes)
	}

	// Uninstall removes ours and only ours.
	un, err := Uninstall(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(un.Removed) != len(Events) {
		t.Fatalf("removed %v, want all %d events", un.Removed, len(Events))
	}
	if un.Kept != 2 {
		t.Fatalf("kept %d foreign hook entries after uninstall, want 2", un.Kept)
	}
	final := parseFile(t, path)
	if !reflect.DeepEqual(final, before) {
		t.Fatalf("the round trip did not restore the file:\n--- before\n%#v\n--- after\n%#v", before, final)
	}
}

// TestUninstallSpareForeignEntriesInTheSameGroup: a group that holds another
// tool's hook alongside ours keeps theirs and loses only ours.
func TestUninstallSparesForeignEntriesInTheSameGroup(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	opts := testOptions(dir)
	mixed := `{"hooks":{"PreToolUse":[{"matcher":"*","hooks":[` +
		`{"type":"command","command":"other-tool guard"},` +
		`{"type":"command","command":"` + opts.Command() + `"}]}]}}`
	if err := os.WriteFile(path, []byte(mixed), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Uninstall(path); err != nil {
		t.Fatal(err)
	}
	doc := parseFile(t, path)
	hooks := doc["hooks"].(map[string]any)
	if !hasCommand(hooks["PreToolUse"], "other-tool guard") {
		t.Fatal("uninstall took the other tool's hook with it")
	}
	if hasCommand(hooks["PreToolUse"], InstallMarkerValue) {
		t.Fatal("uninstall left our entry behind")
	}
}

// TestUninstallWithNothingInstalled is a no-op on content.
func TestUninstallWithNothingInstalled(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(existingSettings), 0o600); err != nil {
		t.Fatal(err)
	}
	before := parseFile(t, path)
	res, err := Uninstall(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Removed) != 0 {
		t.Fatalf("removed %v from a file with no behalf entries", res.Removed)
	}
	if !reflect.DeepEqual(parseFile(t, path), before) {
		t.Fatal("uninstall changed a file it had nothing to do with")
	}
}

// TestInstallCreatesAMissingFile, directories and all.
func TestInstallCreatesAMissingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "claude", "settings.json")
	res, err := Install(path, testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Created {
		t.Fatal("a missing file was not reported as created")
	}
	doc := parseFile(t, path)
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok || len(hooks) != len(Events) {
		t.Fatalf("the created file does not carry all events: %#v", doc)
	}
}

// TestInstallOnAnEmptyOrGarbageFile: empty is a fresh start, garbage is an
// error rather than a silent overwrite of something the user cares about.
func TestInstallOnAnEmptyOrGarbageFile(t *testing.T) {
	dir := t.TempDir()
	empty := filepath.Join(dir, "empty.json")
	if err := os.WriteFile(empty, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(empty, testOptions(dir)); err != nil {
		t.Fatalf("an empty settings file should install cleanly: %v", err)
	}

	garbage := filepath.Join(dir, "garbage.json")
	if err := os.WriteFile(garbage, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Install(garbage, testOptions(dir)); err == nil {
		t.Fatal("install overwrote a file it could not parse")
	}
	b, _ := os.ReadFile(garbage)
	if string(b) != "{not json" {
		t.Fatal("install modified a file it could not parse")
	}
}

// TestSnippetIsPasteable: --print emits valid JSON carrying every event and
// the marker that makes --uninstall precise.
func TestSnippetIsPasteable(t *testing.T) {
	dir := t.TempDir()
	b, err := Snippet(testOptions(dir))
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("the snippet is not valid JSON: %v\n%s", err, b)
	}
	hooks, ok := doc["hooks"].(map[string]any)
	if !ok || len(hooks) != len(Events) {
		t.Fatalf("the snippet does not carry all events:\n%s", b)
	}
	if !strings.Contains(string(b), InstallMarkerFlag+" "+InstallMarkerValue) {
		t.Fatalf("the snippet carries no uninstall marker:\n%s", b)
	}
}

// TestCommandQuotesPathsWithSpaces, because home directories have them.
func TestCommandQuotesPathsWithSpaces(t *testing.T) {
	cmd := InstallOptions{Binary: "/Applications/My Tools/behalf-hook", StateDir: "/Users/a b/.behalf"}.Command()
	if !strings.Contains(cmd, `"/Applications/My Tools/behalf-hook"`) {
		t.Fatalf("the binary path is unquoted: %s", cmd)
	}
	if !strings.Contains(cmd, `"/Users/a b/.behalf"`) {
		t.Fatalf("the state dir is unquoted: %s", cmd)
	}
}

// hasCommand reports whether an event's groups contain a command containing s.
func hasCommand(v any, s string) bool {
	for _, g := range groupsOf(v) {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		entries, _ := gm["hooks"].([]any)
		for _, e := range entries {
			em, ok := e.(map[string]any)
			if !ok {
				continue
			}
			if cmd, _ := em["command"].(string); strings.Contains(cmd, s) {
				return true
			}
		}
	}
	return false
}

// ourGroup returns the group holding behalf's entry.
func ourGroup(t *testing.T, v any) map[string]any {
	t.Helper()
	for _, g := range groupsOf(v) {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		entries, _ := gm["hooks"].([]any)
		for _, e := range entries {
			if isOurs(e) {
				return gm
			}
		}
	}
	t.Fatal("no behalf group found")
	return nil
}
