package hooks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// The install helper writes behalf's hook entries into a Claude Code settings
// file.
//
// The file belongs to the user, not to behalf. It routinely holds hooks from
// other tools, keys this code has never heard of, and hand edits. So the merge
// rules are strict:
//
//   - never clobber: other tools' hooks on the same event survive untouched;
//   - preserve unknown keys, at every level;
//   - leave valid JSON behind, always, and never a partially-written file;
//   - be idempotent: installing twice is installing once;
//   - uninstall removes OUR entries and nothing else.
//
// Ours are identified by the marker flag in the command string
// (InstallMarkerFlag). Matching on the binary path would break the moment
// someone renames or moves it, and matching on a substring like "behalf" would
// happily delete a hook belonging to a different behalf tool.
//
// This does not close the hole under it. The settings file is user-scoped, so
// the person being recorded can delete these entries — see the package doc and
// Q74. The install helper is convenience, not enforcement, and pretending
// otherwise by making the entries hard to remove would be theatre.

// DefaultSettingsPath is Claude Code's user settings file.
const DefaultSettingsPath = "~/.claude/settings.json"

// InstallMarkerFlag is written into every command line this helper installs,
// and is how --uninstall finds exactly our entries. The capture path accepts
// and ignores it.
const InstallMarkerFlag = "--installed-by"

// InstallMarkerValue is the marker's stable value.
const InstallMarkerValue = "sh.behalf/hook/v1"

// InstallOptions configures the settings merge.
type InstallOptions struct {
	// Binary is the command Claude Code runs. Required.
	Binary string
	// StateDir, when set, is passed to the capture command so hooks record
	// into the same state directory the proxy and CLI use.
	StateDir string
	// PolicyPath and ChainPath, when set, are passed through.
	PolicyPath string
	ChainPath  string
}

// Command renders the command line Claude Code will run.
func (o InstallOptions) Command() string {
	parts := []string{quoteArg(o.Binary), "capture"}
	if o.StateDir != "" {
		parts = append(parts, "--state", quoteArg(o.StateDir))
	}
	if o.PolicyPath != "" {
		parts = append(parts, "--policy", quoteArg(o.PolicyPath))
	}
	if o.ChainPath != "" {
		parts = append(parts, "--chain", quoteArg(o.ChainPath))
	}
	parts = append(parts, InstallMarkerFlag, InstallMarkerValue)
	return strings.Join(parts, " ")
}

// quoteArg wraps a path in double quotes when it contains whitespace, which is
// what a shell-run hook command needs and what a home directory with a space
// in it makes necessary.
func quoteArg(s string) string {
	if s == "" || !strings.ContainsAny(s, " \t") {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// Snippet renders just behalf's hooks object — what `--print` emits for
// someone who would rather paste it themselves than let a tool edit their
// settings file.
func Snippet(o InstallOptions) ([]byte, error) {
	doc := map[string]any{"hooks": hookEntries(o)}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// hookEntries builds the per-event groups.
func hookEntries(o InstallOptions) map[string]any {
	cmd := o.Command()
	out := map[string]any{}
	for _, event := range Events {
		entry := map[string]any{"type": "command", "command": cmd}
		group := map[string]any{"hooks": []any{entry}}
		if ToolMatcherEvents[event] {
			// Tool-scoped events take a matcher; "*" is every tool, which is
			// the only honest setting for a recorder (Q2: every hook-visible
			// tool execution is a receipt, reads included).
			group["matcher"] = "*"
		}
		out[event] = []any{group}
	}
	return out
}

// InstallResult reports what the merge changed.
type InstallResult struct {
	Path    string
	Added   []string // events that gained our entry
	Updated []string // events whose existing entry we rewrote
	Removed []string // events that lost our entry
	Kept    int      // hook entries belonging to someone else, left alone
	Created bool     // the settings file did not exist
}

// Install merges behalf's hook entries into the settings file at path.
func Install(path string, o InstallOptions) (*InstallResult, error) {
	if o.Binary == "" {
		return nil, errors.New("hooks: install needs the path of the behalf-hook binary")
	}
	return mutateSettings(path, func(doc map[string]any, res *InstallResult) error {
		hooks := childObject(doc, "hooks")
		cmd := o.Command()
		for _, event := range Events {
			groups := groupsOf(hooks[event])
			kept, found := stripOurs(groups)
			entry := map[string]any{"type": "command", "command": cmd}
			group := map[string]any{"hooks": []any{entry}}
			if ToolMatcherEvents[event] {
				group["matcher"] = "*"
			}
			hooks[event] = append(kept, group)
			if found {
				res.Updated = append(res.Updated, event)
			} else {
				res.Added = append(res.Added, event)
			}
		}
		doc["hooks"] = hooks
		res.Kept = countForeignEntries(hooks)
		return nil
	})
}

// Uninstall removes behalf's hook entries and leaves everything else exactly
// as it was.
func Uninstall(path string) (*InstallResult, error) {
	return mutateSettings(path, func(doc map[string]any, res *InstallResult) error {
		raw, ok := doc["hooks"]
		if !ok {
			return nil
		}
		hooks, ok := raw.(map[string]any)
		if !ok {
			return nil
		}
		for event, v := range hooks {
			groups := groupsOf(v)
			kept, found := stripOurs(groups)
			if !found {
				continue
			}
			res.Removed = append(res.Removed, event)
			if len(kept) == 0 {
				// The event array is ours alone: remove the key rather than
				// leaving an empty array behind, which is noise in a file the
				// user reads.
				delete(hooks, event)
				continue
			}
			hooks[event] = kept
		}
		res.Kept = countForeignEntries(hooks)
		if len(hooks) == 0 {
			delete(doc, "hooks")
		} else {
			doc["hooks"] = hooks
		}
		return nil
	})
}

// mutateSettings reads, mutates and atomically rewrites the settings file.
//
// Numbers are decoded as json.Number so an integer the user wrote does not
// come back as 1e+06. Unknown keys survive because the whole document is
// carried as generic values and only the paths we own are touched. The write
// is temp-file-plus-rename, so a crash never leaves a truncated settings file
// — the file Claude Code reads at startup is never half a document.
func mutateSettings(path string, fn func(map[string]any, *InstallResult) error) (*InstallResult, error) {
	full, err := ExpandPath(path)
	if err != nil {
		return nil, err
	}
	res := &InstallResult{Path: full}
	doc := map[string]any{}
	raw, err := os.ReadFile(full)
	switch {
	case err == nil:
		if len(bytes.TrimSpace(raw)) > 0 {
			dec := json.NewDecoder(bytes.NewReader(raw))
			dec.UseNumber()
			if err := dec.Decode(&doc); err != nil {
				return nil, fmt.Errorf("hooks: %s is not a JSON object: %w", full, err)
			}
		}
	case errors.Is(err, os.ErrNotExist):
		res.Created = true
	default:
		return nil, fmt.Errorf("hooks: read %s: %w", full, err)
	}

	if err := fn(doc, res); err != nil {
		return nil, err
	}

	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	out = append(out, '\n')
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return nil, fmt.Errorf("hooks: create settings dir: %w", err)
	}
	if err := writeSync(full, out); err != nil {
		return nil, fmt.Errorf("hooks: write %s: %w", full, err)
	}
	sort.Strings(res.Added)
	sort.Strings(res.Updated)
	sort.Strings(res.Removed)
	return res, nil
}

// ExpandPath resolves "" to the default settings path and a leading ~ to the
// user's home directory.
func ExpandPath(path string) (string, error) {
	if path == "" {
		path = DefaultSettingsPath
	}
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("hooks: resolve home dir: %w", err)
		}
		if path == "~" {
			return home, nil
		}
		return filepath.Join(home, path[2:]), nil
	}
	return path, nil
}

// childObject returns doc[key] as an object, creating it when absent and
// replacing it only when it is present but not an object — in which case the
// user's value is not something we can merge into, and overwriting a
// non-object `hooks` is the least bad option since Claude Code would reject it
// anyway.
func childObject(doc map[string]any, key string) map[string]any {
	if v, ok := doc[key]; ok {
		if m, ok := v.(map[string]any); ok {
			return m
		}
	}
	return map[string]any{}
}

// groupsOf coerces an event's value into a group list. A non-list value is
// preserved as a single element rather than dropped: it is the user's data and
// this code does not understand it well enough to delete it.
func groupsOf(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return append([]any(nil), t...)
	default:
		return []any{t}
	}
}

// stripOurs removes our entries from a group list and reports whether any were
// found. A group that held other hooks alongside ours keeps them and stays;
// only a group emptied by the removal disappears.
func stripOurs(groups []any) (kept []any, found bool) {
	for _, g := range groups {
		gm, ok := g.(map[string]any)
		if !ok {
			kept = append(kept, g)
			continue
		}
		entries, ok := gm["hooks"].([]any)
		if !ok {
			kept = append(kept, g)
			continue
		}
		var keptEntries []any
		for _, e := range entries {
			if isOurs(e) {
				found = true
				continue
			}
			keptEntries = append(keptEntries, e)
		}
		if len(keptEntries) == 0 && len(entries) > 0 {
			continue // the whole group was ours
		}
		if len(keptEntries) != len(entries) {
			gm["hooks"] = keptEntries
		}
		kept = append(kept, gm)
	}
	return kept, found
}

// isOurs reports whether a hook entry was written by this installer.
func isOurs(entry any) bool {
	m, ok := entry.(map[string]any)
	if !ok {
		return false
	}
	cmd, _ := m["command"].(string)
	return strings.Contains(cmd, InstallMarkerFlag+" "+InstallMarkerValue)
}

func countEntries(groups []any) int {
	n := 0
	for _, g := range groups {
		if gm, ok := g.(map[string]any); ok {
			if entries, ok := gm["hooks"].([]any); ok {
				n += len(entries)
				continue
			}
		}
		n++
	}
	return n
}

func countOurs(groups []any) int {
	n := 0
	for _, g := range groups {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		entries, ok := gm["hooks"].([]any)
		if !ok {
			continue
		}
		for _, e := range entries {
			if isOurs(e) {
				n++
			}
		}
	}
	return n
}

// countForeignEntries counts the hook entries in the document that belong to
// someone else — the number the install and uninstall reports promise was left
// untouched.
func countForeignEntries(hooks map[string]any) int {
	n := 0
	for _, v := range hooks {
		groups := groupsOf(v)
		n += countEntries(groups) - countOurs(groups)
	}
	return n
}
