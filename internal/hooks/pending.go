package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// The pending-intent store is Q4's attempt contract, adapted to a surface
// whose process lifetime is one event.
//
// The proxy spools the intent and keeps the pending call in memory until the
// response arrives. A hook cannot: `PreToolUse` and `PostToolUse` are separate
// processes, and the second has to find what the first wrote. So the intent is
// durable on disk — fsync'd before the hook exits, which is before the tool
// runs — and the later event claims it.
//
// Why not the spool. Writing these as `spool.Intent` records would put them in
// front of the proxy's orphan recovery, which any `behalf-log drain` runs over
// the spool it is given: hook-observed crossings would come back as
// `mcp-proxy`-surface `orphan_intent` receipts. The spool this surface writes
// therefore holds completions only, and the pending store is its own thing.
//
// Layout, under <state>/hook-pending/:
//
//	<key>/<ulid>.json    one unclaimed intent
//
// <key> buckets by (session, tool call) so the same tool called twice with the
// same arguments in one session keeps two distinct intents; the ULID file name
// sorts them, and a claim takes the oldest.

// PendingDirName is the pending-intent store under the state directory.
const PendingDirName = "hook-pending"

// Pending is one durably-recorded intent awaiting its completion.
//
// Every field is a capture-time fact that cannot be recovered later
// (receipt-schema-v1.md §9): the counter that was allocated, the policy that
// classified the call, the run grouping and its provenance, the step key, and
// the CAS addresses of the bytes the crossing committed to.
type Pending struct {
	IntentID     string `json:"intent_id"`
	IntentDigest string `json:"intent_digest"`

	SessionID string `json:"session_id"`
	ToolUseID string `json:"tool_use_id,omitempty"`

	Operation   string `json:"operation"`               // normalised name (dedup.go)
	RawToolName string `json:"raw_tool_name,omitempty"` // Claude Code's spelling
	MCPServer   string `json:"mcp_server,omitempty"`    // self-reported label (Q16)
	Target      string `json:"target,omitempty"`

	AgentID   string `json:"agent_id,omitempty"`
	AgentType string `json:"agent_type,omitempty"`

	CapturedAt      string `json:"captured_at"`
	EmitterJKT      string `json:"emitter_jkt"`
	EmitterCounter  int    `json:"emitter_counter"`
	RunID           string `json:"run_id"`
	RunIDProvenance string `json:"run_id_provenance"`
	StepKey         string `json:"step_key,omitempty"`
	RiskClass       string `json:"risk_class"`
	RiskPolicyDig   string `json:"risk_policy_digest"`

	InputDigest string `json:"input_digest,omitempty"`
	InputSize   int    `json:"input_size,omitempty"`
	FrameDigest string `json:"frame_digest,omitempty"`
	FrameSize   int    `json:"frame_size,omitempty"`
	ChainRef    string `json:"chain_ref,omitempty"`
}

// PendingStore is the on-disk pending-intent store.
type PendingStore struct{ dir string }

// NewPendingStore returns the store under a behalf state directory.
func NewPendingStore(stateDir string) *PendingStore {
	return &PendingStore{dir: filepath.Join(stateDir, PendingDirName)}
}

// Dir returns the store's root directory.
func (s *PendingStore) Dir() string { return s.dir }

// pendingKey buckets an intent.
//
// `tool_use_id` is preferred when Claude Code supplies it, because it survives
// an input rewrite: another installed hook can change `tool_input` between
// PreToolUse and execution (D4's `updatedInput` finding), and a content-derived
// key would then miss. Without an id the content key is the only thing both
// events share, and a miss degrades to post-only capture rather than to loss —
// the unclaimed intent is still flushed as `orphan_intent`.
//
// Both keys are always written, because not every event that needs to find an
// intent carries an id — see Put and linkName.
func pendingKey(sessionID, toolUseID, toolName string, input []byte) string {
	h := sha256.New()
	h.Write([]byte(sessionID))
	h.Write([]byte{0})
	if toolUseID != "" {
		h.Write([]byte(toolUseID))
		return hex.EncodeToString(h.Sum(nil))
	}
	h.Write([]byte(toolName))
	h.Write([]byte{0})
	h.Write(input)
	return hex.EncodeToString(h.Sum(nil))
}

// linkExt marks an alias file: a pointer from one bucket to the bucket that
// actually holds the record.
const linkExt = ".link"

// Put durably records p under the key for this event. It returns only after
// the bytes are on the platter: the tool runs after the hook exits, so this
// fsync is what makes "intent durable before the action" true here.
//
// # Why an alias bucket exists
//
// `PermissionRequest` carries NO `tool_use_id`. That was checked against the
// client's own payload schema in Claude Code 2.1.250 (ENG-33) — the event has
// `tool_name` and `tool_input` and nothing that identifies the tool call.
// `PreToolUse` does carry one, so the intent lands in the id-keyed bucket and a
// later Peek from a permission event, which can only compute the content key,
// looked in a bucket that was always empty.
//
// The consequence was not a crash and not a missing receipt. It was worse than
// either: every `approval` receipt anchored to an intent digest it computed
// itself rather than to the one the tool call recorded, so consent and action
// carried different digests and the Q5 join a reader is told to use silently
// never matched. A blank where the evidence should be is exactly what this
// issue existed to find.
//
// So Put writes the record once, in the id-keyed bucket, and drops a pointer
// file in the content-keyed bucket beside it. The pointer is a hint and is not
// fsync'd: losing it costs the join, which is what the code did before, and
// never costs the record.
func (s *PendingStore) Put(e *Event, p Pending) error {
	key := pendingKey(e.SessionID, e.ToolUseID, e.ToolName, e.ToolInput())
	bucket := filepath.Join(s.dir, key)
	if err := os.MkdirAll(bucket, 0o700); err != nil {
		return fmt.Errorf("hooks: create pending bucket: %w", err)
	}
	if e.ToolUseID != "" {
		alias := filepath.Join(s.dir, pendingKey(e.SessionID, "", e.ToolName, e.ToolInput()))
		if err := os.MkdirAll(alias, 0o700); err == nil {
			_ = os.WriteFile(filepath.Join(alias, p.IntentID+linkExt), []byte(key), 0o600)
		}
	}
	b, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("hooks: marshal pending intent: %w", err)
	}
	name := filepath.Join(bucket, p.IntentID+".json")
	if err := writeSync(name, b); err != nil {
		return err
	}
	return syncDir(bucket)
}

// Claim removes and returns the oldest unclaimed intent for this event, or nil
// when there is none. Both key shapes are tried, so an event that carries a
// `tool_use_id` still finds an intent recorded before ids were available.
func (s *PendingStore) Claim(e *Event) (*Pending, error) {
	keys := []string{pendingKey(e.SessionID, e.ToolUseID, e.ToolName, e.ToolInput())}
	if e.ToolUseID != "" {
		keys = append(keys, pendingKey(e.SessionID, "", e.ToolName, e.ToolInput()))
	}
	for _, key := range keys {
		for _, bucket := range s.followLinks(filepath.Join(s.dir, key)) {
			p, err := s.claimBucket(bucket)
			if err != nil {
				return nil, err
			}
			if p != nil {
				return p, nil
			}
		}
	}
	return nil, nil
}

// Peek returns the oldest unclaimed intent for this event WITHOUT consuming
// it, or nil when there is none.
//
// An `approval` needs the intent's facts — its digest, its counter's sibling
// step key, the class the policy assigned — but must not take it: the tool is
// about to run, and PostToolUse is the event that closes the crossing. Only a
// denial claims, because after a denial nothing else will.
func (s *PendingStore) Peek(e *Event) (*Pending, error) {
	keys := []string{pendingKey(e.SessionID, e.ToolUseID, e.ToolName, e.ToolInput())}
	if e.ToolUseID != "" {
		keys = append(keys, pendingKey(e.SessionID, "", e.ToolName, e.ToolInput()))
	}
	for _, key := range keys {
		for _, bucket := range s.followLinks(filepath.Join(s.dir, key)) {
			p, err := s.readBucket(bucket)
			if err != nil || p != nil {
				return p, err
			}
		}
	}
	return nil, nil
}

// followLinks returns the buckets to search for a key: the bucket itself,
// then whatever buckets its pointer files name. Pointers are followed one hop
// only — an alias never points at another alias.
func (s *PendingStore) followLinks(bucket string) []string {
	out := []string{bucket}
	ents, err := os.ReadDir(bucket)
	if err != nil {
		return out
	}
	seen := map[string]bool{bucket: true}
	for _, ent := range ents {
		if ent.IsDir() || filepath.Ext(ent.Name()) != linkExt {
			continue
		}
		target, err := os.ReadFile(filepath.Join(bucket, ent.Name()))
		if err != nil {
			continue
		}
		dir := filepath.Join(s.dir, string(target))
		if names, err := jsonFiles(dir); err == nil && len(names) == 0 {
			// The record this pointer named is gone — claimed, or swept. The
			// pointer is dead, and leaving it behind would keep an empty alias
			// bucket alive forever.
			_ = os.Remove(filepath.Join(bucket, ent.Name()))
			continue
		}
		if !seen[dir] {
			seen[dir] = true
			out = append(out, dir)
		}
	}
	_ = os.Remove(bucket) // best effort: an alias bucket with nothing left in it
	return out
}

// readBucket returns the oldest intent in a bucket without removing it.
func (s *PendingStore) readBucket(bucket string) (*Pending, error) {
	names, err := jsonFiles(bucket)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	b, err := os.ReadFile(filepath.Join(bucket, names[0]))
	if err != nil {
		return nil, nil
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, nil
	}
	return &p, nil
}

func (s *PendingStore) claimBucket(bucket string) (*Pending, error) {
	names, err := jsonFiles(bucket)
	if err != nil || len(names) == 0 {
		return nil, err
	}
	path := filepath.Join(bucket, names[0])
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil // another hook process claimed it first
		}
		return nil, fmt.Errorf("hooks: read pending intent: %w", err)
	}
	var p Pending
	if err := json.Unmarshal(b, &p); err != nil {
		// A pending file we cannot read is evidence we cannot use. Remove it
		// so it does not jam the bucket forever, and say so.
		_ = os.Remove(path)
		return nil, fmt.Errorf("hooks: parse pending intent %s: %w", path, err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("hooks: claim pending intent: %w", err)
	}
	_ = os.Remove(bucket) // best effort: empty buckets go away
	return &p, nil
}

// Sweep removes and returns every unclaimed intent matching the filter, oldest
// first across the whole store. sessionID limits the sweep to one session
// (what SessionEnd wants); an empty sessionID sweeps all. olderThan drops
// anything younger than that age, measured from the recorded capture time; a
// zero duration keeps everything.
func (s *PendingStore) Sweep(sessionID string, olderThan time.Duration, now time.Time) ([]Pending, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("hooks: read pending store: %w", err)
	}
	var out []Pending
	for _, ent := range ents {
		if !ent.IsDir() {
			continue
		}
		bucket := filepath.Join(s.dir, ent.Name())
		names, err := jsonFiles(bucket)
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			path := filepath.Join(bucket, name)
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				continue
			}
			var p Pending
			if json.Unmarshal(b, &p) != nil {
				_ = os.Remove(path)
				continue
			}
			if sessionID != "" && p.SessionID != sessionID {
				continue
			}
			if olderThan > 0 && !olderEnough(p.CapturedAt, olderThan, now) {
				continue
			}
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			out = append(out, p)
		}
		// Pointer files are not records and were never swept as ones; they are
		// dead as soon as the bucket they name is empty, and this is the sweep
		// that makes the store go back to nothing at session end.
		if links, err := os.ReadDir(bucket); err == nil {
			for _, l := range links {
				if !l.IsDir() && filepath.Ext(l.Name()) == linkExt {
					_ = os.Remove(filepath.Join(bucket, l.Name()))
				}
			}
		}
		_ = os.Remove(bucket)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IntentID < out[j].IntentID })
	return out, nil
}

// olderEnough reports whether a recorded capture time is at least age old. An
// unparseable timestamp counts as old: it cannot be dated, and leaving it in
// the store forever would hide a crossing that never got its receipt.
func olderEnough(capturedAt string, age time.Duration, now time.Time) bool {
	t, err := time.Parse(time.RFC3339, capturedAt)
	if err != nil {
		return true
	}
	return now.Sub(t) >= age
}

func jsonFiles(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("hooks: read pending bucket: %w", err)
	}
	var names []string
	for _, e := range ents {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names) // ULID file names sort in mint order
	return names, nil
}

// writeSync writes data atomically and durably: temp file, fsync, rename.
func writeSync(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".pending-*")
	if err != nil {
		return fmt.Errorf("hooks: write pending intent: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("hooks: open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("hooks: fsync dir: %w", err)
	}
	return nil
}
