package witness

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// The witness's durable state. One small JSON file, rewritten atomically on
// every cosignature.
//
// Why a file and not SQLite: the whole state is one row per log origin —
// four scalars and the last cosigned note — and it is written at most once
// per checkpoint (1/s, D3.3). A file that is fsynced, renamed over, and
// whose directory is fsynced afterwards is the smallest thing that survives
// power loss, and the witness is the one component that must never be hard
// to operate (D3.5: a separate cloud account, run by one person). SQLite
// would add a dependency, a schema, and a migration story to a map with one
// entry.
//
// The invariant this file exists to keep: the witness must never forget a
// head it has already cosigned. Record therefore fsyncs the temp file
// before the rename and fsyncs the directory after it, and Cosign persists
// *before* returning the signature. A witness that returned a signature it
// could not remember issuing would cosign a fork after the next restart —
// which is the attack it exists to detect.
const (
	// StateFileName is the witness's state file inside its state dir.
	StateFileName = "witness-state.json"
	// LockFileName is the advisory lock a serving witness holds for the
	// lifetime of the process: one writer per state dir.
	LockFileName = "witness.lock"
	// StateVersion is stamped on the file so a future format change is a
	// visible refusal, never a silent misread.
	StateVersion = "behalf.sh/witness/state/v1"
)

// OriginState is what the witness holds for one log origin.
type OriginState struct {
	// Size and Root are the highest tree head cosigned for this origin.
	Size uint64 `json:"size"`
	Root string `json:"root"` // lowercase hex
	// CosignedAt is when that head was cosigned (RFC 3339 UTC).
	CosignedAt string `json:"cosigned_at"`
	// Cosignatures counts every cosignature issued for this origin,
	// including idempotent re-cosigns of the head already held.
	Cosignatures uint64 `json:"cosignatures"`
	// Checkpoint is the last cosigned checkpoint note, base64 (standard),
	// kept so `behalf-witness show` can print the evidence and so a
	// conflicting submission can be answered with the note the witness
	// actually signed.
	Checkpoint string `json:"checkpoint"`
}

// Head returns the (size, root) pair, or an error if the stored root is
// not a 32-byte hex string.
func (o OriginState) Head() (Head, error) {
	var h Head
	raw, err := hex.DecodeString(o.Root)
	if err != nil || len(raw) != 32 {
		return h, fmt.Errorf("witness: stored root for size %d is not a 32-byte hex hash", o.Size)
	}
	copy(h.Root[:], raw)
	h.Size = o.Size
	return h, nil
}

// CosignedCheckpoint returns the stored cosigned checkpoint note bytes.
func (o OriginState) CosignedCheckpoint() ([]byte, error) {
	if o.Checkpoint == "" {
		return nil, nil
	}
	return base64.StdEncoding.DecodeString(o.Checkpoint)
}

type stateFile struct {
	Version string                  `json:"version"`
	Origins map[string]*OriginState `json:"origins"`
}

// Store is the witness's durable head state.
type Store struct {
	dir string

	mu sync.RWMutex
	st stateFile
}

// OpenStore opens (or creates) the witness state in dir. A state file whose
// version is unknown is refused rather than reinterpreted.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("witness: create state dir: %w", err)
	}
	s := &Store{dir: dir, st: stateFile{Version: StateVersion, Origins: map[string]*OriginState{}}}
	b, err := os.ReadFile(s.path())
	switch {
	case errors.Is(err, os.ErrNotExist):
		return s, nil
	case err != nil:
		return nil, fmt.Errorf("witness: read state: %w", err)
	}
	var loaded stateFile
	if err := json.Unmarshal(b, &loaded); err != nil {
		return nil, fmt.Errorf("witness: parse state %s: %w", s.path(), err)
	}
	if loaded.Version != StateVersion {
		return nil, fmt.Errorf("witness: state %s has version %q, want %q", s.path(), loaded.Version, StateVersion)
	}
	if loaded.Origins == nil {
		loaded.Origins = map[string]*OriginState{}
	}
	for origin, o := range loaded.Origins {
		if _, err := o.Head(); err != nil {
			return nil, fmt.Errorf("witness: state %s, origin %q: %w", s.path(), origin, err)
		}
	}
	s.st = loaded
	return s, nil
}

// Dir returns the state directory.
func (s *Store) Dir() string { return s.dir }

func (s *Store) path() string { return filepath.Join(s.dir, StateFileName) }

// Head returns the head held for origin, and whether the witness has ever
// cosigned for it.
func (s *Store) Head(origin string) (Head, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.st.Origins[origin]
	if !ok {
		return Head{}, false
	}
	h, err := o.Head()
	if err != nil {
		// Cannot happen: OpenStore validates every root, and Record only
		// ever writes 32-byte hashes.
		return Head{}, false
	}
	return h, true
}

// Get returns the full state held for origin.
func (s *Store) Get(origin string) (OriginState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.st.Origins[origin]
	if !ok {
		return OriginState{}, false
	}
	return *o, true
}

// OriginEntry pairs an origin with its state, for listings.
type OriginEntry struct {
	Origin string `json:"origin"`
	OriginState
}

// List returns every origin the witness holds, sorted by origin.
func (s *Store) List() []OriginEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]OriginEntry, 0, len(s.st.Origins))
	for origin, o := range s.st.Origins {
		out = append(out, OriginEntry{Origin: origin, OriginState: *o})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Origin < out[j].Origin })
	return out
}

// Record durably advances the head for origin and stores the cosigned
// checkpoint. It returns only after the new state is on disk.
func (s *Store) Record(origin string, h Head, cosigned []byte, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.st.Origins[origin]
	next := &OriginState{
		Size:         h.Size,
		Root:         h.RootHex(),
		CosignedAt:   at.UTC().Format(time.RFC3339Nano),
		Cosignatures: 1,
		Checkpoint:   base64.StdEncoding.EncodeToString(cosigned),
	}
	if prev != nil {
		next.Cosignatures = prev.Cosignatures + 1
	}
	s.st.Origins[origin] = next
	if err := s.flushLocked(); err != nil {
		// Roll the in-memory head back so it can never be ahead of disk.
		if prev == nil {
			delete(s.st.Origins, origin)
		} else {
			s.st.Origins[origin] = prev
		}
		return err
	}
	return nil
}

// flushLocked writes the state atomically and durably: temp file, fsync,
// rename, fsync of the directory. The caller holds s.mu.
func (s *Store) flushLocked() error {
	b, err := json.MarshalIndent(s.st, "", "  ")
	if err != nil {
		return fmt.Errorf("witness: marshal state: %w", err)
	}
	b = append(b, '\n')

	tmp := s.path() + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("witness: open temp state: %w", err)
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return fmt.Errorf("witness: write temp state: %w", err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return fmt.Errorf("witness: fsync temp state: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("witness: close temp state: %w", err)
	}
	if err := os.Rename(tmp, s.path()); err != nil {
		return fmt.Errorf("witness: rename state: %w", err)
	}
	// Without the directory fsync the rename itself can be lost on power
	// loss, which is exactly the amnesia this file exists to prevent.
	d, err := os.Open(s.dir)
	if err != nil {
		return fmt.Errorf("witness: open state dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("witness: fsync state dir: %w", err)
	}
	return nil
}
