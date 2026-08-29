package hooks

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/behalf-sh/behalf/internal/flock"
	"github.com/behalf-sh/behalf/internal/spool"
)

// A session-scoped appender for internal/spool's on-disk format.
//
// # Why this is not spool.Open
//
// spool.Open scans and locks every segment in the directory to recover
// orphaned intents, and spool.Spool opens a NEW segment on its first append.
// Both are right for a long-lived proxy and wrong here: a hook is one process
// per event, so spool.Open would mean one segment file per tool call and a
// full-directory rescan on every one of them — O(n^2) over a session, on the
// agent's hot path, in a surface whose first requirement is never to make the
// user wait.
//
// So this appends into ONE segment per Claude Code session, reusing it across
// processes under the segment's own advisory lock — which is exactly the
// "live segment drained incrementally by cursor" case internal/spool already
// supports. Everything else is internal/spool's: the file naming, the record
// format, the fsync-before-return durability, and the reader. spool.Drain,
// spool.ReadAll and spool.Recover read what this writes with no changes, and
// spoolwriter_test.go asserts byte-for-byte that a line written here is the
// line spool.AppendCompletion would have written.
//
// The pending-intent store (pending.go) is what keeps this safe: this spool
// holds completions ONLY, so the proxy's orphan recovery — which any
// `behalf-log drain` runs — finds nothing here to mint.

// DefaultSpoolDirName is the hook capture spool under the state directory. It
// is deliberately separate from the proxy's `proxy-spool`: two surfaces, two
// spools, one drain command that works on either.
const DefaultSpoolDirName = "hook-spool"

// segmentPointerPrefix names the file that remembers which segment a session
// is appending to. The leading dot keeps it out of spool.segments(), which
// matches only `seg-*.jsonl`.
const segmentPointerPrefix = ".behalf-hook-session-"

// spoolWriter appends completion records for one session.
type spoolWriter struct {
	dir     string
	session string
	max     int64
}

func newSpoolWriter(dir, session string) *spoolWriter {
	return &spoolWriter{dir: dir, session: session, max: spool.DefaultSegmentMaxBytes}
}

// appendCompletion durably spools a signed receipt envelope. The envelope
// bytes are spliced in verbatim — the span rule: the bytes the emitter signed
// are the bytes the drain appends (export-format-v1.md §1.2).
func (w *spoolWriter) appendCompletion(intentID, receiptID string, env []byte) error {
	line := completionLine(intentID, receiptID, env)
	if err := os.MkdirAll(w.dir, 0o700); err != nil {
		return fmt.Errorf("hooks: create spool dir: %w", err)
	}
	// Two attempts: the first may lose a race with a drain that renamed the
	// segment to .done between the open and the lock. The second runs against
	// a segment this process just created and cannot lose it.
	for attempt := 0; attempt < 2; attempt++ {
		done, err := w.tryAppend(line, attempt > 0)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
	return errors.New("hooks: could not claim a spool segment to append to")
}

// tryAppend appends one line, returning whether it landed. forceNew skips the
// remembered segment and starts a fresh one. A false return with no error
// means "this segment was not usable" — drained away, or full — and the caller
// retries against a new one.
func (w *spoolWriter) tryAppend(line []byte, forceNew bool) (bool, error) {
	name := ""
	if !forceNew {
		name = w.readPointer()
	}
	if name == "" {
		var err error
		if name, err = w.createSegment(); err != nil {
			return false, err
		}
	}
	path := filepath.Join(w.dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil // drained away; the caller retries with a new one
		}
		return false, fmt.Errorf("hooks: open spool segment: %w", err)
	}
	// The lock and the fd have exactly one owner and one release each: an
	// flock is held on a file DESCRIPTOR, so releasing after a close could
	// unlock whatever file that number has since been handed to.
	defer f.Close()

	// Blocking, not TryLock: a parallel tool call means a parallel hook
	// process, and the second one must wait rather than lose its receipt.
	lock, err := flock.Acquire(f)
	if err != nil {
		return false, fmt.Errorf("hooks: lock spool segment: %w", err)
	}
	defer lock.Release()

	// The lock is held now, so a drain can no longer rename this file. If it
	// already did, between our open and our lock, the fd points at a consumed
	// file and anything appended to it would never be delivered.
	if !stillNamed(f, path) {
		return false, nil
	}
	fi, err := f.Stat()
	if err != nil {
		return false, err
	}
	if fi.Size() > 0 && fi.Size()+int64(len(line)) > w.max {
		return false, nil // rotate: the retry creates the next segment
	}
	if _, err := f.Write(line); err != nil {
		return false, fmt.Errorf("hooks: write spool segment: %w", err)
	}
	// The durability custody begins at (Q48): the signed receipt is on the
	// platter before this process exits.
	if err := f.Sync(); err != nil {
		return false, fmt.Errorf("hooks: fsync spool segment: %w", err)
	}
	return true, nil
}

// stillNamed reports whether path still refers to the open file.
func stillNamed(f *os.File, path string) bool {
	onDisk, err := os.Stat(path)
	if err != nil {
		return false
	}
	open, err := f.Stat()
	if err != nil {
		return false
	}
	return os.SameFile(onDisk, open)
}

func (w *spoolWriter) pointerPath() string {
	h := sha256.Sum256([]byte(w.session))
	return filepath.Join(w.dir, segmentPointerPrefix+hex.EncodeToString(h[:8]))
}

func (w *spoolWriter) readPointer() string {
	b, err := os.ReadFile(w.pointerPath())
	if err != nil {
		return ""
	}
	name := string(trimSpace(b))
	// Only ever trust a plain segment file name from our own directory.
	if filepath.Base(name) != name || !isSegmentName(name) {
		return ""
	}
	return name
}

func isSegmentName(name string) bool {
	return len(name) > len("seg-.jsonl") &&
		name[:4] == "seg-" &&
		filepath.Ext(name) == ".jsonl"
}

// createSegment opens a fresh segment, fsyncs the directory entry so a crash
// never leaves a segment the reader cannot find, and remembers it.
func (w *spoolWriter) createSegment() (string, error) {
	name := newSegmentName()
	f, err := os.OpenFile(filepath.Join(w.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", fmt.Errorf("hooks: create spool segment: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	if err := syncDir(w.dir); err != nil {
		return "", err
	}
	if err := writeSync(w.pointerPath(), []byte(name+"\n")); err != nil {
		return "", err
	}
	return name, nil
}

// newSegmentName matches internal/spool's scheme: lexicographic order is
// creation order, and the random suffix keeps concurrent writers apart.
func newSegmentName() string {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		panic(fmt.Sprintf("hooks: crypto/rand: %v", err))
	}
	return fmt.Sprintf("seg-%020d-%s.jsonl", time.Now().UTC().UnixNano(), hex.EncodeToString(suffix[:]))
}

// completionLine builds internal/spool's completion record. The envelope is
// spliced in verbatim, never re-marshaled.
func completionLine(intentID, receiptID string, env []byte) []byte {
	var line []byte
	line = append(line, `{"type":"`...)
	line = append(line, spool.TypeCompletion...)
	line = append(line, `","intent_id":`...)
	line = appendJSONString(line, intentID)
	line = append(line, `,"receipt_id":`...)
	line = appendJSONString(line, receiptID)
	line = append(line, `,"envelope":`...)
	line = append(line, env...) // signed bytes, verbatim
	line = append(line, '}', '\n')
	return line
}

func appendJSONString(dst []byte, s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("hooks: marshal string: %v", err))
	}
	return append(dst, b...)
}
