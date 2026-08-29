// Package flock wraps advisory whole-file locks. Two callers need them:
// the capture spool, which marks a segment live for as long as a writer
// holds it open (so recovery can tell "a call is in flight" from "a process
// died mid-call"), and the per-emitter monotonic counter, whose
// read-increment-write must be atomic across concurrent proxy processes
// sharing one state directory (Q48 — a duplicated counter would read as a
// gap that never happened).
//
// Locks are per open file description, so they serialize between processes
// and between two handles in one process alike.
package flock

import (
	"fmt"
	"os"
)

// With runs fn while holding an exclusive lock on path, creating the lock
// file if needed. It blocks until the lock is available.
func With(path string, fn func() error) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("flock: open %s: %w", path, err)
	}
	defer f.Close()
	l, err := Acquire(f)
	if err != nil {
		return err
	}
	defer l.Release()
	return fn()
}
