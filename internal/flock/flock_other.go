//go:build !unix

package flock

import "os"

// Without flock there is no way to tell a live file from an abandoned one,
// so every file reads as unlocked: spool recovery may flush an in-flight
// call as an orphan_intent, and two concurrent proxies may draw the same
// emitter counter. behalf v1 targets POSIX (D1's deployment gates name
// ext4/ZFS/CephFS on Linux, with macOS for development); this stub exists
// to keep the tree compiling elsewhere, not to support it.

// Lock is a held advisory lock (a no-op on this platform).
type Lock struct{}

// Acquire always succeeds without excluding anyone.
func Acquire(*os.File) (*Lock, error) { return &Lock{}, nil }

// TryLock always succeeds without excluding anyone.
func TryLock(*os.File) (*Lock, error) { return &Lock{}, nil }

// Release does nothing.
func (l *Lock) Release() {}
