//go:build unix

package flock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// Lock is a held advisory lock.
type Lock struct{ fd int }

// Acquire takes an exclusive lock on f, blocking until it is available.
func Acquire(f *os.File) (*Lock, error) {
	fd := int(f.Fd())
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		return nil, fmt.Errorf("flock: lock %s: %w", f.Name(), err)
	}
	return &Lock{fd: fd}, nil
}

// TryLock takes an exclusive lock on f without blocking. It returns
// (nil, nil) when another holder has the lock — the caller's cue that the
// file is live.
func TryLock(f *os.File) (*Lock, error) {
	fd := int(f.Fd())
	err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
	switch {
	case err == nil:
		return &Lock{fd: fd}, nil
	case errors.Is(err, syscall.EWOULDBLOCK), errors.Is(err, syscall.EAGAIN), errors.Is(err, syscall.EACCES):
		return nil, nil
	default:
		return nil, fmt.Errorf("flock: try-lock %s: %w", f.Name(), err)
	}
}

// Release drops the lock. Closing the file would also drop it; releasing
// explicitly keeps the lifetime obvious at the call site.
func (l *Lock) Release() {
	if l == nil {
		return
	}
	_ = syscall.Flock(l.fd, syscall.LOCK_UN)
}
