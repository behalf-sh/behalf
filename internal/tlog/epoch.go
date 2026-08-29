package tlog

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// Epoch fencing (architecture Q57): Tessera's POSIX driver already enforces
// single-appender with an in-process mutex plus a POSIX lock file held per
// operation; behalf's epoch file supplements that upstream guarantee with a
// product-level fence. Every Open claims a strictly increasing epoch and
// records {epoch, pid, started_at}; an older holder discovers it has been
// fenced (the file records a newer epoch than its own) and refuses to
// append or sign promises — only the current lock-holder's key signs
// promises.
const (
	epochFileName = "epoch.json"
	epochLockName = "epoch.lock"
)

// ErrFenced is returned when this log handle's epoch is no longer the
// newest recorded in the epoch file: a newer claimant exists and this
// handle must stop appending and signing promises.
var ErrFenced = errors.New("tlog: fenced: a newer epoch exists for this log dir")

// EpochRecord is the on-disk epoch file content.
type EpochRecord struct {
	Epoch     uint64 `json:"epoch"`
	PID       int    `json:"pid"`
	StartedAt string `json:"started_at"` // RFC 3339 UTC
}

// ReadEpoch returns the current epoch record, or (zero record, nil) if no
// epoch file exists yet.
func ReadEpoch(dir string) (EpochRecord, error) {
	var rec EpochRecord
	b, err := os.ReadFile(filepath.Join(dir, epochFileName))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return rec, nil
		}
		return rec, err
	}
	if err := json.Unmarshal(b, &rec); err != nil {
		return rec, fmt.Errorf("tlog: parse epoch file: %w", err)
	}
	return rec, nil
}

// claimEpoch atomically claims the next epoch for this process: it reads
// the current record under an flock, writes {cur+1, pid, now} via
// temp-file + rename, and returns the claimed record.
func claimEpoch(dir string) (EpochRecord, error) {
	unlock, err := lockEpochFile(dir)
	if err != nil {
		return EpochRecord{}, err
	}
	defer unlock()

	cur, err := ReadEpoch(dir)
	if err != nil {
		return EpochRecord{}, err
	}
	rec := EpochRecord{
		Epoch:     cur.Epoch + 1,
		PID:       os.Getpid(),
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	if err := writeEpoch(dir, rec); err != nil {
		return EpochRecord{}, err
	}
	return rec, nil
}

// checkEpoch returns ErrFenced if the epoch file no longer records mine.
func checkEpoch(dir string, mine uint64) error {
	cur, err := ReadEpoch(dir)
	if err != nil {
		return err
	}
	if cur.Epoch != mine {
		return fmt.Errorf("%w (mine=%d, current=%d pid=%d)", ErrFenced, mine, cur.Epoch, cur.PID)
	}
	return nil
}

func writeEpoch(dir string, rec EpochRecord) error {
	b, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := filepath.Join(dir, epochFileName+".tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(dir, epochFileName))
}

// lockEpochFile flocks dir/epoch.lock for the duration of a claim.
func lockEpochFile(dir string) (func(), error) {
	f, err := os.OpenFile(filepath.Join(dir, epochLockName), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("tlog: flock epoch: %w", err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
