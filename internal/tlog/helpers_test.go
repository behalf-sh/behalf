package tlog

import (
	"context"
	"testing"
)

// openTestLog opens (creating a checkpoint key on first use) a log in dir. It
// lives in the internal test package because witness_test.go needs it there;
// tlog_test.go is an external test package — it imports internal/fixture,
// which now transitively imports this package — and reaches it through
// export_test.go.

// openTestLog creates a fresh log dir with a generated checkpoint key and
// opens it with the production defaults (1 s checkpoint, 250 ms batch).
func openTestLog(t *testing.T, dir string) (*Log, *CheckpointKey) {
	t.Helper()
	key, err := LoadCheckpointKey(dir)
	if err != nil {
		key, err = GenerateCheckpointKey("behalf.sh/log/test")
		if err != nil {
			t.Fatal(err)
		}
		if err := SaveCheckpointKey(dir, key); err != nil {
			t.Fatal(err)
		}
	}
	l, err := Open(context.Background(), dir, key, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return l, key
}
