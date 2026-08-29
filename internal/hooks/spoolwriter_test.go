package hooks

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/spool"
)

// TestCompletionLineIsSpoolsOwnFormat is the drift guard for the one thing
// spoolwriter.go duplicates: the record format. It writes the same completion
// through internal/spool and through this package and compares the bytes.
//
// If internal/spool ever changes its line shape, this fails here rather than
// silently producing a spool the shipped drain cannot read.
func TestCompletionLineIsSpoolsOwnFormat(t *testing.T) {
	const intentID = "01J0000000000000000000INT"
	const receiptID = "01J0000000000000000000RCP"
	env := []byte(`{"payloadType":"application/vnd.behalf.receipt+json","payload":{"a":"b"},"sig":{"keyid":"k","sig":"cw=="}}`)

	dir := t.TempDir()
	sp, _, err := spool.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := sp.AppendCompletion(intentID, receiptID, env); err != nil {
		t.Fatal(err)
	}
	if err := sp.Close(); err != nil {
		t.Fatal(err)
	}
	want := readOnlySegment(t, dir)

	got := completionLine(intentID, receiptID, env)
	if !bytes.Equal(got, want) {
		t.Fatalf("the hook writer's line is not internal/spool's:\n  got  %s\n  want %s", got, want)
	}
}

// TestOneSegmentPerSession: the reason this writer exists. A session of many
// hook invocations must not leave one spool file per invocation.
func TestOneSegmentPerSession(t *testing.T) {
	s := newSession(t)
	for i := 0; i < 6; i++ {
		s.fire(golden(t, "post_tool_use_bash.json"))
	}
	segs := segmentFiles(t, s.spoolDir())
	if len(segs) != 1 {
		t.Fatalf("6 hook invocations left %d segment files (%v): the session must reuse one", len(segs), segs)
	}
	rs, _ := spooled(t, s.spoolDir())
	if len(rs) != 6 {
		t.Fatalf("read back %d receipts, want 6", len(rs))
	}
}

// TestSeparateSessionsGetSeparateSegments, so two Claude Code windows do not
// serialise against one file.
func TestSeparateSessionsGetSeparateSegments(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "post_tool_use_bash.json"))
	other := strings.Replace(string(golden(t, "post_tool_use_bash.json")), goldenSessionID, "ses_OTHER0001", -1)
	s.fire([]byte(other))

	segs := segmentFiles(t, s.spoolDir())
	if len(segs) != 2 {
		t.Fatalf("two sessions left %d segments, want 2", len(segs))
	}
	rs, _ := spooled(t, s.spoolDir())
	if len(rs) != 2 {
		t.Fatalf("read back %d receipts, want 2", len(rs))
	}
}

// TestSpoolHoldsCompletionsOnly is what makes the shipped drain safe against
// this spool: the proxy's orphan recovery runs over whatever spool it is
// given, and finding hook intents there would mint mcp-proxy-surface receipts
// for hook-observed crossings.
func TestSpoolHoldsCompletionsOnly(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "pre_tool_use_mcp.json")) // an intent, deliberately pending
	s.fire(golden(t, "pre_tool_use_bash.json"))
	s.fire(golden(t, "post_tool_use_bash.json"))

	rec, err := spool.Recover(s.spoolDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Orphans) != 0 {
		t.Fatalf("spool.Recover found %d intents in the hook spool: pending intents must not live there", len(rec.Orphans))
	}
	// The pending intent is durable somewhere else, and recoverable there.
	pend := NewPendingStore(s.stateDir)
	swept, err := pend.Sweep("", 0, s.clock)
	if err != nil {
		t.Fatal(err)
	}
	if len(swept) != 1 {
		t.Fatalf("the pending store holds %d intents, want the 1 that never completed", len(swept))
	}
}

// TestAppendAfterDrainStartsANewSegment: a drain that consumed and retired the
// session's segment must not cost the next event its receipt.
func TestAppendAfterDrainStartsANewSegment(t *testing.T) {
	s := newSession(t)
	s.fire(golden(t, "post_tool_use_bash.json"))

	// A drain consumes everything and marks the quiescent segment .done.
	drained := 0
	if _, err := spool.Drain(s.spoolDir(), func(spool.Completion) error { drained++; return nil }); err != nil {
		t.Fatal(err)
	}
	if drained != 1 {
		t.Fatalf("drained %d, want 1", drained)
	}
	if len(segmentFiles(t, s.spoolDir())) != 0 {
		t.Fatal("the consumed segment was not retired")
	}

	// The next event in the same session still lands, in a fresh segment.
	s.fire(golden(t, "post_tool_use_mcp.json"))
	rs, _ := spooled(t, s.spoolDir())
	if len(rs) != 1 {
		t.Fatalf("after a drain, the spool holds %d receipts, want the 1 written since", len(rs))
	}
	drained = 0
	if _, err := spool.Drain(s.spoolDir(), func(spool.Completion) error { drained++; return nil }); err != nil {
		t.Fatal(err)
	}
	if drained != 1 {
		t.Fatalf("the second drain delivered %d receipts, want 1", drained)
	}
}

// segmentFiles lists the live segment files in a spool directory.
func segmentFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), "seg-") && filepath.Ext(e.Name()) == ".jsonl" {
			out = append(out, e.Name())
		}
	}
	return out
}

func readOnlySegment(t *testing.T, dir string) []byte {
	t.Helper()
	segs := segmentFiles(t, dir)
	if len(segs) != 1 {
		t.Fatalf("expected one segment, found %v", segs)
	}
	b, err := os.ReadFile(filepath.Join(dir, segs[0]))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
