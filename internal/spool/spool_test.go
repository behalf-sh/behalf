package spool

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testIntent(id, tool string, counter int) Intent {
	return Intent{
		IntentID:        id,
		IntentDigest:    strings.Repeat("a", 64),
		Tool:            tool,
		CapturedAt:      "2026-08-27T10:00:00Z",
		Emitter:         Emitter{JKT: "emitter-jkt", Counter: counter},
		RunID:           "run-1",
		RunIDProvenance: "proxy-session",
		RiskClass:       "low",
		RiskPolicyDig:   strings.Repeat("b", 64),
	}
}

func envelopeFor(receiptID string) []byte {
	return []byte(`{"v":"behalf.sh/envelope/v1","payloadType":"application/vnd.behalf.receipt+json","payload":{"receipt_id":"` +
		receiptID + `","nested":{"brace":"}"},"text":"a \"quoted\" }"},"sig":{"keyid":"k","sig":"c2ln"}}`)
}

// TestRoundTripAndSpanFidelity: completions come back with their envelope
// bytes intact, including braces and escapes inside strings — the drain
// hands those bytes straight to the appender, so a scanner that
// parse-and-reserialized would invalidate every signature.
func TestRoundTripAndSpanFidelity(t *testing.T) {
	dir := t.TempDir()
	s, rec, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Orphans) != 0 {
		t.Fatalf("fresh spool recovered %d orphans", len(rec.Orphans))
	}
	want := envelopeFor("01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err := s.AppendIntent(testIntent("i-1", "orders.search", 0)); err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCompletion("i-1", "01ARZ3NDEKTSV4RRFFQ69G5FAV", want); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("read %d completions, want 1", len(got))
	}
	if !bytes.Equal(got[0].Envelope, want) {
		t.Fatalf("envelope came back changed:\n  want %s\n  got  %s", want, got[0].Envelope)
	}
	if got[0].IntentID != "i-1" || got[0].ReceiptID != "01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Fatalf("completion = %+v", got[0])
	}
}

// TestRecoveryFindsOnlyUnmatchedIntents: a completed intent is not an
// orphan, an uncompleted one in a closed spool is (Q4).
func TestRecoveryFindsOnlyUnmatchedIntents(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i, id := range []string{"done-1", "orphan-1", "done-2"} {
		if err := s.AppendIntent(testIntent(id, "t", i)); err != nil {
			t.Fatal(err)
		}
		if id != "orphan-1" {
			if err := s.AppendCompletion(id, "r-"+id, envelopeFor("01ARZ3NDEKTSV4RRFFQ69G5FA"+string(rune('A'+i)))); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A live writer's unmatched intents are calls in flight, not orphans.
	live, err := Recover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(live.Orphans) != 0 {
		t.Fatalf("recovery claimed %d orphans while the writer is live", len(live.Orphans))
	}

	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rec, err := Recover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Orphans) != 1 || rec.Orphans[0].IntentID != "orphan-1" {
		t.Fatalf("recovered %+v, want just orphan-1", rec.Orphans)
	}
	if rec.Orphans[0].Emitter.Counter != 1 || rec.Orphans[0].RiskClass != "low" {
		t.Fatalf("the recovered intent lost capture-time facts: %+v", rec.Orphans[0])
	}
}

// TestCompletionAcrossRotationIsNotAnOrphan: a call that spans a segment
// rotation is still matched, because completion matching considers every
// scanned segment.
func TestCompletionAcrossRotationIsNotAnOrphan(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendIntent(testIntent("spanning", "t", 0)); err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	if err := s.rotate(); err != nil {
		s.mu.Unlock()
		t.Fatal(err)
	}
	s.mu.Unlock()
	if err := s.AppendCompletion("spanning", "r-1", envelopeFor("01ARZ3NDEKTSV4RRFFQ69G5FAV")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	rec, err := Recover(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Orphans) != 0 {
		t.Fatalf("an intent completed after a rotation was called an orphan: %+v", rec.Orphans)
	}
	if segs, _ := segments(dir); len(segs) != 2 {
		t.Fatalf("expected two segments, got %d", len(segs))
	}
}

// TestDrainConsumesOnceAndMarksDone: a drained record is not re-delivered,
// a fully consumed quiescent segment is marked .done, and a second pass
// over an unchanged spool delivers nothing.
func TestDrainConsumesOnceAndMarksDone(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		id := string(rune('a' + i))
		if err := s.AppendIntent(testIntent(id, "t", i)); err != nil {
			t.Fatal(err)
		}
		if err := s.AppendCompletion(id, "r-"+id, envelopeFor("01ARZ3NDEKTSV4RRFFQ69G5FA"+string(rune('A'+i)))); err != nil {
			t.Fatal(err)
		}
	}

	// While the writer is live: records drain, but the segment is not
	// marked done — a cursor holds the position instead.
	var first []string
	stats, err := Drain(dir, func(c Completion) error {
		first = append(first, c.ReceiptID)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 3 || stats.Done != 0 {
		t.Fatalf("first pass delivered %v, marked %d done", first, stats.Done)
	}

	var second []string
	if _, err := Drain(dir, func(c Completion) error {
		second = append(second, c.ReceiptID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(second) != 0 {
		t.Fatalf("second pass re-delivered %v", second)
	}

	// Once the writer is gone, the consumed segment is renamed.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	stats, err = Drain(dir, func(Completion) error {
		t.Fatal("nothing left to deliver")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stats.Done != 1 {
		t.Fatalf("consumed segment was not marked done: %+v", stats)
	}
	if segs, _ := segments(dir); len(segs) != 0 {
		t.Fatalf(".done segments are still listed: %v", segs)
	}
	ents, _ := os.ReadDir(dir)
	var done int
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), doneSuffix) {
			done++
		}
	}
	if done != 1 {
		t.Fatalf("expected one .done file, found %d", done)
	}
}

// TestDrainStopsAtSinkError: the cursor advances only over records the sink
// accepted, so the failed one is re-delivered next pass (at-least-once —
// Q46 makes duplicates safe, losses are not).
func TestDrainStopsAtSinkError(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		id := string(rune('a' + i))
		if err := s.AppendCompletion(id, "r-"+id, envelopeFor("01ARZ3NDEKTSV4RRFFQ69G5FA"+string(rune('A'+i)))); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	boom := errString("sink is down")
	var delivered []string
	_, err = Drain(dir, func(c Completion) error {
		if c.IntentID == "b" {
			return boom
		}
		delivered = append(delivered, c.IntentID)
		return nil
	})
	if err == nil {
		t.Fatal("drain swallowed the sink error")
	}
	if len(delivered) != 1 || delivered[0] != "a" {
		t.Fatalf("delivered %v before the error", delivered)
	}

	var retry []string
	if _, err := Drain(dir, func(c Completion) error {
		retry = append(retry, c.IntentID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(retry, ",") != "b,c" {
		t.Fatalf("retry delivered %v, want the failed record and everything after it", retry)
	}
}

type errString string

func (e errString) Error() string { return string(e) }

// TestPartialTrailingRecordIsIgnored: a torn last line — a crash between
// the write and the fsync — is not a record, and must not break recovery.
func TestPartialTrailingRecordIsIgnored(t *testing.T) {
	dir := t.TempDir()
	s, _, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.AppendCompletion("a", "r-a", envelopeFor("01ARZ3NDEKTSV4RRFFQ69G5FAV")); err != nil {
		t.Fatal(err)
	}
	name := s.segName
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(`{"type":"completion","intent_id":"torn"`)
	f.Close()

	got, err := ReadAll(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].IntentID != "a" {
		t.Fatalf("read %+v, want only the complete record", got)
	}
	if _, err := Recover(dir); err != nil {
		t.Fatalf("recovery tripped over a torn trailing record: %v", err)
	}
}
