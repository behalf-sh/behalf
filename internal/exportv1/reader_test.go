package exportv1_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// buildExport writes a small but real export: a header, n leaves and a signed
// head, all through the writer the log service uses.
func buildExport(t *testing.T, payloads [][]byte) []byte {
	t.Helper()
	k := testkeys.Emitter()
	var buf bytes.Buffer
	w, err := exportv1.NewWriter(&buf, "behalf.sh/log/test", []exportv1.HeaderKey{{JKT: k.JKT, JWK: k.JWK}})
	if err != nil {
		t.Fatal(err)
	}
	signer := exportv1.Signer{KeyID: k.JKT, Private: k.Private}
	for _, p := range payloads {
		if err := w.Append(p, signer); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(signer); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// TestReadRoundTripsTheWriter is the contract that matters: what the log
// service writes, this reads, and the payload spans come back as the exact
// bytes the emitter signed. A reader that produced a re-serialized payload
// would hand the importer bytes whose signature no longer verifies, and the
// resulting log would be quietly unverifiable rather than loudly broken.
func TestReadRoundTripsTheWriter(t *testing.T) {
	payloads := [][]byte{
		[]byte(`{"receipt_id":"r0","amount":1200.00,"nested":{"b":2,"a":1}}`),
		[]byte(`{"receipt_id":"r1","note":"a } brace and a \" quote inside a string"}`),
		[]byte(`{"receipt_id":"r2"}`),
	}
	raw := buildExport(t, payloads)

	ex, err := exportv1.Read(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if ex.LogOrigin != "behalf.sh/log/test" {
		t.Fatalf("log_origin = %q", ex.LogOrigin)
	}
	if len(ex.Keys) != 1 || ex.Keys[0].JKT != testkeys.Emitter().JKT {
		t.Fatalf("header keys = %+v", ex.Keys)
	}
	if len(ex.Leaves) != len(payloads) {
		t.Fatalf("read %d leaves, want %d", len(ex.Leaves), len(payloads))
	}
	for i, leaf := range ex.Leaves {
		if leaf.Index != i {
			t.Fatalf("leaf %d carries index %d", i, leaf.Index)
		}
		// The span rule. Byte equality, not JSON equality: an object whose
		// keys were reordered is equal as JSON and worthless as evidence.
		if !bytes.Equal(leaf.Payload, payloads[i]) {
			t.Fatalf("leaf %d payload came back re-serialized:\n got %s\nwant %s",
				i, leaf.Payload, payloads[i])
		}
		if !dsse.Verify(testkeys.Emitter().Public, exportv1.PayloadTypeReceipt, leaf.Payload, leaf.Sig) {
			t.Fatalf("leaf %d: the signature does not verify over the payload the reader returned", i)
		}
	}
	if ex.Head == nil || ex.Head.Count != len(payloads) {
		t.Fatalf("head = %+v", ex.Head)
	}
	if !dsse.Verify(testkeys.Emitter().Public, exportv1.PayloadTypeChainHead, ex.Head.Bytes, ex.Head.Sig) {
		t.Fatal("the head signature does not verify over the head span the reader returned")
	}
}

// TestReadRefusesLinesThatDescribeThemselvesWrongly: this reader is not the
// verifier and does not try to be, but the one check it does make is the one an
// importer cannot skip. A leaf whose `leaf_hash` does not describe its own
// payload is self-inconsistent before any signature is considered, and
// importing it would put a record into a fresh log under a hash that is not its
// hash.
func TestReadRefusesLinesThatDescribeThemselvesWrongly(t *testing.T) {
	raw := buildExport(t, [][]byte{[]byte(`{"receipt_id":"r0","amount":1200}`)})
	// Edit inside the payload span, exactly the demo's cover-up, without
	// touching leaf_hash.
	tampered := bytes.Replace(raw, []byte(`"amount":1200`), []byte(`"amount":0012`), 1)
	if bytes.Equal(raw, tampered) {
		t.Fatal("the test did not actually edit anything")
	}
	_, err := exportv1.Read(bytes.NewReader(tampered))
	if err == nil {
		t.Fatal("a leaf whose payload no longer hashes to its leaf_hash was accepted")
	}
	if !strings.Contains(err.Error(), "leaf_hash") {
		t.Fatalf("error does not name the inconsistency: %v", err)
	}
}

func TestReadRejectsWhatIsNotAnExport(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"not json", "hello\n"},
		{"json but not an export", "{\"hello\":\"world\"}\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := exportv1.Read(strings.NewReader(tc.in)); err == nil {
				t.Fatal("accepted")
			}
		})
	}

	// A truncated export — every leaf intact, the head line gone — must be
	// refused rather than half-read. Truncation is a tamper class, and an
	// importer that shrugged at it would import a run someone had cut short.
	raw := buildExport(t, [][]byte{[]byte(`{"receipt_id":"r0"}`), []byte(`{"receipt_id":"r1"}`)})
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	truncated := bytes.Join(lines[:len(lines)-1], []byte("\n"))
	_, err := exportv1.Read(bytes.NewReader(append(truncated, '\n')))
	if err == nil {
		t.Fatal("an export with no head line was accepted")
	}
	if !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("error does not name truncation: %v", err)
	}
}

// TestReadRefusesUnknownLineKinds: an unknown *field* is ignored (the greased
// discipline), an unknown *line* is not. A field this reader skips is data it
// does not use; a line it skips is a record it silently drops, and silently
// dropping records is the failure the whole format exists to make detectable.
func TestReadRefusesUnknownLineKinds(t *testing.T) {
	raw := buildExport(t, [][]byte{[]byte(`{"receipt_id":"r0"}`)})
	lines := bytes.Split(bytes.TrimRight(raw, "\n"), []byte("\n"))
	withExtra := bytes.Join([][]byte{
		lines[0],
		lines[1],
		[]byte(`{"kind":"annotation","note":"ignore me"}`),
		lines[2],
	}, []byte("\n"))
	_, err := exportv1.Read(bytes.NewReader(append(withExtra, '\n')))
	if err == nil {
		t.Fatal("an unknown line kind was skipped rather than refused")
	}
	if !strings.Contains(err.Error(), "unknown line kind") {
		t.Fatalf("error does not say what it refused: %v", err)
	}
}
