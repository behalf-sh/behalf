// Package spool is the MCP proxy's durable capture spool — the thing that
// makes Q4's intent contract true.
//
// Custody begins at the capture surface (Q48): the proxy stamps a
// per-emitter monotonic counter and spools the INTENT durably before the
// tools/call request is forwarded, then spools the COMPLETION (the signed
// DSSE receipt envelope) once the response is observed. In the common case
// the two merge into one completion receipt; a crash between them leaves an
// intent with no completion, and recovery flushes it as an `orphan_intent`
// receipt carrying the spooled intent digest (Q4, Q5) — the
// payment-fired-agent-died case leaves evidence.
//
// The proxy never appends to the log itself: one appender process per log
// (Q57). A drain moves spool -> log with at-least-once delivery, which is
// safe because ingest dedups on receipt_id (Q46).
//
// # Layout
//
// A spool directory holds append-only segment files:
//
//	seg-<020d unix-nanos>-<8 hex>.jsonl        an active or sealed segment
//	seg-....jsonl.cursor                       bytes consumed by the drain
//	seg-....jsonl.done                         segment fully consumed
//
// One JSON object per line, `\n`-terminated, and every record is fsync'd
// before Append returns — that is the durability the intent contract needs.
// Segment names sort lexicographically in creation order.
//
// # Records
//
//	{"type":"intent","intent_id":…,"intent_digest":…,"tool":…,…}
//	{"type":"completion","intent_id":…,"receipt_id":…,"envelope":{…}}
//
// The completion's envelope is spliced in verbatim, never re-marshaled: the
// signed bytes are the stored bytes (Q27, export-format-v1.md §1.2).
//
// # Liveness and consumption
//
// A writer holds an advisory lock on its own segment for the segment's
// lifetime. Recovery therefore distinguishes a segment another process is
// still writing (skip: its unmatched intents are calls in flight, not
// orphans) from a quiescent one (its unmatched intents are orphans).
// Completion matching always considers every scanned segment, so an intent
// completed after a rotation is still matched.
//
// Consumption uses both mechanisms the brief allows, each where it fits: a
// `.cursor` sidecar records how many bytes of a segment the drain has
// consumed (so a live segment can be drained incrementally and never
// re-delivers), and a fully-consumed quiescent segment is renamed to
// `.done` so recovery need not scan it again. `.done` marking stops at the
// first segment that is not fully consumable, which preserves the
// invariant recovery depends on: if a segment is `.done`, every earlier
// segment is too, so a scanned intent can never have its completion hidden
// inside a `.done` file.
package spool

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"crypto/rand"
	"encoding/hex"

	"github.com/behalf-sh/behalf/internal/flock"
)

// Record types.
const (
	TypeIntent     = "intent"
	TypeCompletion = "completion"
)

// File suffixes.
const (
	segPrefix    = "seg-"
	segSuffix    = ".jsonl"
	cursorSuffix = ".cursor"
	doneSuffix   = ".done"
)

// DefaultSegmentMaxBytes rotates a segment once it passes this size.
const DefaultSegmentMaxBytes = 8 << 20

// Emitter identifies the capture surface and its monotonic counter (Q48).
// The counter is allocated when the intent is spooled and is carried by
// whichever receipt records that crossing — the completion normally, the
// orphan_intent after a crash — so appended receipts have no counter gaps.
type Emitter struct {
	JKT     string `json:"jkt"`
	Counter int    `json:"counter"`
}

// Intent is the durably-spooled record written before a tools/call is
// forwarded (Q4). Beyond the four capture facts the contract names
// (intent_id, intent_digest, tool, captured_at) plus the emitter stamp, it
// carries exactly what minting a schema-valid `orphan_intent` receipt needs
// after a crash: the capture-time run grouping, step key, risk assignment
// and payload/chain references. All of these are capture-time facts that
// cannot be recovered later (receipt-schema-v1.md §9).
type Intent struct {
	Type            string  `json:"type"`
	IntentID        string  `json:"intent_id"`
	IntentDigest    string  `json:"intent_digest"` // sha256(tool + "\n" + raw params bytes)
	Tool            string  `json:"tool"`
	Target          string  `json:"target,omitempty"`
	CapturedAt      string  `json:"captured_at"` // RFC 3339
	Emitter         Emitter `json:"emitter"`
	RunID           string  `json:"run_id"`
	RunIDProvenance string  `json:"run_id_provenance"`
	StepKey         string  `json:"step_key,omitempty"`
	RiskClass       string  `json:"risk_class"`
	RiskPolicyDig   string  `json:"risk_policy_digest"`
	InputDigest     string  `json:"input_digest,omitempty"` // CAS address of the raw params bytes
	InputSize       int     `json:"input_size,omitempty"`
	ChainRef        string  `json:"chain_ref,omitempty"` // CAS address of the carried chain material
}

// Completion pairs an intent with the signed receipt envelope that closes
// it. Envelope holds the exact DSSE envelope bytes.
type Completion struct {
	IntentID  string
	ReceiptID string
	Envelope  []byte
}

// Spool is an open spool directory with one active segment.
type Spool struct {
	dir string
	max int64

	mu      sync.Mutex
	seg     *os.File
	segName string
	segLock *flock.Lock
	written int64
	closed  bool
}

// Recovery is what Open found: intents in quiescent segments with no
// completion anywhere. The caller mints an `orphan_intent` receipt for each
// and spools it as a completion of its own (Q4).
type Recovery struct {
	Orphans []Intent
}

// Open prepares dir, scans it for orphaned intents, and opens a fresh
// segment for this writer. The returned Recovery is never nil.
func Open(dir string) (*Spool, *Recovery, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, fmt.Errorf("spool: create dir: %w", err)
	}
	rec, err := Recover(dir)
	if err != nil {
		return nil, nil, err
	}
	// The segment is opened lazily, on the first append: a process that
	// only reads — a drain pass, say — leaves no empty segment behind.
	return &Spool{dir: dir, max: DefaultSegmentMaxBytes}, rec, nil
}

// Dir returns the spool directory.
func (s *Spool) Dir() string { return s.dir }

// rotate seals the current segment (if any) and opens a new one. The new
// file and the directory entry are both fsync'd before it is used, so a
// crash never leaves a segment the reader cannot find.
func (s *Spool) rotate() error {
	if s.seg != nil {
		if err := s.seg.Close(); err != nil {
			return err
		}
		s.segLock.Release()
		s.seg, s.segLock = nil, nil
	}
	name := newSegmentName()
	f, err := os.OpenFile(filepath.Join(s.dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("spool: create segment: %w", err)
	}
	lock, err := flock.TryLock(f)
	if err != nil {
		f.Close()
		return fmt.Errorf("spool: lock segment: %w", err)
	}
	if lock == nil {
		f.Close()
		return fmt.Errorf("spool: fresh segment %s is already locked", name)
	}
	if err := syncDir(s.dir); err != nil {
		lock.Release()
		f.Close()
		return err
	}
	s.seg, s.segName, s.segLock, s.written = f, name, lock, 0
	return nil
}

// AppendIntent durably spools an intent record. It returns only after the
// bytes are fsync'd: forwarding the request before this returns would put
// the trust-boundary crossing outside custody (Q4, Q48).
func (s *Spool) AppendIntent(in Intent) error {
	in.Type = TypeIntent
	b, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("spool: marshal intent: %w", err)
	}
	return s.appendLine(append(b, '\n'))
}

// AppendCompletion durably spools the signed receipt envelope that closes
// intentID. The envelope bytes are spliced in verbatim — the span rule.
func (s *Spool) AppendCompletion(intentID, receiptID string, envelope []byte) error {
	var line []byte
	line = append(line, `{"type":"completion","intent_id":`...)
	line = appendJSONString(line, intentID)
	line = append(line, `,"receipt_id":`...)
	line = appendJSONString(line, receiptID)
	line = append(line, `,"envelope":`...)
	line = append(line, envelope...) // signed bytes, verbatim
	line = append(line, '}', '\n')
	return s.appendLine(line)
}

func (s *Spool) appendLine(line []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errors.New("spool: append after close")
	}
	if s.seg == nil || (s.written > 0 && s.written+int64(len(line)) > s.max) {
		if err := s.rotate(); err != nil {
			return err
		}
	}
	if _, err := s.seg.Write(line); err != nil {
		return fmt.Errorf("spool: write %s: %w", s.segName, err)
	}
	// The durability the intent contract rests on: the record is on the
	// platter before the caller proceeds.
	if err := s.seg.Sync(); err != nil {
		return fmt.Errorf("spool: fsync %s: %w", s.segName, err)
	}
	s.written += int64(len(line))
	return nil
}

// Close seals the active segment and releases its lock.
func (s *Spool) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.seg == nil {
		return nil
	}
	err := s.seg.Close()
	s.segLock.Release()
	s.seg, s.segLock = nil, nil
	return err
}

// Recover scans dir and returns the intents that have no completion and
// live in a segment no writer holds open. Intents in a live segment are
// calls in flight, not orphans, and are deliberately left alone.
func Recover(dir string) (*Recovery, error) {
	segs, err := segments(dir)
	if err != nil {
		return nil, err
	}
	completed := map[string]bool{}
	type candidate struct {
		intent Intent
		live   bool
	}
	var candidates []candidate
	for _, seg := range segs {
		live, err := isLive(filepath.Join(dir, seg))
		if err != nil {
			return nil, err
		}
		err = scanSegment(dir, seg, 0, func(_ int64, rec []byte) error {
			typ, err := recordType(rec)
			if err != nil {
				return err
			}
			switch typ {
			case TypeIntent:
				var in Intent
				if err := json.Unmarshal(rec, &in); err != nil {
					return fmt.Errorf("spool: parse intent in %s: %w", seg, err)
				}
				candidates = append(candidates, candidate{intent: in, live: live})
			case TypeCompletion:
				id, err := completionIntentID(rec)
				if err != nil {
					return fmt.Errorf("spool: parse completion in %s: %w", seg, err)
				}
				completed[id] = true
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	rec := &Recovery{}
	for _, c := range candidates {
		if c.live || completed[c.intent.IntentID] {
			continue
		}
		rec.Orphans = append(rec.Orphans, c.intent)
	}
	return rec, nil
}

// DrainStats summarizes one drain pass.
type DrainStats struct {
	Completions int // completion records delivered to the sink
	Segments    int // segments read
	Done        int // segments renamed to .done
}

// Drain delivers every not-yet-consumed completion to sink, in spool
// order, then records how far it got. Delivery is at-least-once: a crash
// between sink success and the cursor write re-delivers, which ingest
// dedups on receipt_id (Q46). A sink error stops the pass with the cursor
// advanced only over records the sink accepted.
func Drain(dir string, sink func(Completion) error) (*DrainStats, error) {
	segs, err := segments(dir)
	if err != nil {
		return nil, err
	}
	stats := &DrainStats{}
	markDone := true // stops at the first segment that is not fully consumable
	for _, seg := range segs {
		stats.Segments++
		path := filepath.Join(dir, seg)
		start, err := readCursor(path)
		if err != nil {
			return stats, err
		}
		consumed := start
		scanErr := scanSegment(dir, seg, start, func(end int64, rec []byte) error {
			typ, err := recordType(rec)
			if err != nil {
				return err
			}
			if typ == TypeCompletion {
				c, err := parseCompletion(rec)
				if err != nil {
					return fmt.Errorf("spool: %s: %w", seg, err)
				}
				if err := sink(c); err != nil {
					return err
				}
				stats.Completions++
			}
			consumed = end
			return nil
		})
		if consumed > start {
			if werr := writeCursor(path, consumed); werr != nil {
				return stats, werr
			}
		}
		if scanErr != nil {
			return stats, scanErr
		}
		// A segment is finished when everything on disk is consumed and no
		// writer can append to it any more.
		live, err := isLive(path)
		if err != nil {
			return stats, err
		}
		fi, err := os.Stat(path)
		if err != nil {
			return stats, err
		}
		finished := !live && consumed == fi.Size()
		if markDone && finished {
			if err := os.Rename(path, path+doneSuffix); err != nil {
				return stats, fmt.Errorf("spool: mark %s consumed: %w", seg, err)
			}
			_ = os.Remove(path + cursorSuffix)
			stats.Done++
			continue
		}
		markDone = false
	}
	return stats, nil
}

// ReadAll returns every completion still in the spool, in spool order,
// without consuming anything or moving any cursor. It is the read-only view
// — what `behalf doctor` and the tests use to look at pending evidence
// without draining it.
func ReadAll(dir string) ([]Completion, error) {
	segs, err := segments(dir)
	if err != nil {
		return nil, err
	}
	var out []Completion
	for _, seg := range segs {
		err := scanSegment(dir, seg, 0, func(_ int64, rec []byte) error {
			typ, err := recordType(rec)
			if err != nil || typ != TypeCompletion {
				return err
			}
			c, err := parseCompletion(rec)
			if err != nil {
				return err
			}
			out = append(out, c)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

// segments lists the spool's live segment files (not .done), sorted in
// creation order.
func segments(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("spool: read dir: %w", err)
	}
	var out []string
	for _, e := range ents {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, segPrefix) || !strings.HasSuffix(n, segSuffix) {
			continue
		}
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

// scanSegment reads seg from byte offset start, calling fn with the end
// offset of each complete record and the record's bytes. A trailing
// partial record (a crash mid-write, which fsync makes unlikely but not
// impossible) is ignored: it is not a complete record and the next drain
// will see it whole or never.
func scanSegment(dir, seg string, start int64, fn func(end int64, rec []byte) error) error {
	f, err := os.Open(filepath.Join(dir, seg))
	if err != nil {
		return fmt.Errorf("spool: open %s: %w", seg, err)
	}
	defer f.Close()
	if start > 0 {
		if _, err := f.Seek(start, io.SeekStart); err != nil {
			return err
		}
	}
	r := bufio.NewReader(f)
	off := start
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			off += int64(len(line))
			rec := line[:len(line)-1]
			if len(rec) > 0 {
				if ferr := fn(off, rec); ferr != nil {
					return ferr
				}
			}
		}
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("spool: read %s: %w", seg, err)
		}
	}
}

func recordType(rec []byte) (string, error) {
	var head struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(rec, &head); err != nil {
		return "", fmt.Errorf("spool: parse record: %w", err)
	}
	return head.Type, nil
}

func completionIntentID(rec []byte) (string, error) {
	var head struct {
		IntentID string `json:"intent_id"`
	}
	if err := json.Unmarshal(rec, &head); err != nil {
		return "", err
	}
	return head.IntentID, nil
}

// parseCompletion pulls the envelope out as its exact byte span, so the
// bytes the emitter signed are the bytes the drain appends.
func parseCompletion(rec []byte) (Completion, error) {
	var head struct {
		IntentID  string `json:"intent_id"`
		ReceiptID string `json:"receipt_id"`
	}
	if err := json.Unmarshal(rec, &head); err != nil {
		return Completion{}, fmt.Errorf("parse completion: %w", err)
	}
	env, err := envelopeSpan(rec)
	if err != nil {
		return Completion{}, err
	}
	return Completion{IntentID: head.IntentID, ReceiptID: head.ReceiptID, Envelope: env}, nil
}

func readCursor(segPath string) (int64, error) {
	b, err := os.ReadFile(segPath + cursorSuffix)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("spool: read cursor: %w", err)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("spool: parse cursor %s: %w", segPath+cursorSuffix, err)
	}
	return n, nil
}

// writeCursor records the consumed byte offset atomically. Losing a cursor
// costs re-delivery, never loss, so it needs no fsync of its own (Q46).
func writeCursor(segPath string, off int64) error {
	path := segPath + cursorSuffix
	tmp, err := os.CreateTemp(filepath.Dir(path), ".cursor-*")
	if err != nil {
		return fmt.Errorf("spool: write cursor: %w", err)
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(strconv.FormatInt(off, 10) + "\n"); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// isLive reports whether some writer still holds path open for appending.
func isLive(path string) (bool, error) {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return false, fmt.Errorf("spool: open %s: %w", path, err)
	}
	defer f.Close()
	lock, err := flock.TryLock(f)
	if err != nil {
		return false, err
	}
	if lock == nil {
		return true, nil
	}
	lock.Release()
	return false, nil
}

// syncDir fsyncs a directory so a newly created segment's name is durable.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("spool: open dir: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("spool: fsync dir: %w", err)
	}
	return nil
}

// newSegmentName sorts lexicographically in creation order and is unique
// across concurrent writers.
func newSegmentName() string {
	var suffix [4]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		panic(fmt.Sprintf("spool: crypto/rand: %v", err))
	}
	return fmt.Sprintf("%s%020d-%s%s", segPrefix, time.Now().UTC().UnixNano(), hex.EncodeToString(suffix[:]), segSuffix)
}

func appendJSONString(dst []byte, s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("spool: marshal string: %v", err))
	}
	return append(dst, b...)
}
