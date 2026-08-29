package tlog

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/tessera"
	"golang.org/x/mod/sumdb/note"

	"github.com/behalf-sh/behalf/internal/witness"
)

// Witnessing, wired into the log (architecture D3.5, Q29, Q76, Q96).
//
// # The availability mode, written down
//
// Q96 asks for one thing above the mechanism: that the availability mode be
// documented as an availability mode. It is this.
//
// **v1 policy is FailOpen: true.** A witness that is down, slow, or
// refusing never blocks publication — and under fail-open it cannot,
// structurally, because witnessing happens *after* the checkpoint is
// published, not before it. Publication does not depend on a network whose
// production tier does not exist (witness-network.org: testing and staging
// tiers only). The self-run witness in a separate cloud account is the
// quorum-of-one that makes the split-view defence real today.
//
// What fail-open costs, stated plainly: between publication and
// cosignature, a checkpoint carries only the log's own signature, so during
// that window the split-view and stale-restore defences are not in force
// for that checkpoint. What fail-open does NOT do is hide the gap: every
// checkpoint gets a witness record (witness/outcomes.jsonl) naming the
// outcome and the reason, so "we published without a cosignature" is a
// fact in the record rather than an absence in it. A refusal in particular
// is recorded, logged at error level by the witness, and surfaced by
// `behalf-log witness` as a non-zero exit with the verifier's own class
// vocabulary — because a refusal is the single most important signal the
// system can produce.
//
// **FailOpen: false** is implemented and is not the v1 default. It engages
// Tessera's own blocking path (AppendOptions.WithWitnesses with
// tessera.WitnessOptions{FailOpen: false}): no quorum, no published
// checkpoint. The posture tightens to this once a real witness network is
// available (Q96, D3.5). The per-checkpoint record is written in both modes
// and carries `fail_open`, so a reader can always tell which posture
// produced a given checkpoint.
//
// # Why behalf submits rather than only handing the job to Tessera
//
// Tessera's fail-open path logs and forgets: `klog.Warningf`, no return
// value, no record. Under FailOpen:true that is exactly the signal Q96 says
// matters, thrown away. behalf therefore does its own submission after
// publication and records the outcome per checkpoint. In fail-closed mode
// Tessera does the blocking submission and behalf's pass observes the
// result — it sees the cosignature already on the published note and
// records `cosigned` without re-submitting.

// Witness policy defaults. Both are explicit configuration; these are the
// documented values used when the config says nothing.
const (
	// DefaultWitnessFailOpen is Q96's v1 policy.
	DefaultWitnessFailOpen = true
	// DefaultWitnessTimeout bounds one witnessing pass. Chosen against the
	// 1 s checkpoint cadence (D3.3) and the 10 s MMD (Q57): a witness pass
	// must finish well inside the interval that produced it, or passes pile
	// up. Note that Tessera's own DefaultWitnessTimeout is 5 s at v1.0.4
	// (D3.5 records 1 s; the source disagrees) — behalf sets its own rather
	// than inheriting either.
	DefaultWitnessTimeout = 1 * time.Second
	// WitnessConfigFileName is the witness policy inside the log dir.
	WitnessConfigFileName = "witnesses.json"
	// WitnessDirName holds the per-checkpoint witness records.
	WitnessDirName = "witness"
	// WitnessOutcomesFileName is the append-only per-checkpoint record.
	WitnessOutcomesFileName = "outcomes.jsonl"
	// WitnessedCheckpointFileName is the latest published checkpoint with
	// the cosignatures behalf holds appended to it, so an export can carry
	// the cosignature alongside the checkpoint. Verifiers that do not know
	// the witness key skip the extra line (D3.4's grease discipline).
	WitnessedCheckpointFileName = "checkpoint.witnessed"
)

// WitnessPolicy is the log's witnessing configuration. It lives at
// <log dir>/witnesses.json and is loaded at Open; Options.Witness overrides
// it in process.
type WitnessPolicy struct {
	// FailOpen: publish checkpoints even when the witness policy cannot be
	// satisfied. Defaults to DefaultWitnessFailOpen (true) when nil.
	FailOpen *bool `json:"fail_open,omitempty"`
	// TimeoutMS bounds one witnessing pass. Zero takes
	// DefaultWitnessTimeout.
	TimeoutMS int64 `json:"timeout_ms,omitempty"`
	// Quorum is how many witnesses must cosign for the policy to be
	// satisfied. Zero means all of them.
	Quorum int `json:"quorum,omitempty"`
	// Witnesses is the configured witness set. Empty disables witnessing
	// entirely, which is recorded as such rather than silently skipped.
	Witnesses []witness.Ref `json:"witnesses"`
}

// FailOpenValue resolves the fail-open policy, applying the default.
func (p *WitnessPolicy) FailOpenValue() bool {
	if p == nil || p.FailOpen == nil {
		return DefaultWitnessFailOpen
	}
	return *p.FailOpen
}

// Timeout resolves the pass timeout, applying the default.
func (p *WitnessPolicy) Timeout() time.Duration {
	if p == nil || p.TimeoutMS <= 0 {
		return DefaultWitnessTimeout
	}
	return time.Duration(p.TimeoutMS) * time.Millisecond
}

// QuorumValue resolves the quorum, applying the "all of them" default.
func (p *WitnessPolicy) QuorumValue() int {
	if p == nil {
		return 0
	}
	if p.Quorum <= 0 || p.Quorum > len(p.Witnesses) {
		return len(p.Witnesses)
	}
	return p.Quorum
}

// Enabled reports whether any witness is configured.
func (p *WitnessPolicy) Enabled() bool { return p != nil && len(p.Witnesses) > 0 }

// WitnessConfigPath is where LoadWitnessPolicy looks.
func WitnessConfigPath(dir string) string { return filepath.Join(dir, WitnessConfigFileName) }

// LoadWitnessPolicy reads <dir>/witnesses.json. A missing file is not an
// error: it means no witnesses are configured, which is a legal (and
// recorded) state.
func LoadWitnessPolicy(dir string) (*WitnessPolicy, error) {
	b, err := os.ReadFile(WitnessConfigPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tlog: read witness policy: %w", err)
	}
	var p WitnessPolicy
	if err := json.Unmarshal(b, &p); err != nil {
		return nil, fmt.Errorf("tlog: parse %s: %w", WitnessConfigPath(dir), err)
	}
	for i, ref := range p.Witnesses {
		if ref.URL == "" || ref.VKey == "" {
			return nil, fmt.Errorf("tlog: %s: witness %d needs both url and vkey", WitnessConfigPath(dir), i)
		}
	}
	return &p, nil
}

// SaveWitnessPolicy writes <dir>/witnesses.json.
func SaveWitnessPolicy(dir string, p *WitnessPolicy) error {
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(WitnessConfigPath(dir), append(b, '\n'), 0o644)
}

// WitnessRecord is one checkpoint's witness outcome — the per-checkpoint
// record Q96 asks for. One line of witness/outcomes.jsonl.
type WitnessRecord struct {
	Time   string `json:"time"`
	Origin string `json:"origin"`
	Size   uint64 `json:"size"`
	Root   string `json:"root"` // lowercase hex
	// Outcome is the aggregate: `cosigned` (quorum met), `refused` (at
	// least one witness applied the safety rule and said no — this
	// dominates, because it is a finding about the log), `not-cosigned`
	// (quorum not met, no refusal), or `no-witnesses` (none configured).
	Outcome string `json:"outcome"`
	// Class and Reason carry the refusal in the verifier's vocabulary
	// (docs/export-format-v1.md): class `truncation` or `chain`, reason
	// `smaller-size`, `same-size-different-root` or `inconsistent-proof`.
	Class  string `json:"class,omitempty"`
	Reason string `json:"reason,omitempty"`
	// Detail says why, in words, whenever the outcome is not `cosigned`.
	Detail string `json:"detail,omitempty"`
	// FailOpen, TimeoutMS and Quorum record the policy this checkpoint was
	// published under, so the record is self-describing years later.
	FailOpen  bool  `json:"fail_open"`
	TimeoutMS int64 `json:"timeout_ms"`
	Quorum    int   `json:"quorum"`
	// Cosigned counts witnesses that cosigned this checkpoint.
	Cosigned int `json:"cosigned"`
	// Witnesses is the per-witness detail, cosignatures included.
	Witnesses []witness.Result `json:"witnesses,omitempty"`
}

// Cosignatures returns the note signature lines held for this checkpoint.
func (r *WitnessRecord) Cosignatures() []string {
	var out []string
	for _, w := range r.Witnesses {
		if w.Outcome == witness.OutcomeCosigned && w.Cosignature != "" {
			out = append(out, w.Cosignature)
		}
	}
	return out
}

// WitnessOutcomesPath is the per-checkpoint record file for a log dir.
func WitnessOutcomesPath(dir string) string {
	return filepath.Join(dir, WitnessDirName, WitnessOutcomesFileName)
}

// WitnessedCheckpointPath is the cosigned checkpoint file for a log dir.
func WitnessedCheckpointPath(dir string) string {
	return filepath.Join(dir, WitnessedCheckpointFileName)
}

// ReadWitnessRecords reads every per-checkpoint witness record in a log
// dir, oldest first. A missing file yields no records and no error.
func ReadWitnessRecords(dir string) ([]WitnessRecord, error) {
	b, err := os.ReadFile(WitnessOutcomesPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tlog: read witness records: %w", err)
	}
	var out []WitnessRecord
	dec := json.NewDecoder(bytes.NewReader(b))
	for dec.More() {
		var rec WitnessRecord
		if err := dec.Decode(&rec); err != nil {
			return out, fmt.Errorf("tlog: parse witness record: %w", err)
		}
		out = append(out, rec)
	}
	return out, nil
}

// witnessSubmitter owns the log side of witnessing for one Log handle.
type witnessSubmitter struct {
	dir     string
	policy  *WitnessPolicy
	clients []*witness.Client

	mu       sync.Mutex
	lastSize uint64
	lastRoot string
	seen     bool
}

func newWitnessSubmitter(dir string, policy *WitnessPolicy, httpClient *http.Client) (*witnessSubmitter, error) {
	s := &witnessSubmitter{dir: dir, policy: policy}
	for _, ref := range policy.Witnesses {
		c, err := witness.NewClient(ref, httpClient)
		if err != nil {
			return nil, fmt.Errorf("tlog: witness config: %w", err)
		}
		s.clients = append(s.clients, c)
	}
	return s, nil
}

// submit runs one witnessing pass over the given published checkpoint,
// records the outcome, and returns it. It never returns an error for a
// refusal or an unreachable witness: those are recorded outcomes. An error
// means the pass itself could not be run or recorded.
func (s *witnessSubmitter) submit(ctx context.Context, checkpoint []byte) (*WitnessRecord, error) {
	origin, head, err := witness.ParseCheckpointHead(checkpoint)
	if err != nil {
		return nil, fmt.Errorf("tlog: witnessing: %w", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec := &WitnessRecord{
		Time:      time.Now().UTC().Format(time.RFC3339Nano),
		Origin:    origin,
		Size:      head.Size,
		Root:      head.RootHex(),
		FailOpen:  s.policy.FailOpenValue(),
		TimeoutMS: s.policy.Timeout().Milliseconds(),
		Quorum:    s.policy.QuorumValue(),
	}

	passCtx, cancel := context.WithTimeout(ctx, s.policy.Timeout())
	defer cancel()

	// A checkpoint published through Tessera's blocking path already
	// carries the cosignatures that let it publish; do not ask again.
	existing := existingCosignatures(checkpoint, s.clients)

	proofFn := func(ctx context.Context, from, to uint64) ([][]byte, error) {
		return ConsistencyProof(ctx, s.dir, from, to)
	}
	results := make([]witness.Result, len(s.clients))
	var wg sync.WaitGroup
	for i, c := range s.clients {
		if sig, ok := existing[c.Ref().Name]; ok {
			results[i] = witness.Result{
				Witness: c.Ref().Name, URL: c.Ref().URL,
				Outcome: witness.OutcomeCosigned, Cosignature: sig,
				Detail: "cosignature was already on the published checkpoint",
			}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = c.Submit(passCtx, checkpoint, proofFn)
		}()
	}
	wg.Wait()

	rec.Witnesses = results
	summarize(rec)

	if err := appendWitnessRecord(s.dir, rec); err != nil {
		return rec, err
	}
	if sigs := rec.Cosignatures(); len(sigs) > 0 {
		if err := writeWitnessedCheckpoint(s.dir, checkpoint, sigs); err != nil {
			return rec, err
		}
	}
	s.lastSize, s.lastRoot, s.seen = head.Size, head.RootHex(), true
	return rec, nil
}

// alreadySubmitted reports whether this exact head has already had a
// witnessing pass from this handle, so the background loop does not
// re-submit an unchanged checkpoint every tick.
func (s *witnessSubmitter) alreadySubmitted(size uint64, rootHex string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.seen && s.lastSize == size && s.lastRoot == rootHex
}

// summarize computes the aggregate outcome. A refusal dominates a missing
// quorum: "the witness says this is a different history" is a different
// statement from "the witness did not answer", and collapsing them would
// lose the only signal that matters.
func summarize(rec *WitnessRecord) {
	if len(rec.Witnesses) == 0 {
		rec.Outcome = "no-witnesses"
		rec.Detail = "no witnesses are configured for this log; the split-view and stale-restore defences are not in force"
		return
	}
	var firstRefusal *witness.Result
	var firstProblem *witness.Result
	for i := range rec.Witnesses {
		w := &rec.Witnesses[i]
		switch w.Outcome {
		case witness.OutcomeCosigned:
			rec.Cosigned++
		case witness.OutcomeRefused:
			if firstRefusal == nil {
				firstRefusal = w
			}
		default:
			if firstProblem == nil {
				firstProblem = w
			}
		}
	}
	switch {
	case firstRefusal != nil:
		rec.Outcome = "refused"
		rec.Class = firstRefusal.Class
		rec.Reason = firstRefusal.Reason
		rec.Detail = fmt.Sprintf("witness %s refused: %s", firstRefusal.Witness, firstRefusal.Detail)
	case rec.Cosigned >= rec.Quorum:
		rec.Outcome = "cosigned"
	default:
		rec.Outcome = "not-cosigned"
		detail := fmt.Sprintf("%d of %d required cosignatures", rec.Cosigned, rec.Quorum)
		if firstProblem != nil {
			detail = fmt.Sprintf("%s; witness %s: %s", detail, firstProblem.Witness, firstProblem.Detail)
		}
		rec.Detail = detail
	}
}

// existingCosignatures returns the cosignature lines already present on a
// published checkpoint, keyed by configured witness name.
func existingCosignatures(checkpoint []byte, clients []*witness.Client) map[string]string {
	out := map[string]string{}
	if len(clients) == 0 {
		return out
	}
	verifiers := make([]note.Verifier, 0, len(clients))
	byName := map[string]string{}
	for _, c := range clients {
		verifiers = append(verifiers, c.Verifier())
		byName[c.Verifier().Name()] = c.Ref().Name
	}
	n, err := note.Open(checkpoint, note.VerifierList(verifiers...))
	if err != nil {
		return out
	}
	for _, sig := range n.Sigs {
		if local, ok := byName[sig.Name]; ok {
			out[local] = fmt.Sprintf("— %s %s", sig.Name, sig.Base64)
		}
	}
	return out
}

// appendWitnessRecord appends one record durably. The record file is
// evidence about the log's own publication history, so it is fsynced: a
// refusal that is not on disk after a crash never happened.
func appendWitnessRecord(dir string, rec *WitnessRecord) error {
	wd := filepath.Join(dir, WitnessDirName)
	if err := os.MkdirAll(wd, 0o755); err != nil {
		return fmt.Errorf("tlog: create witness dir: %w", err)
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("tlog: marshal witness record: %w", err)
	}
	f, err := os.OpenFile(WitnessOutcomesPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("tlog: open witness records: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("tlog: write witness record: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("tlog: fsync witness record: %w", err)
	}
	return nil
}

// writeWitnessedCheckpoint writes the published checkpoint with the
// cosignature lines appended, atomically.
func writeWitnessedCheckpoint(dir string, checkpoint []byte, sigs []string) error {
	out := make([]byte, 0, len(checkpoint)+len(sigs)*128)
	out = append(out, checkpoint...)
	if len(out) > 0 && out[len(out)-1] != '\n' {
		out = append(out, '\n')
	}
	for _, s := range sigs {
		out = append(out, s...)
		out = append(out, '\n')
	}
	path := WitnessedCheckpointPath(dir)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o644); err != nil {
		return fmt.Errorf("tlog: write witnessed checkpoint: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("tlog: rename witnessed checkpoint: %w", err)
	}
	return nil
}

// tesseraWitnessGroup builds Tessera's own witness policy from behalf's
// config. Used only in fail-closed mode, where publication must block on
// quorum — the one thing behalf's post-publication pass structurally
// cannot do.
//
// It goes through Tessera's Sigsum-format policy parser rather than
// NewWitnessGroup because that constructor is variadic over an unexported
// interface, so a slice of witnesses cannot be spread into it from outside
// the package. The policy text is the supported public route.
func tesseraWitnessGroup(p *WitnessPolicy) (tessera.WitnessGroup, error) {
	var b strings.Builder
	names := make([]string, 0, len(p.Witnesses))
	for i, ref := range p.Witnesses {
		if _, err := url.Parse(ref.URL); err != nil {
			return tessera.WitnessGroup{}, fmt.Errorf("tlog: witness %q url: %w", ref.Name, err)
		}
		name := fmt.Sprintf("w%d", i)
		names = append(names, name)
		fmt.Fprintf(&b, "witness %s %s %s\n", name, strings.TrimSpace(ref.VKey), ref.URL)
	}
	fmt.Fprintf(&b, "group behalf-quorum %d %s\n", p.QuorumValue(), strings.Join(names, " "))
	b.WriteString("quorum behalf-quorum\n")
	group, err := tessera.NewWitnessGroupFromPolicy([]byte(b.String()))
	if err != nil {
		return tessera.WitnessGroup{}, fmt.Errorf("tlog: witness policy: %w", err)
	}
	return group, nil
}

// WitnessCheckpoint runs one witnessing pass over the log's currently
// published checkpoint and returns the per-checkpoint record. It is the
// explicit form of what the background pass does, exposed so an operator
// (and the tamper suite) can submit on demand.
func (l *Log) WitnessCheckpoint(ctx context.Context) (*WitnessRecord, error) {
	if l.wit == nil {
		return nil, fmt.Errorf("tlog: no witnesses configured for %s", l.dir)
	}
	cp, err := l.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("tlog: read checkpoint for witnessing: %w", err)
	}
	return l.wit.submit(ctx, cp)
}

// WitnessDir submits the currently published checkpoint of the log in dir
// to its configured witnesses, without opening an appender (so it never
// fences the running log service — Q57). This is the path
// `behalf-log witness` uses.
func WitnessDir(ctx context.Context, dir string, policy *WitnessPolicy) (*WitnessRecord, error) {
	if policy == nil {
		var err error
		policy, err = LoadWitnessPolicy(dir)
		if err != nil {
			return nil, err
		}
	}
	if !policy.Enabled() {
		return nil, fmt.Errorf("tlog: no witnesses configured for %s (write %s)", dir, WitnessConfigPath(dir))
	}
	// Verify our own checkpoint before offering it to anyone.
	cp, err := ParseLogCheckpoint(ctx, dir)
	if err != nil {
		return nil, err
	}
	s, err := newWitnessSubmitter(dir, policy, nil)
	if err != nil {
		return nil, err
	}
	return s.submit(ctx, cp.Raw)
}

// witnessLoop submits each newly published checkpoint. It runs only while
// the log handle is open; publication never waits for it (Q96).
func (l *Log) witnessLoop(ctx context.Context) {
	interval := l.witInterval
	if interval <= 0 {
		interval = DefaultCheckpointInterval
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			l.witnessPass(ctx)
		}
	}
}

func (l *Log) witnessPass(ctx context.Context) {
	cp, err := l.ReadCheckpoint(ctx)
	if err != nil {
		return
	}
	_, head, err := witness.ParseCheckpointHead(cp)
	if err != nil {
		return
	}
	if l.wit.alreadySubmitted(head.Size, head.RootHex()) {
		return
	}
	// Errors here are recorded outcomes, not failures of the log: nothing
	// upstream of this call can be blocked by a witness (Q96).
	_, _ = l.wit.submit(ctx, cp)
}
