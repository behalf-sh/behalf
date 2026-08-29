package hooks

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/behalf-sh/behalf/internal/capture"
	"github.com/behalf-sh/behalf/internal/flock"
)

// run_id is populated by normative precedence and every receipt records which
// rung fired, so grouping is honest about its own provenance (Q7,
// receipt-schema-v1.md §6 and §9 item 7).
//
// This surface owns the second rung — "Claude Code session/agent id from
// hooks" — which is the whole reason the enum has a `hook-session` value. The
// session id, not the agent id, is what groups a run: a sub-agent's tool calls
// belong to the session that spawned it, and reconstruction wants the whole
// session in one view (Q82). The agent id rides as an asserted label and in
// correlation, where it can distinguish sub-agent work without splitting the
// run.
//
// The top rung matters for a different reason: BEHALF_RUN_ID is the only thing
// that makes a hook receipt and a proxy receipt agree on a run_id, and the
// cross-surface collapse in dedup.go needs that agreement.

// resolveRunID applies the precedence for one event.
func (c *Capture) resolveRunID(e *Event) (runID, provenance, traceID string) {
	tp := capture.TraceIDFromTraceparent(c.getenv(capture.EnvTraceparent))
	if v := strings.TrimSpace(c.getenv(capture.EnvRunID)); v != "" {
		return v, capture.ProvenanceCaller, tp
	}
	if s := strings.TrimSpace(e.SessionID); s != "" {
		return s, capture.ProvenanceHookSession, tp
	}
	if tp != "" {
		return tp, capture.ProvenanceTraceparent, tp
	}
	// No caller key, no session id, no trace context. The honest last rung is
	// this capture process's own session — the same rung the proxy falls to,
	// and the enum has no other value for it.
	return "hook-" + c.ids.ULIDAt(c.now()), capture.ProvenanceProxySession, ""
}

// OrdinalDirName holds the per-run causal ordinal counters.
const OrdinalDirName = "hook-runs"

// nextOrdinal allocates the causal ordinal for step_key: the position of this
// call in the run (Q85).
//
// The proxy keeps this in a struct field because it is one process for the
// whole session. A hook is a fresh process per tool call, so the ordinal is
// durable per run and allocated under a file lock — the same discipline as the
// emitter counter, for the same reason: two tool calls can be in flight at
// once, and two hook processes must not both be step 7.
//
// The ordinal counts what THIS surface saw. A proxy running beside it counts
// what IT saw, and the two sequences differ whenever one surface sees a call
// the other cannot — which is most of the time, since the hook sees Bash and
// the proxy does not. So step_key aligns a run against itself across days
// (which is what `behalf diff` needs) and does not align a hook receipt to a
// proxy receipt. dedup.go's collapse rule deliberately does not use it.
func (c *Capture) nextOrdinal(runID string) (int, error) {
	dir := filepath.Join(c.state, OrdinalDirName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return 0, fmt.Errorf("hooks: create ordinal dir: %w", err)
	}
	h := sha256.Sum256([]byte(runID))
	base := filepath.Join(dir, hex.EncodeToString(h[:16]))
	var n int
	err := flock.With(base+".lock", func() error {
		b, err := os.ReadFile(base + ".ordinal")
		switch {
		case err == nil:
			v, perr := strconv.Atoi(strings.TrimSpace(string(b)))
			if perr != nil {
				return fmt.Errorf("hooks: parse ordinal %s: %w", base+".ordinal", perr)
			}
			n = v
		case errors.Is(err, os.ErrNotExist):
			n = 0
		default:
			return err
		}
		return writeSync(base+".ordinal", []byte(strconv.Itoa(n+1)+"\n"))
	})
	if err != nil {
		return 0, err
	}
	return n, nil
}
