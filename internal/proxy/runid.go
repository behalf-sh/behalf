package proxy

import (
	"strings"
	"time"
)

// run_id is populated by normative precedence, and every receipt records
// which rung fired so grouping is honest about its own provenance (Q7,
// receipt-schema-v1.md §6 and §9 item 7). The proxy can reach three of the
// four rungs; `hook-session` belongs to the Claude Code hook surface (D4).
const (
	// EnvRunID is the caller/SDK-supplied key — the top rung.
	EnvRunID = "BEHALF_RUN_ID"
	// EnvTraceparent is the W3C traceparent the caller exported; its
	// trace-id field is the root trace_id (Q7, Q50).
	EnvTraceparent = "TRACEPARENT"
)

// Provenance values, matching the schema's run_id_provenance enum.
const (
	ProvenanceCaller       = "caller"
	ProvenanceTraceparent  = "traceparent"
	ProvenanceProxySession = "proxy-session"
)

// resolveRunID applies the precedence. getenv is injected so tests cover
// every rung without touching the process environment; ids is the same
// injectable ULID source the receipts use, so a recorder that falls all the
// way through to the proxy-session rung still gets a reproducible run id.
func resolveRunID(getenv func(string) string, now time.Time, ids *idSource) (runID, provenance, traceID string) {
	if v := strings.TrimSpace(getenv(EnvRunID)); v != "" {
		// A traceparent, if also exported, still populates correlation.trace_id.
		return v, ProvenanceCaller, traceIDFromTraceparent(getenv(EnvTraceparent))
	}
	if tid := traceIDFromTraceparent(getenv(EnvTraceparent)); tid != "" {
		return tid, ProvenanceTraceparent, tid
	}
	return "proxy-" + ids.ulidAt(now), ProvenanceProxySession, ""
}

// traceIDFromTraceparent extracts the 32-hex trace-id from a W3C
// traceparent header value (version-format:
// "00-<32 hex trace-id>-<16 hex parent-id>-<2 hex flags>"). Anything that
// does not parse yields "", which drops the rung.
func traceIDFromTraceparent(tp string) string {
	parts := strings.Split(strings.TrimSpace(tp), "-")
	if len(parts) < 4 || len(parts[1]) != 32 {
		return ""
	}
	if strings.Trim(parts[1], "0123456789abcdef") != "" || parts[1] == strings.Repeat("0", 32) {
		return ""
	}
	return parts[1]
}
