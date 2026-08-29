package hooks

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// The hook event names this surface handles. Claude Code sends one JSON object
// on stdin per event, with `hook_event_name` naming which one.
const (
	EventPreToolUse        = "PreToolUse"
	EventPostToolUse       = "PostToolUse"
	EventPostToolUseFailed = "PostToolUseFailure"
	EventPermissionReq     = "PermissionRequest"
	EventPermissionDenied  = "PermissionDenied"
	EventSubagentStart     = "SubagentStart"
	EventSubagentStop      = "SubagentStop"
	EventSessionEnd        = "SessionEnd"
	EventStop              = "Stop"
)

// ObservedClientVersion is the Claude Code build this surface's payload
// handling was checked against (ENG-33). Every golden under `testdata/` is
// either a capture from this build or was rewritten to match the payload
// schemas it carries; `testdata/PROVENANCE.md` says which, per file.
//
// The payload shape is Claude Code's and it moves. This constant is here so a
// future reader can tell how stale the goldens are without guessing.
const ObservedClientVersion = "2.1.250"

// Events is every event this surface installs and handles, in the order the
// install helper writes them.
var Events = []string{
	EventPreToolUse,
	EventPostToolUse,
	EventPostToolUseFailed,
	EventPermissionReq,
	EventPermissionDenied,
	EventSubagentStart,
	EventSubagentStop,
	EventSessionEnd,
	EventStop,
}

// ToolMatcherEvents are the events Claude Code scopes with a `matcher`. The
// rest install without one.
var ToolMatcherEvents = map[string]bool{
	EventPreToolUse:        true,
	EventPostToolUse:       true,
	EventPostToolUseFailed: true,
	EventPermissionReq:     true,
	EventPermissionDenied:  true,
}

// ErrUnhandledEvent marks a well-formed payload for an event this surface does
// not receipt. It is not a capture failure: Claude Code may add events, and an
// unknown one must be ignored quietly rather than recorded as something it is
// not.
var ErrUnhandledEvent = errors.New("hooks: event not handled by this surface")

// Event is one parsed hook payload.
//
// Parsing is deliberately tolerant and deliberately lossless. Tolerant,
// because the payload shape is Claude Code's and it moves: fields this struct
// does not model must not turn a capture into a failure. Lossless, because
// Raw — the exact stdin bytes — is written to the customer-held CAS and
// referenced by digest from the receipt (`raw_frame_ref`, Q49), so a field
// behalf never learned to read is still evidence a reader can go and find.
//
// The three *Raw fields hold exact byte spans out of the payload, extracted
// without a parse-and-reserialize round trip: they become payload slots whose
// digests must commit to what Claude Code actually wrote.
type Event struct {
	Raw []byte // the exact stdin bytes

	Name           string `json:"hook_event_name"`
	SessionID      string `json:"session_id"`
	TranscriptRef  string `json:"transcript_path"`
	CWD            string `json:"cwd"`
	PermissionMode string `json:"permission_mode"`

	ToolName  string `json:"tool_name"`
	ToolUseID string `json:"tool_use_id"`

	// Sub-agent identity, self-reported (Q16). SubagentStart/Stop carry these;
	// tool events inside a sub-agent may carry them too.
	AgentID   string `json:"agent_id"`
	AgentType string `json:"agent_type"`

	// PromptID correlates every event from one user prompt to the next
	// (observed; also emitted as the OTel `prompt.id` attribute, which is what
	// makes it a usable run-grouping rung).
	PromptID string `json:"prompt_id"`

	// Reason is the refusal on `PermissionDenied` (required there) and the
	// close reason on `SessionEnd` (one of clear|resume|logout|
	// prompt_input_exit|other). It is the ONLY reason-shaped member either
	// event carries.
	//
	// Checked against Claude Code 2.1.250 (ENG-33). Three fields this struct
	// used to read speculatively — `message`, `permission_decision`,
	// `decision` — do not exist on any hook payload and were removed rather
	// than left implying a check that never ran. `PermissionRequest` in
	// particular carries NO reason of any kind: see the note on
	// handlePermission.
	Reason string `json:"reason"`

	// Error is `PostToolUseFailure`'s failure message, a plain string. This is
	// the real failure signal from this surface — a tool call that fails does
	// not produce a `PostToolUse` at all.
	Error string `json:"error"`
	// IsInterrupt marks a failure caused by the user interrupting rather than
	// by the tool.
	IsInterrupt bool `json:"is_interrupt"`

	// Exact byte spans, absent when the key is absent.
	ToolInputRaw    []byte
	ToolResponseRaw []byte
}

// Parse reads one hook payload.
func Parse(raw []byte) (*Event, error) {
	trimmed := trimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("hooks: empty hook payload on stdin")
	}
	var e Event
	if err := json.Unmarshal(trimmed, &e); err != nil {
		return nil, fmt.Errorf("hooks: hook payload is not a JSON object: %w", err)
	}
	e.Raw = trimmed
	if e.Name == "" {
		return nil, errors.New("hooks: hook payload carries no hook_event_name")
	}
	if span, err := jsonspan.ExtractTopLevelValue(trimmed, "tool_input"); err == nil {
		e.ToolInputRaw = span
	}
	if span, err := jsonspan.ExtractTopLevelValue(trimmed, "tool_response"); err == nil {
		e.ToolResponseRaw = span
	}
	return &e, nil
}

// trimSpace strips leading and trailing ASCII whitespace without allocating.
// The stdin bytes are the bytes the receipt commits to, so the trim is the one
// normalisation applied, and only at the edges: a trailing newline from a
// shell pipe must not change the digest of the same event.
func trimSpace(b []byte) []byte {
	i, j := 0, len(b)
	for i < j && isSpace(b[i]) {
		i++
	}
	for j > i && isSpace(b[j-1]) {
		j--
	}
	return b[i:j]
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// mcpToolPrefix is how Claude Code names a tool served over MCP.
const mcpToolPrefix = "mcp__"

// mcpToolSep separates the server label from the tool name.
const mcpToolSep = "__"

// SanitizeClientToolName applies the character substitution Claude Code
// applies when it builds a tool name, so that a name recorded on the MCP wire
// can be compared against the name the client reported.
//
// Observed in Claude Code 2.1.250 (ENG-33): the client composes an MCP tool
// name as `mcp__<sanitise(server)>__<sanitise(tool)>` where sanitise replaces
// every character outside `[A-Za-z0-9_-]` with `_`. A server publishing
// `refund.issue` therefore reaches the hook as `mcp__payments__refund_issue`.
//
// The substitution is LOSSY and not invertible: `refund_issue` on the wire and
// `refund.issue` on the wire arrive at this surface as the same string. So
// nothing here tries to reconstruct the wire name. Each surface records the
// name it actually saw, and the cross-surface join (dedup.go) compares the two
// under this function — which is the only comparison that can be made honestly.
func SanitizeClientToolName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '_', c == '-':
			b.WriteByte(c)
		default:
			b.WriteByte('_')
		}
	}
	return b.String()
}

// NormalizeToolName splits Claude Code's `mcp__<server>__<tool>` spelling into
// the tool name and the server label.
//
// It returns the tool name AS CLAUDE CODE SPELLED IT, which is the sanitised
// form described on SanitizeClientToolName — not the name on the MCP wire.
// This used to claim it produced the wire name so that both surfaces would
// write `operation.name = "refund.issue"`; against a real client that is
// impossible, because the dot never survives to this surface. What each
// receipt records is what its own surface observed, and the join reconciles
// them at read time.
//
// The server label is self-reported and rides as an asserted label, never as
// identity (Q16, D4).
//
// A local tool (Bash, Edit, Read) passes through unchanged with no server.
func NormalizeToolName(name string) (operation, server string) {
	if !strings.HasPrefix(name, mcpToolPrefix) {
		return name, ""
	}
	rest := name[len(mcpToolPrefix):]
	i := strings.Index(rest, mcpToolSep)
	if i <= 0 || i+len(mcpToolSep) >= len(rest) {
		// `mcp__` with nothing usable behind it. Record the name verbatim
		// rather than inventing a split.
		return name, ""
	}
	return rest[i+len(mcpToolSep):], rest[:i]
}

// IsMCPTool reports whether Claude Code named this tool as MCP-served — the
// precondition for the cross-surface duplicate rule in dedup.go.
func IsMCPTool(name string) bool {
	_, server := NormalizeToolName(name)
	return server != ""
}

// Operation returns the normalised operation name and the self-reported MCP
// server label for this event's tool.
func (e *Event) Operation() (operation, server string) { return NormalizeToolName(e.ToolName) }

// ToolInput returns the raw tool_input bytes, or an empty JSON object when the
// payload carried none. An empty object is the honest normalisation: the
// digest then commits to "no arguments were present", which is a fact, rather
// than to nothing at all.
func (e *Event) ToolInput() []byte {
	if len(e.ToolInputRaw) == 0 {
		return []byte("{}")
	}
	return e.ToolInputRaw
}

// DenialReason renders what the payload said about a refusal.
//
// `reason` is REQUIRED on `PermissionDenied` in Claude Code 2.1.250, so the
// fallback sentence is for a payload from some other producer, not for the
// normal path.
func (e *Event) DenialReason() string {
	if s := strings.TrimSpace(e.Reason); s != "" {
		return s
	}
	return "the human refused this tool call at the Claude Code permission prompt"
}
