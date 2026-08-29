package proxy

import (
	"bytes"

	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// MethodToolsCall is the one method the proxy treats as a trust-boundary
// crossing (Q2's closed rule: every MCP tools/call through the proxy is a
// receipt). Everything else crosses byte-verbatim.
const MethodToolsCall = "tools/call"

// frame splits a raw stdio line into its JSON body and its terminator, so
// pass-through can reassemble the exact bytes that arrived. MCP over stdio
// is newline-delimited (revision 2026-07-28), and the revision is stateless
// — there is no initialize session to track — so each line stands alone.
type frame struct {
	body []byte // the line without its terminator
	term []byte // "\n", "\r\n", or empty on a final unterminated line
}

func splitFrame(line []byte) frame {
	body := line
	term := []byte(nil)
	if n := len(body); n > 0 && body[n-1] == '\n' {
		if n > 1 && body[n-2] == '\r' {
			term, body = body[n-2:], body[:n-2]
		} else {
			term, body = body[n-1:], body[:n-1]
		}
	}
	return frame{body: body, term: term}
}

// message is the minimal read of a JSON-RPC line: enough to route it, never
// enough to rewrite it. Spans alias the body bytes.
type message struct {
	object    bool
	method    string
	idSpan    []byte // exact byte span of "id", the response-matching key
	hasID     bool
	hasResult bool
	hasError  bool
}

// parseMessage reads only what routing needs. A line that is not a JSON
// object — a batch array, or anything unparseable — comes back with
// object=false and is passed through untouched (Q45's append-and-flag is an
// ingest rule; the proxy's job on the wire is to be transparent).
func parseMessage(body []byte) message {
	var m message
	if len(bytes.TrimSpace(body)) == 0 || bytes.TrimSpace(body)[0] != '{' {
		return m
	}
	fields, err := jsonspan.TopLevelKeys(body)
	if err != nil {
		return m
	}
	m.object = true
	for _, f := range fields {
		switch f.Name {
		case "method":
			var s string
			if err := unmarshalString(body[f.Start:f.End], &s); err == nil {
				m.method = s
			}
		case "id":
			m.hasID = true
			m.idSpan = body[f.Start:f.End]
		case "result":
			m.hasResult = true
		case "error":
			m.hasError = true
		}
	}
	return m
}

// isToolsCallRequest reports whether the message is a client->server
// tools/call request the proxy must receipt: a request carries both a
// method and an id (a notification has no id and gets no response, so it
// has no request/response pair to receipt — Q1).
func (m message) isToolsCallRequest() bool {
	return m.object && m.method == MethodToolsCall && m.hasID
}

// isResponse reports whether the message is a response to a request the
// proxy may have in flight. Server->client *requests* also carry an id, so
// the presence of a method disqualifies them.
func (m message) isResponse() bool {
	return m.object && m.method == "" && m.hasID && (m.hasResult || m.hasError)
}

// matchKey is the response-matching key: the id's exact byte span. Raw
// spans, not decoded values, so the JSON-RPC ids 1 and "1" — which are
// different ids — never collide.
func (m message) matchKey() string { return string(m.idSpan) }
