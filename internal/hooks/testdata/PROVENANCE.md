# Where these hook payloads came from

**Client: Claude Code 2.1.250. Checked 28 Aug 2026 (ENG-33).**

Until this pass the goldens in this directory were *guesses*. The hooks companion
shipped a parser for `PermissionRequest` and `PermissionDenied` written without
anyone having seen one, and the guesses were wrong in ways that produced blanks
rather than errors — which is the worst failure mode a recorder has.

They are now pinned to the client. Two sources, and each file says which:

- **observed** — captured from a live `claude -p` session with a hook that
  appended the exact stdin bytes of every event. Identifiers (session id,
  transcript path, cwd, tool-use ids) are replaced with stable synthetic ones so
  the goldens are deterministic; every **key, type and shape** is as observed.
- **schema** — reconstructed from the payload schemas the client binary carries
  for events a headless session cannot produce. `PermissionRequest` and
  `PermissionDenied` need an interactive permission prompt, which `-p` never
  shows: in print mode a tool that is not pre-allowed is auto-denied with no
  permission event at all.

| File | Source |
|---|---|
| `pre_tool_use_bash.json` | observed |
| `post_tool_use_bash.json` | observed |
| `pre_tool_use_mcp.json` | observed |
| `post_tool_use_mcp.json` | observed |
| `post_tool_use_failure.json` | schema — the live failing call produced *no* completion event to capture, which is itself the finding |
| `pre_tool_use_denied.json` | observed shape, second tool-use id |
| `permission_request.json` | schema |
| `permission_denied.json` | schema |
| `subagent_start.json` | observed |
| `subagent_stop.json` | observed |
| `session_end.json` | observed |
| `stop.json` | observed |
| `unknown_event.json` | synthetic — an event this surface deliberately does not handle |

## What was wrong, and what it cost

Seven findings, in the order they bite.

**1. A failed tool call produces no `PostToolUse`.** It produces
`PostToolUseFailure`, an event this surface neither installed nor handled,
carrying a top-level string `error` (and `is_interrupt` when the user
interrupted). Observed directly: an MCP tool returning `isError: true` fired
`PreToolUse` and then nothing. Every failed tool call therefore left a durable
intent that nothing claimed, and surfaced at session end as an `orphan_intent`
reading "no completion observed" — when the completion *had* been observed and
was a failure. Reporting a known failure as an unknown silence is the exact
thing this product exists to remove.

**2. `PermissionRequest` carries no reason of any kind.** Its whole payload is
the base fields plus `tool_name`, `tool_input`, and an optional
`permission_suggestions`. The shipped parser read `reason`, `message`,
`permission_decision` and `decision`; none of the last three exists on any hook
payload. `PermissionDenied` does carry `reason`, and it is required there.

**3. `PermissionRequest` carries no `tool_use_id`.** The pending-intent store
buckets on the id when one is present, so a permission event could only compute
the content key and looked in a bucket that was always empty. Consequence:
approvals anchored to a digest they computed themselves rather than to the one
the tool call recorded, so the consent-to-action join silently never matched.

**4. The client sanitises MCP tool names.** It composes them as
`mcp__<sanitise(server)>__<sanitise(tool)>`, replacing every character outside
`[A-Za-z0-9_-]` with `_`. A server publishing `refund.issue` arrives as
`mcp__payments__refund_issue`. The substitution is lossy and not invertible, so
the two capture surfaces cannot record the same string, and a cross-surface join
comparing names for equality could never fire for the demo's own tool.

**5. An MCP `tool_response` is a bare JSON array** of content blocks, not an
object. `isError`, `success` and `error` are not reachable in it under any
spelling. A built-in tool's response is an object, but carries no status member
either (`Bash` gives `{stdout, stderr, interrupted, isImage, noOutputExpected}`).

**6. `SubagentStart` carries no `prompt`**, and `SubagentStop` requires
`agent_transcript_path`, which the old golden omitted. Both carry `agent_id` and
`agent_type`; so does *any* hook that fires inside a sub-agent, which is how a
sub-agent's own tool calls are told apart from the main thread's.

**7. `SessionEnd.reason` is an enum** — `clear | resume | logout |
prompt_input_exit | other`. The old golden said `exit`, which is not a value.

The base payload also gained fields the struct did not model: `prompt_id`
(constant from one user prompt to the next, and emitted as the OTel `prompt.id`
attribute, which makes it a real run-grouping rung) and `effort`.

## Still not verified

- The **ordering** of `PermissionRequest` relative to `PreToolUse`. The fix in
  `pending.go` works either way, but which arrives first has not been seen.
- The **cross-surface digest join**: whether the client serialises `tool_input`
  byte-for-byte as it serialises `arguments` on the MCP wire. Closing that needs
  a proxy and a client observing the same call.

## How to redo this

Install a hook on every event whose command is `cat >> events.jsonl`, point a
`claude -p` run at it with `--settings`, and diff the result against these files.
Update `ObservedClientVersion` in `payload.go` when you do.
