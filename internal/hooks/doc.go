// Package hooks is behalf's Claude Code hook capture surface — the demo
// companion, scoped to one client (D4, Q44).
//
// The MCP proxy is the canonical v1 surface. This is not a second one. It
// exists because three things happen inside Claude Code that an MCP proxy
// structurally cannot see:
//
//   - The human's consent decision. `PermissionRequest` and
//     `PermissionDenied` are the moment a person allowed or refused a tool
//     call, captured as first-class `approval` / `denial` receipts anchored to
//     the delegation token `jti` plus the intent digest (Q5, Q24).
//   - The agent-to-subagent delegation edge. `SubagentStart` / `SubagentStop`
//     hand us the human -> agent -> subagent hop as `delegation` receipts
//     (Q1, Q5, D4).
//   - Local tool calls. Bash, Edit and Read never cross an MCP boundary, so
//     the proxy never sees them at all.
//
// # Scope, deliberately narrow
//
// One client. There is no adapter layer, no plugin interface, and none is
// coming. The four-client hook story was refuted on ground truth (D4): Claude
// Code reads ~/.claude/settings.json, VS Code Copilot reads two files in two
// dialects, Cursor and Codex read machine-scoped files that need admin rights.
// Four files, three parsers, two needing root — and obot-sentry already owns
// that ground with MDM distribution behalf cannot match. Building an
// abstraction that implies otherwise would be the dishonest part.
//
// # Two weaknesses, recorded rather than hidden
//
// **The observed user can delete the hook.** The hook configuration lives in a
// user-scoped settings file, so the person whose calls are being recorded can
// remove it — the same hole obot-sentry's own README concedes. This is out of
// scope for v1 integrity claims (Q74: a workstation user "can delete hooks or
// bypass the proxy"). It is not silently out of scope: it shows up as silence,
// and capture-coverage visibility is the only mitigation until managed policy
// settings arrive in act two. Nothing in this package pretends otherwise.
//
// **A hook can observe pre-rewrite input.** `updatedInput` on `PreToolUse` is
// real, and the rewrite is applied at execution time — verified at runtime on
// Claude Code 2.1.247 (D4). So when another input-modifying hook is installed,
// what this surface records is the input the model proposed, not necessarily
// the input the tool ran. The proxy records the request actually forwarded.
// That asymmetry is one of the reasons the proxy is canonical, and it is why a
// receipt from this surface is a second observation of a crossing, never the
// authority on it (see dedup.go).
//
// # How a receipt gets built
//
// The same path the proxy uses, through internal/capture: the emitter key and
// the cross-process monotonic counter from internal/identity (the flock
// matters — the hook binary and a behalf-proxy may be allocating counters
// against one state directory at the same instant), a client-minted ULID
// receipt_id (Q46), risk_class from a capture-time tool policy with its digest
// recorded (Q6), a step_key over the normalized argument schema and a durable
// per-run causal ordinal (Q85), run_id by the Q7 precedence with the Claude
// Code session id as the `hook-session` rung, payload blobs into the
// customer-held CAS with their field-digest manifests (Q37), DSSE-signed with
// the emitter key, durably spooled (Q48). `emitter.surface` is
// `claude-code-hook`.
//
// # The attempt contract, adapted
//
// Q4 wants intent durable before the action and merged into one completion
// receipt. The proxy holds its pending calls in memory because it is one
// long-lived process. A hook is a fresh process per event, so the pending
// intent is durable on disk instead (pending.go): `PreToolUse` fsyncs it
// before the tool runs and emits no receipt; `PostToolUse` claims it and mints
// the single `tool_call` receipt; `PermissionDenied` claims it and mints a
// `denial` instead, because the tool will not run. Unclaimed intents become
// `orphan_intent` receipts — at `SessionEnd` for that session, or on an
// explicit `behalf-hook recover` sweep.
//
// Pending intents are deliberately NOT written into the spool as
// `spool.Intent` records. If they were, any `behalf-log drain` against this
// spool would run the proxy's orphan recovery over them and mint
// `mcp-proxy`-surface receipts for hook-observed crossings. The spool this
// surface writes holds completions only, so draining it is safe with the
// shipped drain, unchanged.
//
// # Failure posture — the deliberate inversion
//
// The proxy aborts when it cannot record: a recorder that cannot record must
// not forward the call. This surface does the opposite and exits 0 on every
// capture failure. A hook that fails closed breaks the user's editor session,
// and behalf is a recorder, not a runtime (Q47). The loss is visible as
// silence and as a gap in the per-emitter counter sequence, which is exactly
// what Q48 stamped the counter for. cmd/behalf-hook carries the same note at
// the point where it swallows the error.
package hooks
