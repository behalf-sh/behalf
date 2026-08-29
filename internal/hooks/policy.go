package hooks

// risk_class is assigned by a capture-time tool-policy config, never
// self-reported by the producer, and the digest of the config that made the
// assignment rides the receipt so the assignment is auditable rather than
// free-floating (Q6). The config format and the matcher are internal/proxy's,
// loaded through proxy.LoadPolicy — one policy engine, two surfaces.
//
// # Why this policy is not the proxy's, and what that costs
//
// The proxy's built-in rules classify MCP tool names. They say nothing about
// Bash, Write or WebFetch, because the proxy never sees them: those tools
// never cross an MCP boundary. A surface that DOES see them and lets them fall
// to `default: "low"` would be recording "arbitrary shell execution, low risk"
// — self-asserted metadata failure by omission, which is the thing the product
// exists to correct.
//
// So this policy is the proxy's rules VERBATIM AND FIRST, with Claude Code's
// local tool names appended. The ordering is the load-bearing part: first match
// wins, so any MCP tool name classifies identically on both surfaces, and a
// tool captured twice never disagrees with itself about its own risk. The
// digests differ — two different policies really did make the two assignments,
// and Q6 wants that visible rather than smoothed over.
//
// policy_test.go asserts the prefix property, so an edit to either policy that
// breaks cross-surface agreement fails the build rather than drifting quietly.

// DefaultPolicyJSON is the built-in policy for the hook surface. It is a real
// config, digested like any other, so a receipt written without a --policy file
// still says exactly what classified it.
const DefaultPolicyJSON = `{"version":"behalf.sh/tool-policy/v1","default":"low","rules":[` +
	// --- internal/proxy's DefaultPolicyJSON rules, verbatim and first ---
	`{"pattern":"*refund*","class":"high"},` +
	`{"pattern":"*payment*","class":"high"},` +
	`{"pattern":"*charge*","class":"high"},` +
	`{"pattern":"*delete*","class":"high"},` +
	`{"pattern":"*write*","class":"medium"},` +
	`{"pattern":"*update*","class":"medium"},` +
	`{"pattern":"*create*","class":"medium"},` +
	`{"pattern":"*send*","class":"medium"},` +
	// --- Claude Code's local tools, which the proxy structurally cannot see ---
	// Bash is arbitrary command execution on the user's machine. Nothing this
	// surface records is riskier.
	`{"pattern":"Bash","class":"high"},` +
	`{"pattern":"KillShell","class":"medium"},` +
	// Filesystem mutation.
	`{"pattern":"Write","class":"medium","target_arg":"file_path"},` +
	`{"pattern":"Edit","class":"medium","target_arg":"file_path"},` +
	`{"pattern":"NotebookEdit","class":"medium","target_arg":"notebook_path"},` +
	// Egress: bytes leaving, or arriving from, outside the machine.
	`{"pattern":"WebFetch","class":"medium","target_arg":"url"},` +
	`{"pattern":"WebSearch","class":"medium","target_arg":"query"},` +
	// Delegation: spawning a sub-agent widens who is acting.
	`{"pattern":"Task","class":"medium","target_arg":"subagent_type"},` +
	`{"pattern":"Agent","class":"medium","target_arg":"subagent_type"},` +
	// Reads. Recorded, not omitted — risk differentiation is carried by
	// risk_class and kind, never by leaving the crossing out (Q2).
	`{"pattern":"Read","class":"low","target_arg":"file_path"},` +
	`{"pattern":"Glob","class":"low","target_arg":"pattern"},` +
	`{"pattern":"Grep","class":"low","target_arg":"pattern"},` +
	`{"pattern":"BashOutput","class":"low"}` +
	`]}`
