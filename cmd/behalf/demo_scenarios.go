package main

import "fmt"

// The four scenarios. Each is one objection, answered by running shipped
// commands against the deterministic recording — no slides, no mock output,
// nothing this file renders on the product's behalf.
//
// Only the commands live here. What to say at each beat, the abbreviated
// expected output and the recovery move live in docs/demo-runbook.md, and
// TestRunbookCoversEveryStep asserts the runbook still names every command
// this file prints, so the script and the driver cannot drift apart
// silently.
type scenario struct {
	Order     int
	Name      string
	Headline  string
	Proves    string
	Objection string
	Runtime   string

	// Needs are the sibling binaries the scenario reaches for. `setup`
	// resolves every one of them before the call rather than letting a
	// missing tool surface at minute two.
	Needs []string

	// Prepare runs after the reset. It is for checks and state the scenario
	// specifically depends on; it returns lines for the printout.
	Prepare func(root string) ([]string, error)

	Steps []demoStep
}

// demoStep is one command the operator types.
type demoStep struct {
	Cmd string

	// Exit is the status the command is expected to return. It is not
	// always zero: a detected tamper exits 1, and a scenario whose payoff is
	// a non-zero exit has to say so, or the test that drives these steps
	// would call the payoff a failure.
	Exit int

	// Manual marks a step a machine should not run — it opens a window, or
	// waits on a person. Printed for the operator; skipped by the test.
	Manual bool
}

var scenarios = map[string]scenario{
	"diff": {
		Order:     1,
		Name:      "diff",
		Headline:  "which step caused it",
		Proves:    "two runs that both succeeded, and the one divergence that made them differ",
		Objection: "we already have tracing",
		Runtime:   "about 2 minutes",
		Steps: []demoStep{
			{Cmd: "behalf runs"},
			{Cmd: "behalf diff rec_9f2a rec_c71e"},
			{Cmd: "behalf diff rec_9f2a rec_c71e --all"},
			{Cmd: "behalf why rec_c71e:13"},
		},
	},

	"why": {
		Order:     2,
		Name:      "why",
		Headline:  "on whose behalf",
		Proves:    "the delegated intent, the scope it granted, and what behalf refuses to call verified",
		Objection: "isn't this just structured logging",
		Runtime:   "about 3 minutes",
		Needs:     []string{"otel-attribution"},
		Steps: []demoStep{
			{Cmd: "behalf why rec_c71e:31"},
			{Cmd: "behalf why rec_9f2a:31"},
			{Cmd: "otel-attribution"},
			{Cmd: "OTEL_RESOURCE_ATTRIBUTES=user.email=ceo@corp.com otel-attribution"},
			{Cmd: "behalf why rec_c71e:31"},
		},
	},

	"tamper": {
		Order:     3,
		Name:      "tamper",
		Headline:  "two cover-ups, two different findings",
		Proves:    "a payload that stopped matching its commitment while the log stayed perfect, and a receipt edit that breaks the chain and takes everything after it down",
		Objection: "how do I know your tamper-evidence works",
		Runtime:   "about 3 minutes",
		Needs:     []string{"behalf-log", "behalf-verify"},
		Prepare:   prepareRefundTarget,
		Steps: []demoStep{
			{Cmd: "behalf-verify log $BEHALF_HOME/log --emitter-keys $BEHALF_HOME/emitter.jwks.json"},
			{Cmd: "behalf demo tamper payload"},
			{Cmd: "behalf-log rehydrate --run rec_c71e >/dev/null", Exit: 1},
			{Cmd: "behalf-verify log $BEHALF_HOME/log --emitter-keys $BEHALF_HOME/emitter.jwks.json"},
			{Cmd: "behalf-log export --run rec_c71e --out $BEHALF_HOME/refund.jsonl"},
			{Cmd: "behalf-verify $BEHALF_HOME/refund.jsonl"},
			{Cmd: "behalf demo tamper export $BEHALF_HOME/refund.jsonl"},
			{Cmd: "behalf-verify $BEHALF_HOME/refund.jsonl", Exit: 1},
		},
	},

	"custody": {
		Order:     4,
		Name:      "custody",
		Headline:  "your data never leaves",
		Proves:    "behalf holds digests and refs, never content — and a run whose payloads are gone is still evidence a third party can verify",
		Objection: "why would I ship my agent's actions to a solo founder's cloud",
		Runtime:   "about 3 minutes",
		Needs:     []string{"behalf-log", "behalf-verify"},
		Prepare:   prepareRefundTarget,
		Steps: []demoStep{
			{Cmd: "behalf demo blob"},
			{Cmd: "rm $(behalf demo blob --path)"},
			{Cmd: "behalf demo blob"},
			{Cmd: "behalf export --run rec_c71e --html $BEHALF_HOME/refund.html"},
			{Cmd: "open $BEHALF_HOME/refund.html", Manual: true},
			{Cmd: "behalf-log export --run rec_c71e --out $BEHALF_HOME/refund.jsonl"},
			{Cmd: "behalf-verify $BEHALF_HOME/refund.jsonl"},
		},
	},
}

// prepareRefundTarget is the layout check both byte-level scenarios depend
// on, run before the call instead of discovered during it.
//
// It is the same check scripts/tamper_suite.sh makes: the literal the
// cover-up edits must exist in exactly one blob of the whole store, or the
// demo would be editing several records while claiming to edit one. If the
// recording drifts, this fails at setup — quietly, in a terminal, with
// nobody watching — rather than at the moment the payoff was supposed to
// land.
func prepareRefundTarget(root string) ([]string, error) {
	target, err := findRefundPayload(root)
	if err != nil {
		return nil, err
	}
	in := target.Input()
	return []string{
		fmt.Sprintf("%s:%d %s target=%s is log index %d; its arguments are one blob of %d bytes",
			target.RunID, target.Step, target.Operation, target.Target, target.LogIndex, in.Size),
	}, nil
}
