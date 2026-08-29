package htmlexport

import (
	"html/template"

	"github.com/behalf-sh/behalf/internal/payload"
	"github.com/behalf-sh/behalf/internal/why"
)

// The view model. It is deliberately a plain-data projection: everything
// the template shows has already been decided here, so the template makes
// no judgements and the tests can assert on the model as well as on the
// bytes.
//
// Nothing in this model is stored anywhere. Like `behalf why` and `behalf
// diff`, the comparisons and rollups on it are recomputed from the stored
// receipt bytes on every render (Q11).

// Page is one exported document.
type Page struct {
	// Title is the document title and the <h1>.
	Title string
	// Subtitle names what the page is: one run, or two runs compared.
	Subtitle string
	// GeneratedAt is when this rendering was produced, RFC 3339 UTC. It is
	// a property of the RENDERING, never of the evidence: the receipts
	// carry their own capture times and this does not touch them.
	GeneratedAt string
	// Pair is true when two runs were given and the page leads with a diff.
	Pair bool

	Log   LogIdentity
	Diff  *DiffView
	Runs  []*RunView
	Trust TrustBlock

	// Notes collect anything this rendering could not show honestly from
	// the stored data — a missing checkpoint, an unreadable alias map. They
	// are printed on the page, not swallowed.
	Notes []string

	// Findings counts the payload slots whose stored bytes contradict the
	// digest committed in their signed receipt, across every run on the
	// page. The caller's warning line hangs off this.
	Findings int
}

// LogIdentity is the page's answer to "what bytes is this a rendering of,
// and how do I check them myself". It is the export's chain head: the
// signed checkpoint's origin, size and root hash, plus the exact command a
// sceptic runs offline (Q29, Q18).
type LogIdentity struct {
	Dir      string
	Origin   string
	TreeSize uint64
	RootHex  string
	// Checkpoint is the signed note verbatim, as written in the log dir.
	Checkpoint string
	// Available is false when the checkpoint could not be read or did not
	// verify. The page then says so rather than showing a blank identity.
	Available bool
	// Commands are the verification commands, in the order to run them.
	Commands []Command
}

// Command is one shell line the page shows, with what it establishes.
type Command struct {
	Line string
	What string
}

// TrustBlock is the honesty furniture: what a reader may conclude from this
// document, and what they may not. The wording is the README's threat model
// (Q74, Q29), reused rather than reinvented, because the limits are the
// product's own published claims.
type TrustBlock struct {
	Proves    []Claim
	NotProves []Claim
	States    []StateNote
	Footnote  string
}

// Claim is one line of the trust block: a short label and the sentence that
// qualifies it.
type Claim struct {
	Label string
	Body  string
}

// StateNote explains one of the three verification states.
type StateNote struct {
	State string
	Body  string
}

// RunView is one run's header, timeline and receipts.
type RunView struct {
	ID      string
	Started string
	Ended   string
	// Status is `ok` unless some receipt records a failed operation. It is
	// not a completeness claim: run completeness is marked by a session-end
	// receipt, and the frozen kind enum has no such kind yet (Q82).
	Status string
	// Receipts is every receipt in the run view — log-index order filtered
	// to the run, the authoritative reconstruction order (Q58, Q82).
	Receipts []*ReceiptView
	// Actions counts the action-family receipts: the denominator of the
	// attribution metric (Q6, Q86).
	Actions int
	// Actor names the human at the root of the delegation chain — who the
	// run was carried out on behalf of. A display label off the local alias
	// map (Q16): asserted, never evidence.
	Actor    string
	ActorJKT string
	// Attribution is the run's weakest stored rollup (Q12).
	Attribution string
	// Rollup is the Q86 metric: the share of action receipts at each
	// verification state, with its denominator stated.
	Rollup Rollup
	// PayloadSummary counts the resolved slot states across the run.
	PayloadSummary string
	// Findings is how many slots contradicted their commitment.
	Findings int
	// Anchor is the run section's html id.
	Anchor string
}

// Rollup is the unattributed-rate metric for one run (Q86): numerators per
// verification state over a stated denominator, so a reader can reproduce
// the number from their own receipts.
type Rollup struct {
	Denominator int
	Rows        []RollupRow
	// Note states what the denominator is and where the numerators come
	// from — the reproducibility half of Q86.
	Note string
}

// RollupRow is one state's share.
type RollupRow struct {
	State   string
	Count   int
	Percent string
	// Width is the bar segment's width. It is a CSS length by type, so the
	// template writes it into a style attribute without the escaper having
	// to guess whether a computed string is safe there.
	Width template.CSS
}

// ReceiptView is one receipt: what happened, what authorised it, and what
// the payload slots resolved to.
type ReceiptView struct {
	Step      int
	Anchor    string
	LogIndex  uint64
	LeafHash  string
	ReceiptID string
	Kind      string
	RunID     string

	CapturedAt string
	// Elapsed is the offset from the run's first capture — "t+60s".
	Elapsed string

	Operation string
	Target    string
	Outcome   string
	OutcomeOK bool
	Amount    string
	Currency  string

	Actor    string
	ActorJKT string

	// Attribution and Class are the stored rollup and the stored attribution
	// class (Q12, §8), read and never recomputed.
	Attribution string
	Class       string

	Hops         []HopView
	VerifiedHops int
	TotalHops    int
	// Excess is the read-time scope finding: the operation exceeded the
	// ceiling the chain delegated. Recorded, never enforced (Q11, Q45).
	Excess *why.ScopeExcess

	Slots []SlotView
	// Findings is how many of this receipt's slots are tamper findings.
	Findings int
	// Differs marks a receipt the diff named as differing from its
	// counterpart, so the timeline can point at it.
	Differs bool
}

// HopView is one delegation hop, with the honesty furniture attached: what
// this hop's state actually rests on, and what it does not.
type HopView struct {
	Depth    int
	MaxDepth int
	Label    string
	JKT      string
	// Status is the stored per-hop three-state: verified, asserted, broken
	// (Q12, D5).
	Status string
	// StatusWord is the display form; asserted is named, never collapsed
	// into failure.
	StatusWord string
	Method     string
	// Evidence is the human-readable evidence column: what makes this hop
	// verified, or empty when nothing does.
	Evidence    string
	EvidenceRef string

	// Checked and NotChecked are the per-state statement of what was and
	// was not established. Every `asserted` hop carries them; so does every
	// other state, because an unqualified "verified" is the more dangerous
	// half.
	Checked    []string
	NotChecked []string

	Intent string
	Scope  string
	// Attenuation is the read-time comparison against the parent hop,
	// stamped with the comparator version (Q11, Q13). Only shown when it
	// says something the reader must not miss.
	Attenuation       string
	AttenuationReason string

	Credential  why.Credential
	RootBinding *why.RootBinding
	Carriage    string
	JTI         string
	ParHash     string
	Exp         string
}

// SlotView is one payload slot, joined against the customer's store.
type SlotView struct {
	Label       string
	Role        string
	State       string
	Committed   string
	Custody     string
	ContentType string
	Size        int
	SizeText    string
	Digest      string
	Ref         string
	CauseRef    string
	Subjects    []string

	// Placeholder is the typed stand-in for a non-present slot, rendered by
	// internal/payload so the HTML and the NDJSON say the same thing.
	Placeholder string

	// Content is the rendered payload: pretty-printed when the bytes are
	// JSON, verbatim when they are text, a typed summary when they are
	// binary. Non-empty only for a present slot.
	Content string
	// Language hints the content kind for display: "json", "text" or
	// "binary".
	Language string
	// Collapsed is true when the content starts behind its disclosure
	// control because it is long.
	Collapsed bool
	// Truncated is set when the content exceeded MaxInlineBytes; Omitted is
	// how many bytes were left out.
	Truncated bool
	Omitted   int

	// Tampered marks the payload cover-up: bytes in the store that do not
	// hash to the digest the signed receipt commits to.
	Tampered bool
	Mismatch *payload.Mismatch
	// Err records a lookup that failed for a reason that is neither absence
	// nor a mismatch — a bad mount, a permission denial. Such a slot is
	// `unreadable` too, and is deliberately NOT a tamper finding.
	Err string

	// ManifestFields is how many field digests the receipt committed for
	// this slot (Q37); zero means whole-blob only, which is a gap in the
	// evidence rather than a clean bill.
	ManifestFields int
}

// stateBadge maps a resolved payload state onto its display word. The
// schema's strings are used as-is; nothing here invents a friendlier
// vocabulary for a finding.
func stateBadge(s payload.State) string { return string(s) }
