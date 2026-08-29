package hooks

import (
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// The cross-surface duplicate rule.
//
// When an MCP tool is called from Claude Code with a behalf-proxy in front of
// the server, ONE crossing is observed twice: the proxy sees the `tools/call`
// on the wire, the hook sees `PreToolUse`/`PostToolUse` in the client. Two
// receipts reach the log describing one thing.
//
// # The rule: append both, flag both, collapse on read
//
// Both surfaces append. Neither suppresses. This is Q45's resolution applied
// where it bites — a silent gap is indistinguishable from tampering, so the
// failure we choose is the visible one — and it is also the only rule that can
// actually be implemented at capture: a hook process cannot know whether a
// proxy is running without a synchronous cross-process query on the agent's
// hot path, which is exactly what this surface must never do. A rule that
// requires an impossible check is not a rule.
//
// What makes the duplicate legible rather than merely tolerated:
//
//   - `operation.name` is comparable, though NOT equal. Claude Code says
//     `mcp__payments__refund_issue` — it sanitises every character outside
//     `[A-Za-z0-9_-]` to `_` when it composes a tool name — while the wire, and
//     therefore the proxy, says `refund.issue`. The substitution is lossy and
//     cannot be inverted, so each surface records the name it saw and the join
//     compares them under the client's own substitution (ENG-33).
//   - `emitter.surface` says which surface saw it — `mcp-proxy` or
//     `claude-code-hook`.
//   - The hook receipt carries a typed link, `rel: "attests"`, whose anchor
//     holds the ARGUMENTS DIGEST: the plain SHA-256 of the raw argument bytes.
//     This is the flag half of append-and-flag, and it is machine-readable.
//
// # Why the arguments digest is the join
//
// It is the only value both surfaces provably commit to. The proxy's input
// slot is the whole `params` object, and its field-digest manifest (Q37)
// carries `$.arguments` -> sha256 of that field's exact raw bytes. The hook's
// input slot IS those argument bytes, so its digest is the same number. No
// other candidate works:
//
//   - `attempt.intent_digest` differs by construction: the proxy hashes the
//     `params` object, the hook hashes `tool_input`. Neither surface can see
//     the other's input.
//   - `step_key` differs: its causal ordinal counts what each surface saw, and
//     the hook sees Bash calls the proxy cannot.
//   - `receipt_id` is per-record by design (Q46) and must never collide.
//
// # The honest caveat
//
// The join holds when Claude Code serialises `tool_input` in the hook payload
// byte-for-byte as it serialises `arguments` on the MCP wire. That is very
// likely — it is one client emitting one value twice — and it is still NOT
// verified end to end: closing it needs a proxy and a client observing the same
// call, which ENG-33's capture run did not set up. What ENG-33 did establish is
// the name half, and it was wrong: the client sanitises the tool name, so a
// join that compared the two names for equality could never fire for any tool
// whose wire name contains a dot — `refund.issue`, the demo's own tool, among
// them. That is fixed here.
//
// D4 records a related finding that says be careful with the digest half: when
// another input-modifying hook is installed, a hook can observe pre-rewrite
// input while the proxy records what was actually forwarded. In that case the
// digests genuinely differ, because the two surfaces genuinely saw different
// bytes, and refusing to collapse them is the correct answer rather than a bug.
//
// This is precisely why the rule is append-and-flag and not suppress-one. A
// join that can miss must never be allowed to delete a record.
//
// # What a read surface does with a collapsed pair
//
// The proxy receipt is canonical (Q44, D4): it records the request actually
// forwarded. The hook receipt folds in as a second observation contributing
// what only it could see — the consent link, and the fact that this surface
// had coverage of the call. Neither is discarded, and `behalf verify` still
// sees two independently signed leaves, which is the point: two surfaces
// agreeing is stronger evidence than one, and the log should not have thrown
// that away to look tidy.

// CrossSurfaceRel is the `links[].rel` a hook receipt uses to flag itself as
// possibly-a-second-observation. The frozen enum offers six values; `attests`
// is the one that means "this record speaks to another record", which is what
// a second observation of one crossing does.
const CrossSurfaceRel = "attests"

// ArgumentsPath is the field-digest manifest path the proxy records the raw
// argument bytes under.
const ArgumentsPath = "$.arguments"

// crossSurfaceLink builds the flag, for MCP-served tools only. A local tool —
// Bash, Edit, Read — has no second surface that could have seen it, so
// flagging one would be noise claiming to be a finding.
//
// `anchor.intent_digest` carries the arguments digest. The frozen anchor
// object has three members — `jti`, `par_hash`, `intent_digest` — and this is
// the one that means "the digest identifying the intended operation". Using it
// for the arguments digest stretches the name and is called out here rather
// than left for a reader to discover.
func crossSurfaceLink(e *Event, argsDigest string) *receipt.Link {
	if !IsMCPTool(e.ToolName) || argsDigest == "" {
		return nil
	}
	return &receipt.Link{
		Rel:    CrossSurfaceRel,
		Anchor: &receipt.Anchor{IntentDigest: argsDigest},
	}
}

// CrossSurfaceDigest returns the arguments digest a hook receipt flagged
// itself with, or "".
func CrossSurfaceDigest(r *receipt.Receipt) string {
	for _, l := range r.Links {
		if l.Rel == CrossSurfaceRel && l.Anchor != nil {
			return l.Anchor.IntentDigest
		}
	}
	return ""
}

// ProxyArgumentsDigest returns the digest of the raw argument bytes a proxy
// receipt committed to, read out of its input slot's field-digest manifest, or
// "".
func ProxyArgumentsDigest(r *receipt.Receipt) string {
	for _, s := range r.Payload {
		if s.Role != "input" || s.Manifest == nil {
			continue
		}
		for _, f := range s.Manifest.Fields {
			if f.Path == ArgumentsPath {
				return f.Digest
			}
		}
	}
	return ""
}

// SameCrossing reports whether a proxy receipt and a hook receipt describe one
// trust-boundary crossing.
//
// All four conditions must hold, and each is doing work: the surfaces must
// differ (or it is not a cross-surface pair), the run must be the same (which
// in practice means BEHALF_RUN_ID was exported to both, the only rung that
// makes two surfaces agree — Q7), the two operation names must name the same
// tool under the client's own name substitution, and the argument bytes must
// hash the same.
func SameCrossing(proxyR, hookR *receipt.Receipt) bool {
	if proxyR == nil || hookR == nil {
		return false
	}
	if proxyR.Emitter.Surface != proxy.Surface || hookR.Emitter.Surface != Surface {
		return false
	}
	if proxyR.RunID == "" || proxyR.RunID != hookR.RunID {
		return false
	}
	if !sameOperation(proxyR.Operation.Name, hookR.Operation.Name) {
		return false
	}
	want := ProxyArgumentsDigest(proxyR)
	got := CrossSurfaceDigest(hookR)
	return want != "" && want == got
}

// sameOperation reports whether a proxy-recorded operation name and a
// hook-recorded one name the same tool.
//
// The comparison is not equality, because the two surfaces cannot record the
// same string: the proxy records the name on the MCP wire and the client
// records that name with every character outside `[A-Za-z0-9_-]` replaced by
// `_`. Comparing under the client's substitution is the only sound direction —
// it maps the richer name onto the poorer one. The reverse would have to guess
// which `_` used to be a `.`.
//
// The cost of the substitution is a collision: a server publishing both
// `refund.issue` and `refund_issue` makes the two indistinguishable to this
// surface. Two things keep that from mattering. The name is one of four
// conditions in SameCrossing, and the arguments digest is the discriminating
// one; and the rule is append-and-flag, so the worst case of a wrong join is a
// rendering that groups two records, never a record that is dropped.
func sameOperation(proxyName, hookName string) bool {
	if proxyName == "" || hookName == "" {
		return false
	}
	return SanitizeClientToolName(proxyName) == hookName
}

// Crossing is one trust-boundary crossing with every receipt that observed it.
type Crossing struct {
	// Canonical is the receipt a read surface should render: the proxy's when
	// one exists, because it records the request actually forwarded (Q44).
	Canonical *receipt.Receipt
	// Observations is every receipt describing this crossing, canonical
	// included, in the order given. Nothing is dropped: the collapse is a
	// rendering decision, never a deletion.
	Observations []*receipt.Receipt
}

// Duplicated reports whether more than one surface observed this crossing.
func (c Crossing) Duplicated() bool { return len(c.Observations) > 1 }

// Surfaces lists the distinct emitter surfaces that observed this crossing, in
// observation order.
func (c Crossing) Surfaces() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range c.Observations {
		if s := r.Emitter.Surface; s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// Collapse groups receipts into crossings, folding each hook receipt onto the
// proxy receipt it duplicates. Receipt order is preserved and no receipt is
// ever dropped — a hook receipt with no proxy partner (a Bash call, a
// consent decision, a session where no proxy ran) is its own crossing.
//
// This is the read-side half of the rule. It exists here, beside the capture
// code that writes the flag, so the two cannot drift apart.
func Collapse(rs []*receipt.Receipt) []Crossing {
	out := make([]Crossing, 0, len(rs))
	// unpaired maps a proxy receipt's (run, name, arguments digest) to the
	// positions in out that have not been paired yet, oldest first. A queue
	// rather than a single slot, because the same tool called twice with the
	// same arguments in one run is a normal thing to do: the first hook
	// observation pairs with the first proxy receipt, and the second with the
	// second, rather than both landing on whichever came last.
	type key struct{ run, name, args string }
	unpaired := map[key][]int{}
	for _, r := range rs {
		if r == nil {
			continue
		}
		if r.Emitter.Surface == proxy.Surface {
			if d := ProxyArgumentsDigest(r); d != "" && r.RunID != "" {
				// Keyed on the sanitised name, so the hook's own key — which is
				// already sanitised, because the client sanitised it — lands in
				// the same bucket.
				k := key{r.RunID, SanitizeClientToolName(r.Operation.Name), d}
				unpaired[k] = append(unpaired[k], len(out))
			}
			out = append(out, Crossing{Canonical: r, Observations: []*receipt.Receipt{r}})
			continue
		}
		if d := CrossSurfaceDigest(r); d != "" && r.RunID != "" {
			k := key{r.RunID, r.Operation.Name, d}
			if q := unpaired[k]; len(q) > 0 && SameCrossing(out[q[0]].Canonical, r) {
				out[q[0]].Observations = append(out[q[0]].Observations, r)
				unpaired[k] = q[1:]
				continue
			}
		}
		out = append(out, Crossing{Canonical: r, Observations: []*receipt.Receipt{r}})
	}
	return out
}
