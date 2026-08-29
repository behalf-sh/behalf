package why

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"
)

// Layout of the authority tree. The tree is one fixed grid so the three
// verification states line up down the page and a broken hop is impossible
// to miss:
//
//	refund.issue(amount=1200.00)                    run_c71e  step 31
//
//	  ✔ alice@acme.com                    verified   OIDC/google  02:16:58Z
//	       │ delegated: "resolve ticket 4417"
//	       │ scope: tickets.*, orders.read, refund.issue<=100.00
//	       ▼
//	  ✔ support-orchestrator @1.4.2       verified   ed25519 ..whCQN8
//	       ▼
//	  ✖ billing-agent                     UNVERIFIED
//	       │ actor "alice@acme.com" is caller-asserted. no signature.
//	       ▼
//	    refund.issue  amount=1200.00
const (
	headerWidth = 48 // operation summary field on the header line
	labelWidth  = 34 // hop label field, from column 4
	statusWidth = 11 // hop status field ("verified" + gutter)
	detailPad   = "       │ "
	connector   = "       ▼"
)

// ANSI attributes, used only when the destination is a terminal.
const (
	ansiReset  = "\033[0m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiRed    = "\033[31m"
	ansiBold   = "\033[1m"
)

// Options controls rendering. Colour is opt-in and off by default so piped
// and captured output is plain text.
type Options struct {
	Color   bool
	Aliases Aliases
}

// ColorFor reports whether w should get ANSI colour: a terminal, and
// NO_COLOR unset (no-color.org).
func ColorFor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

type painter struct{ on bool }

func (p painter) paint(code, s string) string {
	if !p.on || s == "" {
		return s
	}
	return code + s + ansiReset
}

// Render writes the authority tree for one receipt.
func Render(w io.Writer, res *Result, opt Options) error {
	p := painter{on: opt.Color}
	aliases := opt.Aliases
	if aliases == nil {
		aliases = demoAliases()
	}
	var b strings.Builder

	// Header: what happened, and where it lives.
	b.WriteString(pad(p.paint(ansiBold, operationSummary(res)), headerWidth, operationSummary(res)))
	fmt.Fprintf(&b, "%s  step %d\n\n", res.Address.RunID, res.Address.Step)

	if len(res.Chain) == 0 {
		b.WriteString("  ✖ no delegation chain on this receipt: attribution is unattributed.\n\n")
		fmt.Fprintf(&b, "  chain intact for 0 of 0 hops.\n")
		_, err := io.WriteString(w, b.String())
		return err
	}

	rootLabel := aliases.Label(res.Chain[0].JKT)
	for _, hop := range res.Chain {
		mark, status, color := hopState(hop)
		label := aliases.Label(hop.JKT)
		line := "  " + p.paint(color, mark) + " " +
			pad(label, labelWidth, label) +
			pad(p.paint(color, status), statusWidth, status) +
			hopMethod(hop)
		b.WriteString(strings.TrimRight(line, " ") + "\n")

		for _, d := range hopDetails(hop, rootLabel) {
			b.WriteString(detailPad + d + "\n")
		}
		b.WriteString(connector + "\n")
	}

	// The action itself, at the foot of the chain that authorised it. A
	// failed operation is still an action that happened and says so here
	// (Q4: outcome covers failure of the attempted operation).
	b.WriteString("    " + res.Operation)
	if args := operationArgs(res); args != "" {
		b.WriteString("  " + args)
	}
	if res.Outcome != "" && res.Outcome != "ok" {
		b.WriteString("  [" + p.paint(ansiRed, res.Outcome) + "]")
	}
	b.WriteString("\n")

	if res.Excess != nil {
		b.WriteString("\n  " + p.paint(ansiYellow, "⚠ ") + excessLine(res.Excess) + "\n")
	}
	fmt.Fprintf(&b, "\n  chain intact for %d of %d hops.\n", res.VerifiedHops, res.TotalHops)

	_, err := io.WriteString(w, b.String())
	return err
}

// excessLine is the scope-excess finding, computed at read time and stated
// as a recording, not an enforcement (Q11, Q13, Q45).
func excessLine(e *ScopeExcess) string {
	return fmt.Sprintf("scope: %s<=%s delegated; %s issued. (recorded, not enforced)",
		e.Operation, e.Limit, e.Amount)
}

// hopState maps the stored three-state onto its mark, label and colour. The
// middle state is named, not collapsed into failure: "asserted (unverifiable)
// reads as engineering, FUD does not" (D5).
func hopState(h Hop) (mark, status, color string) {
	switch h.Verification.Status {
	case "verified":
		return "✔", "verified", ansiGreen
	case "broken":
		return "✖", "BROKEN", ansiRed
	default:
		return "✖", "UNVERIFIED", ansiYellow
	}
}

// hopMethod renders the evidence column: what actually makes this hop
// verified, or nothing at all when nothing does.
func hopMethod(h Hop) string {
	if h.Verification.Status != "verified" {
		return ""
	}
	m := h.Verification.Method
	switch {
	case strings.Contains(m, "oidc"):
		out := "OIDC/" + provider(h.Credential.Issuer)
		if h.Credential.AuthTime > 0 {
			out += "  " + time.Unix(h.Credential.AuthTime, 0).UTC().Format("15:04:05Z")
		}
		return out
	case strings.Contains(m, "ed25519"):
		return "ed25519 " + short(h.JKT)
	case m == "":
		return ""
	default:
		return m
	}
}

// provider shortens an issuer URL to the name a human recognises:
// https://accounts.google.com -> google.
func provider(issuer string) string {
	host := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	host, _, _ = strings.Cut(host, "/")
	host = strings.TrimPrefix(host, "accounts.")
	host = strings.TrimPrefix(host, "login.")
	if name, _, ok := strings.Cut(host, "."); ok && name != "" {
		return name
	}
	return host
}

// hopDetails are the indented lines under a hop: what was delegated, and
// what is missing.
func hopDetails(h Hop, rootLabel string) []string {
	var out []string
	if h.Depth == 0 {
		if intent := intentOf(h.Grants); intent != "" {
			out = append(out, fmt.Sprintf("delegated: %q", intent))
		}
		if scope := scopeLine(h.Grants); scope != "" {
			out = append(out, "scope: "+scope)
		}
	}
	switch h.Verification.Status {
	case "asserted":
		// The identity this hop acts under is the chain's root principal,
		// carried here by assertion rather than by signature.
		out = append(out, fmt.Sprintf("actor %q is caller-asserted. no signature.", rootLabel))
	case "broken":
		// Broken is stored at capture: a signature that did not verify or
		// an AAT invariant that did not hold (Q12, Q45).
		line := "chain broken here: a signature or an AAT invariant failed at capture."
		if h.Verification.EvidenceRef != "" {
			line += " evidence: " + h.Verification.EvidenceRef
		}
		out = append(out, line)
	}
	// The read-time comparison, surfaced only when it says something the
	// reader must not miss (Q13).
	switch h.Computed {
	case AttenuationUnknown:
		line := "attenuation: unknown"
		if h.ComputedReason != "" {
			line += " (" + h.ComputedReason + ")"
		}
		out = append(out, line)
	case AttenuationBroadened:
		line := "attenuation: broadened"
		if h.ComputedReason != "" {
			line += " (" + h.ComputedReason + ")"
		}
		out = append(out, line)
	}
	return out
}

// intentOf is the human's words for what was delegated, from the root
// grant.
func intentOf(grants []Grant) string {
	for _, g := range grants {
		if g.Intent != "" {
			return g.Intent
		}
	}
	return ""
}

// scopeLine renders a grant set as the delegated scope, with each
// operation's ceiling appended to it: "tickets.*, orders.read,
// refund.issue<=100.00".
func scopeLine(grants []Grant) string {
	var parts []string
	seen := map[string]bool{}
	for _, g := range grants {
		for _, a := range g.Actions {
			if seen[a] {
				continue
			}
			seen[a] = true
			if l, ok := limitFor(grants, a); ok && l != nil {
				parts = append(parts, a+"<="+l.Amount)
				continue
			}
			parts = append(parts, a)
		}
	}
	return strings.Join(parts, ", ")
}

// operationSummary is the header's left half: the action, with the argument
// the scope check actually compared.
func operationSummary(res *Result) string {
	if args := operationArgs(res); args != "" {
		return res.Operation + "(" + args + ")"
	}
	return res.Operation
}

func operationArgs(res *Result) string {
	if res.Amount != "" {
		return "amount=" + res.Amount
	}
	if res.Target != "" {
		return "target=" + res.Target
	}
	return ""
}

// pad left-aligns s in a field of width columns, measuring plain (the same
// text without ANSI escapes) so colour never shifts the grid. A value wider
// than its field gets a single space rather than a broken column.
func pad(s string, width int, plain string) string {
	n := utf8.RuneCountInString(plain)
	if n >= width {
		return s + " "
	}
	return s + strings.Repeat(" ", width-n)
}
