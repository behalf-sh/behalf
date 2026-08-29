package htmlexport

import (
	"fmt"
	"strings"

	"github.com/behalf-sh/behalf/internal/why"
)

// The honesty furniture.
//
// This block is on the page for the same reason it is first in the README:
// "anyone security-literate will find these limits in ten seconds; stating
// them up front is cheaper than being corrected." The wording below is the
// README's, deliberately — the limits are behalf's published claims, and a
// second set of words for them is a second set of claims to keep true.
//
// A reader who has never met behalf will meet it through one of these
// files. They must not come away believing the document proves the agent
// did what it says it did (Q29, Q74, D5).

func trustBlock() TrustBlock {
	return TrustBlock{
		Proves: []Claim{
			{
				Label: "Record integrity",
				Body: "No receipt was modified, dropped, reordered or back-dated after it was written. " +
					"The log is a tiled transparency log; checkpoints are signed every second; verification is " +
					"fully offline against the exported bytes — no call to behalf, no call to your identity provider.",
			},
			{
				Label: "Chain authorisation",
				Body: "That hop N of a delegation chain was authorised by hop N−1, cryptographically, per hop. " +
					"Where that signature was checked at capture, this page says so on the hop itself.",
			},
			{
				Label: "The identity root",
				Body: "That a specific human authenticated with a specific identity provider at a specific time, " +
					"and controls the device key the chain descends from. This is the one genuinely " +
					"third-party-checkable fact in the stack: the OIDC nonce is the thumbprint of a freshly " +
					"generated device key, so the provider's own signature binds that human to that key.",
			},
		},
		NotProves: []Claim{
			{
				Label: "That the agent did what the receipt says",
				Body: "behalf records what the capture surface observed. A compromised or prompt-injected agent " +
					"can emit a receipt describing something it did not do. Such content is recorded as " +
					"asserted, and this page says so.",
			},
			{
				Label: "The agent's own integrity",
				Body:  "Local capture cannot attest the process it runs inside. This is a structural limit, not a v1 shortcut.",
			},
			{
				Label: "Anything before capture",
				Body: "Custody begins when the capture surface signs. Suppression upstream of that point is out of " +
					"scope; what the record does show is silence.",
			},
			{
				Label: "That a workstation user cannot bypass capture",
				Body: "They can — by removing the proxy from their config. v1 makes capture coverage visible rather " +
					"than pretending it is enforced.",
			},
		},
		States: []StateNote{
			{State: "verified", Body: "The hop's signature was checked at capture and held, by the method named beside it."},
			{State: "asserted", Body: "Recorded, not proven. The honest middle: the record carries what the capture surface " +
				"observed, and nothing cryptographic was established at this hop. Collapsing it into “broken” would be FUD."},
			{State: "broken", Body: "A signature or an AAT invariant failed at capture. Everything this hop authorises is unproven, " +
				"and the receipt-level rollup is the weakest hop."},
		},
		Footnote: "Names shown for keys — “alice@acme.com”, “billing-agent” — come from the local alias map. " +
			"They are asserted labels, never cryptographic claims: the canonical actor identity is the key " +
			"thumbprint printed beside each one.",
	}
}

// hopChecks states, per hop, what its verification state actually rests on
// and what it does not. Every state gets both halves — an unqualified
// "verified" is the more dangerous one to leave unexplained.
func hopChecks(h why.Hop, rootLabel string) (checked, notChecked []string) {
	method := strings.ToLower(h.Verification.Method)
	switch h.Verification.Status {
	case "verified":
		switch {
		case strings.Contains(method, "oidc"):
			checked = []string{
				"the identity provider's signature over the ID token",
				"that the OIDC nonce equals the RFC 7638 thumbprint of this device key",
				"that the root delegation is signed by that same key",
			}
			notChecked = []string{
				"who was at the keyboard — the binding proves control of a key, not presence",
				"that this human intended this particular action; approval, where it exists, is a separate receipt and never reclassifies attribution",
			}
		case strings.Contains(method, "ed25519") || strings.Contains(method, "aat") || strings.Contains(method, "jws"):
			checked = []string{
				"this hop's AAT signature, against the parent hop's confirmation key",
				"the AAT draft's attenuation invariants over the raw RFC 9396 grants",
			}
			notChecked = []string{
				"what the holder of this key actually did — the operation below is the capture surface's observation, not a proof",
			}
		default:
			checked = []string{"this hop's signature, by the method recorded at capture"}
			notChecked = []string{
				"what the holder of this key actually did — the operation below is the capture surface's observation, not a proof",
			}
		}
	case "broken":
		checked = []string{"a signature or an AAT invariant was checked at capture, and it failed"}
		notChecked = []string{
			"nothing this hop authorises can be relied on",
			"the receipt-level rollup is the weakest hop, so this receipt reads broken however strong the hops above it are",
		}
		if h.Verification.EvidenceRef != "" {
			checked = append(checked, "evidence: "+h.Verification.EvidenceRef)
		}
	default:
		checked = []string{
			"the record carries this hop's claimed key, grants and expiry exactly as the capture surface saw them",
		}
		notChecked = []string{
			"no signature over this hop was verified at capture",
			fmt.Sprintf("the identity this hop acts under (%s) is the chain's root principal, carried here by assertion rather than by signature", rootLabel),
			"nothing binds this hop to its parent beyond the record itself",
		}
	}
	return checked, notChecked
}

// verifyCommands are the exact lines a sceptic runs. They are the shipped
// verifier's own argument shapes (docs/export-format-v1.md §2, §2a) — this
// page is a rendering, and these commands go at the bytes that are the
// evidence.
func verifyCommands(logDir string, runs []string) []Command {
	cmds := []Command{{
		Line: fmt.Sprintf("behalf-verify log %s", shellQuote(logDir)),
		What: "Verifies the log directory this page was rendered from: the checkpoint note signature, " +
			"bundle coverage, every entry's content, and the recomputed Merkle root against the signed one. " +
			"Offline — it makes no network call and no call to behalf.",
	}}
	for _, run := range runs {
		cmds = append(cmds,
			Command{
				Line: fmt.Sprintf("behalf-log export --dir %s --run %s --out %s.jsonl", shellQuote(logDir), shellQuote(run), run),
				What: "Writes the self-contained export file for this run: the signed receipt bytes verbatim, " +
					"the keys they were signed with, and the chain head.",
			},
			Command{
				Line: fmt.Sprintf("behalf-verify %s.jsonl", run),
				What: "Checks that export on its own. Exit 0 means every receipt is intact and the chain and head verify; " +
					"exit 1 names the tamper class and the receipt index it broke at.",
			},
		)
	}
	cmds = append(cmds, Command{
		Line: fmt.Sprintf("behalf-log rehydrate --dir %s --run %s", shellQuote(logDir), shellQuote(firstOr(runs, "<run>"))),
		What: "Joins the receipts against your own payload store and reports any blob whose bytes no longer hash " +
			"to the digest committed in its signed receipt — the payload finding this page shows in full.",
	})
	return cmds
}

func firstOr(s []string, def string) string {
	if len(s) == 0 {
		return def
	}
	return s[0]
}

// shellQuote makes a path safe to paste. The commands on this page are
// meant to be copied and run, so a directory with a space in it must not
// turn into two arguments.
func shellQuote(s string) string {
	if s == "" {
		return "''"
	}
	safe := true
	for _, r := range s {
		if !(r == '/' || r == '.' || r == '-' || r == '_' || r == '~' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
