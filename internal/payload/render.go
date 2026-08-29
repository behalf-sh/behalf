package payload

import (
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"
)

// Rendering exists because absence is the normal reading of a behalf
// record, not a failure of it. Payloads are customer-held (D7), so a
// reconstruction assembled on a machine whose CAS was pruned, or years
// after a retention sweep, is *mostly* placeholders — and it is still
// verifiable evidence, because the receipts carry the digests regardless
// (Q83). A renderer that printed nothing for a non-present slot would turn
// that honest state into an apparent gap in the record, which is the one
// thing behalf must never do.
//
// So: every slot renders. A present slot renders its content; every other
// slot renders a typed placeholder naming the state, the commitment and the
// custody mode, so the reader can see precisely which of the three findings
// they are looking at.

// shortDigestLen is how much of a hex digest a placeholder shows. Twelve
// hex characters is 48 bits — enough to recognise a digest across a
// rendering and to match it against a store listing by eye, and short
// enough that a 47-step reconstruction stays readable.
const shortDigestLen = 12

// Short abbreviates a digest for display: `sha256:9f2ac71e0a4b…`. It keeps
// any `sha256:` prefix the value already carries and adds one otherwise, so
// a slot's Ref and its Digest render identically.
func Short(digest string) string {
	if digest == "" {
		return "sha256:?"
	}
	body := strings.TrimPrefix(digest, "sha256:")
	if len(body) <= shortDigestLen {
		return "sha256:" + body
	}
	return "sha256:" + body[:shortDigestLen] + "…"
}

// Placeholder renders the typed stand-in for a slot whose content this
// reader does not have:
//
//	[missing: sha256:9f2ac71e0a4b… (customer-held)]
//	[deleted: sha256:9f2ac71e0a4b… (customer-held) — erasure_notice run_c71e:44]
//	[dropped-at-capture: sha256:9f2ac71e0a4b… (dropped-with-digest)]
//	[unreadable: sha256:9f2ac71e0a4b… (customer-held) — stored bytes hash to
//	 sha256:1de9f0a3b7c2…, not the committed sha256:9f2ac71e0a4b… (changed: $.amount)]
//
// A present slot has no placeholder and renders as the empty string; use
// Render, which picks between the two.
func (s Slot) Placeholder() string {
	if s.State == StatePresent {
		return ""
	}
	custody := s.Custody
	if custody == "" {
		custody = "custody unrecorded"
	}
	b := &strings.Builder{}
	fmt.Fprintf(b, "[%s: %s (%s)", s.State, Short(s.Digest), custody)
	switch {
	case s.Mismatch != nil:
		b.WriteString(" — " + s.Mismatch.String())
	case s.Err != nil:
		b.WriteString(" — " + s.Err.Error())
	case s.CauseRef != "":
		b.WriteString(" — erasure_notice " + s.CauseRef)
	}
	b.WriteString("]")
	return b.String()
}

// Render is what a reconstruction prints for one slot: the content when the
// slot is present, the typed placeholder otherwise. It never returns "".
//
// Binary content — anything that is not valid UTF-8 — renders as a typed
// summary rather than as mojibake, because the point of a rendering is to
// be read.
func (s Slot) Render() string {
	if s.State != StatePresent {
		return s.Placeholder()
	}
	if utf8.Valid(s.Content) {
		return string(s.Content)
	}
	return fmt.Sprintf("[present: %s (%s) — %d bytes of %s, base64 %s]",
		Short(s.Digest), s.Custody, len(s.Content), s.contentType(),
		base64.StdEncoding.EncodeToString(s.Content))
}

// Label names the slot for a human: its role when it has one, else its
// short digest. `input`, `output` — the two the MCP proxy writes.
func (s Slot) Label() string {
	if s.Role != "" {
		return s.Role
	}
	return Short(s.Digest)
}

func (s Slot) contentType() string {
	if s.ContentType == "" {
		return "application/octet-stream"
	}
	return s.ContentType
}

// RenderAll renders every slot as `role: rendering` lines, in slot order —
// the order the capture surface wrote them, which for the MCP proxy is
// input then output.
func RenderAll(slots []Slot) string {
	b := &strings.Builder{}
	for i, s := range slots {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(s.Label())
		b.WriteString(": ")
		b.WriteString(s.Render())
	}
	return b.String()
}

// Summary counts the slots by resolved state, in the schema's enum order,
// for a one-line coverage report: `47 present, 2 missing`. States with no
// slots are omitted.
func Summary(slots []Slot) string {
	order := []State{StatePresent, StateMissing, StateDeleted, StateUnreadable, StateDroppedAtCapture}
	counts := map[State]int{}
	for _, s := range slots {
		counts[s.State]++
	}
	var parts []string
	for _, st := range order {
		if n := counts[st]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, st))
		}
	}
	if len(parts) == 0 {
		return "no payload slots"
	}
	return strings.Join(parts, ", ")
}
