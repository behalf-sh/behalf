package htmlexport

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Value rendering. Two rules, both of them the same rule the terminal
// keeps:
//
//   - A captured value is never round-tripped through a float. Every decode
//     uses json.Number, so a decimal stored as 1200.00 renders as 1200.00.
//   - What the renderer adds is stated as something the renderer added. The
//     one display convention on this page is the minor-units reading of a
//     `_cents` field, and it travels in its own field (DiffRow.Gloss) so it
//     can never be mistaken for a stored value.
//
// The page shows values in full. The terminal elides at 44 characters
// because it has 78 columns; a document does not, and a digest shown as
// `sha256:143dac…` is not evidence. The caps below exist only to stop one
// pathological value from becoming the whole page, and they say how much
// they left out when they fire.

const (
	// maxValueChars bounds one diff value. Past it the value is cut and the
	// cut is stated, with the byte count of the whole.
	maxValueChars = 2000
	// maxGlossCents guards the currency gloss against a value that is not
	// plausibly money in minor units.
	maxGlossCents = int64(1) << 53
)

// valueText renders one stored value for display: a string unquoted, a
// scalar verbatim, a container pretty-printed.
func valueText(path string, raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var text string
	switch jsonKind(raw) {
	case kindObject, kindArray:
		text = prettyJSON(raw)
	case kindString:
		s, _ := jsonUnquote(raw)
		text = s
	default:
		text = string(bytes.TrimSpace(raw))
	}
	if utf8.RuneCountInString(text) > maxValueChars {
		r := []rune(text)
		return string(r[:maxValueChars]) + fmt.Sprintf("\n… (%d bytes in the stored value; the rest is in the payload slot)", len(raw))
	}
	return text
}

// gloss is the renderer's display convention, kept apart from the value it
// glosses. A field whose name ends in `_cents` holds money in minor units;
// the receipts store integer cents on purpose, so that a decimal string
// never appears where it should not, and showing a bare 120000 to someone
// reading a refund would be the worse lie. The stored value is still shown
// beside it.
func gloss(path string, raw json.RawMessage) string {
	if !strings.HasSuffix(leafKey(path), "_cents") {
		return ""
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil || n > maxGlossCents || n < -maxGlossCents {
		return ""
	}
	return money(n)
}

func money(cents int64) string {
	sign := ""
	if cents < 0 {
		sign, cents = "-", -cents
	}
	return fmt.Sprintf("%s$%s.%02d", sign, group(cents/100), cents%100)
}

// group inserts thousands separators. Amounts on this page are read by
// humans deciding whether a refund was too large; 120000 and 1200.00 are
// exactly the pair that must not be confusable.
func group(n int64) string {
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return s
	}
	var b strings.Builder
	pre := len(s) % 3
	if pre > 0 {
		b.WriteString(s[:pre])
	}
	for i := pre; i < len(s); i += 3 {
		if b.Len() > 0 {
			b.WriteByte(',')
		}
		b.WriteString(s[i : i+3])
	}
	return b.String()
}

// leafKey is the last named segment of a path: "orders[0].amount_cents" ->
// "amount_cents".
func leafKey(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.IndexByte(path, '['); i >= 0 {
		path = path[:i]
	}
	return path
}

type jsonType int

const (
	kindOther jsonType = iota
	kindObject
	kindArray
	kindString
)

func jsonKind(raw []byte) jsonType {
	for _, c := range raw {
		switch c {
		case ' ', '\t', '\n', '\r':
			continue
		case '{':
			return kindObject
		case '[':
			return kindArray
		case '"':
			return kindString
		default:
			return kindOther
		}
	}
	return kindOther
}

func jsonUnquote(raw json.RawMessage) (string, bool) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false
	}
	return s, true
}

func jsonString(s string) json.RawMessage {
	b, err := json.Marshal(s)
	if err != nil {
		return json.RawMessage(`""`)
	}
	return b
}

// prettyJSON re-indents a stored value for reading. It is a DISPLAY
// transformation and nothing more: the bytes that are the evidence are the
// stored span, the digest covers those, and this never travels back into
// anything that is hashed or compared. Numbers keep their literal source
// text (json.Number), so 1200.00 does not become 1200.
func prettyJSON(raw []byte) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return string(raw)
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// canonEqual reports structural equality of two stored values: object keys
// sorted, numbers kept as literal text, so a key-order difference is not a
// difference.
func canonEqual(a, b json.RawMessage) bool {
	ca, errA := canon(a)
	cb, errB := canon(b)
	if errA != nil || errB != nil {
		return bytes.Equal(a, b)
	}
	return bytes.Equal(ca, cb)
}

func canon(raw json.RawMessage) ([]byte, error) {
	if len(raw) == 0 {
		return []byte("null"), nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return json.Marshal(v)
}

// renderContent turns a present slot's bytes into something readable, and
// reports what kind of thing it turned out to be. JSON is pretty-printed,
// valid UTF-8 is passed through, and anything else is summarised rather
// than smeared across the page as mojibake — the point of a rendering is to
// be read.
func renderContent(content []byte, contentType string, maxInline int) (text, language string, truncated bool, omitted int) {
	switch {
	case json.Valid(content) && (jsonKind(content) == kindObject || jsonKind(content) == kindArray):
		text, language = prettyJSON(content), "json"
	case utf8.Valid(content):
		text, language = string(content), "text"
	default:
		// Binary. Show the head as base64 and say plainly what it is; the
		// digest still commits to every byte.
		b64 := base64.StdEncoding.EncodeToString(content)
		if len(b64) > maxInline {
			b64 = b64[:maxInline]
			truncated, omitted = true, len(content)-(maxInline/4*3)
		}
		return fmt.Sprintf("%d bytes of %s, base64:\n%s", len(content), orDefault(contentType, "application/octet-stream"), b64),
			"binary", truncated, omitted
	}
	if len(text) > maxInline {
		cut := maxInline
		for cut > 0 && !utf8.RuneStart(text[cut]) {
			cut--
		}
		omitted = len(text) - cut
		return text[:cut], language, true, omitted
	}
	return text, language, false, 0
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// sizeText renders a byte count the way a reader wants it, with the exact
// count kept beside it wherever the exact count matters.
func sizeText(n int) string {
	switch {
	case n < 1024:
		return fmt.Sprintf("%d B", n)
	case n < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(n)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(n)/(1024*1024))
	}
}

// elapsed renders the offset from a run's first capture to a step's, the
// coordinate the diff's section headers carry.
func elapsed(from, to string) string {
	a, errA := time.Parse(time.RFC3339, from)
	b, errB := time.Parse(time.RFC3339, to)
	if errA != nil || errB != nil {
		return ""
	}
	d := b.Sub(a)
	switch {
	case d < 0:
		return ""
	case d < time.Second:
		return fmt.Sprintf("t+%dms", d.Milliseconds())
	case d < 90*time.Second:
		if d%time.Second == 0 {
			return fmt.Sprintf("t+%ds", int(d.Seconds()))
		}
		return fmt.Sprintf("t+%.1fs", d.Seconds())
	default:
		m := int(d / time.Minute)
		s := int((d % time.Minute) / time.Second)
		return fmt.Sprintf("t+%dm%02ds", m, s)
	}
}

// expiryText renders a per-hop `exp` verbatim as a timestamp. The stored
// value is the number of seconds; showing the date beside it is a display
// convenience and the number stays visible.
func expiryText(exp int64) string {
	if exp == 0 {
		return ""
	}
	return fmt.Sprintf("%s (exp %d)", time.Unix(exp, 0).UTC().Format(time.RFC3339), exp)
}
