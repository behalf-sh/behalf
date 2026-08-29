// Package htmlexport renders one run — or one pair of runs — as a single
// self-contained HTML file.
//
// The terminal is the demo; this is the workhorse. Real runs carry
// multi-kilobyte payloads that no terminal can show, and the export is what
// somebody attaches to a ticket, sends to a colleague, or opens six months
// later in the middle of an incident. It is also the page behalf publishes
// as its own demo: zero backend, linkable, and literally the product's own
// output.
//
// # Three rules the renderer keeps
//
// **Self-contained, absolutely.** The document makes no network request of
// any kind: no CDN, no web font, no remote image, no analytics, no fetch.
// CSS is one inline <style>, script is one inline <script>, every mark is a
// text glyph or an inline SVG. The page also ships its own restrictive
// Content-Security-Policy meta tag, so the promise is enforced by the
// document and not only by the code that wrote it. Assume it will be opened
// from a file:// URL on a machine with no network, because it will be.
//
// **Absence renders.** Payloads are customer-held (Q34, D7), so a run
// exported on a machine whose store was pruned is mostly placeholders — and
// it is still evidence, because the receipts carry the digests regardless
// (Q83). Every slot renders: content when it is present and hashes to its
// commitment, a typed placeholder when it does not, and a visible tamper
// finding — committed digest, actual digest, changed field paths — when the
// stored bytes contradict the signed receipt. A page full of placeholders
// must read as evidence, never as a broken document.
//
// **Nothing is claimed that the bytes do not support.** Every hop states
// what was checked and what was not; the suppression rule is labelled a
// heuristic exactly as the terminal labels it; names come from the local
// alias map and say so; and the page carries the README's threat model, so
// a reader who has never met behalf cannot come away over-trusting the
// document. The page also names itself a rendering and points at the bytes
// that are the evidence, with the exact offline command that re-checks them.
//
// # What it is not
//
// It is not the terminal's ANSI layout transcribed into HTML. Different
// medium, different design: reading-width prose, real hierarchy, monospace
// reserved for the things where it means something (digests, identifiers,
// payload bytes), and a print stylesheet, because these get attached to
// tickets as PDFs.
package htmlexport

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/why"
)

// DefaultCollapseBytes is the rendered-payload size past which a slot's
// content starts collapsed behind its disclosure control. Roughly a dozen
// lines of pretty-printed JSON: enough that a small argument object reads
// inline, little enough that a 40 KB tool response never pushes the next
// receipt off the page.
const DefaultCollapseBytes = 600

// DefaultMaxInlineBytes bounds how much of one payload is written into the
// document. Collapsing keeps a 40 KB blob usable; a 20 MB blob is a
// different problem, and inlining it would produce a file nobody can open.
// Past this bound the head of the content is shown with an explicit,
// visible note naming how many bytes were left out — the digest still
// commits to all of them, and the note says where to get the rest.
const DefaultMaxInlineBytes = 256 << 10

// Options configures one export.
type Options struct {
	// LogDir is the tlog-tiles directory to read. Required.
	LogDir string
	// Runs is one or two run ids. One renders the single-run page; two
	// render the diff-led comparison.
	Runs []string
	// Store is the customer's payload CAS. A nil store is legal and
	// common: every slot then resolves `missing` and renders as a
	// placeholder, which is the normal path (Q83).
	Store *cas.Store
	// Aliases turns key thumbprints into display labels (Q16). Labels are
	// asserted, never evidence, and the page says so.
	Aliases why.Aliases

	// Now stamps the document's generation time. Zero means time.Now.
	Now time.Time
	// CollapseBytes and MaxInlineBytes override the defaults above.
	CollapseBytes  int
	MaxInlineBytes int
}

func (o Options) withDefaults() Options {
	if o.CollapseBytes <= 0 {
		o.CollapseBytes = DefaultCollapseBytes
	}
	if o.MaxInlineBytes <= 0 {
		o.MaxInlineBytes = DefaultMaxInlineBytes
	}
	if o.Now.IsZero() {
		o.Now = time.Now()
	}
	return o
}

// Write builds the page for opt and renders it to w.
func Write(ctx context.Context, w io.Writer, opt Options) (*Page, error) {
	page, err := Build(ctx, opt)
	if err != nil {
		return nil, err
	}
	if err := Render(w, page); err != nil {
		return nil, err
	}
	return page, nil
}

// WriteFile renders the page to path, writing through a temporary file in
// the same directory so an interrupted export never leaves a half-written
// document that looks like a complete one.
func WriteFile(ctx context.Context, path string, opt Options) (*Page, error) {
	page, err := Build(ctx, opt)
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".behalf-export-*.html")
	if err != nil {
		return nil, fmt.Errorf("htmlexport: create %s: %w", path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after a successful rename

	if err := Render(tmp, page); err != nil {
		tmp.Close()
		return nil, err
	}
	if err := tmp.Close(); err != nil {
		return nil, err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return nil, fmt.Errorf("htmlexport: write %s: %w", path, err)
	}
	return page, nil
}
