package htmlexport

import "html/template"

// The document's whole appearance and behaviour, inline.
//
// Nothing here loads: no font file, no stylesheet, no script, no image. The
// type stacks are system stacks, the marks are text glyphs, and the one
// script is thirty lines that open disclosure controls for printing and
// copy a payload to the clipboard. A file opened from file:// on a machine
// with no network must look and behave exactly as it does anywhere else,
// and the only way to guarantee that is to depend on nothing.
//
// The design brief, for whoever changes this next: it is an evidence
// document, not a marketing page. Serif for prose because these get printed
// and read; a system sans for the structural furniture; monospace ONLY
// where monospace means something — digests, identifiers, payload bytes.
// Tabular numerals wherever numbers are meant to be compared down a column.
// Colour carries state (verified / asserted / broken) and nothing else, at
// text weight rather than as blocks of fill, because a page of green panels
// would say "everything is fine" louder than the record does.

const styles template.CSS = `
/* ---- tokens -------------------------------------------------------- */
/* The complete palette is defined here, on :root, for BOTH themes. The
   media query below only overrides values; no colour is ever defined only
   inside a media query, so a browser that reports no preference still gets
   a full palette. */
:root {
  color-scheme: light dark;

  --bg:            #faf9f7;
  --surface:       #ffffff;
  --sunken:        #f3f1ec;
  --ink:           #1a1a18;
  --ink-2:         #4b4945;
  --ink-3:         #767068;
  --rule:          #e3dfd7;
  --rule-strong:   #c8c2b6;
  --accent:        #2b5573;
  --accent-soft:   #eaf0f5;

  --verified:      #17654a;
  --verified-bg:   #e7f1eb;
  --asserted:      #8a5f10;
  --asserted-bg:   #f7eede;
  --broken:        #9d2020;
  --broken-bg:     #f8e8e6;
  --neutral:       #4b4945;
  --neutral-bg:    #efece6;

  --serif: "Iowan Old Style", "Palatino Linotype", Palatino, "Book Antiqua", Georgia, "Times New Roman", serif;
  --sans:  system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
  --mono:  ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace;

  --measure: 72ch;
  --radius: 3px;
}

@media (prefers-color-scheme: dark) {
  :root {
    --bg:          #121211;
    --surface:     #1a1a19;
    --sunken:      #232220;
    --ink:         #e9e6df;
    --ink-2:       #b5b0a7;
    --ink-3:       #8a857c;
    --rule:        #302e2b;
    --rule-strong: #47443f;
    --accent:      #9dbcd4;
    --accent-soft: #1b242b;

    --verified:    #74c39c;
    --verified-bg: #16281f;
    --asserted:    #dcb264;
    --asserted-bg: #2b2314;
    --broken:      #e78d82;
    --broken-bg:   #2d1b18;
    --neutral:     #b5b0a7;
    --neutral-bg:  #26251f;
  }
}

/* ---- base ---------------------------------------------------------- */
* { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: var(--serif);
  font-size: 17px;
  line-height: 1.55;
  /* Receipts are full of long unbreakable tokens — digests, key
     thumbprints, absolute paths. One of them must never push the whole
     page sideways on a narrow screen. */
  overflow-wrap: break-word;
}
.page { max-width: 68rem; margin: 0 auto; padding: 2.5rem 1.5rem 6rem; }
p { margin: 0 0 0.9em; max-width: var(--measure); }
a { color: var(--accent); text-underline-offset: 2px; }
h1, h2, h3, h4 { font-family: var(--serif); font-weight: 600; line-height: 1.2; margin: 0; }
h1 { font-size: 2.1rem; letter-spacing: -0.01em; }
h2 { font-size: 1.45rem; margin: 3.5rem 0 0.4rem; }
h3 { font-size: 1.12rem; margin: 2rem 0 0.4rem; }
h4 { font-size: 0.95rem; margin: 1.2rem 0 0.3rem; }
hr { border: 0; border-top: 1px solid var(--rule); margin: 2.5rem 0; }
code, kbd, pre, .mono { font-family: var(--mono); font-variant-ligatures: none; }
.num, td.num, .digest, .amount { font-variant-numeric: tabular-nums; }
/* A 64-hex digest is one unbreakable word. Printed in full — which is the
   point of an evidence document — it will push the page sideways on a
   narrow screen unless it is told it may break anywhere. <pre> blocks are
   excluded: they carry their own horizontal scroll, and rewrapping a
   payload would change what the reader sees. */
code, .digest { overflow-wrap: anywhere; }
pre, pre code { overflow-wrap: normal; }

/* Small structural furniture is sans: labels, tables, badges, controls.
   The prose stays serif. */
.label, th, .badge, .state, .kv dt, .chip, button, .note-kind, .toc, .crumbs,
table, .timeline, .slot-meta, .hop-meta { font-family: var(--sans); }

.label {
  font-size: 0.68rem; letter-spacing: 0.09em; text-transform: uppercase;
  color: var(--ink-3); font-weight: 600;
}
.muted { color: var(--ink-3); }
.small { font-size: 0.85rem; }
.measured { max-width: var(--measure); }
.spaced { margin-top: 1rem; }
.inset { padding: 0.2rem 1rem 0.7rem; }
.lede { font-size: 1.05rem; color: var(--ink-2); max-width: var(--measure); }

/* ---- document head ------------------------------------------------- */
.doc-head { border-bottom: 2px solid var(--rule-strong); padding-bottom: 1.4rem; }
.wordmark {
  font-family: var(--sans); font-weight: 700; font-size: 0.8rem;
  letter-spacing: 0.16em; text-transform: uppercase; color: var(--ink-3);
  margin-bottom: 0.8rem;
}
.doc-head h1 { margin-bottom: 0.25rem; }
.doc-head .sub { color: var(--ink-2); margin-bottom: 1rem; }

.kv { display: grid; grid-template-columns: repeat(auto-fit, minmax(11rem, 1fr)); gap: 0.9rem 1.6rem; margin: 1.2rem 0 0; }
.kv > div { min-width: 0; }
.kv dt { font-size: 0.68rem; letter-spacing: 0.09em; text-transform: uppercase; color: var(--ink-3); font-weight: 600; margin-bottom: 0.15rem; }
.kv dd { margin: 0; font-size: 0.98rem; overflow-wrap: anywhere; }

/* ---- state badges -------------------------------------------------- */
.state {
  display: inline-flex; align-items: baseline; gap: 0.4em;
  font-size: 0.74rem; font-weight: 600; letter-spacing: 0.04em;
  padding: 0.12em 0.5em; border-radius: var(--radius);
  border: 1px solid transparent; white-space: nowrap;
}
.state::before { content: "\25CF"; font-size: 0.7em; line-height: 1; }
.state-verified { color: var(--verified); background: var(--verified-bg); border-color: color-mix(in srgb, var(--verified) 25%, transparent); }
.state-asserted { color: var(--asserted); background: var(--asserted-bg); border-color: color-mix(in srgb, var(--asserted) 25%, transparent); }
.state-broken   { color: var(--broken);   background: var(--broken-bg);   border-color: color-mix(in srgb, var(--broken) 30%, transparent); }
.state-neutral, .state-unattributed, .state-missing, .state-deleted,
.state-dropped-at-capture { color: var(--neutral); background: var(--neutral-bg); border-color: var(--rule); }
.state-present    { color: var(--verified); background: var(--verified-bg); border-color: color-mix(in srgb, var(--verified) 25%, transparent); }
.state-unreadable { color: var(--broken);   background: var(--broken-bg);   border-color: color-mix(in srgb, var(--broken) 30%, transparent); }
.state-error      { color: var(--broken);   background: var(--broken-bg);   border-color: color-mix(in srgb, var(--broken) 30%, transparent); }
.state-ok         { color: var(--neutral);  background: var(--neutral-bg);  border-color: var(--rule); }

/* ---- blocks -------------------------------------------------------- */
.panel {
  background: var(--surface); border: 1px solid var(--rule);
  border-radius: var(--radius); padding: 1.25rem 1.4rem; margin: 1.2rem 0;
}
.panel > :last-child { margin-bottom: 0; }
.rail { border-left: 3px solid var(--rule-strong); padding-left: 1.1rem; }
.rail-broken { border-left-color: var(--broken); }
.rail-asserted { border-left-color: var(--asserted); }
.rail-accent { border-left-color: var(--accent); }

.claims { display: grid; grid-template-columns: repeat(auto-fit, minmax(19rem, 1fr)); gap: 0 2.2rem; }
.claims h3 { margin-top: 1.2rem; }
.claim { margin: 0 0 1rem; }
.claim b { font-weight: 600; }
.claim p { font-size: 0.93rem; color: var(--ink-2); margin: 0.15rem 0 0; }

.states-legend { margin: 1.2rem 0 0; padding: 0; list-style: none; }
.states-legend li { margin-bottom: 0.5rem; font-size: 0.93rem; color: var(--ink-2); max-width: var(--measure); }

/* ---- tables -------------------------------------------------------- */
.scroll { overflow-x: auto; margin: 1rem 0; }
table { border-collapse: collapse; width: 100%; font-size: 0.88rem; }
th, td { text-align: left; padding: 0.42rem 0.7rem; border-bottom: 1px solid var(--rule); vertical-align: top; }
th {
  font-size: 0.66rem; letter-spacing: 0.09em; text-transform: uppercase;
  color: var(--ink-3); font-weight: 600; border-bottom: 1px solid var(--rule-strong);
  white-space: nowrap;
}
tbody tr:hover { background: var(--sunken); }
td.num, th.num { text-align: right; font-variant-numeric: tabular-nums; }
/* The Q86 three-state bar: one segment per verification state, sized by
   share. The only dynamic style on the page, and it is a number the model
   computed, never anything read out of a receipt. */
.rollup-bar { display: flex; height: 0.5rem; border-radius: 2px; overflow: hidden; margin: 0.5rem 0 0.7rem; }
.rollup-bar .seg { height: 100%; border: 0; border-radius: 0; }

.timeline td:first-child { width: 3.5rem; }
.timeline .op { font-weight: 600; }
.timeline .flag { color: var(--asserted); font-weight: 700; }

/* ---- receipts ------------------------------------------------------ */
.receipt {
  border: 1px solid var(--rule); border-radius: var(--radius);
  background: var(--surface); margin: 1.1rem 0; overflow: hidden;
  /* A real export is hundreds of cards. content-visibility lets the browser
     skip laying out the ones off screen, which is the difference between a
     document that scrolls and one that stutters. Find-in-page and anchor
     links still reach inside; print turns it off (below) so nothing is
     skipped on paper. */
  content-visibility: auto;
  contain-intrinsic-size: auto 460px;
}
.receipt-head {
  display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.5rem 0.9rem;
  padding: 0.85rem 1.1rem; border-bottom: 1px solid var(--rule); background: var(--sunken);
}
.receipt-head .step { font-family: var(--sans); font-size: 0.72rem; font-weight: 700; letter-spacing: 0.07em; text-transform: uppercase; color: var(--ink-3); }
.receipt-head .op { font-size: 1.05rem; font-weight: 600; }
.receipt-head .spacer { flex: 1 1 auto; }
.receipt-body { padding: 1rem 1.1rem 1.2rem; }
.receipt-body > section { margin-top: 1.3rem; }
.receipt-body > section:first-child { margin-top: 0; }

/* ---- delegation chain ---------------------------------------------- */
.chain { list-style: none; margin: 0.6rem 0 0; padding: 0; }
.hop { position: relative; padding: 0 0 1.1rem 1.5rem; border-left: 2px solid var(--rule); }
.hop:last-child { border-left-color: transparent; padding-bottom: 0.2rem; }
.hop::before {
  content: ""; position: absolute; left: -0.42rem; top: 0.42rem;
  width: 0.7rem; height: 0.7rem; border-radius: 50%;
  background: var(--surface); border: 2px solid var(--rule-strong);
}
.hop-verified::before { border-color: var(--verified); background: var(--verified); }
.hop-asserted::before { border-color: var(--asserted); background: var(--surface); }
.hop-broken::before   { border-color: var(--broken); background: var(--broken); }
.hop-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.45rem 0.8rem; }
.hop-head .who { font-weight: 600; }
.hop-meta { font-size: 0.8rem; color: var(--ink-3); margin-top: 0.15rem; overflow-wrap: anywhere; }
.hop-detail { font-size: 0.9rem; color: var(--ink-2); margin-top: 0.5rem; max-width: var(--measure); }
.checks { margin: 0.45rem 0 0; padding: 0; list-style: none; font-size: 0.87rem; }
.checks li { padding-left: 1.3rem; position: relative; color: var(--ink-2); margin-bottom: 0.15rem; max-width: var(--measure); }
.checks li::before { position: absolute; left: 0; top: 0; font-family: var(--sans); }
.checks-yes li::before { content: "\2713"; color: var(--verified); }
.checks-no li::before { content: "\2014"; color: var(--ink-3); }
.checks-title { font-size: 0.7rem; letter-spacing: 0.08em; text-transform: uppercase; color: var(--ink-3); font-weight: 600; margin-top: 0.6rem; font-family: var(--sans); }

/* ---- payload slots ------------------------------------------------- */
.slot { border: 1px solid var(--rule); border-radius: var(--radius); margin: 0.6rem 0; }
.slot-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.4rem 0.8rem; padding: 0.5rem 0.75rem; }
.slot-head .role { font-weight: 600; font-family: var(--sans); font-size: 0.85rem; }
.slot-meta { font-size: 0.76rem; color: var(--ink-3); padding: 0 0.75rem 0.55rem; overflow-wrap: anywhere; }
.slot-meta span + span::before { content: " \00B7 "; color: var(--rule-strong); }
.placeholder {
  margin: 0 0.75rem 0.7rem; padding: 0.5rem 0.7rem; background: var(--sunken);
  border-radius: var(--radius); font-family: var(--mono); font-size: 0.78rem;
  color: var(--ink-2); overflow-wrap: anywhere;
}

.slot-note { padding: 0 0.75rem 0.6rem; margin: 0; }
.finding { margin: 0 0.75rem 0.75rem; border-left: 3px solid var(--broken); background: var(--broken-bg); padding: 0.65rem 0.85rem; border-radius: 0 var(--radius) var(--radius) 0; }
.finding-run { margin-left: 0; margin-right: 0; }
.finding h4 { margin: 0 0 0.35rem; color: var(--broken); font-family: var(--sans); font-size: 0.78rem; letter-spacing: 0.06em; text-transform: uppercase; }
.finding p { font-size: 0.9rem; margin: 0 0 0.5rem; }
.finding dl { display: grid; grid-template-columns: max-content 1fr; gap: 0.15rem 0.8rem; margin: 0; font-size: 0.8rem; }
.finding dt { font-family: var(--sans); font-size: 0.68rem; letter-spacing: 0.07em; text-transform: uppercase; color: var(--ink-3); padding-top: 0.15em; }
.finding dd { margin: 0; font-family: var(--mono); overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }

/* ---- disclosure + payload bodies ----------------------------------- */
details { border-top: 1px solid var(--rule); }
details > summary {
  cursor: pointer; padding: 0.45rem 0.75rem; font-family: var(--sans);
  font-size: 0.78rem; color: var(--ink-2); list-style: none;
  display: flex; align-items: baseline; gap: 0.5rem;
}
details > summary::-webkit-details-marker { display: none; }
details > summary::before { content: "\25B8"; color: var(--ink-3); font-size: 0.8em; }
details[open] > summary::before { content: "\25BE"; }
details > summary:hover { background: var(--sunken); }
details > summary .grow { flex: 1 1 auto; }

pre.payload {
  margin: 0; padding: 0.75rem 0.9rem; background: var(--sunken);
  font-size: 0.78rem; line-height: 1.5; overflow-x: auto;
  border-top: 1px solid var(--rule); white-space: pre; tab-size: 2;
}
.payload-foot { padding: 0.4rem 0.9rem; font-size: 0.76rem; color: var(--ink-3); font-family: var(--sans); border-top: 1px solid var(--rule); }
.truncation { color: var(--broken); }

button.copy {
  font: inherit; font-family: var(--sans); font-size: 0.72rem;
  background: var(--surface); color: var(--ink-2); border: 1px solid var(--rule-strong);
  border-radius: var(--radius); padding: 0.1rem 0.5rem; cursor: pointer;
}
button.copy:hover { background: var(--accent-soft); color: var(--accent); }

/* ---- diff ---------------------------------------------------------- */
.diff-lead { font-size: 1.2rem; font-weight: 600; max-width: var(--measure); margin-bottom: 0.8rem; }
.divergence { border: 1px solid var(--rule); border-left: 3px solid var(--accent); border-radius: 0 var(--radius) var(--radius) 0; background: var(--surface); margin: 1rem 0; }
.divergence.suppressed { border-left-color: var(--rule-strong); }
.divergence-head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 0.4rem 0.8rem; padding: 0.7rem 1rem; border-bottom: 1px solid var(--rule); background: var(--sunken); }
.divergence-head .coords { margin-left: auto; font-family: var(--sans); font-size: 0.74rem; color: var(--ink-3); }
.section-rule { display: flex; align-items: baseline; gap: 0.7rem; margin: 2rem 0 0.2rem; }
.section-rule h3 { margin: 0; white-space: nowrap; }
.section-rule::after { content: ""; flex: 1 1 auto; border-top: 1px solid var(--rule); }

table.sides { font-size: 0.85rem; }
/* A reordered array's columns are short values; letting them spread across
   the full width would put two related numbers a hand's width apart. */
table.sides.compact { width: auto; }
table.sides.compact th, table.sides.compact td { padding-right: 1.6rem; }
table.sides th.run { font-family: var(--mono); text-transform: none; letter-spacing: 0; font-size: 0.78rem; color: var(--ink-2); }
table.sides td.path { font-family: var(--mono); font-size: 0.78rem; color: var(--ink-2); white-space: nowrap; }
table.sides td.val { font-family: var(--mono); font-size: 0.8rem; overflow-wrap: anywhere; font-variant-numeric: tabular-nums; }
table.sides td.val pre { margin: 0; white-space: pre-wrap; font-size: 0.76rem; }
.gloss { color: var(--ink-3); font-family: var(--sans); font-size: 0.75rem; }
.changed { background: color-mix(in srgb, var(--asserted) 12%, transparent); }

.heuristic { border-left: 3px solid var(--asserted); background: var(--asserted-bg); padding: 0.7rem 0.95rem; border-radius: 0 var(--radius) var(--radius) 0; margin: 1.2rem 0; }
.heuristic .note-kind { display: block; font-size: 0.68rem; letter-spacing: 0.09em; text-transform: uppercase; font-weight: 700; color: var(--asserted); margin-bottom: 0.25rem; }
.heuristic p { font-size: 0.9rem; margin: 0 0 0.5rem; }
.heuristic p:last-child { margin-bottom: 0; }

.warning { border-left: 3px solid var(--asserted); padding: 0.6rem 0.95rem; margin: 1rem 0; background: var(--surface); }
.warning p { margin: 0; font-size: 0.95rem; }
.warning code { font-size: 0.82rem; }

/* ---- verification block -------------------------------------------- */
.verify { background: var(--surface); border: 1px solid var(--rule); border-radius: var(--radius); padding: 1.25rem 1.4rem; }
.cmd { margin: 0.9rem 0; }
.cmd pre {
  margin: 0 0 0.3rem; padding: 0.55rem 0.8rem; background: var(--sunken);
  border-radius: var(--radius); font-size: 0.8rem; overflow-x: auto; white-space: pre;
}
.cmd p { font-size: 0.87rem; color: var(--ink-2); margin: 0; }
pre.checkpoint { margin: 0.6rem 0 0; padding: 0.7rem 0.9rem; background: var(--sunken); border-radius: var(--radius); font-size: 0.76rem; overflow-x: auto; white-space: pre; }

/* ---- toc + controls ------------------------------------------------ */
.toolbar { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; margin: 1.4rem 0 0; }
.toc { display: flex; flex-wrap: wrap; gap: 0.15rem 1.1rem; font-size: 0.84rem; margin: 1.2rem 0 0; padding: 0.7rem 0 0; border-top: 1px solid var(--rule); }
.toc a { color: var(--ink-2); text-decoration: none; }
.toc a:hover { color: var(--accent); text-decoration: underline; }

.notes { border-left: 3px solid var(--rule-strong); padding: 0.6rem 0.95rem; background: var(--sunken); margin: 1.4rem 0; }
.notes p { font-size: 0.9rem; margin: 0 0 0.5rem; }
.notes p:last-child { margin-bottom: 0; }

footer.doc-foot { margin-top: 4rem; padding-top: 1.2rem; border-top: 1px solid var(--rule); color: var(--ink-3); font-size: 0.85rem; }

/* ---- print --------------------------------------------------------- */
@page { margin: 16mm 14mm; }
@media print {
  :root {
    --bg: #ffffff; --surface: #ffffff; --sunken: #f4f4f2;
    --ink: #000000; --ink-2: #262626; --ink-3: #555555;
    --rule: #cccccc; --rule-strong: #999999; --accent: #14364a; --accent-soft: #eef2f5;
    --verified: #14563d; --verified-bg: #eef5f1;
    --asserted: #6f4c0c; --asserted-bg: #f8f1e2;
    --broken: #8a1a1a; --broken-bg: #f8eceb;
    --neutral: #262626; --neutral-bg: #f0efec;
  }
  body { font-size: 10.5pt; background: #fff; }
  .page { max-width: none; padding: 0; }
  .no-print { display: none !important; }
  a { color: inherit; text-decoration: none; }
  h2 { break-after: avoid; page-break-after: avoid; margin-top: 1.6rem; }
  h3, h4, .section-rule { break-after: avoid; page-break-after: avoid; }
  .receipt, .divergence, .slot, .finding, .cmd, .claim, .hop {
    break-inside: avoid; page-break-inside: avoid;
  }
  .receipt { border-color: var(--rule-strong); content-visibility: visible; contain-intrinsic-size: auto; }
  tbody tr:hover { background: none; }
  pre.payload { max-height: none; white-space: pre-wrap; overflow: visible; }
  .scroll { overflow: visible; }
  /* If the print handler ran, everything is open and this never fires. It
     is here for a reader who has scripting off: a collapsed section must
     never print as though it were absent. */
  details:not([open]) > summary::after {
    content: " \2014 collapsed; expand before printing";
    color: var(--broken); font-size: 0.9em;
  }
  /* Each run, and the verification block, start a fresh page. These get
     attached to tickets, and a run that begins two lines from the bottom of
     a page reads as a continuation of the one above it. */
  section[data-section="run"], section[data-section="verify"] {
    break-before: page; page-break-before: always;
  }
}
`

// script is the entire behaviour of the document: open disclosure controls
// for printing (and put them back), an expand/collapse-everything control,
// and a copy button per payload. It touches nothing outside this page and
// reaches for no network API.
//
// Everything it does is a convenience. With scripting off the page is
// complete: the sections are all there, the payloads are all there behind
// their own <summary>, and the print stylesheet marks anything still
// collapsed rather than letting it print as an absence.
const script template.JS = `
(function () {
  "use strict";
  var body = document.body;

  function all(sel) { return Array.prototype.slice.call(document.querySelectorAll(sel)); }

  // Printing: a collapsed <details> prints as a one-line summary, which
  // would read as though the payload were not in the document. Open them
  // all, print, then put back exactly what the reader had open.
  var reopened = [];
  function expandForPrint() {
    reopened = all("details:not([open])");
    reopened.forEach(function (d) { d.open = true; });
  }
  function restoreAfterPrint() {
    reopened.forEach(function (d) { d.open = false; });
    reopened = [];
  }
  window.addEventListener("beforeprint", expandForPrint);
  window.addEventListener("afterprint", restoreAfterPrint);
  if (window.matchMedia) {
    var mq = window.matchMedia("print");
    var onChange = function (e) { if (e.matches) { expandForPrint(); } else { restoreAfterPrint(); } };
    if (mq.addEventListener) { mq.addEventListener("change", onChange); }
    else if (mq.addListener) { mq.addListener(onChange); }
  }

  // One control for the whole document.
  var toggle = document.getElementById("expand-all");
  if (toggle) {
    toggle.hidden = false;
    toggle.addEventListener("click", function () {
      var open = toggle.getAttribute("data-open") !== "true";
      all("details").forEach(function (d) { d.open = open; });
      toggle.setAttribute("data-open", open ? "true" : "false");
      toggle.textContent = open ? "Collapse everything" : "Expand everything";
    });
  }

  // Copy a payload. The clipboard API is unavailable on some file:// origins,
  // so fall back to selecting the text — which is what the reader would do
  // by hand anyway.
  body.addEventListener("click", function (ev) {
    var btn = ev.target.closest ? ev.target.closest("button[data-copy]") : null;
    if (!btn) { return; }
    var target = document.getElementById(btn.getAttribute("data-copy"));
    if (!target) { return; }
    var text = target.textContent;
    var done = function (msg) {
      var was = btn.textContent;
      btn.textContent = msg;
      setTimeout(function () { btn.textContent = was; }, 1400);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { done("copied"); }, function () { select(target); done("selected"); });
    } else {
      select(target);
      done("selected");
    }
  });

  function select(node) {
    var sel = window.getSelection && window.getSelection();
    if (!sel) { return; }
    var range = document.createRange();
    range.selectNodeContents(node);
    sel.removeAllRanges();
    sel.addRange(range);
  }
})();
`
