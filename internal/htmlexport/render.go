package htmlexport

import (
	"bufio"
	"fmt"
	"html/template"
	"io"
	"strings"
)

// Render writes the page.
//
// The document is assembled by html/template, which escapes in context. That
// matters more here than in most renderers: everything on this page came out
// of a receipt, and a receipt records what an agent said. Operation names,
// targets, labels and payload bytes are all attacker-influenceable in the
// threat model this product is about (Q74), so none of them may reach the
// output unescaped, and none of them do — the template has no raw-HTML
// interpolation anywhere. The only pre-typed values in the whole page are
// the stylesheet, the script and the rollup bar's widths, all three of them
// constants or computed numbers, none of them derived from a receipt.
func Render(w io.Writer, p *Page) error {
	bw := bufio.NewWriterSize(w, 64<<10)
	if err := pageTemplate.Execute(bw, p); err != nil {
		return fmt.Errorf("htmlexport: render: %w", err)
	}
	return bw.Flush()
}

var funcs = template.FuncMap{
	// stateClass maps a state word onto its CSS class, through a whitelist.
	// A state the schema does not define renders neutral rather than
	// inventing a class name out of stored data.
	"stateClass": func(state string) string {
		switch state {
		case "verified", "asserted", "broken", "present", "unreadable",
			"missing", "deleted", "dropped-at-capture", "ok", "error", "unattributed":
			return "state-" + strings.ReplaceAll(state, " ", "-")
		default:
			return "state-neutral"
		}
	},
	"styles": func() template.CSS { return styles },
	"script": func() template.JS { return script },
	"join":   func(sep string, items []string) string { return strings.Join(items, sep) },
	// payloadID names a <pre> so its copy button can find it. Both halves go
	// through safeID, so a role or run id out of a receipt cannot forge an
	// element id.
	"payloadID": func(runID string, step int, label string) string {
		return fmt.Sprintf("payload-%s-%d-%s", safeID(runID), step, safeID(label))
	},
	"multiline": func(s string) bool { return strings.Contains(s, "\n") },
	// dict passes several values into a sub-template, which Go templates
	// otherwise cannot do. Keys must be strings; a bad call is a programming
	// error in this file and fails the render loudly rather than silently
	// dropping a section.
	"dict": func(kv ...any) (map[string]any, error) {
		if len(kv)%2 != 0 {
			return nil, fmt.Errorf("dict: odd argument count %d", len(kv))
		}
		m := make(map[string]any, len(kv)/2)
		for i := 0; i < len(kv); i += 2 {
			k, ok := kv[i].(string)
			if !ok {
				return nil, fmt.Errorf("dict: key %d is not a string", i)
			}
			m[k] = kv[i+1]
		}
		return m, nil
	},
}

var pageTemplate = template.Must(template.New("page").Funcs(funcs).Parse(pageHTML))

// pageHTML is the whole document.
//
// The Content-Security-Policy is not decoration. The package promises the
// page makes no network request; the meta tag makes the DOCUMENT enforce
// that promise, so a future edit that reaches for a CDN fails visibly in the
// browser instead of silently phoning home from someone's laptop.
// `default-src 'none'` forbids every fetch destination; style and script are
// allowed inline and from nowhere else; images are allowed only as data:
// URIs. There is no connect-src, so fetch, XHR and WebSocket are all denied.
const pageHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'">
<meta name="generator" content="behalf export">
<meta name="robots" content="noindex">
<title>{{.Title}} — behalf receipt export</title>
<style>{{styles}}</style>
</head>
<body data-mode="{{if .Pair}}pair{{else}}run{{end}}" data-runs="{{len .Runs}}" data-findings="{{.Findings}}">
<div class="page">

<header class="doc-head" data-section="document-head">
  <div class="wordmark">behalf &middot; action receipt export</div>
  <h1>{{.Title}}</h1>
  <p class="sub">{{.Subtitle}}</p>
  <dl class="kv">
    <div><dt>Rendered</dt><dd class="num">{{.GeneratedAt}}</dd></div>
    <div><dt>Log origin</dt><dd class="mono small">{{if .Log.Available}}{{.Log.Origin}}{{else}}unavailable{{end}}</dd></div>
    <div><dt>Tree size</dt><dd class="num">{{if .Log.Available}}{{.Log.TreeSize}} leaves{{else}}—{{end}}</dd></div>
    <div><dt>Chain head</dt><dd class="mono small digest">{{if .Log.Available}}{{.Log.RootHex}}{{else}}—{{end}}</dd></div>
  </dl>
  <div class="toolbar no-print">
    <button type="button" id="expand-all" class="copy" hidden data-open="false">Expand everything</button>
    <span class="small muted">This page is a rendering of the bytes in the log. It is not the evidence; the receipts are.</span>
  </div>
  <nav class="toc">
    <a href="#what-this-proves">What this proves</a>
    {{if .Diff}}<a href="#divergence">Divergence</a>{{end}}
    {{range .Runs}}<a href="#{{.Anchor}}">Run {{.ID}}</a>{{end}}
    <a href="#verify">Verify it yourself</a>
  </nav>
</header>

{{if .Notes}}
<div class="notes" data-section="notes">
  <p class="label">What this rendering could not show</p>
  {{range .Notes}}<p>{{.}}</p>{{end}}
</div>
{{end}}

{{/* ---------------------------------------------------------------- */}}
{{template "trust" .}}

{{if .Diff}}{{template "diff" .}}{{end}}

{{range .Runs}}{{template "run" .}}{{end}}

{{template "verify" .}}

<footer class="doc-foot">
  <p>Generated by <b>behalf export</b> at {{.GeneratedAt}} from <code>{{.Log.Dir}}</code>.
  Self-contained: this file loads nothing and reports nothing anywhere.
  Names shown for keys are local alias-map labels, never cryptographic claims.</p>
</footer>

</div>
<script>{{script}}</script>
</body>
</html>
`

func init() {
	template.Must(pageTemplate.New("trust").Parse(trustHTML))
	template.Must(pageTemplate.New("diff").Parse(diffHTML))
	template.Must(pageTemplate.New("diffblock").Parse(diffBlockHTML))
	template.Must(pageTemplate.New("run").Parse(runHTML))
	template.Must(pageTemplate.New("receipt").Parse(receiptHTML))
	template.Must(pageTemplate.New("slot").Parse(slotHTML))
	template.Must(pageTemplate.New("verify").Parse(verifyHTML))
}

const trustHTML = `
<section id="what-this-proves" data-section="trust">
  <h2>What this document proves — and what it does not</h2>
  <p class="lede">This section is first on purpose. Anyone security-literate will find these limits in ten
  seconds; stating them up front is cheaper than being corrected.</p>
  <div class="panel claims">
    <div>
      <h3>What the verifier proves</h3>
      {{range .Trust.Proves}}
      <div class="claim" data-claim="proves"><b>{{.Label}}.</b><p>{{.Body}}</p></div>
      {{end}}
    </div>
    <div>
      <h3>What it does not prove, and cannot</h3>
      {{range .Trust.NotProves}}
      <div class="claim" data-claim="not-proves"><b>{{.Label}}.</b><p>{{.Body}}</p></div>
      {{end}}
    </div>
  </div>
  <ul class="states-legend" data-section="states">
    {{range .Trust.States}}
    <li><span class="state {{stateClass .State}}">{{.State}}</span> {{.Body}}</li>
    {{end}}
  </ul>
  <p class="small muted measured">{{.Trust.Footnote}}</p>
</section>
`

const diffHTML = `
{{with .Diff}}
<section id="divergence" data-section="diff" data-differences="{{len .All}}" data-suppressed="{{.SuppressedCount}}" data-opaque="{{len .Opaque}}" data-aligner="{{.Aligner}}">
  <h2>Which step diverged</h2>
  <p class="diff-lead" data-diff-summary>{{.Summary}}</p>
  <p class="small muted">{{.AlignerNote}}</p>

  {{if .First}}
    <div class="section-rule"><h3>First divergence</h3></div>
    <p class="small muted">The first difference in aligned order. This is a fact about the alignment, not a claim about the world.</p>
    {{template "diffblock" dict "Block" .First "Role" "first"}}
    {{if .LinkText}}<p class="small" data-link-evidence>{{.LinkText}}</p>{{end}}

    {{if and .Featured (not .FeaturedIsFirst)}}
      <div class="section-rule"><h3>{{.FeaturedTitle}}</h3></div>
      {{if .FeaturedIsConsequence}}
        <p class="small muted">The furthest-downstream step whose differing arguments are traceable to the first
        divergence by value equality. The link is exhibited above, not asserted: this is not a dataflow tracer.</p>
      {{else}}
        <p class="small muted">The last differing step. No value from the first divergence can be shown to have
        reached it, so it is named a later difference and not a consequence.</p>
      {{end}}
      {{template "diffblock" dict "Block" .Featured "Role" "featured"}}
    {{end}}
  {{else}}
    <div class="panel">
      <p>No divergence: every aligned step matches in operation, arguments and outcome. Only run-scoped
      fields differ, and those are filtered by construction.</p>
    </div>
  {{end}}

  {{if .SuppressionNote}}
  <div class="heuristic" data-note="suppression">
    <span class="note-kind">Heuristic, not a finding</span>
    <p>The first difference in aligned order is named the cause, and every later difference is presumed
    downstream of it. There is no dataflow tracer behind that presumption.</p>
    <p>{{.SuppressionNote}}</p>
  </div>
  {{end}}

  {{if .OpaqueNote}}<p class="small muted" data-note="opaque">{{.OpaqueNote}}</p>{{end}}

  {{range .Warnings}}
  <div class="warning" data-warning="attribution">
    {{if .Unattributed}}
    <p><b>{{.Operation}}</b> in {{.RunID}} carries no delegation chain: its attribution is
    <span class="state state-neutral">unattributed</span>. <code>{{.Command}}</code></p>
    {{else}}
    <p><b>{{.Operation}}</b> in {{.RunID}} is attributed to {{.Actor}}, but that hop is
    <span class="state {{if eq .State "broken"}}state-broken{{else}}state-asserted{{end}}">{{.State}}</span>.
    <code>{{.Command}}</code></p>
    {{end}}
  </div>
  {{end}}

  {{if .AttributionNote}}<p class="small muted" data-note="run-attribution">{{.AttributionNote}}</p>{{end}}

  {{if or .All .Opaque}}
  <details data-section="all-differences">
    <summary><span class="grow">Every difference, suppression off &middot; {{len .All}} explained{{if .Opaque}}, {{len .Opaque}} digest-only{{end}}</span></summary>
    <div class="inset">
      {{range $i, $b := .All}}{{template "diffblock" dict "Block" $b "Role" "all"}}{{end}}
      {{range $i, $b := $.Diff.Opaque}}{{template "diffblock" dict "Block" $b "Role" "opaque"}}{{end}}
    </div>
  </details>
  {{end}}
</section>
{{end}}
`

// diffBlockHTML renders one aligned pair. It is called with a dict so the
// block knows what part it is playing on the page.
const diffBlockHTML = `
{{$b := .Block}}
<div class="divergence{{if $b.Suppressed}} suppressed{{end}}" data-role="{{.Role}}" data-step-a="{{$b.StepA}}" data-step-b="{{$b.StepB}}"{{if $b.Opaque}} data-opaque="true"{{end}}>
  <div class="divergence-head">
    <span class="label">{{$b.Label}}</span>
    <span class="op mono">{{$b.Operation}}</span>
    {{if $b.Target}}<span class="small muted">{{$b.Target}}</span>{{end}}
    {{range $b.Classes}}<span class="state state-neutral">{{.}}</span>{{end}}
    {{if $b.Coords}}<span class="coords">{{$b.Coords}}</span>{{end}}
  </div>
  <div class="inset">
    <p class="small muted">Acting key: {{$b.Actor}}.{{if $b.MissingFrom}} This step has no counterpart in {{$b.MissingFrom}}.{{end}}
      {{if or $b.AnchorA $b.AnchorB}}
        Receipt detail:
        {{if $b.AnchorA}}<a href="#{{$b.AnchorA}}">step {{$b.StepA}}</a>{{end}}{{if and $b.AnchorA $b.AnchorB}},{{end}}
        {{if $b.AnchorB}}<a href="#{{$b.AnchorB}}">step {{$b.StepB}}</a>{{end}}.
      {{end}}
    </p>

    {{with $b.Reordered}}
    <p class="small"><b>{{.Count}} {{.Path}} returned in a different order.</b>
      {{if ge .Index 0}} The runs first hold different elements at position [{{.Index}}]{{if .Fields}}, differing in {{join ", " .Fields}}{{end}}.{{end}}
      Same elements, same count — the divergence that reads as “nothing changed” to every other tool.</p>
    <div class="scroll">
      <table class="sides compact" data-table="reordered">
        <thead><tr><th>run</th>{{range .Fields}}<th>{{.}}</th>{{end}}</tr></thead>
        <tbody>
          <tr><th class="run">{{$b.RunA}}</th>{{range $i, $v := .RowsA}}<td class="val">{{$v}}{{$g := index $.Block.Reordered.GlossA $i}}{{if $g}} <span class="gloss">{{$g}}</span>{{end}}</td>{{end}}</tr>
          <tr><th class="run">{{$b.RunB}}</th>{{range $i, $v := .RowsB}}<td class="val changed">{{$v}}{{$g := index $.Block.Reordered.GlossB $i}}{{if $g}} <span class="gloss">{{$g}}</span>{{end}}</td>{{end}}</tr>
        </tbody>
      </table>
    </div>
    {{end}}

    {{if $b.Rows}}
    <div class="scroll">
      <table class="sides" data-table="fields">
        <thead><tr><th>field</th><th class="run">{{$b.RunA}}</th><th class="run">{{$b.RunB}}</th></tr></thead>
        <tbody>
          {{range $b.Rows}}
          <tr data-path="{{.Path}}" data-kind="{{.Kind}}">
            <td class="path">{{.Path}}</td>
            <td class="val">{{if multiline .A}}<pre>{{.A}}</pre>{{else}}{{.A}}{{end}}{{if .GlossA}} <span class="gloss">{{.GlossA}}</span>{{end}}</td>
            <td class="val changed">{{if multiline .B}}<pre>{{.B}}</pre>{{else}}{{.B}}{{end}}{{if .GlossB}} <span class="gloss">{{.GlossB}}</span>{{end}}</td>
          </tr>
          {{end}}
        </tbody>
      </table>
    </div>
    {{end}}

    {{if $b.Truncated}}<p class="small muted">More field-level differences were found than the engine keeps for one pair; the rest are not listed.</p>{{end}}
    {{if $b.NoiseFiltered}}<p class="small muted" data-noise>{{len $b.NoiseFiltered}} field(s) ignored as run-scoped noise: {{join ", " $b.NoiseFiltered}}.</p>{{end}}
    {{if $b.Opaque}}<p class="small muted">Only a payload digest differs here. The receipt records that customer-held content changed, not what changed in it — so this is reported and never named as a cause.</p>{{end}}
  </div>
</div>
`

const runHTML = `
<section id="{{.Anchor}}" data-section="run" data-run="{{.ID}}" data-actions="{{.Actions}}" data-receipts="{{len .Receipts}}" data-status="{{.Status}}" data-attribution="{{.Attribution}}" data-findings="{{.Findings}}">
  <h2>Run {{.ID}}</h2>
  <dl class="kv" data-block="run-header">
    <div><dt>Run</dt><dd class="mono">{{.ID}}</dd></div>
    <div><dt>Started</dt><dd class="num">{{.Started}}</dd></div>
    <div><dt>Last receipt</dt><dd class="num">{{.Ended}}</dd></div>
    <div><dt>Status</dt><dd><span class="state {{stateClass .Status}}">{{.Status}}</span></dd></div>
    <div><dt>Actions</dt><dd class="num">{{.Actions}} of {{len .Receipts}} receipts</dd></div>
    <div><dt>On behalf of</dt><dd>{{.Actor}}</dd></div>
    <div><dt>Attribution</dt><dd><span class="state {{stateClass .Attribution}}">{{.Attribution}}</span> (weakest receipt)</dd></div>
    <div><dt>Payloads</dt><dd>{{.PayloadSummary}}</dd></div>
  </dl>
  {{if .ActorJKT}}<p class="small muted">“{{.Actor}}” is a local alias for key <code class="digest">{{.ActorJKT}}</code>. The key is the evidence; the name is not.</p>{{end}}
  {{if gt .Findings 0}}
  <div class="finding finding-run" data-run-finding="true">
    <h4>Payload finding</h4>
    <p>{{.Findings}} payload slot(s) in this run hold bytes that do not hash to the digest committed in their
    signed receipt. The log, the checkpoint and the receipt signatures are unaffected — that is the point:
    you hold the bytes, behalf holds the commitment, and the change is still detectable. Each finding is shown
    on its receipt below.</p>
  </div>
  {{end}}

  {{with .Rollup}}
  {{if .Rows}}
  <div class="panel" data-block="rollup" data-denominator="{{.Denominator}}">
    <p class="label">Attribution across {{.Denominator}} action receipts</p>
    <div class="rollup-bar">
      {{range .Rows}}<div class="seg {{stateClass .State}}" style="width:{{.Width}}" title="{{.State}}"></div>{{end}}
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th>state</th><th class="num">receipts</th><th class="num">share</th></tr></thead>
        <tbody>
        {{range .Rows}}
        <tr data-rollup-state="{{.State}}"><td><span class="state {{stateClass .State}}">{{.State}}</span></td><td class="num">{{.Count}}</td><td class="num">{{.Percent}}</td></tr>
        {{end}}
        </tbody>
      </table>
    </div>
    <p class="small muted">{{.Note}}</p>
  </div>
  {{end}}
  {{end}}

  <div class="section-rule"><h3>Timeline</h3></div>
  <p class="small muted">Log-index order filtered to this run — the authoritative reconstruction order. Run
  completeness is not claimed: it would be marked by a session-end receipt, and the frozen record-kind enum
  has no such kind yet.</p>
  <div class="scroll">
    <table class="timeline" data-section="timeline" data-run="{{.ID}}">
      <thead>
        <tr><th class="num">step</th><th>elapsed</th><th>operation</th><th>target</th><th>outcome</th><th>attribution</th><th>payload</th></tr>
      </thead>
      <tbody>
        {{range .Receipts}}
        <tr data-step="{{.Step}}" data-outcome="{{.Outcome}}" data-attribution="{{.Attribution}}"{{if .Differs}} data-differs="true"{{end}}{{if gt .Findings 0}} data-finding="true"{{end}}>
          <td class="num"><a href="#{{.Anchor}}">{{.Step}}</a></td>
          <td class="num small">{{.Elapsed}}</td>
          <td class="op mono">{{.Operation}}{{if .Differs}} <span class="flag" title="differs from the other run">&#9670;</span>{{end}}</td>
          <td class="mono small">{{.Target}}</td>
          <td><span class="state {{stateClass .Outcome}}">{{.Outcome}}</span></td>
          <td><span class="state {{stateClass .Attribution}}">{{.Attribution}}</span></td>
          <td class="small">{{range .Slots}}<span class="state {{stateClass .State}}">{{.Label}}: {{.State}}</span> {{end}}</td>
        </tr>
        {{end}}
      </tbody>
    </table>
  </div>

  <div class="section-rule"><h3>Receipts</h3></div>
  <p class="small muted">One card per receipt: what happened, the delegation chain that authorised it with each
  hop's verification state, and the payload slots joined against the local store.</p>
  <div data-section="receipts" data-run="{{.ID}}">
    {{range .Receipts}}{{template "receipt" .}}{{end}}
  </div>
</section>
`

const receiptHTML = `
<article class="receipt" id="{{.Anchor}}" data-receipt="{{.Step}}" data-run="{{.RunID}}" data-operation="{{.Operation}}" data-outcome="{{.Outcome}}" data-attribution="{{.Attribution}}" data-hops="{{.TotalHops}}" data-verified-hops="{{.VerifiedHops}}" data-findings="{{.Findings}}">
  <div class="receipt-head">
    <span class="step">step {{.Step}}</span>
    <span class="op mono">{{.Operation}}</span>
    {{if .Target}}<span class="small muted mono">{{.Target}}</span>{{end}}
    {{if .Amount}}<span class="small amount mono">amount {{.Amount}}{{if .Currency}} {{.Currency}}{{end}}</span>{{end}}
    <span class="spacer"></span>
    {{if .Elapsed}}<span class="small muted num">{{.Elapsed}}</span>{{end}}
    <span class="state {{stateClass .Outcome}}">{{.Outcome}}</span>
    <span class="state {{stateClass .Attribution}}">{{.Attribution}}</span>
  </div>
  <div class="receipt-body">

    <section data-block="operation">
      <dl class="kv">
        <div><dt>Kind</dt><dd class="mono small">{{.Kind}}</dd></div>
        <div><dt>Captured</dt><dd class="num small">{{.CapturedAt}}</dd></div>
        <div><dt>Receipt id</dt><dd class="mono small">{{.ReceiptID}}</dd></div>
        <div><dt>Log index</dt><dd class="num small">{{.LogIndex}}</dd></div>
        <div><dt>Attribution class</dt><dd class="small">{{.Class}}</dd></div>
        <div><dt>Acting key</dt><dd class="small">{{.Actor}}</dd></div>
      </dl>
      <p class="small muted">Leaf hash <code class="digest">{{.LeafHash}}</code> — the log's Merkle leaf over the
      stored envelope bytes. This card was rendered from those bytes after re-hashing them and checking them
      against this value.</p>
    </section>

    {{with .Excess}}
    <section data-block="scope-excess">
      <div class="heuristic" data-note="scope">
        <span class="note-kind">Scope excess — recorded, not enforced</span>
        <p>The chain delegated <code>{{.Operation}} &le; {{.Limit}}{{if .Currency}} {{.Currency}}{{end}}</code>
        and this operation issued <b>{{.Amount}}</b>. behalf records scope excess and displays it; it does not
        block. The comparison is recomputed on every read from the raw stored grants
        (<code>{{.ComparatorVersion}}</code>) and is never written back into the record.</p>
      </div>
    </section>
    {{end}}

    <section data-block="chain">
      <h4>Delegation chain — {{.VerifiedHops}} of {{.TotalHops}} hops verified</h4>
      {{if .Hops}}
      <ol class="chain">
        {{range .Hops}}
        <li class="hop hop-{{.Status}}" data-hop="{{.Depth}}" data-hop-status="{{.Status}}">
          <div class="hop-head">
            <span class="who">{{.Label}}</span>
            <span class="state {{stateClass .Status}}">{{.StatusWord}}</span>
            {{if .Evidence}}<span class="small muted">{{.Evidence}}</span>{{end}}
            <span class="small muted">depth {{.Depth}}{{if .MaxDepth}} of max {{.MaxDepth}}{{end}}</span>
          </div>
          <div class="hop-meta">
            {{if .JKT}}key <code class="digest">{{.JKT}}</code>{{end}}
            {{if .JTI}} &middot; jti <code>{{.JTI}}</code>{{end}}
            {{if .Exp}} &middot; expires {{.Exp}}{{end}}
            {{if .Carriage}} &middot; carried {{.Carriage}}{{end}}
          </div>
          {{if .Intent}}<div class="hop-detail">Delegated: “{{.Intent}}”</div>{{end}}
          {{if .Scope}}<div class="hop-detail">Scope: <code>{{.Scope}}</code></div>{{end}}
          {{if .Attenuation}}
          <div class="hop-detail" data-attenuation="{{.Attenuation}}">Attenuation against the parent hop:
            <b>{{.Attenuation}}</b>{{if .AttenuationReason}} — {{.AttenuationReason}}{{end}}.
            Computed on this read from the raw grants, never stored.</div>
          {{end}}
          {{with .Credential}}
          {{if .Issuer}}<div class="hop-meta">credential {{.Kind}} from {{.Issuer}}{{if .ID}}, id <code>{{.ID}}</code>{{end}}{{if .AMR}} &middot; amr {{join ", " .AMR}}{{end}}</div>{{end}}
          {{end}}
          {{with .RootBinding}}
          <div class="hop-meta" data-root-binding="true">root binding: nonce <code class="digest">{{.Nonce}}</code>
            {{if .DeviceJKT}}&middot; device key <code class="digest">{{.DeviceJKT}}</code>{{end}}
            {{if .IDTokenRef}}&middot; ID token blob <code class="digest">{{.IDTokenRef}}</code> (customer-held){{end}}</div>
          {{end}}
          <div class="checks-title">Checked</div>
          <ul class="checks checks-yes" data-checks="yes">{{range .Checked}}<li>{{.}}</li>{{end}}</ul>
          <div class="checks-title">Not checked</div>
          <ul class="checks checks-no" data-checks="no">{{range .NotChecked}}<li>{{.}}</li>{{end}}</ul>
        </li>
        {{end}}
      </ol>
      {{else}}
      <p class="small">This receipt carries no delegation chain, so its attribution is
      <span class="state state-neutral">unattributed</span>: nothing in the record says who this was done on
      behalf of, and nothing later can fill that in — receipts are immutable.</p>
      {{end}}
    </section>

    <section data-block="payload">
      <h4>Payload slots</h4>
      {{if .Slots}}
        {{$run := .RunID}}{{$step := .Step}}
        {{range .Slots}}{{template "slot" dict "Slot" . "Run" $run "Step" $step}}{{end}}
      {{else}}
      <p class="small muted">This receipt carries no payload slots. Not every record kind has one — an approval
      or a policy change carries none — and an empty list here is the schema's legal answer, not a gap.</p>
      {{end}}
    </section>

  </div>
</article>
`

const slotHTML = `
{{$s := .Slot}}{{$id := payloadID .Run .Step $s.Label}}
<div class="slot" data-slot="{{$s.Label}}" data-slot-state="{{$s.State}}" data-committed-state="{{$s.Committed}}" data-custody="{{$s.Custody}}" data-size="{{$s.Size}}"{{if $s.Tampered}} data-tampered="true"{{end}}{{if $s.Collapsed}} data-collapsed="true"{{end}}>
  <div class="slot-head">
    <span class="role">{{$s.Label}}</span>
    <span class="state {{stateClass $s.State}}">{{$s.State}}</span>
    {{if ne $s.State $s.Committed}}<span class="small muted">committed as {{$s.Committed}}</span>{{end}}
  </div>
  <div class="slot-meta">
    <span>{{$s.Custody}}</span>
    {{if $s.ContentType}}<span>{{$s.ContentType}}</span>{{end}}
    {{if $s.Size}}<span class="num">{{$s.SizeText}} ({{$s.Size}} bytes committed)</span>{{end}}
    {{if $s.Digest}}<span>digest <code class="digest">{{$s.Digest}}</code></span>{{end}}
    {{if $s.ManifestFields}}<span>{{$s.ManifestFields}} field digests</span>{{else}}<span>whole-blob digest only</span>{{end}}
    {{if $s.CauseRef}}<span>cause {{$s.CauseRef}}</span>{{end}}
    {{if $s.Subjects}}<span>subjects (asserted): {{join ", " $s.Subjects}}</span>{{end}}
  </div>

  {{if $s.Tampered}}
  <div class="finding" data-finding="payload">
    <h4>This payload no longer matches its commitment</h4>
    <p>The bytes in the store do not hash to the digest committed inside a signed, log-committed receipt.
    The log, the checkpoint and the receipt signatures still verify perfectly: what changed is content you
    hold. You hold the bytes, behalf holds the commitment, and the change is still provable.</p>
    <dl>
      <dt>Committed</dt><dd>sha256:{{$s.Mismatch.Committed}}</dd>
      <dt>Actual</dt><dd>sha256:{{$s.Mismatch.Actual}}</dd>
      {{if $s.Mismatch.StoredSize}}<dt>Stored size</dt><dd>{{$s.Mismatch.StoredSize}} bytes (receipt committed {{$s.Size}})</dd>{{end}}
      {{if $s.Mismatch.ChangedFields}}<dt>Changed fields</dt><dd>{{join ", " $s.Mismatch.ChangedFields}}</dd>{{end}}
    </dl>
    {{if not $s.Mismatch.ChangedFields}}
    <p class="small muted">No field-digest manifest was captured for this slot, so the change cannot be
    localised to a field. That is a gap in the evidence, not a clean bill.</p>
    {{end}}
  </div>
  {{else if $s.Placeholder}}
  <div class="placeholder" data-placeholder="{{$s.State}}">{{$s.Placeholder}}</div>
  {{if $s.Err}}<p class="small muted slot-note">The store refused this read: {{$s.Err}}. That is a broken mount or a permission problem, not a tamper finding — the two are deliberately not the same.</p>{{end}}
  {{end}}

  {{if $s.Content}}
  <details{{if not $s.Collapsed}} open{{end}} data-payload="{{$s.State}}">
    <summary>
      <span class="grow">{{$s.Label}} payload &middot; {{$s.SizeText}} &middot; {{$s.Language}}</span>
      <button type="button" class="copy no-print" data-copy="{{$id}}">copy</button>
    </summary>
    <pre class="payload" id="{{$id}}">{{$s.Content}}</pre>
    {{if $s.Truncated}}
    <div class="payload-foot truncation" data-truncated="true">Only the first part of this payload is inlined;
      {{$s.Omitted}} further bytes were left out to keep this document openable. The digest above commits to
      all {{$s.Size}} bytes — read the whole blob out of your own store to check it.</div>
    {{else}}
    <div class="payload-foot">These are the bytes the digest above commits to, re-hashed and matched on this read.</div>
    {{end}}
  </details>
  {{end}}
</div>
`

const verifyHTML = `
<section id="verify" data-section="verify" data-checkpoint="{{if .Log.Available}}available{{else}}unavailable{{end}}">
  <h2>Verify it yourself</h2>
  <p class="lede">This page is a rendering. The evidence is the bytes in the log, and the point of those bytes
  is that nobody has to take this document's word for anything in it — including behalf's.</p>
  <div class="verify">
    {{if .Log.Available}}
    <dl class="kv">
      <div><dt>Log origin</dt><dd class="mono small">{{.Log.Origin}}</dd></div>
      <div><dt>Tree size</dt><dd class="num">{{.Log.TreeSize}} leaves</dd></div>
      <div><dt>Directory</dt><dd class="mono small">{{.Log.Dir}}</dd></div>
    </dl>
    <p class="label spaced">Chain head — Merkle root of the signed checkpoint</p>
    <p><code class="digest">{{.Log.RootHex}}</code></p>
    <details data-block="checkpoint">
      <summary>
        <span class="grow">The signed checkpoint, verbatim</span>
        <button type="button" class="copy no-print" data-copy="checkpoint-note">copy</button>
      </summary>
      <pre class="checkpoint" id="checkpoint-note">{{.Log.Checkpoint}}</pre>
      <div class="payload-foot">A signed note: the origin line, the tree size, the root hash, and the
      signature lines. Checkpoints are signed every second; unknown extra lines are legal and are skipped by
      verifiers, because production logs grease them.</div>
    </details>
    {{else}}
    <p>The signed checkpoint could not be read from <code>{{.Log.Dir}}</code>, so this page cannot state the
    chain head it was rendered against. Run the verifier against the directory before relying on anything here.</p>
    {{end}}

    <h3>The commands</h3>
    <p class="small muted">These run offline. They make no network call, no call to behalf and no call to your
    identity provider; everything they need is in the directory and in the files they read.</p>
    {{range .Log.Commands}}
    <div class="cmd" data-verify-command>
      <pre>{{.Line}}</pre>
      <p>{{.What}}</p>
    </div>
    {{end}}
    <p class="small muted">Exit codes are stable and load-bearing: <b>0</b> verified — every receipt intact,
    chain and head verify; <b>1</b> tampering detected, with the class (content, drop, reorder, chain,
    truncation, head) and the receipt index it broke at; <b>2</b> unverifiable — not a readable export.
    A payload whose bytes no longer match its commitment is reported as its own class, <code>payload</code>,
    precisely because the log around it is still intact.</p>
  </div>
</section>
`
