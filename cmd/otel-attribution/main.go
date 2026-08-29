// Command otel-attribution is a small OpenTelemetry-instrumented program.
//
// It exists for one beat of the `why` demo scenario (docs/demo-runbook.md),
// and it is deliberately not part of behalf: it imports no behalf package,
// reads no behalf state, and knows nothing about receipts. It builds a real
// span tree with the upstream OpenTelemetry Go SDK
// (go.opentelemetry.io/otel/sdk), exports it through a real span exporter,
// and prints the resource attributes those spans carry.
//
// # Why this is in the repo
//
// The `why` scenario makes a claim about attribution, and the claim has to
// be demonstrated rather than asserted. OTEL_RESOURCE_ATTRIBUTES is a
// documented OpenTelemetry SDK configuration mechanism: the value is a
// comma-separated list of key=value pairs, percent-encoded where a key or
// value contains `,` or `=`, and the SDK's environment detector turns it
// into resource attributes that ride on every span the process emits
// (OpenTelemetry SDK configuration spec, "Specifying resource information
// via an environment variable"). Nothing signs those attributes and nothing
// checks them — they are configuration, which is what they are specified to
// be.
//
// So the demonstration is: set the variable, watch the attribute appear on
// every span, and observe that the output is identical whether the value is
// true or invented. That is a real, documented property of a real SDK, shown
// by running it. It is not a claim about any vendor's product and this
// program neither imitates nor names one — the reading is done by
// resource.WithFromEnv() from the upstream SDK, not by a parser written
// here, precisely so that nothing about the behaviour is ours to shade.
//
// The comparison the scenario draws is against behalf's own receipt for the
// same action, printed by `behalf why rec_c71e:31`, where a hop that carries
// no signature is rendered UNVERIFIED and the actor string is named as
// caller-asserted rather than promoted.
//
// # Determinism
//
// Trace and span ids come from a fixed-seed generator so that two runs print
// the same bytes; the demo is re-run repeatedly and a diff of two runs should
// be empty. Nothing else about the SDK path is stubbed.
//
// # Usage
//
//	otel-attribution
//	OTEL_RESOURCE_ATTRIBUTES=user.email=ceo@corp.com otel-attribution
package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

// envResourceAttributes is the variable the OpenTelemetry SDK configuration
// spec defines for supplying resource attributes out of the environment. It
// is named here only so the program can echo what it was given; the reading
// is done by resource.WithFromEnv().
const envResourceAttributes = "OTEL_RESOURCE_ATTRIBUTES"

// serviceName is this program's in-code service name. It is set before the
// environment detector runs, so anything the environment supplies wins —
// which is the intended precedence and, for this demonstration, the point.
const serviceName = "support-desk-agent"

func main() {
	if err := run(context.Background(), os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "otel-attribution:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, out io.Writer) error {
	// The environment detector last: later detectors win in resource.New, so
	// OTEL_RESOURCE_ATTRIBUTES overrides the in-code service name above.
	res, err := resource.New(ctx,
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attribute.String("service.name", serviceName)),
		resource.WithFromEnv(),
	)
	if err != nil {
		// The spec says a malformed value SHOULD be reported. resource.New
		// returns a usable partial resource alongside the error, so report
		// and carry on rather than exiting: the demo beat is the attributes
		// that did survive.
		fmt.Fprintf(out, "note: the SDK reported a problem reading %s: %v\n\n", envResourceAttributes, err)
	}
	if res == nil {
		return fmt.Errorf("the SDK returned no resource")
	}

	spans, err := emit(ctx, res)
	if err != nil {
		return err
	}
	report(out, res, spans)
	return nil
}

// emit builds the span tree for one support-desk refund and returns the
// spans as the exporter received them. The tree mirrors the shape of the
// demo run so the two screens sit side by side: a ticket resolution, an
// order read, and the refund.
func emit(ctx context.Context, res *resource.Resource) ([]tracetest.SpanStub, error) {
	exp := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithResource(res),
		sdktrace.WithIDGenerator(&fixedIDs{}),
		sdktrace.WithSyncer(exp),
	)
	tr := tp.Tracer("otel-attribution")

	ctx, ticket := tr.Start(ctx, "support.resolve_ticket",
		trace.WithAttributes(attribute.String("ticket.id", "tk_4437")))
	ctx, order := tr.Start(ctx, "orders.read",
		trace.WithAttributes(attribute.String("order.id", "ord_5518")))
	_, refund := tr.Start(ctx, "refund.issue",
		trace.WithAttributes(
			attribute.String("order.id", "ord_5518"),
			attribute.String("refund.amount", "1200.00"),
			attribute.String("refund.currency", "USD"),
		))
	refund.End()
	order.End()
	ticket.End()

	// WithSyncer exports on End, so the spans are already in the exporter.
	// They must be read before Shutdown: InMemoryExporter.Shutdown resets its
	// buffer, and reading after it would silently yield nothing.
	spans := exp.GetSpans()
	if err := tp.Shutdown(ctx); err != nil {
		return nil, fmt.Errorf("shut the tracer provider down: %w", err)
	}
	if len(spans) == 0 {
		return nil, fmt.Errorf("the SDK exported no spans")
	}
	return spans, nil
}

// report prints the resource attributes, then the span tree, then what the
// two together do and do not establish.
func report(out io.Writer, res *resource.Resource, spans []tracetest.SpanStub) {
	env := os.Getenv(envResourceAttributes)

	fmt.Fprintf(out, "otel-attribution — an OpenTelemetry-instrumented program. Not behalf.\n")
	fmt.Fprintf(out, "Spans below were built and exported by the upstream OpenTelemetry Go SDK\n")
	fmt.Fprintf(out, "(go.opentelemetry.io/otel/sdk); the resource was assembled by that SDK's own\n")
	fmt.Fprintf(out, "resource.WithFromEnv() detector.\n\n")

	fmt.Fprintf(out, "$%s = %s\n\n", envResourceAttributes, quoteEnv(env))

	fmt.Fprintf(out, "resource attributes — every span in this process carries all of these:\n\n")
	fromEnv := envKeys(env)
	attrs := res.Attributes()
	sort.Slice(attrs, func(i, j int) bool { return attrs[i].Key < attrs[j].Key })
	width := 0
	for _, a := range attrs {
		if n := len(a.Key); n > width {
			width = n
		}
	}
	for _, a := range attrs {
		line := fmt.Sprintf("  %-*s  %s", width, a.Key, a.Value.Emit())
		if fromEnv[string(a.Key)] {
			line += strings.Repeat(" ", maxInt(1, 44-len(line))) + "← from $" + envResourceAttributes
		}
		fmt.Fprintln(out, line)
	}

	fmt.Fprintf(out, "\nspan tree:\n\n")
	renderTree(out, spans)

	fmt.Fprintf(out, "\nWhat that establishes: the process emitted three spans, and every one of them\n")
	fmt.Fprintf(out, "carries the attributes listed above. Any backend that groups, filters or\n")
	fmt.Fprintf(out, "displays by one of those keys will do so using these values.\n\n")

	if len(fromEnv) > 0 {
		fmt.Fprintf(out, "What it does not establish: that any of the values marked ← is true. They came\n")
		fmt.Fprintf(out, "from a process environment variable. Nothing signed them, nothing checked them,\n")
		fmt.Fprintf(out, "and the key is arbitrary — the mechanism does not validate it. This is\n")
		fmt.Fprintf(out, "documented, intended OpenTelemetry behaviour: resource attributes are\n")
		fmt.Fprintf(out, "configuration, not authentication.\n\n")
		fmt.Fprintf(out, "Run this again with a different value and the output changes to match it.\n")
	} else {
		fmt.Fprintf(out, "What it does not establish: who ran it. Nothing above was signed or checked.\n")
		fmt.Fprintf(out, "Set the variable and the process attributes its spans to whatever it says:\n\n")
		fmt.Fprintf(out, "  %s=user.email=ceo@corp.com otel-attribution\n", envResourceAttributes)
	}

	fmt.Fprintf(out, "\nFor the same action, recorded as a behalf receipt:  behalf why rec_c71e:31\n")
	fmt.Fprintf(out, "(trace and span ids here come from a fixed seed, so two runs print the same bytes.)\n")
}

// renderTree prints the spans as a tree, parents before children.
func renderTree(out io.Writer, spans []tracetest.SpanStub) {
	children := map[trace.SpanID][]tracetest.SpanStub{}
	var roots []tracetest.SpanStub
	for _, s := range spans {
		if s.Parent.IsValid() {
			children[s.Parent.SpanID()] = append(children[s.Parent.SpanID()], s)
			continue
		}
		roots = append(roots, s)
	}
	if len(roots) > 0 {
		fmt.Fprintf(out, "  trace %s\n", roots[0].SpanContext.TraceID())
	}
	var walk func(s tracetest.SpanStub, depth int)
	walk = func(s tracetest.SpanStub, depth int) {
		// The name column is padded to a fixed width measured from the left
		// margin, not from the indent, so the attributes line up down the
		// tree instead of stepping right with it.
		const nameColumn = 30
		indent := strings.Repeat("  ", depth+1)
		label := indent + s.Name
		fmt.Fprintf(out, "%s%s%s\n", label, strings.Repeat(" ", maxInt(1, nameColumn-len(label))), spanAttrs(s))
		kids := children[s.SpanContext.SpanID()]
		sort.Slice(kids, func(i, j int) bool { return kids[i].StartTime.Before(kids[j].StartTime) })
		for _, k := range kids {
			walk(k, depth+1)
		}
	}
	for _, r := range roots {
		walk(r, 0)
	}
}

func spanAttrs(s tracetest.SpanStub) string {
	parts := make([]string, 0, len(s.Attributes))
	for _, a := range s.Attributes {
		parts = append(parts, fmt.Sprintf("%s=%s", a.Key, a.Value.Emit()))
	}
	return strings.Join(parts, " ")
}

// envKeys reports which attribute keys came out of the environment
// variable, so the rendering can mark them. It parses only for that
// labelling; the attribute values themselves are the SDK's.
func envKeys(env string) map[string]bool {
	keys := map[string]bool{}
	for _, pair := range strings.Split(env, ",") {
		k, _, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if k = strings.TrimSpace(k); k != "" {
			keys[k] = true
		}
	}
	return keys
}

func quoteEnv(v string) string {
	if v == "" {
		return "(unset)"
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// fixedIDs is a deterministic trace/span id generator. The SDK's default
// generator is random, which would make two runs of this program differ in
// every id; the demo is run repeatedly and compared, so the ids are a
// counter instead. Nothing else in the SDK path is substituted.
type fixedIDs struct {
	mu sync.Mutex
	n  uint64
}

// The high half of every trace id and the high bits of every span id, so the
// ids are recognisably from this program rather than looking like entropy.
const (
	traceIDPrefix uint64 = 0x0be7a1f0de305180
	spanIDPrefix  uint64 = 0x5040000000000000
)

func (f *fixedIDs) next() uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
	return f.n
}

func (f *fixedIDs) NewIDs(context.Context) (trace.TraceID, trace.SpanID) {
	var tid trace.TraceID
	binary.BigEndian.PutUint64(tid[0:8], traceIDPrefix)
	binary.BigEndian.PutUint64(tid[8:16], f.next())
	return tid, f.newSpanID()
}

func (f *fixedIDs) NewSpanID(context.Context, trace.TraceID) trace.SpanID {
	return f.newSpanID()
}

func (f *fixedIDs) newSpanID() trace.SpanID {
	var sid trace.SpanID
	binary.BigEndian.PutUint64(sid[:], spanIDPrefix|f.next())
	return sid
}
