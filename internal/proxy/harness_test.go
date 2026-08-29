package proxy

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/behalf-sh/behalf/internal/envelope"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
)

// sessionOpts scripts one hermetic proxy run against the fake MCP server.
type sessionOpts struct {
	stateDir string            // reused across runs to test restart behaviour
	lines    []string          // the client's stdio, in order
	server   map[string]string // extra env for the fake server
	env      map[string]string // what the proxy's run-id precedence sees
	policy   string            // tool-policy file contents, if any
	chain    string            // chain material file contents, if any
	now      func() time.Time
}

type sessionResult struct {
	stateDir   string
	spoolDir   string
	stdout     []byte
	stderr     []byte
	inWitness  []byte // every line the server received, verbatim
	outWitness []byte // every line the server sent, verbatim
	err        error
}

func runSession(t *testing.T, opts sessionOpts) sessionResult {
	t.Helper()
	stateDir := opts.stateDir
	if stateDir == "" {
		stateDir = t.TempDir()
	}
	work := t.TempDir()
	res := sessionResult{
		stateDir: stateDir,
		spoolDir: filepath.Join(stateDir, DefaultSpoolDirName),
	}
	inW := filepath.Join(work, "in.witness")
	outW := filepath.Join(work, "out.witness")

	childEnv := []string{
		envFakeServer + "=1",
		envInWitness + "=" + inW,
		envOutWitness + "=" + outW,
	}
	for k, v := range opts.server {
		childEnv = append(childEnv, k+"="+v)
	}

	cfg := Config{
		StateDir: stateDir,
		Command:  []string{os.Args[0]},
		Env:      childEnv,
		Getenv:   func(k string) string { return opts.env[k] },
		Now:      opts.now,
	}
	if opts.policy != "" {
		cfg.PolicyPath = writeTemp(t, work, "policy.json", opts.policy)
	}
	if opts.chain != "" {
		cfg.ChainPath = writeTemp(t, work, "chain.json", opts.chain)
	}

	var stdout, stderr bytes.Buffer
	res.err = Run(cfg, strings.NewReader(strings.Join(opts.lines, "")), &stdout, &stderr)
	res.stdout = stdout.Bytes()
	res.stderr = stderr.Bytes()
	res.inWitness, _ = os.ReadFile(inW)
	res.outWitness, _ = os.ReadFile(outW)
	return res
}

func writeTemp(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// spooledReceipts returns the receipts sitting in the spool, decoded from
// their stored envelopes, alongside the envelopes themselves.
func spooledReceipts(t *testing.T, spoolDir string) ([]receipt.Receipt, []*envelope.Envelope) {
	t.Helper()
	completions, err := spool.ReadAll(spoolDir)
	if err != nil {
		t.Fatal(err)
	}
	var rs []receipt.Receipt
	var envs []*envelope.Envelope
	for _, c := range completions {
		env, err := envelope.Parse(c.Envelope)
		if err != nil {
			t.Fatalf("parse spooled envelope: %v", err)
		}
		var r receipt.Receipt
		if err := json.Unmarshal(env.Payload, &r); err != nil {
			t.Fatalf("decode receipt payload: %v", err)
		}
		rs = append(rs, r)
		envs = append(envs, env)
	}
	return rs, envs
}

// schemaValidate checks a receipt payload against the frozen v1 schema.
func schemaValidate(t *testing.T, payload []byte) {
	t.Helper()
	sch := compiledSchema(t)
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(payload))
	if err != nil {
		t.Fatalf("unmarshal payload: %v", err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("receipt violates the frozen v1 schema: %v\npayload: %s", err, payload)
	}
}

var schemaCache *jsonschema.Schema

func compiledSchema(t *testing.T) *jsonschema.Schema {
	t.Helper()
	if schemaCache != nil {
		return schemaCache
	}
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("../../docs/receipt-schema-v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	schemaCache = sch
	return sch
}

// lines splits a witness file into its raw newline-terminated lines.
func splitLines(b []byte) [][]byte {
	var out [][]byte
	for len(b) > 0 {
		i := bytes.IndexByte(b, '\n')
		if i < 0 {
			out = append(out, b)
			break
		}
		out = append(out, b[:i+1])
		b = b[i+1:]
	}
	return out
}

// request/response line builders for the scripted client sessions.
func initializeLine(id string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"initialize","params":{"protocolVersion":"2026-07-28","capabilities":{},"clientInfo":{"name":"test-client","version":"1.0"}}}` + "\n"
}

func initializedLine() string {
	return `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"
}

func toolsListLine(id string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/list","params":{}}` + "\n"
}

func toolsCallLine(id, name, args string) string {
	return `{"jsonrpc":"2.0","id":` + id + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}` + "\n"
}
