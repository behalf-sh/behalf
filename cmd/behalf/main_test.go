package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
	"github.com/behalf-sh/behalf/internal/oidctest"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/tlog"
)

func TestWhoamiWithoutLoginWarnsAssertedForever(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run(context.Background(), []string{"whoami", "--dir", t.TempDir()}, &out, &errOut)
	if code != 0 {
		t.Fatalf("exit = %d, stderr: %s", code, errOut.String())
	}
	s := out.String()
	if !strings.Contains(s, "Not logged in") || !strings.Contains(s, "asserted") || !strings.Contains(s, "FOREVER") {
		t.Fatalf("whoami without login must warn about permanently-asserted records; got:\n%s", s)
	}
}

// TestWhyAddressErrors: the address surface fails with a usage exit and a
// message that shows the shape, whichever side of the flags it sits on.
func TestWhyAddressErrors(t *testing.T) {
	for _, args := range [][]string{
		{"why"},
		{"why", "run_c71e"},
		{"why", "run_c71e:x", "--dir", t.TempDir()},
		{"why", "run_c71e:1", "run_9f2a:1"},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != 2 {
			t.Fatalf("run(%v) = %d, want 2 (stderr: %s)", args, code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "run_c71e:31") {
			t.Fatalf("run(%v) stderr should show the address shape: %s", args, errOut.String())
		}
	}
}

// TestWhyOnAnEmptyLogDirFails: a directory with no log is an error, not an
// empty tree rendered as if it were evidence.
func TestWhyOnAnEmptyLogDirFails(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"why", "run_c71e:31", "--dir", t.TempDir()}, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout: %s)", code, out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("nothing should be printed to stdout: %s", out.String())
	}
}

// TestDiffArgErrors: `diff` takes exactly two run ids, on either side of
// the flags, and says so rather than guessing.
func TestDiffArgErrors(t *testing.T) {
	for _, args := range [][]string{
		{"diff"},
		{"diff", "run_9f2a"},
		{"diff", "run_9f2a", "run_c71e", "run_extra"},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != 2 {
			t.Fatalf("run(%v) = %d, want 2 (stderr: %s)", args, code, errOut.String())
		}
		if !strings.Contains(errOut.String(), "behalf diff run_9f2a run_c71e") {
			t.Fatalf("run(%v) stderr should show the shape; got: %s", args, errOut.String())
		}
	}
	// The flags may sit either side of the two positionals.
	flags, pos := splitPositional([]string{"--dir", "d", "run_9f2a", "run_c71e", "--all"})
	if strings.Join(flags, " ") != "--dir d --all" || strings.Join(pos, " ") != "run_9f2a run_c71e" {
		t.Fatalf("splitPositional = %v, %v", flags, pos)
	}
}

// TestDiffOnAnEmptyLogDirFails: a directory with no log is an error, not an
// empty comparison rendered as if it were evidence.
func TestDiffOnAnEmptyLogDirFails(t *testing.T) {
	var out, errOut bytes.Buffer
	args := []string{"diff", "run_9f2a", "run_c71e", "--dir", t.TempDir()}
	if code := run(context.Background(), args, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout: %s)", code, out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("nothing should be printed to stdout: %s", out.String())
	}
}

// TestUsageNamesDiff: the flagship command has to be discoverable.
func TestUsageNamesDiff(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit = %d", code)
	}
	for _, want := range []string{
		"behalf diff   <runA> <runB>", "--all", "first step that diverged",
		"behalf export --run ID [--run ID2] --html FILE", "The file loads nothing",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("usage does not mention %q:\n%s", want, out.String())
		}
	}
}

// TestExportArgErrors: `export` needs one or two --run flags and a --html
// destination, and says which is missing rather than guessing.
func TestExportArgErrors(t *testing.T) {
	dir := t.TempDir()
	for _, args := range [][]string{
		{"export"},
		{"export", "--run", "run_9f2a"},
		{"export", "--html", "out.html"},
		{"export", "--run", "a", "--run", "b", "--run", "c", "--html", "out.html"},
		{"export", "run_9f2a", "--html", "out.html", "--dir", dir},
	} {
		var out, errOut bytes.Buffer
		if code := run(context.Background(), args, &out, &errOut); code != 2 {
			t.Fatalf("run(%v) = %d, want 2 (stderr: %s)", args, code, errOut.String())
		}
	}
	// A directory with no log is an error, not an empty page rendered as if
	// it were evidence.
	var out, errOut bytes.Buffer
	args := []string{"export", "--run", "run_9f2a", "--html", filepath.Join(dir, "x.html"), "--dir", dir}
	if code := run(context.Background(), args, &out, &errOut); code != 1 {
		t.Fatalf("exit = %d, want 1 (stdout: %s)", code, out.String())
	}
	if _, err := os.Stat(filepath.Join(dir, "x.html")); !os.IsNotExist(err) {
		t.Error("a failed export must not leave a file behind")
	}
}

// TestExportEndToEnd drives the real CLI against the real demo log: the
// fixture pair ingested through the production append path, then exported
// as one self-contained HTML file.
func TestExportEndToEnd(t *testing.T) {
	logDir := demoLogDir(t)
	outDir := t.TempDir()
	out := filepath.Join(outDir, "incident.html")

	var stdout, stderr bytes.Buffer
	code := run(context.Background(),
		[]string{"export", "--run", "run_9f2a", "--run", "run_c71e", "--html", out,
			"--dir", logDir, "--state", t.TempDir()},
		&stdout, &stderr)
	if code != 0 {
		t.Fatalf("exit = %d\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "run_9f2a vs run_c71e") ||
		!strings.Contains(stdout.String(), "no external requests") {
		t.Errorf("export summary: %s", stdout.String())
	}

	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	doc := string(b)
	if !strings.HasPrefix(doc, "<!doctype html>") {
		t.Fatal("the export is not an HTML document")
	}
	// The evidence a reader opens this file for.
	for _, want := range []string{
		`data-mode="pair"`,
		`data-run="run_9f2a"`, `data-run="run_c71e"`,
		"47 actions in both runs. 22 differ. 1 caused the rest.",
		`data-note="suppression"`,
		"First divergence", "Consequence",
		"behalf why run_c71e:31",
		"What this document proves",
		"That the agent did what the receipt says",
		"behalf-verify log ",
		"Chain head",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the exported page is missing %q", want)
		}
	}
	// Self-contained: nothing is loaded.
	for _, banned := range []string{"<link", "<script src", "<img", "@import", "url(", "fetch("} {
		if strings.Contains(doc, banned) {
			t.Errorf("the exported page contains %q", banned)
		}
	}
	// A single run exports too, and does not carry a diff.
	single := filepath.Join(outDir, "one.html")
	stdout.Reset()
	stderr.Reset()
	if code := run(context.Background(),
		[]string{"export", "--dir", logDir, "--run", "run_9f2a", "--html", single}, &stdout, &stderr); code != 0 {
		t.Fatalf("single-run export exit = %d: %s", code, stderr.String())
	}
	b, err = os.ReadFile(single)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `data-section="diff"`) {
		t.Error("a single-run export must not carry a diff section")
	}
	if !strings.Contains(string(b), `data-mode="run"`) {
		t.Error("a single-run export should render in run mode")
	}
}

// demoLogDir ingests the fixture pair through the production log path — the
// same log `behalf diff` and `behalf why` read.
func demoLogDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	ctx := context.Background()
	key, err := tlog.GenerateCheckpointKey("behalf.sh/log/cli-test")
	if err != nil {
		t.Fatal(err)
	}
	if err := tlog.SaveCheckpointKey(dir, key); err != nil {
		t.Fatal(err)
	}
	l, err := tlog.Open(ctx, dir, key, tlog.Options{})
	if err != nil {
		t.Fatal(err)
	}
	emitter := testkeys.Emitter()
	jwk, err := json.Marshal(emitter.JWK)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.RegisterKey(emitter.JKT, string(jwk)); err != nil {
		t.Fatal(err)
	}
	var pendings []*tlog.Pending
	for _, spec := range []fixture.Spec{fixture.Run9F2A(), fixture.RunC71E()} {
		res, err := fixture.Generate(spec)
		if err != nil {
			t.Fatal(err)
		}
		for _, body := range res.Payloads {
			sig := dsse.Sign(emitter.Private, exportv1.PayloadTypeReceipt, body)
			p, err := l.BeginAppend(ctx, tlog.BuildEnvelope(exportv1.PayloadTypeReceipt, body, emitter.JKT, sig))
			if err != nil {
				t.Fatal(err)
			}
			pendings = append(pendings, p)
		}
	}
	for _, p := range pendings {
		if _, err := p.Wait(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(ctx); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestSplitPositional: a positional argument may sit on either side of the
// flags.
func TestSplitPositional(t *testing.T) {
	cases := []struct {
		args      []string
		wantFlags []string
		wantPos   []string
	}{
		{[]string{"run:1", "--dir", "d"}, []string{"--dir", "d"}, []string{"run:1"}},
		{[]string{"--dir", "d", "run:1"}, []string{"--dir", "d"}, []string{"run:1"}},
		{[]string{"--dir=d", "run:1"}, []string{"--dir=d"}, []string{"run:1"}},
		{[]string{"--", "-weird-run:1"}, nil, []string{"-weird-run:1"}},
	}
	for _, tc := range cases {
		flags, pos := splitPositional(tc.args)
		if strings.Join(flags, " ") != strings.Join(tc.wantFlags, " ") ||
			strings.Join(pos, " ") != strings.Join(tc.wantPos, " ") {
			t.Fatalf("splitPositional(%v) = %v, %v; want %v, %v", tc.args, flags, pos, tc.wantFlags, tc.wantPos)
		}
	}
}

func TestUnknownCommand(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"frobnicate"}, &out, &errOut); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
}

func TestLoginMissingFlags(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"login", "--dir", t.TempDir()}, &out, &errOut); code != 2 {
		t.Fatalf("exit = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), "--issuer") {
		t.Fatalf("stderr should name the missing flags: %s", errOut.String())
	}
}

// TestLoginWhoamiEndToEnd drives the real CLI: `behalf login --no-browser`
// against the fake IdP (following the printed auth URL programmatically),
// then `behalf whoami` offline.
func TestLoginWhoamiEndToEnd(t *testing.T) {
	idp := oidctest.New()
	dir := t.TempDir()

	pr, pw := io.Pipe()
	var mu strings.Builder
	done := make(chan struct{})
	urlRe := regexp.MustCompile(`https?://\S+/authorize\S*`)
	go func() {
		defer close(done)
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		followed := false
		for sc.Scan() {
			line := sc.Text()
			mu.WriteString(line + "\n")
			if u := urlRe.FindString(line); u != "" && !followed {
				followed = true
				go func() {
					resp, err := http.Get(u)
					if err != nil {
						t.Logf("follow auth url: %v", err)
						return
					}
					io.Copy(io.Discard, resp.Body) //nolint:errcheck
					resp.Body.Close()
				}()
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var errOut bytes.Buffer
	code := run(ctx, []string{"login", "--issuer", idp.URL, "--client-id", "behalf-cli-test", "--no-browser", "--dir", dir}, pw, &errOut)
	pw.Close()
	<-done
	if code != 0 {
		t.Fatalf("login exit = %d\nstdout:\n%s\nstderr:\n%s", code, mu.String(), errOut.String())
	}
	if !strings.Contains(mu.String(), "Logged in.") {
		t.Fatalf("login output:\n%s", mu.String())
	}

	// whoami runs offline: the IdP is gone.
	idp.Close()
	var out, errOut2 bytes.Buffer
	if code := run(context.Background(), []string{"whoami", "--dir", dir}, &out, &errOut2); code != 0 {
		t.Fatalf("whoami exit = %d, stderr: %s", code, errOut2.String())
	}
	s := out.String()
	if !strings.Contains(s, "verification: verified") {
		t.Fatalf("whoami after login should print a verified root; got:\n%s", s)
	}
	if !strings.Contains(s, "issuer:") || !strings.Contains(s, "sub_digest:") || !strings.Contains(s, "device jkt:") {
		t.Fatalf("whoami output missing identity fields:\n%s", s)
	}
}
