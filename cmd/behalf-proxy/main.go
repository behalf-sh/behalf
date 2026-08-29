// Command behalf-proxy is the behalf MCP stdio interposer — the canonical
// v1 capture surface (D4, Q44). It wraps a real MCP server:
//
//	behalf-proxy --state DIR [--policy FILE] [--chain FILE] [--spool DIR] -- SERVER [ARGS...]
//
// Newline-delimited JSON-RPC crosses in both directions verbatim, except
// that client->server `tools/call` requests gain the two legal
// `params._meta` keys (`sh.behalf/chain`, `baggage`). Every tools/call is
// spooled as an intent before it is forwarded and closed as a signed
// receipt when the response arrives (Q4, Q48).
//
// The proxy does not touch the log: `behalf-log drain --spool DIR --dir
// LOGDIR` moves the spool into it (Q57, Q46).
//
// In an MCP client config, replace the server command with this one:
//
//	{"command": "behalf-proxy",
//	 "args": ["--state", "~/.behalf", "--", "my-mcp-server", "--flag"]}
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"

	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/proxy"
)

func main() {
	fs := flag.NewFlagSet("behalf-proxy", flag.ExitOnError)
	state := fs.String("state", "", "behalf state directory (default $BEHALF_HOME, else ~/.behalf)")
	policy := fs.String("policy", "", "tool-policy JSON assigning risk_class (default: built-in policy)")
	chain := fs.String("chain", "", "delegation chain material to carry in params._meta (default: none, receipts are asserted)")
	spoolDir := fs.String("spool", "", "capture spool directory (default <state>/proxy-spool)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: behalf-proxy --state DIR [--policy FILE] [--chain FILE] [--spool DIR] -- SERVER [ARGS...]")
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		os.Exit(2)
	}
	command := fs.Args()
	if len(command) == 0 {
		fs.Usage()
		os.Exit(2)
	}

	dir, err := identity.ResolveDir(*state)
	if err != nil {
		fail(err)
	}
	cfg := proxy.Config{
		StateDir:   dir,
		SpoolDir:   *spoolDir,
		PolicyPath: *policy,
		ChainPath:  *chain,
		Command:    command,
		Env:        os.Environ(),
	}
	if err := proxy.Run(cfg, os.Stdin, os.Stdout, os.Stderr); err != nil {
		// The server's own exit status is the proxy's: an MCP client that
		// watches for a crashing server must still see one.
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.ExitCode())
		}
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "behalf-proxy:", err)
	os.Exit(1)
}
