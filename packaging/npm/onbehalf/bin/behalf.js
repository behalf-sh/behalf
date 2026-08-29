#!/usr/bin/env node
'use strict'

// The `behalf` shim: exec the platform binary with the arguments as given.
//
// npm's `behalf` name was checked harmless — a dormant 2015 package with no
// `bin` — so this package ships the binary under its real name and `npx
// onbehalf demo` prints commands a reader can type verbatim.
//
// Nothing is interpreted here. Arguments pass through untouched, stdio is
// inherited so the CLI's own colour and width detection sees the real terminal,
// and the exit code is the binary's. A shim that rewrote either would make the
// documented exit codes (0 verified, 1 tampered, 2 unverifiable) a lie at one
// remove, and CI depends on them (Q92).

const { spawnSync } = require('child_process')
const { binary } = require('./resolve')

try {
  const res = spawnSync(binary('behalf'), process.argv.slice(2), { stdio: 'inherit' })
  if (res.error) throw res.error
  if (res.signal) {
    // Reproduce death-by-signal rather than flattening it to an exit code:
    // a Ctrl-C on the demo should look like a Ctrl-C to the shell.
    process.kill(process.pid, res.signal)
  }
  process.exitCode = res.status === null ? 1 : res.status
} catch (err) {
  process.stderr.write(`behalf: ${err.message}\n`)
  process.exitCode = 1
}
