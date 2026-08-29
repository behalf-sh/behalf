#!/usr/bin/env node
'use strict'

// `npx onbehalf demo` — the self-serve entry point.
//
// What it does is unpack: the package carries the two recorded runs as export
// files and this rebuilds a local log from them. No network, no API key, no
// account, no tokens spent (Q92). The recordings were made once, by
// `cmd/behalf-record` driving the real MCP proxy against an in-repo desk
// server, and shipping the result is what lets a stranger see the product
// without running an agent first.
//
// # Two seeding paths, deliberately
//
// This is NOT `behalf demo reset`. That one re-records the pair by driving the
// proxy, needs the recorder binary and a loopback socket, and exists for the
// operator running a live call (docs/demo-runbook.md). This one unpacks a
// shipped recording and is the only one that is a product surface. Two code
// paths on purpose (D9.8).
//
// # Why seeding is a command and not automatic
//
// Sentry shipped auto-sample data in 2013 and removed it in 2016. The pattern
// that survived is an explicit command or a checkbox. Nothing here writes
// anything until someone types `demo`.

const { spawnSync } = require('child_process')
const fs = require('fs')
const os = require('os')
const path = require('path')

const { binary } = require('./resolve')

const RUNS = ['run_9f2a', 'run_c71e']

function demoHome () {
  if (process.env.BEHALF_DEMO_HOME) return process.env.BEHALF_DEMO_HOME
  if (process.env.BEHALF_HOME) return path.join(process.env.BEHALF_HOME, 'demo')
  return path.join(os.homedir(), '.behalf', 'demo')
}

function run (bin, args, env) {
  const res = spawnSync(bin, args, {
    stdio: ['ignore', 'inherit', 'inherit'],
    env: { ...process.env, ...env }
  })
  if (res.error) throw res.error
  return res.status === null ? 1 : res.status
}

function exportFiles () {
  const dir = path.join(__dirname, '..', 'demo')
  return RUNS.map((r) => {
    const p = path.join(dir, `${r}.jsonl`)
    if (!fs.existsSync(p)) {
      throw new Error(
        `the shipped recording is missing: ${p}\n` +
        '  The package should carry demo/run_9f2a.jsonl and demo/run_c71e.jsonl.'
      )
    }
    return p
  })
}

function demo (argv) {
  const home = demoHome()
  const logDir = path.join(home, 'log')

  if (fs.existsSync(path.join(logDir, 'checkpoint')) && !argv.includes('--again')) {
    console.log(`The demo is already unpacked at ${home}.`)
    console.log('Pass --again to unpack it a second time (it is idempotent), or go straight to:\n')
    printNextSteps(home)
    return 0
  }

  fs.mkdirSync(home, { recursive: true })

  // The offline verifier runs over each file before its receipts enter the log.
  // These files arrived from a registry, and "you need not take anyone's word
  // for what is in them" is the entire pitch — so the tool does not take its
  // own word for it either. `behalf-log import` finds the verifier beside
  // itself; both binaries are in the same platform package.
  const code = run(binary('behalf-log'), ['import', '--quiet', '--dir', logDir, ...exportFiles()], {
    BEHALF_VERIFY: binary('behalf-verify')
  })
  if (code !== 0) return code

  console.log('')
  console.log(`unpacked  two recorded runs into ${home}`)
  console.log('          no network, no key, no account, nothing spent')
  console.log('')
  printNextSteps(home)
  return 0
}

function printNextSteps (home) {
  const win = process.platform === 'win32'
  console.log(win ? `  set BEHALF_HOME=${home}` : `  export BEHALF_HOME=${home}`)
  console.log('')
  console.log('  behalf runs                        two runs of one agent. both ok.')
  console.log('  behalf diff run_9f2a run_c71e      which step made them differ')
  console.log('  behalf why run_c71e:31             and on whose behalf it was done')
  console.log('')
}

function usage (out) {
  out.write(`onbehalf — action receipts for AI agents

Usage:
  npx onbehalf demo [--again]     unpack two recorded runs and print what to type
  npx onbehalf where              print the paths of the installed binaries
  behalf <command>                the CLI itself (installed alongside)

\`demo\` writes only under BEHALF_DEMO_HOME, else demo/ under BEHALF_HOME, else
~/.behalf/demo. It makes no network calls and needs no account.
`)
}

function where () {
  for (const name of ['behalf', 'behalf-log', 'behalf-verify']) {
    console.log(`${name.padEnd(15)} ${binary(name)}`)
  }
  return 0
}

function main () {
  const argv = process.argv.slice(2)
  const cmd = argv[0]
  switch (cmd) {
    case 'demo':
      return demo(argv.slice(1))
    case 'where':
      return where()
    case undefined:
    case 'help':
    case '-h':
    case '--help':
      usage(process.stdout)
      return 0
    default:
      process.stderr.write(`onbehalf: unknown command ${JSON.stringify(cmd)}\n\n`)
      usage(process.stderr)
      return 2
  }
}

try {
  process.exitCode = main()
} catch (err) {
  process.stderr.write(`onbehalf: ${err.message}\n`)
  process.exitCode = 1
}
