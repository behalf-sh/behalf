#!/usr/bin/env node
'use strict'

// The `behalf-log` shim: exec the platform binary with the arguments as given, the
// same way bin/behalf.js does. Nothing is interpreted; the exit code is the
// binary's, which the verifier's documented exit codes depend on.

const { spawnSync } = require('child_process')
const { binary } = require('./resolve')

try {
  const res = spawnSync(binary('behalf-log'), process.argv.slice(2), { stdio: 'inherit' })
  if (res.error) throw res.error
  if (res.signal) process.kill(process.pid, res.signal)
  process.exitCode = res.status === null ? 1 : res.status
} catch (err) {
  process.stderr.write(`behalf-log: ${err.message}\n`)
  process.exitCode = 1
}
