'use strict'

// Finding the platform binaries, and saying something useful when they are not
// there.
//
// The package ships no binaries of its own. Each platform's are a separate
// package — `@onbehalf/cli-darwin-arm64` and its five siblings — declared as
// `optionalDependencies` and filtered by npm's own `os` and `cpu` fields, so
// installing `onbehalf` downloads one platform's binaries and not six (D9.8).
//
// There is deliberately **no `postinstall` script**. A postinstall that fetched
// a binary from somewhere else is exactly the unauditable install-time step
// this product exists to eliminate, and it is blocked outright in many of the
// enterprises this demo is aimed at. The cost of not having one is that when
// the optional dependency did not install, nothing has run to notice — so this
// file has to notice, and has to explain, because npm's own failure mode for a
// missing optional dependency is silence.

const fs = require('fs')
const path = require('path')

// The platforms with published packages, keyed the way Node reports them.
// Windows is absent on purpose: the log's storage driver is POSIX-only, so
// neither `behalf` nor `behalf-log` builds there, and the demo needs both.
const SUPPORTED = new Set([
  'darwin-arm64',
  'darwin-x64',
  'linux-arm64',
  'linux-x64'
])

function platformKey () {
  return `${process.platform}-${process.arch}`
}

function packageName () {
  return `@onbehalf/cli-${platformKey()}`
}

/**
 * Absolute path to one binary inside the platform package.
 * Throws with a sentence a human can act on, never a bare MODULE_NOT_FOUND.
 */
function binary (name) {
  const key = platformKey()
  if (!SUPPORTED.has(key)) {
    const windows = process.platform === 'win32'
      ? '  Windows is not supported yet: the log\'s storage driver is POSIX-only.\n' +
        '  It runs under WSL. Tracked at https://github.com/behalf-sh/behalf/issues\n'
      : ''
    throw new Error(
      `behalf does not ship a binary for ${key}.\n` +
      windows +
      `  Supported: ${[...SUPPORTED].join(', ')}.\n` +
      '  Everything here builds from source: https://github.com/behalf-sh/behalf'
    )
  }
  const exe = process.platform === 'win32' ? `${name}.exe` : name

  const pkgRoot = findPackageRoot(packageName())
  if (!pkgRoot) {
    throw new Error(
      `the platform package ${packageName()} is not installed.\n` +
      '  It is an optionalDependency, so npm may have skipped it without failing —\n' +
      '  usually --no-optional, an --omit=optional lockfile, or an offline install.\n' +
      `  Fix: npm install ${packageName()}\n` +
      '  There is no postinstall script that could fetch it for you, on purpose:\n' +
      '  an install-time download from somewhere else is the step this tool exists\n' +
      '  to make unnecessary.'
    )
  }

  const p = path.join(pkgRoot, 'bin', exe)
  if (!fs.existsSync(p)) {
    throw new Error(
      `${packageName()} is installed but does not contain ${exe}.\n` +
      `  Looked in ${path.join(pkgRoot, 'bin')}.\n` +
      '  That is a broken package rather than a broken install; please report it:\n' +
      '  https://github.com/behalf-sh/behalf/issues'
    )
  }
  return p
}

/**
 * Locate the platform package's directory, or null.
 *
 * `require.resolve` alone is not enough, and the reason is worth stating
 * because the failure it produces is a confident wrong answer. Node resolves
 * this file through its *realpath*, so when the package is reached by a symlink
 * — `npm link`, a `file:` dependency, a workspace, a monorepo — the resolver
 * walks up from wherever the package really lives and never sees the consuming
 * project's node_modules at all. The result is "the platform package is not
 * installed" about a package sitting right there, which sends someone off to
 * fix an install that is fine.
 *
 * So: ask the resolver first, since it is right for an ordinary registry
 * install, and then walk up from the symlinked location and the working
 * directory. Three cheap lookups, and the error message only appears when the
 * package genuinely is not there.
 */
function findPackageRoot (name) {
  try {
    return path.dirname(require.resolve(`${name}/package.json`))
  } catch { /* fall through to the symlink-aware search */ }

  const starts = []
  // process.argv[1] is the bin as invoked, which for a symlinked install is
  // inside the consuming project rather than beside the real file.
  if (process.argv[1]) starts.push(path.dirname(process.argv[1]))
  starts.push(process.cwd(), __dirname)

  for (const start of starts) {
    let dir = path.resolve(start)
    for (;;) {
      const candidate = path.join(dir, 'node_modules', ...name.split('/'))
      if (fs.existsSync(path.join(candidate, 'package.json'))) return candidate
      const parent = path.dirname(dir)
      if (parent === dir) break
      dir = parent
    }
  }
  return null
}

module.exports = { binary, packageName, platformKey, SUPPORTED }
