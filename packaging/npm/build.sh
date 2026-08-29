#!/usr/bin/env bash
# Assemble the npm packages: one root package and six per-platform ones.
#
# Usage:
#   packaging/npm/build.sh <version> [platform...]
#
# With no platforms named it builds every one it can: the Go halves always,
# the Rust half only where a target is installed. That asymmetry is the whole
# cost of D9.8's decision to ship the native verifier alongside the CLI — Go
# cross-compiles from anywhere with no cgo, Rust needs a toolchain per target —
# and it is why the release workflow does the Rust builds on matrix runners
# rather than cross-compiling them from one host.
#
# Output: packaging/npm/dist/<package>/, ready for `npm publish`.
#
# What this script deliberately does NOT do: publish. Publishing happens in CI
# over OIDC trusted publishing, so no long-lived token exists to leak, and the
# provenance attestation names the workflow that built the artefact. A local
# `npm publish` would produce a package with no attestation, which for a
# provenance product is not a shortcut worth having.

set -euo pipefail

VERSION="${1:-}"
if [ -z "$VERSION" ]; then
  echo "usage: $0 <version> [platform...]" >&2
  echo "  platform is one of: darwin-arm64 darwin-x64 linux-arm64 linux-x64 win32-arm64 win32-x64" >&2
  exit 2
fi
shift || true

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKG="$ROOT/packaging/npm"
DIST="$PKG/dist"

ALL_PLATFORMS=(darwin-arm64 darwin-x64 linux-arm64 linux-x64 win32-arm64 win32-x64)
PLATFORMS=("$@")
if [ ${#PLATFORMS[@]} -eq 0 ]; then PLATFORMS=("${ALL_PLATFORMS[@]}"); fi

# npm's os/cpu vocabulary is Node's, and Go's is not. The mapping is small and
# fixed; getting it wrong means npm installs a package that cannot run, which
# is a failure the user sees and the CI does not.
go_os()   { case "$1" in darwin) echo darwin;; linux) echo linux;; win32) echo windows;; esac; }
go_arch() { case "$1" in arm64) echo arm64;; x64) echo amd64;; esac; }
rust_triple() {
  case "$1-$2" in
    darwin-arm64) echo aarch64-apple-darwin;;
    darwin-x64)   echo x86_64-apple-darwin;;
    linux-arm64)  echo aarch64-unknown-linux-gnu;;
    linux-x64)    echo x86_64-unknown-linux-gnu;;
    win32-arm64)  echo aarch64-pc-windows-msvc;;
    win32-x64)    echo x86_64-pc-windows-msvc;;
  esac
}

rm -rf "$DIST"
mkdir -p "$DIST"

# ---------------------------------------------------------------- root package

ROOT_OUT="$DIST/onbehalf"
mkdir -p "$ROOT_OUT/bin" "$ROOT_OUT/demo"
cp "$PKG/onbehalf/bin/"*.js "$ROOT_OUT/bin/"
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$ROOT_OUT/"
cp "$PKG/onbehalf/README.md" "$ROOT_OUT/README.md"

# The recording. These are the run's evidence; the log is rebuilt from them on
# the user's machine (`behalf-log import`), because the built tile directory is
# 23 MB against 452 KB for these two files and `npx` re-downloads every time.
cp "$ROOT/testdata/fixtures/run_9f2a.jsonl" "$ROOT/testdata/fixtures/run_c71e.jsonl" "$ROOT_OUT/demo/"

# Version stamping is a single jq-free substitution so this script needs nothing
# but bash, go, cargo and node.
node -e '
const fs = require("fs"), p = process.argv[1], v = process.argv[2];
const m = JSON.parse(fs.readFileSync(p, "utf8"));
m.version = v;
for (const k of Object.keys(m.optionalDependencies || {})) m.optionalDependencies[k] = v;
fs.writeFileSync(p + ".out", JSON.stringify(m, null, 2) + "\n");
' "$PKG/onbehalf/package.json" "$VERSION"
mv "$PKG/onbehalf/package.json.out" "$ROOT_OUT/package.json"

echo "built  onbehalf@$VERSION"

# ------------------------------------------------------------ platform packages

for plat in "${PLATFORMS[@]}"; do
  os="${plat%-*}"; cpu="${plat#*-}"
  goos="$(go_os "$os")"; goarch="$(go_arch "$cpu")"
  triple="$(rust_triple "$os" "$cpu")"
  out="$DIST/cli-$plat"
  ext=""; [ "$os" = "win32" ] && ext=".exe"
  mkdir -p "$out/bin"

  # Go is pure (no cgo), so every target cross-compiles from any host.
  # -trimpath keeps the build reproducible: a binary embedding the builder's
  # home directory is a binary two machines cannot agree on.
  for cmd in behalf behalf-log; do
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
      go build -trimpath -ldflags "-s -w" -o "$out/bin/$cmd$ext" "$ROOT/cmd/$cmd"
  done

  # Rust only where the target is installed. A missing target is reported and
  # skipped rather than failing the whole build, so a developer can assemble
  # their own platform without installing six toolchains — but the release
  # workflow builds each platform on its own runner and treats a skip as fatal
  # via --require-verifier.
  if rustup target list --installed 2>/dev/null | grep -qx "$triple"; then
    ( cd "$ROOT/verifier" && cargo build --release --target "$triple" )
    cp "$ROOT/verifier/target/$triple/release/behalf-verify$ext" "$out/bin/"
  elif [ "${REQUIRE_VERIFIER:-0}" = "1" ]; then
    echo "error: rust target $triple is not installed and REQUIRE_VERIFIER=1" >&2
    exit 1
  else
    echo "  note: rust target $triple not installed — $plat ships without behalf-verify" >&2
  fi

  cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$out/"
  sed -e "s/__OS__/$os/g" -e "s/__CPU__/$cpu/g" -e "s/__VERSION__/$VERSION/g" \
    "$PKG/platform/package.json.tmpl" > "$out/package.json"

  echo "built  @onbehalf/cli-$plat@$VERSION  ($(ls "$out/bin" | tr '\n' ' '))"
done

echo
echo "dist:  $DIST"
echo "next:  npm publish each directory (CI does this over OIDC with provenance)"
