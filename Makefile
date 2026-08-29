GO ?= go
CARGO ?= cargo
PYTHON ?= python3
WASM_BINDGEN ?= wasm-bindgen
VERIFIER_DIR := verifier
VERIFY_BIN := $(VERIFIER_DIR)/target/release/behalf-verify
WASM_TARGET := wasm32-unknown-unknown
WASM_PROFILE := release-wasm
WASM_OUT := $(VERIFIER_DIR)/target/$(WASM_TARGET)/$(WASM_PROFILE)/behalf_verify.wasm
WEB_DIR := $(VERIFIER_DIR)/web
WEB_DIST := $(WEB_DIR)/dist

.PHONY: all build test fixtures vectors conformance tamper-suite lint ci wasm wasm-test

all: build

build:
	$(GO) build ./...
	cd $(VERIFIER_DIR) && $(CARGO) build --release

test:
	$(GO) test ./...
	cd $(VERIFIER_DIR) && $(CARGO) test

fixtures:
	$(GO) run ./cmd/behalf-fixtures

vectors:
	$(GO) run ./cmd/behalf-vectors

conformance: vectors build
	cd $(VERIFIER_DIR) && BEHALF_VECTORS=$(abspath testdata/vectors) $(CARGO) test --test conformance -- --nocapture

# The suite's three gated sections each want their own fresh directory:
# BEHALF_LOG_DIR for the log-storage cases (a Tessera log built by
# cmd/behalf-log ingest), BEHALF_RECORD_DIR for the payload cases (the demo
# session pair recorded through the real proxy by cmd/behalf-record), and
# BEHALF_WITNESS_DIR for the witness cases (a real behalf-witness process on
# a loopback port, plus the log it cosigns for — the split-view and
# stale-restore defences, ENG-11). All are temp dirs, cleaned up after.
tamper-suite: fixtures build
	@d=$$(mktemp -d); \
	BEHALF_VERIFY=$(VERIFY_BIN) BEHALF_LOG_DIR=$$d/log BEHALF_RECORD_DIR=$$d/record \
	  BEHALF_WITNESS_DIR=$$d/witness \
	  bash scripts/tamper_suite.sh; \
	status=$$?; rm -rf "$$d"; exit $$status

lint:
	$(GO) vet ./...
	cd $(VERIFIER_DIR) && $(CARGO) clippy -- -D warnings

ci: build test lint conformance tamper-suite

# ---------------------------------------------------------------------------
# Browser verifier (ENG-19). Additive: nothing above depends on these, and
# `make ci` is unchanged — the wasm build needs two tools the native gate does
# not (the wasm32 target and wasm-bindgen-cli):
#
#   rustup target add wasm32-unknown-unknown
#   cargo install wasm-bindgen-cli --version 0.2.127 --locked   # match Cargo.lock
#
# Outputs land in verifier/web/dist/ and are gitignored:
#
#   dist/verify.html   one self-contained file — wasm inlined, opens from
#                      file://, fetches nothing
#   dist/index.html    the served build, next to behalf_verify_bg.wasm
#
# `fixtures` supplies the intact demo export the page's tamper buttons mutate,
# so the wasm build needs Go too. build.py itself does not: run it directly
# with a missing --sample and it warns, drops the sample buttons and still
# emits a working drop zone (a 312 KB self-contained page instead of 601 KB).
wasm: fixtures
	cd $(VERIFIER_DIR) && $(CARGO) build --lib --profile $(WASM_PROFILE) --target $(WASM_TARGET)
	$(WASM_BINDGEN) --target no-modules --no-typescript --out-dir $(WEB_DIST) $(WASM_OUT)
	$(PYTHON) $(WEB_DIR)/build.py \
	  --template $(WEB_DIR)/index.html \
	  --glue $(WEB_DIST)/behalf_verify.js \
	  --wasm $(WEB_DIST)/behalf_verify_bg.wasm \
	  --sample testdata/fixtures/run_c71e.jsonl \
	  --out-dir $(WEB_DIST) \
	  --version $$(cd $(VERIFIER_DIR) && $(CARGO) metadata --no-deps --format-version 1 \
	                 | $(PYTHON) -c 'import json,sys; print(json.load(sys.stdin)["packages"][0]["version"])')

# Headless wasm-bindgen tests, run under node. Same guarantees as the native
# suite: intact verifies, tampering classifies, malformed input returns a
# structured error instead of panicking.
wasm-test:
	cd $(VERIFIER_DIR) && \
	  CARGO_TARGET_WASM32_UNKNOWN_UNKNOWN_RUNNER=wasm-bindgen-test-runner \
	  $(CARGO) test --target $(WASM_TARGET) --test wasm_verify
