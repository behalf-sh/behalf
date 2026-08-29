#!/usr/bin/env bash
# The tamper-detection suite (ENG-1). The only test that exercises the central
# claim: the shipped verifier must catch and correctly classify every mutation.
# Cases and expected classifications: docs/export-format-v1.md §5.
set -euo pipefail

BIN=${BEHALF_VERIFY:-verifier/target/release/behalf-verify}
FIX=${BEHALF_FIXTURES:-testdata/fixtures}
TMP=$(mktemp -d)
WITNESS_PID=
cleanup() {
  [ -n "$WITNESS_PID" ] && kill "$WITNESS_PID" 2>/dev/null
  rm -rf "$TMP"
}
trap cleanup EXIT

[ -x "$BIN" ] || { echo "verifier binary not found at $BIN" >&2; exit 2; }
[ -f "$FIX/run_9f2a.jsonl" ] && [ -f "$FIX/run_c71e.jsonl" ] || {
  echo "fixtures missing under $FIX (run: make fixtures)" >&2; exit 2; }

# Layout sanity: 1 header + 47 leaves + 1 head = 49 lines. The line surgery
# below indexes into this layout; drift here must fail loudly, not silently.
lines=$(wc -l < "$FIX/run_c71e.jsonl" | tr -d ' ')
[ "$lines" -eq 49 ] || { echo "fixture layout drift: $lines lines, want 49" >&2; exit 2; }

fail() { echo "FAIL: $*" >&2; exit 1; }

# The demo emitter's public key (internal/testkeys Emitter(), derived from a
# fixed public seed — part of the frozen fixture determinism). Both gated
# sections below verify against it: the Week-2 log built by `behalf-log
# ingest` and the Week-3 log recorded by `behalf-record` are signed by the
# same demo emitter, which is what makes either artifact verifiable by
# anyone holding this one file.
JWKS="$TMP/emitter.jwks.json"
cat > "$JWKS" <<'JWKSEOF'
{"keys":[{"jkt":"nhMxY9Ev1I_tjGngoLrnpVglp7I-93EorGFMI7RAh5U","jwk":{"kty":"OKP","crv":"Ed25519","x":"rZD4XaC6oZArnhEaNPzHTCA3HAJaHvoWpNFEI61-EnU"}}]}
JWKSEOF

expect_cmd() { # name want_exit stderr_pattern cmd [args...]
  local name=$1 want=$2 pat=$3
  shift 3
  local got=0
  set +e
  "$@" >"$TMP/$name.out" 2>"$TMP/$name.err"
  got=$?
  set -e
  if [ "$got" -ne "$want" ]; then
    sed 's/^/  stderr: /' "$TMP/$name.err" >&2
    fail "$name: exit $got, want $want"
  fi
  if [ -n "$pat" ] && ! grep -q "$pat" "$TMP/$name.err"; then
    sed 's/^/  stderr: /' "$TMP/$name.err" >&2
    fail "$name: stderr missing '$pat'"
  fi
  echo "ok: $name"
}

expect() { # name file want_exit [stderr_pattern]
  expect_cmd "$1" "$3" "${4:-}" "$BIN" "$2"
}

# -- intact -------------------------------------------------------------------
expect intact-9f2a "$FIX/run_9f2a.jsonl" 0
expect intact-c71e "$FIX/run_c71e.jsonl" 0

# -- the cover-up: the demo's own sed, byte for byte --------------------------
sed 's/1200\.00/12.00/' "$FIX/run_c71e.jsonl" > "$TMP/coverup.jsonl"
expect coverup "$TMP/coverup.jsonl" 1 'class=content index=31'

# -- drop: delete the leaf at index 20 (line 22) ------------------------------
sed '22d' "$FIX/run_c71e.jsonl" > "$TMP/drop.jsonl"
expect drop "$TMP/drop.jsonl" 1 'class=drop'

# -- reorder: swap leaves 10 and 11 (lines 12 and 13) -------------------------
awk 'NR==12{h=$0;next} NR==13{print;print h;next} {print}' \
  "$FIX/run_c71e.jsonl" > "$TMP/reorder.jsonl"
expect reorder "$TMP/reorder.jsonl" 1 'class=reorder'

# -- truncation: drop the last 5 leaves, keep the head ------------------------
sed -n '1,43p;49p' "$FIX/run_c71e.jsonl" > "$TMP/truncate.jsonl"
expect truncate "$TMP/truncate.jsonl" 1 'class=truncation'

# -- signature byte-flip on leaf index 5 (line 7) -----------------------------
python3 - "$FIX/run_c71e.jsonl" "$TMP/sigflip.jsonl" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src, 'rb').read().split(b'\n')
line = lines[6].decode()
k = line.index('"sig":"', line.index('"sig":{')) + len('"sig":"')
repl = 'AAAAAAAA' if line[k:k+8] != 'AAAAAAAA' else 'BBBBBBBB'
lines[6] = (line[:k] + repl + line[k+8:]).encode()
open(dst, 'wb').write(b'\n'.join(lines))
PY
expect sigflip "$TMP/sigflip.jsonl" 1 'class=content index=5'

# -- head edit: corrupt one hex char of head.chain ----------------------------
python3 - "$FIX/run_c71e.jsonl" "$TMP/headedit.jsonl" <<'PY'
import sys
src, dst = sys.argv[1], sys.argv[2]
lines = open(src, 'rb').read().split(b'\n')
line = lines[48].decode()
k = line.index('"chain":"') + len('"chain":"')
repl = '0' if line[k] != '0' else '1'
lines[48] = (line[:k] + repl + line[k+1:]).encode()
open(dst, 'wb').write(b'\n'.join(lines))
PY
expect headedit "$TMP/headedit.jsonl" 1 'class=\(head\|chain\)'

# -- garbage: not an export at all --------------------------------------------
printf 'this is not an export\x00\xff{{{\n' > "$TMP/garbage.jsonl"
expect garbage "$TMP/garbage.jsonl" 2

# ============================================================================
# log-storage cases (ENG-7): the same claims against the real log storage —
# a Tessera v1.0.4 tile directory written by cmd/behalf-log, verified with
# `behalf-verify log`. Gated on BEHALF_LOG_DIR so the Week-1 section keeps
# running standalone.
# ============================================================================
if [ -z "${BEHALF_LOG_DIR:-}" ]; then
  echo "log-storage cases: skipped (set BEHALF_LOG_DIR to a fresh directory to run them)"
else
  LOG="$BEHALF_LOG_DIR"
  if [ -e "$LOG/checkpoint" ]; then
    echo "BEHALF_LOG_DIR ($LOG) already contains a log; point it at a fresh directory" >&2
    exit 2
  fi

  # Build the log in two ingests so a genuinely earlier checkpoint exists
  # for the stale-restore case (Q76): run_9f2a -> indices 0..46, snapshot
  # the checkpoint, then run_c71e -> indices 47..93.
  echo "building log at $LOG via cmd/behalf-log (Tessera POSIX driver)..."
  go run ./cmd/behalf-log init   --dir "$LOG" >/dev/null
  go run ./cmd/behalf-log ingest --dir "$LOG" --runs run_9f2a >/dev/null
  cp "$LOG/checkpoint" "$TMP/checkpoint.mid"    # saved before the last append
  go run ./cmd/behalf-log ingest --dir "$LOG" --runs run_c71e >/dev/null
  cp "$LOG/checkpoint" "$TMP/checkpoint.latest"

  # Layout sanity, mirroring the Week-1 line-count check: the byte surgery
  # below targets this bundle file; drift must fail loudly.
  BUNDLE="tile/entries/000.p/94"
  [ -f "$LOG/$BUNDLE" ] || { echo "log layout drift: $BUNDLE missing" >&2; exit 2; }

  # -- intact log -------------------------------------------------------------
  expect_cmd log-intact 0 '' \
    "$BIN" log "$LOG" --emitter-keys "$JWKS" --latest-known "$TMP/checkpoint.latest"
  expect_cmd log-intact-keyless 0 '' "$BIN" log "$LOG"

  # -- content: flip one byte inside a stored envelope's payload region -------
  # run_c71e step 31 (log index 47+31=78) carries the demo's unique
  # "amount":"1200.00"; flip one bit inside that span in the entry bundle.
  cp -R "$LOG" "$TMP/log-flip"
  python3 - "$TMP/log-flip/$BUNDLE" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, 'rb').read())
k = b.find(b'"amount":"1200.00"')
assert k >= 0, 'payload marker not found in entry bundle'
b[k + len('"amount":"12')] ^= 0x01  # one bit, inside the signed payload span
open(p, 'wb').write(bytes(b))
PY
  expect_cmd log-flip 1 'class=content index=78' \
    "$BIN" log "$TMP/log-flip" --emitter-keys "$JWKS"

  # -- truncation: delete the highest entry-bundle file -----------------------
  # The stale partial .p/47 lingers (Tessera GC off); coverage now ends at
  # 47 while the signed checkpoint commits to 94.
  cp -R "$LOG" "$TMP/log-truncate"
  rm "$TMP/log-truncate/$BUNDLE"
  expect_cmd log-truncate 1 'class=truncation' \
    "$BIN" log "$TMP/log-truncate" --emitter-keys "$JWKS"

  # -- stale restore (Q76): an older checkpoint restored over newer tiles -----
  # Without the later checkpoint the restore is undetectable (a valid
  # prefix tree) — that is the witness's job. With --latest-known it must
  # classify as truncation.
  cp -R "$LOG" "$TMP/log-restore"
  cp "$TMP/checkpoint.mid" "$TMP/log-restore/checkpoint"
  expect_cmd log-restore-undetected-alone 0 '' \
    "$BIN" log "$TMP/log-restore" --emitter-keys "$JWKS"
  expect_cmd log-restore 1 'class=truncation index=-1' \
    "$BIN" log "$TMP/log-restore" --emitter-keys "$JWKS" --latest-known "$TMP/checkpoint.latest"

  # -- head: edit the checkpoint root ----------------------------------------
  # The checkpoint note signature is verified before anything else in log
  # mode, so an edited root classifies as head (documented in
  # verifier/src/logdir.rs; file mode classifies its head-edit as chain).
  cp -R "$LOG" "$TMP/log-headedit"
  python3 - "$TMP/log-headedit/checkpoint" <<'PY'
import sys
p = sys.argv[1]
lines = open(p, 'rb').read().split(b'\n')
root = bytearray(lines[2])  # line 3: the base64 root hash
root[0] = ord('B') if root[0] != ord('B') else ord('C')
lines[2] = bytes(root)
open(p, 'wb').write(b'\n'.join(lines))
PY
  expect_cmd log-headedit 1 'class=head index=-1' \
    "$BIN" log "$TMP/log-headedit" --emitter-keys "$JWKS"
fi

# ============================================================================
# payload cases (ENG-24): the cover-up, moved to where the bytes actually
# live.
#
# The two sections above tamper with behalf's own record. This one does not
# touch it. Real proxy-recorded receipts do not embed tool arguments —
# payloads are customer-held, and the receipt carries a digest, a content
# address, a size and a content type, never the content (Q34–Q38, D7). So an
# attacker covering up a $1200 refund does not edit a receipt they cannot
# forge; they edit the arguments in their own store, which they own outright.
#
# behalf catches it anyway, because the blob no longer hashes to the digest
# committed inside a DSSE-signed, log-committed receipt. You hold the bytes,
# we hold the commitment, and we can still prove your bytes changed.
#
# What makes the case worth its own class is what stays true after the edit:
# the log verifies, the checkpoint verifies, every receipt signature
# verifies. Nothing in the transparency log noticed, because nothing in the
# transparency log changed. The finding is `class=payload`, and the two
# assertions that bracket it — verifier clean before AND after — are the
# point of the case, not scaffolding around it.
#
# Gated on BEHALF_RECORD_DIR, mirroring BEHALF_LOG_DIR, so the earlier
# sections keep running standalone.
# ============================================================================
if [ -z "${BEHALF_RECORD_DIR:-}" ]; then
  echo "payload cases: skipped (set BEHALF_RECORD_DIR to a fresh directory to run them)"
else
  REC="$BEHALF_RECORD_DIR"
  if [ -e "$REC/log/checkpoint" ]; then
    echo "BEHALF_RECORD_DIR ($REC) already contains a log; point it at a fresh directory" >&2
    exit 2
  fi
  RECLOG="$REC/log"
  RECSTATE="$REC/state"
  CAS="$RECSTATE/blobs"
  RUN_B=rec_c71e   # the run whose step-31 refund went to ord_5518 for 1200.00

  # Record the demo pair through the REAL proxy against the in-repo desk MCP
  # server: 47 tool calls per run, one log, payload blobs in the CAS,
  # receipts appended via the drain path. Deterministic — same bytes every
  # run — which is what lets this case index a fixed leaf.
  echo "recording the demo session pair at $REC via cmd/behalf-record (real proxy)..."
  go run ./cmd/behalf-record --dir "$RECLOG" --out "$RECSTATE" --quiet

  # Layout sanity, mirroring the line-count and bundle-path checks above:
  # run A takes log indices 0..46, run B 47..93, so run B's step 31 — the
  # refund — is leaf 78. Drift must fail loudly, not silently retarget.
  PAYLOAD_INDEX=78
  op=$(go run ./cmd/behalf-log rehydrate --dir "$RECLOG" --run "$RUN_B" --state "$RECSTATE" \
        | sed -n "s/.*\"log_index\":$PAYLOAD_INDEX,.*\"name\":\"\([^\"]*\)\".*/\1/p")
  [ "$op" = "refund.issue" ] || {
    echo "recording layout drift: leaf $PAYLOAD_INDEX is '$op', want refund.issue" >&2; exit 2; }

  # The literal the cover-up edits must exist in exactly one blob of the
  # whole store, or the demo would be editing several records while claiming
  # to edit one. (Search results carry integer cents for this reason.)
  # shellcheck disable=SC2012
  BLOB=$(grep -l '1200\.00' "$CAS"/* || true)
  [ -n "$BLOB" ] && [ "$(printf '%s\n' "$BLOB" | wc -l | tr -d ' ')" -eq 1 ] || {
    echo "payload layout drift: $(printf '%s\n' "$BLOB" | grep -c . || true) blobs contain 1200.00, want exactly 1" >&2
    exit 2; }

  # -- clean: the recording verifies, and its payloads rehydrate -------------
  expect_cmd record-log-intact 0 '' \
    "$BIN" log "$RECLOG" --emitter-keys "$JWKS"
  expect_cmd record-rehydrate-clean 0 '' \
    go run ./cmd/behalf-log rehydrate --dir "$RECLOG" --run "$RUN_B" --state "$RECSTATE"

  # -- the payload cover-up: the demo's own sed, against the customer's own
  #    store. The receipt is not touched; the blob keeps its name, which is
  #    the digest it no longer hashes to.
  sed 's/1200\.00/12.00/' "$BLOB" > "$TMP/blob.edited"
  cp "$TMP/blob.edited" "$BLOB"

  expect_cmd record-payload-coverup 1 "class=payload index=$PAYLOAD_INDEX" \
    go run ./cmd/behalf-log rehydrate --dir "$RECLOG" --run "$RUN_B" --state "$RECSTATE"

  # The finding names the receipt and what moved, not just "something is
  # wrong somewhere".
  grep -q "run=$RUN_B step=31" "$TMP/record-payload-coverup.err" || {
    sed 's/^/  stderr: /' "$TMP/record-payload-coverup.err" >&2
    fail "record-payload-coverup: the finding does not name the receipt"; }
  grep -q 'operation=refund.issue target=ord_5518' "$TMP/record-payload-coverup.err" || {
    sed 's/^/  stderr: /' "$TMP/record-payload-coverup.err" >&2
    fail "record-payload-coverup: the finding does not name the operation"; }

  # -- and the log is still perfect ------------------------------------------
  # This is the case's real assertion. A tamper suite that only showed the
  # payload break would leave the impression that something in the log gave
  # it away. Nothing did: the tree, the checkpoint and every receipt
  # signature verify exactly as before, and the only thing that changed is
  # that the customer's bytes stopped matching what behalf signed.
  expect_cmd record-log-intact-after-coverup 0 '' \
    "$BIN" log "$RECLOG" --emitter-keys "$JWKS"

  # -- absence is not tampering ----------------------------------------------
  # Delete the blob outright instead of editing it. A run whose payloads are
  # gone still resolves cleanly — placeholders are the normal path, not an
  # error path (Q83) — so this must exit 0 while the edit above exits 1.
  cp -R "$CAS" "$TMP/cas-emptied"
  rm -f "$TMP/cas-emptied"/*
  expect_cmd record-rehydrate-absent 0 '' \
    go run ./cmd/behalf-log rehydrate --dir "$RECLOG" --run "$RUN_B" --cas "$TMP/cas-emptied"
  grep -q '"state":"missing"' "$TMP/record-rehydrate-absent.out" || \
    fail "record-rehydrate-absent: an empty store must render missing placeholders"
fi

# ============================================================================
# witness cases (ENG-11): the split-view and stale-restore defences, with an
# actual independent witness in the loop.
#
# Everything above this point verifies one directory against itself. That is
# exactly what a split view defeats: an operator who serves you one history
# and someone else another can make both directories verify perfectly, and
# a stale restore — an older checkpoint put back over newer tiles — verifies
# clean in isolation on purpose (the log-storage section asserts that, as
# `log-restore-undetected-alone`, exit 0).
#
# The witness is what closes both. It holds the highest (size, root) it has
# cosigned for an origin, durably, and refuses anything inconsistent with
# it. The three cases below are the payoff, in the order the witness's state
# machine requires:
#
#   1. happy path      first checkpoint at 47, then growth to 94 with a
#                      consistency proof read from the log's own tiles
#   2. fork            a different 47-entry history under the same
#                      checkpoint key -> class=chain reason=same-size-different-root
#   3. stale restore   the size-47 checkpoint put back after 94 was
#                      witnessed -> class=truncation reason=smaller-size
#
# and then the availability mode itself: with the witness stopped, the log
# still publishes (fail_open=true, Q96) and records the gap.
#
# Gated on BEHALF_WITNESS_DIR, mirroring BEHALF_LOG_DIR/BEHALF_RECORD_DIR.
# ============================================================================
if [ -z "${BEHALF_WITNESS_DIR:-}" ]; then
  echo "witness cases: skipped (set BEHALF_WITNESS_DIR to a fresh directory to run them)"
else
  WIT="$BEHALF_WITNESS_DIR"
  if [ -e "$WIT/state/witness-state.json" ] || [ -e "$WIT/log/checkpoint" ]; then
    echo "BEHALF_WITNESS_DIR ($WIT) already contains a witness or a log; point it at a fresh directory" >&2
    exit 2
  fi
  mkdir -p "$WIT/state"

  # Build the two binaries once: the witness runs as a background process
  # for the whole section, and `go run` would leave an orphan child behind.
  WITBIN="$TMP/behalf-witness"
  LOGBIN="$TMP/behalf-log"
  go build -o "$WITBIN" ./cmd/behalf-witness
  go build -o "$LOGBIN" ./cmd/behalf-log

  # The witness's own key, in its own directory — in production this whole
  # side lives in a separate cloud account (D3.5). Nothing here shares a
  # key, a directory or a process with the log.
  "$WITBIN" init --key "$WIT/witness.skey" --name behalf.sh/witness/demo >/dev/null
  WVKEY=$(cat "$WIT/witness.skey.vkey")

  WLOG="$WIT/log"
  "$LOGBIN" init --dir "$WLOG" --origin behalf.sh/log/witness-demo >/dev/null
  cp "$WLOG/keys/checkpoint.vkey" "$WIT/logs.txt"

  # The log's witness policy: fail-open, the v1 posture (Q96), with the
  # timeout and quorum stated rather than implied.
  WPORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
  cat > "$TMP/witnesses.json" <<WITEOF
{"fail_open": true, "timeout_ms": 5000, "quorum": 1,
 "witnesses": [{"name": "witness-1", "vkey": "$WVKEY", "url": "http://127.0.0.1:$WPORT"}]}
WITEOF
  cp "$TMP/witnesses.json" "$WLOG/witnesses.json"

  "$WITBIN" serve --state "$WIT/state" --key "$WIT/witness.skey" \
    --logs "$WIT/logs.txt" --addr "127.0.0.1:$WPORT" > "$TMP/witness.log" 2>&1 &
  WITNESS_PID=$!
  python3 - "$WPORT" <<'PY'
import socket, sys, time
port = int(sys.argv[1])
for _ in range(200):
    try:
        socket.create_connection(("127.0.0.1", port), 0.2).close()
        sys.exit(0)
    except OSError:
        time.sleep(0.05)
raise SystemExit("witness did not come up")
PY
  echo "witness listening on 127.0.0.1:$WPORT (state $WIT/state)"

  # -- 1a. happy path, first checkpoint --------------------------------------
  # 47 receipts. The log submits its own checkpoint after publishing it and
  # records the outcome per checkpoint — no operator action — so the
  # cosigned record must already be there when ingest returns.
  "$LOGBIN" ingest --dir "$WLOG" --runs run_9f2a >/dev/null
  cp "$WLOG/checkpoint" "$TMP/w-checkpoint.47"
  [ -f "$WLOG/witness/outcomes.jsonl" ] || \
    fail "witness-first: publishing a checkpoint must write a per-checkpoint witness record"
  tail -n 1 "$WLOG/witness/outcomes.jsonl" | grep -q '"size":47,.*"outcome":"cosigned"' || {
    tail -n 1 "$WLOG/witness/outcomes.jsonl" | sed 's/^/  /' >&2
    fail "witness-first: the log's own submission after publication must be recorded as cosigned"; }
  # The same submission again, explicitly: the witness has never seen a
  # different history for this origin, so it re-cosigns rather than
  # refusing. Idempotence is part of the safety rule, not an accident.
  expect_cmd witness-first 0 '' "$LOGBIN" witness --dir "$WLOG"
  grep -q 'outcome    cosigned' "$TMP/witness-first.out" || \
    fail "witness-first: the first checkpoint for an unseen origin must be cosigned"

  # -- 2. the fork: a different history at the same size ---------------------
  # Same checkpoint key, same origin, same 47 entries' worth of length — a
  # different 47 receipts. This is the split view: two histories the
  # operator could serve to two different people, each internally perfect.
  mkdir -p "$WIT/fork/keys"
  cp "$WLOG/keys/checkpoint.skey" "$WLOG/keys/checkpoint.vkey" "$WIT/fork/keys/"
  "$LOGBIN" ingest --dir "$WIT/fork" --runs run_c71e >/dev/null
  cp "$TMP/witnesses.json" "$WIT/fork/witnesses.json"

  # Both directories verify on their own. That is the point: the tile
  # verifier cannot tell them apart, because neither is corrupt.
  expect_cmd witness-fork-verifies-alone 0 '' \
    "$BIN" log "$WIT/fork" --emitter-keys "$JWKS"
  # The witness can, and does.
  expect_cmd witness-fork 1 'class=chain reason=same-size-different-root index=-1' \
    "$LOGBIN" witness --dir "$WIT/fork"
  grep -q 'outcome    refused' "$TMP/witness-fork.out" || \
    fail "witness-fork: the record must name the refusal"

  # A refusal must not move the head: the witness still holds the real 47.
  "$WITBIN" show --state "$WIT/state" --json > "$TMP/witness-show-47.out"
  grep -q '"size": 47' "$TMP/witness-show-47.out" || {
    sed 's/^/  /' "$TMP/witness-show-47.out" >&2
    fail "witness show: a refused fork must leave the held head at 47"; }

  # -- 1b. happy path, growth ------------------------------------------------
  # 47 -> 94 on the real log. The consistency proof comes out of the log's
  # own hash tiles and carries the held root forward, so the witness
  # advances rather than refusing.
  "$LOGBIN" ingest --dir "$WLOG" --runs run_c71e >/dev/null
  expect_cmd witness-growth 0 '' "$LOGBIN" witness --dir "$WLOG"
  grep -q 'outcome    cosigned' "$TMP/witness-growth.out" || \
    fail "witness-growth: normal growth must cosign cleanly"
  "$WITBIN" show --state "$WIT/state" --json > "$TMP/witness-show-94.out"
  grep -q '"size": 94' "$TMP/witness-show-94.out" || {
    sed 's/^/  /' "$TMP/witness-show-94.out" >&2
    fail "witness show: the witness must now hold 94"; }

  # The cosignature rides on the checkpoint as one more note signature
  # line. A verifier that does not know the witness key must skip it
  # (D3.4's grease discipline), so checkpoint.witnessed is still a
  # perfectly good latest-known checkpoint for the Rust verifier.
  [ -f "$WLOG/checkpoint.witnessed" ] || fail "witness-growth: no cosigned checkpoint was persisted"
  grep -q 'behalf.sh/witness/demo' "$WLOG/checkpoint.witnessed" || \
    fail "witness-growth: checkpoint.witnessed carries no witness signature line"
  expect_cmd witness-cosigned-checkpoint-tolerated 0 '' \
    "$BIN" log "$WLOG" --emitter-keys "$JWKS" --latest-known "$WLOG/checkpoint.witnessed"

  # -- 3. the stale restore --------------------------------------------------
  # Roll a copy of the directory back to the size-47 checkpoint, after the
  # witness has cosigned 94. In isolation this verifies clean (the
  # log-storage section proves it, above). The witness refuses it, and that
  # refusal is the Q76 rule with teeth.
  cp -R "$WLOG" "$WIT/restore"
  cp "$TMP/w-checkpoint.47" "$WIT/restore/checkpoint"
  rm -f "$WIT/restore/checkpoint.witnessed"
  expect_cmd witness-restore-verifies-alone 0 '' \
    "$BIN" log "$WIT/restore" --emitter-keys "$JWKS"
  expect_cmd witness-stale-restore 1 'class=truncation reason=smaller-size index=-1' \
    "$LOGBIN" witness --dir "$WIT/restore"

  # -- the availability mode, exercised as an availability mode (Q96) --------
  # Stop the witness. Publication must proceed — that is what FailOpen:true
  # means — and the gap must land in the per-checkpoint record with its
  # reason, so "we published without a cosignature" is a fact in the record
  # rather than an absence in it.
  kill "$WITNESS_PID" 2>/dev/null || true
  wait "$WITNESS_PID" 2>/dev/null || true
  WITNESS_PID=
  expect_cmd witness-fail-open 0 'fail_open=true is the v1 policy' \
    "$LOGBIN" witness --dir "$WLOG"
  tail -n 1 "$WLOG/witness/outcomes.jsonl" > "$TMP/witness-last-record.json"
  grep -q '"outcome":"not-cosigned"' "$TMP/witness-last-record.json" || {
    sed 's/^/  /' "$TMP/witness-last-record.json" >&2
    fail "witness-fail-open: the gap must be recorded per checkpoint"; }
  grep -q '"fail_open":true' "$TMP/witness-last-record.json" || \
    fail "witness-fail-open: the record must state the availability mode it published under"

  # And the log still accepts appends and still publishes with no witness
  # reachable at all. (Both fixture runs are already in this log, so the
  # receipts dedup — what is being asserted here is that the write path
  # completes, not that the tree grows.)
  "$LOGBIN" ingest --dir "$WLOG" --runs run_9f2a >/dev/null 2>&1 || \
    fail "witness-fail-open: a dead witness must not block ingest"
  expect_cmd witness-fail-open-log-intact 0 '' "$BIN" log "$WLOG" --emitter-keys "$JWKS"

  echo "ok: witness cases (fork, stale restore, growth, fail-open)"
fi

echo "tamper suite: all cases detected and classified"
