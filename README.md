# behalf

**Action receipts for AI agents.** One immutable, tamper-evident record per consequential
thing an agent does, carrying the delegation chain that authorised it — human → agent →
sub-agent → tool — so that months later you can ask *which step caused this* and *who was
this actually done on behalf of*, and get an answer a third party can check.

Every observability tool will tell you an agent called `refund.issue`. behalf tells you
whether the human at the root of that chain ever authorised a refund of that size — and
says plainly when nobody can know, instead of attributing the action to whatever name the
caller supplied.

**On cold start:** Sentry needs you to have a bug. CloudTrail needs you to have a breach.
behalf needs you to run your agent twice — and agents are nondeterministic, so the second
run *will* differ.

> **Status: in development, not yet published.** The pipeline runs end to end — capture,
> log, verification, and the headline commands — and the `npx` packages are built and
> tested. What has not happened is the publish: there is nothing on a registry yet, so the
> quickstart below describes a command you cannot run until it is. See
> [What works today](#what-works-today) for the line-by-line.

---

## Quickstart

```sh
npx onbehalf demo
```

Two recorded runs of the same support-desk agent, unpacked onto your machine. No network,
no API key, no account, no tokens spent — and nothing is written until you type `demo`.
Then:

```sh
npx onbehalf runs                        # two runs of one agent. both ok.
npx onbehalf diff run_9f2a run_c71e      # which step made them differ
npx onbehalf why run_c71e:31             # and on whose behalf it was done
```

`npx` runs from npm's cache and puts nothing on `PATH`, so the commands are written the way
they work. `npm install -g onbehalf` puts `behalf`, `behalf-log` and `behalf-verify` on `PATH`
if you would rather type the short form.

**Before you run any of that — a challenge.** Both exports are in the package
(`node_modules/onbehalf/demo/`). Open them in whatever you use today. Forty-seven steps
each, twenty-two of them different, both runs `ok` from end to end. Find the one that
caused the other twenty-one, and find out whether the human at the root of the chain ever
authorised a refund of that size.

Then run `behalf diff`. It names step 12 and shows you the consequence at step 31, and
`behalf why run_c71e:31` tells you that the hop which issued the refund is
**unverified** — the actor name on it is a string the caller supplied, and the delegation
it claims was for a hundred dollars.

The point is not that the tool is fast. It is that the second question — *on whose behalf*
— is not one your current tools can answer at all, because nothing in a trace carries the
delegation chain.

Wrapping your own MCP server is one line, and produces a receipt on the first call:

```sh
behalf login --issuer https://your-idp.example --client-id <id>
behalf-proxy -- your-mcp-server --its --own --flags
```

`behalf login` mints the identity root: a device key bound through the OIDC `nonce`, so the
IdP's own signature ties a human to that key. Everything after it chains from there, and
`behalf whoami` re-verifies it offline.

---

## What behalf claims — and what it does not

This section is first on purpose. Anyone security-literate will find these limits in ten
seconds; stating them up front is cheaper than being corrected.

**What the offline verifier proves** — the Rust binary in `verifier/`, which anyone can build
and run against the exported bytes, with no call to behalf and no call to your IdP:

- **Record integrity.** No receipt was modified, dropped, reordered or back-dated after it
  was written. The log is a tiled transparency log ([C2SP tlog-tiles], via
  [Tessera]); checkpoints are signed every second. Two implementations agree on this and are
  held to it in CI: a Go writer and a Rust verifier, pinned against each other by a
  conformance corpus.

**What behalf's own tooling establishes** — checked at capture by `internal/aat`, recorded
per hop, and shown by `behalf why`:

- **Chain authorisation.** That hop N of a delegation chain was authorised by hop N−1,
  cryptographically, per hop. **When this is checked matters and is stated here rather than
  glossed:** the signature, the `par_hash` linkage and the depth and expiry invariants are
  checked once, at capture, and the verdict is written into the receipt. What `behalf why`
  recomputes on every read is the *attenuation comparison*, from the raw grants the record
  carries — so a comparator bug cannot freeze into evidence. The signature verdict is not
  recomputed there.
  That distinction would be worth little if the evidence were gone, so it is not: each hop's
  token is retained in your own store at exactly the address the hop's `evidence_ref` names,
  it travels in the export, and **the offline verifier re-runs the check against it** — the
  signature, the depth and expiry invariants and the `par_hash` linkage, in an implementation
  that shares no code with the one that wrote the record. What it does *not* re-run is the
  attenuation comparison; see below.
- **The identity root.** That a specific human authenticated with a specific identity
  provider at a specific time, and controls the device key the chain descends from.
  `behalf login` sets the OIDC `nonce` to the thumbprint of a freshly generated device key,
  so the IdP's own signature binds that human to that key — anchored in keys we neither
  control nor can forge, which is what makes it checkable by someone who does not trust us.

**The offline verifier now covers four of the six delegation invariants, and says which.**
Of the vendored draft's six, the Rust verifier independently checks **I1** (each hop was
signed by the key its parent confirms), **I2** (depth increments, the budget never widens),
**I3** (a hop never outlives its parent) and **I5** (`par_hash` names one parent token
instance). The conformance corpus covers them: a forged, reparented, over-long or
depth-skipping hop is caught by an implementation that shares no code with the writer, in a
record whose integrity is otherwise perfect.

**Two of the six it does not check, and it prints that on every run — including successful
ones.** **I4** (capability monotonicity) is the draft's nine-type subsumption matrix, and Go
holds the only implementation; a second one that was subtly looser would be worse than none,
because it would stay silent exactly where the first reports a break. **I6** (proof of
possession) is not applicable to v1 at all — behalf records, it does not enforce. So the
offline verifier reports delegation *findings* rather than a hop verdict, and never borrows
the word `verified` for an invariant nobody checked. The same rule the record itself follows.

**The identity root is still not offline-checkable.** The verifier checks that the depth-0
hop is self-signed under the key it confirms and names no parent. It says nothing about
*whose* device key that is: establishing that means checking an OIDC `id_token` against the
IdP's published keys, which needs either a network call or a pinned JWKS in the export.
Neither is built, and the verifier does not imply otherwise.

This rests on a fix landed 28 Aug 2026: until then the hop tokens were not kept at all. Every
receipt named its evidence by digest and nothing ever wrote the blob, so the only surviving
record of a delegation signature was behalf's own capture-time verdict inside a receipt. That
is the self-graded exam this project refuses everywhere else, and it is fixed rather than
explained.

**What it does not prove, and cannot:**

- **That the agent did what the receipt says.** behalf records what the capture surface
  observed. A compromised or prompt-injected agent can emit a receipt describing something
  it did not do. Such content is recorded as `asserted`, and the tooling says so.
- **The agent's own integrity.** Local capture cannot attest the process it runs inside.
  This is a structural limit, not a v1 shortcut.
- **Anything before capture.** Custody begins when the capture surface signs. Suppression
  upstream of that point is out of scope; what the record does show is silence.
- **That a workstation user cannot bypass capture.** They can — by removing the proxy from
  their config. v1 makes capture coverage visible rather than pretending it is enforced.
- **That an export came from who it claims.** Signatures are checked against keys carried in
  the export itself, so a passing verification means *internally consistent*: an export forged
  end to end under someone else's keys verifies identically. Binding a key to a real emitter is
  a published key log's job, and that log does not exist yet. The human root is the exception —
  it is anchored in the identity provider's public keys, which we neither control nor can forge.

Three states, not two: every hop is `verified`, `asserted`, or `broken`. "Asserted" is the
honest middle — it means *recorded, not proven* — and collapsing it into "broken" would be
FUD. It is also where an invariant that could not be *run* lands: a delegation written in a
grant vocabulary behalf has no comparison rules for is `asserted`, never `verified`, because
`verified` claims every check was made.

## Vocabulary: reconstruct, don't re-run

behalf **reconstructs** a run from its receipts. It never re-executes anything. Engineers
reading "replay" reasonably assume the dangerous meaning, so the word is avoided: replaying
the demo scenario would issue real refunds. Reconstruction is reading; nothing is called
twice.

## What works today

Built and covered by tests on every commit:

| Component | State |
|---|---|
| Tessera POSIX log service, durable-commit ack, signed receipt promises, 1 s checkpoints | working (`cmd/behalf-log`) |
| SQLite follower index — rebuildable from the log, keys included, run reconstruction as NDJSON | working (`reindex`, `runs`, `reconstruct`) |
| MCP stdio proxy — the capture surface; intent spooled before forwarding | working (`cmd/behalf-proxy`) |
| `behalf login` / `behalf whoami` — device key, OIDC nonce-thumbprint root, offline three-check verification | working (`cmd/behalf`) |
| Delegation chains — minted as signed hops, verified at capture, three states recorded | working (`internal/aat`) |
| `behalf diff` / `behalf why` / `behalf runs` — causal divergence and the chain, rendered | working (`cmd/behalf`) |
| Payload rehydration and verification — customer-held blobs, typed placeholders, tamper findings | working (`behalf-log rehydrate`) |
| Independent witness — cosigns tree heads, refuses forks and stale restores, fail-open | working (`cmd/behalf-witness`), one machine; a separate cloud account is not provisioned |
| Offline verifier — export files and live tile directories, stable exit codes | working (`verifier/`, Rust) |
| WASM browser verifier — the same crate, file mode, nothing uploaded | working (`make wasm`) |
| `behalf export --html` — one self-contained file per run or run pair, no external requests | working (`cmd/behalf`, `internal/htmlexport`) |
| Claude Code hooks companion — consent, sub-agent delegation, local tool calls, failures | working (`cmd/behalf-hook`), payloads pinned to client 2.1.250 |
| Witness — cosigning, split-view and stale-restore refusal, fail-open | working (`cmd/behalf-witness`) |
| Offline verification of the delegation chain — the property that makes this not a log | working for I1, I2, I3, I5 (`verifier/src/aat.rs`); I4 and the identity root are not checked offline, and the verifier says so on every run |
| Tamper-detection suite in CI — 30 adversarial cases across exports, log storage, payloads and the witness | working (`make tamper-suite`) |
| Published key log — so an export's keys can be attributed to a real emitter | not built |
| `npx onbehalf demo` — unpacks two recorded runs, no network, no key, nothing spent | built, not yet published (`packaging/npm`). macOS and Linux, x64 and arm64. **Not Windows**: the log's storage driver is POSIX-only; WSL works |
| `behalf-log import` — rebuild a log from export files, every leaf byte-for-byte | working (`cmd/behalf-log`) |
| Importers for existing trace data | not started |

## The Claude Code hooks companion

The MCP proxy is the canonical capture surface. The hooks companion is a **second, deliberately
narrower one, scoped to Claude Code and no other client** — because four things happen inside
the client that a proxy sitting on the wire structurally cannot see:

- **The human's consent decision.** `PermissionRequest` and `PermissionDenied` become
  `approval` and `denial` receipts, anchored to the delegation token `jti` plus the intent
  digest. They are marked `asserted`, in the schema and on the record: a click is not
  cryptography. `PermissionRequest` fires when consent is **sought**, not when it is
  granted — the payload carries no decision field at all — so an approval is an inference
  from the absence of a matching denial, and `outcome.consent_evidence` says so on every
  record. A denial is direct.
- **The agent-to-sub-agent delegation edge.** `SubagentStart` / `SubagentStop` become
  `delegation` receipts, joined as a pair.
- **Local tool calls.** `Bash`, `Edit` and `Read` never cross an MCP boundary.
- **Tool calls that fail.** A failed call emits `PostToolUseFailure` and no `PostToolUse`
  at all, so a surface that installs only the latter records every failure as silence.

```sh
go build -o behalf-hook ./cmd/behalf-hook
./behalf-hook install                       # merges into ~/.claude/settings.json
./behalf-hook install --print               # or print the snippet and paste it yourself
./behalf-hook install --uninstall           # removes our entries and nothing else
behalf-log drain --spool ~/.behalf/hook-spool --dir ~/.behalf/log
```

`install` merges: hooks belonging to other tools survive, unknown keys survive, the file stays
valid JSON, and installing twice is installing once.

The payload shapes are pinned to a real client rather than to the documentation: the
goldens in `internal/hooks/testdata/` are captures from Claude Code 2.1.250 (or, for the
two events a headless session cannot produce, reconstructions from the schemas that build
carries), and `testdata/PROVENANCE.md` records which is which, what the previous
hand-written guesses got wrong, and what is still unverified. Publishing that list is the
same habit as the gap list below: the payload shape is Claude Code's and it moves, so the
useful thing to state is how stale this is and how to redo it.

### Two weaknesses, written down rather than papered over

**The person being recorded can delete the hook.** Hook configuration lives in a user-scoped
settings file. Whoever's calls are being captured can remove the entries — the same hole
obot-sentry's own README concedes about this surface. It is out of scope for the v1 integrity
claim, it shows up only as *silence*, and the honest mitigation until managed policy settings
arrive is capture-coverage visibility, not a stronger claim.

**A hook can observe pre-rewrite input.** `updatedInput` on `PreToolUse` is real, and the
rewrite is applied at execution time. So when another input-modifying hook is installed, this
surface can record the input the model proposed rather than the input the tool ran. The proxy
records the request actually forwarded. That is one of the reasons the proxy is canonical, and
why a hook receipt is treated as a *second observation* of a crossing rather than the authority
on it.

### When both surfaces see the same call

An MCP tool called from Claude Code through `behalf-proxy` is observed twice. **Both receipts
are appended** — a silent gap is indistinguishable from tampering, and a hook process cannot
know whether a proxy is running without a blocking cross-process check on the agent's hot path.
The hook receipt flags itself with a typed `attests` link carrying the arguments digest, which
is the one value both surfaces provably commit to, and read surfaces collapse the pair onto the
proxy's record without discarding either. When the two surfaces genuinely saw different bytes,
the join misses and both records stand — which is the correct answer, not a bug.

### Never blocks the agent

`behalf-hook capture` exits 0 on every capture failure and explains itself on stderr. This
inverts the proxy's posture on purpose: the proxy aborts rather than forward an unrecorded
call, but a hook that fails closed does not protect a crossing — it breaks the editor session,
and a recorder that takes the editor down gets uninstalled, which records nothing at all. The
loss is not silent: it is a hole in the per-emitter counter sequence.

## Not in the first release

Publishing the gap list is deliberate — cosign shipped "Intentionally Missing Features" in
its first README, and it is a recurring habit of the tools in this space that worked.

- **No accounts, no hosted service.** Everything runs on your machine; payloads never leave
  it. Nothing in the quickstart requires a signup.
- **No dashboard.** No charts, no p95s, no cost graphs. Those imply a different product and
  invite comparison against tools that have spent a decade on them.
- **No enforcement.** Scope excess is recorded and displayed — "recorded, not enforced" —
  never blocked. Enforcement is guardrails: a different, crowded product. An opt-in
  fail-closed mode exists in the architecture and stays off by default.
- **No evals or scoring.** Braintrust is years ahead there. Export into it.
- **No compliance framing.** Not even a badge. behalf is an engineering tool.
- **No AI-generated summaries.** An LLM narrating a diff would destroy the
  deterministic-and-verifiable property the whole product rests on.
- **No public witness network.** Its production tier is not open. A self-run witness in a
  separate account provides the independent tree head instead, and witnessing is
  **fail-open**: checkpoints publish whether or not a witness answers, with the outcome
  recorded per checkpoint. See [The witness](#the-witness).

## Verify it yourself

The one claim that matters most is the one most easily faked, so it is tested on every
commit — nine adversarial cases against export files, seven against real on-disk log
storage, five against recorded runs and their payloads, and nine against a live witness,
each requiring the shipped tooling to both *detect* and *correctly classify* the mutation:

```bash
make tamper-suite
```

The canonical case is a cover-up, not random corruption: a refund amount edited back down
after the fact. The verifier reports the break at the exact receipt and marks everything
downstream unverifiable.

The sharper version of that case is the one where behalf holds nothing. Payloads are
yours: the receipt carries a digest, a content address and a size, never the arguments
themselves, so a cover-up does not touch a receipt — it edits the arguments in your own
store, which you own outright. behalf still catches it, because those bytes no longer
hash to the digest committed inside a signed, log-committed receipt. The suite asserts
both halves: the payload is reported as no longer matching its commitment, *and* the log,
the checkpoint and every receipt signature still verify perfectly. You hold the bytes, we
hold the commitment, and we can still prove your bytes changed.

This matters because the category has failed here before: a widely deployed immutable database shipped "tamper-evident"
for years with an auditor that did not detect on-disk tampering, and it surfaced only when
a user hex-edited a value file and audit mode stayed silent.

### Or verify it in a browser, with no command line at all

```bash
make wasm      # needs: rustup target add wasm32-unknown-unknown
               #        cargo install wasm-bindgen-cli --version 0.2.127 --locked
open verifier/web/dist/verify.html
```

That is one HTML file. Open it from `file://`, with the network off if you like: the
WebAssembly module and the demo export are inside it, so the page makes no requests at
all — not to behalf, not to anyone. Drop an export on it and it verifies locally, in the
tab, using a `wasm32-unknown-unknown` build of the same `verifier/` crate the CLI is
built from. Same checks, same tamper classes, same exit codes; `verifier/tests/browser_parity.rs`
asserts on every commit that the browser's output and the terminal's are byte-identical.

Buttons on the page break the sample for you — the refund cover-up, a deleted receipt, an
edited chain head — so you can watch it go red without editing a byte yourself. The page
also states plainly what a green tick does *not* mean: signatures are checked against the
keys the export itself carries, so this proves internal consistency, not that the signing
key is the legitimate one. That is the published key log's job, and the key log does not
exist yet. Tile-directory mode needs a filesystem and is deliberately not in the browser
build.

`make wasm` writes to `verifier/web/dist/`, which is gitignored; `verifier/web/index.html`
is the source template, and `verifier/web/build.py` assembles it (stdlib Python, no npm).
The wasm build is not part of `make ci`.

## The witness

Everything above verifies one directory against itself, and two attacks survive that:
a **split view** — serving one history to you and a different one to someone
else, both internally perfect — and a **stale restore** — putting an older checkpoint back
over newer tiles, which verifies clean in isolation *by design* (the suite asserts that,
as `log-restore-undetected-alone`, exit 0).

A witness closes both. It is a separate process, on a separate machine, in a separate
cloud account, holding one thing per log: the highest `(size, root)` it has cosigned,
written to disk before the signature goes out. A new checkpoint is cosigned only if it is
consistent with that head, and refused otherwise with one of three reasons:

| reason | what happened | class |
|---|---|---|
| `smaller-size` | an older tree than the one already witnessed — restore-as-truncation | `truncation` |
| `same-size-different-root` | two histories at the same size — a split view | `chain` |
| `inconsistent-proof` | a larger tree whose consistency proof does not carry the held root forward | `chain` |

The classes are the verifier's own, so a witness finding reads like any other finding.

```bash
behalf-witness init  --key /srv/witness/witness.skey          # prints the vkey to give logs
behalf-witness serve --state /srv/witness/state \
                     --key /srv/witness/witness.skey \
                     --logs /srv/witness/trusted-logs.txt \
                     --addr 0.0.0.0:7777
behalf-witness show  --state /srv/witness/state               # what it currently holds
```

The log side is configuration, not code: `<log dir>/witnesses.json`.

```json
{"fail_open": true, "timeout_ms": 1000, "quorum": 1,
 "witnesses": [{"name": "witness-1", "vkey": "…", "url": "https://witness.example:7777"}]}
```

The log submits each published checkpoint itself, over [C2SP tlog-witness], with a
consistency proof read from its own hash tiles, and writes a record per checkpoint to
`<log dir>/witness/outcomes.jsonl` — cosigned, refused with the reason, or not cosigned
with the reason. Cosignatures land in `<log dir>/checkpoint.witnessed`, which is the
published checkpoint with the witness's signature line appended; verifiers that do not
know the witness key skip that line, so it stays a perfectly ordinary checkpoint.
`behalf-log witness --dir <dir>` runs a submission on demand and exits non-zero on a
refusal, printing `class=… reason=… index=-1` the way the verifier does.

Running one for real — a separate cloud account, TLS in front of it, and the two things
that cannot be recovered if you lose them — is
[`docs/witness-operations.md`](docs/witness-operations.md). The short version, because it
is the part people get backwards: **never back up the witness key, always back up
`witness-state.json`.** They fail in opposite directions.

**The availability mode, stated as an availability mode.** v1 is `fail_open: true`.
Witnessing happens *after* publication, so a witness that is down, slow or refusing cannot
block or delay a checkpoint — publication does not depend on a network whose production
tier does not exist. What that costs, plainly: between publication and cosignature a
checkpoint carries only the log's own signature, and during that window neither defence is
in force for it. What it does not cost is visibility — every checkpoint gets a record, so
"published without a cosignature" is a fact *in* the record rather than an absence from
it. `fail_open: false` is implemented and not the default: it engages the log's blocking
publication path, where no quorum means no checkpoint. The posture tightens to that when a
real witness network exists.

[C2SP tlog-witness]: https://github.com/C2SP/C2SP/blob/main/tlog-witness.md

## Repository layout

```
cmd/behalf          the product CLI: login, whoami, runs, diff, why, export, demo
cmd/behalf-log      log service: init, ingest, import, drain, status, witness, export,
                    reindex, runs, reconstruct, rehydrate
cmd/behalf-witness  the independent witness: init, serve, show
cmd/behalf-proxy    the MCP stdio interposer you put in front of a real MCP server
cmd/behalf-hook     the Claude Code hooks companion: capture, install, uninstall, recover
cmd/behalf-record   the demo session pair, recorded through that same proxy
cmd/behalf-bench    the write-path measurement harness
internal/tlog       Tessera POSIX log, durable ack, receipt promises, epoch fencing,
                    Merkle proofs, witness submission and per-checkpoint records
internal/witness    the witness itself: the safety rule, durable heads, the HTTP surface
internal/index      the rebuildable SQLite follower
internal/proxy      the canonical capture surface: intent spool, CAS writes, signed receipts
internal/hooks      the Claude Code companion surface: consent, sub-agent edges, local tools
internal/capture    receipt-building primitives shared by the capture surfaces
internal/payload    rehydration and verification of customer-held payloads
internal/htmlexport the self-contained HTML export: one file, no network
internal/cas        the content-addressed payload store on your own disk
internal/oidclogin  the OIDC nonce-thumbprint identity root
verifier/           the offline Rust verifier (file mode and tile-directory mode)
verifier/web/       the browser build of that same crate: one self-contained page
packaging/npm/      the `npx onbehalf demo` packages: one root, six per-platform
docs/               architecture, frozen receipt schema, export format, measurements
```

Start with [`docs/architecture.md`](docs/architecture.md) for the decisions and their
reasoning, and [`docs/receipt-schema-v1.md`](docs/receipt-schema-v1.md) for what a receipt
actually contains and why each field had to be frozen before the first record was written.

## Licence

Decided, and the line falls between **checking** the record and **keeping** it:

| Licence | What it covers |
|---|---|
| **Apache-2.0** | `verifier/` (native and WASM), the receipt and token schemas, the `testdata/vectors/` conformance corpus, the CLI, and both capture surfaces — `cmd/behalf-proxy`, `cmd/behalf-hook` |
| **FSL-1.1-ALv2** | two binaries: the local log service and the witness — `cmd/behalf-log`, `cmd/behalf-witness` — converting to Apache-2.0 two years after each release |

The verifier is permanently open because the claim is *don't trust us, run it yourself*, and
that claim is worthless under a licence that lets us withdraw it. So is the conformance corpus:
a second implementation can only be checked against ours if both halves can be read. FSL covers
the durable half — which permits every non-competing use, including the whole self-host path,
and blocks a competitor lifting the storage layer wholesale. It covers the two service binaries
and not the libraries beneath them: the CLI links those to read a log and check a cosigned
checkpoint, so gating them would make the CLI itself mixed-licence. FSL rather than BSL or ELv2 for the
reasons recorded in the decision record: no Additional Use Grant to re-read per deployment, one standard text, and a
two-year conversion rather than three.

[`LICENSING.md`](LICENSING.md) is the operational form: which paths carry which licence, what FSL
permits, and how the published packages declare themselves. Both FSL directories also carry a copy
of the licence and a header in every file, so the answer is visible from whatever you are reading.

## Namespaces held

| Registry | Name | Status |
|---|---|---|
| crates.io | [`behalf-verify`](https://crates.io/crates/behalf-verify) | the offline verifier: `cargo install behalf-verify` |
| crates.io | [`behalf`](https://crates.io/crates/behalf) | reserved, v0.0.0 |
| crates.io | [`onbehalf`](https://crates.io/crates/onbehalf) | reserved, v0.0.0 |
| Go | [`github.com/behalf-sh/behalf`](https://pkg.go.dev/github.com/behalf-sh/behalf) | the module itself: `go install github.com/behalf-sh/behalf/cmd/behalf@latest` (and `cmd/behalf-log`, `cmd/behalf-proxy`, `cmd/behalf-hook`) |
| npm | [`onbehalf`](https://www.npmjs.com/package/onbehalf) | reserved, v0.0.0 |
| npm org | [`@onbehalf`](https://www.npmjs.com/org/onbehalf) | claimed |
| PyPI | [`onbehalf`](https://pypi.org/project/onbehalf/) | reserved, v0.0.0 |
| GitHub | `behalf-sh` | this org |

Not available: npm `behalf` (unrelated cookie/request library, dormant since 2022), npm
scope `@behalf` (dormant user, inactive 8 years), PyPI `behalf` (taken 2026-07-22), GitHub
users `behalf` (2019) and `onbehalf` (2013, dormant).

The first release adds one package per platform under the claimed `@onbehalf` org —
`@onbehalf/cli-darwin-arm64` and its siblings — pulled in by `onbehalf` as
`optionalDependencies` and selected by npm's own `os`/`cpu` fields, so `npx onbehalf demo`
downloads one platform's binaries and runs no install script. Four platforms: macOS and
Linux, each on x64 and arm64. **Windows is not one of them.** The log's storage driver is
Tessera's POSIX driver — `flock(2)`, `O_DIRECTORY` — and does not compile for Windows, so
neither `behalf` nor `behalf-log` does, and the demo needs both. The Rust verifier alone
cross-compiles fine. The `@onbehalf/cli-win32-*` names are reserved and deprecated with that
sentence; WSL runs everything.

That is built and assembles from `packaging/npm/build.sh`; what is left is the publish
itself. Two things it turns on are worth knowing:

- **No `postinstall`, and no fat package.** An install-time download from somewhere else is
  the unauditable step this product exists to eliminate, and it is blocked outright in many
  of the enterprises this demo targets. A package carrying every platform would multiply
  the `npx` download by six, and `npx` is the feature.
- **The download is 452 KB of evidence, not 23 MB of index.** The package ships the two runs
  as export files and rebuilds the log locally with `behalf-log import`. Every receipt keeps
  the emitter signature it was captured with — the re-exported leaves are byte-identical, and
  a test asserts it — while the checkpoint over them is the local log's own, because the
  original log's checkpoint key is not in an export and could not be. Each file is checked by
  the offline verifier *before* its receipts enter the log: the files came from a registry,
  and not having to take anyone's word for what is in them is the whole pitch.

[C2SP tlog-tiles]: https://github.com/C2SP/C2SP/blob/main/tlog-tiles.md
[Tessera]: https://github.com/transparency-dev/tessera
