# Demo runbook

The operator's script for the live demo (ENG-25, ENG-26). This is the one you run on a
Zoom call, typing by hand. It is not `npx onbehalf demo` (self-serve, separate) and not
the CI dry run.

Everything here is offline and deterministic. No network, no API keys, no accounts. If
the machine's wifi is off the demo still runs — and saying so out loud is worth a beat.
That was measured, not assumed: see "The dry run" below, which also records the one
command that needs a loopback socket and why airplane mode does not affect it.

**The rule that matters:** `behalf demo` never finds a tamper. It performs the edit, and
the shipped tooling — `behalf-verify`, `behalf-log rehydrate` — finds it. A demo command
that both broke the artifact and diagnosed the break would prove nothing.

## Which data every scenario runs on

All four run on the **recorded** pair — `rec_9f2a` and `rec_c71e`, produced by
`cmd/behalf-record`, which drives two 47-step sessions through the real MCP proxy against
an in-repo desk server, spools them, drains them and appends them to a real Tessera log.
Not the hand-built fixtures in `testdata/fixtures` (`run_9f2a`, `run_c71e`).

Two reasons, and both are worth saying out loud if anyone asks where the data came from:

- **Provenance.** Every receipt on screen was signed by the same capture surface, over the
  same bytes, by the same code as a live session. A hand-authored recording proves only
  that someone can author JSON.
- **Custody.** The fixtures carry their payloads inline. The recorded pair puts them in a
  real CAS where a customer's would be, which is the only reason the `tamper` and
  `custody` scenarios can exist at all — there is no "edit your own blob" beat against a
  fixture that has no blobs.

The cost is that the recorded data is *honest about what it cannot show*, and one place
that surfaces is `diff` — see the note in scenario 1.

---

## Pre-call checklist

Run this the day before, and again 20 minutes before the call. It takes about two
minutes.

```bash
# 1. Build and install the whole toolchain into one directory.
go install ./cmd/...
cargo build --release --manifest-path verifier/Cargo.toml
cp verifier/target/release/behalf-verify "$(go env GOPATH)/bin/"

# 2. Confirm all five are on PATH.
which behalf behalf-log behalf-record behalf-verify otel-attribution

# 3. Reset once. The first reset after a build is slower than the rest —
#    macOS verifies freshly signed binaries on first exec — so getting that
#    out of the way now means the call gets the warm one (~5 s).
behalf demo reset

# 4. Export the line reset printed, and run each scenario once, end to end.
export BEHALF_HOME=~/.behalf/demo
behalf demo setup diff     # then type its four commands
behalf demo setup why
behalf demo setup tamper
behalf demo setup custody

# 5. Airplane mode ON. Run `behalf demo setup tamper` and its commands again.
#    Everything must still pass. This is the check worth doing, because
#    "it works offline" is a claim you will make out loud.
```

Then, immediately before the call:

```bash
behalf demo reset
```

and leave the terminal on that output. It is a good opening frame: the log was built 30
seconds ago, in front of nobody, from a recorder that produces the same bytes every time.

### Terminal

The `why` tree and the `diff` output are fixed-width and drawn with box characters. Zoom
downscales shared screens, so under-sized text turns `─` and `▼` into mush.

| Setting | Value | Why |
|---|---|---|
| Columns | **100** | `diff --all` wraps below ~96; `why` needs 84 for the widest hop line. 100 leaves margin without shrinking the font. |
| Rows | 40+ | `behalf demo blob` is 30 lines; `why` is 18. Fewer rows and the top of a payoff scrolls away mid-sentence. |
| Font | **18 pt** minimum, 20 pt better | At 1920×1080 shared into a Zoom tile, 14 pt is unreadable for the person on a laptop. |
| Font family | any of SF Mono, Menlo, JetBrains Mono, Fira Code | All four draw U+2500 `─`, U+25BC `▼`, U+2714 `✔`, U+2716 `✖`, U+2026 `…` at full width. Avoid fonts with partial box-drawing coverage. |
| Theme | dark, high contrast | The colour output marks `verified` green and `UNVERIFIED` red. On a washed-out light theme the one beat that depends on colour disappears. |
| Ligatures | off | `->` and `=>` in output become glyphs a viewer cannot read back to you. |

Check it renders before the call: `behalf why rec_c71e:31` should show an unbroken
vertical `│ ▼ │ ▼` spine with nothing wrapped.

Share the **window**, not the whole screen: a notification landing mid-tamper-demo is the
one interruption you cannot narrate away.

---

## If a command fails live

**One recovery move. Do not debug on the call.**

```bash
behalf demo reset
```

Then re-run the scenario's commands from the top. Reset is idempotent, takes about five
seconds, and removes every tampered artefact along with the log and the payload store.

Say, without apology: *"Let me reset — that's one command, and it re-records both runs
from scratch."* The reset is itself a demo of determinism; it costs you five seconds and
buys back the room.

If reset *also* fails, stop. Say *"I'll follow up with a recording"* and move to the next
part of the call. Do not open an editor. A founder debugging a demo live loses more than a
founder who ran out of demo.

Two failures worth recognising by sight:

| What you see | What it is | Move |
|---|---|---|
| `behalf-verify: command not found` | The Rust verifier is not on PATH | Skip to the `custody` or `why` scenario. Fix after the call (checklist step 1). |
| `holds no demo state (no .behalf-demo marker)` | `BEHALF_HOME` is pointing somewhere else | `behalf demo reset`, then re-export the line it prints. |

---

## Scenario 1 — `diff`

**Setup:** `behalf demo setup diff`
**Duration:** about 2 minutes.
**Pre-empts:** *"we already have tracing"*

The beat that carries this scenario is that the first command shows **nothing wrong**. Do
not rush past it.

### `behalf runs`

```
RUN       STARTED               STATUS  ACTIONS  ACTOR           ATTRIBUTION
rec_9f2a  2026-08-26T09:00:02Z  ok      47       alice@acme.com  verified
rec_c71e  2026-08-26T14:30:02Z  ok      47       alice@acme.com  1 hop unverified
```

> "Two runs of the same support-desk agent. Forty-seven tool calls each. Both `ok` — no
> exception, no error, nothing for an error tracker to catch. One of them refunded twelve
> dollars and the other refunded twelve hundred."

### `behalf diff rec_9f2a rec_c71e`

```
  47 actions in both runs.  21 differ.  1 caused the rest.

  ── first divergence ──────────────────────────── hop 3, t+52s
  step 13   billing-agent → orders.read(...)
     rec_9f2a   target=ord_5512  output.digest=sha256:3aa91e…  +1 more   → ok
     rec_c71e   target=ord_5518  output.digest=sha256:1492e7…  +1 more   → ok

  ── later difference ─────────────────────────────────────────
  step NN   billing-agent → <one later step>
  ── N downstream differences suppressed (--all to show) ──────
```

> "Twenty-one steps differ. One caused the other twenty. At step 13 the desk's search
> index returned the same two refundable orders in a different order, the agent took
> `results[0]` in both runs, and from there everything downstream is a consequence, not a
> cause."

**Do not pin the `later difference` step number.** The first divergence — step 13 — is
stable and is what your narration rests on. The single *later* step the diff features
underneath it is a ranked pick, not a fixed one, and it is expected to change as the
ranking improves. Read whatever it names off the screen.

Worth saying, if the header line or the step number invites the question:

> "On this data the diff can't *prove* the link between step 13 and the later steps,
> because the values it would have to compare are customer-held — it only sees digests. So
> it labels them 'later difference', not 'consequence', and it prints the heuristic it
> used at the bottom. It would be easy to draw a confident arrow there. It would also be
> the one place in this product where we'd be guessing."

### `behalf diff rec_9f2a rec_c71e --all`

Scrolls — roughly 150 lines. That is the point. Let it scroll, then scroll back to the top.

> "Here's everything, suppression off. This is what you'd be reading in a trace viewer:
> twenty-one differences, all of them real, only one of them causal. The default view does
> the reading for you, and it says out loud that it's a heuristic — first difference in
> aligned order, everything after it presumed downstream."

### `behalf why rec_c71e:13`

```
orders.read(target=ord_5518)                    rec_c71e  step 13
  ...
  chain intact for 2 of 3 hops.
```

**Payoff.**

> "And from the step that caused it, one command gets you to who authorised it. Which is
> the next thing you'd want to know."

---

## Scenario 2 — `why`

**Setup:** `behalf demo setup why`
**Duration:** about 3 minutes.
**Pre-empts:** *"isn't this just structured logging"*

### `behalf why rec_c71e:31`

```
refund.issue(amount=1200.00)                    rec_c71e  step 31

  ✔ alice@acme.com                    verified   OIDC/demo  07:55:00Z
       │ delegated: "resolve ticket tk_4437"
       │ scope: tickets.*, orders.*, refund.issue<=100.00
       ▼
  ✔ support-orchestrator @1.4.2       verified   ed25519 ..whCQN8
       ▼
  ✖ billing-agent                     UNVERIFIED
       │ actor "alice@acme.com" is caller-asserted. no signature.
       ▼
    refund.issue  amount=1200.00

  ⚠ scope: refund.issue<=100.00 delegated; 1200.00 issued. (recorded, not enforced)

  chain intact for 2 of 3 hops.
```

Take these one line at a time. Four sentences, in this order:

> 1. "The root is a real human, and it's the one genuinely third-party-checkable fact
>    here: `behalf login` put the thumbprint of a fresh device key into the OIDC nonce, so
>    the identity provider's own signature binds Alice to that key. We didn't sign that.
>    They did."
> 2. "She delegated an intent — resolve ticket 4437 — with a scope that caps refunds at a
>    hundred dollars."
> 3. "Twelve hundred was issued. behalf says so, and says plainly that it *recorded* that
>    and did not *enforce* it. We're not a guardrail product and we don't pretend to be."
> 4. "And the last hop is unsigned. Something called itself Alice. behalf writes down that
>    it was told that, and refuses to call it verified."

### `behalf why rec_9f2a:31`

```
  ✔ billing-agent                     verified   ed25519 ..652H7M
  chain intact for 3 of 3 hops.
```

> "Same command, other run. Three of three. That difference is cryptographic, not a typed
> field — the proxy verified both chains at capture and recorded what it found."

### `otel-attribution`

A small OpenTelemetry-instrumented program in this repo. It is not behalf: it imports no
behalf package, and it builds and exports a real span tree with the upstream
OpenTelemetry Go SDK.

```
$OTEL_RESOURCE_ATTRIBUTES = (unset)

resource attributes — every span in this process carries all of these:

  service.name            support-desk-agent
  telemetry.sdk.language  go
  ...
```

> "Here's the same action instrumented the ordinary way. Real OpenTelemetry SDK, real
> spans, real exporter."

### `OTEL_RESOURCE_ATTRIBUTES=user.email=ceo@corp.com otel-attribution`

```
  user.email              ceo@corp.com      ← from $OTEL_RESOURCE_ATTRIBUTES
  ...
What it does not establish: that any of the values marked ← is true. They came
from a process environment variable. Nothing signed them, nothing checked them,
and the key is arbitrary — the mechanism does not validate it. This is
documented, intended OpenTelemetry behaviour: resource attributes are
configuration, not authentication.
```

> "One environment variable, and every span in that tree is now attributed to the CEO.
> That is not a bug and I'm not picking on anyone — `OTEL_RESOURCE_ATTRIBUTES` is a
> documented configuration mechanism doing exactly what it's specified to do. Resource
> attributes are configuration. They were never authentication, and nothing downstream can
> tell the difference, because there is no difference to tell."

### `behalf why rec_c71e:31`

**Payoff.** Back to the receipt, with the OTel output still fresh.

> "behalf saw the same self-asserted string — `alice@acme.com`, from the caller — and put
> it here, marked UNVERIFIED, next to the two hops where it can show you the key
> thumbprint that actually signed. Same input. It just refuses to promote it."

---

## Scenario 3 — `tamper`

**Setup:** `behalf demo setup tamper`
**Duration:** about 3 minutes.
**Pre-empts:** *"how do I know your tamper-evidence works"*

Needs `behalf-verify` on PATH.

### `behalf-verify log $BEHALF_HOME/log --emitter-keys $BEHALF_HOME/emitter.jwks.json`

```
✔ 94/94 entries intact   checkpoint root accd…e16d
```

> "Baseline. Ninety-four entries, the Merkle tree, the signed checkpoint, and every
> receipt signature against the emitter's public key. That's the Rust verifier, offline —
> it doesn't call us and it doesn't call your identity provider."

### `behalf demo tamper payload`

```
edited the customer's own payload store — not behalf's record.

  file    ~/.behalf/demo/blobs/b29224815eff…
  step    rec_c71e:31  refund.issue  target=ord_5518  (log index 78)
  edit    "amount":"1200.00"  →  "amount":"12.00"
  now     sha256:c86e1ca2dbad…
  named   sha256:b29224815eff…   ← the filename it still has
```

> "Now the cover-up, done where a real one would happen. Receipts don't contain tool
> arguments — payloads are yours, we hold a digest — so an attacker doesn't forge a
> receipt they can't sign. They edit the arguments in their own store, which they own
> outright."

### `behalf-log rehydrate --run rec_c71e >/dev/null`

```
class=payload index=78 run=rec_c71e step=31 receipt=01M0Z7… role=input
  committed=sha256:b29224815eff… actual=sha256:c86e1ca2dbad… fields=$.arguments
  operation=refund.issue target=ord_5518
```

> "Caught, at the exact receipt, naming the operation and the field that moved. Those
> bytes no longer hash to the digest committed inside a signed, log-committed receipt.
> You hold the bytes, we hold the commitment, and we can still prove your bytes changed."

### `behalf-verify log $BEHALF_HOME/log --emitter-keys $BEHALF_HOME/emitter.jwks.json`

```
✔ 94/94 entries intact   checkpoint root accd…e16d
```

**This is the beat people miss. Pause on it.**

> "And the log is still perfect. Nothing in the transparency log noticed, because nothing
> in the transparency log changed. Two different findings, and the tooling tells you which
> one you're looking at — `class=payload` is not `class=content`. A product that collapsed
> those into one red banner would be lying to you about where the damage is."

### `behalf-log export --run rec_c71e --out $BEHALF_HOME/refund.jsonl`
### `behalf-verify $BEHALF_HOME/refund.jsonl`

```
✔ 47/47 receipts intact   chain head 490b…762b
```

> "Second cover-up, this time against our own record. Here's an export of the run — one
> file, forty-seven receipts."

### `behalf demo tamper export $BEHALF_HOME/refund.jsonl`

```
edited a receipt inside the export — behalf's own record this time.
  leaf    31  refund.issue  (run rec_c71e)
  edit    "amount_cents":120000  →  "amount_cents":12000
```

### `behalf-verify $BEHALF_HOME/refund.jsonl`

```
✖ TAMPERED
receipt 31: content hash mismatch (expected 815c… computed e7e8…)
chain breaks at 31; receipts 32-46 unverifiable.
class=content index=31
```

**Payoff.**

> "Named the receipt, and marked everything after it unverifiable rather than quietly
> re-verifying a re-chained tail. And every adversarial case like this one runs on every
> commit — `make tamper-suite`, across exports, on-disk log storage and payloads. We test
> it that hard because the category has failed here before: a widely deployed immutable database shipped 'tamper-evident'
> for years with an auditor that did not detect on-disk tampering, and it surfaced when a
> user hex-edited a value file and audit mode stayed silent. The claim is easy to make and
> easy to get wrong."

Don't quote a case count from memory — the suite grows. If you want the number on the
call, run `make tamper-suite` in the pre-call checklist and read the tail off it.

---

## Scenario 4 — `custody`

**Setup:** `behalf demo setup custody`
**Duration:** about 3 minutes.
**Pre-empts:** *"why would I ship my agent's actions to a solo founder's cloud"*

Needs `behalf-verify` on PATH.

### `behalf demo blob`

```
rec_c71e:31  refund.issue  target=ord_5518  → ok        log index 78

what behalf's signed record holds about the payloads — all of it:

  input    digest        sha256:b29224815eff…
           content type  application/json
           size          3559 bytes
           custody       customer-held
  ...
where the bytes are — your disk, resolved just now:

  input    ~/.behalf/demo/blobs/b29224815eff…
           present, 3559 bytes, hashes to its commitment
```

> "Top half is the whole payload side of the receipt: a digest, a size, a content type.
> No arguments, no results, no customer content — there is nothing else in there to send
> anywhere. Bottom half is your disk."

### `rm $(behalf demo blob --path)`

> "So let's delete it. Retention sweep, GDPR erasure, or a laptop that got wiped — this
> happens, and it isn't an incident."

### `behalf demo blob`

```
  input    ~/.behalf/demo/blobs/b29224815eff…
           [missing: sha256:b29224815eff… (customer-held)]
```

> "Top half unchanged — behalf never had those bytes, so losing them changes nothing about
> what we hold. Bottom half is a typed placeholder that names the state and the commitment.
> Absence is a state, not a gap in the record."

### `behalf export --run rec_c71e --html $BEHALF_HOME/refund.html`

```
wrote …/refund.html (732880 bytes) — rec_c71e, self-contained, no external requests
```

### `open $BEHALF_HOME/refund.html`

(Linux: `xdg-open`. Or drag the file onto a browser window.)

Point at the header — **Payloads: 93 present, 1 missing** — and then at step 31, where the
input slot renders `[missing: sha256:b29224815eff… (customer-held)]` beside a present
output.

> "One file. It loads nothing — no CDN, no font, no script from anywhere — so it opens
> from `file://` on a machine with no network and prints to PDF cleanly. This is what
> actually gets attached to a ticket. And it's still evidence with the payload gone,
> because the receipt carries the digest regardless."

### `behalf-log export --run rec_c71e --out $BEHALF_HOME/refund.jsonl`
### `behalf-verify $BEHALF_HOME/refund.jsonl`

```
✔ 47/47 receipts intact   chain head 490b…762b
```

**Payoff.**

> "Now hand that file to a third party. They verify it with a binary that talks to nobody
> — not to us, not to your IdP — or in a browser with `make wasm`, which is one HTML file
> with the WebAssembly build of that same crate inside it. Nothing uploads. Everything you
> just saw ran on this laptop."

If they ask what a green tick does *not* mean, answer it straight — the honesty is the
product:

> "Signatures are checked against keys the export itself carries, so this proves internal
> consistency: an export forged end to end under someone else's keys verifies identically.
> Binding a key to a real emitter is a published key log's job and that log doesn't exist
> yet. The human root is the exception, because it's anchored in the identity provider's
> keys, which we neither control nor can forge."

---

## The dry run — what was actually measured

Performed 28 Aug 2026 (ENG-21) on macOS 15 / arm64, against the toolchain built from
`main`. This section records **numbers that were measured**, not numbers anyone expected;
where an expectation was wrong it is corrected here and the code is fixed.

### Timing

| Step | Measured |
|---|---|
| `go build ./cmd/...` + `cargo build --release` | ~1 s Go (warm), Rust cached |
| `behalf demo reset` — cold, first exec after a build | **5.3 s** |
| `behalf demo reset` — warm | **4.6 s** |
| `behalf runs` | 19 ms |
| `behalf diff rec_9f2a rec_c71e` | 22 ms |
| `behalf why rec_c71e:31` | 16 ms |
| `behalf export --run … --run … --html` | 58 ms, 1.46 MB |
| the whole `tamper` scenario, typed | under a minute of machine time |

Nothing in the script is slow enough to need narration except the reset, which already
prints what it is doing.

### Determinism across takes

Two full resets, then a byte-for-byte compare of `runs`, `diff`, `why`, `behalf-verify log`
and a `behalf-log export` of `rec_c71e`. **All five identical.** The numbers on screen do
not move between takes, which is the property that lets you run a scenario twice on a call
without the second run inviting the scepticism the first disarmed.

### Airplane mode, and the sharper version of it

Run under a sandbox denying **all outbound traffic except loopback** — the faithful model
of airplane mode, since airplane mode disables the radios and leaves `lo0` alone — the
entire script passes, `behalf demo reset` included. The claim is safe to make out loud.

Run under a sandbox denying **all** network, loopback included, the results split:

| | |
|---|---|
| `runs`, `diff`, `why`, `demo blob`, `export --html`, `behalf-log export`, `behalf-verify` (file **and** log mode) | all pass, exit 0 |
| `behalf demo reset` | **fails** |

The recorder mints the demo's identity root through a real OIDC code flow against an
in-process provider, which listens on `127.0.0.1`. That is a genuine loopback socket, and
`httptest` **panics** rather than erroring when the bind is refused — so the operator's one
recovery move produced a twenty-line Go stack trace.

Airplane mode does not trigger it. A restrictive local policy does: an endpoint agent, a
locked-down corporate image, a sandbox denying `network*`. Which is to say, exactly the
laptop a security-conscious customer hands you, and exactly the machine on which someone
tests a claim that the tool makes no network calls.

Fixed here: `behalf-record` now checks the bind up front and fails with a sentence naming
the cause, what still works without it, and the fact that nothing leaves the machine. The
stack trace is gone. **The underlying constraint remains and is worth knowing:** rebuilding
the recording needs a loopback socket; reading and verifying an existing one needs nothing
at all.

### Layout at the documented width

Every command in the script, measured in display columns at the 100 this document
specifies:

| Command | Widest line |
|---|---|
| `behalf runs` | 81 |
| `behalf diff` | 77 |
| `behalf diff --all` | 82 |
| `behalf why rec_c71e:31` | 83 |
| `behalf demo reset` | 96 |
| `behalf demo list` | 98 |
| `behalf demo blob` | 96 |
| `behalf demo setup <any>` | 85–87 |
| `behalf-verify log` | 50 |

Four of those did not fit before this pass and were fixed rather than documented around:
`behalf demo list` ran to **174** columns, `behalf demo setup` to **163**, its `prepared`
line to **108**, and `behalf demo blob` to **115** — the last one on screen during the
custody scenario. The `proves` and `prepared` sentences now wrap at 76; the blob view
prints its store directory once and the file name under it, losing nothing (`--path` still
prints the whole path on one line).

Nothing reflows with the terminal: `runs`, `diff` and `why` are byte-identical at 80
columns and at 100. They are fixed-width by design, so a narrower terminal wraps rather
than degrades — which is why the 100-column setting above is a requirement and not a
preference.

### The rehearsed fallback, written down

**If a command fails live, the move is `behalf demo reset`, then re-run the scenario from
the top.** Do not debug. That is above, in "If a command fails live", and the dry run
confirms it costs about five seconds.

**If reset itself fails**, the fallback is the HTML export, and it must already be on disk
before the call:

```bash
behalf export --run rec_9f2a --run rec_c71e --html ~/demo-fallback.html
```

One self-contained file, 1.46 MB, no external requests — checked: zero `src=`/`href=`
attributes pointing anywhere off the page. Open it and keep talking. It carries the diff,
the chain and the payload findings, so every beat except the live tamper survives. Have the
tab open before the call so recovering is a click and not a file dialog.

## Reference

| | |
|---|---|
| Scenarios and what each proves | `behalf demo list` |
| Rebuild clean state | `behalf demo reset` (~5 s) |
| Where the demo lives | `$BEHALF_DEMO_HOME`, else `demo/` under `$BEHALF_HOME` / `~/.behalf` |
| What reset removes | the whole demo root — log, index, payload store, exports, tampered artefacts |
| Safety guard | reset refuses any directory without the `.behalf-demo` marker it writes |
| The recording | `cmd/behalf-record`: two 47-step runs through the real MCP proxy, deterministic |
| The adversarial suite | `make tamper-suite` |
