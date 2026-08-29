# Running a witness

The operator procedure for `cmd/behalf-witness`: what to provision, what to do when
something breaks, and the two things that cannot be recovered if you lose them.

The software half of ENG-11 is done and tested. This is the other half, and it is the half
that decides whether the witness proves anything: **a witness inside the same blast radius
as the log proves the mechanism, not the independence**, and independence is the entire
point against the operator adversary. A witness running on the log's own machine is a
demo of the code. A witness in a separate cloud account, under a separate credential, is
the thing a customer's counsel would accept.

## What a witness is for

Everything else in behalf verifies one directory against itself, and two attacks survive
that:

- a **split view** — serving one history to you and a different one to someone else, both
  internally perfect;
- a **stale restore** — putting an older checkpoint back over newer tiles, which verifies
  clean in isolation *by design* (the tamper suite asserts exactly that, as
  `log-restore-undetected-alone`, exit 0).

A witness closes both by holding one thing per log: the highest `(size, root)` it has
cosigned, written to disk before the signature goes out. That single durable fact is the
whole defence, which is why the backup policy below matters more than it looks.

## Provisioning

**A separate cloud account, not a separate VM in the same one.** The adversary this defends
against is whoever can write to the log's storage — which, in most deployments, is whoever
holds the account credentials. A witness reachable with the same credential defends against
nothing that matters. Separate account, separate credential, separate billing contact if you
can manage it.

The machine is small: the witness holds one JSON file per log and verifies consistency
proofs. Anything that can run a static Go binary will do.

```sh
# once, on the witness host
behalf-witness init --key /srv/witness/witness.skey --name witness-1
# prints the vkey. That string is what each log needs; it is public.

# the logs this witness will cosign for, one checkpoint vkey per line
printf '%s\n' "$LOG_VKEY" > /srv/witness/trusted-logs.txt

behalf-witness serve \
  --state /srv/witness/state \
  --key   /srv/witness/witness.skey \
  --logs  /srv/witness/trusted-logs.txt \
  --addr  127.0.0.1:7777
```

On the log side it is configuration, not code — `<log dir>/witnesses.json`:

```json
{"fail_open": true, "timeout_ms": 1000, "quorum": 1,
 "witnesses": [{"name": "witness-1", "vkey": "…", "url": "https://witness.example:7777"}]}
```

`behalf-log witness --dir <dir>` runs a submission on demand and exits non-zero on a
refusal, which makes it a usable readiness check.

## TLS and reachability

`serve` speaks **plain HTTP and defaults to `127.0.0.1`**. That default is right for a
process nobody has exposed yet and wrong for the deployment this document describes, so
exposing it is a deliberate act with three parts:

1. **Terminate TLS in front of it.** A reverse proxy — Caddy, nginx, a cloud load balancer —
   holding the certificate, forwarding to `127.0.0.1:7777`. Do not bind the witness itself
   to a public address.
2. **A stable hostname.** The log stores the witness URL in `witnesses.json`, and a witness
   that moves is a witness that stops being consulted — silently, because the posture is
   fail-open. Use a name you control, not an IP.
3. **Firewall to the log's egress address.** The witness surface is small and speaks
   [C2SP tlog-witness], but it is still an endpoint that signs things, and there is no
   reason for it to be reachable from anywhere except the log that submits to it.

What TLS buys here is narrower than usual and worth being precise about: the cosignature is
an Ed25519 signature the log verifies against a vkey it already holds, so an attacker on the
wire cannot forge a cosignature by intercepting the connection. TLS protects availability and
prevents an interceptor from *suppressing* submissions less visibly. It is not what makes the
cosignature trustworthy.

## Key custody

**`witness.skey` is 0600 and is deliberately excluded from backups.** That is a decision, not
an omission, and it has a consequence you must be ready for.

Losing the host means losing the key. There is no recovery: you re-key and re-register with
every log that trusts this witness.

```sh
behalf-witness init --key /srv/witness/witness.skey --name witness-1   # new key
# then, for every log: put the new vkey into <log dir>/witnesses.json
```

Until each log's `witnesses.json` is updated, that log's checkpoints publish **without a
cosignature** — recorded per checkpoint, and not blocked, because the posture is fail-open.
So a key loss degrades the defence visibly rather than breaking publication. Treat the
re-registration as urgent, not as an emergency.

Why not back the key up: a witness key in a backup is a witness key in a second place, and
the second place is usually the log operator's own storage — which is the blast radius this
whole arrangement exists to leave. A witness whose key the log operator can obtain is a
witness the log operator can impersonate, and a cosignature you can mint yourself is not a
second opinion.

This belongs with the key-rotation procedure when that is written; the two are the same
question asked about different keys.

## Backing up `witness-state.json`

**This is the one file that makes a witness a witness**, and it is the sharpest operational
hazard here.

It holds the highest `(size, root)` the witness has cosigned per log. It survives a restart
— it is written before each signature goes out, and read back on start — but it does **not**
survive disk loss, and unlike the log's index it is **not rebuildable from anything**. The
log cannot supply it: the log is the party the witness exists to check, so accepting a head
from the log would defeat the mechanism entirely.

What losing it costs, precisely: a witness that comes back with empty state will cosign
whatever it is next shown, including a checkpoint smaller than one it had already
witnessed. That is exactly the stale restore it was deployed to refuse. The failure is
**silent** — the cosignature looks normal — which is what makes it worse than a witness
that is simply down.

So:

- **Back up `<state>/witness-state.json`.** Frequently. It is a few hundred bytes.
- Back it up somewhere the log operator cannot write. A backup an attacker can roll back is
  a rollback attack with extra steps.
- **After any restore, check what came back before serving.** `behalf-witness show --state
  <dir>` prints what it currently holds; `--json` for scripting. A restored state file that
  is *older* than what the witness had actually cosigned is worse than empty state, because
  it will refuse legitimate growth and look like a fork.

The asymmetry with the key is deliberate and worth holding in mind: **never back up the key,
always back up the state.** They fail in opposite directions — a leaked key lets someone
else speak as the witness, and a lost state file lets the witness be lied to.

## When a submission is refused

`behalf-log witness` exits non-zero and prints `class=… reason=… index=-1`, the same shape
`behalf-verify` emits. Three reasons, and they are not equally alarming:

| reason | what happened | class | what to do |
|---|---|---|---|
| `smaller-size` | an older tree than the one already witnessed — restore-as-truncation | `truncation` | **Investigate before doing anything else.** Either the log's storage was rolled back, or its state was restored from a backup. Both are worth knowing about. |
| `same-size-different-root` | two histories at the same size — a split view | `chain` | **Investigate.** This is the attack the witness exists to catch. |
| `inconsistent-proof` | a larger tree whose consistency proof does not carry the held root forward | `chain` | Same. |

None of these is fixed by restarting the witness, and restarting it with cleared state
"to make the error go away" destroys the evidence and disables the defence. If the log is
genuinely a new log, register it as one rather than clearing the witness's memory of the
old.

## The availability posture, stated as one

v1 is `fail_open: true`, and witnessing happens **after** publication — so a witness that is
down, slow or refusing cannot block or delay a checkpoint. Publication does not depend on a
network whose production tier does not exist.

What that costs, plainly: between publication and cosignature a checkpoint carries only the
log's own signature, and during that window neither defence is in force for it.

What it does not cost is visibility. Every checkpoint gets a record in
`<log dir>/witness/outcomes.jsonl` — cosigned, refused with the reason, or not cosigned with
the reason — so "published without a cosignature" is a fact *in* the record rather than an
absence from it. Monitor that file: a witness that quietly stopped answering looks exactly
like a witness that is fine, if nobody is reading the outcomes.

`fail_open: false` is implemented and is not the default. It engages the log's blocking
publication path, where no quorum means no checkpoint. The posture tightens to that when a
real witness network exists; the C2SP tlog-witness client means a network witness drops into
`witnesses.json` with no code change.

[C2SP tlog-witness]: https://github.com/C2SP/C2SP/blob/main/tlog-witness.md
