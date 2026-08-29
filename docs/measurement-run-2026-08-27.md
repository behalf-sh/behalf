# Demo-hardware measurement run — 27 Aug 2026

The confirmation run the architecture's open item #1 called for (architecture.md, "What
remains open"; Linear ENG-10). Tool: `cmd/behalf-bench` (in-repo, rerunnable); target: the
real `internal/tlog.Append` path — Tessera v1.0.4 POSIX, default options (1 s checkpoint
interval, 250 ms batch max age, batch size 256), ~2.6 KB receipt-shaped payloads,
pre-signed envelopes so signing cost never pollutes append latency.

**Machine:** MacBook Pro 18,2 (Apple M1 Max, 10 CPU, 64 GB), APFS. macOS numbers are
interface measurements — `O_SYNC` issues no drive-cache barrier for file data on macOS —
so they bound behaviour, not durability; Linux carries full integrity semantics.

## Results

| phase | concurrency | appends/s | p50 | p90 | p99 | max |
|---|---|---|---|---|---|---|
| sequential | 1 | 3.6 | 279 ms | 284 ms | 297 ms | 351 ms |
| burst | 4 | 14.1 | 283 ms | 290 ms | 298 ms | 305 ms |
| burst | 16 | 55.5 | 287 ms | 302 ms | 325 ms | 336 ms |
| burst | 64 | 201.9 | 315 ms | 349 ms | 371 ms | 389 ms |
| ack → checkpoint cover | 1 | — | 1288 ms | 1298 ms | 1302 ms | 1305 ms |

6,000 appends total, tree fully integrated, no errors, no duplicate anomalies.

## What the numbers decide

1. **The `Add`-latency threshold is set: 1000 ms sustained over a 30 s window.** The
   worst measured p99 under 64-way load is 371 ms and the structural floor is the 250 ms
   batch age, so 1 s is ~2.7× worst-case normal and cannot false-positive on load alone.
   Past it, observe mode (default) spools durably and continues; shedding follows the
   signed `loss_marker` policy.
2. **The 10 s MMD holds, with ~7.7× headroom.** Worst ack→checkpoint-cover is 1.30 s
   (checkpoint interval + batch age, as designed). The headroom is the budget for witness
   cosigning timeouts when the witness lands; revisit only if witness p99 exceeds
   ~8 s.
3. **A refinement the architecture should carry:** end-to-end ack latency is dominated by
   `BatchMaxAge`, not fsync. The earlier microbenchmarks (0.066 ms WAL commit, 5.06 ms
   `F_FULLFSYNC`) measured the storage floor; the ack a caller actually observes is
   ~280 ms p50 = batch close (250 ms) + integration (~30 ms). Consequences:
   - **Observe mode** (default) is unaffected — the proxy spools durably and never blocks
     on `Add`.
   - **Enforcement mode** ("no receipt, no execution") adds ~280 ms p50 to each gated
     call at default settings. That is visible, not noise. It is tunable: `BatchMaxAge`
     trades ack latency against batching efficiency, and at receipt volumes (1–3 % of
     trace volume) a lower batch age is affordable. Decision deferred until
     enforcement mode ships; the knob and the numbers are now on record.
4. **Throughput ceiling at defaults on this machine: ~200 appends/s** at 64-way
   concurrency — two orders of magnitude above expected demo volumes.

## Deployment gates (restated, now with a run behind them)

- Production runs on **Linux** (macOS `O_SYNC` caveat above).
- Log storage on **ext4/ZFS/CephFS**; Tessera's POSIX driver is untested on NFS and s3fs — do not deploy onto either.
- One appender per log dir; the epoch fence and Tessera's lock file both enforce it.

Rerun: `go run ./cmd/behalf-bench -json out.json` (flags: `-n`, `-pad`, `-mmd-samples`).
A Linux confirmation run on real production hardware remains worth doing before any
hosted deployment; nothing in these numbers blocks the demo.
