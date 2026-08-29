# behalf — the product

Org-wide context (positioning, language rules, the research boundary) is in
`../ops/ORG-CONTEXT.md` and loads automatically.

Go writer and tooling, plus a Rust offline verifier in `verifier/` that anyone can build
and run against exported bytes with no call to behalf and no call to an IdP. The two
implementations are pinned against each other by a conformance corpus in CI.

```sh
make build
make test
make ci            # build test lint conformance tamper-suite — run before opening a PR
make conformance   # Go writer vs Rust verifier against the vectors
make tamper-suite  # fixtures + detection checks
```

Work through PRs off `main`, not direct commits.

## Discipline that matters here

The README's "what behalf claims — and what it does not" section is load-bearing and
comes first on purpose. Anyone security-literate finds the limits in ten seconds, so they
are stated up front. Keep that separation exact when changing anything user-facing:

- **What the offline verifier proves** — record integrity: nothing modified, dropped,
  reordered or back-dated after it was written.
- **What behalf's own tooling establishes** — recomputed from the stored record at read
  time by `internal/aat`, shown by `behalf why`.

An uncomparable grant is **asserted, not verified**, and must be reported that way. Never
let a claim drift from one column to the other in docs, output strings or copy.

The site is a separate repo (`../www`) — this one carries no website.
