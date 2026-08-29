# Which licence covers what

behalf is licensed under **two** licences. The line falls between *checking* the
record and *keeping* it: everything that lets you verify behalf's claims is
permissively licensed and always will be, and the durable log service is not.

The reasoning is recorded in the project's decision record. This file is the
operational form of that decision —
what to look at when you need to know which licence applies to a file.

## The map

| Path | Licence |
|---|---|
| `cmd/behalf-log/**` | **FSL-1.1-ALv2** ([LICENSE-FSL](LICENSE-FSL)) |
| `cmd/behalf-witness/**` | **FSL-1.1-ALv2** ([LICENSE-FSL](LICENSE-FSL)) |
| **everything else** | **Apache-2.0** ([LICENSE](LICENSE)) |

That is the whole rule: **two directories are FSL, the rest of the repository is
Apache-2.0.** Both FSL directories also carry a copy of the licence, and every
Go file in them carries a header saying so, so the answer is visible from the
file you happen to be reading.

Explicitly Apache-2.0, because they are the parts that make the claims
checkable or that a customer runs on their own machines:

- `verifier/` — the offline verifier, native and WASM. behalf's central claim is
  *don't trust us, run the verifier*, which is worthless under a licence that
  lets us withdraw it.
- `testdata/vectors/` — the cross-implementation conformance corpus. A second
  implementation can only be checked against ours if both halves can be read.
- `docs/receipt-schema-v1.md`, `docs/receipt-schema-v1.schema.json`,
  `docs/aat-profile-v1.md` — the receipt and token formats. Never a proprietary
  wire format.
- `cmd/behalf`, `cmd/behalf-proxy`, `cmd/behalf-hook` — the CLI and the capture
  surfaces. A security team must be able to read what it deploys on its
  engineers' machines.
- **all of `internal/`** — including `internal/aat` (the delegation chain) and
  `internal/why` (the attribution comparator). The capture surfaces link them,
  because building and checking the chain is the collector's job, and the
  collector is Apache. Licensing them otherwise would make those binaries
  mixed-licence for no gain.

## What FSL means for you

FSL permits **every non-competing use**, including running the log service and
the witness in production, self-hosted, for as long as you like, at no cost. The
one thing it does not permit is using them to offer a competing product or
service.

It is **not** an OSI-approved open source licence during that term, and it is
not described as one here or anywhere else in this repository.

Each version converts to **Apache-2.0 two years after that version is made
available**. This is a formula, not a date anyone maintains: there is no Change
Date to fill in, look up or get wrong — which is why FSL was chosen over BSL.

## Third-party code

`verifier/vendor/azul` is vendored at a pinned revision from Cloudflare, under
the 3-clause BSD licence. Its notice is retained at
`verifier/vendor/azul/LICENSE` and reproduced in [NOTICE](NOTICE), as that
licence requires.

## Copyright holder

Copyright is currently held by George Chigrichenko as an individual, since no
entity exists yet. If one is formed, copyright is assigned to it and subsequent
releases carry the entity's name; versions already published stay licensed on
the terms under which they were published. The assignment itself is paperwork
for incorporation, not a code change.

## Published packages

The `npx onbehalf demo` package ships the CLI and the native verifier and **no
FSL-covered binary**, so it is Apache-2.0 throughout and declares
`"license": "Apache-2.0"`. If a published package ever includes `behalf-log` or
`behalf-witness`, that package's metadata must change to
`"SEE LICENSE IN LICENSING.md"` — `FSL-1.1-ALv2` is not on the SPDX list, so no
identifier expresses it.
