# onbehalf

**Action receipts for AI agents.** One immutable, tamper-evident record per consequential
thing an agent does, carrying the delegation chain that authorised it — human → agent →
sub-agent → tool.

```sh
npx onbehalf demo
```

That unpacks two recorded runs of the same support-desk agent onto your machine and prints
three commands. No network, no API key, no account, no tokens spent. Nothing is written
until you type `demo`.

```
behalf runs                        two runs of one agent. both ok.
behalf diff run_9f2a run_c71e      which step made them differ
behalf why run_c71e:31             and on whose behalf it was done
```

Both runs succeeded. An error tracker has nothing to show you here. One of them refunded
twelve dollars and the other refunded twelve hundred, and `diff` names the single step that
caused it.

## What the demo actually does

The package carries the two runs as **export files** — the evidence, 452 KB — and rebuilds
a local transparency log from them with `behalf-log import`. Every receipt keeps the
signature the capture surface gave it; the checkpoint over them is your log's own, because
the original log's checkpoint key is not in an export and could not be.

Each file is checked by the offline verifier **before** its receipts enter the log. These
files arrived from a registry, and the point of this tool is that you need not take anyone's
word for what is in them — including ours.

## What is in the box

| Binary | What it is |
|---|---|
| `behalf` | the CLI: `runs`, `diff`, `why`, `export --html`, `login` |
| `behalf-log` | the local log: `import`, `export`, `reindex`, `rehydrate` |
| `behalf-verify` | the **independent offline verifier**, written in Rust |

`behalf-verify` is a separate implementation on purpose. The claim is *don't trust us, run
it yourself*, and a verifier that shared code with the writer would not be a second opinion.
The two are pinned against each other by a conformance corpus on every commit.

## Install shape

No `postinstall` script. The platform binaries are separate packages —
`@onbehalf/cli-darwin-arm64` and its siblings — declared as `optionalDependencies` and
selected by npm's own `os`/`cpu` fields, so you download one platform's binaries rather than
six. An install-time download from somewhere else is exactly the unauditable step this tool
exists to eliminate, and it is blocked outright in many enterprises.

Published over npm trusted publishing (OIDC), with provenance attestations. Shipping a
provenance product without attestation would be a self-inflicted objection.

## Licence

Apache-2.0 throughout this package. The repository's two service binaries are FSL-1.1-ALv2
and are not shipped here, so there is no mixed-licence metadata: see
[LICENSING.md](https://github.com/behalf-sh/behalf/blob/main/LICENSING.md).

Source, threat model and the published gap list: <https://github.com/behalf-sh/behalf>
