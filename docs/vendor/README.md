# Vendored normative references

Third-party specification text, copied verbatim so that behalf's claims about what it
implements can be checked against something this repository actually holds.

Nothing here is behalf's work. Nothing here may be edited. If a newer version of a document
is adopted, add it as a new file next to the old one and update the profile that cites it —
never in place, because the whole point of a vendored copy is that it does not move under a
claim that was checked against it.

---

## `draft-niyikiza-oauth-attenuating-agent-tokens-01.txt`

The normative reference for behalf's delegation token. Verbatim IETF plain-text
rendering, including the boilerplate, the Status of This Memo, the IETF Trust copyright
notice, and the author's address.

| | |
|---|---|
| Title | Attenuating Authorization Tokens for Agentic Delegation Chains |
| Author | N. A. Niyikiza (Tenuo) |
| Version | `-01` |
| Retrieved from | `https://www.ietf.org/archive/id/draft-niyikiza-oauth-attenuating-agent-tokens-01.txt` |
| Retrieved on | 27 August 2026 |
| Datatracker entry | `https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/` |
| Published | 15 June 2026 |
| Expires | 17 December 2026 |
| Intended status | Standards Track |
| Actual status | Active Internet-Draft, **individual submission** |
| Working group | **None.** Not adopted by the OAuth WG or any other. |
| Size | 164,466 bytes, SHA-256 in `SHA256SUMS` |

### Why it is vendored

Because it is going to disappear, and because nobody owns it.

An Internet-Draft is not a stable reference — the IETF's own boilerplate says it is
"inappropriate to use Internet-Drafts as reference material". This one expires **17 December
2026**, at which point it stops being a current draft. No working group has adopted it, so
there is no chartered body obliged to carry it to a successor: it was announced on the OAuth
WG list on 15 June 2026, drew one substantive review, missed the IETF 126 OAuth agenda, and
has had no adoption call.

behalf nevertheless implements it, and `docs/aat-profile-v1.md` claims conformance to it hop
by hop. A conformance claim against a document that expires and is not held in the repository
is a claim that cannot be checked. That was the open gap `aat-profile-v1.md` §8 recorded
honestly until this copy landed; the copy is what closes it.

If a successor draft moves the format, divergence is absorbed through `schema_version`
— this file stays exactly as it is, as the reference the shipped v1 was built against.

### Copyright

Copyright (c) 2026 IETF Trust and the persons identified as the document authors. All rights
reserved. Subject to BCP 78 and the IETF Trust's Legal Provisions Relating to IETF Documents
(https://trustee.ietf.org/license-info). Code components extracted from the document are
subject to the Revised BSD License. The full notice is retained in the vendored file itself.
