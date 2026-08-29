package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// Chain material: what the proxy carries in `params._meta["sh.behalf/chain"]`
// and embeds whole in the receipt's `authority` (Q10, Q15, D4).
//
// The material is AAT carriage per internal/aat: an ordered array of hops,
// each presenting either a compact JWS token or a bare claim set. The proxy
// verifies it at capture (Q18) and records what it checked; it never trusts
// what the material claims about itself.
//
// Two older shapes still load, because material the proxy cannot mint is
// still material it must carry (Q15, Q45): the receipt's `authority` object
// (`{"chain":[hop,…]}`) and a bare hop array. Neither carries signatures, so
// every hop in them verifies as `asserted` with the caller-asserted reason —
// which is the honest reading of a chain nobody signed.
//
// The file is JSON. It is compacted on load because it is spliced into a
// newline-delimited stream and must be one line; compaction removes only
// insignificant whitespace, so no value's bytes change.

// Chain is loaded chain material.
type Chain struct {
	Raw  []byte    // compacted JSON, injected verbatim into _meta
	Hops []aat.Hop // parsed hops, verified at capture and embedded whole (Q10, Q18)
}

// LoadChain reads chain material. An empty path returns nil: absent chain
// means no injection and no authority block.
func LoadChain(pathname string) (*Chain, error) {
	if pathname == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(pathname)
	if err != nil {
		return nil, fmt.Errorf("proxy: read chain material: %w", err)
	}
	return ParseChain(raw)
}

// ParseChain compacts and parses chain material bytes.
func ParseChain(raw []byte) (*Chain, error) {
	var compact bytes.Buffer
	if err := json.Compact(&compact, raw); err != nil {
		return nil, fmt.Errorf("proxy: chain material is not JSON: %w", err)
	}
	c := &Chain{Raw: compact.Bytes()}

	hops, err := aat.ParseChain(c.Raw)
	switch {
	case err == nil:
		c.Hops = hops
		return c, nil
	case !errors.Is(err, aat.ErrNotAATChain):
		// AAT-shaped material that does not parse. It still travels — the
		// carriage route is metadata and verification comes from signatures
		// (Q15) — but there are no hops to embed, so those receipts stay
		// `unattributed` rather than carrying a half-read chain.
		return c, nil
	}

	var authority struct {
		Chain []receipt.Hop `json:"chain"`
	}
	if err := json.Unmarshal(c.Raw, &authority); err == nil && len(authority.Chain) > 0 {
		c.Hops = unsignedHops(authority.Chain)
		return c, nil
	}
	var legacy []receipt.Hop
	if err := json.Unmarshal(c.Raw, &legacy); err == nil && len(legacy) > 0 {
		c.Hops = unsignedHops(legacy)
		return c, nil
	}
	// Material the proxy cannot read as behalf hops still travels; it just
	// cannot be embedded in `authority`.
	return c, nil
}

// unsignedHops converts pre-AAT hop objects into hops with no token behind
// them. Their carried `verification` is deliberately dropped: it was the
// source's claim about itself, and this proxy records what it checked, not
// what it was told (Q29).
func unsignedHops(hops []receipt.Hop) []aat.Hop {
	out := make([]aat.Hop, 0, len(hops))
	for _, h := range hops {
		claims := aat.Claims{
			DelDepth:             h.DelDepth,
			DelMaxDepth:          h.DelMaxDepth,
			ParHash:              h.ParHash,
			Cnf:                  h.Cnf,
			AuthorizationDetails: h.AuthorizationDetails,
			Exp:                  h.Exp,
			JTI:                  h.JTI,
			Credential:           h.Credential,
			RootPrincipalBinding: h.RootPrincipalBinding,
			Trigger:              h.Trigger,
		}
		raw, err := json.Marshal(claims)
		if err != nil {
			continue
		}
		out = append(out, aat.Hop{Claims: claims, Raw: raw})
	}
	return out
}
