package main

import (
	"crypto/ed25519"
	"testing"

	"github.com/behalf-sh/behalf/internal/aat"
)

// The conformance corpus exists so two implementations stay honest about the
// same bytes. The Rust half is pinned by verifier/tests/conformance.rs, which
// reads these vectors and asserts the findings. This is the other direction:
// the Go verifier must call the very same forged chains broken.
//
// Without this, a vector could encode a break only Rust believes in — and a
// corpus where the two implementations disagree about what is broken is worse
// than no corpus, because it launders a divergence as agreement.

func TestGoAndRustAgreeTheForgedChainsAreBroken(t *testing.T) {
	sound, err := soundChain()
	if err != nil {
		t.Fatal(err)
	}
	root, child := sound[0], sound[1]

	cases := []struct {
		name   string
		mutate func(*aat.Claims)
		signer ed25519.PrivateKey
		method string
	}{
		{"i1_authority", func(*aat.Claims) {}, seedKey(0x99), aat.MethodBrokenSignature},
		{"i2_depth", func(c *aat.Claims) { c.DelDepth = 3 }, seedKey(0x71), aat.MethodBrokenDepth},
		{"i3_expiry", func(c *aat.Claims) { c.Exp = vecChainExp + 1 }, seedKey(0x71), aat.MethodBrokenExpiry},
		{"i5_linkage", func(c *aat.Claims) {
			c.ParHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		}, seedKey(0x71), aat.MethodBrokenParHash},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			claims := child.Claims
			c.mutate(&claims)
			forged, err := forge(c.signer, claims)
			if err != nil {
				t.Fatal(err)
			}
			res := aat.Verify([]aat.Hop{root, forged}, aat.RootMaterial{})
			if len(res) != 2 {
				t.Fatalf("want 2 hop results, got %d", len(res))
			}
			if res[1].Status != aat.StatusBroken {
				t.Fatalf("Go read the forged hop as %q (%s), not broken — the Rust verifier calls it broken, "+
					"so the two implementations disagree about these bytes",
					res[1].Status, res[1].Method)
			}
			if res[1].Method != c.method {
				t.Errorf("broken for the wrong reason: got %q want %q", res[1].Method, c.method)
			}
		})
	}
}

func TestTheSoundChainVerifiesGoSide(t *testing.T) {
	// The intact vector must be genuinely sound, not merely unchecked. A
	// corpus whose "intact" case is quietly broken proves nothing when it
	// passes.
	sound, err := soundChain()
	if err != nil {
		t.Fatal(err)
	}
	res := aat.Verify(sound, aat.RootMaterial{})
	for i, r := range res {
		if r.Status == aat.StatusBroken {
			t.Fatalf("hop %d of the intact vector is broken: %s — %s", i, r.Method, r.Reason)
		}
	}
}
