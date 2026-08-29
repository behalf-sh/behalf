package aat

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/oidctest"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/testkeys"
	"github.com/behalf-sh/behalf/internal/why"
)

// The three demo keys, in the roles the product gives them: the human's
// device key at depth 0, an orchestrator at depth 1, a sub-agent at depth 2.
func keys() (root, hop1, hop2 testkeys.Key) {
	return testkeys.ActorRoot(), testkeys.ActorHop1(), testkeys.ActorHop2()
}

const (
	testMaxDepth = 4
	testExp      = int64(1787788800) // 2026-08-27T00:00:00Z
)

// loginDir performs a real headless login against the in-repo fake IdP and
// returns the state directory it wrote. The device key is pinned so the
// chain minted below roots in a key the test can name.
func loginDir(t *testing.T) (string, *oidclogin.Result) {
	t.Helper()
	idp := oidctest.New()
	defer idp.Close()
	idp.AuthTime = time.Now().Add(-time.Minute).Unix()
	idp.AMR = []string{"pwd", "mfa"}

	root, _, _ := keys()
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := oidclogin.Login(ctx, oidclogin.Config{
		Issuer:    idp.URL,
		ClientID:  "behalf-aat-test",
		Dir:       dir,
		NoBrowser: true,
		DeviceKey: &identity.Key{Private: root.Private, Public: root.Public, JWK: root.JWK, JKT: root.JKT},
		OnAuthURL: func(u string) {
			go func() {
				resp, err := http.Get(u) //nolint:gosec // loopback fake IdP
				if err != nil {
					return
				}
				io.Copy(io.Discard, resp.Body) //nolint:errcheck
				resp.Body.Close()
			}()
		},
	})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return dir, res
}

// rootParams builds the depth-0 mint parameters from a completed login.
func rootParams(t *testing.T, res *oidclogin.Result) MintParams {
	t.Helper()
	root, _, _ := keys()
	return MintParams{
		Subject:  root.Public,
		MaxDepth: testMaxDepth,
		AuthorizationDetails: []map[string]any{{
			"type":    "sh.behalf/support-desk",
			"intent":  "resolve ticket tk_4437",
			"actions": []any{"tickets.read", "orders.read", "refund.issue"},
			"privileges": []any{map[string]any{
				"operation": "refund.issue",
				"limit":     map[string]any{"amount": "100.00", "currency": "USD"},
			}},
		}},
		Exp: testExp,
		JTI: "aat-test-hop0",
		Credential: receipt.Credential{
			Issuer: res.Issuer,
			Kind:   "oidc-id-token",
			ID:     "oidc-sub-digest:" + res.SubDigest,
			Exp:    testExp,
			JKT:    res.DeviceJKT,
		},
		RootPrincipalBinding: &receipt.RootBinding{
			Nonce:      res.DeviceJKT,
			DeviceJKT:  res.DeviceJKT,
			IDTokenRef: res.IDTokenDigest,
		},
	}
}

func hopParams(subject ed25519.PublicKey, jti string, actions []any) MintParams {
	return MintParams{
		Subject: subject,
		AuthorizationDetails: []map[string]any{{
			"type":    "sh.behalf/support-desk",
			"actions": actions,
			"privileges": []any{map[string]any{
				"operation": "refund.issue",
				"limit":     map[string]any{"amount": "100.00", "currency": "USD"},
			}},
		}},
		Exp: testExp,
		JTI: jti,
		Credential: receipt.Credential{
			Issuer: "https://desk.demo.internal",
			Kind:   "aat-jws",
			ID:     "aat-jws:" + jti,
			Exp:    testExp,
		},
	}
}

// mintChain builds the three-hop demo chain: root -> orchestrator ->
// sub-agent, each signed by its parent and each narrower than its parent.
func mintChain(t *testing.T, res *oidclogin.Result) []Hop {
	t.Helper()
	root, hop1, hop2 := keys()

	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatalf("mint hop 0: %v", err)
	}
	h1, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1", []any{"orders.read", "refund.issue"}))
	if err != nil {
		t.Fatalf("mint hop 1: %v", err)
	}
	h2, err := Mint(hop1.Private, &h1, hopParams(hop2.Public, "aat-test-hop2", []any{"refund.issue"}))
	if err != nil {
		t.Fatalf("mint hop 2: %v", err)
	}
	return []Hop{h0, h1, h2}
}

func statuses(res []HopResult) []string {
	out := make([]string, len(res))
	for i, r := range res {
		out[i] = r.Status
	}
	return out
}

func methods(res []HopResult) []string {
	out := make([]string, len(res))
	for i, r := range res {
		out[i] = r.Method
	}
	return out
}

func want(t *testing.T, res []HopResult, statusesWant, methodsWant []string) {
	t.Helper()
	got, gotM := statuses(res), methods(res)
	for i := range statusesWant {
		if i >= len(got) || got[i] != statusesWant[i] || gotM[i] != methodsWant[i] {
			t.Fatalf("hop statuses %v methods %v, want %v / %v\n  reasons: %v",
				got, gotM, statusesWant, methodsWant, reasons(res))
		}
	}
	if len(got) != len(statusesWant) {
		t.Fatalf("%d hops, want %d", len(got), len(statusesWant))
	}
}

func reasons(res []HopResult) []string {
	out := make([]string, len(res))
	for i, r := range res {
		out[i] = r.Reason
	}
	return out
}

// TestFullChainVerifies is the claim the product is built on: three hops of
// real cryptography, checked offline, all three verified.
func TestFullChainVerifies(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)

	got := Verify(chain, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusVerified, StatusVerified},
		[]string{MethodRootOIDC, MethodHopJWS, MethodHopJWS})
	if r := Weakest(got); r != StatusVerified {
		t.Fatalf("rollup %s, want verified", r)
	}
	// The root's evidence is the signed delegation statement, not the token:
	// the statement is what the three checks ran against (Q22).
	if wantRef := "sha256:" + res.StatementDigest; got[0].EvidenceRef != wantRef {
		t.Fatalf("root evidence_ref = %q, want %q", got[0].EvidenceRef, wantRef)
	}
	// Every hop above the root narrows.
	for i := 1; i < len(got); i++ {
		if got[i].Attenuation != why.AttenuationAttenuated {
			t.Fatalf("hop %d attenuation = %q, want attenuated", i, got[i].Attenuation)
		}
	}
}

// TestCallerAssertedLeaf is the distinction the whole product rests on: a
// hop with no signature is asserted — never verified, never broken — and it
// says so in a machine-readable reason.
func TestCallerAssertedLeaf(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)
	chain[2] = chain[2].Unsigned()

	got := Verify(chain, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusVerified, StatusAsserted},
		[]string{MethodRootOIDC, MethodHopJWS, MethodNoSignature})
	if r := Weakest(got); r != StatusAsserted {
		t.Fatalf("rollup %s, want asserted", r)
	}
	if !strings.Contains(got[2].Reason, "caller-asserted") {
		t.Fatalf("leaf reason %q does not say caller-asserted", got[2].Reason)
	}
	// It carries no evidence reference, because there is no evidence.
	if got[2].EvidenceRef != "" {
		t.Fatalf("an unsigned hop carries evidence_ref %q", got[2].EvidenceRef)
	}
}

// TestWrongSignerIsBroken: a hop re-signed by a key the parent never
// confirmed. Something was checked and it failed.
func TestWrongSignerIsBroken(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)
	_, _, hop2 := keys()

	// hop2's own key signs hop2 — self-issued authority, the classic forgery.
	forged, err := sign(hop2.Private, hop2.JKT, chain[2].Raw)
	if err != nil {
		t.Fatal(err)
	}
	chain[2].JWS = forged

	got := Verify(chain, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusVerified, StatusBroken},
		[]string{MethodRootOIDC, MethodHopJWS, MethodBrokenSignature})
	if r := Weakest(got); r != StatusBroken {
		t.Fatalf("rollup %s, want broken", r)
	}
}

// TestReparentedHopIsBroken pins what par_hash buys. Two parent hops confirm
// the SAME agent key and differ only in their own jti, so the child's
// signature verifies under either one. Only par_hash — which covers the
// parent's signature, not just its claims — catches the swap.
func TestReparentedHopIsBroken(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, hop2 := keys()

	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatal(err)
	}
	actions := []any{"orders.read", "refund.issue"}
	h1a, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1-a", actions))
	if err != nil {
		t.Fatal(err)
	}
	h1b, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1-b", actions))
	if err != nil {
		t.Fatal(err)
	}
	child, err := Mint(hop1.Private, &h1a, hopParams(hop2.Public, "aat-test-hop2", []any{"refund.issue"}))
	if err != nil {
		t.Fatal(err)
	}

	// Sanity: under its real parent the child verifies.
	if got := Verify([]Hop{h0, h1a, child}, LoadRootMaterial(dir)); got[2].Status != StatusVerified {
		t.Fatalf("the child does not verify under its own parent: %+v", got[2])
	}
	// Re-parented under the sibling: same key, same grant, different token.
	got := Verify([]Hop{h0, h1b, child}, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusVerified, StatusBroken},
		[]string{MethodRootOIDC, MethodHopJWS, MethodBrokenParHash})
	if !strings.Contains(got[2].Reason, "different parent") {
		t.Fatalf("re-parent reason %q", got[2].Reason)
	}
}

// TestBroadenedGrantIsBroken: Mint refuses to widen, and a hop that widened
// anyway verifies as broken.
func TestBroadenedGrantIsBroken(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, hop2 := keys()

	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatal(err)
	}
	h1, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1", []any{"refund.issue"}))
	if err != nil {
		t.Fatal(err)
	}

	// Mint will not produce it.
	if _, err := Mint(hop1.Private, &h1, hopParams(hop2.Public, "aat-test-hop2",
		[]any{"refund.issue", "orders.delete"})); err == nil {
		t.Fatal("Mint produced a hop that broadens its parent's grant")
	}

	// A hostile minter would. Build the same token by hand and check the
	// verifier catches it.
	widened := Claims{
		DelDepth:    2,
		DelMaxDepth: h1.Claims.DelMaxDepth,
		ParHash:     ParHash(h1.JWS),
		Cnf:         receipt.Cnf{JWK: jwkMap(hop2.JWK)},
		AuthorizationDetails: []map[string]any{{
			"type":    "sh.behalf/support-desk",
			"actions": []any{"refund.issue", "orders.delete"},
		}},
		Exp:        testExp,
		JTI:        "aat-test-hop2-widened",
		Credential: receipt.Credential{Issuer: "https://desk.demo.internal", Kind: "aat-jws", ID: "aat-jws:widened", Exp: testExp},
	}
	raw, err := json.Marshal(widened)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := sign(hop1.Private, hop1.JKT, raw)
	if err != nil {
		t.Fatal(err)
	}

	got := Verify([]Hop{h0, h1, {Claims: widened, Raw: raw, JWS: jws}}, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusVerified, StatusBroken},
		[]string{MethodRootOIDC, MethodHopJWS, MethodBrokenAttenuation})
	if got[2].Attenuation != why.AttenuationBroadened {
		t.Fatalf("attenuation %q, want broadened", got[2].Attenuation)
	}
	// A broadened grant is a break, not a flag: the frozen enum has no
	// value for it and the status carries the finding instead.
	if f := got[2].StoredFlag(); f != "" {
		t.Fatalf("stored attenuation_flag = %q for a broadened grant, want empty", f)
	}
}

// TestHopWithoutJTIIsMalformed pins one rule and no more: a SIGNED hop whose
// claim set carries no `jti` reads `broken` with `broken: malformed hop`,
// rather than `verified`.
//
// What it does not pin: it says nothing about whether the jti is unique,
// well-formed, a UUIDv7, or unrepeated across the chain. The vendored draft
// asks for all of those (§3.2 recommends UUIDv7; §7 step 2c DENIES a chain
// with a repeated jti) and behalf checks none of them — see
// docs/aat-profile-v1.md §9, where the gap is recorded rather than quietly
// closed. This test pins presence, which is the part Mint already enforced
// and the verifier did not.
func TestHopWithoutJTIIsMalformed(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, _ := keys()

	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatal(err)
	}

	// Mint will not produce it.
	p := hopParams(hop1.Public, "", []any{"refund.issue"})
	if _, err := Mint(root.Private, &h0, p); err == nil {
		t.Fatal("Mint produced a hop with no jti")
	}

	// A hostile minter would. Same claims, signed by the right key, jti
	// dropped — the token is cryptographically impeccable and still malformed.
	naked := Claims{
		DelDepth:             1,
		DelMaxDepth:          h0.Claims.DelMaxDepth,
		ParHash:              ParHash(h0.JWS),
		Cnf:                  receipt.Cnf{JWK: jwkMap(hop1.JWK)},
		AuthorizationDetails: []map[string]any{{"type": "sh.behalf/support-desk", "actions": []any{"refund.issue"}}},
		Exp:                  testExp,
		Credential:           receipt.Credential{Issuer: "https://desk.demo.internal", Kind: "aat-jws", ID: "aat-jws:nojti", Exp: testExp},
	}
	raw, err := json.Marshal(naked)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := sign(root.Private, root.JKT, raw)
	if err != nil {
		t.Fatal(err)
	}

	got := Verify([]Hop{h0, {Claims: naked, Raw: raw, JWS: jws}}, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusBroken},
		[]string{MethodRootOIDC, MethodBrokenMalformed})

	// And the same rule at depth 0, where there is no parent to inherit it.
	rootless := h0.Claims
	rootless.JTI = ""
	rootRaw, err := json.Marshal(rootless)
	if err != nil {
		t.Fatal(err)
	}
	rootJWS, err := sign(root.Private, root.JKT, rootRaw)
	if err != nil {
		t.Fatal(err)
	}
	got = Verify([]Hop{{Claims: rootless, Raw: rootRaw, JWS: rootJWS}}, LoadRootMaterial(dir))
	want(t, got, []string{StatusBroken}, []string{MethodBrokenMalformed})

	// An UNSIGNED hop with no jti stays `asserted`: nothing was checked, so
	// nothing broke. The distinction is the product, and this rule must not
	// erode it.
	got = Verify([]Hop{h0, {Claims: naked, Raw: raw}}, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusAsserted},
		[]string{MethodRootOIDC, MethodNoSignature})
}

// TestUnknownAttenuationIsFlaggedNeverSwallowed (Q13, D8.7): a vocabulary the
// invariants cannot compare does not silently pass and does not break — it is
// recorded as unknown, on a hop that is `asserted`.
//
// Both halves matter. Q13's rule is that the finding is never swallowed: the
// flag says `unknown` and the reason says which vocabulary and why. D8.7 is
// the half that changed — the hop used to read `verified` beside that flag,
// which claimed an invariant nobody had checked. Mint still emits such a
// grant: an uncomparable delegation is a real thing to record, it is just not
// a verified one.
func TestUnknownAttenuationIsFlaggedNeverSwallowed(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, _ := keys()

	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatal(err)
	}
	// An Entra-style role grant: no RFC 9396 `actions` to compare.
	p := hopParams(hop1.Public, "aat-test-hop1", nil)
	p.AuthorizationDetails = []map[string]any{{
		"type":  "https://graph.microsoft.example/roles",
		"roles": []any{"Mail.Send"},
	}}
	h1, err := Mint(root.Private, &h0, p)
	if err != nil {
		t.Fatalf("mint must not refuse an uncomparable grant: %v", err)
	}

	// D8.7: the hop is `asserted`, not `verified`. Its signature, depth,
	// expiry and linkage all hold — and I4 was never checked, so the word
	// `verified` is not available to it. Nothing here is `broken`: no
	// invariant failed, one could not be run.
	got := Verify([]Hop{h0, h1}, LoadRootMaterial(dir))
	want(t, got, []string{StatusVerified, StatusAsserted}, []string{MethodRootOIDC, MethodUncomparableGrant})
	if got[1].Attenuation != why.AttenuationUnknown {
		t.Fatalf("attenuation %q, want unknown", got[1].Attenuation)
	}
	if got[1].AttenuationReason == "" {
		t.Fatal("unknown attenuation was swallowed: no reason recorded")
	}
	// Flagged, not swallowed (Q13) — D8.7 changed the hop's status, not the
	// record's honesty about why.
	if f := got[1].StoredFlag(); f != string(why.AttenuationUnknown) {
		t.Fatalf("stored attenuation_flag = %q, want unknown", f)
	}
	if !strings.Contains(got[1].Reason, "cannot be compared") {
		t.Fatalf("the hop's reason does not say the grant was uncomparable: %q", got[1].Reason)
	}
	if r := Weakest(got); r != StatusAsserted {
		t.Fatalf("rollup %s, want asserted: an uncomparable grant must not roll up as verified", r)
	}
}

// TestDraftShapedBroadeningIsBroken is the test that used to pin the gap.
//
// It previously asserted that a chain in the vendored draft's own grant shape
// — a single `attenuating_agent_token` entry carrying a `tools` map (§3.3) —
// was not compared at all, so a child that ADDED a tool its parent never
// granted was minted happily and recorded `verified` with
// `attenuation_flag: unknown`. Draft §7 step 4p1 says DENY for exactly that
// chain, and profile §9.1 wrote the divergence up.
//
// The gap is closed. `why.CompareGrants` now routes an
// `attenuating_agent_token` entry through §4.5's subsumption rules, so the
// same chain is refused at mint time and `broken` at verification time. What
// this test pins now is the corrected behaviour, both halves of it.
func TestDraftShapedBroadeningIsBroken(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, _ := keys()

	// Draft §3.3 shape, exactly: one entry, type attenuating_agent_token,
	// a tools map of tool name -> argument constraints.
	parentGrant := []map[string]any{{
		"type": "attenuating_agent_token",
		"tools": map[string]any{
			"read_file": map[string]any{
				"path": map[string]any{"constraint_type": "one_of", "values": []any{"/data/q3.pdf"}},
			},
		},
	}}
	// A child that adds a tool the parent never granted. Draft §7 step 4p1:
	// "If any child tool is absent from the parent, DENY."
	childGrant := []map[string]any{{
		"type": "attenuating_agent_token",
		"tools": map[string]any{
			"read_file": map[string]any{
				"path": map[string]any{"constraint_type": "one_of", "values": []any{"/data/q3.pdf"}},
			},
			"delete_file": map[string]any{},
		},
	}}

	rp := rootParams(t, res)
	rp.AuthorizationDetails = parentGrant
	h0, err := Mint(root.Private, nil, rp)
	if err != nil {
		t.Fatal(err)
	}
	p := hopParams(hop1.Public, "aat-test-hop1", nil)
	p.AuthorizationDetails = childGrant

	// Mint refuses it, and the refusal is typed and names the tool — a caller
	// that hit this needs to know which capability to drop, not merely that
	// something was too wide.
	if _, err := Mint(root.Private, &h0, p); err == nil {
		t.Fatal("Mint produced a draft-shaped chain its own verifier rejects")
	} else {
		var be *BroadeningError
		if !errors.As(err, &be) {
			t.Fatalf("Mint refused with %T, want a *BroadeningError: %v", err, err)
		}
		if be.Tool != "delete_file" {
			t.Fatalf("the refusal names tool %q, want \"delete_file\"", be.Tool)
		}
		if !be.Capability() {
			t.Fatal("the refusal does not report itself as a capability finding")
		}
	}

	// A hostile minter would sign it anyway. Build the same token by hand and
	// check the verifier catches it.
	raw, jws := handSign(t, root.Private, root.JKT, Claims{
		DelDepth:             1,
		DelMaxDepth:          h0.Claims.DelMaxDepth,
		ParHash:              ParHash(h0.JWS),
		Cnf:                  receipt.Cnf{JWK: jwkMap(hop1.JWK)},
		AuthorizationDetails: childGrant,
		Exp:                  testExp,
		JTI:                  "aat-test-hop1",
		Credential: receipt.Credential{
			Issuer: "https://desk.demo.internal", Kind: "aat-jws", ID: "aat-jws:widened", Exp: testExp,
		},
	})

	got := Verify([]Hop{h0, {Claims: mustClaims(t, raw), Raw: raw, JWS: jws}}, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusBroken},
		[]string{MethodRootOIDC, MethodBrokenAttenuation})
	if got[1].Attenuation != why.AttenuationBroadened {
		t.Fatalf("attenuation %q, want broadened", got[1].Attenuation)
	}
	// A broadened grant is a break, not a flag: the frozen enum has no value
	// for it, and the rollup follows the weakest hop.
	if f := got[1].StoredFlag(); f != "" {
		t.Fatalf("stored attenuation_flag = %q for a broadened grant, want empty", f)
	}
	if r := Weakest(got); r != StatusBroken {
		t.Fatalf("rollup %s, want broken", r)
	}
	if !strings.Contains(got[1].AttenuationReason, "delete_file") {
		t.Fatalf("the reason does not name the undelegated tool: %q", got[1].AttenuationReason)
	}
}

// TestDraftShapedNarrowingVerifies is the other half of the fix: a genuinely
// conforming attenuation in the draft's shape must still verify, or the gap
// would have been closed by refusing everything.
//
// The grant is draft §3.3's own example, and the child drops a tool, narrows
// a one_of to a single value, replaces a wildcard with an exact, and tightens
// a range ceiling — four attenuations §4.5 permits.
func TestDraftShapedNarrowingVerifies(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, _ := keys()

	rp := rootParams(t, res)
	rp.AuthorizationDetails = []map[string]any{{
		"type": "attenuating_agent_token",
		"tools": map[string]any{
			"read_file": map[string]any{
				"path": map[string]any{
					"constraint_type": "one_of",
					"values":          []any{"/data/q3-report.pdf", "/data/q4-report.pdf"},
				},
			},
			"search_index": map[string]any{
				"query": map[string]any{"constraint_type": "wildcard"},
				"limit": map[string]any{"constraint_type": "range", "max": 100},
			},
		},
	}}
	h0, err := Mint(root.Private, nil, rp)
	if err != nil {
		t.Fatal(err)
	}

	p := hopParams(hop1.Public, "aat-test-hop1", nil)
	p.AuthorizationDetails = []map[string]any{{
		"type": "attenuating_agent_token",
		"tools": map[string]any{
			"search_index": map[string]any{
				"query": map[string]any{"constraint_type": "exact", "value": "public filings"},
				"limit": map[string]any{"constraint_type": "range", "max": 10},
			},
		},
	}}
	h1, err := Mint(root.Private, &h0, p)
	if err != nil {
		t.Fatalf("Mint refused a conforming attenuation: %v", err)
	}

	got := Verify([]Hop{h0, h1}, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusVerified},
		[]string{MethodRootOIDC, MethodHopJWS})
	if got[1].Attenuation != why.AttenuationAttenuated {
		t.Fatalf("attenuation %q, want attenuated", got[1].Attenuation)
	}
	if f := got[1].StoredFlag(); f != string(why.AttenuationAttenuated) {
		t.Fatalf("stored attenuation_flag = %q, want attenuated", f)
	}
}

// handSign builds a token the way a hostile minter would: signed correctly,
// linked correctly, and carrying whatever claims it likes.
func handSign(t *testing.T, key ed25519.PrivateKey, kid string, c Claims) ([]byte, string) {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	jws, err := sign(key, kid, raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, jws
}

func mustClaims(t *testing.T, raw []byte) Claims {
	t.Helper()
	var c Claims
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestNoRootMaterialKeepsEverythingAsserted is the day-zero path (Q21) and
// the one the proxy must keep working: no `behalf login`, so the root cannot
// be checked, and nothing above a root that was not checked can be either.
func TestNoRootMaterialKeepsEverythingAsserted(t *testing.T) {
	_, res := loginDir(t)
	chain := mintChain(t, res)

	got := Verify(chain, LoadRootMaterial(t.TempDir()))
	want(t, got,
		[]string{StatusAsserted, StatusAsserted, StatusAsserted},
		[]string{MethodNoRootMaterial, MethodParentUnverified, MethodParentUnverified})
	if r := Weakest(got); r != StatusAsserted {
		t.Fatalf("rollup %s, want asserted", r)
	}
	if !strings.Contains(got[0].Reason, "behalf login") {
		t.Fatalf("root reason %q does not name the missing login", got[0].Reason)
	}
}

// TestTamperedIDTokenBreaksRootAndRollup: edit the customer-held ID-token
// blob and the root predicate fails — the root is broken and so is the
// receipt-level rollup, even though every hop signature above it is intact.
func TestTamperedIDTokenBreaksRootAndRollup(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)

	blob := filepath.Join(identity.BlobsDir(dir), res.IDTokenDigest)
	raw, err := os.ReadFile(blob)
	if err != nil {
		t.Fatal(err)
	}
	altered := append([]byte(nil), raw...)
	altered[len(altered)-1] ^= 0x01
	if err := os.WriteFile(blob, altered, 0o600); err != nil {
		t.Fatal(err)
	}

	got := Verify(chain, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusBroken, StatusAsserted, StatusAsserted},
		[]string{MethodBrokenRoot, MethodParentUnverified, MethodParentUnverified})
	if r := Weakest(got); r != StatusBroken {
		t.Fatalf("rollup %s, want broken", r)
	}
}

// TestDeletedEvidenceDegradesToAsserted (Q22): the customer deleting their
// own ID-token blob is not tampering. The root degrades to behalf-attested
// and the record says so, rather than reading as a break.
func TestDeletedEvidenceDegradesToAsserted(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)

	if err := os.Remove(filepath.Join(identity.BlobsDir(dir), res.IDTokenDigest)); err != nil {
		t.Fatal(err)
	}
	got := Verify(chain, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusAsserted, StatusAsserted, StatusAsserted},
		[]string{MethodRootDegraded, MethodParentUnverified, MethodParentUnverified})
}

// TestRootKeyIsNotTheLoggedInDevice: a chain rooted in some other key than
// the one this login bound does not root here, and says so.
func TestRootKeyIsNotTheLoggedInDevice(t *testing.T) {
	dir, res := loginDir(t)
	other := testkeys.New("aat-test-other-device")

	p := rootParams(t, res)
	p.Subject = other.Public
	p.RootPrincipalBinding = &receipt.RootBinding{Nonce: other.JKT, DeviceJKT: other.JKT}
	h0, err := Mint(other.Private, nil, p)
	if err != nil {
		t.Fatal(err)
	}
	got := Verify([]Hop{h0}, LoadRootMaterial(dir))
	want(t, got, []string{StatusBroken}, []string{MethodBrokenRoot})
	if !strings.Contains(got[0].Reason, "device key") {
		t.Fatalf("reason %q", got[0].Reason)
	}
}

// TestRootBindingMustBeTheThumbprint: nonce == jkt(device_pubkey) is the
// binding (D5). A root asserting anything else is broken.
func TestRootBindingMustBeTheThumbprint(t *testing.T) {
	dir, res := loginDir(t)
	root, _, _ := keys()

	p := rootParams(t, res)
	p.RootPrincipalBinding = &receipt.RootBinding{Nonce: "not-a-thumbprint", DeviceJKT: root.JKT}
	h0, err := Mint(root.Private, nil, p)
	if err != nil {
		t.Fatal(err)
	}
	got := Verify([]Hop{h0}, LoadRootMaterial(dir))
	want(t, got, []string{StatusBroken}, []string{MethodBrokenRoot})
}

// TestDepthInvariants: increment by one, never widen the budget, never
// exceed it.
func TestDepthInvariants(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, hop2 := keys()
	rootMat := LoadRootMaterial(dir)

	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatal(err)
	}
	h1, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1", []any{"refund.issue"}))
	if err != nil {
		t.Fatal(err)
	}

	forge := func(mutate func(*Claims)) Hop {
		t.Helper()
		c := h1.Claims
		c.DelDepth = 2
		c.ParHash = ParHash(h1.JWS)
		c.Cnf = receipt.Cnf{JWK: jwkMap(hop2.JWK)}
		c.JTI = "aat-test-forged"
		mutate(&c)
		raw, err := json.Marshal(c)
		if err != nil {
			t.Fatal(err)
		}
		jws, err := sign(hop1.Private, hop1.JKT, raw)
		if err != nil {
			t.Fatal(err)
		}
		return Hop{Claims: c, Raw: raw, JWS: jws}
	}

	cases := []struct {
		name   string
		mutate func(*Claims)
	}{
		{"skips a depth", func(c *Claims) { c.DelDepth = 3 }},
		{"widens the budget", func(c *Claims) { c.DelMaxDepth = testMaxDepth + 5 }},
		{"exceeds the budget", func(c *Claims) { c.DelDepth, c.DelMaxDepth = 2, 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Verify([]Hop{h0, h1, forge(tc.mutate)}, rootMat)
			if got[2].Status != StatusBroken || got[2].Method != MethodBrokenDepth {
				t.Fatalf("hop 2 = %s/%s (%s), want broken/%s", got[2].Status, got[2].Method, got[2].Reason, MethodBrokenDepth)
			}
		})
	}
}

// TestExpiryInvariants: a hop never outlives its parent, and — when the
// caller supplies a capture instant — is not already expired at it.
func TestExpiryInvariants(t *testing.T) {
	dir, res := loginDir(t)
	root, hop1, hop2 := keys()
	rootMat := LoadRootMaterial(dir)

	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatal(err)
	}
	h1, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1", []any{"refund.issue"}))
	if err != nil {
		t.Fatal(err)
	}

	// Mint refuses to outlive the parent.
	long := hopParams(hop2.Public, "aat-test-hop2", []any{"refund.issue"})
	long.Exp = testExp + 86400
	if _, err := Mint(hop1.Private, &h1, long); err == nil {
		t.Fatal("Mint produced a hop that outlives its parent")
	}

	// Hand-built, it verifies as broken.
	c := h1.Claims
	c.DelDepth, c.ParHash, c.Exp, c.JTI = 2, ParHash(h1.JWS), testExp+86400, "aat-test-long"
	c.Cnf = receipt.Cnf{JWK: jwkMap(hop2.JWK)}
	raw, _ := json.Marshal(c)
	jws, err := sign(hop1.Private, hop1.JKT, raw)
	if err != nil {
		t.Fatal(err)
	}
	got := Verify([]Hop{h0, h1, {Claims: c, Raw: raw, JWS: jws}}, rootMat)
	if got[2].Status != StatusBroken || got[2].Method != MethodBrokenExpiry {
		t.Fatalf("hop 2 = %s/%s (%s)", got[2].Status, got[2].Method, got[2].Reason)
	}

	// A capture instant after the whole chain expired breaks it there.
	late := rootMat
	late.At = time.Unix(testExp+1, 0).UTC()
	got = Verify([]Hop{h0, h1}, late)
	if got[0].Status != StatusBroken || got[0].Method != MethodBrokenExpiry {
		t.Fatalf("expired root = %s/%s (%s)", got[0].Status, got[0].Method, got[0].Reason)
	}
	// And with no instant supplied, the same chain reads exactly as it did
	// at capture — offline re-verification must not manufacture findings.
	if got := Verify([]Hop{h0, h1}, rootMat); got[0].Status != StatusVerified {
		t.Fatalf("offline re-verification turned a then-valid root into %s", got[0].Status)
	}
}

// TestUnsignedParentStopsVerificationWithoutBreaking: past a caller-asserted
// hop there is nothing for par_hash to name, so the hops above are asserted
// — out of scope is not a failure (Q17).
func TestUnsignedParentStopsVerificationWithoutBreaking(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)
	chain[1] = chain[1].Unsigned()

	got := Verify(chain, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusVerified, StatusAsserted, StatusAsserted},
		[]string{MethodRootOIDC, MethodNoSignature, MethodParentUnverified})
	if r := Weakest(got); r != StatusAsserted {
		t.Fatalf("rollup %s, want asserted", r)
	}
}

// TestUnsupportedKeyIsAssertedNotBroken (Q17): everything outside Ed25519 is
// out of v1 scope, and out of scope reads as asserted.
func TestUnsupportedKeyIsAssertedNotBroken(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)
	chain[0].Claims.Cnf = receipt.Cnf{JWK: map[string]any{"kty": "EC", "crv": "P-256", "x": "a", "y": "b"}}

	got := Verify(chain, LoadRootMaterial(dir))
	if got[0].Status != StatusAsserted || got[0].Method != MethodUnsupportedKey {
		t.Fatalf("root = %s/%s (%s)", got[0].Status, got[0].Method, got[0].Reason)
	}
}

// TestRootMustBeDepthZero: every chain has a depth-0 root (Q14).
func TestRootMustBeDepthZero(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)

	got := Verify(chain[1:], LoadRootMaterial(dir))
	if got[0].Status != StatusBroken || got[0].Method != MethodBrokenDepth {
		t.Fatalf("headless chain root = %s/%s (%s)", got[0].Status, got[0].Method, got[0].Reason)
	}
}

// TestUnsignedRootIsAsserted: the root with no token behind it is the
// caller-asserted case too, and must not read as broken.
func TestUnsignedRootIsAsserted(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)
	chain[0] = chain[0].Unsigned()

	got := Verify(chain, LoadRootMaterial(dir))
	want(t, got,
		[]string{StatusAsserted, StatusAsserted, StatusAsserted},
		[]string{MethodNoSignature, MethodParentUnverified, MethodParentUnverified})
}

// TestDeterministicMinting: fixed keys and fixed parameters produce
// byte-identical tokens. Recordings ship and are re-verified in CI, so a
// minter with any hidden entropy in it would make the demo artifact
// irreproducible (D9.2, Q92).
func TestDeterministicMinting(t *testing.T) {
	_, res := loginDir(t)
	root, hop1, _ := keys()

	build := func() []Hop {
		h0, err := Mint(root.Private, nil, rootParams(t, res))
		if err != nil {
			t.Fatal(err)
		}
		h1, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1", []any{"refund.issue"}))
		if err != nil {
			t.Fatal(err)
		}
		return []Hop{h0, h1}
	}
	a, b := build(), build()
	for i := range a {
		if a[i].JWS != b[i].JWS {
			t.Fatalf("hop %d is not reproducible:\n  a %s\n  b %s", i, a[i].JWS, b[i].JWS)
		}
	}
	// And the same claim set under a different signer is a different token,
	// so determinism is not coming from the payload alone.
	other, err := Mint(root.Private, &a[0], hopParams(hop1.Public, "aat-test-hop1-other", []any{"refund.issue"}))
	if err != nil {
		t.Fatal(err)
	}
	if other.JWS == a[1].JWS {
		t.Fatal("two different jti values produced the same token")
	}
}

// TestChainRoundTrip: carriage material survives the wire, tokens verbatim
// and unsigned hops recognisable as unsigned.
func TestChainRoundTrip(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)
	chain[2] = chain[2].Unsigned()

	raw, err := MarshalChain(chain)
	if err != nil {
		t.Fatal(err)
	}
	back, err := ParseChain(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != 3 {
		t.Fatalf("parsed %d hops, want 3", len(back))
	}
	for i := range chain {
		if back[i].JWS != chain[i].JWS {
			t.Fatalf("hop %d token changed on the wire", i)
		}
		if string(back[i].Raw) != string(chain[i].Raw) {
			t.Fatalf("hop %d claim bytes changed on the wire", i)
		}
	}
	if back[2].Signed() {
		t.Fatal("the unsigned hop came back signed")
	}
	// The parsed chain verifies exactly as the minted one did.
	if a, b := statuses(Verify(chain, LoadRootMaterial(dir))), statuses(Verify(back, LoadRootMaterial(dir))); strings.Join(a, ",") != strings.Join(b, ",") {
		t.Fatalf("verification differs across the wire: %v vs %v", a, b)
	}

	if _, err := ParseChain([]byte(`{"chain":[]}`)); err == nil {
		t.Fatal("non-AAT material parsed as an AAT chain")
	}
}

// TestReceiptHopMatchesTheFrozenFieldSet: the projection into the receipt
// carries every §7 member and nothing invented.
func TestReceiptHopMatchesTheFrozenFieldSet(t *testing.T) {
	dir, res := loginDir(t)
	chain := mintChain(t, res)
	results := Verify(chain, LoadRootMaterial(dir))

	h := chain[0].ReceiptHop(results[0])
	if h.DelDepth != 0 || h.DelMaxDepth != testMaxDepth || h.ParHash != RootParHash {
		t.Fatalf("root hop projection: %+v", h)
	}
	if h.JTI != "aat-test-hop0" || h.Exp != testExp || h.Credential.Kind != "oidc-id-token" {
		t.Fatalf("root hop projection: %+v", h)
	}
	if h.RootPrincipalBinding == nil || h.RootPrincipalBinding.Nonce != res.DeviceJKT {
		t.Fatalf("root binding lost in projection: %+v", h.RootPrincipalBinding)
	}
	if h.Verification.Status != StatusVerified || h.Verification.Method != MethodRootOIDC {
		t.Fatalf("verification lost in projection: %+v", h.Verification)
	}
	// The token's own claim bytes never carry a verification status: a token
	// that graded itself would be worthless.
	var claims map[string]any
	if err := json.Unmarshal(chain[0].Raw, &claims); err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"verification", "carriage_route", "attenuation_flag"} {
		if _, ok := claims[forbidden]; ok {
			t.Fatalf("the token claims carry %q, which behalf writes after checking, not the caller", forbidden)
		}
	}
}

// TestMintRefusesUnsoundChains covers the guardrails that stop a caller
// producing material Verify would only reject later.
func TestMintRefusesUnsoundChains(t *testing.T) {
	_, res := loginDir(t)
	root, hop1, hop2 := keys()
	h0, err := Mint(root.Private, nil, rootParams(t, res))
	if err != nil {
		t.Fatal(err)
	}
	h1, err := Mint(root.Private, &h0, hopParams(hop1.Public, "aat-test-hop1", []any{"refund.issue"}))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		run  func() error
	}{
		{"root not signed by the key it confirms", func() error {
			p := rootParams(t, res)
			p.Subject = hop1.Public
			_, err := Mint(root.Private, nil, p)
			return err
		}},
		{"root with no anchor", func() error {
			p := rootParams(t, res)
			p.RootPrincipalBinding = nil
			_, err := Mint(root.Private, nil, p)
			return err
		}},
		{"child signed by a key the parent never confirmed", func() error {
			_, err := Mint(hop2.Private, &h1, hopParams(hop2.Public, "x", []any{"refund.issue"}))
			return err
		}},
		{"root binding above depth 0", func() error {
			p := hopParams(hop2.Public, "x", []any{"refund.issue"})
			p.RootPrincipalBinding = &receipt.RootBinding{Nonce: root.JKT}
			_, err := Mint(hop1.Private, &h1, p)
			return err
		}},
		{"del_max_depth chosen rather than inherited", func() error {
			p := hopParams(hop2.Public, "x", []any{"refund.issue"})
			p.MaxDepth = testMaxDepth + 1
			_, err := Mint(hop1.Private, &h1, p)
			return err
		}},
		{"extending past a caller-asserted hop", func() error {
			unsigned := h1.Unsigned()
			_, err := Mint(hop1.Private, &unsigned, hopParams(hop2.Public, "x", []any{"refund.issue"}))
			return err
		}},
		{"no jti", func() error {
			p := hopParams(hop2.Public, "", []any{"refund.issue"})
			_, err := Mint(hop1.Private, &h1, p)
			return err
		}},
		{"no exp", func() error {
			p := hopParams(hop2.Public, "x", []any{"refund.issue"})
			p.Exp = 0
			_, err := Mint(hop1.Private, &h1, p)
			return err
		}},
		{"no grant", func() error {
			p := hopParams(hop2.Public, "x", nil)
			p.AuthorizationDetails = nil
			_, err := Mint(hop1.Private, &h1, p)
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatal("Mint accepted it")
			}
		})
	}
}

// TestWeakestIsTheRollup (schema §8).
func TestWeakestIsTheRollup(t *testing.T) {
	v := HopResult{Status: StatusVerified}
	a := HopResult{Status: StatusAsserted}
	b := HopResult{Status: StatusBroken}
	cases := []struct {
		in   []HopResult
		want string
	}{
		{nil, StatusAsserted},
		{[]HopResult{v, v, v}, StatusVerified},
		{[]HopResult{v, v, a}, StatusAsserted},
		{[]HopResult{v, a, b}, StatusBroken},
		{[]HopResult{b, v, v}, StatusBroken},
	}
	for _, tc := range cases {
		if got := Weakest(tc.in); got != tc.want {
			t.Fatalf("Weakest(%v) = %s, want %s", statuses(tc.in), got, tc.want)
		}
	}
}
