package proxy

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/oidctest"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// testChainJSON builds two-hop chain material shaped like what act two's
// AAT minting will produce: a depth-0 root carrying the OIDC
// nonce-thumbprint binding (D5) and one attenuated hop for the agent. The
// hops must satisfy the frozen hop schema, since the proxy embeds them
// whole in a receipt that is validated against it.
func testChainJSON() string {
	root := testkeys.ActorRoot()
	hop1 := testkeys.ActorHop1()
	const rootParHash = "0000000000000000000000000000000000000000000000000000000000000000"
	const hop1ParHash = "1111111111111111111111111111111111111111111111111111111111111111"

	chain := map[string]any{
		"chain": []any{
			map[string]any{
				"del_depth":     0,
				"del_max_depth": 4,
				"par_hash":      rootParHash,
				"cnf":           map[string]any{"jwk": map[string]any{"kty": root.JWK.Kty, "crv": root.JWK.Crv, "x": root.JWK.X}},
				"authorization_details": []any{
					map[string]any{"type": "sh.behalf/root-delegation/v1"},
				},
				"exp": 4102444800,
				"jti": "behalf-root-01hzzzzzzzzzzzzzzzzzzzzzzz",
				"credential": map[string]any{
					"issuer": "https://idp.example",
					"kind":   "oidc-id-token",
					"id":     "oidc-sub-digest:" + rootParHash,
					"exp":    4102444800,
					"jkt":    root.JKT,
				},
				"root_principal_binding": map[string]any{
					"nonce":      root.JKT,
					"device_jkt": root.JKT,
				},
				"verification": map[string]any{"status": "verified", "method": "oidc-nonce-binding"},
			},
			map[string]any{
				"del_depth":     1,
				"del_max_depth": 4,
				"par_hash":      hop1ParHash,
				"cnf":           map[string]any{"jwk": map[string]any{"kty": hop1.JWK.Kty, "crv": hop1.JWK.Crv, "x": hop1.JWK.X}},
				"authorization_details": []any{
					map[string]any{"type": "sh.behalf/tool-scope/v1", "actions": []any{"orders.search", "refund.issue"}},
				},
				"exp": 4102444800,
				"jti": "behalf-hop-01hzzzzzzzzzzzzzzzzzzzzzzz",
				"credential": map[string]any{
					"issuer": "https://idp.example",
					"kind":   "oauth-jti",
					"id":     "aat:hop-1",
					"exp":    4102444800,
					"jkt":    hop1.JKT,
				},
				"verification":     map[string]any{"status": "asserted", "method": "aat-chain"},
				"attenuation_flag": "attenuated",
			},
		},
	}
	b, err := json.Marshal(chain)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// TestParseChainShapes: the loader accepts both the authority object and a
// bare hop array, and material it cannot read as behalf hops still travels
// (carriage is metadata; verification comes from signatures — Q15).
func TestParseChainShapes(t *testing.T) {
	full, err := ParseChain([]byte(testChainJSON()))
	if err != nil {
		t.Fatal(err)
	}
	if len(full.Hops) != 2 {
		t.Fatalf("parsed %d hops, want 2", len(full.Hops))
	}

	var authority struct {
		Chain json.RawMessage `json:"chain"`
	}
	if err := json.Unmarshal([]byte(testChainJSON()), &authority); err != nil {
		t.Fatal(err)
	}
	bare, err := ParseChain(authority.Chain)
	if err != nil {
		t.Fatal(err)
	}
	if len(bare.Hops) != 2 {
		t.Fatalf("bare array parsed %d hops, want 2", len(bare.Hops))
	}

	opaque, err := ParseChain([]byte(`{"jws":"eyJhbGciOiJFZERTQSJ9.e30.sig"}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(opaque.Hops) != 0 {
		t.Fatal("opaque material should parse to no hops")
	}
	if len(opaque.Raw) == 0 {
		t.Fatal("opaque material must still be carried")
	}

	// Multi-line material is compacted: it is spliced into a
	// newline-delimited stream and must be one line.
	pretty, err := ParseChain([]byte("{\n  \"chain\": []\n}\n"))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range pretty.Raw {
		if b == '\n' {
			t.Fatalf("chain material was not compacted: %q", pretty.Raw)
		}
	}
}

// ---- verification at capture (Q18) ------------------------------------

const chainTestExp = int64(1787788800) // 2026-08-27T00:00:00Z

// loginInto performs a real headless login against the in-repo fake IdP,
// writing the device key, the ID-token and JWKS blobs and the signed root
// delegation statement into dir — the material the depth-0 predicate needs.
func loginInto(t *testing.T, dir string) *oidclogin.Result {
	t.Helper()
	idp := oidctest.New()
	defer idp.Close()
	idp.AuthTime = time.Now().Add(-time.Minute).Unix()

	root := testkeys.ActorRoot()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	res, err := oidclogin.Login(ctx, oidclogin.Config{
		Issuer:    idp.URL,
		ClientID:  "behalf-proxy-test",
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
	return res
}

// mintTestChain builds a two-hop signed chain rooted in the login's device
// key: the human, then one attenuated agent hop.
func mintTestChain(t *testing.T, res *oidclogin.Result) []aat.Hop {
	t.Helper()
	root, hop1 := testkeys.ActorRoot(), testkeys.ActorHop1()

	h0, err := aat.Mint(root.Private, nil, aat.MintParams{
		Subject:  root.Public,
		MaxDepth: 4,
		AuthorizationDetails: []map[string]any{{
			"type":    "sh.behalf/tool-scope/v1",
			"actions": []any{"orders.search", "orders.read", "refund.issue"},
		}},
		Exp: chainTestExp,
		JTI: "proxy-test-hop0",
		Credential: receipt.Credential{
			Issuer: res.Issuer, Kind: "oidc-id-token",
			ID: "oidc-sub-digest:" + res.SubDigest, Exp: chainTestExp, JKT: res.DeviceJKT,
		},
		RootPrincipalBinding: &receipt.RootBinding{
			Nonce: res.DeviceJKT, DeviceJKT: res.DeviceJKT, IDTokenRef: res.IDTokenDigest,
		},
	})
	if err != nil {
		t.Fatalf("mint root hop: %v", err)
	}
	h1, err := aat.Mint(root.Private, &h0, aat.MintParams{
		Subject: hop1.Public,
		AuthorizationDetails: []map[string]any{{
			"type":    "sh.behalf/tool-scope/v1",
			"actions": []any{"orders.search"},
		}},
		Exp: chainTestExp,
		JTI: "proxy-test-hop1",
		Credential: receipt.Credential{
			Issuer: "https://desk.demo.internal", Kind: "aat-jws",
			ID: "aat-jws:proxy-test-hop1", Exp: chainTestExp, JKT: hop1.JKT,
		},
	})
	if err != nil {
		t.Fatalf("mint hop 1: %v", err)
	}
	return []aat.Hop{h0, h1}
}

func marshalChain(t *testing.T, hops []aat.Hop) string {
	t.Helper()
	raw, err := aat.MarshalChain(hops)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// captureAt runs one tools/call through the proxy with the given chain
// material and state directory, and returns the receipt it recorded. The
// clock is frozen before the chain's expiry so the freshness check passes.
func captureAt(t *testing.T, stateDir, chain string) receipt.Receipt {
	t.Helper()
	res := runSession(t, sessionOpts{
		stateDir: stateDir,
		chain:    chain,
		now:      FixedClock(time.Unix(chainTestExp-3600, 0).UTC(), time.Second),
		lines:    []string{toolsCallLine(`1`, "orders.search", `{"query":"a"}`)},
	})
	if res.err != nil {
		t.Fatalf("proxy: %v (stderr %s)", res.err, res.stderr)
	}
	rs, envs := spooledReceipts(t, res.spoolDir)
	if len(rs) != 1 {
		t.Fatalf("%d receipts, want 1", len(rs))
	}
	schemaValidate(t, envs[0].Payload)
	return rs[0]
}

// TestVerificationAtCapture is the capture-time half: the proxy runs
// aat.Verify on the chain it forwards and writes the real per-hop result
// into the receipt. With a login behind it and signed hops in front of it,
// `verified` is what the record says — and it says it because something was
// checked (Q18).
func TestVerificationAtCapture(t *testing.T) {
	stateDir := t.TempDir()
	login := loginInto(t, stateDir)
	chain := marshalChain(t, mintTestChain(t, login))

	r := captureAt(t, stateDir, chain)
	if r.Authority == nil || len(r.Authority.Chain) != 2 {
		t.Fatalf("receipt does not embed the chain whole: %+v", r.Authority)
	}
	hops := r.Authority.Chain
	if hops[0].Verification.Status != "verified" || hops[0].Verification.Method != aat.MethodRootOIDC {
		t.Fatalf("root hop verification = %+v", hops[0].Verification)
	}
	if hops[1].Verification.Status != "verified" || hops[1].Verification.Method != aat.MethodHopJWS {
		t.Fatalf("hop 1 verification = %+v", hops[1].Verification)
	}
	if hops[0].Verification.EvidenceRef != "sha256:"+login.StatementDigest {
		t.Fatalf("root evidence_ref = %q", hops[0].Verification.EvidenceRef)
	}
	if r.Attribution.Verification != "verified" || r.Attribution.Class != "delegated" {
		t.Fatalf("attribution = %+v, want verified/delegated", r.Attribution)
	}
	for i, h := range hops {
		if h.CarriageRoute != CarriageRouteMeta {
			t.Fatalf("hop %d carriage_route = %q", i, h.CarriageRoute)
		}
	}
	// The actor is the deepest hop's key: keys are what the cryptography
	// proves (Q16).
	if r.Actor == nil || r.Actor.JKT != testkeys.ActorHop1().JKT {
		t.Fatalf("actor = %+v", r.Actor)
	}
}

// TestCallerAssertedHopAtCapture: the same chain with its leaf hop arriving
// unsigned. The root still verifies, the leaf is asserted with the
// machine-readable reason, and the receipt rolls up to the weakest hop.
func TestCallerAssertedHopAtCapture(t *testing.T) {
	stateDir := t.TempDir()
	login := loginInto(t, stateDir)
	hops := mintTestChain(t, login)
	hops[1] = hops[1].Unsigned()

	r := captureAt(t, stateDir, marshalChain(t, hops))
	if got := r.Authority.Chain[0].Verification.Status; got != "verified" {
		t.Fatalf("root hop = %s, want verified", got)
	}
	leaf := r.Authority.Chain[1].Verification
	if leaf.Status != "asserted" || leaf.Method != aat.MethodNoSignature {
		t.Fatalf("leaf verification = %+v, want asserted/%s", leaf, aat.MethodNoSignature)
	}
	if r.Attribution.Verification != "asserted" {
		t.Fatalf("rollup = %q, want asserted (the weakest hop)", r.Attribution.Verification)
	}
}

// TestNoRootMaterialAtCapture is the day-zero path (Q21) that must keep
// working: no `behalf login` in the state directory, so the root cannot be
// checked and everything above it stays asserted — with a reason, not a
// shrug.
func TestNoRootMaterialAtCapture(t *testing.T) {
	stateDir := t.TempDir()
	login := loginInto(t, t.TempDir()) // logged in SOMEWHERE ELSE
	chain := marshalChain(t, mintTestChain(t, login))

	r := captureAt(t, stateDir, chain)
	for i, h := range r.Authority.Chain {
		if h.Verification.Status != "asserted" {
			t.Fatalf("hop %d = %s, want asserted with no login material", i, h.Verification.Status)
		}
	}
	if got := r.Authority.Chain[0].Verification.Method; got != aat.MethodNoRootMaterial {
		t.Fatalf("root method = %q, want %q", got, aat.MethodNoRootMaterial)
	}
	if got := r.Authority.Chain[1].Verification.Method; got != aat.MethodParentUnverified {
		t.Fatalf("hop 1 method = %q, want %q", got, aat.MethodParentUnverified)
	}
	if r.Attribution.Verification != "asserted" {
		t.Fatalf("rollup = %q, want asserted", r.Attribution.Verification)
	}
}

// TestBrokenChainIsRecordedNotRejected (Q45): a chain whose leaf was minted
// under a key the parent never delegated to is appended and flagged, never
// dropped, and the call is still forwarded — this is observe mode, not an
// authorization engine.
func TestBrokenChainIsRecordedNotRejected(t *testing.T) {
	stateDir := t.TempDir()
	login := loginInto(t, stateDir)
	hops := mintTestChain(t, login)

	hop2 := testkeys.ActorHop2()
	forged, err := aat.Mint(hop2.Private, nil, aat.MintParams{
		Subject:              hop2.Public,
		MaxDepth:             4,
		AuthorizationDetails: hops[1].Claims.AuthorizationDetails,
		Exp:                  chainTestExp,
		JTI:                  "proxy-test-forged",
		Credential:           hops[1].Claims.Credential,
		RootPrincipalBinding: &receipt.RootBinding{Nonce: hop2.JKT, DeviceJKT: hop2.JKT},
	})
	if err != nil {
		t.Fatal(err)
	}
	hops[1] = forged

	r := captureAt(t, stateDir, marshalChain(t, hops))
	if got := r.Authority.Chain[1].Verification.Status; got != "broken" {
		t.Fatalf("leaf = %s, want broken", got)
	}
	if r.Attribution.Verification != "broken" {
		t.Fatalf("rollup = %q, want broken", r.Attribution.Verification)
	}
	// The evidence reference names the token that failed, so a reader can
	// fetch the thing that did not verify.
	if !strings.HasPrefix(r.Authority.Chain[1].Verification.EvidenceRef, "sha256:") {
		t.Fatalf("broken hop evidence_ref = %q", r.Authority.Chain[1].Verification.EvidenceRef)
	}
}

// TestPreAATMaterialStillTravels: the older carriage shapes load, and every
// hop in them reads asserted-with-no-signature, because that is what they
// are — including the one whose carried material claims `verified`.
func TestPreAATMaterialStillTravels(t *testing.T) {
	stateDir := t.TempDir()
	loginInto(t, stateDir)

	r := captureAt(t, stateDir, testChainJSON())
	if len(r.Authority.Chain) != 2 {
		t.Fatalf("%d hops embedded, want 2", len(r.Authority.Chain))
	}
	for i, h := range r.Authority.Chain {
		if h.Verification.Status != "asserted" || h.Verification.Method != aat.MethodNoSignature {
			t.Fatalf("hop %d verification = %+v, want asserted/%s", i, h.Verification, aat.MethodNoSignature)
		}
	}
	if r.Attribution.Verification != "asserted" {
		t.Fatalf("rollup = %q", r.Attribution.Verification)
	}
}
