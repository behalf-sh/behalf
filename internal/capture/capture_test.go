package capture

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// The primitives here are checked against internal/proxy's real output in
// internal/hooks/crosssurface_test.go — that is the test that would catch the
// lift drifting. What is covered here is the behaviour that has branches:
// concurrent counter allocation, argument-schema normalisation, and the
// attribution rollup's shape rules.

// TestNextCounterIsAtomicUnderConcurrency: the counter is the Q48 integrity
// primitive, so two goroutines (standing in for two capture surfaces) must
// never receive the same value.
func TestNextCounterIsAtomicUnderConcurrency(t *testing.T) {
	dir := t.TempDir()
	if err := identity.EnsureDir(dir); err != nil {
		t.Fatal(err)
	}
	const n = 64
	out := make([]int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			v, err := NextCounter(dir)
			if err != nil {
				t.Error(err)
				return
			}
			out[i] = v
		}(i)
	}
	wg.Wait()
	seen := map[int]bool{}
	for _, v := range out {
		if seen[v] {
			t.Fatalf("counter %d was allocated twice", v)
		}
		seen[v] = true
	}
	for i := 0; i < n; i++ {
		if !seen[i] {
			t.Fatalf("counter %d was never allocated: the sequence has a gap", i)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, CounterLockFile)); err != nil {
		t.Fatalf("no lock file at %s: the allocation was not serialised across processes", CounterLockFile)
	}
}

func TestNormalizedArgSchema(t *testing.T) {
	cases := []struct{ in, want string }{
		{`{"b":1,"a":2}`, "$.a,$.b"}, // sorted, so call order cannot change the key
		{`{}`, ""},                   // no fields
		{``, ""},                     // absent arguments
		{`[1,2]`, ""},                // non-object
		{`{"a":{"deep":1}}`, "$.a"},  // top level only
		{`{"a b":1}`, "$.a b"},       // names are taken verbatim
		{`{"z":1,"a":2,"m":3}`, "$.a,$.m,$.z"},
	}
	for _, tc := range cases {
		if got := NormalizedArgSchema([]byte(tc.in)); got != tc.want {
			t.Fatalf("NormalizedArgSchema(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// The same call with reordered keys hashes the same step_key; a call with
	// a different argument SHAPE does not (Q85).
	same := StepKey("t", []byte(`{"a":1,"b":2}`), 0) == StepKey("t", []byte(`{"b":9,"a":8}`), 0)
	if !same {
		t.Fatal("key order changed the step key")
	}
	if StepKey("t", []byte(`{"a":1}`), 0) == StepKey("t", []byte(`{"a":1,"c":2}`), 0) {
		t.Fatal("a changed argument shape did not change the step key")
	}
	if StepKey("t", []byte(`{"a":1}`), 0) == StepKey("t", []byte(`{"a":1}`), 1) {
		t.Fatal("the causal ordinal does not reach the step key")
	}
}

func TestIntentDigestSeparatesNameFromArgs(t *testing.T) {
	// The newline is load-bearing: without it, ("ab", "c") and ("a", "bc")
	// would collide, and two different crossings would share an anchor.
	if IntentDigest("ab", []byte("c")) == IntentDigest("a", []byte("bc")) {
		t.Fatal("the name and the arguments are not separated in the digest")
	}
}

func TestTraceIDFromTraceparent(t *testing.T) {
	const good = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	if got := TraceIDFromTraceparent(good); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("got %q", got)
	}
	for _, bad := range []string{
		"",
		"nonsense",
		"00-tooshort-00f067aa0ba902b7-01",
		"00-00000000000000000000000000000000-00f067aa0ba902b7-01", // the all-zero trace id is invalid
		"00-4bf92f3577b34da6a3ce929d0e0e473G-00f067aa0ba902b7-01", // not hex
	} {
		if got := TraceIDFromTraceparent(bad); got != "" {
			t.Fatalf("TraceIDFromTraceparent(%q) = %q, want the rung dropped", bad, got)
		}
	}
}

func TestAuthorityShapeRules(t *testing.T) {
	// No chain: nothing was carried, so nothing is claimed.
	auth, attr := Authority(nil, nil, "route")
	if auth != nil || attr.Verification != "asserted" || attr.Class != "unattributed" {
		t.Fatalf("empty chain gave %+v / %+v", auth, attr)
	}

	root := hop(0, nil)
	// One hop is `direct`; two is `delegated`; a triggered root is
	// `autonomous` regardless of length (Q14).
	if _, a := Authority([]aat.Hop{root}, results(1), "r"); a.Class != "direct" {
		t.Fatalf("one hop classed %q", a.Class)
	}
	if _, a := Authority([]aat.Hop{root, hop(1, nil)}, results(2), "r"); a.Class != "delegated" {
		t.Fatalf("two hops classed %q", a.Class)
	}
	trig := hop(0, &receipt.Trigger{Kind: "schedule", DescriptorDigest: zeros})
	if _, a := Authority([]aat.Hop{trig, hop(1, nil)}, results(2), "r"); a.Class != "autonomous" {
		t.Fatalf("a triggered root classed %q", a.Class)
	}

	// Every hop carries the carriage route, and a hop with no result records
	// `asserted` with a reason rather than an empty status the schema rejects.
	got, attr := Authority([]aat.Hop{root, hop(1, nil)}, nil, "route-x")
	if len(got.Chain) != 2 {
		t.Fatalf("chain length %d", len(got.Chain))
	}
	for i, h := range got.Chain {
		if h.CarriageRoute != "route-x" {
			t.Fatalf("hop %d carriage_route = %q", i, h.CarriageRoute)
		}
		if h.Verification.Status != aat.StatusAsserted || h.Verification.Method == "" {
			t.Fatalf("hop %d verification = %+v, want asserted with a reason", i, h.Verification)
		}
	}
	if attr.Verification != "asserted" {
		t.Fatalf("rollup = %q", attr.Verification)
	}
}

func TestActorNeedsAKeyTheChainProves(t *testing.T) {
	if a := Actor(nil, map[string]string{"x": "y"}); a != nil {
		t.Fatal("an actor was invented with no chain")
	}
	// A hop whose cnf key is not one v1 proves yields no thumbprint, so no
	// actor — the schema requires actor.jkt whenever actor is present.
	auth := &receipt.Authority{Chain: []receipt.Hop{{Cnf: receipt.Cnf{JWK: map[string]any{"kty": "RSA"}}}}}
	if a := Actor(auth, nil); a != nil {
		t.Fatalf("an actor was minted from an unsupported key: %+v", a)
	}
	auth.Chain[0].Credential.JKT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	a := Actor(auth, map[string]string{"agent_id": "agt_1", "empty": ""})
	if a == nil || a.EmitterToActor != "asserted" {
		t.Fatalf("actor = %+v", a)
	}
	if a.Labels["agent_id"] != "agt_1" {
		t.Fatalf("labels = %v", a.Labels)
	}
	if _, ok := a.Labels["empty"]; ok {
		t.Fatal("an empty label was recorded as if it were a fact")
	}
}

func TestSlotCommitsToTheBytes(t *testing.T) {
	store := cas.New(t.TempDir())
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"order_id":"ord_5518","amount":"1200.00"}`)
	s, err := Slot(store, "input", raw, "application/json")
	if err != nil {
		t.Fatal(err)
	}
	if s.Digest != cas.Digest(raw) || s.Ref != "sha256:"+s.Digest {
		t.Fatalf("slot = %+v", s)
	}
	if s.Custody != "customer-held" || s.State != "present" || s.Size != len(raw) {
		t.Fatalf("slot = %+v", s)
	}
	if s.Manifest == nil || len(s.Manifest.Fields) != 2 {
		t.Fatalf("no field-digest manifest: %+v", s.Manifest)
	}
	back, err := store.Get(s.Digest)
	if err != nil || string(back) != string(raw) {
		t.Fatalf("the store does not hold the committed bytes: %v", err)
	}
	// A non-JSON slot gets a whole-blob digest and no manifest, per the
	// schema's "non-JSON gets whole-blob only" rule.
	s2, err := Slot(store, "raw", []byte("not json"), "text/plain")
	if err != nil {
		t.Fatal(err)
	}
	if s2.Manifest != nil {
		t.Fatal("a non-JSON payload got a field manifest")
	}
}

func TestIDSourceMintsSortableULIDs(t *testing.T) {
	ids := NewIDSource(nil)
	base := time.Date(2026, 8, 27, 10, 0, 0, 0, time.UTC)
	a := ids.ULIDAt(base)
	b := ids.ULIDAt(base.Add(time.Second))
	if len(a) != 26 || len(b) != 26 {
		t.Fatalf("ulids %q %q", a, b)
	}
	if a >= b {
		t.Fatalf("ULIDs do not sort by mint time: %q >= %q", a, b)
	}
}

const zeros = "0000000000000000000000000000000000000000000000000000000000000000"

func hop(depth int, trigger *receipt.Trigger) aat.Hop {
	return aat.Hop{Claims: aat.Claims{
		DelDepth:    depth,
		DelMaxDepth: 4,
		ParHash:     zeros,
		Cnf:         receipt.Cnf{JWK: map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "AAAA"}},
		Exp:         4102444800,
		JTI:         "jti",
		Trigger:     trigger,
	}}
}

func results(n int) []aat.HopResult {
	out := make([]aat.HopResult, n)
	for i := range out {
		out[i] = aat.HopResult{Status: aat.StatusAsserted, Method: aat.MethodNoSignature}
	}
	return out
}

// TestEveryEvidenceRefResolves is the property `evidence_ref` was always
// supposed to have and never did: a reader handed a receipt can fetch the
// bytes the hop's verification was decided on and re-run the check.
//
// Before capture.RetainHopTokens existed, every capture surface wrote
// `sha256:<digest of the hop's compact JWS>` into each hop and stored no such
// blob. The reference dangled, so the only record of whether a delegation hop's
// signature verified was behalf's own capture-time verdict, embedded in a
// receipt — a claim about a check with the evidence for it thrown away.
func TestEveryEvidenceRefResolves(t *testing.T) {
	root, hop1 := testkeys.ActorRoot(), testkeys.ActorHop1()
	const exp = 4102444800

	h0, err := aat.Mint(root.Private, nil, aat.MintParams{
		Subject:  root.Public,
		MaxDepth: 4,
		AuthorizationDetails: []map[string]any{{
			"type": "sh.behalf/test", "actions": []any{"orders.*", "refund.issue"},
		}},
		Exp: exp,
		JTI: "aat-test-hop0",
		Credential: receipt.Credential{
			Issuer: "https://idp.example", Kind: "oidc-id-token",
			ID: "oidc-sub-digest:deadbeef", Exp: exp, JKT: root.JKT,
		},
		RootPrincipalBinding: &receipt.RootBinding{Nonce: root.JKT, DeviceJKT: root.JKT},
	})
	if err != nil {
		t.Fatalf("mint root hop: %v", err)
	}
	h1, err := aat.Mint(root.Private, &h0, aat.MintParams{
		Subject: hop1.Public,
		AuthorizationDetails: []map[string]any{{
			"type": "sh.behalf/test", "actions": []any{"refund.issue"},
		}},
		Exp: exp,
		JTI: "aat-test-hop1",
		Credential: receipt.Credential{
			Issuer: "https://desk.example", Kind: "aat-jws",
			ID: "aat-jws:aat-test-hop1", Exp: exp, JKT: hop1.JKT,
		},
	})
	if err != nil {
		t.Fatalf("mint hop 1: %v", err)
	}
	chain := []aat.Hop{h0, h1}

	store := cas.New(t.TempDir())
	if err := store.Ensure(); err != nil {
		t.Fatal(err)
	}
	if err := RetainHopTokens(store, chain); err != nil {
		t.Fatalf("retain hop tokens: %v", err)
	}

	auth, _ := Authority(chain, aat.Verify(chain, aat.RootMaterial{}), "test")
	if auth == nil || len(auth.Chain) != 2 {
		t.Fatalf("authority = %+v, want two hops", auth)
	}
	for i, hop := range auth.Chain {
		ref := hop.Verification.EvidenceRef
		if ref == "" {
			t.Fatalf("hop %d carries no evidence_ref", i)
		}
		digest, ok := strings.CutPrefix(ref, "sha256:")
		if !ok {
			t.Fatalf("hop %d: evidence_ref %q is not a sha256 reference", i, ref)
		}
		got, err := store.Get(digest)
		if err != nil {
			t.Fatalf("hop %d: evidence_ref %s does not resolve in the customer's store: %v", i, ref, err)
		}
		// And what it resolves to is the token itself, not something that
		// merely hashes right: the signature must verify under the key the
		// hop beneath it confirmed.
		if string(got) != chain[i].JWS {
			t.Fatalf("hop %d: the stored blob is not the hop's token", i)
		}
	}

	// The unsigned case is the one that must NOT gain a dangling reference:
	// nothing backs a caller-asserted hop, so there is no evidence to fetch
	// and none is claimed.
	unsigned := []aat.Hop{h0.Unsigned()}
	if err := RetainHopTokens(store, unsigned); err != nil {
		t.Fatalf("retain over an unsigned chain: %v", err)
	}
	uauth, _ := Authority(unsigned, aat.Verify(unsigned, aat.RootMaterial{}), "test")
	if ref := uauth.Chain[0].Verification.EvidenceRef; ref != "" {
		t.Fatalf("an unsigned hop claims evidence at %q", ref)
	}
}
