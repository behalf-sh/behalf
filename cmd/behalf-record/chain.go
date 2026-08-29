package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/oidctest"
	"github.com/behalf-sh/behalf/internal/proxy"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// checkLoopback fails early, and in a sentence, when this machine will not let
// the recorder bind a loopback socket.
//
// The recording mints its identity root through a real OIDC code flow against
// an in-process provider (see login below), and that provider is an
// `httptest.NewServer` — which listens on 127.0.0.1 and **panics** rather than
// returning an error when the bind is refused. Without this check the operator
// sees a twenty-line Go stack trace, from the one command the runbook names as
// the recovery move on a live call.
//
// This is not the airplane-mode case, and the distinction is worth keeping
// straight because the demo makes a claim about it out loud. Airplane mode
// disables the radios; `lo0` is unaffected, the bind succeeds, and the whole
// demo runs — verified 28 Aug 2026 under a sandbox denying all outbound
// traffic except loopback (ENG-21). What refuses a loopback bind is a
// restrictive local policy: an endpoint agent, a locked-down corporate image,
// or a sandbox denying `network*` outright. That is a plausible machine to be
// handed by a security-conscious customer, and it is exactly the machine on
// which someone tests a claim that the tool makes no network calls.
//
// Everything downstream of the recording is genuinely socket-free: `runs`,
// `diff`, `why`, `export --html`, `behalf-log export` and both modes of
// `behalf-verify` all pass with the network denied entirely.
func checkLoopback() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("the recorder needs to bind a loopback socket and this machine refused: %w\n"+
			"  It mints the demo's identity root through a real OIDC flow against an in-process\n"+
			"  provider on 127.0.0.1. Nothing leaves the machine — airplane mode is fine — but a\n"+
			"  local policy that blocks listening sockets will stop it.\n"+
			"  Already-recorded state needs none of this: runs, diff, why, export and verify all\n"+
			"  work with the network off entirely", err)
	}
	return ln.Close()
}

// The delegation chain the recording carries: a human root, an
// orchestrator, and the support-desk sub-agent that performs the calls
// (Q10, Q11, D4). The proxy injects it into `params._meta` under
// `sh.behalf/chain` on every tools/call, verifies it at capture (Q18), and
// embeds it whole in every receipt.
//
// # Two variants, and why the difference is cryptographic
//
// The runs differ in the chain, and only in the chain's last hop:
//
//	run A   root -> orchestrator -> sub-agent, all three signed and
//	        attenuating; all three verify.
//	run B   byte-identical claims, except the sub-agent hop arrives with NO
//	        SIGNATURE — an agent claiming to act as the human, which is the
//	        realistic failure and the one the demo is about.
//
// Nothing in either receipt is hand-set. Run A says `verified` because
// `aat.Verify` checked three signatures, a par_hash linkage, the depth and
// expiry invariants and the attenuation of every grant, and they held. Run B
// says `asserted` on its leaf because there was no signature to check, and
// `behalf why` renders exactly that:
//
//	actor "alice@acme.com" is caller-asserted. no signature.
//
// A demo whose contrast is a field somebody typed proves only that somebody
// can type. This one is the difference between a token and no token.
//
// # Where the root comes from
//
// From a real login. The recorder runs `behalf login`'s own flow — OAuth 2.1
// authorization-code with PKCE, a real token exchange, a real IdP-signed ID
// token whose nonce is jkt(device key) — against the in-repo fake provider
// (internal/oidctest), headlessly. The ID token, the JWKS snapshot and the
// device-key-signed root delegation statement land in the customer-held
// store, and the proxy's depth-0 predicate re-checks all three offline.
//
// Nothing here fabricates an ID token, and nothing hand-writes a hop's
// verification status.

// Demo identity constants. The issuer is a NAME, not an address: nothing
// listens there, and oidctest.Client() routes it to the local fake provider.
const (
	DemoIssuer   = "https://login.demo.internal"
	DemoClientID = "behalf-desk-demo"
	DemoSubject  = "u-4417-alice"
)

// loginLead is how long before the first run the human logged in. A demo in
// which the login and the first tool call share a timestamp reads as a lie
// about what happened.
const loginLead = time.Hour

// chainExp is the fixed per-hop expiry on every demo hop:
// 2026-08-27T00:00:00Z — after both runs, so the capture-time freshness
// check passes and the recording is about delegation rather than about
// expiry.
const chainExp = int64(1787788800)

// chainMaxDepth is del_max_depth on the root delegation: three hops, and no
// room for a fourth.
const chainMaxDepth = 3

// refundLimit is the root grant's ceiling. It is $100.00, which both runs'
// chains carry and which the $1200.00 run exceeds — the scope excess `why`
// computes at read time from these raw grants (Q11, Q13). It is never
// stamped into the record as a conclusion.
const refundLimit = "100.00"

// login performs the headless OIDC flow into opts.StateDir and returns what
// it persisted.
//
// Determinism (D9.2, Q92): the provider signs with an Ed25519 key derived
// from --seed, stamps a fixed clock into the ID token, and advertises a
// stable issuer name — so the ID token bytes, their digest, the root
// delegation statement and every receipt field derived from them are the
// same on every recording. --live opts out of the fixed clock, as it does
// everywhere else.
//
// The device key is the frozen demo key from internal/testkeys, for the same
// reason the emitter key is (see prepareState): a recording rooted in a
// random key is not reproducible and cannot be named in the checked-in alias
// map that makes `behalf why` read like the product. A real `behalf login`
// generates a fresh device key per login and the CLI never passes one.
func login(opts Options) (*oidclogin.Result, time.Time, error) {
	loginAt := opts.Start.Add(-loginLead).UTC()
	if opts.Live {
		loginAt = time.Now().UTC()
	}
	if err := checkLoopback(); err != nil {
		return nil, time.Time{}, err
	}
	idp := oidctest.NewDeterministic(oidctest.DeterministicOptions{
		Issuer:   DemoIssuer,
		Seed:     opts.Seed + "/idp",
		Sub:      DemoSubject,
		At:       loginAt,
		AuthTime: loginAt.Add(-5 * time.Minute).Unix(),
		AMR:      []string{"pwd", "mfa"},
	})
	defer idp.Close()

	client := idp.Client()
	device := testkeys.ActorRoot()
	cfg := oidclogin.Config{
		Issuer:     DemoIssuer,
		ClientID:   DemoClientID,
		Dir:        opts.StateDir,
		NoBrowser:  true,
		HTTPClient: client,
		Now:        func() time.Time { return loginAt },
		DeviceKey: &identity.Key{
			Private: device.Private, Public: device.Public, JWK: device.JWK, JKT: device.JKT,
		},
		// The "user" approves instantly: GET the authorization URL and let
		// the provider 302 back to the flow's own loopback listener.
		OnAuthURL: func(u string) { go followRedirect(client, u) },
	}
	if !opts.Live {
		cfg.Entropy = proxy.FixedEntropy(opts.Seed + "/login")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	res, err := oidclogin.Login(ctx, cfg)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("headless login against the in-repo fake IdP: %w", err)
	}
	return res, loginAt, nil
}

func followRedirect(c *http.Client, u string) {
	resp, err := c.Get(u)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
}

// mintChain builds the three signed hops of run A from the login material.
func mintChain(res *oidclogin.Result, loginAt time.Time) ([]aat.Hop, error) {
	root, hop1, hop2 := testkeys.ActorRoot(), testkeys.ActorHop1(), testkeys.ActorHop2()
	idTokenExp := loginAt.Add(oidctest.TokenTTL).Unix()

	// Depth 0: the human. Signed by the device key the OIDC nonce bound,
	// carrying that binding and the reference to the customer-held ID token
	// (D5, Q22).
	h0, err := aat.Mint(root.Private, nil, aat.MintParams{
		Subject:  root.Public,
		MaxDepth: chainMaxDepth,
		AuthorizationDetails: []map[string]any{{
			"type":      "sh.behalf/support-desk",
			"intent":    "resolve ticket tk_4437",
			"actions":   []any{"tickets.*", "orders.*", "refund.issue"},
			"locations": []any{"https://desk.demo.internal"},
			"privileges": []any{map[string]any{
				"operation": "refund.issue",
				"limit":     map[string]any{"amount": refundLimit, "currency": "USD"},
			}},
		}},
		Exp: chainExp,
		JTI: "aat-desk-demo-hop0",
		Credential: receipt.Credential{
			Issuer:   res.Issuer,
			Kind:     "oidc-id-token",
			ID:       "oidc-sub-digest:" + res.SubDigest,
			Exp:      idTokenExp,
			JKT:      res.DeviceJKT,
			AuthTime: loginAt.Add(-5 * time.Minute).Unix(),
			AMR:      []string{"pwd", "mfa"},
		},
		RootPrincipalBinding: &receipt.RootBinding{
			Nonce:      res.DeviceJKT, // nonce == jkt(device_pubkey) (D5)
			DeviceJKT:  res.DeviceJKT,
			IDTokenRef: res.IDTokenDigest,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mint the root hop: %w", err)
	}

	// Depth 1: the orchestrator, signed by the device key, narrowed to the
	// order and refund surface.
	h1, err := aat.Mint(root.Private, &h0, aat.MintParams{
		Subject: hop1.Public,
		AuthorizationDetails: []map[string]any{{
			"type":      "sh.behalf/support-desk",
			"actions":   []any{"orders.*", "refund.issue"},
			"locations": []any{"https://desk.demo.internal"},
			"privileges": []any{map[string]any{
				"operation": "refund.issue",
				"limit":     map[string]any{"amount": refundLimit, "currency": "USD"},
			}},
		}},
		Exp: chainExp,
		JTI: "aat-desk-demo-hop1",
		Credential: receipt.Credential{
			Issuer: "https://desk.demo.internal",
			Kind:   "aat-jws",
			ID:     "aat-jws:aat-desk-demo-hop1",
			Exp:    chainExp,
			JKT:    hop1.JKT,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mint the orchestrator hop: %w", err)
	}

	// Depth 2: the sub-agent that actually issues the refund, signed by the
	// orchestrator and narrowed to that one action.
	h2, err := aat.Mint(hop1.Private, &h1, aat.MintParams{
		Subject: hop2.Public,
		AuthorizationDetails: []map[string]any{{
			"type":      "sh.behalf/support-desk",
			"actions":   []any{"refund.issue"},
			"locations": []any{"https://desk.demo.internal"},
			"privileges": []any{map[string]any{
				"operation": "refund.issue",
				"limit":     map[string]any{"amount": refundLimit, "currency": "USD"},
			}},
		}},
		Exp: chainExp,
		JTI: "aat-desk-demo-hop2",
		Credential: receipt.Credential{
			Issuer: "https://desk.demo.internal",
			Kind:   "aat-jws",
			ID:     "aat-jws:aat-desk-demo-hop2",
			Exp:    chainExp,
			JKT:    hop2.JKT,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mint the sub-agent hop: %w", err)
	}
	return []aat.Hop{h0, h1, h2}, nil
}

// chainVariants renders the two carriage files: run A fully signed, run B
// identical but for its leaf hop's missing signature.
func chainVariants(res *oidclogin.Result, loginAt time.Time) (runA, runB []byte, err error) {
	signed, err := mintChain(res, loginAt)
	if err != nil {
		return nil, nil, err
	}
	runA, err = aat.MarshalChain(signed)
	if err != nil {
		return nil, nil, err
	}

	// The one divergence: the same claim set, arriving with nothing behind
	// it. Strip the token, keep the claims — which is precisely what an
	// agent asserting the human's authority looks like on the wire.
	asserted := make([]aat.Hop, len(signed))
	copy(asserted, signed)
	asserted[len(asserted)-1] = asserted[len(asserted)-1].Unsigned()
	runB, err = aat.MarshalChain(asserted)
	if err != nil {
		return nil, nil, err
	}
	return runA, runB, nil
}
