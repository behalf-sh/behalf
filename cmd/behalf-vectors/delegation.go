package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// Delegation-chain vectors (ENG-38).
//
// The integrity vectors are generated from the demo fixture, whose hops are
// deliberately synthetic — `par_hash` there is a made-up digest and
// `evidence_ref` is a `jkt:` reference, because those fixtures predate any
// hop token being retained at all. They cannot exercise the chain path.
//
// So these are minted for the purpose, with `aat.Mint`, which is
// deterministic: no clock, no randomness, claims marshaled in declaration
// order. The same seeds produce the same bytes forever, which is what a vector
// corpus requires.
//
// The broken variants are hand-forged rather than minted, because `Mint`
// refuses to produce an unsound chain — it will not sign a child under the
// wrong key or let a hop raise its own depth budget. That refusal is a feature
// being relied on elsewhere; here it means the adversary's tokens have to be
// built the way an adversary would build them.

const (
	vecChainExp  = 2_000_000_000
	vecParentExp = 1_900_000_000
)

func seedKey(b byte) ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{b}, ed25519.SeedSize))
}

func vecGrant(actions ...string) []map[string]any {
	as := make([]any, len(actions))
	for i, a := range actions {
		as[i] = a
	}
	return []map[string]any{{
		"type":      "sh.behalf/support-desk",
		"actions":   as,
		"locations": []any{"https://desk.demo.internal"},
	}}
}

func vecCredential(kind, id string) receipt.Credential {
	return receipt.Credential{Issuer: "https://desk.demo.internal", Kind: kind, ID: id, Exp: vecChainExp}
}

// soundChain mints a real two-hop chain: a depth-0 root confirming the device
// key, and one delegation above it that narrows nothing but stays inside every
// invariant.
func soundChain() ([]aat.Hop, error) {
	rootKey := seedKey(0x71)
	hopKey := seedKey(0x72)

	root, err := aat.Mint(rootKey, nil, aat.MintParams{
		Subject:              rootKey.Public().(ed25519.PublicKey),
		MaxDepth:             3,
		AuthorizationDetails: vecGrant("tickets.*", "orders.read", "refund.issue"),
		Exp:                  vecChainExp,
		JTI:                  "aat-vec-hop0",
		Credential:           vecCredential("oidc-id-token", "oidc-sub-digest:vec"),
		RootPrincipalBinding: &receipt.RootBinding{
			Nonce:     dsse.JWKFromPublic(rootKey.Public().(ed25519.PublicKey)).Thumbprint(),
			DeviceJKT: dsse.JWKFromPublic(rootKey.Public().(ed25519.PublicKey)).Thumbprint(),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("mint root: %w", err)
	}
	child, err := aat.Mint(rootKey, &root, aat.MintParams{
		Subject:              hopKey.Public().(ed25519.PublicKey),
		AuthorizationDetails: vecGrant("orders.read", "refund.issue"),
		Exp:                  vecParentExp,
		JTI:                  "aat-vec-hop1",
		Credential:           vecCredential("aat-jws", "aat-jws:aat-vec-hop1"),
	})
	if err != nil {
		return nil, fmt.Errorf("mint hop1: %w", err)
	}
	return []aat.Hop{root, child}, nil
}

// forge builds a compact EdDSA JWS over claims, signed by signer. This is the
// adversary's minting function: it applies none of Mint's soundness rules,
// which is the whole point of it existing.
func forge(signer ed25519.PrivateKey, claims aat.Claims) (aat.Hop, error) {
	payload, err := json.Marshal(claims)
	if err != nil {
		return aat.Hop{}, err
	}
	protected, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "aat+jwt", "kid": "forged"})
	if err != nil {
		return aat.Hop{}, err
	}
	b64 := func(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
	signingInput := b64(protected) + "." + b64(payload)
	sig := ed25519.Sign(signer, []byte(signingInput))
	return aat.Hop{Claims: claims, Raw: payload, JWS: signingInput + "." + b64(sig)}, nil
}

// delegationExport builds a one-receipt export whose receipt embeds chain and
// whose header carries the tokens for it.
func delegationExport(chain []aat.Hop) ([]byte, error) {
	emitter := seedKey(0x2a)
	jwk := dsse.JWKFromPublic(emitter.Public().(ed25519.PublicKey))
	jkt := jwk.Thumbprint()

	hops := make([]receipt.Hop, len(chain))
	tokens := map[string]string{}
	for i, h := range chain {
		ref := exportv1.TokenRef(h.JWS)
		hops[i] = receipt.Hop{
			DelDepth:             h.Claims.DelDepth,
			DelMaxDepth:          h.Claims.DelMaxDepth,
			ParHash:              h.Claims.ParHash,
			Cnf:                  h.Claims.Cnf,
			AuthorizationDetails: h.Claims.AuthorizationDetails,
			Exp:                  h.Claims.Exp,
			JTI:                  h.Claims.JTI,
			Credential:           h.Claims.Credential,
			RootPrincipalBinding: h.Claims.RootPrincipalBinding,
			Verification: receipt.Verification{
				Status:      "verified",
				Method:      "aat-jws-ed25519",
				EvidenceRef: ref,
			},
		}
		tokens[ref] = h.JWS
	}

	payload, err := json.Marshal(struct {
		SchemaVersion string             `json:"schema_version"`
		ReceiptID     string             `json:"receipt_id"`
		RunID         string             `json:"run_id"`
		Authority     *receipt.Authority `json:"authority"`
	}{"behalf.sh/receipt/v1", "rcpt_vec_delegation_0", "run_vec_delegation", &receipt.Authority{Chain: hops}})
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	wr, err := exportv1.NewWriterWithTokens(&buf, "behalf.sh/vectors/delegation", []exportv1.HeaderKey{{JKT: jkt, JWK: jwk}}, tokens)
	if err != nil {
		return nil, err
	}
	signer := exportv1.Signer{Private: emitter, KeyID: jkt}
	if err := wr.Append(payload, signer); err != nil {
		return nil, err
	}
	if err := wr.Close(signer); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeDelegation emits the intact chain vector and one vector per broken
// invariant class. Each broken case is a file whose *record* is perfectly
// intact — every integrity check passes on it — so the only thing a verifier
// can find is the delegation break. That is what makes them chain vectors
// rather than more tamper vectors.
func writeDelegation(dir string) error {
	sound, err := soundChain()
	if err != nil {
		return err
	}
	root, child := sound[0], sound[1]

	intact, err := delegationExport(sound)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "intact_delegation.jsonl"), intact, 0o644); err != nil {
		return err
	}

	// Each variant re-forges the child hop with exactly one invariant broken,
	// leaving every other property sound, so a finding names one cause.
	variant := func(mutate func(c *aat.Claims), signer ed25519.PrivateKey) ([]byte, error) {
		claims := child.Claims
		mutate(&claims)
		forged, err := forge(signer, claims)
		if err != nil {
			return nil, err
		}
		return delegationExport([]aat.Hop{root, forged})
	}

	cases := []struct {
		name     string
		build    func() ([]byte, error)
		expected expectedResult
	}{
		{
			// I1: signed by a key the parent never confirmed. Every claim is
			// unchanged; only the signer is wrong.
			name:     "tampered_delegation_i1_authority",
			build:    func() ([]byte, error) { return variant(func(*aat.Claims) {}, seedKey(0x99)) },
			expected: expectedResult{1, []expectedClass{{"delegation", 0}}},
		},
		{
			// I2: del_depth does not increment its parent's.
			name: "tampered_delegation_i2_depth",
			build: func() ([]byte, error) {
				return variant(func(c *aat.Claims) { c.DelDepth = 3 }, seedKey(0x71))
			},
			expected: expectedResult{1, []expectedClass{{"delegation", 0}}},
		},
		{
			// I3: the hop outlives the authority it came from.
			name: "tampered_delegation_i3_expiry",
			build: func() ([]byte, error) {
				return variant(func(c *aat.Claims) { c.Exp = vecChainExp + 1 }, seedKey(0x71))
			},
			expected: expectedResult{1, []expectedClass{{"delegation", 0}}},
		},
		{
			// I5: par_hash names some other token instance.
			name: "tampered_delegation_i5_linkage",
			build: func() ([]byte, error) {
				return variant(func(c *aat.Claims) {
					c.ParHash = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
				}, seedKey(0x71))
			},
			expected: expectedResult{1, []expectedClass{{"delegation", 0}}},
		},
	}

	for _, c := range cases {
		data, err := c.build()
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		cdir := filepath.Join(dir, c.name)
		if err := os.MkdirAll(cdir, 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(cdir, "file.jsonl"), data, 0o644); err != nil {
			return err
		}
		if err := writeJSON(filepath.Join(cdir, "expected.json"), c.expected); err != nil {
			return err
		}
	}
	return nil
}
