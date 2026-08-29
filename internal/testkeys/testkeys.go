// Package testkeys provides deterministic Ed25519 keys for tests, fixtures,
// and test vectors.
//
// TEST-ONLY. Every key here is derived from a fixed, public seed and offers
// no security whatsoever. These keys must never sign anything outside
// testdata, fixtures, and unit tests (export-format-v1.md §3: "deterministic
// test keys derived from fixed 32-byte seeds; never used outside tests").
package testkeys

import (
	"crypto/ed25519"
	"crypto/sha256"

	"github.com/behalf-sh/behalf/internal/dsse"
)

// seedDomain is the fixed derivation domain. Changing it changes every test
// key, every fixture signature, and every vector — it is part of the frozen
// fixture determinism.
const seedDomain = "behalf.sh/testkeys/v1\n"

// Key is a deterministic Ed25519 test key.
type Key struct {
	Name    string
	Seed    [32]byte // the fixed 32-byte seed the key derives from
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	JWK     dsse.JWK
	JKT     string // RFC 7638 thumbprint of JWK
}

// New derives the deterministic test key for a label:
// seed = SHA-256(seedDomain + label), key = ed25519.NewKeyFromSeed(seed).
func New(label string) Key {
	seed := sha256.Sum256([]byte(seedDomain + label))
	priv := ed25519.NewKeyFromSeed(seed[:])
	pub := priv.Public().(ed25519.PublicKey)
	jwk := dsse.JWKFromPublic(pub)
	return Key{
		Name:    label,
		Seed:    seed,
		Private: priv,
		Public:  pub,
		JWK:     jwk,
		JKT:     jwk.Thumbprint(),
	}
}

// Emitter is the demo mcp-proxy emitter key used by the fixture runs. It
// signs every fixture leaf and the fixture heads.
func Emitter() Key { return New("emitter-mcp-proxy-1") }

// HeadSigner is a second key used by the tiny vector export so the corpus
// exercises multi-key headers.
func HeadSigner() Key { return New("head-signer-1") }

// ActorRoot, ActorHop1 and ActorHop2 are the delegation-chain hop keys
// embedded (as public JWKs only) in fixture receipts' authority.chain cnf
// claims. ActorRoot is the human's device key — the depth-0 root the OIDC
// nonce binds (D5); the display name that goes with it lives in the CLI's
// local alias map, never in a receipt (Q16, Q40).
func ActorRoot() Key { return New("actor-root-device-1") }

// ActorHop1 is the depth-1 delegated agent key (the orchestrator).
func ActorHop1() Key { return New("actor-hop1-agent-1") }

// ActorHop2 is the depth-2 sub-agent key (the leaf actor of the demo runs).
// In run_9f2a this hop is signature-verified; in run_c71e the same key is
// only caller-asserted, which is the whole point of the `behalf why` demo.
func ActorHop2() Key { return New("actor-hop2-agent-1") }
