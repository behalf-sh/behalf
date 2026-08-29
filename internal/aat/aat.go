// Package aat mints and verifies the delegation chain: AAT-shaped hop
// tokens per `draft-niyikiza-oauth-attenuating-agent-tokens-01`, adopted as
// specified rather than reinvented (D8.1, Q95).
//
// # The token
//
// One hop is one compact JWS (RFC 7515), EdDSA over Ed25519:
//
//	BASE64URL(UTF8(protected)) "." BASE64URL(payload) "." BASE64URL(sig)
//
// with protected header `{"alg":"EdDSA","typ":"aat+jwt","kid":<parent jkt>}`
// and a payload that is exactly the frozen per-hop field set of
// receipt-schema-v1.md §7 — `del_depth`, `del_max_depth`, `par_hash`,
// `cnf.jwk`, raw RFC 9396 `authorization_details`, `exp`, `jti`,
// `credential`, plus at depth 0 the `root_principal_binding` behalf
// extension (Q11) and, for autonomous roots, `trigger` (Q14).
//
// The three §7 members that are NOT claims are the ones behalf writes after
// checking rather than the ones a caller asserts: `verification`,
// `carriage_route` and `attenuation_flag`. A token that carried its own
// verification status would be a self-graded exam.
//
// # The signing rule, and par_hash
//
// Each hop is signed by its PARENT's key — the key the parent hop confirmed
// in its own `cnf.jwk`. The depth-0 hop has no parent, so it is signed by
// the device key `behalf login` bound, which is also the key it confirms:
// the root is self-signed, and what makes it evidence is not that signature
// but the OIDC nonce binding underneath it (D5).
//
// `par_hash` is the DAG edge (Q10), defined here as:
//
//	par_hash = lowercase-hex SHA-256 over the parent hop's compact JWS,
//	           taken as the ASCII bytes of all three dot-joined segments
//	           (protected "." payload "." signature) — the token exactly as
//	           it travels.
//
// At depth 0 there is no parent and the value is the all-zero sentinel
// (oidclogin.RootParHash), which the frozen schema requires the field to
// carry anyway.
//
// Hashing the parent's *signature* as well as its claims is the load-bearing
// choice: re-parenting a hop under a different parent — even one asserting
// byte-identical claims under a different key — changes the parent's
// signature, so the child's par_hash no longer names it and the chain reads
// `broken`. TestReparentedHopIsBroken pins that.
//
// # What this package does not do
//
// It runs no network. Depth 0 reuses oidclogin's three offline checks
// verbatim (Q17, D5); it does not reimplement them. Attenuation reuses
// internal/why's comparator (Q13); there is no second comparator here, and
// there is no bespoke normalization layer.
package aat

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/oidclogin"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/why"
)

// RootParHash is par_hash at depth 0: the explicit no-parent sentinel, the
// same constant `behalf login` mints into its root receipt.
const RootParHash = oidclogin.RootParHash

// Alg and Typ are the JWS header values every hop token carries. EdDSA over
// Ed25519 is the only algorithm v1 mints or accepts: the four v1 keys are
// all Ed25519 (Q69), and an algorithm agility surface nobody needs is an
// attack surface nobody wanted.
const (
	Alg = "EdDSA"
	Typ = "aat+jwt"
)

// ChainSchemaVersion is the projection key on carried chain material — the
// bytes that travel in `params._meta["sh.behalf/chain"]` (Q15, D4).
const ChainSchemaVersion = "behalf.sh/aat-chain/v1"

// Claims is one hop's token claim set: the frozen §7 per-hop field set, in
// §7's order. Field order here is serialization order, and the serialized
// bytes are the signed bytes.
type Claims struct {
	DelDepth             int                  `json:"del_depth"`
	DelMaxDepth          int                  `json:"del_max_depth"`
	ParHash              string               `json:"par_hash"`
	Cnf                  receipt.Cnf          `json:"cnf"`
	AuthorizationDetails []map[string]any     `json:"authorization_details"`
	Exp                  int64                `json:"exp"`
	JTI                  string               `json:"jti"`
	Credential           receipt.Credential   `json:"credential"`
	RootPrincipalBinding *receipt.RootBinding `json:"root_principal_binding,omitempty"`
	Trigger              *receipt.Trigger     `json:"trigger,omitempty"`
}

// Hop is one delegation hop as it travels and as it is verified.
//
// Raw is the exact payload bytes the signature covers, kept verbatim: a hop
// parsed off the wire is verified against the bytes that arrived, never
// against a re-marshaling of Claims, because a JSON round-trip that reorders
// or renumbers anything would silently invalidate a valid token (the span
// rule, export-format-v1.md §1.2).
//
// JWS is the compact serialization. An EMPTY JWS is not an error and not a
// forgery: it is the caller-asserted hop — an agent presenting a claim with
// no token behind it. Verify records it as `asserted`, never `verified` and
// never `broken`.
type Hop struct {
	Claims Claims
	Raw    []byte
	JWS    string
}

// Signed reports whether the hop arrived with a token behind it.
func (h Hop) Signed() bool { return h.JWS != "" }

// Unsigned returns a copy of h with its signature stripped: the same claim
// set, arriving caller-asserted. This is the realistic failure the demo's
// run B records — an agent that simply claims to act as the human — and it
// is deliberately constructible, because a product whose failure mode cannot
// be reproduced cannot be shown.
func (h Hop) Unsigned() Hop {
	h.JWS = ""
	return h
}

// JKT returns the RFC 7638 thumbprint of the hop's confirmed key, or "" if
// cnf.jwk is not an Ed25519 OKP key (Q16, Q17).
func (h Hop) JKT() string { return jwkThumbprint(h.Claims.Cnf.JWK) }

// ParHash returns the par_hash value a child must carry to name jws as its
// parent: lowercase-hex SHA-256 over the compact JWS's ASCII bytes, all
// three segments and the two dots included. An empty jws has no par_hash and
// returns "".
func ParHash(jws string) string {
	if jws == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(jws))
	return hex.EncodeToString(sum[:])
}

// MintParams is everything a hop asserts about itself. Depth, max depth and
// par_hash are NOT here: they are derived from the parent, which is what
// makes a minted chain structurally sound by construction.
type MintParams struct {
	// Subject is the hop's own public key. It becomes cnf.jwk, and it is the
	// key the next hop's signature must verify under.
	Subject ed25519.PublicKey
	// MaxDepth sets del_max_depth at depth 0. Above the root it is inherited
	// from the parent and must be left zero or repeated exactly: a hop that
	// could raise its own depth budget would have no budget.
	MaxDepth int
	// AuthorizationDetails is the raw RFC 9396 grant, captured verbatim
	// (Q11). At least one object is required.
	AuthorizationDetails []map[string]any
	// Exp is the per-hop expiry, verbatim (Q11, Q23). Above the root it must
	// not outlive the parent.
	Exp int64
	// JTI is the per-hop token id — the behalf extension submitted upstream
	// per D8.6, and the other half of the revocation-window join (Q23).
	JTI string
	// Credential is the canonical credential reference — never the token
	// itself (Q23).
	Credential receipt.Credential
	// RootPrincipalBinding is the depth-0 OIDC nonce-thumbprint binding
	// (D5). Required at depth 0 unless Trigger is set; refused above it.
	RootPrincipalBinding *receipt.RootBinding
	// Trigger marks an autonomous depth-0 root (Q14). Refused above depth 0.
	Trigger *receipt.Trigger
}

// Mint signs one hop with parent's key.
//
// parentHop nil mints the depth-0 root: par_hash is the no-parent sentinel
// and the signing key must be the key the root confirms (the device key
// `behalf login` bound). Otherwise the hop sits one below parentHop, and the
// signing key must be the key parentHop confirmed in its cnf.jwk — signing a
// child with any other key produces a token that verifies under nothing,
// which Mint refuses to produce rather than leaving for Verify to find.
//
// Minting is deterministic: no clock, no randomness. Ed25519 signing is
// deterministic, the claim set marshals in declaration order, and
// `authorization_details` maps marshal with sorted keys — so the same
// parameters under the same keys produce the same token bytes forever.
func Mint(parent ed25519.PrivateKey, parentHop *Hop, params MintParams) (Hop, error) {
	if len(parent) != ed25519.PrivateKeySize {
		return Hop{}, errors.New("aat: mint: parent signing key is not an Ed25519 private key")
	}
	if len(params.Subject) != ed25519.PublicKeySize {
		return Hop{}, errors.New("aat: mint: params.Subject is not an Ed25519 public key")
	}
	if params.Exp <= 0 {
		return Hop{}, errors.New("aat: mint: exp is required (Q11: per-hop expiry, verbatim)")
	}
	if params.JTI == "" {
		return Hop{}, errors.New("aat: mint: jti is required (Q23: the revocation-window join)")
	}
	if len(params.AuthorizationDetails) == 0 {
		return Hop{}, errors.New("aat: mint: at least one RFC 9396 authorization_details object is required")
	}
	if params.Credential.Issuer == "" || params.Credential.Kind == "" || params.Credential.ID == "" {
		return Hop{}, errors.New("aat: mint: credential {issuer, kind, id} is required (Q23)")
	}

	signerJWK := dsse.JWKFromPublic(parent.Public().(ed25519.PublicKey))
	subjectJWK := dsse.JWKFromPublic(params.Subject)

	claims := Claims{
		Cnf:                  receipt.Cnf{JWK: jwkMap(subjectJWK)},
		AuthorizationDetails: params.AuthorizationDetails,
		Exp:                  params.Exp,
		JTI:                  params.JTI,
		Credential:           params.Credential,
	}

	switch parentHop {
	case nil:
		if params.MaxDepth < 0 {
			return Hop{}, errors.New("aat: mint: del_max_depth must not be negative")
		}
		if signerJWK.Thumbprint() != subjectJWK.Thumbprint() {
			return Hop{}, errors.New("aat: mint: the depth-0 hop is signed by the key it confirms; " +
				"the signing key is not params.Subject")
		}
		if params.RootPrincipalBinding == nil && params.Trigger == nil {
			return Hop{}, errors.New("aat: mint: the depth-0 hop needs either a root_principal_binding " +
				"(D5) or a trigger (Q14): every chain has a root, and the root says what anchors it")
		}
		claims.DelDepth = 0
		claims.DelMaxDepth = params.MaxDepth
		claims.ParHash = RootParHash
		claims.RootPrincipalBinding = params.RootPrincipalBinding
		claims.Trigger = params.Trigger
	default:
		if params.RootPrincipalBinding != nil || params.Trigger != nil {
			return Hop{}, errors.New("aat: mint: root_principal_binding and trigger belong to depth 0 only")
		}
		if !parentHop.Signed() {
			return Hop{}, errors.New("aat: mint: the parent hop carries no signature, so there is nothing " +
				"for par_hash to name; a chain cannot be extended past a caller-asserted hop")
		}
		if got := parentHop.JKT(); got == "" || got != signerJWK.Thumbprint() {
			return Hop{}, fmt.Errorf("aat: mint: the signing key %s is not the key the parent hop confirmed (%s)",
				signerJWK.Thumbprint(), parentHop.JKT())
		}
		if params.MaxDepth != 0 && params.MaxDepth != parentHop.Claims.DelMaxDepth {
			return Hop{}, fmt.Errorf("aat: mint: del_max_depth is inherited, not chosen: parent says %d, params say %d",
				parentHop.Claims.DelMaxDepth, params.MaxDepth)
		}
		claims.DelDepth = parentHop.Claims.DelDepth + 1
		claims.DelMaxDepth = parentHop.Claims.DelMaxDepth
		claims.ParHash = ParHash(parentHop.JWS)
		if claims.DelDepth > claims.DelMaxDepth {
			return Hop{}, fmt.Errorf("aat: mint: depth %d exceeds del_max_depth %d",
				claims.DelDepth, claims.DelMaxDepth)
		}
		if parentHop.Claims.Exp > 0 && params.Exp > parentHop.Claims.Exp {
			return Hop{}, fmt.Errorf("aat: mint: exp %d outlives the parent hop's %d",
				params.Exp, parentHop.Claims.Exp)
		}
		// A hop that widens its parent's grant is not a delegation. Refusing
		// it here means Mint cannot produce a chain Verify would call broken
		// for attenuation (Q13) — and since both sides consult the same
		// comparator, that parity holds for every grant shape the comparator
		// can decide, the draft's own included.
		att, reason, v := why.CompareGrantsDetail(grantsOf(parentHop.Claims), grantsOf(claims))
		if att == why.AttenuationBroadened {
			return Hop{}, newBroadeningError(reason, v)
		}
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return Hop{}, fmt.Errorf("aat: mint: marshal claims: %w", err)
	}
	jws, err := sign(parent, signerJWK.Thumbprint(), payload)
	if err != nil {
		return Hop{}, err
	}
	return Hop{Claims: claims, Raw: payload, JWS: jws}, nil
}

// BroadeningError is Mint's refusal to sign a hop whose grant widens the
// authority its parent delegated.
//
// It is a typed error rather than a sentence because the caller that hit it
// usually needs to fix one specific thing. For a grant in the AAT draft's own
// shape (§3.3), the fields name exactly which capability failed §4.5: the
// tool, the argument key, and the two `constraint_type` values that could not
// be shown to narrow. For behalf's own grant shape the comparator has no tool
// to name, the fields are empty, and Reason carries the whole finding.
//
// The message is unchanged from when this refusal was untyped, deliberately:
// the sentence a human reads is the comparator's own reason either way.
type BroadeningError struct {
	// Tool is the draft §3.3 tool identifier, empty when the finding did not
	// come from the draft's rules.
	Tool string
	// Argument is the constraint map key, empty for a tool-level finding —
	// a tool the parent never granted, or a closed-world key set that changed
	// shape.
	Argument string
	// ParentConstraint and DerivedConstraint are the two `constraint_type`
	// values, empty where one side had no constraint at all.
	ParentConstraint  string
	DerivedConstraint string
	// Reason is the comparator's explanation, citing the draft section.
	Reason string
}

func (e *BroadeningError) Error() string {
	return "aat: mint: the grant broadens its parent's: " + e.Reason
}

// Capability reports whether this refusal names a specific draft §3.3 tool.
func (e *BroadeningError) Capability() bool { return e.Tool != "" }

func newBroadeningError(reason string, v *why.I4Violation) *BroadeningError {
	e := &BroadeningError{Reason: reason}
	if v != nil {
		e.Tool, e.Argument = v.Tool, v.Argument
		e.ParentConstraint, e.DerivedConstraint = v.ParentType, v.DerivedType
	}
	return e
}

// header is the JWS protected header. Declaration order is serialization
// order; the bytes are covered by the signature.
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"` // the SIGNING key's RFC 7638 thumbprint (the parent's)
}

// sign produces the compact serialization over payload.
func sign(key ed25519.PrivateKey, kid string, payload []byte) (string, error) {
	protected, err := json.Marshal(header{Alg: Alg, Typ: Typ, Kid: kid})
	if err != nil {
		return "", fmt.Errorf("aat: marshal protected header: %w", err)
	}
	signingInput := b64(protected) + "." + b64(payload)
	sig := ed25519.Sign(key, []byte(signingInput))
	return signingInput + "." + b64(sig), nil
}

// verifySignature reports whether jws is a well-formed compact EdDSA JWS
// whose signature verifies under pub, and that its payload segment is
// payload. The second half matters: a verifier that checks a signature over
// bytes it then discards in favour of a re-parse has verified nothing.
func verifySignature(jws string, pub ed25519.PublicKey, payload []byte) error {
	protectedSeg, payloadSeg, sigSeg, err := split(jws)
	if err != nil {
		return err
	}
	protected, err := base64.RawURLEncoding.DecodeString(protectedSeg)
	if err != nil {
		return errors.New("protected header is not base64url")
	}
	var h header
	if err := json.Unmarshal(protected, &h); err != nil {
		return errors.New("protected header is not JSON")
	}
	if h.Alg != Alg {
		return fmt.Errorf("alg %q is not %s: v1 mints and accepts Ed25519 only (Q69)", h.Alg, Alg)
	}
	gotPayload, err := base64.RawURLEncoding.DecodeString(payloadSeg)
	if err != nil {
		return errors.New("payload is not base64url")
	}
	if !bytes.Equal(gotPayload, payload) {
		return errors.New("the token's payload segment is not the claim bytes being verified")
	}
	sig, err := base64.RawURLEncoding.DecodeString(sigSeg)
	if err != nil {
		return errors.New("signature is not base64url")
	}
	if !ed25519.Verify(pub, []byte(protectedSeg+"."+payloadSeg), sig) {
		return errors.New("signature does not verify under the key")
	}
	return nil
}

func split(jws string) (protected, payload, sig string, err error) {
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", errors.New("not a compact JWS: want three non-empty dot-separated segments")
	}
	return parts[0], parts[1], parts[2], nil
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ---- the wire form ----------------------------------------------------

// wireChain is the carried chain material: an ordered array of hops, each
// presenting EITHER a token or a bare claim. The distinction is the product:
// a hop that presents a claim with no token is telling you, in the wire
// format itself, that nothing backs it.
type wireChain struct {
	SchemaVersion string    `json:"schema_version"`
	Hops          []wireHop `json:"hops"`
}

type wireHop struct {
	JWS    string          `json:"jws,omitempty"`
	Claims json.RawMessage `json:"claims,omitempty"`
}

// MarshalChain renders chain as carriage material.
func MarshalChain(chain []Hop) ([]byte, error) {
	w := wireChain{SchemaVersion: ChainSchemaVersion, Hops: make([]wireHop, 0, len(chain))}
	for i, h := range chain {
		switch {
		case h.Signed():
			w.Hops = append(w.Hops, wireHop{JWS: h.JWS})
		case len(h.Raw) > 0:
			w.Hops = append(w.Hops, wireHop{Claims: append(json.RawMessage(nil), h.Raw...)})
		default:
			return nil, fmt.Errorf("aat: marshal chain: hop %d has neither a token nor claim bytes", i)
		}
	}
	return json.Marshal(w)
}

// ParseChain reads carriage material. It does not verify anything: parsing
// and verifying are separate so that material which fails to verify is still
// recorded rather than dropped (Q45 — append and flag, never silently
// discard).
//
// It returns ErrNotAATChain for material that is not this format at all, so
// a caller can fall back to older carriage without treating it as corruption.
func ParseChain(raw []byte) ([]Hop, error) {
	var w wireChain
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, ErrNotAATChain
	}
	if w.SchemaVersion != ChainSchemaVersion || len(w.Hops) == 0 {
		return nil, ErrNotAATChain
	}
	out := make([]Hop, 0, len(w.Hops))
	for i, wh := range w.Hops {
		h, err := parseHop(wh)
		if err != nil {
			return nil, fmt.Errorf("aat: chain hop %d: %w", i, err)
		}
		out = append(out, h)
	}
	return out, nil
}

// ErrNotAATChain marks material that is not AAT chain carriage.
var ErrNotAATChain = errors.New("aat: not AAT chain material")

func parseHop(wh wireHop) (Hop, error) {
	if wh.JWS != "" {
		_, payloadSeg, _, err := split(wh.JWS)
		if err != nil {
			return Hop{}, err
		}
		raw, err := base64.RawURLEncoding.DecodeString(payloadSeg)
		if err != nil {
			return Hop{}, errors.New("token payload is not base64url")
		}
		var c Claims
		if err := json.Unmarshal(raw, &c); err != nil {
			return Hop{}, fmt.Errorf("token payload is not a hop claim set: %w", err)
		}
		return Hop{Claims: c, Raw: raw, JWS: wh.JWS}, nil
	}
	if len(wh.Claims) == 0 {
		return Hop{}, errors.New("hop carries neither a token nor claims")
	}
	var c Claims
	if err := json.Unmarshal(wh.Claims, &c); err != nil {
		return Hop{}, fmt.Errorf("claims are not a hop claim set: %w", err)
	}
	return Hop{Claims: c, Raw: append([]byte(nil), wh.Claims...)}, nil
}

// ---- projection into the receipt --------------------------------------

// ReceiptHop projects one verified hop into the frozen receipt shape
// (schema §7): the claim set, plus the three members behalf writes after
// checking rather than a caller asserts.
//
// The claim bytes are re-serialized here, which is safe precisely because
// they are not the evidence: the evidence is the token, addressed from
// verification.evidence_ref and held in the customer's store. What the
// receipt embeds is the chain in the schema's own shape, so a reader with
// nothing but the receipt still sees the whole delegation (Q10).
func (h Hop) ReceiptHop(res HopResult) receipt.Hop {
	return receipt.Hop{
		DelDepth:             h.Claims.DelDepth,
		DelMaxDepth:          h.Claims.DelMaxDepth,
		ParHash:              h.Claims.ParHash,
		Cnf:                  h.Claims.Cnf,
		AuthorizationDetails: h.Claims.AuthorizationDetails,
		Exp:                  h.Claims.Exp,
		JTI:                  h.Claims.JTI,
		Credential:           h.Claims.Credential,
		RootPrincipalBinding: h.Claims.RootPrincipalBinding,
		Trigger:              h.Claims.Trigger,
		Verification: receipt.Verification{
			Status:      res.Status,
			Method:      res.Method,
			EvidenceRef: res.EvidenceRef,
		},
		AttenuationFlag: res.StoredFlag(),
	}
}

// grantsOf projects a claim set's raw authorization_details into
// internal/why's comparison form, so the invariants applied here are the
// same code `behalf why` applies at read time — one comparator, not two that
// could disagree about whether a chain attenuates (Q13).
//
// A grant that does not fit the projection keeps its raw bytes and simply
// has nothing comparable in it, which CompareGrants reports as `unknown`
// rather than ignoring — the same tolerance why's own reader has.
func grantsOf(c Claims) []why.Grant {
	out := make([]why.Grant, 0, len(c.AuthorizationDetails))
	for _, g := range c.AuthorizationDetails {
		b, err := json.Marshal(g)
		if err != nil {
			continue
		}
		var wg why.Grant
		_ = json.Unmarshal(b, &wg)
		wg.Raw = b
		out = append(out, wg)
	}
	return out
}

func jwkMap(j dsse.JWK) map[string]any {
	return map[string]any{"kty": j.Kty, "crv": j.Crv, "x": j.X}
}

// jwkThumbprint returns the RFC 7638 thumbprint of an OKP/Ed25519 cnf.jwk,
// or "" for anything else — v1 proves Ed25519 keys and says nothing about
// the rest (Q17).
func jwkThumbprint(jwk map[string]any) string {
	j, ok := ed25519JWK(jwk)
	if !ok {
		return ""
	}
	return j.Thumbprint()
}

func ed25519JWK(jwk map[string]any) (dsse.JWK, bool) {
	kty, _ := jwk["kty"].(string)
	crv, _ := jwk["crv"].(string)
	x, _ := jwk["x"].(string)
	if kty != "OKP" || crv != "Ed25519" || x == "" {
		return dsse.JWK{}, false
	}
	return dsse.JWK{Kty: kty, Crv: crv, X: x}, true
}

// publicKey decodes an Ed25519 cnf.jwk into a usable public key.
func publicKey(jwk map[string]any) (ed25519.PublicKey, bool) {
	j, ok := ed25519JWK(jwk)
	if !ok {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, false
	}
	return ed25519.PublicKey(raw), true
}
