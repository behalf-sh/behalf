package oidclogin

import (
	"crypto/rand"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// The root receipt: kind "delegation", a single depth-0 hop binding the
// human principal (via the OIDC nonce == device-key thumbprint, D5) to the
// device key. It validates against the frozen v1 schema
// (docs/receipt-schema-v1.schema.json), which constrains where each part of
// the binding lives:
//
//   - hop.root_principal_binding carries the frozen subset
//     {nonce, device_jkt, id_token_ref} — the schema closes this object
//     (unevaluatedProperties: false), so the wider binding cannot go here.
//   - issuer and sub_digest ride hop.credential {issuer, kind, id, exp}
//     (Q23, Q40) — the credential is the ID token, referenced, never
//     embedded.
//   - id_token_digest, jwks_digest and the signed root delegation
//     statement are customer-held payload slots (§9-adjacent, Q22); the
//     statement blob carries the full five-field binding, signed by the
//     device key.
//
// The DSSE envelope over the sealed receipt is signed by the EMITTER key;
// the delegation statement inside the payload store is signed by the
// DEVICE key. Two keys, two roles (Q19, D5).

// OtelConventionsVersion is the gen_ai.* conventions version in force at
// capture (Q8, Q49).
const OtelConventionsVersion = "1.29.0"

// loginRiskPolicy is the built-in capture-time policy that assigns
// behalf.login its risk class (Q6). Its digest rides the receipt so the
// assignment is auditable.
const loginRiskPolicy = "behalf.sh/login/risk-policy/v1\n{\"behalf.login\":\"high\"}\n"

// RootParHash is par_hash at depth 0. The AAT draft gives the root no
// parent, but the frozen hop schema requires the field; all-zeros is the
// explicit no-parent sentinel. Exported so internal/aat mints and checks the
// same sentinel rather than defining a second one that could drift.
const RootParHash = "0000000000000000000000000000000000000000000000000000000000000000"

// rootParHashSentinel is the pre-export spelling, kept as the name this file
// reads best with.
const rootParHashSentinel = RootParHash

// DefaultRootMaxDepth is del_max_depth minted on the root delegation: the
// deepest chain the D5 prototype exercised plus one for the proxy hop.
const DefaultRootMaxDepth = 4

// DefaultRootTTL is the root delegation statement's validity. The ID
// token's own exp is minutes; the root delegation is the standing local
// authority anchor, so it gets its own expiry, recorded verbatim in the
// hop and re-minted by the next login.
const DefaultRootTTL = 90 * 24 * time.Hour

// VerificationMethodRoot names the D5 three-check root predicate on the
// hop's verification object (Q17).
const VerificationMethodRoot = "oidc-nonce-binding"

// rootReceiptInput is everything buildRootReceipt needs, gathered by Login.
type rootReceiptInput struct {
	Emitter        *identity.Key
	EmitterCounter int
	Device         *identity.Key
	Statement      *Statement

	IDTokenSize   int
	JWKSSize      int
	StatementBlob []byte // sealed statement envelope bytes
	StatementDig  string

	IDTokenExp      int64
	IDTokenAuthTime int64    // 0 if the IdP did not expose auth_time
	IDTokenAMR      []string // nil if not exposed

	CapturedAt time.Time
	RunID      string

	// Entropy is the ULID entropy source; nil means crypto/rand.
	Entropy io.Reader
}

// buildRootReceipt assembles the depth-0 delegation receipt.
func buildRootReceipt(in rootReceiptInput) *receipt.Receipt {
	st := in.Statement
	return &receipt.Receipt{
		SchemaVersion:      receipt.SchemaVersion,
		OtelConventionsVer: OtelConventionsVersion,
		ReceiptID:          newULID(in.CapturedAt, in.Entropy),
		Kind:               "delegation",
		RiskClass:          "high",
		RiskPolicyDigest:   digestHex([]byte(loginRiskPolicy)),
		CapturedAt:         nowRFC3339(in.CapturedAt),
		Emitter: receipt.Emitter{
			JKT: in.Emitter.JKT,
			// cli was widened into the emitter.surface enum
			// forward-only (schema §5) for receipts the behalf CLI
			// itself emits; the login root receipt is the first.
			Surface: "cli",
			Counter: in.EmitterCounter,
		},
		Actor: &receipt.Actor{
			JKT:            in.Device.JKT,
			EmitterToActor: "asserted",
		},
		Operation: receipt.Operation{
			Name:    "behalf.login",
			Target:  st.Issuer,
			Outcome: receipt.Outcome{Status: "ok"},
		},
		RunID:           in.RunID,
		RunIDProvenance: "proxy-session",
		Authority: &receipt.Authority{
			Chain: []receipt.Hop{rootHop(in)},
		},
		// A chain whose root passes the D5 checks is verified at the
		// root; this receipt IS the root, so the weakest hop is the
		// root itself (Q12).
		Attribution: receipt.Attribution{Verification: "verified", Class: "direct"},
		Payload: []receipt.Slot{
			slot("id_token", st.IDTokenDigest, "application/jwt", in.IDTokenSize),
			slot("jwks_snapshot", st.JWKSDigest, "application/jwk-set+json", in.JWKSSize),
			slot("root_delegation", in.StatementDig, PayloadTypeStatement, len(in.StatementBlob)),
		},
		Provenance: receipt.Provenance{Source: "native"},
	}
}

func rootHop(in rootReceiptInput) receipt.Hop {
	st := in.Statement
	hop := receipt.Hop{
		DelDepth:    0,
		DelMaxDepth: DefaultRootMaxDepth,
		ParHash:     rootParHashSentinel,
		Cnf: receipt.Cnf{JWK: map[string]any{
			"kty": st.DeviceJWK.Kty,
			"crv": st.DeviceJWK.Crv,
			"x":   st.DeviceJWK.X,
		}},
		// The raw RFC 9396 grant of the root: the device key holds the
		// principal's undivided authority; attenuation begins at hop 1.
		AuthorizationDetails: []map[string]any{{
			"type": "sh.behalf/root-delegation/v1",
		}},
		Exp: st.Exp,
		JTI: st.JTI,
		Credential: receipt.Credential{
			Issuer: st.Issuer,
			Kind:   "oidc-id-token",
			ID:     "oidc-sub-digest:" + st.SubDigest,
			Exp:    in.IDTokenExp,
			JKT:    st.NonceJKT,
		},
		RootPrincipalBinding: &receipt.RootBinding{
			Nonce:      st.NonceJKT,
			DeviceJKT:  st.NonceJKT,
			IDTokenRef: st.IDTokenDigest,
		},
		Verification: receipt.Verification{
			Status:      "verified",
			Method:      VerificationMethodRoot,
			EvidenceRef: "sha256:" + in.StatementDig,
		},
	}
	if in.IDTokenAuthTime > 0 {
		hop.Credential.AuthTime = in.IDTokenAuthTime
	}
	if len(in.IDTokenAMR) > 0 {
		hop.Credential.AMR = in.IDTokenAMR
	}
	return hop
}

func slot(role, digest, contentType string, size int) receipt.Slot {
	return receipt.Slot{
		Role:        role,
		Digest:      digest,
		Custody:     "customer-held",
		ContentType: contentType,
		Size:        size,
		Ref:         "sha256:" + digest,
		State:       "present",
	}
}

// newULID mints a ULID at t from entropy (Q46: receipt_id is client-minted
// at capture). A nil entropy source means crypto/rand, which is what a real
// login uses; a deterministic recording injects its own stream so the login
// it performs is reproducible (Config.Entropy).
func newULID(t time.Time, entropy io.Reader) string {
	if entropy == nil {
		entropy = rand.Reader
	}
	id, err := ulid.New(ulid.Timestamp(t.UTC()), entropy)
	if err != nil {
		// crypto/rand failure is unrecoverable for an identity CLI.
		panic(fmt.Sprintf("oidclogin: mint ulid: %v", err))
	}
	return id.String()
}

// newJTI mints the root delegation's per-hop token id (Q11).
func newJTI(t time.Time, entropy io.Reader) string {
	return "behalf-root-" + strings.ToLower(newULID(t, entropy))
}
