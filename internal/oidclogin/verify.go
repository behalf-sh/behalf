package oidclogin

import (
	"context"
	"errors"
	"fmt"

	"github.com/coreos/go-oidc/v3/oidc"
)

// VerifyRoot re-runs the D5 root predicate entirely offline, from persisted
// material only (Q17, Q18, Q22):
//
//  1. the IdP signed the ID token — checked against the JWKS snapshot taken
//     at login, never against the network;
//  2. nonce == jkt(device_pubkey);
//  3. the root delegation statement is signed by that device key.
//
// Expiry is deliberately NOT enforced: the claim is "this human
// authenticated at time T and controls this key", checkable years later
// (D5); login-time validation already enforced freshness once.
//
// Outcome composition: any check that runs and fails → broken; else any
// check skipped because a customer-held blob is gone → degraded (the root
// is then behalf-attested, Q22, and the report says so); else verified.

// State is the root verification outcome.
type State string

// The three outcomes. A fourth condition — no login ever — is not a State:
// VerifyRoot returns ErrNoLogin and the caller renders the
// asserted-forever warning (Q21).
const (
	StateVerified State = "verified"
	StateDegraded State = "degraded"
	StateBroken   State = "broken"
)

// CheckStatus is one check's disposition.
type CheckStatus string

// Check dispositions.
const (
	CheckPass    CheckStatus = "pass"
	CheckFail    CheckStatus = "fail"
	CheckSkipped CheckStatus = "skipped"
)

// Check names (the D5 predicate, in order).
const (
	CheckIdPSignature = "idp-signature"             // check 1
	CheckNonceBinding = "nonce-binding"             // check 2
	CheckRootDelegSig = "root-delegation-signature" // check 3
)

// Check is one predicate check's result.
type Check struct {
	Name   string
	Status CheckStatus
	Detail string
}

// Report is what VerifyRoot found. Reasons explains every non-verified
// outcome in plain language.
type Report struct {
	State   State
	Checks  []Check
	Reasons []string
	Login   *LoginState
	// DeviceJKT is the thumbprint of the key this login bound — read from
	// the signed statement where it survives, else from login.json (which is
	// an index, not evidence). A chain root whose cnf.jwk is not this key was
	// not minted by this human's device key.
	DeviceJKT string
	// StatementDigest addresses the signed root delegation statement in the
	// customer-held store: the evidence behind a verified depth-0 hop.
	StatementDigest string
	// Issuer is the OIDC issuer that signed the ID token.
	Issuer string
}

// report building helpers.
func (r *Report) check(name string, status CheckStatus, detail string) {
	r.Checks = append(r.Checks, Check{Name: name, Status: status, Detail: detail})
}

func (r *Report) fail(name, detail string) {
	r.check(name, CheckFail, detail)
	r.Reasons = append(r.Reasons, detail)
}

func (r *Report) skip(name, detail string) {
	r.check(name, CheckSkipped, detail)
	r.Reasons = append(r.Reasons, detail)
}

// VerifyRoot runs the offline root predicate against stateDir. It returns
// ErrNoLogin (wrapped) when no login has ever completed there.
func VerifyRoot(stateDir string) (*Report, error) {
	login, err := LoadLoginState(stateDir)
	if err != nil {
		return nil, err
	}
	rep := &Report{Login: login}

	// Check 3 material first: the statement carries the authoritative
	// binding (device JWK, digests); login.json is only the index.
	var st *Statement
	switch blob, err := getBlob(stateDir, login.StatementDigest); {
	case err == nil:
		st, err = openStatement(blob)
		if err != nil {
			rep.fail(CheckRootDelegSig, fmt.Sprintf("root delegation statement invalid: %v", err))
		} else {
			rep.check(CheckRootDelegSig, CheckPass, "statement signature valid for the embedded device key")
		}
	case errors.Is(err, ErrBlobMissing):
		rep.skip(CheckRootDelegSig, "root delegation statement blob deleted from the customer-held store; the root degrades to behalf-attested (Q22)")
	default:
		rep.fail(CheckRootDelegSig, fmt.Sprintf("root delegation statement blob unusable: %v", err))
	}

	// Locate the rest of the evidence via the statement where possible.
	jwksDigest, idTokenDigest := login.JWKSDigest, login.IDTokenDigest
	deviceJKT, issuer := login.DeviceJKT, login.Issuer
	if st != nil {
		jwksDigest, idTokenDigest = st.JWKSDigest, st.IDTokenDigest
		deviceJKT, issuer = st.DeviceJWK.Thumbprint(), st.Issuer
		if st.NonceJKT != deviceJKT {
			rep.fail(CheckNonceBinding, fmt.Sprintf("statement nonce_jkt %q is not the embedded device key's thumbprint %q", st.NonceJKT, deviceJKT))
		}
		if login.DeviceJKT != deviceJKT {
			rep.Reasons = append(rep.Reasons, fmt.Sprintf("note: login.json device_jkt %q disagrees with the signed statement %q; the statement governs", login.DeviceJKT, deviceJKT))
		}
	}

	rep.DeviceJKT, rep.Issuer = deviceJKT, issuer
	rep.StatementDigest = login.StatementDigest

	jwksRaw := loadEvidence(stateDir, jwksDigest, "JWKS snapshot", rep)
	idTokenRaw := loadEvidence(stateDir, idTokenDigest, "ID-token", rep)

	switch {
	case jwksRaw == nil || idTokenRaw == nil:
		// A required blob is gone or unusable: checks 1 and 2 cannot run.
		// loadEvidence already recorded why.
		rep.skip(CheckIdPSignature, "cannot re-check the IdP signature without both the ID-token and JWKS-snapshot blobs")
		rep.skip(CheckNonceBinding, "cannot re-check the nonce binding without a signature-verified ID token")
	default:
		keySet, err := staticKeySet(jwksRaw)
		if err != nil {
			rep.fail(CheckIdPSignature, fmt.Sprintf("JWKS snapshot unusable: %v", err))
			rep.skip(CheckNonceBinding, "cannot re-check the nonce binding without a signature-verified ID token")
			break
		}
		verifier := oidc.NewVerifier(issuer, keySet, &oidc.Config{
			ClientID:             login.ClientID,
			SupportedSigningAlgs: signingAlgs,
			SkipExpiryCheck:      true, // the claim is anchored at auth time T, not "still fresh" (D5)
		})
		idToken, err := verifier.Verify(context.Background(), string(idTokenRaw))
		if err != nil {
			rep.fail(CheckIdPSignature, fmt.Sprintf("ID token fails against the login-time JWKS snapshot: %v", err))
			rep.skip(CheckNonceBinding, "cannot re-check the nonce binding without a signature-verified ID token")
			break
		}
		rep.check(CheckIdPSignature, CheckPass, "IdP signature, issuer and audience verify against the login-time snapshot")

		if idToken.Nonce != deviceJKT {
			rep.fail(CheckNonceBinding, fmt.Sprintf("ID-token nonce %q is not the device key thumbprint %q", idToken.Nonce, deviceJKT))
		} else {
			rep.check(CheckNonceBinding, CheckPass, "nonce == jkt(device_pubkey)")
		}

		// The pseudonymous principal must still be the one the statement
		// (and receipts) name (Q40).
		if st != nil {
			if got := SubDigest(idToken.Issuer, idToken.Subject); got != st.SubDigest {
				rep.fail(CheckNonceBinding, fmt.Sprintf("sub_digest mismatch: statement says %s, ID token yields %s", st.SubDigest, got))
			}
		}
	}

	rep.State = compose(rep.Checks)
	if rep.State == StateDegraded {
		rep.Reasons = append(rep.Reasons, "root identity is behalf-attested, not third-party re-verifiable, until the missing material is restored")
	}
	return rep, nil
}

// loadEvidence fetches one blob, recording tampering as a failure and
// deletion as a skip-with-reason. Returns nil when unusable.
func loadEvidence(stateDir, digest, what string, rep *Report) []byte {
	if digest == "" {
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("no %s digest recorded", what))
		return nil
	}
	b, err := getBlob(stateDir, digest)
	switch {
	case err == nil:
		return b
	case errors.Is(err, ErrBlobMissing):
		rep.Reasons = append(rep.Reasons, fmt.Sprintf("%s blob %s deleted from the customer-held store; the root degrades to behalf-attested (Q22)", what, digest))
		return nil
	default:
		// Tampered or unreadable: evidence that contradicts itself.
		rep.fail(CheckIdPSignature, fmt.Sprintf("%s blob %s unusable: %v", what, digest, err))
		return nil
	}
}

// compose applies the outcome rule: fail beats skipped beats pass.
func compose(checks []Check) State {
	state := StateVerified
	for _, c := range checks {
		switch c.Status {
		case CheckFail:
			return StateBroken
		case CheckSkipped:
			state = StateDegraded
		}
	}
	return state
}
