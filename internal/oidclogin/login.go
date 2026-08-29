// Package oidclogin implements `behalf login` — the verified identity root
// (D5, Q17, Q21, Q22) — and its offline re-verification.
//
// The flow is ordinary OAuth 2.1 authorization-code + PKCE (S256) on a
// loopback redirect against any conformant OIDC provider, with one
// deviation: the OIDC nonce is the RFC 7638 JWK thumbprint of a freshly
// generated device Ed25519 key. OIDC Core requires the AS to echo the nonce
// into the signed ID token, so the IdP signs the thumbprint back without
// knowing it is doing anything unusual. The offline predicate is three
// checks (D5, Q17):
//
//  1. the IdP signed the ID token (against the JWKS snapshot taken at login),
//  2. nonce == jkt(device_pubkey),
//  3. the root delegation statement is signed by that device key.
//
// Everything above the root is asserted; skipping login yields
// permanently-asserted records (Q21).
package oidclogin

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	jose "github.com/go-jose/go-jose/v4"
	"golang.org/x/oauth2"

	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/receipt"
)

// signingAlgs are the ID-token signature algorithms accepted at login and
// at offline re-verification. Asymmetric only; no provider-chosen HMAC.
var signingAlgs = []string{
	string(jose.RS256), string(jose.RS384), string(jose.RS512),
	string(jose.ES256), string(jose.ES384), string(jose.ES512),
	string(jose.PS256), string(jose.PS384), string(jose.PS512),
	string(jose.EdDSA),
}

// Config configures Login.
type Config struct {
	// Issuer is the OIDC issuer URL (its /.well-known/openid-configuration
	// must be conformant). Required.
	Issuer string
	// ClientID is the OAuth public client id. Required.
	ClientID string
	// Dir is the resolved state directory (identity.ResolveDir). Required.
	Dir string
	// Scopes defaults to [openid, email, profile].
	Scopes []string
	// NoBrowser suppresses opening the system browser; the auth URL is
	// delivered via OnAuthURL for the caller to print (or, in tests, to
	// drive programmatically).
	NoBrowser bool
	// OnAuthURL, if set, receives the authorization URL once the loopback
	// listener is accepting the redirect.
	OnAuthURL func(url string)
	// HTTPClient overrides the client used for discovery, JWKS snapshot
	// and token exchange. Nil means http.DefaultClient.
	HTTPClient *http.Client
	// Now overrides the clock (tests). Nil means time.Now.
	Now func() time.Time
	// Entropy overrides the ULID entropy source that mints the root
	// delegation's `jti`, the root receipt's `receipt_id` and its `run_id`.
	// Nil means crypto/rand, which is what a real login uses. A
	// deterministic recording injects a fixed stream so the login it
	// performs is byte-reproducible (see cmd/behalf-record).
	Entropy io.Reader
	// DeviceKey, if set, is bound as the human's device key instead of a
	// freshly generated one.
	//
	// DEMO AND TEST MATERIAL ONLY. A real login generates a fresh key per
	// login (that is what makes the nonce bind THIS login to THIS key), and
	// the CLI never sets this. It exists for the same reason
	// cmd/behalf-record pins the emitter key: a recording signed by a random
	// key is not reproducible and cannot be named in a checked-in alias map.
	// The login it performs is otherwise the real flow — real PKCE, real
	// token exchange, a real IdP-signed ID token echoing jkt(DeviceKey).
	DeviceKey *identity.Key
}

// Result is what a completed login produced and persisted.
type Result struct {
	StateDir        string
	Issuer          string
	ClientID        string
	SubDigest       string
	DeviceJKT       string
	IDTokenDigest   string
	JWKSDigest      string
	StatementDigest string
	ReceiptID       string
	SealedReceipt   []byte // the sealed receipt payload bytes, as spooled
}

// Login runs the browser (or --no-browser) OIDC flow, persists the JWKS
// snapshot, the full raw ID token and the device-key-signed root delegation
// statement as customer-held blobs (Q22), appends the root delegation
// receipt to the local spool, and records login.json.
func Login(ctx context.Context, cfg Config) (*Result, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.Dir == "" {
		return nil, errors.New("oidclogin: issuer, client id and state dir are required")
	}
	now := time.Now
	if cfg.Now != nil {
		now = cfg.Now
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}

	// A fresh device key per login: the nonce binds THIS login to THIS
	// key (D5). It is persisted only after the ID token validates, so a
	// failed login never clobbers an existing root.
	device := cfg.DeviceKey
	if device == nil {
		var err error
		device, err = identity.Generate()
		if err != nil {
			return nil, err
		}
	}

	// Discovery.
	ctx = oidc.ClientContext(ctx, httpClient)
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidclogin: discovery: %w", err)
	}
	var disco struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&disco); err != nil {
		return nil, fmt.Errorf("oidclogin: discovery claims: %w", err)
	}
	if disco.JWKSURI == "" {
		return nil, errors.New("oidclogin: discovery document has no jwks_uri")
	}

	// JWKS snapshot: the raw bytes are the blob; the parsed keys are the
	// verification keyset. Verifying against the snapshot (not go-oidc's
	// remote keyset) proves at login time that the persisted snapshot is
	// sufficient for offline re-verification (Q22).
	jwksRaw, err := fetchRaw(ctx, httpClient, disco.JWKSURI)
	if err != nil {
		return nil, fmt.Errorf("oidclogin: fetch jwks: %w", err)
	}
	keySet, err := staticKeySet(jwksRaw)
	if err != nil {
		return nil, err
	}
	verifier := oidc.NewVerifier(cfg.Issuer, keySet, &oidc.Config{
		ClientID:             cfg.ClientID,
		SupportedSigningAlgs: signingAlgs,
		Now:                  now,
	})

	// Loopback redirect (RFC 8252 §7.3): 127.0.0.1, ephemeral port.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("oidclogin: loopback listener: %w", err)
	}
	defer ln.Close()
	redirectURL := fmt.Sprintf("http://%s/callback", ln.Addr().String())

	oauthCfg := oauth2.Config{
		ClientID:    cfg.ClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: redirectURL,
		Scopes:      scopes,
	}
	state, err := randomToken()
	if err != nil {
		return nil, err
	}
	pkceVerifier := oauth2.GenerateVerifier()
	authURL := oauthCfg.AuthCodeURL(state,
		oauth2.S256ChallengeOption(pkceVerifier),
		oauth2.SetAuthURLParam("nonce", device.JKT), // THE deviation (D5)
	)

	codeCh := make(chan callbackResult, 1)
	srv := &http.Server{Handler: callbackHandler(state, codeCh)}
	go srv.Serve(ln) //nolint:errcheck // Serve returns on Shutdown/Close
	defer srv.Shutdown(context.Background())

	if cfg.OnAuthURL != nil {
		cfg.OnAuthURL(authURL)
	}
	if !cfg.NoBrowser {
		openBrowser(authURL) // best effort; the printed URL is the fallback
	}

	var cb callbackResult
	select {
	case cb = <-codeCh:
	case <-ctx.Done():
		return nil, fmt.Errorf("oidclogin: waiting for redirect: %w", ctx.Err())
	}
	if cb.err != nil {
		return nil, cb.err
	}

	// Token exchange (PKCE).
	tok, err := oauthCfg.Exchange(ctx, cb.code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidclogin: token exchange: %w", err)
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, errors.New("oidclogin: token response carried no id_token")
	}

	// Validate: iss/aud/exp/signature against the snapshot, then the
	// nonce-thumbprint binding.
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, fmt.Errorf("oidclogin: id token rejected: %w", err)
	}
	if idToken.Nonce != device.JKT {
		return nil, fmt.Errorf("oidclogin: nonce %q is not the device key thumbprint %q: the ID token does not bind this login's device key", idToken.Nonce, device.JKT)
	}
	var extraClaims struct {
		AuthTime int64    `json:"auth_time"`
		AMR      []string `json:"amr"`
	}
	_ = idToken.Claims(&extraClaims) // optional claims; absence is fine

	// Persist, customer-held (Q22): JWKS snapshot + full raw ID token as
	// content-addressed blobs, then the device-key-signed statement.
	if err := identity.EnsureDir(cfg.Dir); err != nil {
		return nil, err
	}
	jwksDigest, err := putBlob(cfg.Dir, jwksRaw)
	if err != nil {
		return nil, err
	}
	idTokenDigest, err := putBlob(cfg.Dir, []byte(rawIDToken))
	if err != nil {
		return nil, err
	}

	loginTime := now().UTC()
	st := &Statement{
		SchemaVersion: StatementSchemaVersion,
		JTI:           newJTI(loginTime, cfg.Entropy),
		Issuer:        idToken.Issuer,
		SubDigest:     SubDigest(idToken.Issuer, idToken.Subject),
		NonceJKT:      device.JKT,
		IDTokenDigest: idTokenDigest,
		JWKSDigest:    jwksDigest,
		DeviceJWK:     device.JWK,
		DelegatedAt:   nowRFC3339(loginTime),
		Exp:           loginTime.Add(DefaultRootTTL).Unix(),
	}
	stBlob, err := sealStatement(st, device)
	if err != nil {
		return nil, err
	}
	stDigest, err := putBlob(cfg.Dir, stBlob)
	if err != nil {
		return nil, err
	}

	// The login validated: the device key becomes the active root.
	if err := identity.SaveDevice(cfg.Dir, device); err != nil {
		return nil, err
	}

	// Emit the root receipt, envelope-signed by the emitter key.
	emitter, err := identity.LoadOrGenerateEmitter(cfg.Dir)
	if err != nil {
		return nil, err
	}
	counter, err := identity.NextEmitterCounter(cfg.Dir)
	if err != nil {
		return nil, err
	}
	r := buildRootReceipt(rootReceiptInput{
		Emitter:         emitter,
		EmitterCounter:  counter,
		Device:          device,
		Statement:       st,
		IDTokenSize:     len(rawIDToken),
		JWKSSize:        len(jwksRaw),
		StatementBlob:   stBlob,
		StatementDig:    stDigest,
		IDTokenExp:      idToken.Expiry.Unix(),
		IDTokenAuthTime: extraClaims.AuthTime,
		IDTokenAMR:      extraClaims.AMR,
		CapturedAt:      loginTime,
		RunID:           "login-" + newULID(loginTime, cfg.Entropy),
		Entropy:         cfg.Entropy,
	})
	sealed, err := receipt.Seal(r)
	if err != nil {
		return nil, err
	}
	if err := appendSpool(cfg.Dir, sealed.Bytes(), emitter); err != nil {
		return nil, err
	}

	if err := saveLoginState(cfg.Dir, &LoginState{
		SchemaVersion:   loginStateSchemaVersion,
		Issuer:          st.Issuer,
		ClientID:        cfg.ClientID,
		SubDigest:       st.SubDigest,
		DeviceJKT:       device.JKT,
		IDTokenDigest:   idTokenDigest,
		JWKSDigest:      jwksDigest,
		StatementDigest: stDigest,
		ReceiptID:       r.ReceiptID,
		LoggedInAt:      nowRFC3339(loginTime),
	}); err != nil {
		return nil, err
	}

	return &Result{
		StateDir:        cfg.Dir,
		Issuer:          st.Issuer,
		ClientID:        cfg.ClientID,
		SubDigest:       st.SubDigest,
		DeviceJKT:       device.JKT,
		IDTokenDigest:   idTokenDigest,
		JWKSDigest:      jwksDigest,
		StatementDigest: stDigest,
		ReceiptID:       r.ReceiptID,
		SealedReceipt:   sealed.Bytes(),
	}, nil
}

type callbackResult struct {
	code string
	err  error
}

// callbackHandler accepts exactly one redirect, checks state, and delivers
// the code (or the AS error) on ch.
func callbackHandler(state string, ch chan<- callbackResult) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		deliver := func(res callbackResult, status int, msg string) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(status)
			fmt.Fprintf(w, "<!doctype html><meta charset=utf-8><title>behalf</title><body style=\"font-family:system-ui\"><p>%s</p></body>", msg)
			select {
			case ch <- res:
			default: // a second redirect: first one already won
			}
		}
		if e := q.Get("error"); e != "" {
			deliver(callbackResult{err: fmt.Errorf("oidclogin: authorization error: %s (%s)", e, q.Get("error_description"))},
				http.StatusBadRequest, "Login failed — return to the terminal.")
			return
		}
		if q.Get("state") != state {
			deliver(callbackResult{err: errors.New("oidclogin: redirect state mismatch")},
				http.StatusBadRequest, "Login failed (state mismatch) — return to the terminal.")
			return
		}
		code := q.Get("code")
		if code == "" {
			deliver(callbackResult{err: errors.New("oidclogin: redirect carried no code")},
				http.StatusBadRequest, "Login failed (no code) — return to the terminal.")
			return
		}
		deliver(callbackResult{code: code}, http.StatusOK, "Login complete — you can close this tab and return to the terminal.")
	})
	return mux
}

// staticKeySet parses a raw JWKS document into an offline oidc.KeySet.
func staticKeySet(jwksRaw []byte) (oidc.KeySet, error) {
	var set jose.JSONWebKeySet
	if err := json.Unmarshal(jwksRaw, &set); err != nil {
		return nil, fmt.Errorf("oidclogin: parse jwks: %w", err)
	}
	var keys []crypto.PublicKey
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		if !k.Valid() || !k.IsPublic() {
			continue
		}
		keys = append(keys, k.Key)
	}
	if len(keys) == 0 {
		return nil, errors.New("oidclogin: jwks snapshot contains no usable signing keys")
	}
	return &oidc.StaticKeySet{PublicKeys: keys}, nil
}

// fetchRaw GETs url and returns the body bytes.
func fetchRaw(ctx context.Context, c *http.Client, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// randomToken returns 32 bytes of crypto/rand, base64url.
func randomToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// openBrowser opens url in the system browser, best effort.
func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}
