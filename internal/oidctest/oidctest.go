// Package oidctest is an httptest fake OIDC provider for exercising the
// `behalf login` flow with no real IdP and no browser.
//
// TEST-ONLY, like internal/testkeys: nothing here may run outside tests.
// The server implements the minimum conformant surface the flow touches —
// discovery, JWKS, an authorize endpoint that 302s straight back to the
// client's loopback redirect with code+state (the "user" approves
// instantly), and a token endpoint that checks PKCE (S256) and mints an
// RS256 ID token echoing the requested nonce, per OIDC Core's mandatory
// nonce return.
//
// Knobs (set before driving a flow) make it adversarial: MintNonce rewrites
// the echoed nonce (nonce-mismatch rejection) and SignWith substitutes a
// signing key that is not in the published JWKS (wrong-signature
// rejection).
//
// NewDeterministic is the reproducible variant: an Ed25519 signing key from
// a fixed seed, a fixed clock, and an advertised issuer that is a stable
// name rather than an ephemeral 127.0.0.1 port — so the ID token it mints,
// and therefore its digest and everything a receipt records about it, is the
// same bytes every run. cmd/behalf-record needs that to keep its recordings
// byte-deterministic while performing a genuine login (Q92, D9.2).
package oidctest

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// TokenTTL is how long an ID token this provider mints stays valid. It is
// exported because a caller recording a chain has to state the credential's
// `exp` verbatim (Q23) and must not guess it.
const TokenTTL = time.Hour

// Server is a fake OIDC provider.
type Server struct {
	// URL is the issuer.
	URL string
	// Key is the provider's RSA signing key; its public half is published
	// at /jwks.
	Key *rsa.PrivateKey
	// KID is the published key id.
	KID string

	// MintNonce, if set, transforms the nonce echoed into the ID token
	// (default: echo verbatim, as OIDC Core requires).
	MintNonce func(requested string) string
	// SignWith, if set, signs ID tokens with this key instead of Key —
	// a signature the published JWKS cannot verify.
	SignWith *rsa.PrivateKey
	// Sub is the authenticated subject (default "user-1234").
	Sub string
	// AuthTime and AMR, if set, are included as ID-token claims.
	AuthTime int64
	AMR      []string
	// Now overrides the clock stamped into iat and exp. Nil means time.Now.
	Now func() time.Time

	// edKey, when set, replaces Key as the signer: EdDSA over Ed25519,
	// published as an OKP JWK. Set by NewDeterministic, because Ed25519 key
	// derivation and signing are both deterministic and RSA generation is
	// deliberately not (crypto/internal/randutil).
	edKey ed25519.PrivateKey
	alg   jose.SignatureAlgorithm

	srv       *httptest.Server
	jwksBytes []byte

	mu    sync.Mutex
	codes map[string]authRequest
}

type authRequest struct {
	clientID    string
	redirectURI string
	nonce       string
	challenge   string
}

// New starts the fake provider. Callers must Close it.
func New() *Server {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(fmt.Sprintf("oidctest: generate rsa key: %v", err))
	}
	s := &Server{
		Key:   key,
		KID:   "oidctest-key-1",
		Sub:   "user-1234",
		alg:   jose.RS256,
		codes: make(map[string]authRequest),
	}
	s.start(s.Key.Public(), "")
	return s
}

// DeterministicOptions configures NewDeterministic. Every field is pinned on
// purpose: an ephemeral port in the issuer, a random signing key or a
// wall-clock `iat` would each, on their own, make the ID token — and so its
// digest, and so every receipt that references it — different on every run.
type DeterministicOptions struct {
	// Issuer is the advertised issuer and endpoint base, e.g.
	// "https://login.demo.internal". It is a NAME, not an address: nothing
	// listens there. Drive the flow with Client(), which routes it to the
	// local test server.
	Issuer string
	// Seed derives the provider's Ed25519 signing key.
	Seed string
	// Sub is the authenticated subject.
	Sub string
	// At is the fixed instant stamped into iat, and exp one hour later.
	At time.Time
	// AuthTime and AMR, if set, become ID-token claims.
	AuthTime int64
	AMR      []string
}

// NewDeterministic starts a fake provider whose ID tokens are byte-identical
// across runs given the same options. Callers must Close it.
//
// TEST AND DEMO MATERIAL ONLY, like the rest of this package: the signing
// key is derived from a public seed and secures nothing.
func NewDeterministic(o DeterministicOptions) *Server {
	if o.Issuer == "" || o.Seed == "" {
		panic("oidctest: NewDeterministic needs an Issuer and a Seed")
	}
	seed := sha256.Sum256([]byte("behalf.sh/oidctest/v1\n" + o.Seed))
	priv := ed25519.NewKeyFromSeed(seed[:])
	sub := o.Sub
	if sub == "" {
		sub = "user-1234"
	}
	at := o.At.UTC()
	s := &Server{
		KID:      "oidctest-ed25519-1",
		Sub:      sub,
		AuthTime: o.AuthTime,
		AMR:      o.AMR,
		Now:      func() time.Time { return at },
		edKey:    priv,
		alg:      jose.EdDSA,
		codes:    make(map[string]authRequest),
	}
	s.start(priv.Public(), o.Issuer)
	return s
}

// start publishes the JWKS, mounts the endpoints and records the advertised
// issuer. An empty issuer means "advertise the address we actually listen
// on", which is what New does.
func (s *Server) start(pub crypto.PublicKey, issuer string) {
	jwks := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       pub,
		KeyID:     s.KID,
		Algorithm: string(s.alg),
		Use:       "sig",
	}}}
	var err error
	s.jwksBytes, err = json.Marshal(jwks)
	if err != nil {
		panic(fmt.Sprintf("oidctest: marshal jwks: %v", err))
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/token", s.token)
	s.srv = httptest.NewServer(mux)
	s.URL = s.srv.URL
	if issuer != "" {
		s.URL = strings.TrimSuffix(issuer, "/")
	}
}

// Close shuts the provider down.
func (s *Server) Close() { s.srv.Close() }

// Client returns an HTTP client that resolves this provider's advertised
// issuer to the address it actually listens on, and passes everything else
// (the loopback redirect above all) through untouched.
//
// This is what makes a stable issuer possible without binding a fixed port:
// the flow is a real HTTP flow, the issuer in the discovery document, the ID
// token and the receipt is a stable name, and only the transport knows where
// that name lives.
func (s *Server) Client() *http.Client {
	base, err := url.Parse(s.srv.URL)
	if err != nil {
		panic(fmt.Sprintf("oidctest: parse server url: %v", err))
	}
	issuer, err := url.Parse(s.URL)
	if err != nil {
		panic(fmt.Sprintf("oidctest: parse issuer url: %v", err))
	}
	return &http.Client{Transport: &issuerTransport{issuerHost: issuer.Host, base: base}}
}

type issuerTransport struct {
	issuerHost string
	base       *url.URL
}

func (t *issuerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host == t.issuerHost {
		clone := r.Clone(r.Context())
		clone.URL.Scheme = t.base.Scheme
		clone.URL.Host = t.base.Host
		clone.Host = ""
		r = clone
	}
	return http.DefaultTransport.RoundTrip(r)
}

// JWKS returns the exact bytes served at /jwks (what a login snapshots).
func (s *Server) JWKS() []byte { return s.jwksBytes }

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, map[string]any{
		"issuer":                                s.URL,
		"authorization_endpoint":                s.URL + "/authorize",
		"token_endpoint":                        s.URL + "/token",
		"jwks_uri":                              s.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "email", "profile"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.Write(s.jwksBytes) //nolint:errcheck
}

// authorize is the instant-approval authorization endpoint: it validates
// the shape of the request, stores the code, and 302s back to the loopback.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	redirectURI := q.Get("redirect_uri")
	ru, err := url.Parse(redirectURI)
	if err != nil || ru.Scheme != "http" {
		http.Error(w, "bad redirect_uri", http.StatusBadRequest)
		return
	}
	if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" ||
		q.Get("code_challenge") == "" || q.Get("client_id") == "" || q.Get("state") == "" {
		http.Error(w, "bad authorization request", http.StatusBadRequest)
		return
	}
	code, err := randomToken()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.codes[code] = authRequest{
		clientID:    q.Get("client_id"),
		redirectURI: redirectURI,
		nonce:       q.Get("nonce"),
		challenge:   q.Get("code_challenge"),
	}
	s.mu.Unlock()

	dest := *ru
	dq := dest.Query()
	dq.Set("code", code)
	dq.Set("state", q.Get("state"))
	dest.RawQuery = dq.Encode()
	http.Redirect(w, r, dest.String(), http.StatusFound)
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if r.PostForm.Get("grant_type") != "authorization_code" {
		oauthError(w, "unsupported_grant_type")
		return
	}
	s.mu.Lock()
	req, ok := s.codes[r.PostForm.Get("code")]
	delete(s.codes, r.PostForm.Get("code")) // single use
	s.mu.Unlock()
	if !ok {
		oauthError(w, "invalid_grant")
		return
	}
	// PKCE S256: BASE64URL(SHA256(code_verifier)) == code_challenge.
	verifier := r.PostForm.Get("code_verifier")
	sum := sha256.Sum256([]byte(verifier))
	if verifier == "" || base64.RawURLEncoding.EncodeToString(sum[:]) != req.challenge {
		oauthError(w, "invalid_grant")
		return
	}
	if got := r.PostForm.Get("redirect_uri"); got != "" && got != req.redirectURI {
		oauthError(w, "invalid_grant")
		return
	}

	nonce := req.nonce
	if s.MintNonce != nil {
		nonce = s.MintNonce(nonce)
	}
	now := time.Now()
	if s.Now != nil {
		now = s.Now()
	}
	claims := map[string]any{
		"iss":   s.URL,
		"sub":   s.Sub,
		"aud":   req.clientID,
		"exp":   now.Add(TokenTTL).Unix(),
		"iat":   now.Unix(),
		"nonce": nonce,
		"email": s.Sub + "@example.test",
	}
	if s.AuthTime != 0 {
		claims["auth_time"] = s.AuthTime
	}
	if len(s.AMR) > 0 {
		claims["amr"] = s.AMR
	}
	idToken, err := s.mintJWT(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]any{
		"access_token": "at-" + r.PostForm.Get("code"),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (s *Server) mintJWT(claims map[string]any) (string, error) {
	var key any = s.Key
	if s.edKey != nil {
		key = s.edKey
	}
	// SignWith substitutes a key the published JWKS cannot verify — the
	// wrong-signature case — and wins over both.
	if s.SignWith != nil {
		key = s.SignWith
	}
	alg := s.alg
	if alg == "" {
		alg = jose.RS256
	}
	if s.SignWith != nil {
		alg = jose.RS256
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", s.KID).WithType("JWT"),
	)
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	return obj.CompactSerialize()
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func oauthError(w http.ResponseWriter, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": code}) //nolint:errcheck
}

func randomToken() (string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
