package oidclogin

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/identity"
	"github.com/behalf-sh/behalf/internal/oidctest"
	"github.com/behalf-sh/behalf/internal/receipt"
)

const testClientID = "behalf-cli-test"

// follow drives the redirect leg headlessly: GET the auth URL; the fake IdP
// 302s straight back to the flow's loopback listener.
func follow(u string) {
	resp, err := http.Get(u)
	if err != nil {
		return
	}
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	resp.Body.Close()
}

// login runs one full headless flow against idp into dir.
func login(t *testing.T, idp *oidctest.Server, dir string) (*Result, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return Login(ctx, Config{
		Issuer:    idp.URL,
		ClientID:  testClientID,
		Dir:       dir,
		NoBrowser: true,
		OnAuthURL: func(u string) { go follow(u) },
	})
}

// mustLogin runs a successful login and closes the IdP, so everything the
// test does afterwards is provably offline.
func mustLogin(t *testing.T) (string, *Result) {
	t.Helper()
	idp := oidctest.New()
	defer idp.Close()
	idp.AuthTime = time.Now().Add(-time.Minute).Unix()
	idp.AMR = []string{"pwd"}
	dir := t.TempDir()
	res, err := login(t, idp, dir)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	return dir, res
}

// spoolEntry mirrors one spool.jsonl line.
type spoolEntry struct {
	Kind        string          `json:"kind"`
	PayloadType string          `json:"payloadType"`
	Payload     json.RawMessage `json:"payload"`
	Sig         struct {
		KeyID string `json:"keyid"`
		Sig   string `json:"sig"`
	} `json:"sig"`
	LeafHash string `json:"leaf_hash"`
}

func readSpool(t *testing.T, dir string) []spoolEntry {
	t.Helper()
	b, err := os.ReadFile(dir + "/" + SpoolFile)
	if err != nil {
		t.Fatalf("read spool: %v", err)
	}
	var out []spoolEntry
	for _, line := range bytes.Split(bytes.TrimSpace(b), []byte("\n")) {
		var e spoolEntry
		if err := json.Unmarshal(line, &e); err != nil {
			t.Fatalf("parse spool line: %v\nline: %s", err, line)
		}
		out = append(out, e)
	}
	return out
}

func TestLoginFullFlow(t *testing.T) {
	dir, res := mustLogin(t)

	if !regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`).MatchString(res.DeviceJKT) {
		t.Fatalf("device jkt %q is not an RFC 7638 thumbprint", res.DeviceJKT)
	}
	// The pseudonymous principal: sha256(issuer "\n" sub), never the raw
	// sub (Q40).
	if want := SubDigest(res.Issuer, "user-1234"); res.SubDigest != want {
		t.Fatalf("sub_digest = %s, want %s", res.SubDigest, want)
	}

	// The persisted device key is the one the nonce bound.
	dev, err := identity.LoadDevice(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dev.JKT != res.DeviceJKT {
		t.Fatalf("persisted device key jkt %s != login result %s", dev.JKT, res.DeviceJKT)
	}

	// login.json exists and matches.
	st, err := LoadLoginState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if st.DeviceJKT != res.DeviceJKT || st.IDTokenDigest != res.IDTokenDigest ||
		st.JWKSDigest != res.JWKSDigest || st.StatementDigest != res.StatementDigest {
		t.Fatal("login.json does not match the login result")
	}

	// The raw sub must not appear anywhere outside the ID-token blob.
	for _, f := range []string{dir + "/" + LoginStateFile, dir + "/" + SpoolFile} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte("user-1234")) {
			t.Fatalf("raw sub leaked into %s", f)
		}
	}
}

func TestBlobsPersistedWithCorrectDigests(t *testing.T) {
	dir, res := mustLogin(t)

	for _, d := range []string{res.IDTokenDigest, res.JWKSDigest, res.StatementDigest} {
		b, err := getBlob(dir, d)
		if err != nil {
			t.Fatalf("blob %s: %v", d, err)
		}
		if digestHex(b) != d {
			t.Fatalf("blob %s content hashes to %s", d, digestHex(b))
		}
	}

	// The ID-token blob is the FULL raw compact JWS.
	idTok, err := getBlob(dir, res.IDTokenDigest)
	if err != nil {
		t.Fatal(err)
	}
	if parts := strings.Split(string(idTok), "."); len(parts) != 3 {
		t.Fatalf("ID-token blob is not a compact JWS (%d segments)", len(parts))
	}

	// The JWKS blob parses as a key set usable for verification.
	jwks, err := getBlob(dir, res.JWKSDigest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staticKeySet(jwks); err != nil {
		t.Fatalf("persisted JWKS snapshot unusable: %v", err)
	}

	// The statement blob opens and carries the full five-field binding.
	stBlob, err := getBlob(dir, res.StatementDigest)
	if err != nil {
		t.Fatal(err)
	}
	stmt, err := openStatement(stBlob)
	if err != nil {
		t.Fatal(err)
	}
	if stmt.Issuer != res.Issuer || stmt.SubDigest != res.SubDigest ||
		stmt.NonceJKT != res.DeviceJKT || stmt.IDTokenDigest != res.IDTokenDigest ||
		stmt.JWKSDigest != res.JWKSDigest {
		t.Fatalf("statement binding does not match the login result: %+v", stmt)
	}
}

func TestJWKSSnapshotMatchesProvider(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	dir := t.TempDir()
	res, err := login(t, idp, dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := getBlob(dir, res.JWKSDigest)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, idp.JWKS()) {
		t.Fatal("JWKS snapshot is not the bytes the provider served")
	}
}

func TestRootReceiptSpooledSignedAndSchemaValid(t *testing.T) {
	dir, res := mustLogin(t)

	entries := readSpool(t, dir)
	if len(entries) != 1 {
		t.Fatalf("spool has %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Kind != "spooled" || e.PayloadType != exportv1.PayloadTypeReceipt {
		t.Fatalf("unexpected spool entry framing: kind=%q payloadType=%q", e.Kind, e.PayloadType)
	}
	if !bytes.Equal(e.Payload, res.SealedReceipt) {
		t.Fatal("spooled payload is not the sealed receipt bytes, verbatim")
	}

	// Envelope signature: the EMITTER key, not the device key (Q19).
	em, err := identity.LoadKey(identity.EmitterKeyPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	if e.Sig.KeyID != em.JKT {
		t.Fatalf("spool sig keyid = %s, want emitter %s", e.Sig.KeyID, em.JKT)
	}
	if e.Sig.KeyID == res.DeviceJKT {
		t.Fatal("receipt envelope must not be signed by the device key")
	}
	sig, err := base64.StdEncoding.DecodeString(e.Sig.Sig)
	if err != nil {
		t.Fatal(err)
	}
	if !dsse.Verify(em.Public, e.PayloadType, e.Payload, sig) {
		t.Fatal("emitter DSSE signature over the sealed receipt does not verify")
	}

	// The frozen v1 schema accepts the payload.
	c := jsonschema.NewCompiler()
	sch, err := c.Compile("../../docs/receipt-schema-v1.schema.json")
	if err != nil {
		t.Fatalf("compile schema: %v", err)
	}
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(e.Payload))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(v); err != nil {
		t.Fatalf("root receipt violates the frozen schema: %v\npayload: %s", err, e.Payload)
	}

	// Spot-check the receipt shape.
	var r receipt.Receipt
	if err := json.Unmarshal(e.Payload, &r); err != nil {
		t.Fatal(err)
	}
	if r.Kind != "delegation" {
		t.Fatalf("kind = %q, want delegation", r.Kind)
	}
	if r.Attribution.Verification != "verified" || r.Attribution.Class != "direct" {
		t.Fatalf("attribution = %+v", r.Attribution)
	}
	if r.Authority == nil || len(r.Authority.Chain) != 1 {
		t.Fatal("root receipt must carry exactly the depth-0 hop")
	}
	hop := r.Authority.Chain[0]
	if hop.DelDepth != 0 {
		t.Fatalf("del_depth = %d, want 0", hop.DelDepth)
	}
	rb := hop.RootPrincipalBinding
	if rb == nil || rb.Nonce != res.DeviceJKT || rb.DeviceJKT != res.DeviceJKT || rb.IDTokenRef != res.IDTokenDigest {
		t.Fatalf("root_principal_binding = %+v", rb)
	}
	if hop.Credential.Issuer != res.Issuer || hop.Credential.ID != "oidc-sub-digest:"+res.SubDigest {
		t.Fatalf("credential = %+v", hop.Credential)
	}
	if hop.Credential.AuthTime == 0 || len(hop.Credential.AMR) == 0 {
		t.Fatalf("credential must carry auth_time and amr when the IdP exposes them: %+v", hop.Credential)
	}
	roles := map[string]string{}
	for _, s := range r.Payload {
		roles[s.Role] = s.Digest
		if s.Custody != "customer-held" || s.State != "present" {
			t.Fatalf("payload slot %q: custody=%q state=%q", s.Role, s.Custody, s.State)
		}
	}
	if roles["id_token"] != res.IDTokenDigest || roles["jwks_snapshot"] != res.JWKSDigest || roles["root_delegation"] != res.StatementDigest {
		t.Fatalf("payload slots = %v", roles)
	}
}

func TestVerifyRootAllGreenOffline(t *testing.T) {
	// mustLogin closed the fake IdP: this verification has no network to
	// talk to (Q18: offline, against the snapshot).
	dir, _ := mustLogin(t)

	rep, err := VerifyRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateVerified {
		t.Fatalf("state = %s, want verified; reasons: %v", rep.State, rep.Reasons)
	}
	if len(rep.Reasons) != 0 {
		t.Fatalf("verified root should carry no reasons, got %v", rep.Reasons)
	}
	got := map[string]CheckStatus{}
	for _, c := range rep.Checks {
		got[c.Name] = c.Status
	}
	for _, name := range []string{CheckIdPSignature, CheckNonceBinding, CheckRootDelegSig} {
		if got[name] != CheckPass {
			t.Fatalf("check %s = %s, want pass (checks: %+v)", name, got[name], rep.Checks)
		}
	}
}

func TestVerifyRootDegradedAfterIDTokenBlobDeleted(t *testing.T) {
	dir, res := mustLogin(t)

	if err := os.Remove(identity.BlobsDir(dir) + "/" + res.IDTokenDigest); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateDegraded {
		t.Fatalf("state = %s, want degraded (NOT broken); reasons: %v", rep.State, rep.Reasons)
	}
	all := strings.Join(rep.Reasons, "\n")
	if !strings.Contains(all, "behalf-attested") {
		t.Fatalf("degraded report must say the root is behalf-attested (Q22); got: %s", all)
	}
	// Check 3 still passes: the statement is intact.
	for _, c := range rep.Checks {
		if c.Name == CheckRootDelegSig && c.Status != CheckPass {
			t.Fatalf("root delegation check = %s, want pass", c.Status)
		}
	}
}

func TestVerifyRootDegradedAfterStatementBlobDeleted(t *testing.T) {
	dir, res := mustLogin(t)

	if err := os.Remove(identity.BlobsDir(dir) + "/" + res.StatementDigest); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateDegraded {
		t.Fatalf("state = %s, want degraded; reasons: %v", rep.State, rep.Reasons)
	}
	// Checks 1 and 2 still run from login.json's index and pass.
	got := map[string]CheckStatus{}
	for _, c := range rep.Checks {
		got[c.Name] = c.Status
	}
	if got[CheckIdPSignature] != CheckPass || got[CheckNonceBinding] != CheckPass {
		t.Fatalf("checks 1/2 should still pass without the statement: %+v", rep.Checks)
	}
	if got[CheckRootDelegSig] != CheckSkipped {
		t.Fatalf("check 3 = %s, want skipped", got[CheckRootDelegSig])
	}
}

func TestVerifyRootBrokenOnTamperedIDTokenBlob(t *testing.T) {
	dir, res := mustLogin(t)

	path := identity.BlobsDir(dir) + "/" + res.IDTokenDigest
	if err := os.WriteFile(path, []byte("not the token"), 0o600); err != nil {
		t.Fatal(err)
	}
	rep, err := VerifyRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateBroken {
		t.Fatalf("state = %s, want broken; reasons: %v", rep.State, rep.Reasons)
	}
}

func TestNonceMismatchRejected(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	idp.MintNonce = func(requested string) string { return "evil-" + requested[:20] }
	dir := t.TempDir()

	_, err := login(t, idp, dir)
	if err == nil {
		t.Fatal("login accepted an ID token whose nonce is not the device key thumbprint")
	}
	if !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("rejection should name the nonce binding: %v", err)
	}
	// Nothing was persisted: a failed login leaves no root.
	if _, err := LoadLoginState(dir); !errors.Is(err, ErrNoLogin) {
		t.Fatalf("failed login must not write login.json: %v", err)
	}
	if _, err := identity.LoadDevice(dir); !os.IsNotExist(err) {
		t.Fatalf("failed login must not persist a device key: %v", err)
	}
}

func TestWrongSignatureRejected(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	evil := oidctest.New() // a second provider only for its RSA key
	defer evil.Close()
	idp.SignWith = evil.Key
	dir := t.TempDir()

	_, err := login(t, idp, dir)
	if err == nil {
		t.Fatal("login accepted an ID token the published JWKS cannot verify")
	}
	if !strings.Contains(err.Error(), "id token rejected") {
		t.Fatalf("rejection should come from ID-token validation: %v", err)
	}
	if _, err := LoadLoginState(dir); !errors.Is(err, ErrNoLogin) {
		t.Fatalf("failed login must not write login.json: %v", err)
	}
}

func TestReloginRotatesRootAndKeepsSpool(t *testing.T) {
	idp := oidctest.New()
	defer idp.Close()
	dir := t.TempDir()

	first, err := login(t, idp, dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := login(t, idp, dir)
	if err != nil {
		t.Fatal(err)
	}
	if first.DeviceJKT == second.DeviceJKT {
		t.Fatal("each login must mint a fresh device key (D5: the nonce binds THIS login)")
	}
	entries := readSpool(t, dir)
	if len(entries) != 2 {
		t.Fatalf("spool has %d entries after two logins, want 2", len(entries))
	}
	// Emitter counter advanced.
	var r0, r1 receipt.Receipt
	if err := json.Unmarshal(entries[0].Payload, &r0); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(entries[1].Payload, &r1); err != nil {
		t.Fatal(err)
	}
	if r1.Emitter.Counter != r0.Emitter.Counter+1 {
		t.Fatalf("emitter counter %d -> %d, want +1", r0.Emitter.Counter, r1.Emitter.Counter)
	}
	// The new root verifies.
	rep, err := VerifyRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	if rep.State != StateVerified {
		t.Fatalf("state after re-login = %s, want verified; %v", rep.State, rep.Reasons)
	}
}

func TestVerifyRootNoLogin(t *testing.T) {
	_, err := VerifyRoot(t.TempDir())
	if !errors.Is(err, ErrNoLogin) {
		t.Fatalf("err = %v, want ErrNoLogin", err)
	}
}
