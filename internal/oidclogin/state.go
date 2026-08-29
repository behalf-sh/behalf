package oidclogin

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// login.json: the convenience index of the last login. It is NOT evidence —
// every value in it is re-checked against the signed, content-addressed
// material by VerifyRoot — it only tells the verifier where to look.

// LoginStateFile is the login index file name under the state dir.
const LoginStateFile = "login.json"

// SpoolFile is the local receipt spool under the state dir. Each line is a
// signed spool entry; the log service consumes it when it lands.
const SpoolFile = "spool.jsonl"

// ErrNoLogin means no login has ever completed in this state dir. Records
// emitted from here carry asserted attribution forever (Q21): immutability
// means no retro-upgrade.
var ErrNoLogin = errors.New("oidclogin: no login recorded")

// LoginState is the persisted index of the last completed login.
type LoginState struct {
	SchemaVersion   string `json:"schema_version"` // behalf.sh/login-state/v1
	Issuer          string `json:"issuer"`
	ClientID        string `json:"client_id"`
	SubDigest       string `json:"sub_digest"`
	DeviceJKT       string `json:"device_jkt"`
	IDTokenDigest   string `json:"id_token_digest"`
	JWKSDigest      string `json:"jwks_digest"`
	StatementDigest string `json:"statement_digest"`
	ReceiptID       string `json:"receipt_id"`
	LoggedInAt      string `json:"logged_in_at"` // RFC 3339
}

// loginStateSchemaVersion is the login.json projection key.
const loginStateSchemaVersion = "behalf.sh/login-state/v1"

func loginStatePath(stateDir string) string {
	return filepath.Join(stateDir, LoginStateFile)
}

func saveLoginState(stateDir string, st *LoginState) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	tmp := loginStatePath(stateDir) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, loginStatePath(stateDir))
}

// LoadLoginState reads login.json from stateDir. Returns ErrNoLogin
// (wrapped) if it does not exist.
func LoadLoginState(stateDir string) (*LoginState, error) {
	b, err := os.ReadFile(loginStatePath(stateDir))
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("%w (state dir %s)", ErrNoLogin, stateDir)
	}
	if err != nil {
		return nil, err
	}
	var st LoginState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("oidclogin: parse login.json: %w", err)
	}
	if st.SchemaVersion != loginStateSchemaVersion {
		return nil, fmt.Errorf("oidclogin: login.json schema_version %q, want %q", st.SchemaVersion, loginStateSchemaVersion)
	}
	return &st, nil
}
