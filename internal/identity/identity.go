// Package identity manages the behalf state directory and the two local
// Ed25519 keys that live in it:
//
//   - the device key — the human principal's root key. Its RFC 7638 JWK
//     thumbprint is the OIDC nonce at `behalf login` (D5), which makes it
//     the verified identity root. Generated fresh at login.
//   - the emitter key — the capture surface's own key (receipt-schema-v1.md
//     §5, Q19). It signs receipt DSSE envelopes and is distinct from any
//     human device key.
//
// The state directory defaults to ~/.behalf, overridable via the
// BEHALF_HOME environment variable or an explicit --dir flag. Private key
// files are written with mode 0600 and the directory with 0700.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/behalf-sh/behalf/internal/dsse"
)

// EnvHome is the environment variable that overrides the default state dir.
const EnvHome = "BEHALF_HOME"

// DefaultDirName is the state directory created under $HOME by default.
const DefaultDirName = ".behalf"

// File names inside the state directory.
const (
	DeviceKeyFile  = "device_key.jwk"
	EmitterKeyFile = "emitter_key.jwk"
	CounterFile    = "emitter.counter"
	BlobsDirName   = "blobs"
)

// Key is a local Ed25519 keypair with its JWK form and RFC 7638 thumbprint.
type Key struct {
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	JWK     dsse.JWK
	JKT     string
}

// Generate creates a fresh Ed25519 keypair.
func Generate() (*Key, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("identity: generate key: %w", err)
	}
	return fromPrivate(priv, pub), nil
}

func fromPrivate(priv ed25519.PrivateKey, pub ed25519.PublicKey) *Key {
	jwk := dsse.JWKFromPublic(pub)
	return &Key{
		Private: priv,
		Public:  pub,
		JWK:     jwk,
		JKT:     jwk.Thumbprint(),
	}
}

// privateJWK is the on-disk form: an RFC 8037 OKP JWK with the private seed
// in "d" (base64url, no padding).
type privateJWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	D   string `json:"d"`
}

// ResolveDir returns the state directory: explicit (from a --dir flag) if
// non-empty, else $BEHALF_HOME if set, else ~/.behalf.
func ResolveDir(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if env := os.Getenv(EnvHome); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("identity: resolve home dir: %w", err)
	}
	return filepath.Join(home, DefaultDirName), nil
}

// EnsureDir creates the state directory (and its blobs/ subdirectory) with
// owner-only permissions if it does not exist.
func EnsureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("identity: create state dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Join(dir, BlobsDirName), 0o700); err != nil {
		return fmt.Errorf("identity: create blobs dir: %w", err)
	}
	return nil
}

// BlobsDir returns the content-addressed store directory under dir.
func BlobsDir(dir string) string { return filepath.Join(dir, BlobsDirName) }

// SaveKey writes k's private JWK to path with mode 0600. The write is
// atomic: a temp file in the same directory is renamed into place.
func SaveKey(k *Key, path string) error {
	seed := k.Private.Seed()
	pj := privateJWK{
		Kty: k.JWK.Kty,
		Crv: k.JWK.Crv,
		X:   k.JWK.X,
		D:   base64.RawURLEncoding.EncodeToString(seed),
	}
	b, err := json.Marshal(pj)
	if err != nil {
		return fmt.Errorf("identity: marshal key: %w", err)
	}
	return writeFileAtomic(path, b, 0o600)
}

// LoadKey reads a private JWK written by SaveKey.
func LoadKey(path string) (*Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var pj privateJWK
	if err := json.Unmarshal(b, &pj); err != nil {
		return nil, fmt.Errorf("identity: parse %s: %w", path, err)
	}
	if pj.Kty != "OKP" || pj.Crv != "Ed25519" {
		return nil, fmt.Errorf("identity: %s: unsupported key type %q/%q", path, pj.Kty, pj.Crv)
	}
	seed, err := base64.RawURLEncoding.DecodeString(pj.D)
	if err != nil {
		return nil, fmt.Errorf("identity: %s: decode d: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("identity: %s: seed is %d bytes, want %d", path, len(seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	k := fromPrivate(priv, pub)
	if pj.X != k.JWK.X {
		return nil, fmt.Errorf("identity: %s: public half does not match private seed", path)
	}
	return k, nil
}

// DeviceKeyPath returns the device key file path under dir.
func DeviceKeyPath(dir string) string { return filepath.Join(dir, DeviceKeyFile) }

// EmitterKeyPath returns the emitter key file path under dir.
func EmitterKeyPath(dir string) string { return filepath.Join(dir, EmitterKeyFile) }

// LoadDevice loads the device key from dir. os.IsNotExist on the returned
// error distinguishes "never logged in" from corruption.
func LoadDevice(dir string) (*Key, error) {
	return LoadKey(DeviceKeyPath(dir))
}

// SaveDevice persists the device key under dir with mode 0600.
func SaveDevice(dir string, k *Key) error {
	if err := EnsureDir(dir); err != nil {
		return err
	}
	return SaveKey(k, DeviceKeyPath(dir))
}

// LoadOrGenerateEmitter returns the emitter key from dir, generating and
// persisting one on first use. The emitter key is the capture surface's own
// key, distinct from any device key (Q19).
func LoadOrGenerateEmitter(dir string) (*Key, error) {
	path := EmitterKeyPath(dir)
	k, err := LoadKey(path)
	if err == nil {
		return k, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := EnsureDir(dir); err != nil {
		return nil, err
	}
	k, err = Generate()
	if err != nil {
		return nil, err
	}
	if err := SaveKey(k, path); err != nil {
		return nil, err
	}
	return k, nil
}

// NextEmitterCounter returns the next per-emitter monotonic counter value
// and persists the advance (receipt-schema-v1.md §5, Q48). The first call
// returns 0. Single-process use only, which is the CLI's situation; the log
// service owns cross-process sequencing.
func NextEmitterCounter(dir string) (int, error) {
	path := filepath.Join(dir, CounterFile)
	next := 0
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		n, perr := strconv.Atoi(strings.TrimSpace(string(b)))
		if perr != nil {
			return 0, fmt.Errorf("identity: parse %s: %w", path, perr)
		}
		next = n
	case errors.Is(err, os.ErrNotExist):
		// first use
	default:
		return 0, err
	}
	if err := writeFileAtomic(path, []byte(strconv.Itoa(next+1)+"\n"), 0o600); err != nil {
		return 0, err
	}
	return next, nil
}

// writeFileAtomic writes data to path via a same-directory temp file and
// rename, so a crash never leaves a truncated key or counter.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op after successful rename
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
