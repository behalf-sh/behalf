package witness

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// DefaultKeyName is the note key name a fresh witness key takes. It is the
// witness's identity in every cosignature line it ever writes, so it is
// chosen once and never re-keyed (Q70's identifier discipline applied to
// the fourth key of the Q69 custody matrix).
const DefaultKeyName = "behalf.sh/witness/1"

// noteAlgEd25519 is the sumdb/note algorithm byte for a plain Ed25519 key.
// The published witness verifier key uses C2SP's cosignature/v1 algorithm
// (0x04) instead, derived from the same Ed25519 key material.
const noteAlgEd25519 = 1

// Key is the witness's Ed25519 signing key in the three forms it is needed
// in: the sumdb/note private key that is stored on disk, the C2SP
// cosignature/v1 verifier key that logs configure, and the note.Signer that
// produces timestamped cosignature lines.
type Key struct {
	Name string // the note key name; appears in every cosignature line
	SKey string // note-format private key ("PRIVATE+KEY+…"), 0600 on disk
	VKey string // C2SP cosignature/v1 verifier key — what a log configures

	signer   note.Signer
	verifier note.Verifier
}

// GenerateKey creates a fresh Ed25519 witness key under the given note name.
func GenerateKey(name string) (*Key, error) {
	if name == "" {
		name = DefaultKeyName
	}
	skey, _, err := note.GenerateKey(rand.Reader, name)
	if err != nil {
		return nil, fmt.Errorf("witness: generate key: %w", err)
	}
	return ParseKey(skey)
}

// ParseKey rebuilds a Key from its note-format private key string. The
// cosignature/v1 verifier key is derived, not stored redundantly: the note
// skey embeds base64(alg || seed) and the key hash of the plain vkey, which
// is everything the derivation needs.
func ParseKey(skey string) (*Key, error) {
	skey = strings.TrimSpace(skey)
	signer, err := f_note.NewSignerForCosignatureV1(skey)
	if err != nil {
		return nil, fmt.Errorf("witness: parse signing key: %w", err)
	}
	// Fields: PRIVATE+KEY+<name>+<hash>+<base64>. Note names cannot contain
	// '+', but the base64 key material can — split from the left, keeping
	// the final field whole.
	parts := strings.SplitN(skey, "+", 5)
	if len(parts) != 5 || parts[0] != "PRIVATE" || parts[1] != "KEY" {
		return nil, errors.New("witness: malformed note skey")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("witness: decode skey material: %w", err)
	}
	if len(raw) != 1+ed25519.SeedSize || raw[0] != noteAlgEd25519 {
		return nil, errors.New("witness: signing key is not Ed25519")
	}
	pub := ed25519.NewKeyFromSeed(raw[1:]).Public().(ed25519.PublicKey)
	plainVKey := fmt.Sprintf("%s+%s+%s", signer.Name(), parts[3],
		base64.StdEncoding.EncodeToString(append([]byte{noteAlgEd25519}, pub...)))
	vkey, err := f_note.VKeyToCosignatureV1(plainVKey)
	if err != nil {
		return nil, fmt.Errorf("witness: derive cosignature/v1 vkey: %w", err)
	}
	verifier, err := f_note.NewVerifierForCosignatureV1(vkey)
	if err != nil {
		return nil, fmt.Errorf("witness: derived vkey does not parse: %w", err)
	}
	return &Key{
		Name:     signer.Name(),
		SKey:     skey,
		VKey:     vkey,
		signer:   signer,
		verifier: verifier,
	}, nil
}

// CosignText signs a checkpoint note body and returns the signature line
// (`— <name> <base64>\n`), which the caller appends to the checkpoint.
//
// The cosignature/v1 construction signs `cosignature/v1\ntime <unix>\n` +
// the note body, and encodes the timestamp inside the signature, so every
// call produces different bytes for the same body. That is by design: the
// cosignature asserts observation at a time, not just agreement.
func (k *Key) CosignText(text []byte) ([]byte, error) {
	body := text
	if len(body) == 0 || body[len(body)-1] != '\n' {
		body = append(append([]byte{}, body...), '\n')
	}
	signed, err := note.Sign(&note.Note{Text: string(body)}, k.signer)
	if err != nil {
		return nil, fmt.Errorf("witness: sign checkpoint: %w", err)
	}
	i := bytes.Index(signed, []byte("\n\n"))
	if i < 0 {
		return nil, errors.New("witness: signed note has no signature block")
	}
	return signed[i+2:], nil
}

// Verifier returns the note verifier for this witness's cosignatures.
func (k *Key) Verifier() note.Verifier { return k.verifier }

// Witness key files, relative to a key path: the private key at the path
// itself, the published verifier key beside it. The private key is the one
// thing on a witness host that matters; it is never in a backup (Q76) and
// never served.
const vkeySuffix = ".vkey"

// SaveKey writes the private key to path (0600) and the cosignature/v1
// verifier key to path+".vkey" (0644).
func SaveKey(path string, k *Key) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("witness: create key dir: %w", err)
		}
	}
	if err := os.WriteFile(path, []byte(k.SKey+"\n"), 0o600); err != nil {
		return fmt.Errorf("witness: write signing key: %w", err)
	}
	if err := os.WriteFile(path+vkeySuffix, []byte(k.VKey+"\n"), 0o644); err != nil {
		return fmt.Errorf("witness: write verifier key: %w", err)
	}
	return nil
}

// LoadKey reads the private key at path and rebuilds the full Key.
func LoadKey(path string) (*Key, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("witness: read signing key: %w", err)
	}
	return ParseKey(string(b))
}

// VKeyPath is where SaveKey puts the verifier key for a given key path.
func VKeyPath(keyPath string) string { return keyPath + vkeySuffix }
