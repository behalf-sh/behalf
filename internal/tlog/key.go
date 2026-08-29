package tlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/mod/sumdb/note"

	"github.com/behalf-sh/behalf/internal/dsse"
)

// Checkpoint key files, relative to the log dir. The private key must never
// be exposed by whatever serves the log dir (nginx etc.); serving configs
// must exclude keys/, index.db, epoch.json and .state/.
const (
	keyDirName   = "keys"
	skeyFileName = "checkpoint.skey" // note-format private key, 0600
	vkeyFileName = "checkpoint.vkey" // note-format verifier (public) key
)

// CheckpointKey is the log's Ed25519 checkpoint key in both forms behalf
// needs: the note-format signer/verifier strings Tessera expects
// (WithCheckpointSigner takes a note.Signer, and the signer's name becomes
// the checkpoint origin line), and the raw Ed25519 key pair used to sign
// receipt promises (architecture D2/Q57: only the current lock-holder's
// checkpoint key signs promises).
type CheckpointKey struct {
	Origin  string // the note key name == checkpoint origin line
	SKey    string // note-format private key ("PRIVATE+KEY+...")
	VKey    string // note-format verifier key
	Private ed25519.PrivateKey
	Public  ed25519.PublicKey
	JWK     dsse.JWK
	JKT     string // RFC 7638 thumbprint of JWK
}

// GenerateCheckpointKey creates a fresh Ed25519 checkpoint key whose note
// name (and therefore checkpoint origin) is origin.
func GenerateCheckpointKey(origin string) (*CheckpointKey, error) {
	skey, _, err := note.GenerateKey(rand.Reader, origin)
	if err != nil {
		return nil, fmt.Errorf("tlog: generate checkpoint key: %w", err)
	}
	return ParseCheckpointKey(skey)
}

// ParseCheckpointKey rebuilds a CheckpointKey from the note-format private
// key string. The note skey embeds the Ed25519 seed
// (base64(algEd25519 || seed)); the vkey is re-derived from it.
func ParseCheckpointKey(skey string) (*CheckpointKey, error) {
	// Validate via the note package first: name, hash and algorithm checks.
	signer, err := note.NewSigner(skey)
	if err != nil {
		return nil, fmt.Errorf("tlog: parse checkpoint skey: %w", err)
	}
	// Fields: PRIVATE+KEY+<name>+<hash>+<base64>. Note names cannot contain
	// '+', but the base64 key material can — split from the left, keeping
	// the final field whole.
	parts := strings.SplitN(skey, "+", 5)
	if len(parts) != 5 || parts[0] != "PRIVATE" || parts[1] != "KEY" {
		return nil, errors.New("tlog: malformed note skey")
	}
	raw, err := base64.StdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, fmt.Errorf("tlog: decode skey material: %w", err)
	}
	const algEd25519 = 1
	if len(raw) != 1+ed25519.SeedSize || raw[0] != algEd25519 {
		return nil, errors.New("tlog: checkpoint key is not Ed25519")
	}
	priv := ed25519.NewKeyFromSeed(raw[1:])
	pub := priv.Public().(ed25519.PublicKey)
	jwk := dsse.JWKFromPublic(pub)

	// Reconstruct the vkey: <name>+<hash>+<base64(alg||pub)>. The hash in
	// the skey is computed over the same (name, alg||pub) pair, so reuse it.
	vkey := fmt.Sprintf("%s+%s+%s", signer.Name(), parts[3],
		base64.StdEncoding.EncodeToString(append([]byte{algEd25519}, pub...)))
	if _, err := note.NewVerifier(vkey); err != nil {
		return nil, fmt.Errorf("tlog: reconstructed vkey invalid: %w", err)
	}

	return &CheckpointKey{
		Origin:  signer.Name(),
		SKey:    skey,
		VKey:    vkey,
		Private: priv,
		Public:  pub,
		JWK:     jwk,
		JKT:     jwk.Thumbprint(),
	}, nil
}

// SaveCheckpointKey writes the key files under dir/keys.
func SaveCheckpointKey(dir string, k *CheckpointKey) error {
	kd := filepath.Join(dir, keyDirName)
	if err := os.MkdirAll(kd, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(kd, skeyFileName), []byte(k.SKey+"\n"), 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(kd, vkeyFileName), []byte(k.VKey+"\n"), 0o644)
}

// LoadCheckpointKey reads the private key file under dir/keys and rebuilds
// the full CheckpointKey.
func LoadCheckpointKey(dir string) (*CheckpointKey, error) {
	b, err := os.ReadFile(filepath.Join(dir, keyDirName, skeyFileName))
	if err != nil {
		return nil, fmt.Errorf("tlog: read checkpoint key: %w", err)
	}
	return ParseCheckpointKey(strings.TrimSpace(string(b)))
}

// LoadVerifierKey reads the public verifier key file under dir/keys.
func LoadVerifierKey(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, keyDirName, vkeyFileName))
	if err != nil {
		return "", fmt.Errorf("tlog: read verifier key: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

// NoteSigner returns the note.Signer Tessera expects for checkpoint signing.
func (k *CheckpointKey) NoteSigner() (note.Signer, error) {
	return note.NewSigner(k.SKey)
}

// NoteVerifier returns the note.Verifier for this key's checkpoints.
func (k *CheckpointKey) NoteVerifier() (note.Verifier, error) {
	return note.NewVerifier(k.VKey)
}

// ---- emitter key persistence ------------------------------------------

// EmittersFileName holds the public JWKs of every emitter key registered
// with this log, one JSON object per line, under keys/.
//
// # The one thing that was not rebuildable
//
// Q76's claim is that the follower index is disposable: delete it, replay the
// entry bundles, get it back. The keys table was the single exception, and it
// was not a soft one. Stored envelopes carry key *thumbprints* only, so a
// replay recovers no JWK, and the export bridge needs the JWK to write a
// header — `behalf-log export` after a reindex failed outright with
// "exportv1: header requires at least one key". A log you could not export
// from until you happened to re-ingest was a log whose evidence was hostage to
// a cache.
//
// So registration writes here as well as into the index, and Open replays this
// file back. The file lives under `keys/`, which every serving configuration
// already excludes (see the note above), so this publishes nothing that was not
// already public — these are public keys — while keeping them out of the served
// tile directory where a reader might mistake them for log content.
//
// # What this is NOT
//
// It is not a trust anchor and it must not be read as one. A file on the log
// operator's own disk, editable by the log operator, cannot establish that an
// emitter key belongs to anyone: swap a line here and every receipt signed by
// the new key still verifies against it. That is exactly the gap the published
// key log (ENG-31) exists to close, and the honest scope of this file is
// "recover what the index knew", not "say whose key this is".
//
// Append-only and idempotent: re-registering a jkt appends nothing new, so the
// file does not grow with process restarts.
const EmittersFileName = "emitters.jsonl"

type emitterKeyLine struct {
	JKT string          `json:"jkt"`
	JWK json.RawMessage `json:"jwk"`
}

func emittersPath(dir string) string { return filepath.Join(dir, keyDirName, EmittersFileName) }

// LoadEmitterKeys reads the registered emitter keys as jkt -> JWK JSON. A
// missing file is not an error: a log that has never had a key registered has
// none, which is a fact rather than a fault.
func LoadEmitterKeys(dir string) (map[string]string, error) {
	b, err := os.ReadFile(emittersPath(dir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("tlog: read emitter keys: %w", err)
	}
	out := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var l emitterKeyLine
		if err := json.Unmarshal([]byte(line), &l); err != nil {
			// One unreadable line must not cost the rest. A key that cannot be
			// read is a key that was not recovered, which is the state this
			// file exists to improve on rather than a new failure.
			continue
		}
		if l.JKT != "" && len(l.JWK) > 0 {
			out[l.JKT] = string(l.JWK)
		}
	}
	return out, nil
}

// saveEmitterKey appends one registration, unless the jkt is already recorded.
func saveEmitterKey(dir, jkt, jwkJSON string) error {
	existing, err := LoadEmitterKeys(dir)
	if err != nil {
		return err
	}
	if _, ok := existing[jkt]; ok {
		return nil
	}
	if err := os.MkdirAll(filepath.Join(dir, keyDirName), 0o755); err != nil {
		return fmt.Errorf("tlog: create key dir: %w", err)
	}
	line, err := json.Marshal(emitterKeyLine{JKT: jkt, JWK: json.RawMessage(jwkJSON)})
	if err != nil {
		return fmt.Errorf("tlog: marshal emitter key: %w", err)
	}
	f, err := os.OpenFile(emittersPath(dir), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("tlog: open emitter keys: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("tlog: append emitter key: %w", err)
	}
	// The registration must be on the platter before the receipts it explains
	// reach the log: a crash between the two leaves a log nobody can export.
	return f.Sync()
}
