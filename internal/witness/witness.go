// Package witness is behalf's independent witness: the party that holds
// tree heads the log operator cannot retroactively change (architecture
// D3.5, Q29, Q74, Q76, Q96).
//
// A witness turns three claims from assertions into detectable facts:
//
//   - Split view (Q29). The operator cannot show one history to you and
//     another to someone else, because a witness that cosigned tree size N
//     with root R refuses to cosign a different root at size N — and its
//     refusal, like its signature, is evidence.
//   - Restore-as-truncation (Q76). A restore may never present a tree older
//     than the last witnessed checkpoint; a witness holding size N refuses
//     anything smaller.
//   - Checkpoint-key theft (Q74). Bounded, because a thief with the log's
//     signing key still cannot produce witness cosignatures for a forged
//     history: the witness checks consistency against what it already
//     holds, not merely the signature.
//
// # The safety rule
//
// For each log origin the witness holds exactly one head: the highest
// (size, root) it has cosigned. A new checkpoint is accepted only if it is
// consistent with that head:
//
//	never seen this origin  -> accept (and remember)
//	size == held, root ==   -> accept (idempotent re-cosign)
//	size == held, root !=   -> REFUSE same-size-different-root  (split view / fork)
//	size <  held            -> REFUSE smaller-size              (restore / truncation)
//	size >  held            -> accept iff the RFC 6962 consistency proof
//	                           from (held.size, held.root) to (size, root)
//	                           verifies, else REFUSE inconsistent-proof
//
// The consistency proof is supplied by the log, built from its own tiles
// (see tlog.ConsistencyProof), and verified here with
// transparency-dev/merkle's proof.VerifyConsistency — the RFC 6962 maths is
// not re-implemented.
//
// # Durability
//
// The head is persisted before the cosignature is returned. A witness with
// amnesia is not a witness: if it could forget a head it had signed for, it
// would happily cosign a fork after a restart, which is precisely the
// attack it exists to detect. See store.go for the on-disk format and its
// fsync discipline.
//
// # Signature format
//
// Cosignatures are C2SP signed-note `cosignature/v1` (Ed25519, algorithm
// 0x04) lines, so a cosignature rides on the checkpoint as one more
// signature line. Verifiers that do not know the witness key skip it as an
// unknown line — the grease discipline of D3.4, which the Rust verifier
// already implements (verifier/src/note.rs ignores signature lines whose
// decoded length is not 4+64 bytes, and a cosignature/v1 signature is
// 4+8+64).
package witness

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

// Head is the highest (size, root) a witness has cosigned for one origin.
type Head struct {
	Size uint64
	Root [32]byte
}

// RootHex renders the root hash as lowercase hex.
func (h Head) RootHex() string { return hex.EncodeToString(h.Root[:]) }

// Reason is the refusal vocabulary: the three ways a checkpoint can be
// inconsistent with what the witness already holds. These strings are
// stable — they appear in the witness's HTTP responses, in the log's
// per-checkpoint outcome records, and in the tamper suite's assertions.
type Reason string

const (
	// ReasonSmallerSize: the offered checkpoint covers fewer entries than
	// the head the witness holds. This is the Q76 stale-restore rule with
	// teeth — a restore may never present a tree older than the last
	// witnessed checkpoint.
	ReasonSmallerSize Reason = "smaller-size"
	// ReasonForkAtSize: same tree size, different root. This is the split
	// view of Q29: two histories offered as one.
	ReasonForkAtSize Reason = "same-size-different-root"
	// ReasonInconsistentProof: a larger tree whose consistency proof does
	// not carry the held root forward. The log grew into a different tree.
	ReasonInconsistentProof Reason = "inconsistent-proof"
)

// Class maps a refusal onto the verifier's existing tamper-class
// vocabulary (docs/export-format-v1.md §2/§2a), so witness findings speak
// the same language as `behalf-verify log`: a stale restore is
// `truncation`, a fork is `chain`.
func (r Reason) Class() string {
	switch r {
	case ReasonSmallerSize:
		return "truncation"
	case ReasonForkAtSize, ReasonInconsistentProof:
		return "chain"
	default:
		return "chain"
	}
}

// Describe is the canonical one-line explanation of a refusal, used by both
// ends: the witness puts it in the Refusal it returns, and the log's
// submitter uses it when the wire response carries only a status code and
// the reason header. One source of truth, so the two never disagree about
// what a refusal means.
func (r Reason) Describe() string {
	switch r {
	case ReasonSmallerSize:
		return "a restore may never present a tree older than the last witnessed checkpoint (Q76)"
	case ReasonForkAtSize:
		return "two different roots at the same tree size: a split view (Q29)"
	case ReasonInconsistentProof:
		return "the consistency proof does not carry the witnessed root forward into this tree"
	default:
		return string(r)
	}
}

// Refusal is the typed error a witness returns when a checkpoint is not
// consistent with the head it holds. A refusal is not a failure of the
// witness: it is the single most important signal the system can produce,
// and callers must record it loudly rather than retry it away.
type Refusal struct {
	Reason  Reason
	Origin  string
	Held    Head
	Offered Head
	Detail  string
}

func (r *Refusal) Error() string {
	msg := fmt.Sprintf("witness refuses to cosign %s at size %d (root %s): %s; holds size %d (root %s)",
		r.Origin, r.Offered.Size, short(r.Offered.RootHex()), r.Reason, r.Held.Size, short(r.Held.RootHex()))
	if r.Detail != "" {
		msg += ": " + r.Detail
	}
	return msg
}

// AsRefusal extracts the typed refusal from err, if there is one.
func AsRefusal(err error) (*Refusal, bool) {
	var r *Refusal
	ok := errors.As(err, &r)
	return r, ok
}

// Errors that are not refusals: the submission never got as far as the
// safety rule.
var (
	// ErrUnknownOrigin: the witness holds no log key for this checkpoint's
	// origin. C2SP tlog-witness maps this to 404.
	ErrUnknownOrigin = errors.New("witness: unknown checkpoint origin")
	// ErrLogSignature: the checkpoint carries no valid signature by the
	// log key registered for its origin. C2SP maps this to 403.
	ErrLogSignature = errors.New("witness: checkpoint is not signed by the log key for its origin")
	// ErrMalformedCheckpoint: the bytes are not a checkpoint note at all.
	ErrMalformedCheckpoint = errors.New("witness: malformed checkpoint")
)

// Witness cosigns checkpoints for the log origins whose keys it holds.
// It is safe for concurrent use: the read-verify-sign-persist sequence runs
// under one mutex, so two submissions racing at the same size can never
// both be cosigned unless they carry the same root.
type Witness struct {
	key   *Key
	logs  map[string]note.Verifier // origin -> the log's checkpoint verifier
	store *Store

	mu  sync.Mutex
	now func() time.Time
}

// New builds a witness signing with key, persisting to store, and trusting
// the note verifier keys in logVKeys (one standard Ed25519 note vkey per
// log; the key's name is the log origin it is trusted for).
func New(key *Key, store *Store, logVKeys []string) (*Witness, error) {
	if key == nil {
		return nil, errors.New("witness: nil key")
	}
	if store == nil {
		return nil, errors.New("witness: nil store")
	}
	logs := map[string]note.Verifier{}
	for _, vkey := range logVKeys {
		vkey = strings.TrimSpace(vkey)
		if vkey == "" {
			continue
		}
		v, err := note.NewVerifier(vkey)
		if err != nil {
			return nil, fmt.Errorf("witness: log verifier key %q: %w", short(vkey), err)
		}
		if _, dup := logs[v.Name()]; dup {
			return nil, fmt.Errorf("witness: two log keys for origin %q", v.Name())
		}
		logs[v.Name()] = v
	}
	return &Witness{key: key, logs: logs, store: store, now: time.Now}, nil
}

// Key returns the witness's signing key.
func (w *Witness) Key() *Key { return w.key }

// Store returns the witness's durable state.
func (w *Witness) Store() *Store { return w.store }

// Origins returns the log origins this witness will cosign for.
func (w *Witness) Origins() []string {
	out := make([]string, 0, len(w.logs))
	for origin := range w.logs {
		out = append(out, origin)
	}
	return out
}

// Held returns the head the witness currently holds for origin.
func (w *Witness) Held(origin string) (Head, bool) { return w.store.Head(origin) }

// Inspect verifies the log's own signature over a checkpoint and returns
// its origin and head, without applying the safety rule or writing
// anything. The HTTP surface uses it so that every statement it makes about
// a submission — including a refusal — is a statement about an
// authenticated checkpoint.
func (w *Witness) Inspect(checkpoint []byte) (string, Head, error) {
	cp, _, err := w.parse(checkpoint)
	if err != nil {
		return "", Head{}, err
	}
	return cp.Origin, cp.Head, nil
}

// Cosign implements the safety rule. It verifies the log's own signature
// over checkpoint, checks the checkpoint against the head held for its
// origin — accepting the same root at the same size, or a strictly larger
// size whose consistency proof checks against the held root — persists the
// new head, and returns the cosignature as a note signature line
// (`— <name> <base64>\n`), ready to append to the checkpoint.
//
// consistencyProof is the RFC 6962 consistency proof from the held size to
// the offered size, as built by the log from its tiles. It must be empty
// when the witness holds nothing for this origin or when the sizes are
// equal.
//
// A checkpoint that is not consistent is refused with a *Refusal carrying
// one of the three reasons; nothing is written and no signature is
// produced.
func (w *Witness) Cosign(checkpoint []byte, consistencyProof [][]byte) ([]byte, error) {
	cp, text, err := w.parse(checkpoint)
	if err != nil {
		return nil, err
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	held, seen := w.store.Head(cp.Origin)
	if seen {
		if err := checkConsistent(cp.Origin, held, cp.Head, consistencyProof); err != nil {
			return nil, err
		}
	} else if len(consistencyProof) > 0 {
		// Nothing to be consistent with: a proof here is meaningless, and
		// silently ignoring it would hide a client bug.
		return nil, &Refusal{
			Reason: ReasonInconsistentProof, Origin: cp.Origin, Offered: cp.Head,
			Detail: fmt.Sprintf("first checkpoint for this origin, but %d consistency-proof hashes were supplied", len(consistencyProof)),
		}
	}

	sig, err := w.key.CosignText(text)
	if err != nil {
		return nil, err
	}
	// Persist before returning: a cosignature the witness cannot remember
	// having issued is worse than no cosignature at all.
	cosigned := make([]byte, 0, len(checkpoint)+len(sig))
	cosigned = append(cosigned, checkpoint...)
	cosigned = append(cosigned, sig...)
	if err := w.store.Record(cp.Origin, cp.Head, cosigned, w.now().UTC()); err != nil {
		return nil, err
	}
	return sig, nil
}

// checkConsistent is the safety rule proper, factored out so the table of
// cases reads as the table in the package comment.
func checkConsistent(origin string, held, offered Head, consistencyProof [][]byte) error {
	switch {
	case offered.Size < held.Size:
		return &Refusal{
			Reason: ReasonSmallerSize, Origin: origin, Held: held, Offered: offered,
			Detail: ReasonSmallerSize.Describe(),
		}
	case offered.Size == held.Size:
		if offered.Root != held.Root {
			return &Refusal{
				Reason: ReasonForkAtSize, Origin: origin, Held: held, Offered: offered,
				Detail: ReasonForkAtSize.Describe(),
			}
		}
		if len(consistencyProof) > 0 {
			return &Refusal{
				Reason: ReasonInconsistentProof, Origin: origin, Held: held, Offered: offered,
				Detail: "sizes are equal but a consistency proof was supplied",
			}
		}
		return nil
	default: // offered.Size > held.Size
		if err := proof.VerifyConsistency(rfc6962.DefaultHasher,
			held.Size, offered.Size, consistencyProof, held.Root[:], offered.Root[:]); err != nil {
			return &Refusal{
				Reason: ReasonInconsistentProof, Origin: origin, Held: held, Offered: offered,
				Detail: err.Error(),
			}
		}
		return nil
	}
}

// parsed is a checkpoint whose log signature has been verified.
type parsed struct {
	Origin string
	Head   Head
}

// parse verifies the log signature over a checkpoint note and extracts
// (origin, size, root). The origin is read from the note body first so the
// right log key can be selected; an origin the witness holds no key for is
// ErrUnknownOrigin, and a body the key does not authenticate is
// ErrLogSignature. Neither is a refusal: the safety rule never ran.
func (w *Witness) parse(checkpoint []byte) (parsed, []byte, error) {
	origin, err := originLine(checkpoint)
	if err != nil {
		return parsed{}, nil, err
	}
	verifier, ok := w.logs[origin]
	if !ok {
		return parsed{}, nil, fmt.Errorf("%w: %q", ErrUnknownOrigin, origin)
	}
	n, err := note.Open(checkpoint, note.VerifierList(verifier))
	if err != nil {
		return parsed{}, nil, fmt.Errorf("%w: %q: %v", ErrLogSignature, origin, err)
	}
	head, err := parseBody(n.Text)
	if err != nil {
		return parsed{}, nil, err
	}
	return parsed{Origin: origin, Head: head}, []byte(n.Text), nil
}

// originLine reads the first line of a note as the checkpoint origin,
// without trusting anything about it beyond its shape.
func originLine(checkpoint []byte) (string, error) {
	i := bytes.IndexByte(checkpoint, '\n')
	if i <= 0 {
		return "", fmt.Errorf("%w: no origin line", ErrMalformedCheckpoint)
	}
	origin := string(checkpoint[:i])
	if strings.ContainsAny(origin, " \t") || !isPrint(origin) {
		return "", fmt.Errorf("%w: origin line %q is not a note key name", ErrMalformedCheckpoint, origin)
	}
	return origin, nil
}

func isPrint(s string) bool {
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:4] + "…" + s[len(s)-4:]
}
