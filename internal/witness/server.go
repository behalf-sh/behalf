package witness

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
)

// MaxRequestBytes bounds an add-checkpoint submission. A checkpoint is a
// few hundred bytes and a consistency proof is at most 64 hashes; anything
// approaching this is not a witness submission.
const MaxRequestBytes = 1 << 16

// Server exposes a Witness over the C2SP tlog-witness `add-checkpoint`
// endpoint. It is deliberately the whole HTTP surface: one route, one
// method, nothing configurable at runtime. The witness is the one thing
// that must never be hard to operate.
type Server struct {
	w   *Witness
	log *slog.Logger
}

// NewServer wraps a witness. A nil logger discards.
func NewServer(w *Witness, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	return &Server{w: w, log: logger}
}

// Handler returns the witness's HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+AddCheckpointPath, s.addCheckpoint)
	return mux
}

func (s *Server) addCheckpoint(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	if err != nil {
		http.Error(w, "cannot read request body", http.StatusBadRequest)
		return
	}
	req, err := DecodeRequest(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Verify the log's own signature before anything else: everything below
	// is a statement about a checkpoint, and an unauthenticated checkpoint
	// is not one.
	origin, offered, err := s.w.Inspect(req.Checkpoint)
	if err != nil {
		s.fail(w, err)
		return
	}
	held, seen := s.w.Held(origin)

	// A tree smaller than the one the witness holds is a finding, not a
	// calibration error, whatever the submitter declares for `old`: this is
	// the Q76 stale-restore rule, and it must not be answered with a polite
	// "here is my size, try again".
	if seen && offered.Size < held.Size {
		s.refuse(w, &Refusal{
			Reason: ReasonSmallerSize, Origin: origin, Held: held, Offered: offered,
			Detail: ReasonSmallerSize.Describe(),
		})
		return
	}
	// C2SP: the old size must not exceed the checkpoint size.
	if req.OldSize > offered.Size {
		http.Error(w, fmt.Sprintf("old size %d exceeds checkpoint size %d", req.OldSize, offered.Size),
			http.StatusBadRequest)
		return
	}
	// C2SP: the old size must match the size of the latest checkpoint the
	// witness cosigned for this origin (zero if it never has). If it does
	// not, answer with the size the witness holds so the submitter can
	// build the right proof and retry.
	if heldSize := heldSizeOf(held, seen); req.OldSize != heldSize {
		w.Header().Set("Content-Type", SizeContentType)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", heldSize)
		return
	}

	sig, err := s.w.Cosign(req.Checkpoint, req.Proof)
	if err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("cosigned", "origin", origin, "size", offered.Size, "root", offered.RootHex())
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(sig)
}

func heldSizeOf(held Head, seen bool) uint64 {
	if !seen {
		return 0
	}
	return held.Size
}

// fail maps a Cosign error onto the C2SP status codes.
func (s *Server) fail(w http.ResponseWriter, err error) {
	if refusal, ok := AsRefusal(err); ok {
		s.refuse(w, refusal)
		return
	}
	switch {
	case errors.Is(err, ErrUnknownOrigin):
		s.log.Warn("unknown origin", "error", err)
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, ErrLogSignature):
		s.log.Warn("bad log signature", "error", err)
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, ErrMalformedCheckpoint):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		s.log.Error("cosign failed", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// refuse writes a refusal. It is logged at error level on purpose: a
// refusal is not routine load, it is the system reporting that someone
// offered it two histories.
func (s *Server) refuse(w http.ResponseWriter, refusal *Refusal) {
	s.log.Error("REFUSED",
		"reason", string(refusal.Reason),
		"class", refusal.Reason.Class(),
		"origin", refusal.Origin,
		"held_size", refusal.Held.Size,
		"held_root", refusal.Held.RootHex(),
		"offered_size", refusal.Offered.Size,
		"offered_root", refusal.Offered.RootHex(),
		"detail", refusal.Detail)
	w.Header().Set(RefusalHeader, string(refusal.Reason))
	if refusal.Reason == ReasonSmallerSize {
		// Carry the held size in the C2SP shape as well, so a submitter
		// that only speaks the standard protocol still learns how far
		// ahead the witness is.
		w.Header().Set("Content-Type", SizeContentType)
		w.WriteHeader(http.StatusConflict)
		fmt.Fprintf(w, "%d\n", refusal.Held.Size)
		return
	}
	status := http.StatusConflict
	if refusal.Reason == ReasonInconsistentProof {
		status = http.StatusUnprocessableEntity
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	fmt.Fprintln(w, refusal.Error())
}
