package witness

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"

	f_note "github.com/transparency-dev/formats/note"
	"golang.org/x/mod/sumdb/note"
)

// The log side of the protocol: submitting a published checkpoint to a
// witness and interpreting what comes back.
//
// This is deliberately a separate implementation from Tessera's own
// (tessera/internal/witness, reachable only through
// AppendOptions.WithWitnesses), for one reason: Tessera's fail-open path
// logs the failure and moves on — `klog.Warningf("WitnessGateway:
// failing-open despite error")` — so there is no per-checkpoint record of
// what the witness said. Under Q96's FailOpen:true that discards the single
// most important signal the system can produce. behalf submits after
// publication and records the outcome per checkpoint instead; see
// tlog.witnessSubmitter.

// Ref identifies one configured witness.
type Ref struct {
	// Name is a local label for logs and outcome records. It does not have
	// to match the witness's note key name (VKey carries that).
	Name string `json:"name"`
	// VKey is the witness's C2SP cosignature/v1 verifier key.
	VKey string `json:"vkey"`
	// URL is the witness root; AddCheckpointPath is appended to it.
	URL string `json:"url"`
}

// Outcome is what one submission to one witness produced. The vocabulary is
// closed and stable: it is written to the log's per-checkpoint witness
// record and asserted on by the tamper suite.
type Outcome string

const (
	// OutcomeCosigned: the witness returned a valid cosignature.
	OutcomeCosigned Outcome = "cosigned"
	// OutcomeRefused: the witness applied the safety rule and said no.
	// This is a finding about the log, not about the witness.
	OutcomeRefused Outcome = "refused"
	// OutcomeUnreachable: the witness could not be contacted, timed out, or
	// answered in a way that is not a refusal. Under FailOpen this never
	// blocks publication; it is recorded so the gap is visible.
	OutcomeUnreachable Outcome = "unreachable"
)

// Result is the record of one submission.
type Result struct {
	Witness string  `json:"witness"`
	URL     string  `json:"url"`
	Outcome Outcome `json:"outcome"`
	// Class is the verifier's tamper-class vocabulary for a refusal
	// (`truncation` or `chain`), empty otherwise.
	Class string `json:"class,omitempty"`
	// Reason is the refusal reason (`smaller-size`,
	// `same-size-different-root`, `inconsistent-proof`), empty otherwise.
	Reason string `json:"reason,omitempty"`
	// Detail is the human-readable explanation for a refusal or an
	// unreachable witness.
	Detail string `json:"detail,omitempty"`
	// HeldSize is the tree size the witness says it holds, when it told us.
	HeldSize *uint64 `json:"held_size,omitempty"`
	// Cosignature is the note signature line, present iff cosigned.
	Cosignature string `json:"cosignature,omitempty"`
}

// ProofFunc builds the consistency proof between two tree sizes of the log
// being submitted. tlog.ConsistencyProof is the implementation; it reads the
// log's own hash tiles.
type ProofFunc func(ctx context.Context, from, to uint64) ([][]byte, error)

// Client submits checkpoints to one witness. It remembers the size that
// witness last cosigned so the common case costs one round trip; the C2SP
// 409 response recalibrates it when the memory is wrong (after a restart,
// or when another submitter has moved the witness on).
type Client struct {
	ref      Ref
	verifier note.Verifier
	http     *http.Client
	url      string

	mu       sync.Mutex
	lastSize uint64
}

// maxRecalibrations bounds the 409 retry loop. A witness that keeps
// answering "not that size either" is misbehaving, and behalf must not spin
// on it while a checkpoint waits.
const maxRecalibrations = 4

// NewClient builds a submitter for one configured witness.
func NewClient(ref Ref, httpClient *http.Client) (*Client, error) {
	if ref.URL == "" {
		return nil, fmt.Errorf("witness %q: no URL", ref.Name)
	}
	v, err := f_note.NewVerifierForCosignatureV1(strings.TrimSpace(ref.VKey))
	if err != nil {
		return nil, fmt.Errorf("witness %q: verifier key: %w", ref.Name, err)
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	name := ref.Name
	if name == "" {
		name = v.Name()
	}
	ref.Name = name
	return &Client{
		ref:      ref,
		verifier: v,
		http:     httpClient,
		url:      strings.TrimSuffix(ref.URL, "/") + AddCheckpointPath,
	}, nil
}

// Ref returns the configuration this client was built from.
func (c *Client) Ref() Ref { return c.ref }

// Verifier returns the note verifier for this witness's cosignatures, so a
// caller can check a checkpoint already carries one.
func (c *Client) Verifier() note.Verifier { return c.verifier }

// Submit offers checkpoint to the witness and returns what happened. It
// never returns an error for a refusal or an unreachable witness — those
// are outcomes, and the caller's job is to record them, not to retry them
// away. An error is returned only when the caller's own inputs are unusable
// (an unparseable checkpoint, a proof builder that fails).
func (c *Client) Submit(ctx context.Context, checkpoint []byte, proofFn ProofFunc) Result {
	res := Result{Witness: c.ref.Name, URL: c.ref.URL}
	_, head, err := ParseCheckpointHead(checkpoint)
	if err != nil {
		res.Outcome = OutcomeUnreachable
		res.Detail = fmt.Sprintf("cannot parse the checkpoint being submitted: %v", err)
		return res
	}

	c.mu.Lock()
	old := c.lastSize
	c.mu.Unlock()

	for attempt := 0; ; attempt++ {
		if old > head.Size {
			// The witness is ahead of the tree we are offering: the log has
			// gone backwards. Do not paper over it by asking for a smaller
			// `old` — that is precisely the restore-as-truncation move.
			return refusedResult(res, ReasonSmallerSize, old, head.Size,
				ReasonSmallerSize.Describe()+"; this submitter has already had a larger tree cosigned by this witness")
		}
		var pf [][]byte
		if old > 0 && old < head.Size {
			pf, err = proofFn(ctx, old, head.Size)
			if err != nil {
				res.Outcome = OutcomeUnreachable
				res.Detail = fmt.Sprintf("cannot build the consistency proof %d->%d: %v", old, head.Size, err)
				return res
			}
		}
		out, retryAt, done := c.post(ctx, checkpoint, head, Request{OldSize: old, Proof: pf, Checkpoint: checkpoint}, res)
		if done {
			if out.Outcome == OutcomeCosigned {
				c.mu.Lock()
				c.lastSize = head.Size
				c.mu.Unlock()
			}
			return out
		}
		if attempt >= maxRecalibrations {
			out.Outcome = OutcomeUnreachable
			out.Detail = fmt.Sprintf("witness kept revising its tree size (last: %d) after %d attempts", retryAt, attempt+1)
			return out
		}
		old = retryAt
		c.mu.Lock()
		c.lastSize = retryAt
		c.mu.Unlock()
	}
}

// post performs one add-checkpoint round trip. done is false when the
// witness answered "my size is retryAt" and the caller should rebuild the
// proof and try again.
func (c *Client) post(ctx context.Context, checkpoint []byte, offered Head, req Request, res Result) (out Result, retryAt uint64, done bool) {
	body := EncodeRequest(req)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		res.Outcome = OutcomeUnreachable
		res.Detail = err.Error()
		return res, 0, true
	}
	httpReq.Header.Set("Content-Type", "text/plain; charset=utf-8")
	resp, err := c.http.Do(httpReq)
	if err != nil {
		res.Outcome = OutcomeUnreachable
		res.Detail = unreachableDetail(err)
		return res, 0, true
	}
	defer func() { _ = resp.Body.Close() }()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, MaxRequestBytes))
	if err != nil {
		res.Outcome = OutcomeUnreachable
		res.Detail = fmt.Sprintf("reading witness response: %v", err)
		return res, 0, true
	}

	// The witness's own name for what it did, when it gave us one.
	declared := Reason(resp.Header.Get(RefusalHeader))

	switch resp.StatusCode {
	case http.StatusOK:
		sig := respBody
		signed := make([]byte, 0, len(checkpoint)+len(sig))
		signed = append(signed, checkpoint...)
		signed = append(signed, sig...)
		if _, err := note.Open(signed, note.VerifierList(c.verifier)); err != nil {
			res.Outcome = OutcomeUnreachable
			res.Detail = fmt.Sprintf("witness returned a signature that does not verify: %v", err)
			return res, 0, true
		}
		res.Outcome = OutcomeCosigned
		res.Cosignature = strings.TrimRight(string(sig), "\n")
		return res, 0, true

	case http.StatusConflict:
		// Either a refusal the witness named, or the C2SP calibration
		// answer carrying the witness's current size.
		if size, ok := parseSizeBody(resp, respBody); ok {
			res.HeldSize = &size
			if declared != "" {
				// The C2SP body carries only the witness's size, so the
				// explanation comes from the shared vocabulary rather than
				// from whatever the response happened to say.
				return refusedResult(res, declared, size, offered.Size, declared.Describe()), 0, true
			}
			if size > req.OldSize && size > 0 {
				// The witness is ahead of where we thought. Recalibrate.
				return res, size, false
			}
			if size < req.OldSize {
				// The witness is behind where we thought — it lost state,
				// or we are talking to a different witness. Recalibrate
				// downwards; the proof will simply be longer.
				return res, size, false
			}
		}
		reason := declared
		if reason == "" {
			reason = ReasonForkAtSize
		}
		return refusedResult(res, reason, 0, offered.Size, bodyOrDescription(respBody, reason)), 0, true

	case http.StatusUnprocessableEntity:
		reason := declared
		if reason == "" {
			reason = ReasonInconsistentProof
		}
		return refusedResult(res, reason, 0, offered.Size, bodyOrDescription(respBody, reason)), 0, true

	case http.StatusNotFound:
		res.Outcome = OutcomeUnreachable
		res.Detail = "the witness does not know this log's origin (register the log's vkey with it)"
		return res, 0, true

	case http.StatusForbidden:
		res.Outcome = OutcomeUnreachable
		res.Detail = "the witness does not trust this log's checkpoint key"
		return res, 0, true

	default:
		res.Outcome = OutcomeUnreachable
		res.Detail = fmt.Sprintf("witness answered HTTP %d: %s", resp.StatusCode, firstLine(respBody))
		return res, 0, true
	}
}

func refusedResult(res Result, reason Reason, heldSize, offeredSize uint64, detail string) Result {
	res.Outcome = OutcomeRefused
	res.Reason = string(reason)
	res.Class = reason.Class()
	if detail == "" {
		detail = reason.Describe()
	}
	if heldSize > 0 {
		detail = fmt.Sprintf("%s (the witness holds tree size %d; this checkpoint covers %d)",
			detail, heldSize, offeredSize)
		h := heldSize
		res.HeldSize = &h
	}
	res.Detail = detail
	return res
}

// bodyOrDescription prefers the witness's own explanation when it sent one,
// and falls back to the shared vocabulary otherwise.
func bodyOrDescription(body []byte, reason Reason) string {
	if s := strings.TrimSpace(string(body)); s != "" {
		return s
	}
	return reason.Describe()
}

func parseSizeBody(resp *http.Response, body []byte) (uint64, bool) {
	if resp.Header.Get("Content-Type") != SizeContentType {
		return 0, false
	}
	size, err := strconv.ParseUint(strings.TrimSpace(string(body)), 10, 64)
	if err != nil {
		return 0, false
	}
	return size, true
}

func unreachableDetail(err error) string {
	if errors.Is(err, context.DeadlineExceeded) {
		return "witness timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "witness submission cancelled"
	}
	return err.Error()
}

func firstLine(b []byte) string {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	if len(b) > 200 {
		b = b[:200]
	}
	return string(b)
}
