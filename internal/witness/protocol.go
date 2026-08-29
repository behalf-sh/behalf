package witness

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
)

// The C2SP tlog-witness `add-checkpoint` wire format, implemented on both
// ends so the log and the witness cannot drift:
//
//	POST /add-checkpoint
//	old <N>\n
//	<base64 consistency proof hash>\n   (zero or more)
//	\n
//	<checkpoint note>
//
// Responses:
//
//	200 OK                      body: the cosignature line(s)
//	400 Bad Request             old size exceeds the checkpoint size
//	403 Forbidden               no signature by a trusted log key
//	404 Not Found               unknown checkpoint origin
//	409 Conflict                old size does not match what the witness
//	                            holds (Content-Type text/x.tlog.size, body
//	                            = the witness's size), or same size with a
//	                            different root
//	422 Unprocessable Entity    the consistency proof does not verify
//
// behalf adds one non-normative response header, `Behalf-Refusal`, carrying
// the refusal reason verbatim (`smaller-size`, `same-size-different-root`,
// `inconsistent-proof`). A standard C2SP log ignores it and falls back to
// the status codes; behalf's log records it, because "the witness refused,
// and this is why" is the single most important line the system can write.
const (
	// AddCheckpointPath is the witness's only endpoint.
	AddCheckpointPath = "/add-checkpoint"
	// RefusalHeader carries the refusal Reason on a 4xx response.
	RefusalHeader = "Behalf-Refusal"
	// SizeContentType is the C2SP content type for a 409 carrying the
	// witness's current tree size.
	SizeContentType = "text/x.tlog.size"
)

// Request is a parsed add-checkpoint submission.
type Request struct {
	// OldSize is the tree size the submitter believes the witness last
	// cosigned for this origin (zero if it has no information).
	OldSize uint64
	// Proof is the consistency proof from OldSize to the checkpoint's size.
	Proof [][]byte
	// Checkpoint is the signed checkpoint note, verbatim.
	Checkpoint []byte
}

// EncodeRequest renders a submission body.
func EncodeRequest(req Request) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "old %d\n", req.OldSize)
	for _, h := range req.Proof {
		b.WriteString(base64.StdEncoding.EncodeToString(h))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	b.Write(req.Checkpoint)
	return b.Bytes()
}

// DecodeRequest parses a submission body. A malformed body is an error, not
// a refusal: the safety rule never ran.
func DecodeRequest(body []byte) (Request, error) {
	sep := bytes.Index(body, []byte("\n\n"))
	if sep < 0 {
		return Request{}, fmt.Errorf("add-checkpoint body has no blank-line separator")
	}
	header, checkpoint := body[:sep+1], body[sep+2:]
	lines := strings.Split(strings.TrimSuffix(string(header), "\n"), "\n")
	if len(lines) == 0 {
		return Request{}, fmt.Errorf("add-checkpoint body has no old-size line")
	}
	sizeStr, ok := strings.CutPrefix(lines[0], "old ")
	if !ok {
		return Request{}, fmt.Errorf("add-checkpoint body does not start with an %q line", "old <N>")
	}
	oldSize, err := strconv.ParseUint(sizeStr, 10, 64)
	if err != nil {
		return Request{}, fmt.Errorf("add-checkpoint old size %q is not a decimal number", sizeStr)
	}
	req := Request{OldSize: oldSize, Checkpoint: checkpoint}
	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		h, err := base64.StdEncoding.DecodeString(line)
		if err != nil {
			return Request{}, fmt.Errorf("add-checkpoint proof line is not base64: %w", err)
		}
		if len(h) != 32 {
			return Request{}, fmt.Errorf("add-checkpoint proof hash is %d bytes, want 32", len(h))
		}
		req.Proof = append(req.Proof, h)
	}
	if len(req.Checkpoint) == 0 {
		return Request{}, fmt.Errorf("add-checkpoint body carries no checkpoint")
	}
	return req, nil
}

// parseBody extracts (size, root) from a checkpoint note body whose log
// signature has already been verified: origin line, decimal tree size,
// base64 root hash, then any number of tolerated extension lines (D3.4's
// grease discipline applies to the body too).
func parseBody(text string) (Head, error) {
	var h Head
	lines := strings.Split(text, "\n")
	if len(lines) < 3 {
		return h, fmt.Errorf("%w: fewer than three body lines", ErrMalformedCheckpoint)
	}
	size, err := strconv.ParseUint(lines[1], 10, 64)
	if err != nil {
		return h, fmt.Errorf("%w: tree size %q is not a decimal number", ErrMalformedCheckpoint, lines[1])
	}
	root, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return h, fmt.Errorf("%w: root hash is not base64: %v", ErrMalformedCheckpoint, err)
	}
	if len(root) != 32 {
		return h, fmt.Errorf("%w: root hash is %d bytes, want 32", ErrMalformedCheckpoint, len(root))
	}
	h.Size = size
	copy(h.Root[:], root)
	return h, nil
}

// ParseCheckpointHead extracts (origin, size, root) from checkpoint note
// bytes *without* verifying any signature. It exists for the log side,
// which has already verified its own checkpoint before submitting it, and
// for tooling that needs to name a checkpoint. The witness itself never
// uses it: it verifies the log signature first (see Witness.parse).
func ParseCheckpointHead(checkpoint []byte) (string, Head, error) {
	origin, err := originLine(checkpoint)
	if err != nil {
		return "", Head{}, err
	}
	sep := bytes.Index(checkpoint, []byte("\n\n"))
	if sep < 0 {
		return "", Head{}, fmt.Errorf("%w: no signature block", ErrMalformedCheckpoint)
	}
	head, err := parseBody(string(checkpoint[:sep+1]))
	if err != nil {
		return "", Head{}, err
	}
	return origin, head, nil
}
