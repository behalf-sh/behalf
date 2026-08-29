// Package why answers "why did this happen": it loads one receipt out of
// the log by run and step, parses the delegation chain embedded in it, and
// renders the authority tree with its three verification states — verified,
// asserted, broken (Q12, D5) — plus any scope excess computed at read time
// from the raw per-hop grants (Q11, Q13).
//
// Two disciplines govern this package:
//
//   - Nothing is written back. The scope excess, the attenuation
//     classification and the verification rollups rendered here are computed
//     from the stored bytes on every read, stamped with ComparatorVersion.
//     Raw inputs are hashed evidence; computed values live on the read path,
//     so a comparison bug can never freeze into evidence (Q11, schema §1).
//   - Nothing is invented. Receipts are pseudonymous — key thumbprints for
//     actors, issuer plus sub-digest for the human principal (Q16, Q40) — so
//     every human-readable name in the output comes from the local alias map
//     (alias.go) and is an asserted label, not a cryptographic claim.
package why

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/tlog"
)

// Address is a receipt's product-level address: a run id and a step.
//
// The step is the run-relative ordinal — the receipt's zero-based position
// in the run view, which is log-index order filtered to the run, the
// authoritative order for reconstruction (Q58, Q82). It is a read-path
// coordinate, not a stored field: the log index is global and shifts with
// interleaved runs, so `run_c71e:31` names the 32nd receipt of run_c71e
// however the log interleaved it. The fixture runs encode the same ordinal
// at capture in emitter.counter (which the index projects), so the demo's
// step 31 is the refund.issue in both runs.
type Address struct {
	RunID string
	Step  int
}

func (a Address) String() string { return fmt.Sprintf("%s:%d", a.RunID, a.Step) }

// ParseAddress parses "<run>:<step>".
func ParseAddress(s string) (Address, error) {
	run, step, ok := strings.Cut(s, ":")
	if !ok || run == "" || step == "" {
		return Address{}, fmt.Errorf("why: %q is not a receipt address — want <run>:<step>, e.g. run_c71e:31", s)
	}
	n, err := strconv.Atoi(step)
	if err != nil || n < 0 {
		return Address{}, fmt.Errorf("why: %q is not a receipt address — step must be a non-negative integer, e.g. run_c71e:31", s)
	}
	return Address{RunID: run, Step: n}, nil
}

// Hop is one delegation hop as rendered: the stored per-hop fields plus the
// read-time comparison against its parent.
type Hop struct {
	Depth        int
	MaxDepth     int
	ParHash      string
	JKT          string // RFC 7638 thumbprint of the hop's cnf.jwk (Q16)
	JTI          string
	Exp          int64
	Grants       []Grant
	Credential   Credential
	RootBinding  *RootBinding
	Verification Verification
	Carriage     string
	// StoredFlag is the attenuation_flag as captured (schema §7); Computed
	// and ComputedReason are this read's comparison against the parent hop
	// and are never written back (Q11).
	StoredFlag     string
	Computed       Attenuation
	ComputedReason string
}

// Credential is the canonical per-hop credential reference — never the
// token itself (Q23).
type Credential struct {
	Issuer   string   `json:"issuer"`
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Exp      int64    `json:"exp"`
	JKT      string   `json:"jkt"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
}

// RootBinding is the depth-0 OIDC nonce-thumbprint binding (D5).
type RootBinding struct {
	Nonce      string `json:"nonce"`
	DeviceJKT  string `json:"device_jkt"`
	IDTokenRef string `json:"id_token_ref"`
}

// Verification is the stored per-hop three-state (Q12).
type Verification struct {
	Status      string `json:"status"`
	Method      string `json:"method"`
	EvidenceRef string `json:"evidence_ref"`
}

// Result is everything one `behalf why` render needs.
type Result struct {
	Address  Address
	LogIndex uint64
	LeafHash string
	// Payload is the exact stored payload span — the signed bytes,
	// untouched (the span rule).
	Payload []byte

	ReceiptID  string
	Kind       string
	CapturedAt string
	Operation  string
	Target     string
	Outcome    string
	// Amount is the operation's amount as captured when the surface reported
	// a decimal, and the read-time rendering of `amount_cents` when it
	// reported minor units (see amountOf). It is what the scope check
	// compares.
	Amount   string
	Currency string
	ActorJKT string

	// StoredAttribution is the receipt-level rollup as captured (§8).
	StoredAttribution string
	AttributionClass  string

	Chain  []Hop
	Excess *ScopeExcess
	// VerifiedHops of TotalHops is the "chain intact for N of M hops" line.
	VerifiedHops int
	TotalHops    int
}

// receiptView is the read-only projection of the stored payload. Reading
// fields is fine; the payload bytes themselves are never re-serialized.
type receiptView struct {
	ReceiptID  string `json:"receipt_id"`
	Kind       string `json:"kind"`
	RunID      string `json:"run_id"`
	CapturedAt string `json:"captured_at"`
	Actor      *struct {
		JKT    string            `json:"jkt"`
		Labels map[string]string `json:"labels"`
	} `json:"actor"`
	Operation struct {
		Name    string                     `json:"name"`
		Target  string                     `json:"target"`
		Outcome map[string]json.RawMessage `json:"outcome"`
	} `json:"operation"`
	Authority *struct {
		Chain []hopView `json:"chain"`
	} `json:"authority"`
	Attribution struct {
		Verification string `json:"verification"`
		Class        string `json:"class"`
	} `json:"attribution"`
}

type hopView struct {
	DelDepth    int    `json:"del_depth"`
	DelMaxDepth int    `json:"del_max_depth"`
	ParHash     string `json:"par_hash"`
	Cnf         struct {
		JWK json.RawMessage `json:"jwk"`
	} `json:"cnf"`
	AuthorizationDetails []json.RawMessage `json:"authorization_details"`
	Exp                  int64             `json:"exp"`
	JTI                  string            `json:"jti"`
	Credential           Credential        `json:"credential"`
	RootPrincipalBinding *RootBinding      `json:"root_principal_binding"`
	Verification         Verification      `json:"verification"`
	CarriageRoute        string            `json:"carriage_route"`
	AttenuationFlag      string            `json:"attenuation_flag"`
}

// Load resolves addr against the log in logDir and builds the render model.
// The index supplies the run view and the leaf hash; the payload bytes come
// from the log's own entry bundles and are checked against that leaf hash
// before anything is read out of them.
func Load(ctx context.Context, logDir string, addr Address) (*Result, error) {
	db, err := index.Open(ctx, logDir)
	if err != nil {
		return nil, err
	}
	defer db.Close()

	rows, err := db.RunRows(addr.RunID)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("why: no receipts indexed for run %q", addr.RunID)
	}
	if addr.Step >= len(rows) {
		return nil, fmt.Errorf("why: run %s has %d receipts (steps 0..%d); there is no step %d",
			addr.RunID, len(rows), len(rows)-1, addr.Step)
	}
	row := rows[addr.Step]

	reader, err := tlog.NewBundleReader(ctx, logDir)
	if err != nil {
		return nil, err
	}
	payload, err := reader.Payload(ctx, row.LogIndex, row.LeafHash)
	if err != nil {
		return nil, err
	}
	return build(addr, row, payload)
}

// FromPayload builds the same model Load builds, from a receipt payload the
// caller has already read out of the log.
//
// It exists for readers that walk a whole run rather than one address — the
// HTML export — and would otherwise re-open the index and re-parse the
// checkpoint once per step. Everything Load computes is computed here too:
// the attenuation deltas and the scope check are read-time comparisons over
// the stored grants and are recomputed on every read, never cached and
// never written back (Q11).
//
// The payload must already have been checked against its indexed leaf hash
// — tlog.BundleReader.Payload does that, and Load reaches it that way. A
// caller that skips the check renders bytes the index does not vouch for.
func FromPayload(addr Address, logIndex uint64, leafHash string, payload []byte) (*Result, error) {
	return build(addr, index.Row{LogIndex: logIndex, LeafHash: leafHash}, payload)
}

// build assembles the render model from one stored payload.
func build(addr Address, row index.Row, payload []byte) (*Result, error) {
	var v receiptView
	if err := json.Unmarshal(payload, &v); err != nil {
		return nil, fmt.Errorf("why: parse receipt at log index %d: %w", row.LogIndex, err)
	}
	res := &Result{
		Address:           addr,
		LogIndex:          row.LogIndex,
		LeafHash:          row.LeafHash,
		Payload:           payload,
		ReceiptID:         v.ReceiptID,
		Kind:              v.Kind,
		CapturedAt:        v.CapturedAt,
		Operation:         v.Operation.Name,
		Target:            v.Operation.Target,
		StoredAttribution: v.Attribution.Verification,
		AttributionClass:  v.Attribution.Class,
	}
	if v.Actor != nil {
		res.ActorJKT = v.Actor.JKT
	}
	res.Outcome = jsonScalar(v.Operation.Outcome["status"])
	res.Amount = amountOf(v.Operation.Outcome)
	res.Currency = jsonScalar(v.Operation.Outcome["currency"])

	if v.Authority != nil {
		for _, h := range v.Authority.Chain {
			hop := Hop{
				Depth:        h.DelDepth,
				MaxDepth:     h.DelMaxDepth,
				ParHash:      h.ParHash,
				JKT:          thumbprint(h.Cnf.JWK),
				JTI:          h.JTI,
				Exp:          h.Exp,
				Grants:       grantsFor(h.AuthorizationDetails),
				Credential:   h.Credential,
				RootBinding:  h.RootPrincipalBinding,
				Verification: h.Verification,
				Carriage:     h.CarriageRoute,
				StoredFlag:   h.AttenuationFlag,
			}
			res.Chain = append(res.Chain, hop)
		}
	}
	// The attenuation delta is computed here, at read time, from the raw
	// per-hop authorization_details — never read out of a stored field
	// (Q11, Q13).
	for i := range res.Chain {
		if i == 0 {
			continue
		}
		res.Chain[i].Computed, res.Chain[i].ComputedReason =
			CompareGrants(res.Chain[i-1].Grants, res.Chain[i].Grants)
	}
	res.TotalHops = len(res.Chain)
	for _, h := range res.Chain {
		if h.Verification.Status == "verified" {
			res.VerifiedHops++
		}
	}
	res.Excess = CheckScope(res.Chain, res.Operation, res.Amount)
	return res, nil
}

// amountOf reads the operation's amount out of the captured outcome.
//
// Two surfaces, one question. A surface that reports a decimal reports
// `amount`, and it is taken verbatim. A surface that reports money in minor
// units reports `amount_cents`, and it is rendered as a decimal HERE, on the
// read path, because that is the only form the delegated ceiling
// ("100.00") can be compared against.
//
// This is a display and comparison convention, stated so it can be argued
// with: `amount_cents` is read as hundredths, which is right for USD and for
// every currency the demo touches, and wrong for the zero- and
// three-decimal currencies (JPY, KWD) that v1 does not claim to handle. It
// is the same convention `behalf diff` documents for `*_cents` fields, kept
// in step deliberately — two renderings of one stored number that disagreed
// would be worse than either. Nothing computed here is ever written back
// (Q11): the record keeps the integer the tool returned.
func amountOf(outcome map[string]json.RawMessage) string {
	if s := jsonScalar(outcome["amount"]); s != "" {
		return s
	}
	return minorUnits(jsonScalar(outcome["amount_cents"]))
}

// minorUnits turns an integer count of hundredths into the decimal string
// the chain's limits are written in: 120000 -> "1200.00". Anything that is
// not a plain integer yields "", which reads as "no comparable amount".
func minorUnits(cents string) string {
	neg := strings.HasPrefix(cents, "-")
	digits := strings.TrimPrefix(cents, "-")
	if digits == "" {
		return ""
	}
	for _, r := range digits {
		if r < '0' || r > '9' {
			return ""
		}
	}
	for len(digits) < 3 {
		digits = "0" + digits
	}
	out := digits[:len(digits)-2] + "." + digits[len(digits)-2:]
	if neg {
		return "-" + out
	}
	return out
}

// jsonScalar renders a captured JSON scalar as text without reformatting
// it: a string is unquoted, anything else keeps its verbatim source bytes,
// so a decimal like 1200.00 is never round-tripped through a float.
func jsonScalar(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	if raw[0] == '"' {
		var s string
		if err := json.Unmarshal(raw, &s); err == nil {
			return s
		}
	}
	return string(raw)
}
