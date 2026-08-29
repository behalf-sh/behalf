package index

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/transparency-dev/merkle/rfc6962"

	"github.com/behalf-sh/behalf/internal/jsonspan"
)

// payloadView is the read-only projection of the receipt payload the index
// extracts (docs/receipt-schema-v1.md §4–§6, §8). Reading fields is fine —
// the payload bytes themselves are never re-serialized (the span rule), and
// every column derived here lives in the index projection, outside the
// signed bytes (Q26).
type payloadView struct {
	ReceiptID       string `json:"receipt_id"`
	Kind            string `json:"kind"`
	RunID           string `json:"run_id"`
	RunIDProvenance string `json:"run_id_provenance"`
	CapturedAt      string `json:"captured_at"`
	Emitter         struct {
		JKT     string `json:"jkt"`
		Counter int64  `json:"counter"`
	} `json:"emitter"`
	Actor *struct {
		JKT string `json:"jkt"`
	} `json:"actor"`
	Operation struct {
		Name    string `json:"name"`
		Target  string `json:"target"`
		Outcome struct {
			Status string `json:"status"`
		} `json:"outcome"`
	} `json:"operation"`
	Correlation *struct {
		TraceID        string `json:"trace_id"`
		SessionID      string `json:"session_id"`
		Txn            string `json:"txn"`
		Acti           string `json:"acti"`
		ConversationID string `json:"conversation_id"`
	} `json:"correlation"`
	StepKey     string `json:"step_key"`
	Attribution struct {
		Verification string `json:"verification"`
		Class        string `json:"class"`
	} `json:"attribution"`
}

// Extract derives an index Row from one stored envelope's bytes: the leaf
// hash over the exact envelope bytes (RFC 6962, the same hash Tessera's
// tree covers) and the indexed columns read from the payload span. It is a
// pure function of the envelope bytes, which is what makes rebuilds
// deterministic: replaying the log re-derives byte-identical rows.
//
// LogIndex and DuplicateOf are left zero/nil — they are assigned where the
// row meets the log (ingest ack or replay), not by extraction.
//
// Only receipt_id is required (Q7 requires run_id of receipts, but ingest
// hygiene is append-and-flag per Q45 — the index projects what is there).
func Extract(envelope []byte) (Row, error) {
	var row Row
	payload, err := jsonspan.ExtractTopLevelValue(envelope, "payload")
	if err != nil {
		return row, fmt.Errorf("index: envelope payload: %w", err)
	}
	var v payloadView
	if err := json.Unmarshal(payload, &v); err != nil {
		return row, fmt.Errorf("index: parse receipt payload: %w", err)
	}
	if v.ReceiptID == "" {
		return row, errors.New("index: receipt payload has no receipt_id")
	}

	row = Row{
		ReceiptID:               v.ReceiptID,
		LeafHash:                hex.EncodeToString(rfc6962.DefaultHasher.HashLeaf(envelope)),
		Kind:                    v.Kind,
		RunID:                   v.RunID,
		RunIDProvenance:         v.RunIDProvenance,
		CapturedAt:              v.CapturedAt,
		EmitterJKT:              v.Emitter.JKT,
		EmitterCounter:          v.Emitter.Counter,
		OperationName:           v.Operation.Name,
		OperationTarget:         v.Operation.Target,
		OutcomeStatus:           v.Operation.Outcome.Status,
		AttributionVerification: v.Attribution.Verification,
		AttributionClass:        v.Attribution.Class,
		StepKey:                 v.StepKey,
	}
	if v.Actor != nil {
		row.ActorJKT = v.Actor.JKT
	}
	if v.Correlation != nil {
		row.TraceID = v.Correlation.TraceID
		row.SessionID = v.Correlation.SessionID
		row.Txn = v.Correlation.Txn
		row.Acti = v.Correlation.Acti
		row.ConversationID = v.Correlation.ConversationID
	}
	return row, nil
}
