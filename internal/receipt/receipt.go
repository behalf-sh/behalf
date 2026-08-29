// Package receipt models the behalf v1 Action Receipt payload
// (docs/receipt-schema-v1.md §4–§8, docs/receipt-schema-v1.schema.json).
//
// The governing invariant is the span rule from docs/export-format-v1.md: the
// writer serializes a payload ONCE, signs those exact bytes, and splices them
// verbatim into the export line. Seal is the single serialization point; a
// Sealed value carries the raw bytes and nothing downstream ever re-marshals
// them.
package receipt

import "encoding/json"

// SchemaVersion is the frozen v1 projection key (schema const, Q8).
const SchemaVersion = "behalf.sh/receipt/v1"

// Receipt is the DSSE-signed receipt payload — everything the capture
// surface asserts (schema §4–§8). Field order here is the serialization
// order; encoding/json emits struct fields in declaration order, so a Receipt
// marshals deterministically.
type Receipt struct {
	SchemaVersion      string       `json:"schema_version"`
	OtelConventionsVer string       `json:"otel_conventions_version"`
	ReceiptID          string       `json:"receipt_id"` // client-minted ULID (Q46)
	Kind               string       `json:"kind"`
	KindExt            string       `json:"kind_ext,omitempty"`
	RiskClass          string       `json:"risk_class"`
	RiskPolicyDigest   string       `json:"risk_policy_digest"` // sha256 hex
	CapturedAt         string       `json:"captured_at"`        // RFC 3339
	Emitter            Emitter      `json:"emitter"`
	Actor              *Actor       `json:"actor,omitempty"`
	Operation          Operation    `json:"operation"`
	Attempt            *Attempt     `json:"attempt,omitempty"`
	RunID              string       `json:"run_id"`
	RunIDProvenance    string       `json:"run_id_provenance"` // caller|hook-session|traceparent|proxy-session
	Correlation        *Correlation `json:"correlation,omitempty"`
	StepKey            string       `json:"step_key,omitempty"` // sha256 hex (Q85)
	Authority          *Authority   `json:"authority,omitempty"`
	Attribution        Attribution  `json:"attribution"`
	Payload            []Slot       `json:"payload,omitempty"`
	HumanInLoop        *HumanInLoop `json:"human_in_loop,omitempty"`
	Provenance         Provenance   `json:"provenance"`
	Links              []Link       `json:"links,omitempty"`
	RawFrameRef        string       `json:"raw_frame_ref,omitempty"`
}

// Emitter is the capture surface that produced the evidence (Q19, Q48).
type Emitter struct {
	JKT     string `json:"jkt"`     // RFC 7638 thumbprint of the surface's Ed25519 key
	Surface string `json:"surface"` // mcp-proxy | claude-code-hook
	Counter int    `json:"counter"` // per-emitter monotonic, stamped before spooling
}

// Actor is who acted, if distinct from the emitter (Q16, Q19).
type Actor struct {
	JKT            string            `json:"jkt"`
	Labels         map[string]string `json:"labels,omitempty"`
	EmitterToActor string            `json:"emitter_to_actor,omitempty"` // const "asserted"
}

// Operation is the trust-boundary crossing (Q1).
type Operation struct {
	Name           string  `json:"name"`
	Target         string  `json:"target,omitempty"`
	Outcome        Outcome `json:"outcome"`
	IdempotencyKey string  `json:"idempotency_key,omitempty"`
}

// Outcome is the result or failure of the attempted operation (Q4). The
// schema allows additional properties here (unevaluatedProperties: true), so
// Extra carries surface-specific result fields; it is flattened into the
// object by MarshalJSON with sorted keys, after status/error.
type Outcome struct {
	Status string `json:"status"` // ok | error
	Error  string `json:"error,omitempty"`
	// Extra fields, marshaled after status/error in sorted key order.
	Extra map[string]any `json:"-"`
}

// MarshalJSON flattens Extra into the outcome object deterministically.
func (o Outcome) MarshalJSON() ([]byte, error) {
	type core Outcome
	base, err := json.Marshal(core(o)) // status/error only; Extra has json:"-"
	if err != nil {
		return nil, err
	}
	if len(o.Extra) == 0 {
		return base, nil
	}
	extra, err := json.Marshal(o.Extra) // map: encoding/json sorts keys
	if err != nil {
		return nil, err
	}
	// base = {...}, extra = {...}; splice: {base...,extra...}
	out := make([]byte, 0, len(base)+len(extra))
	out = append(out, base[:len(base)-1]...)
	out = append(out, ',')
	out = append(out, extra[1:]...)
	return out, nil
}

// Attempt is the spooled intent (Q4).
type Attempt struct {
	IntentDigest string `json:"intent_digest,omitempty"` // sha256 hex
}

// Correlation carries the non-required correlation keys (Q7).
type Correlation struct {
	TraceID        string `json:"trace_id,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	Txn            string `json:"txn,omitempty"`
	Acti           string `json:"acti,omitempty"`
	ConversationID string `json:"conversation_id,omitempty"`
}

// Authority embeds the delegation chain whole (Q10, D8.1).
type Authority struct {
	Chain []Hop `json:"chain"`
}

// Hop is one delegation hop: the AAT draft field set plus the behalf
// extensions (schema $defs/hop).
type Hop struct {
	DelDepth             int              `json:"del_depth"`
	DelMaxDepth          int              `json:"del_max_depth"`
	ParHash              string           `json:"par_hash"` // sha256 hex — the DAG edge (Q10)
	Cnf                  Cnf              `json:"cnf"`
	AuthorizationDetails []map[string]any `json:"authorization_details"` // RFC 9396, raw (Q11)
	Exp                  int64            `json:"exp"`
	JTI                  string           `json:"jti"` // behalf extension (Q23, D8.6)
	Credential           Credential       `json:"credential"`
	RootPrincipalBinding *RootBinding     `json:"root_principal_binding,omitempty"`
	Trigger              *Trigger         `json:"trigger,omitempty"`
	Verification         Verification     `json:"verification"`
	CarriageRoute        string           `json:"carriage_route,omitempty"`
	AttenuationFlag      string           `json:"attenuation_flag,omitempty"` // attenuated|unchanged|unknown
}

// Cnf is the hop key confirmation (Q11).
type Cnf struct {
	JWK map[string]any `json:"jwk"`
}

// Credential is the canonical credential reference — never the token (Q23).
type Credential struct {
	Issuer   string   `json:"issuer"`
	Kind     string   `json:"kind"`
	ID       string   `json:"id"`
	Exp      int64    `json:"exp"`
	JKT      string   `json:"jkt,omitempty"`
	AuthTime int64    `json:"auth_time,omitempty"`
	AMR      []string `json:"amr,omitempty"`
}

// RootBinding is the depth-0 OIDC nonce-thumbprint binding (Q17, D5).
type RootBinding struct {
	Nonce      string `json:"nonce,omitempty"`
	DeviceJKT  string `json:"device_jkt,omitempty"`
	IDTokenRef string `json:"id_token_ref,omitempty"` // sha256 hex
}

// Trigger marks an autonomous depth-0 root (Q14).
type Trigger struct {
	Kind             string `json:"kind"` // schedule | webhook
	DescriptorDigest string `json:"descriptor_digest"`
}

// Verification is the per-hop three-state (Q12, D5).
type Verification struct {
	Status      string `json:"status"` // verified | asserted | broken
	Method      string `json:"method,omitempty"`
	EvidenceRef string `json:"evidence_ref,omitempty"`
}

// Attribution is the two orthogonal axes, stored at write (Q12, Q14).
type Attribution struct {
	Verification string `json:"verification"` // verified | asserted | broken
	Class        string `json:"class"`        // direct | delegated | autonomous | unattributed
}

// Slot is one payload availability slot (Q34–Q40, Q83).
type Slot struct {
	Role        string    `json:"role,omitempty"`
	Digest      string    `json:"digest"`  // plain SHA-256 hex over raw plaintext bytes (Q36)
	Custody     string    `json:"custody"` // customer-held | dropped-with-digest | vendor-held
	ContentType string    `json:"content_type,omitempty"`
	Size        int       `json:"size,omitempty"`
	Ref         string    `json:"ref,omitempty"` // content address (Q38)
	Manifest    *Manifest `json:"field_digest_manifest,omitempty"`
	Subjects    []string  `json:"subjects,omitempty"`
	State       string    `json:"state"` // present | missing | deleted | unreadable | dropped-at-capture
	CauseRef    string    `json:"cause_ref,omitempty"`
}

// Manifest is the field-digest Merkle manifest for JSON payloads (Q37).
type Manifest struct {
	Root   string          `json:"root,omitempty"`
	Fields []ManifestField `json:"fields,omitempty"`
}

// ManifestField is one field digest in the manifest.
type ManifestField struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// HumanInLoop is consent/denial evidence, marked asserted (Q24).
type HumanInLoop struct {
	ApprovalReceiptID    string `json:"approval_receipt_id,omitempty"`
	SatisfiedBy          string `json:"satisfied_by,omitempty"`
	BindingMessageDigest string `json:"binding_message_digest,omitempty"`
	Marked               string `json:"marked,omitempty"` // const "asserted"
}

// Provenance is native vs imported (Q93, D9.3).
type Provenance struct {
	Source      string `json:"source"` // native | import
	ImportFloor string `json:"import_floor,omitempty"`
	Importer    string `json:"importer,omitempty"`
}

// Link is a typed reference to another record (Q5).
type Link struct {
	Rel            string  `json:"rel"`
	TargetLogIndex *int    `json:"target_log_index,omitempty"`
	TargetLeafHash string  `json:"target_leaf_hash,omitempty"`
	Anchor         *Anchor `json:"anchor,omitempty"`
}

// Anchor points denial/delegation_failed records at token evidence (Q5).
type Anchor struct {
	JTI          string `json:"jti,omitempty"`
	ParHash      string `json:"par_hash,omitempty"`
	IntentDigest string `json:"intent_digest,omitempty"`
}
