package proxy

import (
	"errors"

	"github.com/behalf-sh/behalf/internal/aat"
	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/receipt"
	"github.com/behalf-sh/behalf/internal/spool"
)

// Orphan recovery is Q4's other half. Intent is durably spooled before the
// request is forwarded and merged into one completion receipt in the common
// case; when the process dies between the two — payment fired, agent died —
// the intent has no completion, and recovery flushes it into the log as an
// `orphan_intent` receipt carrying the spooled intent digest (Q4, Q5).
//
// The recovered receipt is signed and spooled as a completion of its own,
// so the drain moves it like any other and the intent is never recovered
// twice. It reuses the counter the intent already consumed: one crossing,
// one counter, no gap for the Q48 detector to trip over.

// RecoverOrphans mints, signs and spools an `orphan_intent` receipt for
// every intent left unmatched in the spool at dir. It is what the drain
// calls; the proxy runs the same path at startup. Returns how many were
// flushed.
func RecoverOrphans(cfg Config) (int, error) {
	c, err := newCapture(cfg)
	if err != nil {
		return 0, err
	}
	defer c.spool.Close()
	// newCapture already flushed what Open recovered.
	return c.flushed, nil
}

// flushOrphans mints one receipt per recovered intent.
func (c *capture) flushOrphans(rec *spool.Recovery) (int, error) {
	if rec == nil || len(rec.Orphans) == 0 {
		return 0, nil
	}
	for _, in := range rec.Orphans {
		r, err := c.orphanReceipt(in)
		if err != nil {
			return c.flushed, err
		}
		receiptID, env, err := c.emit(r)
		if err != nil {
			return c.flushed, err
		}
		if err := c.spool.AppendCompletion(in.IntentID, receiptID, env); err != nil {
			return c.flushed, err
		}
		c.flushed++
	}
	return c.flushed, nil
}

// orphanReceipt builds the recovered record from the spooled intent alone —
// every field it needs was a capture-time fact written before the crash.
func (c *capture) orphanReceipt(in spool.Intent) (*receipt.Receipt, error) {
	auth, attribution := c.authorityForRef(in.ChainRef)

	var slots []receipt.Slot
	if in.InputDigest != "" {
		slots = append(slots, c.recoveredInputSlot(in))
	}

	return &receipt.Receipt{
		SchemaVersion:      receipt.SchemaVersion,
		OtelConventionsVer: OtelConventionsVersion,
		ReceiptID:          c.ids.ulidAt(c.now()),
		Kind:               KindOrphanIntent,
		RiskClass:          in.RiskClass,
		RiskPolicyDigest:   in.RiskPolicyDig,
		CapturedAt:         in.CapturedAt,
		Emitter: receipt.Emitter{
			JKT:     in.Emitter.JKT,
			Surface: Surface,
			Counter: in.Emitter.Counter,
		},
		Actor: c.actorFor(auth),
		Operation: receipt.Operation{
			Name:   in.Tool,
			Target: in.Target,
			Outcome: receipt.Outcome{
				Status: "error",
				Error:  "no response observed: the capture surface restarted with this intent still in flight",
			},
		},
		Attempt:         &receipt.Attempt{IntentDigest: in.IntentDigest},
		RunID:           in.RunID,
		RunIDProvenance: in.RunIDProvenance,
		StepKey:         in.StepKey,
		Authority:       auth,
		Attribution:     attribution,
		Payload:         slots,
		Provenance:      receipt.Provenance{Source: "native"},
	}, nil
}

// recoveredInputSlot rebuilds the input slot from the CAS. If the blob is
// still there the manifest is recomputed from the same bytes it was
// computed from at capture; if the customer deleted it, the slot says
// `missing` rather than pretending — three findings, not one (Q36, Q83).
func (c *capture) recoveredInputSlot(in spool.Intent) receipt.Slot {
	slot := receipt.Slot{
		Role:        "input",
		Digest:      in.InputDigest,
		Custody:     "customer-held",
		ContentType: "application/json",
		Size:        in.InputSize,
		Ref:         "sha256:" + in.InputDigest,
		State:       "present",
	}
	raw, err := c.blobs.Get(in.InputDigest)
	switch {
	case err == nil:
		slot.Manifest = fieldDigestManifest(raw)
	case errors.Is(err, cas.ErrMissing):
		slot.State = "missing"
	default:
		slot.State = "unreadable"
	}
	return slot
}

// authorityForRef embeds the chain that was in force when the intent was
// captured, fetched from the CAS by the digest the intent recorded — not
// whatever chain this recovering process happens to be configured with.
func (c *capture) authorityForRef(ref string) (*receipt.Authority, receipt.Attribution) {
	if ref == "" {
		return nil, receipt.Attribution{Verification: "asserted", Class: "unattributed"}
	}
	if c.chainRef == ref {
		return c.authorityFor()
	}
	raw, err := c.blobs.Get(ref)
	if err != nil {
		// The chain material is gone; the crossing is still evidence, and
		// saying `unattributed` is the honest reading of what survives.
		return nil, receipt.Attribution{Verification: "asserted", Class: "unattributed"}
	}
	parsed, err := ParseChain(raw)
	if err != nil {
		return nil, receipt.Attribution{Verification: "asserted", Class: "unattributed"}
	}
	// The recovered chain gets its own verification pass against the same
	// root material: what is recorded is what THIS process could check about
	// the chain that was in force then, which is the honest thing a recovery
	// can say (Q18, Q29).
	return c.authorityForChain(parsed, aat.Verify(parsed.Hops, c.root))
}
