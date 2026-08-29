package tlog

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/client"

	"github.com/behalf-sh/behalf/internal/cas"
	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/index"
	"github.com/behalf-sh/behalf/internal/oidclogin"
)

// ExportRun writes a Week-1 behalf.sh/export/v1 file for one run, derived
// from the log (docs/export-format-v1.md). It is a read-only path over the
// log dir: no appender is started and no epoch is claimed.
//
// The span rule end to end: leaf payload bytes come from the stored
// envelope bytes verbatim — the envelope's payload span is extracted with a
// span scanner and spliced into the leaf line unmodified, and the leaf
// signature is the emitter's original signature from the envelope, never
// re-signed. Only receipts covered by the published checkpoint are
// exportable. The head is signed by the log's checkpoint key, whose JWK is
// in the header key set.
//
// True tile-directory verification (checkpoint + inclusion proofs under a
// new format string) is the next issue (ENG-7); this bridge keeps the
// Week-1 verifier and tamper suite working against log-derived exports.
// ExportOption configures ExportRun.
type ExportOption func(*exportOptions)

type exportOptions struct{ blobs *cas.Store }

// WithHopTokens makes the export carry the delegation hop tokens its receipts
// reference, read from the customer-held blob store (ENG-38).
//
// It is an option rather than the default because the store is the customer's,
// not the log's: an export can legitimately be produced by someone holding the
// log directory and nothing else, and that export is still a valid export —
// just one whose chains cannot be re-verified offline. Silently producing a
// tokenless export from a caller who *did* have the store would be the bad
// outcome, so `behalf-log export` always passes this.
//
// A hop whose token is missing from the store is skipped rather than fatal.
// The store is customer-held and may have been pruned, and an export that
// carries three of a run's four hop tokens is more useful than no export; the
// verifier reports the absent one as unchecked rather than as a break.
func WithHopTokens(blobs *cas.Store) ExportOption {
	return func(o *exportOptions) { o.blobs = blobs }
}

func ExportRun(ctx context.Context, dir, runID string, w io.Writer, opts ...ExportOption) error {
	var o exportOptions
	for _, fn := range opts {
		fn(&o)
	}
	key, err := LoadCheckpointKey(dir)
	if err != nil {
		return err
	}
	idx, err := index.Open(ctx, dir)
	if err != nil {
		return err
	}
	defer idx.Close()

	rows, err := idx.RunRows(runID)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return fmt.Errorf("tlog: no receipts indexed for run %q", runID)
	}

	jwks, order, err := idx.Keys()
	if err != nil {
		return err
	}
	var headerKeys []exportv1.HeaderKey
	pubs := map[string]ed25519.PublicKey{}
	for _, jkt := range order {
		var jwk dsse.JWK
		if err := json.Unmarshal([]byte(jwks[jkt]), &jwk); err != nil {
			return fmt.Errorf("tlog: parse indexed jwk %s: %w", jkt, err)
		}
		raw, err := base64.RawURLEncoding.DecodeString(jwk.X)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			return fmt.Errorf("tlog: indexed jwk %s has bad x", jkt)
		}
		headerKeys = append(headerKeys, exportv1.HeaderKey{JKT: jkt, JWK: jwk})
		pubs[jkt] = ed25519.PublicKey(raw)
	}

	// The key that signs the head goes in the header by construction, not by
	// hoping the index still remembers it.
	//
	// It used to come only from the index, and after a reindex it was gone —
	// so a rebuilt log exported a file whose head signature named a key the
	// header did not carry, and `behalf-verify` reported it **TAMPERED**. An
	// export that reads as tampered because someone rebuilt a cache is the
	// worst possible false positive for this product: it spends the one alarm
	// that has to mean something.
	//
	// This is also just the correct invariant. `exportv1.Writer` signs the head
	// with `key`; a header that does not carry `key` describes a file nobody can
	// verify, whatever the index happens to hold.
	if _, ok := pubs[key.JKT]; !ok {
		headerKeys = append(headerKeys, exportv1.HeaderKey{JKT: key.JKT, JWK: key.JWK})
		pubs[key.JKT] = key.Public
		// The header key order is the index's ascending-jkt order, which the
		// export format does not require but the fixtures rely on for byte
		// stability. Re-sort so a key added here lands where it would have.
		sort.Slice(headerKeys, func(i, j int) bool { return headerKeys[i].JKT < headerKeys[j].JKT })
	}

	// The published checkpoint bounds what is exportable: only entries a
	// signed checkpoint commits to.
	cp, err := ParseLogCheckpoint(ctx, dir)
	if err != nil {
		return err
	}

	fetcher := client.FileFetcher{Root: dir}
	bundles := map[uint64]api.EntryBundle{}

	// One envelope read, shared by the token pre-pass and the emit loop. The
	// bundle cache means the pre-pass costs one decode per receipt, not a
	// second trip to disk.
	readEnvelope := func(row index.Row) ([]byte, error) {
		if row.LogIndex >= cp.Size {
			return nil, fmt.Errorf("tlog: receipt %s at index %d is beyond the published checkpoint (size %d); wait for the next checkpoint",
				row.ReceiptID, row.LogIndex, cp.Size)
		}
		bIdx := row.LogIndex / layout.EntryBundleWidth
		bundle, ok := bundles[bIdx]
		if !ok {
			var err error
			bundle, err = client.GetEntryBundle(ctx, fetcher.ReadEntryBundle, bIdx, cp.Size)
			if err != nil {
				return nil, fmt.Errorf("tlog: read entry bundle %d: %w", bIdx, err)
			}
			bundles[bIdx] = bundle
		}
		off := int(row.LogIndex % layout.EntryBundleWidth)
		if off >= len(bundle.Entries) {
			return nil, fmt.Errorf("tlog: bundle %d has %d entries, need offset %d", bIdx, len(bundle.Entries), off)
		}
		envelope := bundle.Entries[off]
		// Integrity: the stored bytes must still hash to the indexed leaf.
		if got := fmt.Sprintf("%x", rfc6962.DefaultHasher.HashLeaf(envelope)); got != row.LeafHash {
			return nil, fmt.Errorf("tlog: envelope at index %d does not match indexed leaf hash", row.LogIndex)
		}
		return envelope, nil
	}

	// The header carries the tokens, so they must be gathered before the
	// writer is constructed.
	tokens, err := gatherHopTokens(o.blobs, rows, readEnvelope)
	if err != nil {
		return err
	}

	wr, err := exportv1.NewWriterWithTokens(w, key.Origin, headerKeys, tokens)
	if err != nil {
		return err
	}
	for _, row := range rows {
		envelope, err := readEnvelope(row)
		if err != nil {
			return err
		}
		env, err := ParseEnvelope(envelope)
		if err != nil {
			return fmt.Errorf("tlog: index %d: %w", row.LogIndex, err)
		}
		if env.PayloadType != exportv1.PayloadTypeReceipt {
			return fmt.Errorf("tlog: index %d has payloadType %q, not a receipt", row.LogIndex, env.PayloadType)
		}
		// Defense in depth: the original emitter signature must verify over
		// the extracted span before it is re-emitted.
		pub, ok := pubs[env.KeyID]
		if !ok {
			return fmt.Errorf("tlog: index %d signed by unregistered key %s", row.LogIndex, env.KeyID)
		}
		if !dsse.Verify(pub, env.PayloadType, env.Payload, env.Sig) {
			return fmt.Errorf("tlog: index %d: emitter signature does not verify over stored span", row.LogIndex)
		}
		if err := wr.AppendSigned(env.Payload, env.KeyID, env.Sig); err != nil {
			return err
		}
	}
	return wr.Close(exportv1.Signer{Private: key.Private, KeyID: key.JKT})
}

// Reindex rebuilds the follower index from the entry bundles and restores the
// registered emitter keys on top of it.
//
// The second half is what makes Q76's "the index is disposable" true rather
// than nearly true. index.Rebuild replays the log, and the log carries key
// *thumbprints* only — so a bare rebuild produced an index that knew every
// receipt and no key, and `behalf-log export` then failed outright with
// "header requires at least one key". A log you could not export from until
// something happened to re-register a key is a log whose evidence was hostage
// to a cache.
//
// This lives here rather than in internal/index because the keys file is the
// log service's layout, and the index has no business knowing where the log
// keeps its keys — it is a projection, and a projection that reached back into
// the thing it projects would stop being rebuildable in a different way.
func Reindex(ctx context.Context, dir string) (*index.Stats, error) {
	stats, err := index.Rebuild(ctx, dir)
	if err != nil {
		return stats, err
	}
	emitters, err := LoadEmitterKeys(dir)
	if err != nil {
		return stats, err
	}
	if len(emitters) == 0 {
		return stats, nil
	}
	idx, err := index.Open(ctx, dir)
	if err != nil {
		return stats, err
	}
	defer idx.Close()
	for jkt, jwk := range emitters {
		if err := idx.RegisterKey(jkt, jwk); err != nil {
			return stats, fmt.Errorf("tlog: restore emitter key %s: %w", jkt, err)
		}
	}
	return stats, nil
}

// gatherHopTokens collects the compact JWS for every hop token the run's
// receipts reference, keyed by the `evidence_ref` that references it.
//
// The lookup is by the receipt's own stated address, and `cas.Store.Get`
// re-hashes what it returns, so a blob that does not match its address never
// reaches the export. Duplicate references across receipts collapse into one
// entry — a run's receipts typically share the same handful of hops, which is
// what keeps the section proportional to distinct hops rather than to
// receipts.
func gatherHopTokens(blobs *cas.Store, rows []index.Row, readEnvelope func(index.Row) ([]byte, error)) (map[string]string, error) {
	if blobs == nil {
		return nil, nil
	}
	tokens := map[string]string{}
	for _, row := range rows {
		envelope, err := readEnvelope(row)
		if err != nil {
			return nil, err
		}
		env, err := ParseEnvelope(envelope)
		if err != nil {
			return nil, fmt.Errorf("tlog: index %d: %w", row.LogIndex, err)
		}
		if env.PayloadType != exportv1.PayloadTypeReceipt {
			continue
		}
		var r struct {
			Authority *struct {
				Chain []struct {
					ParHash      string `json:"par_hash"`
					Verification struct {
						EvidenceRef string `json:"evidence_ref"`
					} `json:"verification"`
				} `json:"chain"`
			} `json:"authority"`
		}
		if err := json.Unmarshal(env.Payload, &r); err != nil {
			return nil, fmt.Errorf("tlog: index %d: parse receipt for hop tokens: %w", row.LogIndex, err)
		}
		if r.Authority == nil {
			continue
		}
		for _, hop := range r.Authority.Chain {
			// A hop's own evidence_ref names its token — except at depth 0,
			// where a *verified* root's evidence is the signed login
			// statement the D5 checks ran against, not the hop token (Q22).
			take(blobs, tokens, hop.Verification.EvidenceRef)

			// So the root's token is reached the other way: par_hash is
			// defined as SHA-256 over the parent's compact JWS (§3), which
			// means every hop already names its parent's token address. That
			// is what makes the export self-sufficient without a second
			// reference in the receipt — and it costs nothing, because for
			// depth >= 1 the address is one the evidence_ref above already
			// carried.
			if hop.ParHash != "" && hop.ParHash != oidclogin.RootParHash {
				take(blobs, tokens, "sha256:"+hop.ParHash)
			}
		}
	}
	if len(tokens) == 0 {
		return nil, nil
	}
	return tokens, nil
}

// take resolves one `sha256:<hex>` reference in the customer-held store and
// records it under that reference, if it names a hop token.
//
// Anything that is not a compact JWS is skipped rather than carried. The
// store holds more than hop tokens — a verified root's evidence is a signed
// login statement — and an export whose token section contained one would
// hand the verifier something it must then reject, turning a legitimate
// artefact into a finding.
func take(blobs *cas.Store, tokens map[string]string, ref string) {
	if ref == "" {
		return
	}
	if _, seen := tokens[ref]; seen {
		return
	}
	digest, ok := strings.CutPrefix(ref, "sha256:")
	if !ok {
		return
	}
	blob, err := blobs.Get(digest)
	if err != nil {
		// Pruned, or never a blob at all. Not a failure of the export: the
		// verifier reports the hop as unchecked rather than as broken.
		return
	}
	if !isCompactJWS(blob) {
		return
	}
	tokens[ref] = string(blob)
}

// isCompactJWS reports whether b looks like a three-segment compact JWS. This
// is a shape check to keep non-token blobs out of the token section, not a
// verification step — the verifier does that, independently, which is the
// entire point of the section existing.
func isCompactJWS(b []byte) bool {
	parts := bytes.Split(b, []byte("."))
	if len(parts) != 3 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 {
			return false
		}
	}
	return true
}
