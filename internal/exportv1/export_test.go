package exportv1_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/fixture"
)

// Chain known answers, computed independently with shasum -a 256 (raw-byte
// concatenation via xxd), per docs/export-format-v1.md §1.3.
func TestChainKnownAnswer(t *testing.T) {
	start := exportv1.ChainStart("example.org/log")
	if got, want := hex.EncodeToString(start[:]),
		"2f21ad71bc7fea2b2a11b8f53bab4aabaf151b682b45c26ca664228d1fec6e6d"; got != want {
		t.Fatalf("ChainStart = %s, want %s", got, want)
	}

	leaf0 := sha256.Sum256([]byte("leaf-0"))
	leaf1 := sha256.Sum256([]byte("leaf-1"))
	c0 := exportv1.ChainNext(start, leaf0)
	if got, want := hex.EncodeToString(c0[:]),
		"2a8167a197833be884207d1142e9dded7a3b5549fdb312886d386dc3efa4840f"; got != want {
		t.Fatalf("chain after leaf0 = %s, want %s", got, want)
	}
	c1 := exportv1.ChainNext(c0, leaf1)
	if got, want := hex.EncodeToString(c1[:]),
		"b721a724114849d35c0e763048e86431cb8fe11fffb0fc63343ed890e982d7bf"; got != want {
		t.Fatalf("chain after leaf1 = %s, want %s", got, want)
	}

	fs := exportv1.ChainStart("behalf.sh/demo/run_9f2a")
	if got, want := hex.EncodeToString(fs[:]),
		"ff7e8b6cc566737304029065fe8b02ea848c3541f02081b84dabc8cc6282c246"; got != want {
		t.Fatalf("ChainStart(run_9f2a origin) = %s, want %s", got, want)
	}
}

// TestSpanSpliceRoundTrip is the span rule under test: for every leaf line
// of a generated export, the payload span extracted from the raw line bytes
// by the independent scanner must be byte-identical to the bytes that were
// sealed and signed; the recomputed PAE must reproduce leaf_hash and verify
// the signature against the header key. Same for the head span.
func TestSpanSpliceRoundTrip(t *testing.T) {
	for _, spec := range []fixture.Spec{fixture.Tiny(), fixture.Run9F2A()} {
		t.Run(spec.RunID, func(t *testing.T) {
			res, err := fixture.Generate(spec)
			if err != nil {
				t.Fatal(err)
			}
			lines := bytes.Split(bytes.TrimSuffix(res.Bytes, []byte("\n")), []byte("\n"))
			if len(lines) != spec.Count+2 {
				t.Fatalf("got %d lines, want %d", len(lines), spec.Count+2)
			}

			// Header: collect the embedded keys.
			var hdr struct {
				Kind      string `json:"kind"`
				Format    string `json:"format"`
				LogOrigin string `json:"log_origin"`
				Keys      []struct {
					JKT string `json:"jkt"`
					JWK struct {
						Kty string `json:"kty"`
						Crv string `json:"crv"`
						X   string `json:"x"`
					} `json:"jwk"`
				} `json:"keys"`
			}
			if err := json.Unmarshal(lines[0], &hdr); err != nil {
				t.Fatalf("header: %v", err)
			}
			if hdr.Kind != "header" || hdr.Format != exportv1.Format || hdr.LogOrigin != spec.LogOrigin {
				t.Fatalf("bad header: %+v", hdr)
			}
			pubs := map[string][]byte{}
			for _, k := range hdr.Keys {
				if k.JWK.Kty != "OKP" || k.JWK.Crv != "Ed25519" {
					t.Fatalf("bad header jwk: %+v", k.JWK)
				}
				raw, err := base64.RawURLEncoding.DecodeString(k.JWK.X)
				if err != nil || len(raw) != 32 {
					t.Fatalf("bad jwk x for %s: %v", k.JKT, err)
				}
				// The jkt key must be the RFC 7638 thumbprint of the jwk.
				j := dsse.JWK{Kty: k.JWK.Kty, Crv: k.JWK.Crv, X: k.JWK.X}
				if j.Thumbprint() != k.JKT {
					t.Fatalf("header jkt %s does not match jwk thumbprint %s", k.JKT, j.Thumbprint())
				}
				pubs[k.JKT] = raw
			}

			chain := exportv1.ChainStart(spec.LogOrigin)
			for i := 0; i < spec.Count; i++ {
				line := lines[i+1]

				span, err := extractTopLevelValue(line, "payload")
				if err != nil {
					t.Fatalf("leaf %d: %v", i, err)
				}
				if !bytes.Equal(span, res.Payloads[i]) {
					t.Fatalf("leaf %d: extracted span differs from signed bytes\n span: %s\nsigned: %s",
						i, span, res.Payloads[i])
				}

				idxRaw, err := extractTopLevelValue(line, "index")
				if err != nil {
					t.Fatalf("leaf %d index: %v", i, err)
				}
				if idx, err := strconv.Atoi(string(idxRaw)); err != nil || idx != i {
					t.Fatalf("leaf %d: index field = %s", i, idxRaw)
				}

				ptRaw, err := extractTopLevelValue(line, "payloadType")
				if err != nil {
					t.Fatalf("leaf %d payloadType: %v", i, err)
				}
				var pt string
				if err := json.Unmarshal(ptRaw, &pt); err != nil || pt != exportv1.PayloadTypeReceipt {
					t.Fatalf("leaf %d: payloadType = %s", i, ptRaw)
				}

				// Recompute the leaf hash from the extracted span.
				leafHash := dsse.LeafHash(pt, span)
				lhRaw, err := extractTopLevelValue(line, "leaf_hash")
				if err != nil {
					t.Fatalf("leaf %d leaf_hash: %v", i, err)
				}
				var lhHex string
				if err := json.Unmarshal(lhRaw, &lhHex); err != nil {
					t.Fatalf("leaf %d leaf_hash: %v", i, err)
				}
				if lhHex != hex.EncodeToString(leafHash[:]) {
					t.Fatalf("leaf %d: leaf_hash %s != recomputed %x", i, lhHex, leafHash)
				}
				if leafHash != res.LeafHashes[i] {
					t.Fatalf("leaf %d: recomputed hash differs from writer's record", i)
				}

				// Verify the signature over the PAE of the extracted span.
				sigRaw, err := extractTopLevelValue(line, "sig")
				if err != nil {
					t.Fatalf("leaf %d sig: %v", i, err)
				}
				var sig struct {
					KeyID string `json:"keyid"`
					Sig   string `json:"sig"`
				}
				if err := json.Unmarshal(sigRaw, &sig); err != nil {
					t.Fatalf("leaf %d sig: %v", i, err)
				}
				pub, ok := pubs[sig.KeyID]
				if !ok {
					t.Fatalf("leaf %d: keyid %s not in header", i, sig.KeyID)
				}
				sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
				if err != nil {
					t.Fatalf("leaf %d sig b64: %v", i, err)
				}
				if !dsse.Verify(pub, pt, span, sigBytes) {
					t.Fatalf("leaf %d: signature does not verify over extracted span", i)
				}

				chain = exportv1.ChainNext(chain, leafHash)
			}

			// Head line: extract head span, check chain and count, verify sig.
			headLine := lines[len(lines)-1]
			headSpan, err := extractTopLevelValue(headLine, "head")
			if err != nil {
				t.Fatalf("head: %v", err)
			}
			var head struct {
				Format    string `json:"format"`
				LogOrigin string `json:"log_origin"`
				Count     int    `json:"count"`
				Chain     string `json:"chain"`
			}
			if err := json.Unmarshal(headSpan, &head); err != nil {
				t.Fatalf("head: %v", err)
			}
			if head.Format != exportv1.Format || head.LogOrigin != spec.LogOrigin || head.Count != spec.Count {
				t.Fatalf("bad head: %+v", head)
			}
			if head.Chain != hex.EncodeToString(chain[:]) {
				t.Fatalf("head.chain = %s, recomputed %x", head.Chain, chain)
			}
			if chain != res.Chain {
				t.Fatalf("recomputed chain differs from writer's record")
			}

			sigRaw, err := extractTopLevelValue(headLine, "sig")
			if err != nil {
				t.Fatalf("head sig: %v", err)
			}
			var sig struct {
				KeyID string `json:"keyid"`
				Sig   string `json:"sig"`
			}
			if err := json.Unmarshal(sigRaw, &sig); err != nil {
				t.Fatalf("head sig: %v", err)
			}
			pub, ok := pubs[sig.KeyID]
			if !ok {
				t.Fatalf("head keyid %s not in header", sig.KeyID)
			}
			sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
			if err != nil {
				t.Fatalf("head sig b64: %v", err)
			}
			if !dsse.Verify(pub, exportv1.PayloadTypeChainHead, headSpan, sigBytes) {
				t.Fatal("head signature does not verify over extracted head span")
			}
		})
	}
}

// TestTinyExportUsesDistinctHeadKey pins the multi-key header behavior the
// vector corpus relies on.
func TestTinyExportUsesDistinctHeadKey(t *testing.T) {
	res, err := fixture.Generate(fixture.Tiny())
	if err != nil {
		t.Fatal(err)
	}
	lines := bytes.Split(bytes.TrimSuffix(res.Bytes, []byte("\n")), []byte("\n"))
	var hdr struct {
		Keys []struct {
			JKT string `json:"jkt"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(lines[0], &hdr); err != nil {
		t.Fatal(err)
	}
	if len(hdr.Keys) != 2 {
		t.Fatalf("tiny header has %d keys, want 2", len(hdr.Keys))
	}
	leafSig, err := extractTopLevelValue(lines[1], "sig")
	if err != nil {
		t.Fatal(err)
	}
	headSig, err := extractTopLevelValue(lines[len(lines)-1], "sig")
	if err != nil {
		t.Fatal(err)
	}
	var ls, hs struct {
		KeyID string `json:"keyid"`
	}
	if err := json.Unmarshal(leafSig, &ls); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(headSig, &hs); err != nil {
		t.Fatal(err)
	}
	if ls.KeyID == hs.KeyID {
		t.Fatal("tiny export should sign head with a key distinct from the leaf key")
	}
}
