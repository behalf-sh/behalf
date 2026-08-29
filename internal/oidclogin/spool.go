package oidclogin

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/exportv1"
	"github.com/behalf-sh/behalf/internal/identity"
)

// The local spool: receipts wait here, already sealed and DSSE-signed by
// the emitter key, until the log service consumes them. One JSON line per
// receipt, assembled by byte concatenation so the sealed payload bytes are
// spliced verbatim — the span rule (export-format-v1.md §1.2). The line
// shape mirrors an export leaf line minus the log-assigned index.

// appendSpool signs sealed (the exact sealed receipt payload bytes) with
// the emitter key and appends one spool line to <stateDir>/spool.jsonl.
func appendSpool(stateDir string, sealed []byte, emitter *identity.Key) error {
	sig := dsse.Sign(emitter.Private, exportv1.PayloadTypeReceipt, sealed)
	leafHash := dsse.LeafHash(exportv1.PayloadTypeReceipt, sealed)

	var line []byte
	line = append(line, `{"kind":"spooled","payloadType":`...)
	line = appendJSONString(line, exportv1.PayloadTypeReceipt)
	line = append(line, `,"payload":`...)
	line = append(line, sealed...) // signed bytes, verbatim
	line = append(line, `,"sig":{"keyid":`...)
	line = appendJSONString(line, emitter.JKT)
	line = append(line, `,"sig":"`...)
	line = append(line, base64.StdEncoding.EncodeToString(sig)...)
	line = append(line, `"},"leaf_hash":"`...)
	line = append(line, hex.EncodeToString(leafHash[:])...)
	line = append(line, `"}`...)
	line = append(line, '\n')

	f, err := os.OpenFile(filepath.Join(stateDir, SpoolFile), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("oidclogin: open spool: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		f.Close()
		return fmt.Errorf("oidclogin: append spool: %w", err)
	}
	return f.Close()
}

func appendJSONString(dst []byte, s string) []byte {
	b, err := json.Marshal(s)
	if err != nil {
		panic(fmt.Sprintf("oidclogin: marshal string: %v", err))
	}
	return append(dst, b...)
}
