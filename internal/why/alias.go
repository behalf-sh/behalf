package why

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/behalf-sh/behalf/internal/dsse"
	"github.com/behalf-sh/behalf/internal/testkeys"
)

// AliasFileName is the local alias map inside the log dir: a JSON object of
// key thumbprint -> display label.
const AliasFileName = "aliases.json"

// Aliases is the local, versioned alias map that turns key thumbprints into
// names on screen (Q16). It exists because the canonical actor identity is
// the hop's key thumbprint — keys are what the cryptography proves — while
// names are self-reported. Receipts therefore carry no human-readable
// identity at all (Q40): the human principal is issuer plus sub-digest, and
// the display name lives here, locally, under the operator's control. Every
// label this map produces is an asserted label, never evidence.
type Aliases map[string]string

// demoAliases names the deterministic fixture keys so `behalf why` on the
// demo runs reads like the product rather than like a key dump. These are
// test keys from internal/testkeys and nothing else can hold them.
func demoAliases() Aliases {
	return Aliases{
		testkeys.ActorRoot().JKT: "alice@acme.com",
		testkeys.ActorHop1().JKT: "support-orchestrator @1.4.2",
		testkeys.ActorHop2().JKT: "billing-agent",
		testkeys.Emitter().JKT:   "mcp-proxy",
	}
}

// LoadAliases reads logDir/aliases.json over the built-in demo names. A
// missing file is not an error: the map is a display convenience, and an
// unnamed key renders as its own thumbprint.
func LoadAliases(logDir string) (Aliases, error) {
	a := demoAliases()
	b, err := os.ReadFile(filepath.Join(logDir, AliasFileName))
	if os.IsNotExist(err) {
		return a, nil
	}
	if err != nil {
		return a, err
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		return a, err
	}
	for k, v := range m {
		a[k] = v
	}
	return a, nil
}

// Label returns the display label for a key thumbprint, falling back to a
// short form of the thumbprint itself — an honest "we do not know this key"
// rather than a blank.
func (a Aliases) Label(jkt string) string {
	if jkt == "" {
		return "(no key)"
	}
	if l, ok := a[jkt]; ok && l != "" {
		return l
	}
	return "key " + short(jkt)
}

// short renders a thumbprint suffix the way the tree does: "..2a90db".
func short(jkt string) string {
	if len(jkt) <= 6 {
		return ".." + jkt
	}
	return ".." + jkt[len(jkt)-6:]
}

// thumbprint computes the RFC 7638 thumbprint of a stored cnf.jwk. Only
// Ed25519 OKP keys exist in v1 (Q69); anything else yields "", which the
// renderer shows as an unnamed key rather than guessing.
func thumbprint(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var jwk dsse.JWK
	if err := json.Unmarshal(raw, &jwk); err != nil {
		return ""
	}
	if jwk.Kty != "OKP" || jwk.Crv != "Ed25519" || jwk.X == "" {
		return ""
	}
	return jwk.Thumbprint()
}
