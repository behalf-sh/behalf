package proxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path"

	"github.com/behalf-sh/behalf/internal/cas"
)

// Risk class is assigned by the proxy's capture-time tool-policy config,
// never self-reported by the producer, and the digest of the config that
// made the assignment rides the receipt so the assignment is auditable
// rather than free-floating (Q6, receipt-schema-v1.md §4 and §9 item 8).
//
// The config is JSON:
//
//	{
//	  "version": "behalf.sh/tool-policy/v1",
//	  "default": "low",
//	  "rules": [
//	    {"pattern": "refund.*",  "class": "high", "target_arg": "order_id",
//	     "outcome_fields": ["amount_cents", "currency"]},
//	    {"pattern": "orders.*",  "class": "low"}
//	  ]
//	}
//
// Patterns are globs matched against the tool name with path.Match
// semantics ('*' matches any run of non-'/' bytes, so it spans the dot in
// `refund.issue`). The first matching rule wins; no match takes `default`.
// `target_arg`, when set, names the top-level argument whose string value
// becomes `operation.target`.
//
// `outcome_fields`, when set, names the top-level fields of the tool's own
// structured result that are recorded verbatim in `operation.outcome`
// beside the status. It is the mirror image of `target_arg` — the operator
// says which part of the crossing behalf's own record is about — and it
// exists because a receipt that says "a refund happened" without saying for
// how much cannot be read against the ceiling the chain delegated (Q11,
// Q13). Only scalars are lifted, and only the named ones: response content
// stays customer-held and referenced by digest (Q34–Q38), so this is a
// deliberate, per-tool, operator-declared exception and not a door into
// recording payloads.

// DefaultPolicyJSON is the built-in policy used when no --policy file is
// given. It is a real config, digested like any other, so a receipt written
// without a policy file still says exactly what classified it.
const DefaultPolicyJSON = `{"version":"behalf.sh/tool-policy/v1","default":"low","rules":[{"pattern":"*refund*","class":"high"},{"pattern":"*payment*","class":"high"},{"pattern":"*charge*","class":"high"},{"pattern":"*delete*","class":"high"},{"pattern":"*write*","class":"medium"},{"pattern":"*update*","class":"medium"},{"pattern":"*create*","class":"medium"},{"pattern":"*send*","class":"medium"}]}`

// Rule maps a tool-name glob to a risk class.
type Rule struct {
	Pattern   string `json:"pattern"`
	Class     string `json:"class"`
	TargetArg string `json:"target_arg,omitempty"`
	// OutcomeFields names the top-level scalars of the tool's structured
	// result that are recorded in operation.outcome.
	OutcomeFields []string `json:"outcome_fields,omitempty"`
}

// Policy is a loaded tool-policy config plus the digest of the exact bytes
// it was loaded from.
type Policy struct {
	Version string `json:"version"`
	Default string `json:"default"`
	Rules   []Rule `json:"rules"`

	raw    []byte
	digest string
	source string
}

// LoadPolicy reads a tool-policy config. An empty path loads
// DefaultPolicyJSON.
func LoadPolicy(pathname string) (*Policy, error) {
	if pathname == "" {
		p, err := parsePolicy([]byte(DefaultPolicyJSON))
		if err != nil {
			return nil, err
		}
		p.source = "built-in"
		return p, nil
	}
	raw, err := os.ReadFile(pathname)
	if err != nil {
		return nil, fmt.Errorf("proxy: read tool policy: %w", err)
	}
	p, err := parsePolicy(raw)
	if err != nil {
		return nil, err
	}
	p.source = pathname
	return p, nil
}

func parsePolicy(raw []byte) (*Policy, error) {
	var p Policy
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("proxy: parse tool policy: %w", err)
	}
	if p.Default == "" {
		p.Default = "low"
	}
	for _, r := range p.Rules {
		if _, err := path.Match(r.Pattern, "probe"); err != nil {
			return nil, fmt.Errorf("proxy: tool policy pattern %q: %w", r.Pattern, err)
		}
		if r.Class == "" {
			return nil, fmt.Errorf("proxy: tool policy pattern %q has no class", r.Pattern)
		}
	}
	// The digest covers the exact config bytes, not a re-serialization of
	// the parsed struct: the receipt must point at what the operator wrote.
	p.raw = append([]byte(nil), raw...)
	p.digest = cas.Digest(p.raw)
	return &p, nil
}

// Classify returns the risk class for a tool name and the argument name (if
// any) that supplies operation.target.
func (p *Policy) Classify(tool string) (class, targetArg string) {
	if r, ok := p.match(tool); ok {
		return r.Class, r.TargetArg
	}
	return p.Default, ""
}

// OutcomeFields returns the result fields the matching rule records in
// operation.outcome, or nil when the tool has no rule or the rule names
// none.
func (p *Policy) OutcomeFields(tool string) []string {
	if r, ok := p.match(tool); ok {
		return r.OutcomeFields
	}
	return nil
}

// match is the first-rule-wins lookup both accessors share, so a tool can
// never be classified by one rule and read back by another.
func (p *Policy) match(tool string) (Rule, bool) {
	for _, r := range p.Rules {
		if ok, err := path.Match(r.Pattern, tool); err == nil && ok {
			return r, true
		}
	}
	return Rule{}, false
}

// Digest is the sha256 of the config bytes, recorded on every receipt the
// policy classifies (Q6).
func (p *Policy) Digest() string { return p.digest }

// Source names where the policy came from, for diagnostics only.
func (p *Policy) Source() string { return p.source }
