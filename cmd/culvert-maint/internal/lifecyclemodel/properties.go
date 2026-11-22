//go:build lifecycle_conformance

package lifecyclemodel

import (
	"crypto/sha256"
	_ "embed" // properties.json is compiled in
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// propertiesJSON is the property file. It stays JSON so the owner can change a
// property's status without touching code. Nothing in this package writes it.
//
//go:embed properties.json
var propertiesJSON []byte

// EmbeddedPropertiesJSON returns the raw property file compiled into the binary.
func EmbeddedPropertiesJSON() []byte { return propertiesJSON }

// EmbeddedProperties returns the properties compiled into the binary and the
// SHA-256 of the file they were read from.
func EmbeddedProperties() (props []Property, sha string, err error) {
	return ParseProperties(propertiesJSON)
}

// ParseProperties decodes a property file. An unknown status is an error: a property
// that would silently not be evaluated must never look like a pass.
func ParseProperties(raw []byte) (props []Property, sha string, err error) {
	sum := sha256.Sum256(raw)
	sha = hex.EncodeToString(sum[:])
	if err := json.Unmarshal(raw, &props); err != nil {
		return nil, sha, fmt.Errorf("parse properties: %w", err)
	}
	seen := map[string]bool{}
	for i := range props {
		p := &props[i]
		if p.ID == "" || seen[p.ID] {
			return nil, sha, fmt.Errorf("property #%d: missing or duplicate id %q", i, p.ID)
		}
		seen[p.ID] = true
		switch p.Status {
		case StatusProposed, StatusOpen, StatusApproved:
		default:
			return nil, sha, fmt.Errorf("property %s: unknown status %q", p.ID, p.Status)
		}
	}
	return props, sha, nil
}
