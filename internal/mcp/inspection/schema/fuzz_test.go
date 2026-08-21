package schema

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

// FuzzCompileValidate drives the schema compiler and validator with arbitrary
// bytes. Invariants: no panic, bounded work (the injected limits cap it),
// determinism (same input ⇒ same status), and an unsupported keyword never
// silently validates.
func FuzzCompileValidate(f *testing.F) {
	seeds := []string{
		`{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}`,
		`{"enum":[1,2,3]}`,
		`{"anyOf":[{"type":"string"},{"type":"integer"}]}`,
		`{"type":"string","format":"email","minLength":3}`,
		`{"oneOf":[{"type":"string"}]}`,
		`{"pattern":"^x$"}`,
		`{"type":"array","items":{"type":"integer"},"maxItems":3}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s), []byte(`{"a":"x"}`))
	}
	b := canonical.Bounds{MaxBytes: 1 << 14, MaxDepth: 16, MaxObjectMembers: 64, MaxArrayElements: 64, MaxStringBytes: 1 << 12}
	lim := limits.DefaultGatewayInspection()
	f.Fuzz(func(t *testing.T, schemaBytes, valueBytes []byte) {
		sn, err := canonical.Decode(schemaBytes, b)
		if err != nil {
			return
		}
		c1, e1 := Compile(sn, lim)
		c2, e2 := Compile(sn, lim)
		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("non-deterministic compile: %v vs %v", e1, e2)
		}
		if e1 != nil {
			return
		}
		vn, verr := canonical.Decode(valueBytes, b)
		if verr != nil {
			return
		}
		r1 := c1.Validate(vn)
		r2 := c2.Validate(vn)
		if r1.Status != r2.Status {
			t.Fatalf("non-deterministic validate: %v vs %v", r1.Status, r2.Status)
		}
		if r1.Status == StatusUnset {
			t.Fatal("validate returned StatusUnset (fail-closed violation)")
		}
	})
}
