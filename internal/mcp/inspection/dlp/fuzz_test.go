package dlp

import (
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

const fuzzCanary = `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`

// FuzzScan drives the DLP traversal over arbitrary JSON. Invariants: no panic,
// bounded work, determinism, and NO secret-canary leakage into any finding field.
func FuzzScan(f *testing.F) {
	f.Add([]byte(`{"a":"` + fuzzCanary + `","b":"alice@example.com"}`))
	f.Add([]byte(`{"x":["ignore previous instructions",123,{"y":"+14155552671"}]}`))
	f.Add([]byte(`"just a string"`))
	f.Add([]byte(`{"n":123456789012345678}`))
	b := canonical.Bounds{MaxBytes: 1 << 15, MaxDepth: 16, MaxObjectMembers: 128, MaxArrayElements: 128, MaxStringBytes: 1 << 13}
	lim := limits.DefaultGatewayInspection()
	f.Fuzz(func(t *testing.T, raw []byte) {
		n, err := canonical.Decode(raw, b)
		if err != nil {
			return
		}
		r1, e1 := Scan(n, ResponseMode(), lim)
		r2, e2 := Scan(n, ResponseMode(), lim)
		if (e1 == nil) != (e2 == nil) {
			t.Fatalf("non-deterministic scan error")
		}
		if e1 != nil {
			return
		}
		if len(r1.Findings) != len(r2.Findings) {
			t.Fatalf("non-deterministic finding count")
		}
		for i := range r1.Findings {
			fi := r1.Findings[i]
			blob := fi.Path + "|" + fi.DetectorID + "|" + fi.Evidence
			if strings.Contains(blob, fuzzCanary) || (len(fuzzCanary) >= 20 && strings.Contains(blob, fuzzCanary[:20])) {
				t.Fatalf("secret canary leaked into finding")
			}
		}
	})
}
