package rollout

import (
	"encoding/json"
	"testing"
)

// FuzzSignedConfigDecode fuzzes JSON decoding + validation of a SignedConfig. It
// must never panic; any malformed/hostile input is a classified rejection or a
// safe compile, never a crash.
func FuzzSignedConfigDecode(f *testing.F) {
	f.Add([]byte(`{"selector_schema":1,"capability":1,"mode":2,"scope":{"capability":1,"servers":["s1"]},"scope_revision":1,"connector_mode":"local-client"}`))
	f.Add([]byte(`{"selector_schema":99,"capability":1,"mode":4,"scope":{"capability":1,"percent":1}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"connector_mode":"dmz-endpoint"}`))
	lim := DefaultLimits()
	f.Fuzz(func(t *testing.T, raw []byte) {
		var cfg SignedConfig
		if err := json.Unmarshal(raw, &cfg); err != nil {
			return
		}
		// Validation must never panic and must fail closed for either capability.
		_ = cfg.Validate(CapabilityGateway, lim)
		_ = cfg.Validate(CapabilityManagement, lim)
		if sc, err := cfg.CompileScope(lim); err == nil {
			// A compiled scope must never match a subject of the other capability.
			other := CapabilityManagement
			if cfg.Capability == CapabilityManagement {
				other = CapabilityGateway
			}
			if sc.Contains(Subject{Capability: other, Operation: RiskRead}) {
				t.Fatal("scope matched a cross-capability subject")
			}
		}
	})
}

// FuzzStableBucket ensures the percentage bucket never panics and stays in range
// for arbitrary salt/key bytes.
func FuzzStableBucket(f *testing.F) {
	f.Add("salt", "key")
	f.Add("", "")
	f.Fuzz(func(t *testing.T, salt, key string) {
		b := StableBucket(salt, key)
		if b >= 100 {
			t.Fatalf("bucket %d out of range", b)
		}
		if StableBucket(salt, key) != b {
			t.Fatal("bucket not deterministic")
		}
	})
}
