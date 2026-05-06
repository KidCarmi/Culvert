package main

// startup_slice_contract_test.go — pins the cross-slice convention for the
// 11 already-extracted startup slices that landed under the
// `<domain>_startup_config.go` + `<domain>_startup.go` pattern.
//
// Goal: when someone adds a 12th slice or refactors an existing one, this
// test surfaces drift early without requiring an AST walk. Three simple
// semantic invariants are pinned:
//
//   1. Each resolver tolerates a zero-value *FileConfig (or zero-value
//      scalar inputs) without panicking. Proves the resolver is pure
//      and side-effect-free with respect to startup globals.
//   2. Each resolver does not mutate its input *FileConfig in place.
//      A snapshot is taken before the call and compared after; any
//      drift fails the slice. Pinned because a resolver that mutates
//      fc could otherwise pass the determinism check on a shared
//      pointer (idempotent mutation produces identical outputs).
//   3. Each resolver is deterministic: same inputs → equal outputs.
//      Catches accidental introduction of map iteration order, time
//      reads, or hidden mutable state in resolution.
//
// Adding a new slice? Append a closure to the table below; the contract
// follows automatically.

import (
	"reflect"
	"testing"
)

// TestStartupSliceContract_PureAndDeterministic locks the three invariants
// described above for every extracted slice. If a future resolver gains
// a side effect (mutates fc, reads time, etc.), this test fails with a
// clear pointer at the offending slice.
func TestStartupSliceContract_PureAndDeterministic(t *testing.T) {
	cases := []struct {
		name string
		call func(fc *FileConfig) any
	}{
		{"fileblock", func(fc *FileConfig) any { return resolveFileBlockStartupConfig(fc, "") }},
		{"geoip", func(fc *FileConfig) any { return resolveGeoIPStartupConfig(fc, "") }},
		{"inspection_rules", func(fc *FileConfig) any { return resolveInspectionRulesConfig(fc) }},
		{"legacy_auth_providers", func(fc *FileConfig) any { return resolveLegacyAuthProvidersStartupConfig(fc, "") }},
		{"metrics_token", func(fc *FileConfig) any { return resolveMetricsTokenStartupConfig(fc, "") }},
		{"mtls_ocsp", func(fc *FileConfig) any { return resolveMTLSOCSPStartupConfig(fc) }},
		{"pac", func(_ *FileConfig) any { return resolvePACStartupConfig(0) }},
		{"rewrite_default_action", func(fc *FileConfig) any { return resolveRewriteDefaultActionStartupConfig(fc) }},
		{"session", func(fc *FileConfig) any { return resolveSessionStartupConfig(fc, "", 0) }},
		{"ui_access_policy", func(fc *FileConfig) any { return resolveUIAccessPolicyStartupConfig(fc, "") }},
		{"ui_extras", func(fc *FileConfig) any { return resolveUIExtrasStartupConfig(fc, "", false) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Fresh fc per subtest so a mutation by one resolver
			// cannot mask itself across slices.
			fc := &FileConfig{}
			before := *fc

			got1 := mustNotPanic(t, tc.name, func() any { return tc.call(fc) })
			if !reflect.DeepEqual(*fc, before) {
				t.Errorf("resolver %q mutated *FileConfig in place; resolvers must be pure", tc.name)
			}

			got2 := mustNotPanic(t, tc.name, func() any { return tc.call(fc) })
			if !reflect.DeepEqual(got1, got2) {
				t.Errorf("resolver %q is non-deterministic on identical inputs: %#v != %#v",
					tc.name, got1, got2)
			}
		})
	}
}

// mustNotPanic invokes fn under a recover and fails the test if the
// resolver panics. Returns the resolver's output for further assertions.
func mustNotPanic(t *testing.T, name string, fn func() any) (out any) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("resolver %q panicked on zero-value input: %v", name, r)
		}
	}()
	return fn()
}
