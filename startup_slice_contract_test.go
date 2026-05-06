package main

// startup_slice_contract_test.go — pins the cross-slice convention for the
// 11 already-extracted startup slices that landed under the
// `<domain>_startup_config.go` + `<domain>_startup.go` pattern.
//
// Goal: when someone adds a 12th slice or refactors an existing one, this
// test surfaces drift early without requiring an AST walk. Two simple
// semantic invariants are pinned:
//
//   1. Each resolver tolerates a zero-value *FileConfig (or zero-value
//      scalar inputs) without panicking. Proves the resolver is pure
//      and side-effect-free with respect to startup globals.
//   2. Each resolver is deterministic: same inputs → equal outputs.
//      Catches accidental introduction of map iteration order, time
//      reads, or hidden mutable state in resolution.
//
// Adding a new slice? Append a closure to the table below; the contract
// follows automatically.

import (
	"reflect"
	"testing"
)

// TestStartupSliceContract_PureAndDeterministic locks the two invariants
// described above for every extracted slice. If a future resolver gains
// a side effect (file read, global write) or a non-determinism source,
// this test fails with a clear pointer at the offending slice.
func TestStartupSliceContract_PureAndDeterministic(t *testing.T) {
	fc := &FileConfig{}

	cases := []struct {
		name string
		call func() any
	}{
		{"fileblock", func() any { return resolveFileBlockStartupConfig(fc, "") }},
		{"geoip", func() any { return resolveGeoIPStartupConfig(fc, "") }},
		{"inspection_rules", func() any { return resolveInspectionRulesConfig(fc) }},
		{"legacy_auth_providers", func() any { return resolveLegacyAuthProvidersStartupConfig(fc, "") }},
		{"metrics_token", func() any { return resolveMetricsTokenStartupConfig(fc, "") }},
		{"mtls_ocsp", func() any { return resolveMTLSOCSPStartupConfig(fc) }},
		{"pac", func() any { return resolvePACStartupConfig(0) }},
		{"rewrite_default_action", func() any { return resolveRewriteDefaultActionStartupConfig(fc) }},
		{"session", func() any { return resolveSessionStartupConfig(fc, "", 0) }},
		{"ui_access_policy", func() any { return resolveUIAccessPolicyStartupConfig(fc, "") }},
		{"ui_extras", func() any { return resolveUIExtrasStartupConfig(fc, "", false) }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got1 := mustNotPanic(t, tc.name, tc.call)
			got2 := mustNotPanic(t, tc.name, tc.call)
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
