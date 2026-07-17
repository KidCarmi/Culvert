package main

// Allocation-free IdP capability probes (perf: per-request auth hot path).
//
// resolveRequestAuth (proxy.go) evaluates two capability booleans on EVERY
// proxied request:
//
//   - credCapable → hasCredentialCapableProvider (diagnostics.go), which
//     previously scanned idpRegistry.All() — a DEEP CLONE of every profile
//     (struct + EmailDomains/KnownGroups/Scopes slices + OIDC/SAML
//     sub-structs) per call.
//   - ssoCapable → previously len(idpRegistry.EnabledProviders()) > 0, which
//     builds a fresh provider slice per call whenever any provider is enabled.
//
// For an IdP-only SSO deployment (no local bcrypt user, no legacy provider —
// the enterprise configuration) both costs land on every request. The
// HasEnabledProviders / HasEnabledOIDC probes answer the same predicates with
// a read-only scan under RLock: zero allocations, no cloning.
//
// This file pins parity (the probes agree with the accessor-based predicates
// they replaced across registry states) and provides the before/after
// benchmarks. The hard allocation gate lives in bench_regression_test.go
// (TestBenchGate_AuthCapabilityProbeAllocs, -tags benchgate).
//
// Run locally:
//   go test -run TestIdPCapabilityProbe .
//   go test -run '^$' -bench BenchmarkIdPProbe -benchmem .

import (
	"fmt"
	"testing"
)

// buildProbeRegistry returns a registry with n profiles alternating
// SAML/OIDC. enabled controls the Enabled flag on every profile; live
// controls whether each profile gets a compiled provider instance (the
// testProxyIdentityProvider stub from proxy_test.go).
func buildProbeRegistry(n int, enabled, live bool) *IdPRegistry {
	r := &IdPRegistry{live: make(map[string]IdentityProvider)}
	for i := 0; i < n; i++ {
		p := &IdPProfile{
			ID:           fmt.Sprintf("idp-%d", i),
			Name:         fmt.Sprintf("IdP %d", i),
			Type:         IdPTypeSAML,
			Enabled:      enabled,
			EmailDomains: []string{fmt.Sprintf("corp%d.example", i)},
			KnownGroups:  []string{"eng", "ops"},
			SAML:         &SAMLProfileConfig{MetadataXML: "<xml/>"},
		}
		if i%2 == 1 {
			p.Type = IdPTypeOIDC
			p.SAML = nil
			p.OIDC = &OIDCProfileConfig{Issuer: fmt.Sprintf("https://idp%d.example", i), Scopes: []string{"openid", "profile"}}
		}
		r.profiles = append(r.profiles, p)
		if live {
			r.live[p.ID] = &testProxyIdentityProvider{}
		}
	}
	return r
}

// legacySSOCapable is the pre-optimization ssoCapable predicate shape
// (proxy.go): materialize the enabled-provider slice, test emptiness.
func legacySSOCapable(r *IdPRegistry) bool { return len(r.EnabledProviders()) > 0 }

// legacyOIDCCapable is the pre-optimization credential-capable registry scan
// (diagnostics.go): deep-clone all profiles via All(), then test each.
func legacyOIDCCapable(r *IdPRegistry) bool {
	for _, p := range r.All() {
		if p != nil && p.Enabled && p.Type == IdPTypeOIDC {
			return true
		}
	}
	return false
}

// TestIdPCapabilityProbe_Parity proves the allocation-free probes agree with
// the accessor-based predicates they replaced, across the registry states
// that matter: empty, disabled, enabled-without-live, enabled-with-live, and
// a nil-profile entry (defensive — cloneIdPProfiles preserves nils).
func TestIdPCapabilityProbe_Parity(t *testing.T) {
	cases := []struct {
		name string
		reg  *IdPRegistry
	}{
		{"empty", buildProbeRegistry(0, false, false)},
		{"disabled", buildProbeRegistry(4, false, true)},
		{"enabled_no_live", buildProbeRegistry(4, true, false)},
		{"enabled_live", buildProbeRegistry(4, true, true)},
		{"single_saml_live", buildProbeRegistry(1, true, true)}, // even index ⇒ SAML only
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got, want := tc.reg.HasEnabledProviders(), legacySSOCapable(tc.reg); got != want {
				t.Errorf("HasEnabledProviders() = %v, want %v (len(EnabledProviders())>0 parity)", got, want)
			}
			if got, want := tc.reg.HasEnabledOIDC(), legacyOIDCCapable(tc.reg); got != want {
				t.Errorf("HasEnabledOIDC() = %v, want %v (All()-scan parity)", got, want)
			}
		})
	}

	// Defensive: a nil profile entry must not panic the probes (the legacy
	// All()-scan tolerated nils; EnabledProviders would panic, so the SSO
	// parity check is skipped for this shape).
	nilReg := buildProbeRegistry(2, true, true)
	nilReg.profiles = append(nilReg.profiles, nil)
	if !nilReg.HasEnabledProviders() {
		t.Error("HasEnabledProviders() = false with an enabled live profile present")
	}
	if !nilReg.HasEnabledOIDC() {
		t.Error("HasEnabledOIDC() = false with an enabled OIDC profile present")
	}
}

// ── Benchmarks: before vs after ─────────────────────────────────────────────
// The registry size sweep (1/4/16) brackets realistic IdP counts; 4 is the
// typical multi-IdP enterprise shape. The legacy variants are benchmarked
// through the same accessors production used, so the delta is exactly what
// the per-request hot path stopped paying.

func BenchmarkIdPProbe_HasEnabledProviders(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		r := buildProbeRegistry(n, true, true)
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !r.HasEnabledProviders() {
					b.Fatal("want true")
				}
			}
		})
	}
}

func BenchmarkIdPProbe_LegacyEnabledProvidersLen(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		r := buildProbeRegistry(n, true, true)
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if !legacySSOCapable(r) {
					b.Fatal("want true")
				}
			}
		})
	}
}

func BenchmarkIdPProbe_HasEnabledOIDC(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		r := buildProbeRegistry(n, true, true)
		want := n > 1 // odd indices are OIDC; n=1 is SAML-only
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if r.HasEnabledOIDC() != want {
					b.Fatal("unexpected probe result")
				}
			}
		})
	}
}

func BenchmarkIdPProbe_LegacyAllScanOIDC(b *testing.B) {
	for _, n := range []int{1, 4, 16} {
		r := buildProbeRegistry(n, true, true)
		want := n > 1
		b.Run(fmt.Sprintf("profiles=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if legacyOIDCCapable(r) != want {
					b.Fatal("unexpected probe result")
				}
			}
		})
	}
}

// BenchmarkIdPProbe_Concurrent exercises both probes under parallelism —
// the shape resolveRequestAuth produces at load. RLock is shared, so this
// should scale with cores rather than serialize.
func BenchmarkIdPProbe_Concurrent(b *testing.B) {
	r := buildProbeRegistry(4, true, true)
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if !r.HasEnabledProviders() || !r.HasEnabledOIDC() {
				b.Fatal("want true")
			}
		}
	})
}
