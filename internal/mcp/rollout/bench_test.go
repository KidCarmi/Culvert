package rollout

import "testing"

// BenchmarkScopeMatch measures the deterministic scope-membership check on the hot
// path (no I/O, no clock, no allocation in the match itself).
func BenchmarkScopeMatch(b *testing.B) {
	sc, _ := Compile(ScopeSpec{Capability: CapabilityGateway, Tenants: []string{"t1", "t2"}, Servers: []string{"s1"}, Percent: 50, BucketSalt: "salt"}, 1, DefaultLimits())
	subj := gwBenchSubject()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = sc.Contains(subj)
	}
}

// BenchmarkModeResolve measures the pure mode-resolution decision.
func BenchmarkModeResolve(b *testing.B) {
	in := ResolveInput{Mode: ModeCanary, InScope: true, Action: ActionKindAllow, ObligationsSatisfied: true}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Resolve(in)
	}
}

// BenchmarkStateResolveFor measures the lock-free state read + resolution.
func BenchmarkStateResolveFor(b *testing.B) {
	st := NewState(CapabilityGateway, DefaultLimits())
	_ = st.SetConfig(SignedConfig{SelectorSchema: selectorSchema, Capability: CapabilityGateway, Mode: ModeCanary, ScopeRevision: 1,
		Scope: ScopeSpec{Capability: CapabilityGateway, Servers: []string{"s1"}}, ConnectorMode: ConnectorLocalClient}, "a", 1)
	subj := gwBenchSubject()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = st.ResolveFor(subj, ActionKindAllow, false, 0, true)
	}
}

func gwBenchSubject() Subject {
	return Subject{Capability: CapabilityGateway, Tenant: "t1", ServerID: "s1", ToolName: "read", ToolFingerprint: "fp", PrincipalID: "p1", Operation: RiskRead}
}
