package broker

import (
	"context"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/credentials/profile"
	"github.com/KidCarmi/Culvert/internal/mcp/credentials/provider"
)

func BenchmarkPlan(b *testing.B) {
	h := newHarness(b, provider.Capabilities{}, profile.PowerReadOnly)
	in := PlanInput{Identity: h.id, Profile: profID, Environment: "prod", Operation: profile.OpRead}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := h.broker.Plan(in); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaterializeCacheHit(b *testing.B) {
	get, _, _ := mutableClock()
	h, _ := brokerAt(b, get, profile.PowerReadOnly)
	plan := h.readPlan(b)
	// Warm the cache.
	if _, err := h.broker.Materialize(context.Background(), plan, permitGate(), noopCB); err != nil {
		b.Fatal(err)
	}
	gate := permitGate()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := h.broker.Materialize(context.Background(), plan, gate, noopCB); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMaterializeFetch(b *testing.B) {
	get, _, _ := mutableClock()
	h, _ := brokerAt(b, get, profile.PowerWrite) // high-risk always fetches
	plan := h.writePlan(b)
	gate := permitGate()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := h.broker.Materialize(context.Background(), plan, gate, noopCB); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParallelPlanReads(b *testing.B) {
	h := newHarness(b, provider.Capabilities{}, profile.PowerReadOnly)
	in := PlanInput{Identity: h.id, Profile: profID, Environment: "prod", Operation: profile.OpRead}
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := h.broker.Plan(in); err != nil {
				b.Fatal(err)
			}
		}
	})
}
