package alerts

import "testing"

// saveSink snapshots and restores the package-global sink so tests don't
// contaminate each other (the sink is process-global, publish-once in prod).
func saveSink(t *testing.T) {
	t.Helper()
	old := sink.Load()
	t.Cleanup(func() { sink.Store(old) })
}

func TestFire_NoSink_IsNoop(t *testing.T) {
	saveSink(t)
	sink.Store(nil)
	// Must not panic when no sink is installed.
	Fire("anything", Payload{Detail: "x"})
}

func TestSetSink_Fire_Delivers(t *testing.T) {
	saveSink(t)

	var gotEvent string
	var gotPayload Payload
	SetSink(func(event string, p Payload) {
		gotEvent = event
		gotPayload = p
	})

	Fire("threat_detected", Payload{Source: "yara", Detail: "rule-x", Host: "h"})

	if gotEvent != "threat_detected" {
		t.Errorf("event = %q, want threat_detected", gotEvent)
	}
	if gotPayload.Source != "yara" || gotPayload.Detail != "rule-x" || gotPayload.Host != "h" {
		t.Errorf("payload not delivered intact: %+v", gotPayload)
	}
}

func TestSetSink_ReplacesPrevious(t *testing.T) {
	saveSink(t)

	first := 0
	second := 0
	SetSink(func(string, Payload) { first++ })
	SetSink(func(string, Payload) { second++ }) // publish-once: last wins

	Fire("e", Payload{})
	if first != 0 {
		t.Errorf("first sink fired %d times, want 0 (replaced)", first)
	}
	if second != 1 {
		t.Errorf("second sink fired %d times, want 1", second)
	}
}

// ── HasEnabledHookFor (hot-path arm probe) ───────────────────────────────────

// TestHasEnabledHookFor_MatchesDispatchSemantics pins the probe to the exact
// match rule Dispatch applies (enabled + exact event or "*"): a divergence
// would either re-spawn no-op goroutines (probe too permissive) or drop real
// alerts (probe too strict).
func TestHasEnabledHookFor_MatchesDispatchSemantics(t *testing.T) {
	as := &Store{}
	as.Init("")

	if as.HasEnabledHookFor("policy_block") {
		t.Error("empty store: probe = true, want false")
	}

	as.Add(Webhook{Name: "disabled", URL: "http://example.com/a", Events: []string{"policy_block"}, Enabled: false})
	if as.HasEnabledHookFor("policy_block") {
		t.Error("disabled hook: probe = true, want false")
	}

	as.Add(Webhook{Name: "other-event", URL: "http://example.com/b", Events: []string{"cert_expiry"}, Enabled: true})
	if as.HasEnabledHookFor("policy_block") {
		t.Error("enabled hook for a different event: probe = true, want false")
	}

	as.Add(Webhook{Name: "no-events", URL: "http://example.com/c", Events: nil, Enabled: true})
	if as.HasEnabledHookFor("policy_block") {
		t.Error("enabled hook with no event subscriptions: probe = true, want false (Dispatch would match nothing)")
	}

	h := as.Add(Webhook{Name: "exact", URL: "http://example.com/d", Events: []string{"policy_block"}, Enabled: true})
	if !as.HasEnabledHookFor("policy_block") {
		t.Error("enabled exact-event hook: probe = false, want true")
	}
	if as.HasEnabledHookFor("threat_detected") {
		t.Error("exact-event hook must not arm other events")
	}

	as.Delete(h.ID)
	as.Add(Webhook{Name: "wildcard", URL: "http://example.com/e", Events: []string{"*"}, Enabled: true})
	if !as.HasEnabledHookFor("policy_block") || !as.HasEnabledHookFor("threat_detected") {
		t.Error("wildcard hook: probe = false, want true for every event")
	}
}

// TestHasEnabledHookFor_ZeroAlloc pins the probe's allocation-free contract —
// it runs per BLOCKED request on the proxy hot path, so an allocation here is
// a per-request allocation regression.
func TestHasEnabledHookFor_ZeroAlloc(t *testing.T) {
	empty := &Store{}
	empty.Init("")
	if allocs := testing.AllocsPerRun(1000, func() { empty.HasEnabledHookFor("policy_block") }); allocs != 0 {
		t.Errorf("empty-store probe allocates %.1f/op, want 0", allocs)
	}

	armed := &Store{}
	armed.Init("")
	armed.Add(Webhook{Name: "w", URL: "http://example.com/w", Events: []string{"*"}, Enabled: true})
	if allocs := testing.AllocsPerRun(1000, func() { armed.HasEnabledHookFor("policy_block") }); allocs != 0 {
		t.Errorf("armed-store probe allocates %.1f/op, want 0", allocs)
	}
}
