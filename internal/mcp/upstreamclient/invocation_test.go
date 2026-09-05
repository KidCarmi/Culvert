package upstreamclient

import "testing"

// TestClassifyMethod_AdmittedSetIsPartitioned pins the exact classification of
// every admitted V1 method. Auxiliary lifecycle/discovery traffic must never be
// counted as a Canary tool effect merely because it is an HTTP POST (§4).
func TestClassifyMethod_AdmittedSetIsPartitioned(t *testing.T) {
	want := map[string]MethodClass{
		"initialize":                ClassLifecycle,
		"notifications/initialized": ClassLifecycle,
		"ping":                      ClassLifecycle,
		"notifications/cancelled":   ClassLifecycle,
		"tools/list":                ClassDiscovery,
		"tools/call":                ClassToolInvocation,
	}
	for m, w := range want {
		if got := ClassifyMethod(m); got != w {
			t.Errorf("ClassifyMethod(%q) = %v, want %v", m, got, w)
		}
		if !Admitted(m) {
			t.Errorf("%q must be in the admitted set for this partition to be complete", m)
		}
	}
}

// TestSideEffectBearing_OnlyToolCallConsumesBudget is the accounting contract:
// exactly one class may consume a Canary execution reservation.
func TestSideEffectBearing_OnlyToolCallConsumesBudget(t *testing.T) {
	if !ClassToolInvocation.SideEffectBearing() {
		t.Fatal("tools/call must be side-effect-bearing")
	}
	for _, c := range []MethodClass{ClassLifecycle, ClassDiscovery} {
		if c.SideEffectBearing() {
			t.Fatalf("%v must NOT consume the tool-execution budget", c)
		}
	}
}

// TestUnknownMethodFailsClosed pins the fail-closed direction: an unclassified
// method must never be cheaper than a classified one. Exemption is granted only to
// classes positively known to invoke no tool.
func TestUnknownMethodFailsClosed(t *testing.T) {
	if got := ClassifyMethod("tools/definitely-not-a-real-method"); got != ClassUnknown {
		t.Fatalf("unrecognized method must classify as ClassUnknown, got %v", got)
	}
	if !ClassUnknown.SideEffectBearing() {
		t.Fatal("ClassUnknown must be treated as side-effect-bearing (fail closed)")
	}
}
