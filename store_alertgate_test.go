package main

// store_alertgate_test.go — the per-request alert-producer gate.
//
// recordStats (the block path) and fireDNSFailureAlert (the four per-request
// dial sites) consult HasSubscriber before spawning a delivery goroutine. The
// optimization is only sound if the gate is invisible whenever a webhook IS
// listening, so the correctness tests here are the load-bearing half of the
// change: a gate that silently swallowed a policy_block or threat_detected
// alert would be a security-observability regression, not a speed-up.
//
// These tests assert on the DISPATCH DECISION (did the producer call fireAlert
// for the right event?) rather than on webhook HTTP delivery. Delivery is the
// alerts engine's contract and is covered by internal/alerts and
// security_coverage_test.go; asserting on it here would couple this suite to
// internal/alerts' package-global delivery semaphore (cap 10, shared by every
// test in the binary). When unrelated tests saturate those slots, Dispatch
// diverts the payload to the retry queue and a delivery-based assertion fails
// — reporting "the alert was suppressed" when the producer behaved correctly.
// That was a real, reproducible flake in the first version of this file.
//
// The benchmarks live in store_alertgate_bench_test.go; the permanent
// allocation contract is pinned by TestBenchGate_BlockPathAlertAllocs.

import (
	"testing"
	"time"
)

// alertGateHarness installs a fresh, isolated alert store as the process-wide
// singleton plus a seam that records dispatched event names, and returns both.
// The webhook URLs registered by tests are never contacted — the seam
// intercepts before delivery — so they can be unroutable.
func alertGateHarness(t *testing.T) (store *AlertStore, dispatched chan string) {
	t.Helper()

	origStore := globalAlertStore
	origFire := fireAlert
	t.Cleanup(func() {
		globalAlertStore = origStore
		fireAlert = origFire
	})

	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	events := make(chan string, 8)
	fireAlert = func(event string, payload AlertPayload) {
		select {
		case events <- event:
		default:
		}
	}
	return as, events
}

// subscribe registers an enabled webhook for the given events.
func subscribe(t *testing.T, as *AlertStore, events ...string) {
	t.Helper()
	as.Add(AlertWebhook{Name: "t", URL: "http://127.0.0.1:1", Events: events, Enabled: true})
}

// awaitDispatch waits for (or for the absence of) an alert dispatch.
//
// The two waits are asymmetric. Proving a dispatch DID happen gets a generous
// budget so it never flakes on a loaded runner; proving one did NOT happen only
// has to outlast a goroutine start, since the producers dispatch via `go
// fireAlert(...)` with nothing in between.
func awaitDispatch(t *testing.T, ch chan string, wantEvent string, what string) {
	t.Helper()
	if wantEvent == "" {
		select {
		case got := <-ch:
			t.Fatalf("%s: dispatched %q but no subscriber matched — the gate must not invent alerts", what, got)
		case <-time.After(250 * time.Millisecond):
		}
		return
	}
	select {
	case got := <-ch:
		if got != wantEvent {
			t.Fatalf("%s: dispatched event %q, want %q", what, got, wantEvent)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: no alert dispatched within 5s — the HasSubscriber gate SUPPRESSED an alert that had a live subscriber", what)
	}
}

// TestRecordStats_BlockAlertFiresWithSubscriber is the core anti-regression
// test: every status that produces an alert must still dispatch it, for the
// right event, when a webhook subscribes to that event.
func TestRecordStats_BlockAlertFiresWithSubscriber(t *testing.T) {
	cases := []struct {
		status string
		event  string
	}{
		{"THREAT_BLOCKED", "threat_detected"},
		{"SCAN_BLOCKED", "threat_detected"},
		{"DPI_BLOCKED", "threat_detected"},
		{"POLICY_BLOCK", "policy_block"},
		{"POLICY_DROP", "policy_block"},
	}
	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			as, dispatched := alertGateHarness(t)
			subscribe(t, as, tc.event)
			recordStats("203.0.113.9", "gate-"+tc.status+".example.com", tc.status, "rule-"+tc.status, "block")
			awaitDispatch(t, dispatched, tc.event, tc.status)
		})
	}
}

// TestRecordStats_BlockAlertFiresForCatchAll pins that a "*" subscriber still
// receives block alerts — the gate asks HasSubscriber, which honours "*".
func TestRecordStats_BlockAlertFiresForCatchAll(t *testing.T) {
	as, dispatched := alertGateHarness(t)
	subscribe(t, as, "*")
	recordStats("203.0.113.9", "catchall.example.com", "POLICY_BLOCK", "catchall-rule", "block")
	awaitDispatch(t, dispatched, "policy_block", "catch-all subscriber")
}

// TestRecordStats_NoAlertWithoutSubscriber pins the skip itself: a disabled
// webhook and a webhook for an unrelated event must both leave the block path
// silent. This is the pre-change behaviour too (Dispatch filtered these out) —
// the gate just reaches the same answer without spawning a goroutine.
func TestRecordStats_NoAlertWithoutSubscriber(t *testing.T) {
	as, dispatched := alertGateHarness(t)
	as.Add(AlertWebhook{Name: "disabled", URL: "http://127.0.0.1:1", Events: []string{"policy_block"}, Enabled: false})
	as.Add(AlertWebhook{Name: "other", URL: "http://127.0.0.1:1", Events: []string{"cert_expiry"}, Enabled: true})

	recordStats("203.0.113.9", "silent.example.com", "POLICY_BLOCK", "silent-rule", "block")
	awaitDispatch(t, dispatched, "", "no matching subscriber")
}

// TestRecordStats_AllowPathNeverAlerts guards the switch itself: a normal
// allowed request must not reach an alert producer at all.
func TestRecordStats_AllowPathNeverAlerts(t *testing.T) {
	as, dispatched := alertGateHarness(t)
	subscribe(t, as, "*")
	recordStats("203.0.113.9", "allowed.example.com", "OK", "allow-rule", "allow")
	awaitDispatch(t, dispatched, "", "allow path")
}

// TestFireDNSFailureAlert_FiresWithSubscriber pins that consolidating the four
// inline dns_failure producers behind one gated helper did not silence them.
func TestFireDNSFailureAlert_FiresWithSubscriber(t *testing.T) {
	as, dispatched := alertGateHarness(t)
	subscribe(t, as, "dns_failure")
	fireDNSFailureAlert("dns-fail.example.com", errTestDNS{})
	awaitDispatch(t, dispatched, "dns_failure", "dns_failure with subscriber")
}

// TestFireDNSFailureAlert_SilentWithoutSubscriber pins the skip.
func TestFireDNSFailureAlert_SilentWithoutSubscriber(t *testing.T) {
	as, dispatched := alertGateHarness(t)
	subscribe(t, as, "policy_block") // a subscriber, but not for dns_failure
	fireDNSFailureAlert("dns-fail.example.com", errTestDNS{})
	awaitDispatch(t, dispatched, "", "dns_failure without subscriber")
}

type errTestDNS struct{}

func (errTestDNS) Error() string { return "lookup dns-fail.example.com: no such host" }
