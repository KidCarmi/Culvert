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
// The benchmarks live in store_alertgate_bench_test.go; the permanent
// allocation contract is pinned by TestBenchGate_BlockPathAlertAllocs.

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ssrf"
)

// alertGateHarness installs a fresh, isolated alert store as the process-wide
// singleton and returns it alongside the channel that receiving endpoints
// signal on. Mirrors the swap-the-global idiom used by security_coverage_test.go.
func alertGateHarness(t *testing.T) (*AlertStore, chan string) {
	t.Helper()
	restore := ssrf.AllowLoopbackForTest()
	t.Cleanup(restore)

	orig := globalAlertStore
	t.Cleanup(func() { globalAlertStore = orig })
	as := &AlertStore{}
	as.Init("")
	globalAlertStore = as

	return as, make(chan string, 8)
}

// subscribe registers an enabled webhook for the given events pointed at a
// receiver that signals delivered.
func subscribe(t *testing.T, as *AlertStore, delivered chan string, events ...string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case delivered <- "fired":
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	as.Add(AlertWebhook{Name: "t", URL: srv.URL, Events: events, Enabled: true})
}

// awaitDelivery waits for (or for the absence of) a webhook delivery.
//
// The two waits are deliberately asymmetric. Proving a delivery DID happen gets
// a generous budget so the assertion never flakes on a loaded CI runner. Proving
// one did NOT happen only has to outlast a loopback round trip: if the gate were
// broken the goroutine would spawn immediately and deliver in microseconds, so a
// short budget is sufficient and keeps four negative cases from adding twelve
// seconds of pure sleep to every suite run.
func awaitDelivery(t *testing.T, ch chan string, want bool, what string) {
	t.Helper()
	budget := 500 * time.Millisecond
	if want {
		budget = 5 * time.Second
	}
	select {
	case <-ch:
		if !want {
			t.Fatalf("%s: alert was delivered but no subscriber matched — the gate must not invent deliveries", what)
		}
	case <-time.After(budget):
		if want {
			t.Fatalf("%s: no alert delivered within %s — the HasSubscriber gate SUPPRESSED an alert that had a live subscriber", what, budget)
		}
	}
}

// TestRecordStats_BlockAlertFiresWithSubscriber is the core anti-regression
// test: every status that produces an alert must still deliver it when a
// webhook subscribes to that event.
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
			as, delivered := alertGateHarness(t)
			subscribe(t, as, delivered, tc.event)
			// Detail is unique per subtest so the 30s dedup window never
			// suppresses a delivery this test is waiting on.
			recordStats("203.0.113.9", "gate-"+tc.status+".example.com", tc.status, "rule-"+tc.status, "block")
			awaitDelivery(t, delivered, true, tc.status)
		})
	}
}

// TestRecordStats_BlockAlertFiresForCatchAll pins that a "*" subscriber still
// receives block alerts — the gate asks HasSubscriber, which honours "*".
func TestRecordStats_BlockAlertFiresForCatchAll(t *testing.T) {
	as, delivered := alertGateHarness(t)
	subscribe(t, as, delivered, "*")
	recordStats("203.0.113.9", "catchall.example.com", "POLICY_BLOCK", "catchall-rule", "block")
	awaitDelivery(t, delivered, true, "catch-all subscriber")
}

// TestRecordStats_NoAlertWithoutSubscriber pins the skip itself: a disabled
// webhook and a webhook for an unrelated event must both leave the block path
// silent. This is the pre-change behaviour too (Dispatch filtered these out) —
// the gate just reaches the same answer without spawning a goroutine.
func TestRecordStats_NoAlertWithoutSubscriber(t *testing.T) {
	as, delivered := alertGateHarness(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case delivered <- "fired":
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	as.Add(AlertWebhook{Name: "disabled", URL: srv.URL, Events: []string{"policy_block"}, Enabled: false})
	as.Add(AlertWebhook{Name: "other", URL: srv.URL, Events: []string{"cert_expiry"}, Enabled: true})

	recordStats("203.0.113.9", "silent.example.com", "POLICY_BLOCK", "silent-rule", "block")
	awaitDelivery(t, delivered, false, "no matching subscriber")
}

// TestRecordStats_AllowPathNeverAlerts guards the switch itself: a normal
// allowed request must not reach an alert producer at all.
func TestRecordStats_AllowPathNeverAlerts(t *testing.T) {
	as, delivered := alertGateHarness(t)
	subscribe(t, as, delivered, "*")
	recordStats("203.0.113.9", "allowed.example.com", "OK", "allow-rule", "allow")
	awaitDelivery(t, delivered, false, "allow path")
}

// TestFireDNSFailureAlert_FiresWithSubscriber pins that consolidating the four
// inline dns_failure producers behind one gated helper did not silence them.
func TestFireDNSFailureAlert_FiresWithSubscriber(t *testing.T) {
	as, delivered := alertGateHarness(t)
	subscribe(t, as, delivered, "dns_failure")
	fireDNSFailureAlert("dns-fail.example.com", errTestDNS{})
	awaitDelivery(t, delivered, true, "dns_failure with subscriber")
}

// TestFireDNSFailureAlert_SilentWithoutSubscriber pins the skip.
func TestFireDNSFailureAlert_SilentWithoutSubscriber(t *testing.T) {
	as, delivered := alertGateHarness(t)
	as.Add(AlertWebhook{Name: "other", URL: "http://127.0.0.1:1", Events: []string{"policy_block"}, Enabled: true})
	fireDNSFailureAlert("dns-fail.example.com", errTestDNS{})
	awaitDelivery(t, delivered, false, "dns_failure without subscriber")
}

type errTestDNS struct{}

func (errTestDNS) Error() string { return "lookup dns-fail.example.com: no such host" }
