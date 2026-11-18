package alerts

// subscriptions_test.go — the contract for the atomically published subscription
// index behind HasSubscriber (subscriptions.go).
//
// Two things are under test and they are different:
//
//  1. EQUIVALENCE. The index must answer exactly what the original locked scan
//     answered, for every hook set. hasSubscriberScan below is a verbatim copy of
//     the pre-change implementation, kept as a differential oracle: a change to
//     buildSubscriptions that drifts from it fails here rather than silently
//     unsubscribing a configured webhook. An alert that stops firing is a SILENT
//     failure — nothing in the product reports an alert nobody asked to skip —
//     so this equivalence is a security property, not a tidiness one.
//
//  2. ARMING. The fast path is only fast if it is actually published. A nil index
//     is handled by arming it, which is correct but is the SLOW path on first
//     use; if a production mutation stopped republishing, reads would keep
//     answering from a stale index instead, which is WRONG. So every path that
//     writes as.hooks is asserted to leave a published index that reflects the
//     write.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// hasSubscriberScan is the ORIGINAL HasSubscriber body, before the published
// index replaced it. Do not "simplify" it to call the new code — its whole value
// is being an independent second implementation.
func hasSubscriberScan(hooks []Webhook, event string) bool {
	for i := range hooks {
		if !hooks[i].Enabled {
			continue
		}
		for _, ev := range hooks[i].Events {
			if ev == event || ev == "*" {
				return true
			}
		}
	}
	return false
}

// subscriptionCases covers the shapes the scan distinguished: enabled/disabled,
// exact/catch-all/miss, multi-hook, multi-event, and the queries that probe the
// catch-all encoding itself (asking for "*" when no hook has it, and when one
// does — the one place a union-set rewrite could plausibly diverge).
var subscriptionCases = []struct {
	name  string
	hooks []Webhook
	event string
}{
	{"nil hooks", nil, "policy_block"},
	{"empty hooks", []Webhook{}, "policy_block"},
	{"exact match enabled", []Webhook{{Enabled: true, Events: []string{"policy_block"}}}, "policy_block"},
	{"exact match disabled", []Webhook{{Enabled: false, Events: []string{"policy_block"}}}, "policy_block"},
	{"catch-all enabled", []Webhook{{Enabled: true, Events: []string{catchAllEvent}}}, "policy_block"},
	{"catch-all disabled", []Webhook{{Enabled: false, Events: []string{catchAllEvent}}}, "policy_block"},
	{"different event only", []Webhook{{Enabled: true, Events: []string{"cert_expiry"}}}, "policy_block"},
	{"no events at all", []Webhook{{Enabled: true, Events: nil}}, "policy_block"},
	{"empty event name", []Webhook{{Enabled: true, Events: []string{""}}}, "policy_block"},
	{"query empty event", []Webhook{{Enabled: true, Events: []string{""}}}, ""},
	{"query star, no star hook", []Webhook{{Enabled: true, Events: []string{"policy_block"}}}, catchAllEvent},
	{"query star, star hook", []Webhook{{Enabled: true, Events: []string{catchAllEvent}}}, catchAllEvent},
	{"query star, disabled star hook", []Webhook{{Enabled: false, Events: []string{catchAllEvent}}}, catchAllEvent},
	{"one of several", []Webhook{
		{Enabled: true, Events: []string{"cert_expiry"}},
		{Enabled: false, Events: []string{catchAllEvent}},
		{Enabled: true, Events: []string{"threat_detected", "policy_block"}},
	}, "policy_block"},
	{"several, none match", []Webhook{
		{Enabled: true, Events: []string{"cert_expiry"}},
		{Enabled: true, Events: []string{"dns_failure", "scan_skipped"}},
	}, "policy_block"},
	{"duplicate events across hooks", []Webhook{
		{Enabled: true, Events: []string{"policy_block", "policy_block"}},
		{Enabled: true, Events: []string{"policy_block"}},
	}, "policy_block"},
}

// TestSubscriptionIndexMatchesScan is the differential oracle: the published
// index and the original locked scan must agree on every case.
func TestSubscriptionIndexMatchesScan(t *testing.T) {
	for _, tc := range subscriptionCases {
		t.Run(tc.name, func(t *testing.T) {
			want := hasSubscriberScan(tc.hooks, tc.event)

			// Unarmed: &Store{hooks: ...} is the construction several white-box
			// tests use, and it must answer identically on the FIRST call.
			unarmed := &Store{hooks: tc.hooks}
			if got := unarmed.HasSubscriber(tc.event); got != want {
				t.Errorf("unarmed HasSubscriber(%q) = %v, scan says %v", tc.event, got, want)
			}
			// ...and the call must have armed the index, so the second answer
			// comes from the fast path rather than re-deriving forever.
			if unarmed.subs.Load() == nil {
				t.Error("HasSubscriber did not arm the published index")
			}
			if got := unarmed.HasSubscriber(tc.event); got != want {
				t.Errorf("armed HasSubscriber(%q) = %v, scan says %v", tc.event, got, want)
			}

			// And directly against the built index, so a divergence is attributed
			// to buildSubscriptions rather than to the arming wrapper.
			if got := buildSubscriptions(tc.hooks).has(tc.event); got != want {
				t.Errorf("buildSubscriptions(...).has(%q) = %v, scan says %v", tc.event, got, want)
			}
		})
	}
}

// TestSubscriptionIndexEveryEventName sweeps each case against every event name
// mentioned anywhere in it, not just the one the case asks about. The table above
// pins the interesting queries; this makes a divergence on an unasked-for event
// impossible to miss.
func TestSubscriptionIndexEveryEventName(t *testing.T) {
	for _, tc := range subscriptionCases {
		idx := buildSubscriptions(tc.hooks)
		probes := []string{"policy_block", "threat_detected", catchAllEvent, "", "never_configured"}
		for _, h := range tc.hooks {
			probes = append(probes, h.Events...)
		}
		for _, ev := range probes {
			if got, want := idx.has(ev), hasSubscriberScan(tc.hooks, ev); got != want {
				t.Errorf("%s: has(%q) = %v, scan says %v", tc.name, ev, got, want)
			}
		}
	}
}

// TestSubscriptionIndexRepublishedOnMutation is the ARMING contract: Add, Update
// and Delete must each leave an index that reflects the write. A mutation that
// forgot to republish would leave HasSubscriber answering from the previous hook
// set — firing alerts for a deleted webhook, or staying silent for a new one.
func TestSubscriptionIndexRepublishedOnMutation(t *testing.T) {
	as := &Store{}
	as.Init(filepath.Join(t.TempDir(), "alerts.json"))

	if as.subs.Load() == nil {
		t.Fatal("Init left the index unpublished")
	}
	if as.HasSubscriber("policy_block") {
		t.Fatal("fresh store reports a subscriber")
	}

	// Add arms the new subscription.
	h := as.Add(Webhook{Name: "w", URL: "http://example.invalid", Enabled: true, Events: []string{"policy_block"}})
	if !as.HasSubscriber("policy_block") {
		t.Error("after Add, HasSubscriber(policy_block) = false — Add did not republish")
	}
	if as.HasSubscriber("cert_expiry") {
		t.Error("after Add, an unsubscribed event reports a subscriber")
	}

	// Update moves the subscription.
	if !as.Update(h.ID, Webhook{Name: "w", URL: "http://example.invalid", Enabled: true, Events: []string{"cert_expiry"}}) {
		t.Fatal("Update reported no match")
	}
	if as.HasSubscriber("policy_block") {
		t.Error("after Update, the OLD event still reports a subscriber — Update did not republish")
	}
	if !as.HasSubscriber("cert_expiry") {
		t.Error("after Update, the NEW event reports no subscriber")
	}

	// Disabling via Update must unsubscribe too (Enabled is part of the index).
	if !as.Update(h.ID, Webhook{Name: "w", URL: "http://example.invalid", Enabled: false, Events: []string{"cert_expiry"}}) {
		t.Fatal("Update reported no match")
	}
	if as.HasSubscriber("cert_expiry") {
		t.Error("after disabling, HasSubscriber = true — Enabled is not reflected in the index")
	}

	// Delete removes it.
	if !as.Update(h.ID, Webhook{Name: "w", URL: "http://example.invalid", Enabled: true, Events: []string{"cert_expiry"}}) {
		t.Fatal("Update reported no match")
	}
	if !as.Delete(h.ID) {
		t.Fatal("Delete reported no match")
	}
	if as.HasSubscriber("cert_expiry") {
		t.Error("after Delete, HasSubscriber = true — Delete did not republish")
	}
}

// TestSubscriptionIndexArmedByInitWithPersistedHooks covers the startup path: a
// store loading webhooks off disk must publish what it loaded, not an empty index.
func TestSubscriptionIndexArmedByInitWithPersistedHooks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.json")

	seed := &Store{}
	seed.Init(path)
	seed.Add(Webhook{Name: "w", URL: "http://example.invalid", Enabled: true, Events: []string{"threat_detected"}})

	reloaded := &Store{}
	reloaded.Init(path)
	if reloaded.subs.Load() == nil {
		t.Fatal("Init with persisted hooks left the index unpublished")
	}
	if !reloaded.HasSubscriber("threat_detected") {
		t.Error("reloaded store reports no subscriber for a persisted subscription")
	}
	if reloaded.HasSubscriber("policy_block") {
		t.Error("reloaded store reports a subscriber for an unsubscribed event")
	}
}

// TestSubscriptionIndexInitMalformedFileArms covers the Unmarshal-failure path,
// where json may have PARTIALLY written as.hooks. The deferred republish in Init
// must still run, or the index could describe a hook set that no longer exists.
func TestSubscriptionIndexInitMalformedFileArms(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "alerts.json")
	if err := os.WriteFile(path, []byte(`[{"name":"broken","enabled":true,`), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	as := &Store{}
	as.Init(path)
	if as.subs.Load() == nil {
		t.Error("Init over a malformed file left the index unpublished")
	}
	// Whatever survived the partial decode, the index must agree with a scan of it.
	as.mu.RLock()
	want := hasSubscriberScan(as.hooks, "policy_block")
	as.mu.RUnlock()
	if got := as.HasSubscriber("policy_block"); got != want {
		t.Errorf("HasSubscriber = %v, scan of the loaded hooks says %v", got, want)
	}
}

// TestSubscriptionIndexConcurrentReadsDuringMutation is the race/visibility
// check: readers hammer HasSubscriber while an operator churns the hook set. No
// reader may observe a torn index, and the final answer must reflect the final
// hook set. Meaningful under -race.
func TestSubscriptionIndexConcurrentReadsDuringMutation(t *testing.T) {
	as := &Store{}
	as.Init(filepath.Join(t.TempDir(), "alerts.json"))

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					as.HasSubscriber("policy_block")
					as.HasSubscriber(catchAllEvent)
				}
			}
		}()
	}
	for i := 0; i < 50; i++ {
		h := as.Add(Webhook{Name: "w", URL: "http://example.invalid", Enabled: true, Events: []string{"policy_block"}})
		as.Update(h.ID, Webhook{Name: "w", URL: "http://example.invalid", Enabled: true, Events: []string{"cert_expiry"}})
		as.Delete(h.ID)
	}
	close(stop)
	wg.Wait()

	if as.HasSubscriber("policy_block") || as.HasSubscriber("cert_expiry") {
		t.Error("after the churn settled, a removed subscription still reports a subscriber")
	}
}

// TestSubscriptionIndexArmRaces exercises armSubscriptions under concurrent first
// use: several goroutines reaching an unarmed store must all get the right answer
// and must converge on one published value.
func TestSubscriptionIndexArmRaces(t *testing.T) {
	as := &Store{hooks: []Webhook{{Enabled: true, Events: []string{"policy_block"}}}}
	var wg sync.WaitGroup
	got := make([]bool, 8)
	for i := range got {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			got[i] = as.HasSubscriber("policy_block")
		}(i)
	}
	wg.Wait()
	for i, g := range got {
		if !g {
			t.Errorf("goroutine %d got false, want true", i)
		}
	}
	if as.subs.Load() == nil {
		t.Error("index unpublished after concurrent arming")
	}
}
