package alerts

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Alert-event rename migration (CHAOS-47 / T-40: idp_unreachable ->
// identity_backend_unreachable).
//
// The regression these pin is a DETECTION failure, not a bypass: HasSubscriber
// and Dispatch compare event names byte-for-byte, so a webhook left on the
// retired name is never delivered to. The alert in question fires when the
// external identity backend is unreachable and proxy authentication is failing
// closed — i.e. during a full egress outage — so losing the subscription costs
// the operator exactly the page they configured it for.
//
// Migrating on load alone is not enough. Two supported paths put an Events list
// into the store WITHOUT going through Init:
//
//  1. config import (ui_config.go -> globalAlertStore.Add), replaying a backup
//     exported from a pre-rename build;
//  2. POST/PUT /api/alerts/webhooks, which applies no event-name allowlist, so
//     operator automation written before the rename keeps sending the old name.
//
// Both are covered here alongside the load path.

func hasEvent(h Webhook, event string) bool {
	for _, ev := range h.Events {
		if ev == event {
			return true
		}
	}
	return false
}

// TestStore_Add_MigratesLegacyEventNames is the config-import / operator-API
// regression: a webhook admitted through Add under the retired name must be
// subscribed to the current one.
func TestStore_Add_MigratesLegacyEventNames(t *testing.T) {
	as := &Store{}
	created := as.Add(Webhook{
		Name:    "imported-from-pre-rename-backup",
		URL:     "https://example.invalid/hook",
		Events:  []string{"threat_detected", "idp_unreachable"},
		Enabled: true,
	})

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("webhook added under the retired idp_unreachable name is not subscribed to identity_backend_unreachable — the alert would never be delivered")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("HasSubscriber still matches the retired event name after Add")
	}
	if !as.HasSubscriber("threat_detected") {
		t.Error("migration disturbed an unrelated, already-current event name")
	}
	// The returned copy is what the API echoes to the admin UI, whose checkbox
	// is keyed on the current name: if it still said idp_unreachable the box
	// would render unchecked for a hook that IS subscribed.
	if !hasEvent(created, "identity_backend_unreachable") || hasEvent(created, "idp_unreachable") {
		t.Errorf("returned webhook must carry the migrated event list, got %v", created.Events)
	}
}

// TestStore_Update_MigratesLegacyEventNames covers PUT /api/alerts/webhooks,
// which replaces the whole Events list.
func TestStore_Update_MigratesLegacyEventNames(t *testing.T) {
	as := &Store{}
	created := as.Add(Webhook{
		Name:    "hook",
		URL:     "https://example.invalid/hook",
		Events:  []string{"threat_detected"},
		Enabled: true,
	})

	if !as.Update(created.ID, Webhook{
		Name:    "hook",
		URL:     "https://example.invalid/hook",
		Events:  []string{"idp_unreachable"},
		Enabled: true,
	}) {
		t.Fatal("Update reported not found")
	}

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("webhook updated to the retired idp_unreachable name is not subscribed to identity_backend_unreachable")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("HasSubscriber still matches the retired event name after Update")
	}
}

// TestStore_Add_LegacyMigrationDedupes pins the collision case: a list carrying
// BOTH the retired and the current name must not end up with the current name
// twice, or the admin UI round-trips a duplicate on every save.
func TestStore_Add_LegacyMigrationDedupes(t *testing.T) {
	as := &Store{}
	created := as.Add(Webhook{
		URL:     "https://example.invalid/hook",
		Events:  []string{"idp_unreachable", "identity_backend_unreachable", "threat_detected"},
		Enabled: true,
	})

	want := []string{"identity_backend_unreachable", "threat_detected"}
	if len(created.Events) != len(want) {
		t.Fatalf("events = %v, want %v (rewrite must not duplicate the current name)", created.Events, want)
	}
	for i := range want {
		if created.Events[i] != want[i] {
			t.Fatalf("events = %v, want %v (order must be preserved)", created.Events, want)
		}
	}
}

// TestStore_Add_LeavesCurrentEventListUntouched is the negative test: a list
// with nothing to migrate must be stored verbatim. In particular the
// de-duplication is deliberately scoped to lists the rewrite touched, so an
// operator list is never silently reshaped.
func TestStore_Add_LeavesCurrentEventListUntouched(t *testing.T) {
	as := &Store{}
	created := as.Add(Webhook{
		URL:     "https://example.invalid/hook",
		Events:  []string{"threat_detected", "threat_detected", "*"},
		Enabled: true,
	})

	want := []string{"threat_detected", "threat_detected", "*"}
	if len(created.Events) != len(want) {
		t.Fatalf("events = %v, want %v verbatim", created.Events, want)
	}
	for i := range want {
		if created.Events[i] != want[i] {
			t.Fatalf("events = %v, want %v verbatim", created.Events, want)
		}
	}
	if !as.HasSubscriber("threat_detected") {
		t.Error("unrelated event name lost its subscription")
	}
}

// TestNormalizeLegacyEvents_Boundaries covers the empty / nil / unknown-name
// inputs an API caller can submit. A malformed or absent list must be a no-op,
// never a panic and never an invented subscription.
func TestNormalizeLegacyEvents_Boundaries(t *testing.T) {
	if got := normalizeLegacyEvents(nil); got != nil {
		t.Errorf("nil events = %v, want nil (must not allocate or invent a list)", got)
	}
	if got := normalizeLegacyEvents([]string{}); len(got) != 0 {
		t.Errorf("empty events = %v, want empty", got)
	}
	// An unknown / attacker-supplied name is not a legacy name: pass through,
	// do not map it onto a real event.
	in := []string{"", "not_an_event", "identity_backend_unreachable"}
	got := normalizeLegacyEvents(in)
	if len(got) != len(in) {
		t.Fatalf("unknown names = %v, want %v verbatim", got, in)
	}
	for i := range in {
		if got[i] != in[i] {
			t.Fatalf("unknown names = %v, want %v verbatim", got, in)
		}
	}
}

// TestStore_LegacyMigration_ConcurrentAddDispatch runs the migration under the
// race detector against concurrent readers. Add rewrites h.Events on a copy
// before taking as.mu; HasSubscriber and Dispatch read the stored slice under
// the lock. This pins that no reader ever observes a half-rewritten list.
func TestStore_LegacyMigration_ConcurrentAddDispatch(t *testing.T) {
	as := &Store{}
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			as.Add(Webhook{
				URL:     "https://example.invalid/hook",
				Events:  []string{"idp_unreachable", "threat_detected"},
				Enabled: true,
			})
		}()
		go func() {
			defer wg.Done()
			_ = as.HasSubscriber("identity_backend_unreachable")
			_ = as.List()
		}()
	}
	wg.Wait()

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("concurrent Add lost the migrated subscription")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("concurrent Add left a hook on the retired event name")
	}
}

// TestStore_LegacyMigration_SurvivesPersistRoundTrip proves the migrated name
// is what reaches disk, so the fix holds across a restart rather than being
// re-applied from a stale file forever.
func TestStore_LegacyMigration_SurvivesPersistRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_webhooks.json")

	as := &Store{}
	as.Init(path)
	as.Add(Webhook{
		Name:    "hook",
		URL:     "https://example.invalid/hook",
		Events:  []string{"idp_unreachable"},
		Enabled: true,
	})

	// Assert on the BYTES, not on a reloaded Store: Init re-migrates on load,
	// so a reloaded store looks correct even when the retired name is what
	// actually reached disk. Only the file distinguishes "migrated on the way
	// in" from "migrated again on the way out" every restart.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read persisted store: %v", err)
	}
	if strings.Contains(string(raw), "idp_unreachable") {
		t.Errorf("retired event name was persisted to disk: %s", raw)
	}
	if !strings.Contains(string(raw), "identity_backend_unreachable") {
		t.Errorf("migrated event name did not reach disk: %s", raw)
	}

	reloaded := &Store{}
	reloaded.Init(path)
	if !reloaded.HasSubscriber("identity_backend_unreachable") {
		t.Error("migrated subscription did not survive persist + reload")
	}
}
