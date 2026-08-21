package alerts

// store_eventname_migration_test.go — the anti-drift wall for retired alert
// event names (legacyEventNames / normalizeEventNames).
//
// The CHAOS-47 rename (idp_unreachable -> identity_backend_unreachable) shipped
// with the migration applied at ONE of the store's three ingresses — Init, the
// disk load. Add and Update, which serve the admin API and
// `POST /api/config/import`, wrote the retired name straight through, so a
// config exported before the rename and restored after it came back
// permanently unsubscribed from an alert that fires when proxy authentication
// is failing closed fleet-wide.
//
// That is a detection failure, and detection failures are the ones an operator
// cannot notice: the webhook row still shows in the admin UI, the alert simply
// never arrives. These tests pin normalization at EVERY ingress so the next
// rename cannot reintroduce the gap through the two ingresses that were missed.

import (
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// ── Positive: every ingress migrates ─────────────────────────────────────────

// TestNormalizeEventNames_MigratesAtAddIngress is the regression test for the
// gap: Add is what `POST /api/config/import` calls for every webhook in a
// restored backup.
func TestNormalizeEventNames_MigratesAtAddIngress(t *testing.T) {
	as := &Store{}
	added := as.Add(Webhook{
		Name:    "restored-from-pre-rename-export",
		URL:     "https://example.invalid/hook",
		Events:  []string{"threat_detected", "idp_unreachable"},
		Enabled: true,
	})

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("REGRESSION: a webhook Added under the retired idp_unreachable name did not " +
			"migrate — a pre-rename config export restored through /api/config/import comes " +
			"back permanently unsubscribed from the identity-backend outage alert")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("HasSubscriber still matches the retired event name after Add")
	}
	if !as.HasSubscriber("threat_detected") {
		t.Error("migration must not disturb an unrelated, already-current event name")
	}
	// The returned (display) copy must show the migrated name too, or the admin
	// UI renders a checkbox the backend will never match.
	if !containsEvent(added.Events, "identity_backend_unreachable") {
		t.Errorf("Add returned %v, want the migrated name so the UI checkbox matches", added.Events)
	}
}

// TestNormalizeEventNames_MigratesAtUpdateIngress covers operator automation
// that still sends the documented pre-rename name on its next apply.
func TestNormalizeEventNames_MigratesAtUpdateIngress(t *testing.T) {
	as := &Store{}
	added := as.Add(Webhook{
		Name:    "hook",
		URL:     "https://example.invalid/hook",
		Events:  []string{"identity_backend_unreachable"},
		Enabled: true,
	})

	if ok := as.Update(added.ID, Webhook{
		Name:    "hook",
		URL:     "https://example.invalid/hook",
		Events:  []string{"idp_unreachable"}, // stale client
		Enabled: true,
	}); !ok {
		t.Fatal("Update reported no such webhook")
	}

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("REGRESSION: an Update carrying the retired name silently unsubscribed the hook")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("HasSubscriber still matches the retired event name after Update")
	}
}

// TestNormalizeEventNames_MigratesAtInitIngress re-pins the ingress that was
// already covered, so all three live in one place and a future rename has one
// obvious table to extend.
func TestNormalizeEventNames_MigratesAtInitIngress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "alert_webhooks.json")
	legacy := `[{"id":"1","name":"pre-rename","url":"https://example.invalid/hook",` +
		`"events":["idp_unreachable"],"enabled":true}]`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatalf("seed legacy store file: %v", err)
	}

	as := &Store{}
	as.Init(path)

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("a webhook persisted under the retired name did not migrate on load")
	}
}

// ── Negative: the mapping must not widen, narrow, or invent ──────────────────

// TestNormalizeEventNames_LeavesCurrentNamesUntouched is the "never weaken"
// half: normalization is only allowed to carry a retired name forward. It must
// not reorder, drop, or add anything else.
func TestNormalizeEventNames_LeavesCurrentNamesUntouched(t *testing.T) {
	in := []string{"threat_detected", "policy_block", "*", "storage_write_failed"}
	got := normalizeEventNames(in)
	if len(got) != len(in) {
		t.Fatalf("normalizeEventNames(%v) = %v, want the input unchanged", in, got)
	}
	for i := range in {
		if got[i] != in[i] {
			t.Fatalf("normalizeEventNames(%v) = %v, want the input unchanged (order-preserving)", in, got)
		}
	}
}

// TestNormalizeEventNames_DoesNotSubscribeAnUnrelatedEvent proves the mapping
// is closed: an event name that is not a retired one is never rewritten into
// some other event, which would silently widen what the webhook receives.
func TestNormalizeEventNames_DoesNotSubscribeAnUnrelatedEvent(t *testing.T) {
	as := &Store{}
	as.Add(Webhook{
		Name:    "narrow",
		URL:     "https://example.invalid/hook",
		Events:  []string{"scan_skipped"},
		Enabled: true,
	})
	for _, ev := range []string{
		"identity_backend_unreachable", "threat_detected", "policy_block",
		"storage_write_failed", "idp_unreachable",
	} {
		if as.HasSubscriber(ev) {
			t.Errorf("normalization widened the subscription: hook subscribed only to "+
				"scan_skipped now matches %q", ev)
		}
	}
	if !as.HasSubscriber("scan_skipped") {
		t.Error("normalization narrowed the subscription: scan_skipped no longer matches")
	}
}

// TestNormalizeEventNames_WildcardIsNotRewritten guards the catch-all, which
// HasSubscriber and Dispatch both special-case.
func TestNormalizeEventNames_WildcardIsNotRewritten(t *testing.T) {
	as := &Store{}
	as.Add(Webhook{Name: "all", URL: "https://example.invalid/hook", Events: []string{"*"}, Enabled: true})
	if !as.HasSubscriber("anything_at_all") {
		t.Error("the wildcard subscription stopped matching after normalization")
	}
}

// TestNormalizeEventNames_DisabledHookStaysDisabled proves normalization does
// not resurrect delivery for a hook the operator turned off.
func TestNormalizeEventNames_DisabledHookStaysDisabled(t *testing.T) {
	as := &Store{}
	as.Add(Webhook{
		Name:    "off",
		URL:     "https://example.invalid/hook",
		Events:  []string{"idp_unreachable"},
		Enabled: false,
	})
	if as.HasSubscriber("identity_backend_unreachable") {
		t.Error("a DISABLED webhook must not become a subscriber through the rename migration")
	}
}

// ── Boundary / malformed input ───────────────────────────────────────────────

func TestNormalizeEventNames_Boundaries(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, []string{}},
		{"empty string is not an event name", []string{""}, []string{""}},
		{"case sensitive — a near miss is not migrated", []string{"IDP_Unreachable"}, []string{"IDP_Unreachable"}},
		{"substring is not migrated", []string{"idp_unreachable_v2"}, []string{"idp_unreachable_v2"}},
		{"whitespace is not trimmed into a match", []string{" idp_unreachable"}, []string{" idp_unreachable"}},
		{"both aliases collapse to one", []string{"idp_unreachable", "identity_backend_unreachable"}, []string{"identity_backend_unreachable"}},
		{"reverse order collapses the same way", []string{"identity_backend_unreachable", "idp_unreachable"}, []string{"identity_backend_unreachable"}},
		{"pre-existing duplicates collapse", []string{"threat_detected", "threat_detected"}, []string{"threat_detected"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := normalizeEventNames(c.in)
			if len(got) != len(c.want) {
				t.Fatalf("normalizeEventNames(%v) = %v, want %v", c.in, got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("normalizeEventNames(%v) = %v, want %v", c.in, got, c.want)
				}
			}
		})
	}
}

// TestNormalizeEventNames_Idempotent pins that re-running the migration over
// already-migrated state is a no-op. Init runs on every boot and Update runs on
// every edit, so a non-idempotent mapping would compound across restarts.
func TestNormalizeEventNames_Idempotent(t *testing.T) {
	in := []string{"idp_unreachable", "threat_detected"}
	once := normalizeEventNames(in)
	twice := normalizeEventNames(once)
	if len(once) != len(twice) {
		t.Fatalf("not idempotent: once=%v twice=%v", once, twice)
	}
	for i := range once {
		if once[i] != twice[i] {
			t.Fatalf("not idempotent: once=%v twice=%v", once, twice)
		}
	}
}

// TestNormalizeEventNames_DoesNotAliasCallerSlice proves normalization returns
// storage the caller does not share. Add/Update take a Webhook by value but the
// Events slice header is copied, so writing through it would mutate the
// caller's slice — in the import path, the decoded backup.
func TestNormalizeEventNames_DoesNotAliasCallerSlice(t *testing.T) {
	in := []string{"idp_unreachable"}
	got := normalizeEventNames(in)
	if in[0] != "idp_unreachable" {
		t.Errorf("normalizeEventNames mutated the caller's slice: %v", in)
	}
	if len(got) == 0 || got[0] != "identity_backend_unreachable" {
		t.Fatalf("normalizeEventNames(%v) = %v", in, got)
	}
}

// ── Concurrency ──────────────────────────────────────────────────────────────

// TestNormalizeEventNames_ConcurrentIngress runs the three ingresses against
// one store under -race. Normalization happens outside the store mutex (it
// works on the caller's value), so this pins that it introduces no shared
// state.
func TestNormalizeEventNames_ConcurrentIngress(t *testing.T) {
	as := &Store{}
	seed := as.Add(Webhook{
		Name: "seed", URL: "https://example.invalid/hook",
		Events: []string{"idp_unreachable"}, Enabled: true,
	})

	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			switch i % 3 {
			case 0:
				as.Add(Webhook{
					Name: "concurrent", URL: "https://example.invalid/hook",
					Events: []string{"idp_unreachable"}, Enabled: true,
				})
			case 1:
				as.Update(seed.ID, Webhook{
					Name: "seed", URL: "https://example.invalid/hook",
					Events: []string{"idp_unreachable"}, Enabled: true,
				})
			default:
				_ = as.HasSubscriber("identity_backend_unreachable")
			}
		}(i)
	}
	wg.Wait()

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("concurrent ingress lost the migrated subscription")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("concurrent ingress admitted the retired event name")
	}
	for _, h := range as.List() {
		if containsEvent(h.Events, "idp_unreachable") {
			t.Errorf("webhook %q retained the retired event name: %v", h.Name, h.Events)
		}
	}
}

// ── Catalog invariant ────────────────────────────────────────────────────────

// TestLegacyEventNames_MapForward pins the shape of the migration table: a
// retired name must not map to another retired name (which would need two
// passes) and must not map to itself (a no-op row that reads as coverage).
func TestLegacyEventNames_MapForward(t *testing.T) {
	for old, current := range legacyEventNames {
		if old == current {
			t.Errorf("legacyEventNames[%q] maps to itself — a no-op row that reads as coverage", old)
		}
		if _, chained := legacyEventNames[current]; chained {
			t.Errorf("legacyEventNames[%q] = %q, which is itself retired — normalizeEventNames "+
				"is single-pass, so a chained rename would leave the subscription on an "+
				"intermediate name that nothing dispatches", old, current)
		}
	}
}

func containsEvent(events []string, want string) bool {
	for _, ev := range events {
		if ev == want {
			return true
		}
	}
	return false
}
