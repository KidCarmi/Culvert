package main

// alerts_event_rename_import_test.go — end-to-end proof, through the real
// admin API, that a config export taken BEFORE an alert event was renamed
// keeps its subscription when it is restored AFTER the rename.
//
// The store-level invariant lives in
// internal/alerts/store_eventname_migration_test.go. This file exists because
// the gap was not visible at that level: `internal/alerts` cannot see that
// `POST /api/config/import` reconstructs every webhook through Store.Add, and
// so cannot show that a disaster-recovery restore was the delivery vehicle for
// the lost subscription.
//
// Why this is a security test and not a compatibility one: the alert in
// question (identity_backend_unreachable, CHAOS-47) fires when the external
// identity backend cannot be reached and proxy authentication is therefore
// failing closed fleet-wide. Losing the subscription does not degrade
// enforcement — the gateway still fails closed — it degrades DETECTION, and a
// restore is exactly the moment an operator is least able to notice that a
// webhook they can still see listed has quietly stopped firing.

import (
	"net/http/httptest"
	"testing"

	"github.com/KidCarmi/Culvert/internal/alerts"
)

// swapAlertStoreForImport isolates the process-wide alert store for one test.
// Init("") leaves the replacement non-persisting, so nothing touches disk.
func swapAlertStoreForImport(t *testing.T) *alerts.Store {
	t.Helper()
	orig := globalAlertStore
	t.Cleanup(func() { globalAlertStore = orig })
	as := &alerts.Store{}
	as.Init("")
	globalAlertStore = as
	return as
}

// preRenameBackup is the shape a config export produced before the CHAOS-47
// rename: the webhook subscribes to the retired event name.
func preRenameBackup(events []string) map[string]any {
	return map[string]any{
		"version":    1,
		"exportedAt": "2026-08-01T00:00:00Z",
		"alertWebhooks": []map[string]any{{
			"name":    "siem-pre-rename",
			"url":     "https://siem.example.invalid/culvert",
			"events":  events,
			"enabled": true,
		}},
	}
}

func importBackup(t *testing.T, path string, backup map[string]any) {
	t.Helper()
	w := httptest.NewRecorder()
	apiConfigImport(w, jsonReq("POST", path, backup))
	assertStatus(t, w, 200)
}

// TestConfigImport_PreRenameAlertWebhookKeepsSubscription is the regression
// test. Before the fix, the retired name was written straight back into the
// live store and HasSubscriber — which compares names exactly — never matched
// it again.
func TestConfigImport_PreRenameAlertWebhookKeepsSubscription(t *testing.T) {
	snapshotConfigVersionsDir(t)
	as := swapAlertStoreForImport(t)

	importBackup(t, "/api/config/import?mode=merge",
		preRenameBackup([]string{"threat_detected", "idp_unreachable"}))

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("REGRESSION: a pre-rename config export restored through /api/config/import " +
			"came back unsubscribed from identity_backend_unreachable — the operator sees the " +
			"webhook listed but never receives the alert that proxy authentication is failing " +
			"closed fleet-wide")
	}
	if as.HasSubscriber("idp_unreachable") {
		t.Error("the retired event name survived the import ingress")
	}
	if !as.HasSubscriber("threat_detected") {
		t.Error("import must not disturb an unrelated, already-current event name")
	}

	// The restored webhook must be visible to the admin UI under the migrated
	// name, or the panel renders an unchecked box for a live subscription.
	hooks := as.List()
	if len(hooks) != 1 {
		t.Fatalf("restored %d webhooks, want 1: %+v", len(hooks), hooks)
	}
	if !containsAlertEvent(hooks[0].Events, "identity_backend_unreachable") {
		t.Errorf("restored webhook events = %v, want the migrated name", hooks[0].Events)
	}
}

// TestConfigImport_ReplaceModePreRenameWebhookKeepsSubscription covers the
// other import mode. Replace mode deletes the live webhooks first, so a failure
// here would leave the deployment with NO identity-backend alerting at all
// rather than merely one stale row.
func TestConfigImport_ReplaceModePreRenameWebhookKeepsSubscription(t *testing.T) {
	snapshotConfigVersionsDir(t)
	as := swapAlertStoreForImport(t)

	as.Add(alerts.Webhook{
		Name:    "live",
		URL:     "https://live.example.invalid/hook",
		Events:  []string{"identity_backend_unreachable"},
		Enabled: true,
	})

	importBackup(t, "/api/config/import?mode=replace",
		preRenameBackup([]string{"idp_unreachable"}))

	if !as.HasSubscriber("identity_backend_unreachable") {
		t.Error("REGRESSION: replace-mode import of a pre-rename export left the deployment " +
			"with no identity_backend_unreachable subscriber at all")
	}
}

// TestConfigImport_CurrentAlertWebhookIsUnchanged is the negative control: an
// export taken AFTER the rename must round-trip byte-for-byte through the same
// ingress. Normalization is only allowed to carry a retired name forward.
func TestConfigImport_CurrentAlertWebhookIsUnchanged(t *testing.T) {
	snapshotConfigVersionsDir(t)
	as := swapAlertStoreForImport(t)

	importBackup(t, "/api/config/import?mode=merge",
		preRenameBackup([]string{"threat_detected", "identity_backend_unreachable"}))

	hooks := as.List()
	if len(hooks) != 1 {
		t.Fatalf("restored %d webhooks, want 1: %+v", len(hooks), hooks)
	}
	if len(hooks[0].Events) != 2 ||
		hooks[0].Events[0] != "threat_detected" ||
		hooks[0].Events[1] != "identity_backend_unreachable" {
		t.Errorf("post-rename export did not round-trip unchanged: events = %v", hooks[0].Events)
	}
}

// TestConfigImport_PreRenameWebhookDoesNotWidenSubscription proves the import
// ingress cannot subscribe a restored webhook to an event its export never
// named. Normalization must never widen what a webhook receives.
func TestConfigImport_PreRenameWebhookDoesNotWidenSubscription(t *testing.T) {
	snapshotConfigVersionsDir(t)
	as := swapAlertStoreForImport(t)

	importBackup(t, "/api/config/import?mode=merge",
		preRenameBackup([]string{"idp_unreachable"}))

	for _, ev := range []string{"threat_detected", "policy_block", "storage_write_failed", "*"} {
		if as.HasSubscriber(ev) {
			t.Errorf("import widened the restored subscription: it now matches %q", ev)
		}
	}
}

func containsAlertEvent(events []string, want string) bool {
	for _, ev := range events {
		if ev == want {
			return true
		}
	}
	return false
}
