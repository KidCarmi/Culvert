package main

import (
	"strings"
	"testing"
)

func TestAlertDeliveryDiagnostics(t *testing.T) {
	orig := globalAlertStore
	t.Cleanup(func() { globalAlertStore = orig })
	globalAlertStore = &AlertStore{}

	if rows := checkAlertDelivery(); len(rows) != 0 {
		t.Fatalf("no webhooks must add no row, got %+v", rows)
	}

	hook := globalAlertStore.Add(AlertWebhook{Name: "secret-name", URL: "https://hooks.example.com/x", Events: []string{"policy_block"}, Enabled: true})
	if rows := checkAlertDelivery(); len(rows) != 0 {
		t.Fatalf("no recorded attempt must add no row, got %+v", rows)
	}

	globalAlertStore.RecordDelivery(AlertDelivery{WebhookID: hook.ID, Success: false, Error: "dial tcp 10.0.0.1: refused"})
	rows := checkAlertDelivery()
	if len(rows) != 1 {
		t.Fatalf("failed latest delivery must add one row, got %d", len(rows))
	}
	r := rows[0]
	if r.Code != "alert_delivery" || r.Status != diagWarn || r.OperatorAction == "" {
		t.Fatalf("unexpected row %+v", r)
	}
	if strings.Contains(r.Message+r.OperatorAction, "secret-name") || strings.Contains(r.Message+r.OperatorAction, "10.0.0.1") {
		t.Fatalf("viewer-readable row must not carry webhook name or error text: %+v", r)
	}

	globalAlertStore.RecordDelivery(AlertDelivery{WebhookID: hook.ID, Success: true})
	if rows := checkAlertDelivery(); len(rows) != 0 {
		t.Fatalf("a later success must clear the row, got %+v", rows)
	}

	globalAlertStore.RecordDelivery(AlertDelivery{WebhookID: hook.ID, Success: false})
	hook.Enabled = false
	globalAlertStore.Update(hook.ID, hook)
	if rows := checkAlertDelivery(); len(rows) != 0 {
		t.Fatalf("a disabled webhook must add no row, got %+v", rows)
	}

	hook.Enabled = true
	globalAlertStore.Update(hook.ID, hook)
	found := false
	for _, c := range buildOperatorContract().Checks {
		if c.Code == "alert_delivery" {
			found = true
		}
	}
	if !found {
		t.Fatal("alert_delivery row missing from the assembled contract")
	}
}
