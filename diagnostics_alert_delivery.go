package main

// diagnostics_alert_delivery.go — operator-contract row for failing alert delivery.
//
// The delivery history (Security → Alert Webhooks) records every attempt, but the
// one-page diagnostics report — where an operator checks "will I be told when
// something goes wrong" — said nothing when an enabled webhook's most recent
// delivery failed (wrong URL, receiver down, rejected signature, blocked by the
// SSRF dial guard). Security alerts then silently stopped arriving.
//
// Report-only: reads the in-memory delivery history and the webhook list, no I/O,
// no change to dispatch, retry or signing. Contributes nothing when no enabled
// webhook has a recorded attempt, or when each one's latest attempt succeeded.
// History is per-process, so the row clears on restart until the next failure.
// Counts only: no webhook name, URL or delivery error text (viewer-readable).

import "fmt"

// checkAlertDelivery returns zero or one row for enabled webhooks whose latest
// recorded delivery attempt failed.
func checkAlertDelivery() []OperatorContractCheck {
	enabled := map[string]bool{}
	for _, h := range globalAlertStore.List() {
		if h.Enabled {
			enabled[h.ID] = true
		}
	}
	if len(enabled) == 0 {
		return nil
	}
	seen := map[string]bool{}
	failing := 0
	// DeliveryHistory is newest first, so the first record per webhook is its latest.
	for _, d := range globalAlertStore.DeliveryHistory() {
		if !enabled[d.WebhookID] || seen[d.WebhookID] {
			continue
		}
		seen[d.WebhookID] = true
		if !d.Success {
			failing++
		}
	}
	if failing == 0 {
		return nil
	}
	return []OperatorContractCheck{{
		Code:   "alert_delivery",
		Status: diagWarn,
		Message: fmt.Sprintf("%d enabled alert webhook(s) failed their most recent delivery — alerts are not reaching those receivers",
			failing),
		OperatorAction: "Security → Alert Webhooks → delivery history shows which webhook failed and why (HTTP status or connection error). " +
			"Fix the URL, receiver or signing secret, then use Test on the webhook; this warning clears after its next successful delivery or a restart.",
	}}
}
