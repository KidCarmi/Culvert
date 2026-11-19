package alerts

import "testing"

// TestUpdate_PreservesStoredURLWhenPayloadOmitsIt pins the contract the admin
// API's shared payload gate relies on: webhookPayloadRejected admits a
// URL-less PUT (urlRequired=false on the update arm) because "an empty URL on
// an update preserves the stored one (see Store.Update)".
//
// Update used to assign the payload wholesale, so that promise was false and a
// partial PUT — the natural shape for a client that only wants to toggle
// Enabled or rename a hook — blanked the destination while leaving the
// subscription intact. The subscription index then still reported a subscriber,
// so every matching alert was dispatched and every delivery died at the
// validWebhookURL barrier: security alerts stopped arriving with nothing
// failing loudly. An empty URL is never a valid stored state, so there is no
// legitimate "clear the URL" intent for this to mask.
func TestUpdate_PreservesStoredURLWhenPayloadOmitsIt(t *testing.T) {
	as := newFileStore(t)
	created := as.Add(Webhook{
		Name:    "siem",
		URL:     "https://siem.example.invalid/hook",
		Events:  []string{"threat_detected"},
		Enabled: true,
	})

	// A partial update: rename and re-subscribe, no URL supplied.
	if !as.Update(created.ID, Webhook{
		Name:    "siem-renamed",
		Events:  []string{"threat_detected", "policy_block"},
		Enabled: true,
	}) {
		t.Fatal("Update reported no such webhook")
	}

	got, ok := as.GetByID(created.ID)
	if !ok {
		t.Fatal("webhook vanished after update")
	}
	if got.URL != "https://siem.example.invalid/hook" {
		t.Fatalf("URL = %q after a URL-less update, want the stored destination preserved; "+
			"a blanked URL leaves the subscription live and silently drops every delivery", got.URL)
	}
	if got.Name != "siem-renamed" {
		t.Errorf("Name = %q, want the update applied", got.Name)
	}
	if !as.HasSubscriber("policy_block") {
		t.Error("the updated event list did not reach the subscription index")
	}
}

// TestUpdate_SuppliedURLStillReplacesTheStoredOne is the positive control: the
// preservation above must not make the URL immutable.
func TestUpdate_SuppliedURLStillReplacesTheStoredOne(t *testing.T) {
	as := newFileStore(t)
	created := as.Add(Webhook{
		Name:    "siem",
		URL:     "https://old.example.invalid/hook",
		Events:  []string{"threat_detected"},
		Enabled: true,
	})

	if !as.Update(created.ID, Webhook{
		Name:    "siem",
		URL:     "https://new.example.invalid/hook",
		Events:  []string{"threat_detected"},
		Enabled: true,
	}) {
		t.Fatal("Update reported no such webhook")
	}

	got, ok := as.GetByID(created.ID)
	if !ok {
		t.Fatal("webhook vanished after update")
	}
	if got.URL != "https://new.example.invalid/hook" {
		t.Errorf("URL = %q, want the supplied replacement", got.URL)
	}
}
