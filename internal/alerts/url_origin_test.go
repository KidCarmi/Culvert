package alerts

import (
	"strings"
	"testing"
)

func TestURLOrigin_DropsEverythingThatAuthorises(t *testing.T) {
	cases := map[string]string{ //nolint:gosec // G101: URL fixtures for the redactor, not credentials
		"https://hooks.slack.com/services/T0/B0/tok":      "https://hooks.slack.com",
		"https://u:pw@example.com:8443/hook?key=tok#frag": "https://example.com:8443",
		"http://[::1]:9/x":       "http://[::1]:9",
		"":                       "",
		"not a url":              "",
		"http://u:pw%zz@host/x":  "", // unparseable: never echoed
		"mailto:tok@example.com": "",
	}
	for in, want := range cases {
		if got := URLOrigin(in); got != want {
			t.Errorf("URLOrigin(%q) = %q, want %q", in, got, want)
		}
	}
}

// A refused delivery must leave the cause, not the URL, in the history that
// GET /api/alerts/webhooks/history serves to viewers.
func TestDeliver_HistoryErrorOmitsWebhookURL(t *testing.T) {
	as := &Store{}
	as.Init("")
	h := Webhook{ID: "h1", Name: "soc", URL: "http://127.0.0.1:1/services/PATHTOK?key=QUERYTOK"}
	if as.Deliver(h, Payload{Event: "test"}) {
		t.Fatal("delivery to a loopback address must be refused by the SSRF dialer")
	}
	hist := as.DeliveryHistory()
	if len(hist) == 0 {
		t.Fatal("no delivery record")
	}
	got := hist[0].Error
	if strings.Contains(got, "PATHTOK") || strings.Contains(got, "QUERYTOK") {
		t.Errorf("delivery error discloses the webhook URL: %q", got)
	}
	if !strings.Contains(got, "ssrf") {
		t.Errorf("delivery error lost its cause: %q", got)
	}
}
