package main

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthSAMLCallbackLogsProviderRejection(t *testing.T) {
	origRegistry := idpRegistry
	origLogger := logger
	var logs bytes.Buffer
	logger = log.New(&logs, "", 0)
	idpRegistry = &IdPRegistry{
		profiles: []*IdPProfile{
			{ID: "corp-saml", Type: IdPTypeSAML, Enabled: true},
		},
		live: map[string]IdentityProvider{
			"corp-saml": &SAMLProvider{profile: &IdPProfile{ID: "corp-saml", Type: IdPTypeSAML}},
		},
	}
	t.Cleanup(func() {
		idpRegistry = origRegistry
		logger = origLogger
	})

	r := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/auth/saml/callback", strings.NewReader(url.Values{
		"RelayState":   {"missing"},
		"SAMLResponse": {"not-base64"},
	}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	authSAMLCallback(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	got := logs.String()
	if !strings.Contains(got, `SAML callback rejected by provider="corp-saml"`) {
		t.Fatalf("logs missing provider rejection: %q", got)
	}
	if !strings.Contains(got, "saml callback: invalid or expired state") {
		t.Fatalf("logs missing rejection reason: %q", got)
	}
}
