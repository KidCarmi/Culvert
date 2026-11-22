package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// relayBoundOIDCProvider is the smallest OIDCFlowProvider CaptiveLoginURL can
// run on: it needs only an authorization endpoint, a profile ID and a config.
func relayBoundOIDCProvider() *OIDCFlowProvider {
	return &OIDCFlowProvider{
		profile: &IdPProfile{ID: "corp-oidc"},
		cfg:     &OIDCProfileConfig{ClientID: "culvert"},
		disc:    &oidcDiscoveryDoc{AuthorizationEndpoint: "https://idp.example/authorize"},
	}
}

func relayBoundRequest(t *testing.T) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil)
	r.RemoteAddr = "198.51.100.7:40000"
	return r
}

func TestBoundLoginRelay(t *testing.T) {
	pad := func(n int) string { return strings.Repeat("a", n) }
	atLimit := "https://app.example/" + pad(maxLoginRelayBytes-len("https://app.example/"))
	tests := []struct {
		name  string
		relay string
		want  string
	}{
		{"empty", "", ""},
		{"ordinary absolute URL is untouched", "https://app.example/protected?x=1", "https://app.example/protected?x=1"},
		{"same-origin path is untouched", "/dashboard", "/dashboard"},
		{"exactly at the limit is untouched", atLimit, atLimit},
		{"one byte over degrades to the origin root", atLimit + "a", "https://app.example/"},
		{"oversized http path", "http://app.example:8080/" + pad(1<<20), "http://app.example:8080/"},
		{"oversized query with no path", "https://app.example?" + pad(1<<20), "https://app.example/"},
		{"oversized fragment with no path", "https://app.example#" + pad(1<<20), "https://app.example/"},
		{"oversized authority has no usable origin", "http://" + pad(1<<20) + "/x", ""},
		{"oversized with empty authority", "http:///" + pad(1<<20), ""},
		{"oversized same-origin path", "/" + pad(1<<20), ""},
		{"oversized non-http scheme", "javascript://app.example/" + pad(1<<20), ""},
		{"oversized opaque value", pad(1 << 20), ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := boundLoginRelay(tt.relay)
			if got != tt.want {
				t.Fatalf("boundLoginRelay(len=%d) = %q (len %d), want %q", len(tt.relay), clampForTest(got), len(got), tt.want)
			}
			if len(got) > maxLoginRelayBytes {
				t.Fatalf("retained %d bytes, above the %d-byte bound", len(got), maxLoginRelayBytes)
			}
		})
	}
}

func clampForTest(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}

// TestLoginRelay_OIDCStoreRetentionIsBounded is the headline gate: an
// unauthenticated client choosing a ~1 MiB request target must not be able to
// park it in the PKCE store for the entry's TTL. Before the bound every entry
// retained the whole relay, so the store's 1000-entry cap bounded nothing.
func TestLoginRelay_OIDCStoreRetentionIsBounded(t *testing.T) {
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })

	prov := relayBoundOIDCProvider()
	r := relayBoundRequest(t)
	relay := "http://victim.example/" + strings.Repeat("'", 1<<20)

	retained := 0
	const n = 32
	for range n {
		loginURL := prov.CaptiveLoginURL(relay, r)
		u, err := url.Parse(loginURL)
		if err != nil {
			t.Fatalf("login URL parse: %v", err)
		}
		entry, ok := globalPKCEStore.Peek(u.Query().Get("state"))
		if !ok {
			t.Fatal("login state was not stored — the bound must not refuse the login")
		}
		if entry.verifier == "" || entry.nonce == "" || entry.providerID != "corp-oidc" {
			t.Fatalf("login state incomplete: verifier/nonce/provider missing")
		}
		if entry.relayURL != "http://victim.example/" {
			t.Fatalf("oversized relay retained as %q (len %d), want the origin root", clampForTest(entry.relayURL), len(entry.relayURL))
		}
		retained += len(entry.relayURL)
	}
	if limit := n * maxLoginRelayBytes; retained > limit {
		t.Fatalf("store retains %d relay bytes for %d entries, above the %d bound", retained, n, limit)
	}
}

// TestLoginRelay_OIDCOrdinaryRelayIsPreserved is the negative control: the
// bound must not change the return target of any ordinary login.
func TestLoginRelay_OIDCOrdinaryRelayIsPreserved(t *testing.T) {
	orig := globalPKCEStore
	globalPKCEStore = newPKCEStore()
	t.Cleanup(func() { globalPKCEStore = orig })

	relay := "http://intranet.example/reports/q3?tab=2&sig=" + strings.Repeat("s", 2048)
	loginURL := relayBoundOIDCProvider().CaptiveLoginURL(relay, relayBoundRequest(t))
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("login URL parse: %v", err)
	}
	entry, ok := globalPKCEStore.Peek(u.Query().Get("state"))
	if !ok {
		t.Fatal("login state was not stored")
	}
	if entry.relayURL != relay {
		t.Fatalf("an in-bound relay was altered: got len %d, want len %d", len(entry.relayURL), len(relay))
	}
}

// TestLoginRelay_SAMLStoreRetentionIsBounded is the same property on the SAML
// half: the two stores are separate call sites, and a bound that reached only
// one would leave a SAML deployment exposed.
func TestLoginRelay_SAMLStoreRetentionIsBounded(t *testing.T) {
	resetSAMLStateStore(t)
	prov := testSAMLRedirectProvider(t)
	relay := "https://victim.example/" + strings.Repeat("'", 1<<20)

	loginURL := prov.CaptiveLoginURL(relay, relayBoundRequest(t))
	if loginURL == "" {
		t.Fatal("CaptiveLoginURL returned empty URL — the bound must not refuse the login")
	}
	u, err := url.Parse(loginURL)
	if err != nil {
		t.Fatalf("login URL parse: %v", err)
	}
	entry, ok := globalSAMLStateStore.Peek(u.Query().Get("RelayState"))
	if !ok {
		t.Fatal("RelayState did not map to a stored SAML request")
	}
	if entry.requestID == "" || entry.providerID != "corp-saml" {
		t.Fatalf("SAML state incomplete: requestID/provider missing")
	}
	if entry.relayURL != "https://victim.example/" {
		t.Fatalf("oversized relay retained as %q (len %d), want the origin root", clampForTest(entry.relayURL), len(entry.relayURL))
	}
}
