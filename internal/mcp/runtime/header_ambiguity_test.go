package runtime

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// singletonSecurityHeaders are the request headers whose value participates in a
// security decision and that a client may legitimately send at most once.
var singletonSecurityHeaders = []string{
	"Origin",
	"DPoP",
	"Mcp-Session-Id",
	"MCP-Protocol-Version",
	"Authorization",
}

// newExtractListener builds a listener whose transport extraction can be driven
// directly (no socket, no serve loop).
func newExtractListener(t testing.TB) *Listener {
	t.Helper()
	k := newESKey(t, "k1")
	l, err := newListener(gwListenerConfig(t), testDeps(t, k, nil), "amb-gw", 1)
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	return l
}

// SEC-MCP-04. A singleton security header presented TWICE is ambiguous: an
// intermediary, a WAF and the gateway may each resolve the conflict differently,
// so no first-value-wins reading is safe. Authorization was already rejected;
// every other security-relevant singleton must be too, or the anti-ambiguity
// posture is only as strong as its weakest header.
func TestSecurity_DuplicateSingletonHeadersAreRejected(t *testing.T) {
	l := newExtractListener(t)
	for _, h := range singletonSecurityHeaders {
		t.Run(h, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "https://"+gwHost+gwResource, http.NoBody)
			r.Host = gwHost
			// Two DIFFERENT values: the conflict is the whole point.
			r.Header.Add(h, "https://alpha.example")
			r.Header.Add(h, "https://beta.example")
			_, status, _, _ := l.extractRequest(httptest.NewRecorder(), r)
			if status != http.StatusBadRequest {
				t.Fatalf("duplicate %s: status = %d, want 400 (ambiguous)", h, status)
			}
		})
	}
}

// The rejection must be driven by DUPLICATION, not by the header's content: an
// identical repeated value is still ambiguous to a middlebox that keeps only one,
// and a single value of any shape must still be accepted here (later stages own
// its validity).
func TestSecurity_DuplicateRejectionIsAboutCountNotContent(t *testing.T) {
	l := newExtractListener(t)
	for _, h := range singletonSecurityHeaders {
		r := httptest.NewRequest(http.MethodPost, "https://"+gwHost+gwResource, http.NoBody)
		r.Host = gwHost
		r.Header.Add(h, "same-value")
		r.Header.Add(h, "same-value")
		if _, status, _, _ := l.extractRequest(httptest.NewRecorder(), r); status != http.StatusBadRequest {
			t.Fatalf("repeated identical %s must still be rejected, got %d", h, status)
		}

		single := httptest.NewRequest(http.MethodPost, "https://"+gwHost+gwResource, http.NoBody)
		single.Host = gwHost
		single.Header.Set(h, "same-value")
		if _, status, _, _ := l.extractRequest(httptest.NewRecorder(), single); status != 0 {
			t.Fatalf("a single %s must pass transport extraction, got %d", h, status)
		}
	}
}

// Anti-weakening: the guarded set must not shrink. A header that carries a
// security decision but is absent from the guard is exactly the regression this
// test exists to catch.
func TestSecurity_GuardedSingletonSetIsComplete(t *testing.T) {
	for _, h := range []string{"Origin", "DPoP", "Mcp-Session-Id", "MCP-Protocol-Version", "Authorization"} {
		if !isSingletonSecurityHeader(h) {
			t.Fatalf("%s is security-relevant but is not guarded against duplication", h)
		}
	}
}
