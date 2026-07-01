package clientclass

import (
	"context"
	"net/http"
	"testing"
)

func req(method string, headers map[string]string) *http.Request {
	if method == "" {
		method = http.MethodGet
	}
	r, _ := http.NewRequestWithContext(context.Background(), method, "http://x/", http.NoBody)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		headers map[string]string
		want    Class
	}{
		{"connect is opaque", http.MethodConnect, map[string]string{"Accept": "text/html"}, Connect},
		{"connect ignores mozilla", http.MethodConnect, map[string]string{"User-Agent": "Mozilla/5.0"}, Connect},
		{"sec-fetch navigate", "", map[string]string{"Sec-Fetch-Mode": "navigate"}, Browser},
		{"accept text/html", "", map[string]string{"Accept": "text/html,application/xhtml+xml"}, Browser},
		{"mozilla UA without nav signal is non-browser", "", map[string]string{"User-Agent": "Mozilla/5.0"}, NonBrowser},
		{"bare GET", "", nil, NonBrowser},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Classify(req(c.method, c.headers)); got != c.want {
				t.Errorf("Classify = %d, want %d", got, c.want)
			}
		})
	}
}

func TestBrowserRedirectEligibleLegacy(t *testing.T) {
	// Legacy predicate DOES key on the Mozilla UA (quarantined behaviour).
	if !BrowserRedirectEligibleLegacy(req("", map[string]string{"User-Agent": "Mozilla/5.0"})) {
		t.Error("legacy predicate should accept a Mozilla UA on a non-CONNECT request")
	}
	if BrowserRedirectEligibleLegacy(req(http.MethodConnect, map[string]string{"User-Agent": "Mozilla/5.0"})) {
		t.Error("legacy predicate must reject CONNECT regardless of UA")
	}
	if BrowserRedirectEligibleLegacy(req("", map[string]string{"User-Agent": "curl/8"})) {
		t.Error("legacy predicate should reject a non-Mozilla UA")
	}
}
