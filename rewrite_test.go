package main

import (
	"net/http"
	"testing"
)

// ─── matchesHost ──────────────────────────────────────────────────────────────

func TestRewriteRule_MatchesHost(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Empty pattern matches everything.
		{"", "anything.example.com", true},
		{"", "example.com", true},
		{"", "", true},

		// Wildcard prefix.
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", true}, // apex
		{"*.example.com", "notexample.com", false},

		// Exact match (no subdomain inference — unlike matchFQDN).
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", false}, // rewrite uses strict equality
		{"example.com", "other.com", false},

		// Case insensitive.
		{"EXAMPLE.COM", "example.com", true},
		{"*.CORP.LOCAL", "app.corp.local", true},
	}
	for _, c := range cases {
		rule := &RewriteRule{Host: c.pattern}
		got := rule.matchesHost(c.host)
		if got != c.want {
			t.Errorf("matchesHost(pattern=%q, host=%q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// ─── Rewriter CRUD ────────────────────────────────────────────────────────────

func newTestRewriter() *Rewriter {
	return &Rewriter{nextID: 1}
}

func TestRewriter_AddAssignsID(t *testing.T) {
	rw := newTestRewriter()
	r1 := rw.Add(RewriteRule{Host: "a.com"})
	r2 := rw.Add(RewriteRule{Host: "b.com"})

	if r1.ID == r2.ID {
		t.Error("IDs should be unique")
	}
	if r1.ID == 0 || r2.ID == 0 {
		t.Error("IDs should not be zero")
	}
}

func TestRewriter_List(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{Host: "a.com"})
	rw.Add(RewriteRule{Host: "b.com"})

	list := rw.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(list))
	}
	// List returns a copy — modifying it should not affect internal state.
	list[0].Host = "mutated.com"
	if rw.List()[0].Host == "mutated.com" {
		t.Error("List() should return a copy, not a reference")
	}
}

func TestRewriter_RemoveByID(t *testing.T) {
	rw := newTestRewriter()
	r1 := rw.Add(RewriteRule{Host: "a.com"})
	rw.Add(RewriteRule{Host: "b.com"})

	if !rw.RemoveByID(r1.ID) {
		t.Error("RemoveByID should return true for existing ID")
	}
	if rw.RemoveByID(r1.ID) {
		t.Error("RemoveByID should return false for already-removed ID")
	}
	if rw.RemoveByID(9999) {
		t.Error("RemoveByID should return false for non-existent ID")
	}

	list := rw.List()
	if len(list) != 1 || list[0].Host != "b.com" {
		t.Errorf("unexpected list after remove: %+v", list)
	}
}

func TestRewriter_SetRules(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{Host: "old.com"})

	rw.SetRules([]RewriteRule{
		{Host: "new1.com"},
		{Host: "new2.com"},
	})

	list := rw.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 rules after SetRules, got %d", len(list))
	}
	// IDs should be assigned.
	if list[0].ID == 0 || list[1].ID == 0 {
		t.Error("SetRules should assign IDs")
	}
	// IDs should be unique.
	if list[0].ID == list[1].ID {
		t.Error("SetRules IDs should be unique")
	}
}

// ─── ApplyRequest ─────────────────────────────────────────────────────────────

func TestRewriter_ApplyRequest_Set(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{
		Host:   "example.com",
		ReqSet: map[string]string{"X-Proxy": "ProxyShield", "X-Custom": "value"},
	})

	h := http.Header{}
	h.Set("X-Proxy", "old-value")
	rw.ApplyRequest("example.com", h)

	if h.Get("X-Proxy") != "ProxyShield" {
		t.Errorf("X-Proxy = %q, want ProxyShield", h.Get("X-Proxy"))
	}
	if h.Get("X-Custom") != "value" {
		t.Errorf("X-Custom = %q, want value", h.Get("X-Custom"))
	}
}

func TestRewriter_ApplyRequest_Add(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{
		Host:   "example.com",
		ReqAdd: map[string]string{"Via": "1.1 proxy"},
	})

	h := http.Header{}
	h.Add("Via", "1.0 first")
	rw.ApplyRequest("example.com", h)

	via := h["Via"]
	if len(via) != 2 {
		t.Errorf("expected 2 Via values (add), got %v", via)
	}
}

func TestRewriter_ApplyRequest_Remove(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{
		Host:      "example.com",
		ReqRemove: []string{"Cookie", "Authorization"},
	})

	h := http.Header{}
	h.Set("Cookie", "session=abc")
	h.Set("Authorization", "Bearer token")
	h.Set("Accept", "text/html")
	rw.ApplyRequest("example.com", h)

	if h.Get("Cookie") != "" {
		t.Error("Cookie should be removed")
	}
	if h.Get("Authorization") != "" {
		t.Error("Authorization should be removed")
	}
	if h.Get("Accept") == "" {
		t.Error("Accept should be untouched")
	}
}

func TestRewriter_ApplyRequest_NoMatchSkipped(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{
		Host:   "example.com",
		ReqSet: map[string]string{"X-Added": "yes"},
	})

	h := http.Header{}
	rw.ApplyRequest("other.com", h)

	if h.Get("X-Added") != "" {
		t.Error("rule for example.com should not apply to other.com")
	}
}

func TestRewriter_ApplyRequest_MultipleRules(t *testing.T) {
	rw := newTestRewriter()
	// Rule 1: matches all hosts (empty pattern).
	rw.Add(RewriteRule{
		Host:   "",
		ReqSet: map[string]string{"X-Global": "1"},
	})
	// Rule 2: only example.com.
	rw.Add(RewriteRule{
		Host:   "example.com",
		ReqSet: map[string]string{"X-Specific": "1"},
	})

	h := http.Header{}
	rw.ApplyRequest("example.com", h)
	if h.Get("X-Global") == "" || h.Get("X-Specific") == "" {
		t.Errorf("both rules should apply; headers: %v", h)
	}

	h2 := http.Header{}
	rw.ApplyRequest("other.com", h2)
	if h2.Get("X-Global") == "" {
		t.Error("global rule should apply to other.com")
	}
	if h2.Get("X-Specific") != "" {
		t.Error("specific rule should not apply to other.com")
	}
}

// ─── ApplyResponse ────────────────────────────────────────────────────────────

func TestRewriter_ApplyResponse_Nil(_ *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{Host: "example.com", RespSet: map[string]string{"X-Frame-Options": "DENY"}})
	// Should not panic.
	rw.ApplyResponse("example.com", nil)
}

func TestRewriter_ApplyResponse_Set(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{
		Host:    "example.com",
		RespSet: map[string]string{"Strict-Transport-Security": "max-age=31536000"},
	})

	resp := &http.Response{Header: http.Header{}}
	rw.ApplyResponse("example.com", resp)

	if got := resp.Header.Get("Strict-Transport-Security"); got != "max-age=31536000" {
		t.Errorf("STS = %q, want max-age=31536000", got)
	}
}

func TestRewriter_ApplyResponse_Remove(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{
		Host:       "example.com",
		RespRemove: []string{"Server", "X-Powered-By"},
	})

	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Server", "Apache")
	resp.Header.Set("X-Powered-By", "PHP/8.1")
	resp.Header.Set("Content-Type", "text/html")
	rw.ApplyResponse("example.com", resp)

	if resp.Header.Get("Server") != "" {
		t.Error("Server header should be removed")
	}
	if resp.Header.Get("X-Powered-By") != "" {
		t.Error("X-Powered-By should be removed")
	}
	if resp.Header.Get("Content-Type") == "" {
		t.Error("Content-Type should be untouched")
	}
}

func TestRewriter_ApplyResponse_Add(t *testing.T) {
	rw := newTestRewriter()
	rw.Add(RewriteRule{
		Host:    "example.com",
		RespAdd: map[string]string{"X-Custom-Header": "appended"},
	})

	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("X-Custom-Header", "original")
	rw.ApplyResponse("example.com", resp)

	vals := resp.Header["X-Custom-Header"]
	if len(vals) != 2 {
		t.Errorf("expected 2 X-Custom-Header values, got %v", vals)
	}
}
