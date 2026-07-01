package blockpage

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestServe_DefaultTemplate(t *testing.T) {
	w := httptest.NewRecorder()
	Serve(w, "http://blocked.example.com/x", "Malware", "rule-7")

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if ct := w.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}
	body := w.Body.String()
	for _, want := range []string{"http://blocked.example.com/x", "Malware", "rule-7", "Access Denied"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q", want)
		}
	}
}

func TestSetGetHTML_RoundTrip(t *testing.T) {
	orig := GetHTML()
	t.Cleanup(func() { _ = SetHTML(orig) }) // restore default for other tests

	const custom = `<html>{{.URL}}|{{.Category}}|{{.RuleName}}</html>`
	if err := SetHTML(custom); err != nil {
		t.Fatalf("SetHTML: %v", err)
	}
	if got := GetHTML(); got != custom {
		t.Errorf("GetHTML = %q, want %q", got, custom)
	}

	w := httptest.NewRecorder()
	Serve(w, "u", "c", "r")
	if got, want := w.Body.String(), "<html>u|c|r</html>"; got != want {
		t.Errorf("Serve with custom template = %q, want %q", got, want)
	}
}

func TestSetHTML_InvalidTemplateRejected(t *testing.T) {
	orig := GetHTML()
	t.Cleanup(func() { _ = SetHTML(orig) })

	if err := SetHTML("{{.Unclosed"); err == nil {
		t.Error("SetHTML should reject an unparseable template")
	}
	// The prior (valid) template must remain installed after a rejected set.
	if GetHTML() != orig {
		t.Error("a rejected SetHTML must not mutate the installed template")
	}
}

func TestServe_ExecuteError_FallsBackTo403(t *testing.T) {
	orig := GetHTML()
	t.Cleanup(func() { _ = SetHTML(orig) })

	// A template that references a method that errors at execution time:
	// calling .URL.Bad (a string has no Bad field/method) fails Execute.
	if err := SetHTML(`{{.URL.Bad}}`); err != nil {
		t.Fatalf("SetHTML: %v", err)
	}
	w := httptest.NewRecorder()
	Serve(w, "u", "c", "r")
	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d on execute error", w.Code, http.StatusForbidden)
	}
}
