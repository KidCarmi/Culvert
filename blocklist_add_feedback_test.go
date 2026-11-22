package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/blocklist"
)

// TestBlocklistEntryMatchWarning_AgreesWithTheMatcher is the differential
// oracle for the warning: an entry is flagged if and only if storing it does
// NOT block the destination the operator plainly meant. It runs every case
// through the real Store and the same host derivation the proxy uses
// (bareDestHost, then Store.IsBlocked's own normalization), so the warning
// cannot drift from enforcement.
func TestBlocklistEntryMatchWarning_AgreesWithTheMatcher(t *testing.T) {
	cases := []struct {
		entry     string // as the operator typed it (lowercased/trimmed by the store)
		authority string // what a client asking for that destination sends
		wantWarn  bool
	}{
		{"evil.example", "evil.example:443", false},
		{"*.evil.example", "cdn.evil.example:443", false},
		{"192.0.2.10", "192.0.2.10:8080", false},
		{"xn--mnchen-3ya.example", "münchen.example:443", false},
		// Negative controls: each of these was accepted and listed, and never matched.
		{"https://evil.example/login", "evil.example:443", true},
		{"evil.example/login", "evil.example:443", true},
		{"evil.example:443", "evil.example:443", true},
		{"evil.example.", "evil.example:443", true},
		{"münchen.example", "münchen.example:443", true},
		{"evil example", "evil.example:443", true},
	}
	for _, tc := range cases {
		store := blocklist.New()
		store.AddManualBulk([]string{tc.entry})
		blocked := store.IsBlocked(bareDestHost(tc.authority))
		warning := blocklistEntryMatchWarning(tc.entry)
		if (warning != "") != tc.wantWarn {
			t.Errorf("entry %q: warning = %q; want warning = %t", tc.entry, warning, tc.wantWarn)
		}
		if blocked == tc.wantWarn {
			t.Errorf("entry %q: IsBlocked(%q) = %t, so the expectation wantWarn=%t misdescribes the matcher",
				tc.entry, tc.authority, blocked, tc.wantWarn)
		}
	}
	// A bare IPv6 literal contains colons but is not host:port — never flagged.
	if w := blocklistEntryMatchWarning("2001:db8::1"); w != "" {
		t.Errorf("bare IPv6 literal flagged: %q", w)
	}
}

// TestBlocklistAdd_ReportsWhatActuallyHappened pins the response the admin UI
// now renders, and that the feedback is description only: every entry stored
// before is still stored.
func TestBlocklistAdd_ReportsWhatActuallyHappened(t *testing.T) {
	origBL := bl
	bl = blocklist.New()
	t.Cleanup(func() { bl = origBL })
	bl.AddManual("already.pxadd.invalid")

	tooLong := strings.Repeat("a", 254)
	body, err := json.Marshal(map[string]any{"hosts": []string{
		"new.pxadd.invalid",
		"NEW.pxadd.invalid", // within-batch duplicate after normalization
		"already.pxadd.invalid",
		"https://url.pxadd.invalid/path",
		tooLong,
	}})
	if err != nil {
		t.Fatal(err)
	}
	r := adminCtx(httptest.NewRequestWithContext(context.Background(),
		http.MethodPost, "/api/blocklist", strings.NewReader(string(body))))
	w := httptest.NewRecorder()
	apiBlocklist(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d; want 200 (%s)", w.Code, w.Body.String())
	}
	var got struct {
		Added        int                  `json:"added"`
		Unchanged    int                  `json:"unchanged"`
		SkippedCount int                  `json:"skipped_count"`
		WarningCount int                  `json:"warning_count"`
		Skipped      []blocklistEntryNote `json:"skipped"`
		Warnings     []blocklistEntryNote `json:"warnings"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode %s: %v", w.Body.String(), err)
	}
	if got.Added != 2 || got.Unchanged != 1 || got.SkippedCount != 1 || got.WarningCount != 1 {
		t.Fatalf("added=%d unchanged=%d skipped=%d warnings=%d; want 2/1/1/1 (%s)",
			got.Added, got.Unchanged, got.SkippedCount, got.WarningCount, w.Body.String())
	}
	if len(got.Warnings) != 1 || got.Warnings[0].Host != "https://url.pxadd.invalid/path" {
		t.Errorf("warnings = %+v; want the pasted URL", got.Warnings)
	}
	if len(got.Skipped) != 1 || !strings.Contains(got.Skipped[0].Reason, "253") {
		t.Errorf("skipped = %+v; want the over-length entry with its reason", got.Skipped)
	}
	// Behaviour unchanged: the warned entry is still stored exactly as before,
	// and still does not block the host — which is what the warning says.
	stored := strings.Join(bl.List(), "\n")
	if !strings.Contains(stored, "https://url.pxadd.invalid/path") {
		t.Error("the warned entry must still be stored; the feedback must not change what is accepted")
	}
	if bl.IsBlocked("url.pxadd.invalid") {
		t.Error("a pasted URL blocked its host; the warning's premise no longer holds")
	}
	if !bl.IsBlocked("new.pxadd.invalid") {
		t.Error("the ordinary entry must be enforced")
	}
}

// TestBlocklistAdd_FeedbackIsBounded: the per-entry detail is capped while the
// counts stay exact, so the response cannot grow with a bulk import.
func TestBlocklistAdd_FeedbackIsBounded(t *testing.T) {
	var o blocklistAddOutcome
	valid := make([]string, 0, blocklistAddNoteCap+25)
	for i := 0; i < blocklistAddNoteCap+25; i++ {
		o.skip("x", "longer than 253 characters, not stored")
		valid = append(valid, "h"+strings.Repeat("i", i)+".invalid/path")
	}
	resp := o.response(valid, len(valid))
	if resp["skipped_count"] != blocklistAddNoteCap+25 || resp["warning_count"] != blocklistAddNoteCap+25 {
		t.Fatalf("counts = %v / %v; want exact totals", resp["skipped_count"], resp["warning_count"])
	}
	if n := len(resp["skipped"].([]blocklistEntryNote)); n != blocklistAddNoteCap {
		t.Errorf("skipped detail = %d entries; want cap %d", n, blocklistAddNoteCap)
	}
	if n := len(resp["warnings"].([]blocklistEntryNote)); n != blocklistAddNoteCap {
		t.Errorf("warning detail = %d entries; want cap %d", n, blocklistAddNoteCap)
	}
}
