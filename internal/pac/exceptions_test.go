package pac

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExceptionRecord_Status(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	rfc := func(tm time.Time) string { return tm.Format(time.RFC3339) }

	cases := []struct {
		name          string
		rec           ExceptionRecord
		directCapable bool
		want          string
	}{
		{"not applicable when not direct-capable",
			ExceptionRecord{Owner: "a", Reason: "b"}, false, ""},
		{"ungoverned: no owner",
			ExceptionRecord{Reason: "b"}, true, GovUngoverned},
		{"ungoverned: no reason",
			ExceptionRecord{Owner: "a"}, true, GovUngoverned},
		{"expired: past expiry",
			ExceptionRecord{Owner: "a", Reason: "b", ExpiresAt: rfc(now.AddDate(0, 0, -1))}, true, GovExpired},
		{"expired: malformed expiry is fail-safe",
			ExceptionRecord{Owner: "a", Reason: "b", ExpiresAt: "not-a-date"}, true, GovExpired},
		{"review_due: never reviewed with cadence",
			ExceptionRecord{Owner: "a", Reason: "b", ReviewCadenceDays: 90}, true, GovReviewDue},
		{"review_due: past cadence",
			ExceptionRecord{Owner: "a", Reason: "b", ReviewCadenceDays: 30, LastReviewedAt: rfc(now.AddDate(0, 0, -31))}, true, GovReviewDue},
		{"governed: owned, justified, not expired, review current",
			ExceptionRecord{Owner: "a", Reason: "b", ExpiresAt: rfc(now.AddDate(0, 0, 30)), ReviewCadenceDays: 30, LastReviewedAt: rfc(now.AddDate(0, 0, -1))}, true, GovGoverned},
		{"governed: owned + justified, no expiry, no cadence",
			ExceptionRecord{Owner: "a", Reason: "b"}, true, GovGoverned},
	}
	for _, c := range cases {
		if got := c.rec.Status(now, c.directCapable); got != c.want {
			t.Errorf("%s: Status = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestExceptionStore_RoundTripAndQuarantine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pac_exceptions.json")
	var s ExceptionStore
	if err := s.Load(path); err != nil {
		t.Fatalf("load missing: %v", err)
	}
	rec := ExceptionRecord{ProfileID: "hq", Owner: "neteng", Reason: "vendor SaaS", ReviewCadenceDays: 90}
	if err := s.Put(rec); err != nil {
		t.Fatalf("put: %v", err)
	}
	// Reload into a fresh store — persisted round-trip.
	var s2 ExceptionStore
	if err := s2.Load(path); err != nil {
		t.Fatalf("reload: %v", err)
	}
	got, ok := s2.Get("hq")
	if !ok || got.Owner != "neteng" || got.ReviewCadenceDays != 90 {
		t.Errorf("round-trip mismatch: %+v (ok=%v)", got, ok)
	}
	if err := s2.Delete("hq"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, ok := s2.Get("hq"); ok {
		t.Error("record should be gone after delete")
	}

	// Corrupt file → quarantined, empty start (non-fatal).
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	var s3 ExceptionStore
	if err := s3.Load(path); err == nil {
		t.Error("corrupt load should return a (non-fatal) error")
	}
	if len(s3.All()) != 0 {
		t.Error("corrupt load must start empty")
	}
}
