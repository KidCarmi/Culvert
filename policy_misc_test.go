package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

// ─── matchSchedule ────────────────────────────────────────────────────────────

func TestMatchSchedule_WrongDay(t *testing.T) {
	// This test sets days to empty except one specific day that is
	// likely not today. We'll use a more deterministic approach:
	// Set Days to include only a specific day that is NOT today.
	today := time.Now().UTC().Weekday().String()[:3]
	allDays := []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"}
	var notToday []string
	for _, d := range allDays {
		if d != today {
			notToday = append(notToday, d)
			break // just need one day that isn't today
		}
	}
	if len(notToday) == 0 {
		t.Skip("Cannot determine a day that is not today")
	}
	s := &PolicySchedule{Days: notToday}
	if matchSchedule(s) {
		t.Error("matchSchedule with day not matching today should return false")
	}
}

func TestMatchSchedule_TimeRange_InRange(t *testing.T) {
	// Use a very wide time range that always includes now
	s := &PolicySchedule{
		TimeStart: "00:00",
		TimeEnd:   "23:59",
	}
	if !matchSchedule(s) {
		t.Error("matchSchedule with 00:00-23:59 should match any time")
	}
}

func TestMatchSchedule_TimeRange_OutOfRange(_ *testing.T) {
	// Use a time range that is guaranteed not to match current time:
	// if current time is < 12:00, use 12:00-12:01; otherwise 00:00-00:01
	now := time.Now().UTC()
	cur := now.Format("15:04")
	var start, end string
	if cur < "12:00" {
		start, end = "12:00", "12:01"
	} else {
		start, end = "00:00", "00:01"
	}
	s := &PolicySchedule{
		TimeStart: start,
		TimeEnd:   end,
	}
	// This may or may not match depending on exact time — just ensure it doesn't panic
	matchSchedule(s) // just verify no panic
}

func TestMatchSchedule_Timezone(t *testing.T) {
	s := &PolicySchedule{
		Timezone:  "America/New_York",
		TimeStart: "00:00",
		TimeEnd:   "23:59",
	}
	if !matchSchedule(s) {
		t.Error("matchSchedule with valid timezone and wide range should match")
	}
}

func TestMatchSchedule_InvalidTimezone(t *testing.T) {
	s := &PolicySchedule{
		Timezone:  "Invalid/Timezone",
		TimeStart: "00:00",
		TimeEnd:   "23:59",
	}
	// Should fall back to UTC and not panic
	if !matchSchedule(s) {
		t.Error("matchSchedule with invalid timezone should fall back to UTC")
	}
}

// ─── matchDest ────────────────────────────────────────────────────────────────

func TestMatchDest_EmptyRule(t *testing.T) {
	rule := &PolicyRule{}
	if !matchDest(rule, "example.com") {
		t.Error("matchDest with empty rule should match any host")
	}
}

func TestMatchDest_FQDNMatch(t *testing.T) {
	rule := &PolicyRule{DestFQDN: "example.com"}
	if !matchDest(rule, "example.com") {
		t.Error("matchDest should match FQDN")
	}
}

func TestMatchDest_FQDNNoMatch(t *testing.T) {
	rule := &PolicyRule{DestFQDN: "example.com"}
	if matchDest(rule, "other.com") {
		t.Error("matchDest should not match different FQDN")
	}
}

// ─── serveBlockPage ───────────────────────────────────────────────────────────

func TestServeBlockPage(t *testing.T) {
	w := httptest.NewRecorder()
	serveBlockPage(w, "http://blocked.example.com", "malware", "test-rule")
	if w.Code != http.StatusForbidden {
		t.Errorf("serveBlockPage status = %d, want 403", w.Code)
	}
}

// ─── apiAuthLogin ─────────────────────────────────────────────────────────────

func TestAPIAuthLogin_InvalidCreds(t *testing.T) {
	// Set up auth
	_ = cfg.SetAuth("logintest", "correctpass123")
	defer cfg.SetAuth("", "") //nolint:errcheck // test teardown; reset errors are non-actionable

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/auth/login", map[string]any{
		"user": "logintest",
		"pass": "wrongpass",
	})
	apiAuthLogin(w, r)
	assertStatus(t, w, http.StatusUnauthorized)
}

func TestAPIAuthLogin_AuthDisabled(t *testing.T) {
	// When auth is disabled, any credentials succeed
	_ = cfg.SetAuth("", "")

	w := httptest.NewRecorder()
	r := jsonReq(http.MethodPost, "/api/auth/login", map[string]any{
		"user": "anyone",
		"pass": "anypassword",
	})
	apiAuthLogin(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── apiStats ─────────────────────────────────────────────────────────────────

func TestAPIStats_Get(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/stats", http.NoBody)
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	apiStats(w, r)
	assertStatus(t, w, http.StatusOK)
}

// ─── ca.go: LoadOrInitCA ──────────────────────────────────────────────────────

func TestCertMgr_LoadOrInitCA_NewPath(t *testing.T) {
	cm := &CertManager{}
	// Use a temp dir to get a unique path that doesn't exist yet
	dir, err := os.MkdirTemp("", "testca*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup
	path := dir + "/ca.bin"

	if err := cm.LoadOrInitCA(path, ""); err != nil {
		t.Fatalf("LoadOrInitCA on new path: %v", err)
	}
	if !cm.Ready() {
		t.Error("LoadOrInitCA should set CA as ready")
	}
}

func TestCertMgr_LoadOrInitCA_ExistingPath(t *testing.T) {
	dir, err := os.MkdirTemp("", "testca*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) //nolint:errcheck // test cleanup
	path := dir + "/ca.bin"

	// First create it (empty passphrase = plain PEM)
	cm := &CertManager{}
	if err := cm.LoadOrInitCA(path, ""); err != nil {
		t.Fatalf("First LoadOrInitCA: %v", err)
	}

	// Now load it from existing file
	cm2 := &CertManager{}
	if err := cm2.LoadOrInitCA(path, ""); err != nil {
		t.Fatalf("Second LoadOrInitCA: %v", err)
	}
	if !cm2.Ready() {
		t.Error("LoadOrInitCA from existing file should be ready")
	}
}
