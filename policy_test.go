package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── matchFQDN ────────────────────────────────────────────────────────────────

func TestMatchFQDN(t *testing.T) {
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Wildcard star — matches everything.
		{"*", "anything.example.com", true},
		{"*", "example.com", true},

		// Wildcard prefix *.example.com — subdomains and apex.
		{"*.example.com", "www.example.com", true},
		{"*.example.com", "deep.sub.example.com", true},
		{"*.example.com", "example.com", true}, // apex
		{"*.example.com", "notexample.com", false},
		{"*.example.com", "evil-example.com", false},

		// Palo Alto style: bare domain matches apex AND subdomains.
		{"example.com", "example.com", true},
		{"example.com", "www.example.com", true},
		{"example.com", "deep.www.example.com", true},
		{"example.com", "notexample.com", false},

		// Trailing dot tolerance.
		{"example.com.", "example.com", true},
		{"example.com", "example.com.", true},

		// Case-insensitivity.
		{"Example.COM", "example.com", true},
		{"*.EXAMPLE.COM", "sub.example.com", true},

		// 1.2 fix: IDNA normalization — Punycode hosts must match ASCII rules.
		{"example.com", "xn--exmple-cua.com", false}, // punycode host ≠ example.com
		{"münchen.de", "xn--mnchen-3ya.de", true},    // both normalize to punycode
		{"xn--mnchen-3ya.de", "münchen.de", true},    // reverse also matches
	}
	for _, c := range cases {
		got := matchFQDN(c.pattern, c.host)
		if got != c.want {
			t.Errorf("matchFQDN(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

// ─── matchIPOrCIDR ────────────────────────────────────────────────────────────

func TestMatchIPOrCIDR(t *testing.T) {
	cases := []struct {
		cidr string
		ip   string
		want bool
	}{
		// Exact IP match.
		{"192.168.1.1", "192.168.1.1", true},
		{"192.168.1.1", "192.168.1.2", false},

		// CIDR match.
		{"10.0.0.0/8", "10.1.2.3", true},
		{"10.0.0.0/8", "11.0.0.1", false},
		{"192.168.1.0/24", "192.168.1.100", true},
		{"192.168.1.0/24", "192.168.2.1", false},

		// Invalid CIDR returns false (no panic).
		{"not-a-cidr/xx", "1.2.3.4", false},
	}
	for _, c := range cases {
		got := matchIPOrCIDR(c.cidr, c.ip)
		if got != c.want {
			t.Errorf("matchIPOrCIDR(%q, %q) = %v, want %v", c.cidr, c.ip, got, c.want)
		}
	}
}

// ─── matchCategory ────────────────────────────────────────────────────────────

func TestMatchCategory(t *testing.T) {
	cases := []struct {
		cat  URLCategory
		host string
		want bool
	}{
		{CategorySocial, "facebook.com", true},
		{CategorySocial, "www.facebook.com", true},
		{CategorySocial, "sub.twitter.com", true},
		{CategorySocial, "google.com", false},

		{CategoryStreaming, "netflix.com", true},
		{CategoryStreaming, "youtube.com", true},
		{CategoryStreaming, "example.com", false},

		{CategoryNews, "bbc.com", true},
		{CategoryNews, "www.bbc.co.uk", true},
		{CategoryNews, "evil.com", false},

		// Unknown category → false.
		{"UnknownCat", "anything.com", false},
	}
	for _, c := range cases {
		got := matchCategory(c.cat, c.host)
		if got != c.want {
			t.Errorf("matchCategory(%q, %q) = %v, want %v", c.cat, c.host, got, c.want)
		}
	}
}

// ─── matchSchedule ────────────────────────────────────────────────────────────

func TestMatchSchedule_Nil(t *testing.T) {
	if !matchSchedule(nil) {
		t.Error("nil schedule should always match")
	}
}

func TestMatchSchedule_EmptySchedule(t *testing.T) {
	s := &PolicySchedule{}
	if !matchSchedule(s) {
		t.Error("empty schedule should always match")
	}
}

func TestMatchSchedule_AllDays(t *testing.T) {
	// Schedule covering all 7 days with a full-day window — should always match.
	//
	// The end bound is "24:00", NOT "23:59". scheduleTimeMatch is half-open
	// (cur >= start && cur < end) and parseClockMinutes documents "24:00" as the
	// exclusive end-of-day bound a full-day window closes with, so "23:59"
	// excludes the 23:59 minute itself. Written that way this test asserted
	// "always matches" against a window that genuinely does not cover 1439 of
	// the day's 1440 minutes, and failed for one minute out of every day.
	s := &PolicySchedule{
		Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		TimeStart: "00:00",
		TimeEnd:   "24:00",
	}
	if !matchSchedule(s) {
		t.Error("all-day all-week schedule should match")
	}
}

// ─── FileProfileBlocked ───────────────────────────────────────────────────────

func TestFileProfileBlocked(t *testing.T) {
	cases := []struct {
		profile  FileProfileName
		path     string
		enabled  bool
		expected bool
	}{
		// Disabled — never blocks.
		{FileProfileExecutables, "/file.exe", false, false},

		// Executables profile.
		{FileProfileExecutables, "/malware.exe", true, true},
		{FileProfileExecutables, "/script.ps1", true, true},
		{FileProfileExecutables, "/document.pdf", true, false},
		{FileProfileExecutables, "/image.png", true, false},

		// Archives profile.
		{FileProfileArchives, "/archive.zip", true, true},
		{FileProfileArchives, "/archive.tar", true, true},
		{FileProfileArchives, "/archive.7z", true, true},
		{FileProfileArchives, "/file.exe", true, false},

		// Documents (macro-enabled) profile.
		{FileProfileDocuments, "/macro.xlsm", true, true},
		{FileProfileDocuments, "/macro.docm", true, true},
		{FileProfileDocuments, "/plain.docx", true, false},

		// Media profile.
		{FileProfileMedia, "/video.mp4", true, true},
		{FileProfileMedia, "/audio.mp3", true, true},
		{FileProfileMedia, "/image.jpg", true, false},

		// Strict profile includes executables and archives.
		{FileProfileStrict, "/malware.exe", true, true},
		{FileProfileStrict, "/archive.zip", true, true},
		{FileProfileStrict, "/macro.docm", true, true},
		{FileProfileStrict, "/text.txt", true, false},

		// No extension → not blocked.
		{FileProfileExecutables, "/no-extension", true, false},

		// None profile — never blocks even when enabled.
		{FileProfileNone, "/file.exe", true, false},

		// Case-insensitivity.
		{FileProfileExecutables, "/MALWARE.EXE", true, true},
		{FileProfileExecutables, "/Script.PS1", true, true},

		// Path with directories.
		{FileProfileExecutables, "/path/to/file.exe", true, true},
	}
	for _, c := range cases {
		rule := &PolicyRule{
			FileFiltering: c.enabled,
			FileProfile:   c.profile,
		}
		got := rule.FileProfileBlocked(c.path)
		if got != c.expected {
			t.Errorf("FileProfileBlocked(profile=%q, path=%q, enabled=%v) = %v, want %v",
				c.profile, c.path, c.enabled, got, c.expected)
		}
	}
}

// ─── PolicyStore CRUD ─────────────────────────────────────────────────────────

func newTestPolicyStore() *PolicyStore {
	return &PolicyStore{}
}

func TestPolicyStore_AddListDelete(t *testing.T) {
	ps := newTestPolicyStore()

	r1 := ps.Add(PolicyRule{Priority: 10, Name: "allow-all", Action: ActionAllow})
	r2 := ps.Add(PolicyRule{Priority: 5, Name: "block-social", Action: ActionDrop})

	list := ps.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 rules, got %d", len(list))
	}
	// Must be sorted by priority (5 < 10).
	if list[0].Priority != 5 || list[1].Priority != 10 {
		t.Errorf("rules not sorted: got priorities %d, %d", list[0].Priority, list[1].Priority)
	}

	// Delete by priority.
	if !ps.Delete(r2.Priority) {
		t.Error("Delete should return true for existing rule")
	}
	if ps.Delete(999) {
		t.Error("Delete should return false for non-existent priority")
	}
	list = ps.List()
	if len(list) != 1 || list[0].Name != "allow-all" {
		t.Errorf("unexpected list after delete: %+v", list)
	}
	_ = r1
}

func TestPolicyStore_Update(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, Name: "original", Action: ActionAllow})

	ok := ps.Update(1, PolicyRule{Priority: 1, Name: "updated", Action: ActionDrop})
	if !ok {
		t.Fatal("Update should return true for existing priority")
	}
	list := ps.List()
	if list[0].Name != "updated" || list[0].Action != ActionDrop {
		t.Errorf("unexpected rule after update: %+v", list[0])
	}

	// Update non-existent priority.
	if ps.Update(999, PolicyRule{}) {
		t.Error("Update should return false for missing priority")
	}
}

func TestPolicyStore_Reorder(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, Name: "first"})
	ps.Add(PolicyRule{Priority: 2, Name: "second"})
	ps.Add(PolicyRule{Priority: 3, Name: "third"})

	// Reverse the order: [3,2,1] → new priorities [1,2,3] for old rules 3,2,1.
	ok := ps.Reorder([]int{3, 2, 1})
	if !ok {
		t.Fatal("Reorder should succeed")
	}
	list := ps.List()
	if list[0].Name != "third" || list[1].Name != "second" || list[2].Name != "first" {
		t.Errorf("unexpected order after reorder: %v %v %v", list[0].Name, list[1].Name, list[2].Name)
	}

	// Wrong length → false.
	if ps.Reorder([]int{1}) {
		t.Error("Reorder with wrong length should return false")
	}
}

func TestPolicyStore_LoadSave(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	// Create a store, set its path via Load (missing file is ok), add rules, save.
	ps := newTestPolicyStore()
	if err := ps.Load(path); err != nil {
		t.Fatalf("Load on missing file: %v", err)
	}
	ps.Add(PolicyRule{Priority: 1, Name: "first", Action: ActionAllow})
	ps.Add(PolicyRule{Priority: 2, Name: "second", Action: ActionDrop})
	ps.Save()

	// Load into a fresh store and verify round-trip.
	ps2 := newTestPolicyStore()
	if err := ps2.Load(path); err != nil {
		t.Fatalf("Load after Save: %v", err)
	}
	list := ps2.List()
	if len(list) != 2 {
		t.Fatalf("expected 2 rules after load, got %d", len(list))
	}
	if list[0].Name != "first" || list[1].Name != "second" {
		t.Errorf("unexpected names: %q, %q", list[0].Name, list[1].Name)
	}
}

func TestPolicyStore_LoadMissingFile(t *testing.T) {
	ps := newTestPolicyStore()
	if err := ps.Load("/nonexistent/path/policy.json"); err != nil {
		t.Errorf("Load of missing file should not return error, got: %v", err)
	}
}

func TestPolicyStore_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	ps := newTestPolicyStore()
	if err := ps.Load(path); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestPolicyStore_SaveWithoutPath(_ *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, Name: "test"})
	// Should not panic when path is empty.
	ps.Save()
}

// ─── PolicyStore.Evaluate ─────────────────────────────────────────────────────

func TestPolicyStore_Evaluate_FirstMatch(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, Name: "block-social", DestCategory: CategorySocial, Action: ActionDrop})
	ps.Add(PolicyRule{Priority: 2, Name: "allow-all", Action: ActionAllow})

	// facebook.com → social → blocked by priority-1 rule.
	m := ps.Evaluate("1.2.3.4", "", "unauth", "www.facebook.com", nil)
	if m == nil {
		t.Fatal("expected a match")
	}
	if m.Action != ActionDrop {
		t.Errorf("expected Drop, got %v", m.Action)
	}
	if m.Rule.Name != "block-social" {
		t.Errorf("expected rule 'block-social', got %q", m.Rule.Name)
	}

	// google.com → not social → falls through to allow-all.
	m = ps.Evaluate("1.2.3.4", "", "unauth", "google.com", nil)
	if m == nil {
		t.Fatal("expected a match")
	}
	if m.Action != ActionAllow {
		t.Errorf("expected Allow, got %v", m.Action)
	}
}

func TestPolicyStore_Evaluate_NoMatch(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, Name: "block-fb", DestFQDN: "facebook.com", Action: ActionDrop})

	m := ps.Evaluate("1.2.3.4", "", "unauth", "google.com", nil)
	if m != nil {
		t.Errorf("expected nil match, got %+v", m)
	}
}

func TestPolicyStore_Evaluate_SourceIP(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority: 1,
		Name:     "hr-only",
		SourceIP: "10.10.0.0/16",
		Action:   ActionAllow,
	})

	// IP in range → match.
	m := ps.Evaluate("10.10.5.1", "", "unauth", "anything.com", nil)
	if m == nil || m.Action != ActionAllow {
		t.Errorf("expected Allow for IP in CIDR, got %v", m)
	}

	// IP outside range → no match.
	m = ps.Evaluate("10.20.5.1", "", "unauth", "anything.com", nil)
	if m != nil {
		t.Errorf("expected no match for IP outside CIDR, got %+v", m)
	}
}

func TestPolicyStore_Evaluate_SourceIdentity(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:       1,
		SourceIdentity: "alice",
		Action:         ActionAllow,
	})

	m := ps.Evaluate("", "alice", "local", "any.com", nil)
	if m == nil || m.Action != ActionAllow {
		t.Error("expected match for alice")
	}

	m = ps.Evaluate("", "bob", "local", "any.com", nil)
	if m != nil {
		t.Error("expected no match for bob")
	}
}

func TestPolicyStore_Evaluate_Groups(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:    1,
		SourceGroup: "admins",
		Action:      ActionAllow,
	})

	m := ps.Evaluate("", "", "ldap", "any.com", []string{"users", "admins"})
	if m == nil || m.Action != ActionAllow {
		t.Error("expected match for group member")
	}

	m = ps.Evaluate("", "", "ldap", "any.com", []string{"users"})
	if m != nil {
		t.Error("expected no match when group not present")
	}
}

func TestPolicyStore_Evaluate_GroupsTrimSpace(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:    1,
		SourceGroup: " admins ",
		Action:      ActionAllow,
	})

	m := ps.Evaluate("", "", "saml:corp", "any.com", []string{" users ", " admins\t"})
	if m == nil || m.Action != ActionAllow {
		t.Error("expected match for group member with surrounding whitespace")
	}
}

func TestPolicyStore_Evaluate_AuthSourceLegacyIdPAlias(t *testing.T) {
	tests := []struct {
		name       string
		ruleSource string
		authSource string
		wantMatch  bool
	}{
		{name: "canonical matches legacy oidc rule", ruleSource: "oidc:profile-id", authSource: "profile-id", wantMatch: true},
		{name: "legacy oidc matches canonical rule", ruleSource: "profile-id", authSource: "oidc:profile-id", wantMatch: true},
		{name: "canonical matches legacy saml rule", ruleSource: "saml:profile-id", authSource: "profile-id", wantMatch: true},
		{name: "different provider does not match", ruleSource: "oidc:other-id", authSource: "profile-id", wantMatch: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ps := newTestPolicyStore()
			ps.Add(PolicyRule{
				Priority:   1,
				AuthSource: tt.ruleSource,
				Action:     ActionAllow,
			})
			got := ps.Evaluate("", "", tt.authSource, "any.com", nil) != nil
			if got != tt.wantMatch {
				t.Fatalf("match = %v, want %v", got, tt.wantMatch)
			}
		})
	}
}

func TestPolicyStore_Evaluate_HitCount(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, Name: "count-me", Action: ActionAllow})

	for i := 0; i < 3; i++ {
		ps.Evaluate("1.2.3.4", "", "unauth", "example.com", nil)
	}
	list := ps.List()
	if list[0].HitCount != 3 {
		t.Errorf("expected HitCount=3, got %d", list[0].HitCount)
	}
}

func TestPolicyStore_Evaluate_FQDNMatch(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, DestFQDN: "*.corp.local", Action: ActionAllow})

	cases := []struct {
		host string
		want bool
	}{
		{"app.corp.local", true},
		{"deep.app.corp.local", true},
		{"corp.local", true},
		{"evil.corp.local.attacker.com", false},
	}
	for _, c := range cases {
		m := ps.Evaluate("", "", "", c.host, nil)
		matched := m != nil
		if matched != c.want {
			t.Errorf("Evaluate(host=%q): matched=%v, want %v", c.host, matched, c.want)
		}
	}
}

// ─── SSLBypassMatcher ─────────────────────────────────────────────────────────

// The SSLBypassMatcher engine tests (glob/regex/Set/LoadInvalidJSON) moved to
// internal/sslbypass (ADR-0002, policy.go decomposition Phase B).

// ─── PolicyStore.Save — HitCount not persisted ────────────────────────────────

func TestPolicyStore_SaveNoHitCount(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")

	ps := newTestPolicyStore()
	if err := ps.Load(path); err != nil {
		t.Fatal(err)
	}
	ps.Add(PolicyRule{Priority: 1, Name: "tracked"})
	// Simulate 5 hits.
	ps.Evaluate("", "", "", "any.com", nil)
	ps.Evaluate("", "", "", "any.com", nil)
	ps.Evaluate("", "", "", "any.com", nil)
	ps.Evaluate("", "", "", "any.com", nil)
	ps.Evaluate("", "", "", "any.com", nil)

	ps.Save()

	// Reload and check HitCount is zero.
	data, _ := os.ReadFile(path)
	var rules []PolicyRule
	if err := json.Unmarshal(data, &rules); err != nil {
		t.Fatal(err)
	}
	if rules[0].HitCount != 0 {
		t.Errorf("HitCount should not be persisted, got %d", rules[0].HitCount)
	}
}

// ─── Edge-case tests ─────────────────────────────────────────────────────────

func TestMatchSchedule_OvernightInside(t *testing.T) {
	// Construct an overnight schedule (TimeStart > TimeEnd) where the current
	// UTC time falls inside the active window. The overnight condition:
	//   match when cur >= TimeStart OR cur < TimeEnd
	now := time.Now().UTC()
	cur := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())

	// For overnight (start > end), the active window is [start,24:00) ∪ [00:00,end).
	// Place TimeStart 1 hour before now. For overnight we need startStr > endStr,
	// so set endHour = startHour - 1 (wrapping). This gives a 23-hour wide window
	// that includes the current time.
	startHour := (now.Hour() - 1 + 24) % 24
	endHour := (now.Hour() - 2 + 24) % 24
	startStr := fmt.Sprintf("%02d:00", startHour)
	endStr := fmt.Sprintf("%02d:00", endHour)

	// Verify this is actually an overnight schedule (start > end).
	if startStr <= endStr {
		t.Skip("could not construct overnight schedule for this UTC hour")
	}

	s := &PolicySchedule{
		Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		TimeStart: startStr,
		TimeEnd:   endStr,
		Timezone:  "UTC",
	}
	got := matchSchedule(s)
	if !got {
		t.Errorf("matchSchedule(overnight %s–%s UTC) at %s should match (inside window)", startStr, endStr, cur)
	}
}

func TestMatchSchedule_OvernightOutside(t *testing.T) {
	// Construct an overnight schedule (TimeStart > TimeEnd) where the current
	// UTC time falls outside the active window.
	now := time.Now().UTC()
	cur := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())

	// Place TimeStart 2 hours ahead, TimeEnd 2 hours behind.
	// Current time is in the "dead zone" between end and start.
	startHour := (now.Hour() + 2) % 24
	endHour := (now.Hour() - 2 + 24) % 24
	startStr := fmt.Sprintf("%02d:00", startHour)
	endStr := fmt.Sprintf("%02d:00", endHour)

	// Verify this is actually overnight (start > end).
	if startStr <= endStr {
		t.Skip("could not construct overnight schedule for this UTC hour")
	}

	s := &PolicySchedule{
		Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		TimeStart: startStr,
		TimeEnd:   endStr,
		Timezone:  "UTC",
	}
	got := matchSchedule(s)
	if got {
		t.Errorf("matchSchedule(overnight %s–%s UTC) at %s should NOT match (outside window)", startStr, endStr, cur)
	}
}

func TestMatchSchedule_BoundaryEndExclusive(t *testing.T) {
	// TimeEnd is exclusive (>= comparison). When cur == TimeEnd the schedule
	// should NOT match. Construct a normal range ending exactly at the current minute.
	now := time.Now().UTC()
	cur := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())

	// Normal range: some earlier start, end = now.
	startHour := (now.Hour() - 2 + 24) % 24
	startStr := fmt.Sprintf("%02d:00", startHour)

	// Must be a normal range (start <= end).
	if startStr > cur {
		t.Skip("cannot construct normal range at this UTC hour")
	}

	s := &PolicySchedule{
		Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		TimeStart: startStr,
		TimeEnd:   cur,
		Timezone:  "UTC",
	}
	got := matchSchedule(s)
	if got {
		t.Errorf("matchSchedule with TimeEnd=%s at cur=%s should NOT match (end is exclusive)", cur, cur)
	}
}

func TestMatchSchedule_BoundaryStartInclusive(t *testing.T) {
	// TimeStart is inclusive. When cur == TimeStart the schedule should match.
	now := time.Now().UTC()
	cur := fmt.Sprintf("%02d:%02d", now.Hour(), now.Minute())

	// Normal range: start = now, end = 1 minute later.
	endMin := (now.Minute() + 1) % 60
	endHour := now.Hour()
	if endMin == 0 {
		endHour = (endHour + 1) % 24
	}
	endStr := fmt.Sprintf("%02d:%02d", endHour, endMin)

	// Must be a normal range (start <= end).
	if cur > endStr {
		t.Skip("cannot construct normal range at this exact minute")
	}

	s := &PolicySchedule{
		Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		TimeStart: cur,
		TimeEnd:   endStr,
		Timezone:  "UTC",
	}
	got := matchSchedule(s)
	if !got {
		t.Errorf("matchSchedule at exactly TimeStart=%s (end=%s) should match (start is inclusive)", cur, endStr)
	}
}

func TestEvaluate_MultiConditionAND(t *testing.T) {
	// Rule requires BOTH DestFQDN AND DestCategory to match (AND logic).
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:     1,
		Name:         "social-facebook-only",
		DestFQDN:     "facebook.com",
		DestCategory: CategorySocial,
		Action:       ActionDrop,
	})

	// facebook.com is in the Social category — both conditions met — match.
	m := ps.Evaluate("", "", "", "facebook.com", nil)
	if m == nil || m.Action != ActionDrop {
		t.Error("expected Drop when both FQDN and category match")
	}

	// twitter.com IS Social but does NOT match DestFQDN "facebook.com" — no match.
	m = ps.Evaluate("", "", "", "twitter.com", nil)
	if m != nil {
		t.Errorf("expected no match for twitter.com (FQDN mismatch despite correct category), got %+v", m)
	}

	// google.com matches neither FQDN nor category — no match.
	m = ps.Evaluate("", "", "", "google.com", nil)
	if m != nil {
		t.Errorf("expected no match for google.com, got %+v", m)
	}

	// netflix.com is Streaming, not Social — FQDN also doesn't match — no match.
	m = ps.Evaluate("", "", "", "netflix.com", nil)
	if m != nil {
		t.Errorf("expected no match for netflix.com (wrong category), got %+v", m)
	}
}

func TestMatchFQDN_EmptyHost(t *testing.T) {
	// Empty host should not match domain/wildcard patterns.
	cases := []struct {
		pattern string
		host    string
		want    bool
	}{
		// Universal wildcard matches even empty host.
		{"*", "", true},
		// Wildcard prefix should not match empty host.
		{"*.example.com", "", false},
		// Bare domain should not match empty host.
		{"example.com", "", false},
	}
	for _, c := range cases {
		got := matchFQDN(c.pattern, c.host)
		if got != c.want {
			t.Errorf("matchFQDN(%q, %q) = %v, want %v", c.pattern, c.host, got, c.want)
		}
	}
}

func TestReorder_DuplicatePriorities(t *testing.T) {
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{Priority: 1, Name: "first"})
	ps.Add(PolicyRule{Priority: 2, Name: "second"})
	ps.Add(PolicyRule{Priority: 3, Name: "third"})

	// Duplicate values in orderedPriorities — priority 1 appears twice, 3 missing.
	// The function uses a map lookup so duplicate old-priorities will find the
	// same rule twice (already reassigned). It must not panic.
	ok := ps.Reorder([]int{1, 2, 1})
	_ = ok // may or may not return true; the key is no panic

	// Non-existent priority in the list should return false.
	ps2 := newTestPolicyStore()
	ps2.Add(PolicyRule{Priority: 1, Name: "first"})
	ps2.Add(PolicyRule{Priority: 2, Name: "second"})
	ok2 := ps2.Reorder([]int{1, 999})
	if ok2 {
		t.Error("Reorder with non-existent priority should return false")
	}
}

func TestPermutePriorities_DuplicatePriorityInStore(t *testing.T) {
	// Duplicate priorities can enter the store via ReplaceAll (e.g. config import).
	// PermutePriorities must return false rather than silently reassigning only the
	// last rule that shares the ambiguous priority slot.
	ps := newTestPolicyStore()
	ps.ReplaceAll([]PolicyRule{
		{Priority: 5, Name: "dup-a", Action: ActionAllow},
		{Priority: 5, Name: "dup-b", Action: ActionAllow},
		{Priority: 10, Name: "single", Action: ActionDrop},
	})

	// Swapping priorities 5 and 10 is ambiguous because two rules share priority 5.
	ok := ps.PermutePriorities([]int{10, 5})
	if ok {
		t.Errorf("PermutePriorities should return false when store has duplicate priority; got true; store: %v", ps.List())
	}
	// The store must be unchanged on failure.
	rules := ps.List()
	for _, r := range rules {
		if r.Name == "single" && r.Priority != 10 {
			t.Errorf("store mutated despite failure: 'single' priority = %d, want 10", r.Priority)
		}
	}
}

func TestEvaluate_CategoryAnyMatchesAll(t *testing.T) {
	// A rule with DestCategory="Any" should behave as "match any category"
	// (the category condition is effectively a no-op).
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:     1,
		Name:         "any-category",
		DestCategory: CategoryAny,
		Action:       ActionAllow,
	})

	// Should match any host regardless of its actual category.
	hosts := []string{"facebook.com", "google.com", "unknown-host.example", "netflix.com"}
	for _, h := range hosts {
		m := ps.Evaluate("", "", "", h, nil)
		if m == nil || m.Action != ActionAllow {
			t.Errorf("Evaluate(host=%q) with DestCategory=Any: expected Allow, got %v", h, m)
		}
	}
}

func TestEvaluate_CategoryAnyWithFQDN(t *testing.T) {
	// DestCategory="Any" combined with a specific DestFQDN — only FQDN gates.
	ps := newTestPolicyStore()
	ps.Add(PolicyRule{
		Priority:     1,
		Name:         "any-cat-fqdn",
		DestFQDN:     "specific.example.com",
		DestCategory: CategoryAny,
		Action:       ActionDrop,
	})

	// FQDN matches — should match (category Any is not checked).
	m := ps.Evaluate("", "", "", "specific.example.com", nil)
	if m == nil || m.Action != ActionDrop {
		t.Error("expected Drop for matching FQDN with CategoryAny")
	}

	// FQDN doesn't match — should NOT match.
	m = ps.Evaluate("", "", "", "other.example.com", nil)
	if m != nil {
		t.Errorf("expected no match for non-matching FQDN with CategoryAny, got %+v", m)
	}
}

// TestPolicyStore_SaveMeta_NoTmpLeak verifies the .meta sidecar writer
// (atomicWriteFile) does not leave orphaned *.tmp.* files. Save() writes
// both the primary policy file and the .meta sidecar; both now use
// atomicWriteFile (P3.2a hardened the primary write path). The assertion
// covers the whole directory, so this test transitively pins both writes.
// TestPolicyStore_Save_MainFileNoTmpLeak below pins the primary write
// path explicitly.
func TestPolicyStore_SaveMeta_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	ps := newTestPolicyStore()
	ps.path = filepath.Join(dir, "policy.json")
	ps.Add(PolicyRule{Priority: 10, Name: "tmpleak-test", Action: ActionAllow})
	ps.Save()
	assertNoTmpLeak(t, dir)
}

// TestPolicyStore_Save_MainFileNoTmpLeak pins the primary policy file's
// atomicWriteFile cleanup contract (P3.2a). Mirrors the per-store pattern
// established by TestFileBlocker_Save_NoTmpLeak and
// TestFileProfileStore_Save_NoTmpLeak.
func TestPolicyStore_Save_MainFileNoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	ps := newTestPolicyStore()
	ps.path = filepath.Join(dir, "policy.json")
	ps.Add(PolicyRule{Priority: 1, Name: "main-tmpleak-test", Action: ActionAllow})
	ps.Save()
	assertNoTmpLeak(t, dir)
}

// TestPolicyStore_Save_MetaSkippedOnMainWriteFailure pins that saveMeta is
// NOT called when the primary file write fails. Otherwise the .meta sidecar
// could record a newer version/timestamp than the rules on disk after a
// partial-write failure (ENOSPC/EIO mid-Save).
func TestPolicyStore_Save_MetaSkippedOnMainWriteFailure(t *testing.T) {
	dir := t.TempDir()
	ps := newTestPolicyStore()
	// Path under a directory that doesn't exist — atomicWriteFile fails
	// at os.CreateTemp because the parent dir is missing.
	ps.path = filepath.Join(dir, "missing", "policy.json")
	ps.Add(PolicyRule{Priority: 1, Name: "main-write-fails", Action: ActionAllow})
	ps.Save()
	if _, err := os.Stat(ps.path + ".meta"); !os.IsNotExist(err) {
		t.Fatalf(".meta sidecar must not exist when main write fails (stat err=%v)", err)
	}
}
