package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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
		cidr   string
		ip     string
		want   bool
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
	// Schedule covering all 7 days with a wide time window — should always match.
	s := &PolicySchedule{
		Days:      []string{"Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"},
		TimeStart: "00:00",
		TimeEnd:   "23:59",
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

func TestPolicyStore_SaveWithoutPath(t *testing.T) {
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

func TestSSLBypassMatcher_GlobMatches(t *testing.T) {
	m := &SSLBypassMatcher{}
	_ = m.Add("*.corp.local")
	_ = m.Add("exact.example.com")

	cases := []struct {
		host string
		want bool
	}{
		{"app.corp.local", true},
		{"corp.local", true},       // apex
		{"other.example.com", false},
		{"exact.example.com", true},
		{"sub.exact.example.com", true}, // matchFQDN: bare domain also matches subdomains (Palo Alto style)
		{"unrelated.com", false},
	}
	for _, c := range cases {
		got := m.Matches(c.host)
		if got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestSSLBypassMatcher_RegexMatches(t *testing.T) {
	m := &SSLBypassMatcher{}
	if err := m.Add(`~^.*\.gov\.il$`); err != nil {
		t.Fatalf("Add regex: %v", err)
	}

	cases := []struct {
		host string
		want bool
	}{
		{"gov.il", false},               // doesn't have a subdomain prefix
		{"tax.gov.il", true},
		{"deep.sub.gov.il", true},
		{"evil-gov.il", false},
	}
	for _, c := range cases {
		got := m.Matches(c.host)
		if got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestSSLBypassMatcher_Set(t *testing.T) {
	m := &SSLBypassMatcher{}
	_ = m.Add("old.com")

	if err := m.Set([]string{"new1.com", "new2.com"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	list := m.List()
	if len(list) != 2 || list[0] != "new1.com" || list[1] != "new2.com" {
		t.Errorf("unexpected list after Set: %v", list)
	}
}

func TestSSLBypassMatcher_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	_ = os.WriteFile(path, []byte("bad json"), 0o600)

	m := &SSLBypassMatcher{}
	if err := m.Load(path); err == nil {
		t.Error("expected error for invalid JSON")
	}
}

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
