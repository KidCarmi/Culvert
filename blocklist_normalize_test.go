package main

// blocklist_normalize_test.go — coverage for normalizeBlocklistLine, the
// /etc/hosts-format feed parsing fix, per-feed attribution, and the
// load-time repair of entries stored verbatim by pre-normalization imports
// ("0.0.0.0 ads.example" rows that could never match a request host).

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeBlocklistLine(t *testing.T) {
	cases := []struct {
		in     string
		want   string
		wantOK bool
	}{
		// Plain domain lists.
		{"example.com", "example.com", true},
		{"  spaces.net  ", "spaces.net", true},
		{"UPPER.COM", "upper.com", true},
		{"*.wild.org", "*.wild.org", true},
		{"https://stripped.com/path?q=1", "stripped.com", true},
		{"host.com:8080", "host.com", true},
		// Comments and blanks.
		{"", "", false},
		{"# comment", "", false},
		{"ads.example # inline comment", "ads.example", true},
		// /etc/hosts format (StevenBlack et al).
		{"0.0.0.0 ads.example", "ads.example", true},
		{"127.0.0.1 tracker.example", "tracker.example", true},
		{"0.0.0.0 ads.example # comment", "ads.example", true},
		{"0.0.0.0\tads.tabbed.example", "ads.tabbed.example", true},
		// Hosts-file boilerplate must be skipped, not blocked.
		{"127.0.0.1 localhost", "", false},
		{"127.0.0.1 localhost.localdomain", "", false},
		{"255.255.255.255 broadcasthost", "", false},
		{"::1 ip6-localhost", "", false},
		{"ff02::1 ip6-allnodes", "", false},
		// Unblockable IP targets.
		{"0.0.0.0 0.0.0.0", "", false},
		{"0.0.0.0", "", false},
		{"127.0.0.1", "", false},
		// A public IP entry is a legitimate block target.
		{"203.0.113.7", "203.0.113.7", true},
		{"0.0.0.0 203.0.113.7", "203.0.113.7", true},
		// FQDN trailing dot canonicalized away.
		{"example.com.", "example.com", true},
		{"0.0.0.0 ads.example.", "ads.example", true},
		{".", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeBlocklistLine(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("normalizeBlocklistLine(%q) = (%q, %v); want (%q, %v)",
				tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestMergeFromLines_HostsFileFormat(t *testing.T) {
	b := newBlocklist()
	added := b.MergeFromLines([]string{
		"# StevenBlack-style header",
		"127.0.0.1 localhost",
		"0.0.0.0 0.0.0.0",
		"0.0.0.0 ads.hosts-format.invalid",
		"0.0.0.0 tracker.hosts-format.invalid",
		"plain.domain.invalid",
	}, "")
	if added != 3 {
		t.Errorf("added = %d; want 3 (two hosts-format + one plain)", added)
	}
	if !b.isListed("ads.hosts-format.invalid") {
		t.Error("ads.hosts-format.invalid should be blockable after hosts-format normalization")
	}
	if b.isListed("0.0.0.0 ads.hosts-format.invalid") {
		t.Error("verbatim hosts-format line must NOT be stored as an entry")
	}
	if b.isListed("localhost") {
		t.Error("hosts-file boilerplate (localhost) must not be imported")
	}
}

func TestMergeFromLines_FeedAttribution(t *testing.T) {
	b := newBlocklist()
	b.manual = map[string]bool{}
	b.AddManual("manual.attr.invalid")

	const feed = "https://feeds.example/attr.txt"
	b.MergeFromLines([]string{"fed.attr.invalid", "manual.attr.invalid", "*.wild.attr.invalid"}, feed)

	entries := b.ListWithSource()
	byHost := map[string]BlocklistEntry{}
	for _, e := range entries {
		byHost[e.Host] = e
	}
	if e := byHost["fed.attr.invalid"]; e.Source != "feed" || e.Feed != feed {
		t.Errorf("fed.attr.invalid = %+v; want source=feed, feed=%s", e, feed)
	}
	if e := byHost["*.wild.attr.invalid"]; e.Source != "feed" || e.Feed != feed {
		t.Errorf("*.wild.attr.invalid = %+v; want source=feed, feed=%s", e, feed)
	}
	// Admin-added entries keep their badge and never gain feed attribution.
	if e := byHost["manual.attr.invalid"]; e.Source != "manual" || e.Feed != "" {
		t.Errorf("manual.attr.invalid = %+v; want source=manual, no feed", e)
	}
}

// TestBlocklistLoad_RepairsPreNormalizationEntries: a main file written by
// the pre-fix importer contains verbatim "0.0.0.0 domain" rows and junk
// "0.0.0.0 0.0.0.0" rows. Load must repair the former into blockable
// hostnames and drop the latter.
func TestBlocklistLoad_RepairsPreNormalizationEntries(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	old := "0.0.0.0 broken-a.invalid\n" +
		"0.0.0.0 broken-b.invalid\n" +
		"0.0.0.0 0.0.0.0\n" +
		"127.0.0.1 localhost\n" +
		"clean.invalid\n" +
		"*.wild.invalid\n"
	if err := os.WriteFile(path, []byte(old), 0o600); err != nil {
		t.Fatalf("write old-format blocklist: %v", err)
	}

	b := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !b.isListed("broken-a.invalid") || !b.isListed("broken-b.invalid") {
		t.Error("hosts-format rows must be repaired into blockable hostnames")
	}
	if b.isListed("0.0.0.0 broken-a.invalid") {
		t.Error("verbatim hosts-format row must not survive Load")
	}
	if b.isListed("localhost") || b.isListed("0.0.0.0") {
		t.Error("boilerplate/unspecified rows must be dropped on Load")
	}
	if !b.isListed("clean.invalid") || !b.isListed("sub.wild.invalid") {
		t.Error("clean rows must load unchanged")
	}
	if got := b.Count(); got != 4 {
		t.Errorf("Count = %d; want 4 (broken-a, broken-b, clean, *.wild)", got)
	}

	// Save rewrites the file clean; a fresh Load needs no repairs.
	b.Save()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read saved blocklist: %v", err)
	}
	for _, bad := range []string{"0.0.0.0", "localhost"} {
		if containsLine(string(data), bad) {
			t.Errorf("saved file still contains %q:\n%s", bad, data)
		}
	}
}

// containsLine reports whether any line equals needle or starts with
// "needle " (a verbatim hosts-format row). splitLines lives in
// blocklist_addmanual_persist_test.go (same package).
func containsLine(data, needle string) bool {
	for _, l := range splitLines(data) {
		if l == needle || (len(l) > len(needle) && l[:len(needle)+1] == needle+" ") {
			return true
		}
	}
	return false
}

// TestMergeFromLines_AttributionOnlySyncPersists: a re-sync that adds no
// new hosts but stamps attribution on already-listed entries (repaired by
// Load, or imported before the .sources sidecar existed) must still write
// the sidecar — attribution may not be memory-only (Codex P2, PR #438).
// The follow-up no-change sync must NOT rewrite the files.
func TestMergeFromLines_AttributionOnlySyncPersists(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	// Pre-existing entry with no attribution (pre-sidecar import).
	if err := os.WriteFile(path, []byte("preexisting.attr.invalid\n"), 0o600); err != nil {
		t.Fatalf("seed blocklist: %v", err)
	}

	const feed = "https://feeds.example/retro.txt"
	b := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Re-sync: same host, nothing new — only attribution changes.
	if added := b.MergeFromLines([]string{"preexisting.attr.invalid"}, feed); added != 0 {
		t.Fatalf("added = %d; want 0 (host already listed)", added)
	}
	data, err := os.ReadFile(path + ".sources")
	if err != nil {
		t.Fatalf(".sources not written on attribution-only sync: %v", err)
	}
	var sources map[string]string
	if err := json.Unmarshal(data, &sources); err != nil {
		t.Fatalf("unmarshal .sources: %v", err)
	}
	if sources["preexisting.attr.invalid"] != feed {
		t.Errorf(".sources = %v; want preexisting.attr.invalid → %s", sources, feed)
	}

	// Steady state: re-sync with identical content must not rewrite.
	before, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat main file: %v", err)
	}
	if added := b.MergeFromLines([]string{"preexisting.attr.invalid"}, feed); added != 0 {
		t.Fatalf("steady-state added = %d; want 0", added)
	}
	after, err := os.Stat(path)
	if err != nil {
		t.Fatalf("re-stat main file: %v", err)
	}
	if !after.ModTime().Equal(before.ModTime()) {
		t.Error("steady-state re-sync rewrote the main file; expected no save when nothing changed")
	}
}

// TestBlocklistSources_PersistRoundTrip: feed attribution survives a
// Save + Load cycle via the .sources sidecar, and removed hosts are
// pruned from it.
func TestBlocklistSources_PersistRoundTrip(t *testing.T) {
	ensureBlocklistStartupTestLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("seed empty blocklist: %v", err)
	}

	const feed = "https://feeds.example/persist.txt"
	b := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	b.MergeFromLines([]string{"keep.persist.invalid", "gone.persist.invalid"}, feed)
	b.Remove("gone.persist.invalid")
	b.Save()

	b2 := &Blocklist{
		exact: map[string]bool{}, wildcards: map[string]bool{},
		manual: map[string]bool{}, exceptions: map[string]bool{},
	}
	if err := b2.Load(path); err != nil {
		t.Fatalf("re-Load: %v", err)
	}
	entries := b2.ListWithSource()
	if len(entries) != 1 {
		t.Fatalf("entries = %+v; want only keep.persist.invalid", entries)
	}
	if entries[0].Host != "keep.persist.invalid" || entries[0].Feed != feed {
		t.Errorf("entry = %+v; want keep.persist.invalid attributed to %s", entries[0], feed)
	}
}
