package blocklist

// Engine tests, moved in-package from package main's
// blocklist_normalize_test.go and blocklist_totp_extra_test.go with the
// extraction (ADR-0002, store.go decomposition Phase A). The API-handler
// integration test (cleanup-unattributed gate) stays in main.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// splitLines is a local copy of main's test helper (newline split, trailing
// empty line dropped).
func splitLines(s string) []string {
	lines := strings.Split(s, "\n")
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	return lines
}

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
		got, ok := NormalizeLine(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Errorf("NormalizeLine(%q) = (%q, %v); want (%q, %v)",
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
	b.AddManual("manual.attr.invalid")

	const feed = "https://feeds.example/attr.txt"
	b.MergeFromLines([]string{"fed.attr.invalid", "manual.attr.invalid", "*.wild.attr.invalid"}, feed)

	entries := b.ListWithSource()
	byHost := map[string]Entry{}
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

	b := New()
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
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	// Pre-existing entry with no attribution (pre-sidecar import).
	if err := os.WriteFile(path, []byte("preexisting.attr.invalid\n"), 0o600); err != nil {
		t.Fatalf("seed blocklist: %v", err)
	}

	const feed = "https://feeds.example/retro.txt"
	b := New()
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
	dir := t.TempDir()
	path := filepath.Join(dir, "blocklist.list")
	if err := os.WriteFile(path, []byte(""), 0o600); err != nil {
		t.Fatalf("seed empty blocklist: %v", err)
	}

	const feed = "https://feeds.example/persist.txt"
	b := New()
	if err := b.Load(path); err != nil {
		t.Fatalf("Load: %v", err)
	}
	b.MergeFromLines([]string{"keep.persist.invalid", "gone.persist.invalid"}, feed)
	b.Remove("gone.persist.invalid")
	b.Save()

	b2 := New()
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

// ─── Cascade delete + legacy cleanup (PR: feed-source management) ────

func newAttributedBlocklist(t *testing.T) *Store {
	t.Helper()
	b := New()
	b.MergeFromLines([]string{"a.feed-one.invalid", "*.w.feed-one.invalid"}, "https://feeds.example/one.txt")
	b.MergeFromLines([]string{"b.feed-two.invalid"}, "https://feeds.example/two.txt")
	b.MergeFromLines([]string{"legacy.orphan.invalid"}, "") // pre-attribution import
	b.AddManual("keep.manual.invalid")
	return b
}

func TestRemoveByFeedSource_CascadeDeletesOnlyThatFeed(t *testing.T) {
	b := newAttributedBlocklist(t)

	if got := b.CountByFeedSource("https://feeds.example/one.txt"); got != 2 {
		t.Errorf("CountByFeedSource(one) = %d; want 2", got)
	}
	removed := b.RemoveByFeedSource("https://feeds.example/one.txt")
	if removed != 2 {
		t.Errorf("RemoveByFeedSource(one) = %d; want 2", removed)
	}
	if b.isListed("a.feed-one.invalid") || b.isListed("x.w.feed-one.invalid") {
		t.Error("feed-one entries must be gone after cascade delete")
	}
	if !b.isListed("b.feed-two.invalid") {
		t.Error("feed-two entry must survive a feed-one cascade delete")
	}
	if !b.isListed("legacy.orphan.invalid") || !b.isListed("keep.manual.invalid") {
		t.Error("orphan and manual entries must survive a cascade delete")
	}
	if got := b.CountByFeedSource("https://feeds.example/one.txt"); got != 0 {
		t.Errorf("CountByFeedSource(one) after delete = %d; want 0", got)
	}
}

func TestRemoveByFeedSource_ManualOverlapSurvives(t *testing.T) {
	b := newAttributedBlocklist(t)
	// Host both admin-added AND present in feed-one content: manual wins.
	b.AddManual("a.feed-one.invalid")
	if removed := b.RemoveByFeedSource("https://feeds.example/one.txt"); removed != 1 {
		t.Errorf("removed = %d; want 1 (only the wildcard; manual-overlap host kept)", removed)
	}
	if !b.isListed("a.feed-one.invalid") {
		t.Error("admin-added host must survive cascade delete of its feed")
	}
}

func TestRemoveUnattributedFeedEntries_OnlyOrphans(t *testing.T) {
	b := newAttributedBlocklist(t)
	removed := b.RemoveUnattributedFeedEntries()
	if removed != 1 {
		t.Errorf("removed = %d; want 1 (only legacy.orphan.invalid)", removed)
	}
	if b.isListed("legacy.orphan.invalid") {
		t.Error("orphan must be removed")
	}
	if !b.isListed("a.feed-one.invalid") || !b.isListed("b.feed-two.invalid") {
		t.Error("attributed entries must survive orphan cleanup")
	}
	if !b.isListed("keep.manual.invalid") {
		t.Error("manual entries must survive orphan cleanup")
	}
}

// TestRestoreFeedSources_SurvivesRebuild pins the Codex P1 (PR #447) fix:
// a config-rollback-style rebuild (Remove all + Add) must not strand feed
// entries as unattributed — attribution is snapshotted and re-stamped for
// hosts that survive the rebuild.
func TestRestoreFeedSources_SurvivesRebuild(t *testing.T) {
	b := newAttributedBlocklist(t)

	snap := b.SnapshotFeedSources()
	for _, h := range b.List() {
		b.Remove(h)
	}
	// Re-add a subset, the way applyConfigBackup does (plain Add).
	b.Add("a.feed-one.invalid")
	b.Add("b.feed-two.invalid")
	b.RestoreFeedSources(snap)

	byHost := map[string]Entry{}
	for _, e := range b.ListWithSource() {
		byHost[e.Host] = e
	}
	if e := byHost["a.feed-one.invalid"]; e.Feed != "https://feeds.example/one.txt" {
		t.Errorf("a.feed-one.invalid attribution after rebuild = %+v; want feed-one", e)
	}
	if e := byHost["b.feed-two.invalid"]; e.Feed != "https://feeds.example/two.txt" {
		t.Errorf("b.feed-two.invalid attribution after rebuild = %+v; want feed-two", e)
	}
	// Hosts NOT re-added must not be resurrected into feedSrc.
	if got := b.CountByFeedSource("https://feeds.example/one.txt"); got != 1 {
		t.Errorf("CountByFeedSource(one) = %d; want 1 (wildcard not re-added)", got)
	}
}

func newBlocklist() *Store { return New() }

func TestBlocklist_MergeFromLines_Basic(t *testing.T) {
	b := newBlocklist()

	lines := []string{
		"example.com",
		"*.wildcard.org",
		"# this is a comment",
		"",
		"  spaces.net  ",
		"https://stripped.com/path?q=1",
		"http://also-stripped.net:8080/foo",
		"UPPERCASE.COM",
		"example.com", // duplicate — should not count twice
	}

	added := b.MergeFromLines(lines, "")
	// Expect: example.com, *.wildcard.org, spaces.net, stripped.com, also-stripped.net, uppercase.com = 6
	if added != 6 {
		t.Errorf("expected 6 new entries, got %d", added)
	}

	// Exact match.
	if !b.isListed("example.com") {
		t.Error("example.com should be in blocklist")
	}
	// Wildcard match.
	if !b.isListed("sub.wildcard.org") {
		t.Error("sub.wildcard.org should match *.wildcard.org")
	}
	// Stripped scheme.
	if !b.isListed("stripped.com") {
		t.Error("stripped.com should be in blocklist after scheme strip")
	}
	// Port/path stripped.
	if !b.isListed("also-stripped.net") {
		t.Error("also-stripped.net should be in blocklist")
	}
	// Case normalised.
	if !b.isListed("uppercase.com") {
		t.Error("UPPERCASE.COM should be lowercased and in blocklist")
	}

	// Merge again — all duplicates, added should be 0.
	added2 := b.MergeFromLines([]string{"example.com", "*.wildcard.org"}, "")
	if added2 != 0 {
		t.Errorf("re-merging existing entries should add 0, got %d", added2)
	}
}

func TestBlocklist_MergeFromLines_Empty(t *testing.T) {
	b := newBlocklist()
	added := b.MergeFromLines(nil, "")
	if added != 0 {
		t.Errorf("nil input should add 0 entries, got %d", added)
	}
	added = b.MergeFromLines([]string{"", "#comment", "   "}, "")
	if added != 0 {
		t.Errorf("blank/comment-only input should add 0 entries, got %d", added)
	}
}

func TestBlocklist_MergeFromLines_SchemeOnlyStripsToEmpty(t *testing.T) {
	b := newBlocklist()
	// "https://" alone — after stripping scheme gets "", should be skipped.
	added := b.MergeFromLines([]string{"https://", "http://"}, "")
	if added != 0 {
		t.Errorf("scheme-only lines should be skipped, got %d added", added)
	}
}

// ── Blocklist mode helpers ────────────────────────────────────────────────────

func TestBlocklist_ModeSetGet(t *testing.T) {
	b := newBlocklist()

	// Default mode is "block".
	if b.Mode() != "block" {
		t.Errorf("default mode should be block, got %s", b.Mode())
	}

	// Switch to allow mode (no file path — save is a no-op).
	b.SetMode("allow")
	if b.Mode() != "allow" {
		t.Errorf("expected allow mode, got %s", b.Mode())
	}

	// Invalid mode falls back to "block".
	b.SetMode("invalid")
	if b.Mode() != "block" {
		t.Errorf("invalid mode should fall back to block, got %s", b.Mode())
	}
}

func TestBlocklist_IsBlockedAndAllowlist(t *testing.T) {
	b := newBlocklist()
	b.MergeFromLines([]string{"evil.com", "*.bad.org"}, "")

	// Block mode (default): listed host → blocked.
	if !b.IsBlocked("evil.com") {
		t.Error("evil.com should be blocked in block mode")
	}
	if !b.IsBlocked("sub.bad.org") {
		t.Error("sub.bad.org should be blocked via wildcard in block mode")
	}
	if b.IsBlocked("safe.com") {
		t.Error("safe.com should not be blocked in block mode")
	}

	// Allow mode: listed hosts are allowed (not blocked), unlisted are blocked.
	b.SetMode("allow")
	if b.IsBlocked("evil.com") {
		t.Error("evil.com should NOT be blocked in allowlist mode (it's in the allow list)")
	}
	if b.IsBlocked("sub.bad.org") {
		t.Error("sub.bad.org should NOT be blocked in allowlist mode")
	}
	if !b.IsBlocked("safe.com") {
		t.Error("safe.com SHOULD be blocked in allowlist mode (not in allow list)")
	}
}
