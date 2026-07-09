package threatfeed

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── NormaliseURL ─────────────────────────────────────────────────────────────

func TestNormaliseFeedURL_Valid(t *testing.T) {
	norm, host := NormaliseURL("http://malware.example.com/bad/path?query=1")
	if norm == "" {
		t.Error("NormaliseURL: expected non-empty norm")
	}
	if host != "malware.example.com" {
		t.Errorf("NormaliseURL host = %q, want malware.example.com", host)
	}
	// query stripped
	if norm != "http://malware.example.com/bad/path" {
		t.Errorf("NormaliseURL norm = %q, want path only (no query)", norm)
	}
}

func TestNormaliseFeedURL_NoScheme(t *testing.T) {
	norm, host := NormaliseURL("evil.example.com/malware")
	if norm == "" {
		t.Error("NormaliseURL: no-scheme URL should still parse")
	}
	if host != "evil.example.com" {
		t.Errorf("NormaliseURL host = %q, want evil.example.com", host)
	}
}

func TestNormaliseFeedURL_InvalidURL(t *testing.T) {
	norm, host := NormaliseURL("://bad")
	if norm != "" || host != "" {
		t.Errorf("NormaliseURL invalid URL should return empty, got norm=%q host=%q", norm, host)
	}
}

func TestNormaliseFeedURL_PrivateIP(t *testing.T) {
	norm, host := NormaliseURL("http://192.168.1.1/malware")
	if norm != "" || host != "" {
		t.Errorf("NormaliseURL private IP should return empty, got norm=%q host=%q", norm, host)
	}
}

func TestNormaliseFeedURL_TrailingSlash(t *testing.T) {
	norm, _ := NormaliseURL("http://evil.example.com/")
	if norm == "" {
		t.Fatal("expected non-empty norm")
	}
	// trailing slash should be trimmed
	if norm[len(norm)-1] == '/' {
		t.Errorf("NormaliseURL should trim trailing slash, got %q", norm)
	}
}

// ─── Feed CheckURL / CheckDomain ──────────────────────────────────────────────

func newEnabledFeed() *Feed {
	tf := &Feed{
		urls:            make(map[string]entry),
		domains:         make(map[string]entry),
		domainAllowlist: make(map[string]bool),
		enabled:         true,
	}
	tf.totalEntries.Store(0)
	return tf
}

func TestThreatFeed_CheckURL_Hit(t *testing.T) {
	tf := newEnabledFeed()
	tf.urls["http://malware.example.com/evil"] = entry{Source: "urlhaus", AddedAt: time.Now()}

	hit, src := tf.CheckURL("http://malware.example.com/evil")
	if !hit {
		t.Error("CheckURL should detect known malicious URL")
	}
	if src != "urlhaus" {
		t.Errorf("CheckURL source = %q, want urlhaus", src)
	}
}

func TestThreatFeed_CheckURL_Miss(t *testing.T) {
	tf := newEnabledFeed()
	hit, _ := tf.CheckURL("http://clean.example.com/page")
	if hit {
		t.Error("CheckURL should not flag unknown URL")
	}
}

func TestThreatFeed_CheckURL_DomainFallback(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["malware.example.com"] = entry{Source: "openphish", AddedAt: time.Now()}

	// URL not in urls map but domain is in domains map
	hit, src := tf.CheckURL("http://malware.example.com/some/path")
	if !hit {
		t.Error("CheckURL should fall back to domain lookup")
	}
	if src != "openphish" {
		t.Errorf("CheckURL domain fallback source = %q, want openphish", src)
	}
}

func TestThreatFeed_CheckURL_Disabled(t *testing.T) {
	tf := &Feed{
		urls:    make(map[string]entry),
		domains: make(map[string]entry),
		enabled: false,
	}
	hit, _ := tf.CheckURL("http://malware.example.com/evil")
	if hit {
		t.Error("CheckURL should return false when feed is disabled")
	}
}

func TestThreatFeed_CheckDomain_Hit(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["phishing.example.com"] = entry{Source: "openphish", AddedAt: time.Now()}

	hit, src := tf.CheckDomain("phishing.example.com")
	if !hit {
		t.Error("CheckDomain should detect known malicious domain")
	}
	if src != "openphish" {
		t.Errorf("CheckDomain source = %q, want openphish", src)
	}
}

func TestThreatFeed_CheckDomain_CaseInsensitive(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["malware.example.com"] = entry{Source: "urlhaus", AddedAt: time.Now()}

	hit, _ := tf.CheckDomain("MALWARE.EXAMPLE.COM")
	if !hit {
		t.Error("CheckDomain should be case-insensitive")
	}
}

func TestThreatFeed_CheckDomain_TrailingDot(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["malware.example.com"] = entry{Source: "urlhaus", AddedAt: time.Now()}

	hit, _ := tf.CheckDomain("malware.example.com.")
	if !hit {
		t.Error("CheckDomain should strip trailing dot")
	}
}

func TestThreatFeed_CheckDomain_Miss(t *testing.T) {
	tf := newEnabledFeed()
	hit, _ := tf.CheckDomain("clean.example.com")
	if hit {
		t.Error("CheckDomain should not flag unknown domain")
	}
}

func TestThreatFeed_DomainAllowlistMasksDomainButKeepsThreatIntelAndURLBlock(t *testing.T) {
	tf := newEnabledFeed()
	tf.urls["https://www.google.com/malware"] = entry{Source: "urlhaus", AddedAt: time.Now()}
	tf.domains["www.google.com"] = entry{Source: "urlhaus", AddedAt: time.Now()}

	if err := tf.AddDomainAllowlist("www.google.com"); err != nil {
		t.Fatalf("AddDomainAllowlist: %v", err)
	}

	if hit, _ := tf.CheckDomain("www.google.com"); hit {
		t.Fatal("allowlisted domain should not be blocked by stale domain map")
	}
	if _, ok := tf.domains["www.google.com"]; !ok {
		t.Fatal("allowlisting should preserve domain-level threat intel")
	}
	if hit, src := tf.CheckURL("https://www.google.com/malware?utm=ignored"); !hit || src != "urlhaus" {
		t.Fatalf("exact malicious URL must remain blocked after domain allowlist; hit=%v src=%q", hit, src)
	}
	if err := tf.RemoveDomainAllowlist("www.google.com"); err != nil {
		t.Fatalf("RemoveDomainAllowlist: %v", err)
	}
	if hit, src := tf.CheckDomain("www.google.com"); !hit || src != "urlhaus" {
		t.Fatalf("removing allowlist should immediately re-enable domain block; hit=%v src=%q", hit, src)
	}
}

func TestThreatFeed_CheckDomainAllowlistDefendsAgainstStaleDomainMap(t *testing.T) {
	tf := newEnabledFeed()
	tf.domainAllowlist["www.google.com"] = true
	tf.domains["www.google.com"] = entry{Source: "openphish", AddedAt: time.Now()}

	if hit, _ := tf.CheckDomain("www.google.com"); hit {
		t.Fatal("CheckDomain should honor allowlist even if stale domain entry remains")
	}
	if hit, _ := tf.CheckURL("https://www.google.com/anything"); hit {
		t.Fatal("CheckURL domain fallback should honor allowlist when no exact URL is present")
	}
}

func TestThreatFeed_DomainAllowlistNormalizesOperatorInputs(t *testing.T) {
	tf := newEnabledFeed()
	if err := tf.SetDomainAllowlist([]string{
		" HTTPS://WWW.Google.COM:443/some/path ",
		"www.google.com.",
	}); err != nil {
		t.Fatalf("SetDomainAllowlist: %v", err)
	}

	got := tf.DomainAllowlist()
	if len(got) != 1 || got[0] != "www.google.com" {
		t.Fatalf("normalized allowlist = %v, want [www.google.com]", got)
	}
	if !tf.DomainAllowlisted("https://www.google.com:443/other") {
		t.Fatal("DomainAllowlisted should normalize URL-shaped operator input")
	}
}

func TestThreatFeed_DomainAllowlistIsExactHost(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["www.google.com"] = entry{Source: "urlhaus", AddedAt: time.Now()}
	if err := tf.SetDomainAllowlist([]string{"google.com"}); err != nil {
		t.Fatalf("SetDomainAllowlist: %v", err)
	}

	if hit, src := tf.CheckDomain("www.google.com"); !hit || src != "urlhaus" {
		t.Fatalf("bare-domain allowlist should not suppress subdomain hits; hit=%v src=%q", hit, src)
	}
}

func TestThreatFeed_DomainAllowlistCanonicalizesIDNConsistently(t *testing.T) {
	tf := newEnabledFeed()
	const asciiHost = "xn--bcher-kva.example"
	tf.domains[asciiHost] = entry{Source: "urlhaus", AddedAt: time.Now()}

	if err := tf.SetDomainAllowlist([]string{"b\u00fccher.example"}); err != nil {
		t.Fatalf("SetDomainAllowlist: %v", err)
	}

	if got := tf.DomainAllowlist(); len(got) != 1 || got[0] != asciiHost {
		t.Fatalf("IDN allowlist normalized to %v, want [%s]", got, asciiHost)
	}
	if hit, _ := tf.CheckDomain(asciiHost); hit {
		t.Fatal("punycode domain hit should be suppressed by equivalent Unicode allowlist entry")
	}
	if hit, _ := tf.CheckURL("https://b\u00fccher.example/anything"); hit {
		t.Fatal("URL host canonicalization should match the domain allowlist")
	}
}

func TestThreatFeed_SetDomainAllowlistReturnsPersistenceError(t *testing.T) {
	tf := newEnabledFeed()
	tf.dbPath = filepath.Join(t.TempDir(), "missing-parent", "feed.json")

	if err := tf.SetDomainAllowlist([]string{"persist-error.example"}); err == nil {
		t.Fatal("SetDomainAllowlist should return persistence errors")
	}
	if !tf.DomainAllowlisted("persist-error.example") {
		t.Fatal("allowlist should still apply in memory when persistence fails")
	}
}

func TestThreatFeed_CheckDomain_Disabled(t *testing.T) {
	tf := &Feed{
		urls:    make(map[string]entry),
		domains: make(map[string]entry),
		enabled: false,
	}
	hit, _ := tf.CheckDomain("evil.example.com")
	if hit {
		t.Error("CheckDomain should return false when feed is disabled")
	}
}

// ─── Feed.loadFromDisk ────────────────────────────────────────────────────────

func TestThreatFeed_LoadFromDisk_NonExistent(t *testing.T) {
	tf := newEnabledFeed()
	err := tf.loadFromDisk("/tmp/nonexistent_feed_test_xyz.json")
	if err != nil {
		t.Errorf("loadFromDisk on nonexistent file should return nil, got %v", err)
	}
}

func TestThreatFeed_LoadFromDisk_Valid(t *testing.T) {
	db := feedDB{
		LastSync: time.Now(),
		URLs:     map[string]entry{"http://evil.com/bad": {Source: "urlhaus", AddedAt: time.Now()}},
		Domains:  map[string]entry{"evil.com": {Source: "urlhaus", AddedAt: time.Now()}},
	}
	data, _ := json.Marshal(db)
	f, err := os.CreateTemp("", "feeddb*.json")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.Write(data)
	f.Close()

	tf := newEnabledFeed()
	if err := tf.loadFromDisk(f.Name()); err != nil {
		t.Fatalf("loadFromDisk error: %v", err)
	}
	if _, ok := tf.urls["http://evil.com/bad"]; !ok {
		t.Error("loadFromDisk should populate URLs map")
	}
	// Legacy DB shape (no LastSuccess/LastSyncErr): back-fill lastSuccess
	// from LastSync so a pre-SyncStatus save still reports "last synced OK
	// at <time>" instead of "never synced successfully".
	if ok, lastSuccess, errSummary := tf.SyncStatus(); !ok || errSummary != "" || !lastSuccess.Equal(db.LastSync) {
		t.Errorf("SyncStatus after loading legacy DB = (%v, %v, %q), want (true, %v, \"\")", ok, lastSuccess, errSummary, db.LastSync)
	}
}

func TestThreatFeed_SaveLoad_PersistsSyncFailure(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/feed.json"

	tf := newEnabledFeed()
	tf.dbPath = path
	tf.urls["http://evil.com/bad"] = entry{Source: "urlhaus", AddedAt: time.Now()}
	tf.lastSync = time.Now()
	tf.lastSyncErr = "OpenPhish: HTTP 503 from https://openphish.com/feed.txt"
	// lastSuccess left zero: this feed has never synced cleanly.
	if err := tf.saveToDisk(); err != nil {
		t.Fatalf("saveToDisk error: %v", err)
	}

	reloaded := newEnabledFeed()
	if err := reloaded.loadFromDisk(path); err != nil {
		t.Fatalf("loadFromDisk error: %v", err)
	}
	ok, lastSuccess, errSummary := reloaded.SyncStatus()
	if ok {
		t.Error("SyncStatus after reloading a failed-sync DB should report ok=false")
	}
	if errSummary != tf.lastSyncErr {
		t.Errorf("SyncStatus errSummary = %q, want %q", errSummary, tf.lastSyncErr)
	}
	if !lastSuccess.IsZero() {
		t.Errorf("SyncStatus lastSuccess = %v, want zero (feed never synced cleanly)", lastSuccess)
	}
}

func TestThreatFeed_SaveLoad_PersistsSyncSuccess(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/feed.json"

	tf := newEnabledFeed()
	tf.dbPath = path
	success := time.Now().Add(-2 * time.Hour)
	tf.lastSync = success
	tf.lastSuccess = success
	if err := tf.saveToDisk(); err != nil {
		t.Fatalf("saveToDisk error: %v", err)
	}

	reloaded := newEnabledFeed()
	if err := reloaded.loadFromDisk(path); err != nil {
		t.Fatalf("loadFromDisk error: %v", err)
	}
	ok, lastSuccess, errSummary := reloaded.SyncStatus()
	if !ok || errSummary != "" || !lastSuccess.Equal(success) {
		t.Errorf("SyncStatus after reloading a successful-sync DB = (%v, %v, %q), want (true, %v, \"\")", ok, lastSuccess, errSummary, success)
	}
}

func TestThreatFeed_LoadFromDisk_BadJSON(t *testing.T) {
	f, _ := os.CreateTemp("", "badfeed*.json")
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.WriteString("not json")
	f.Close()

	tf := newEnabledFeed()
	err := tf.loadFromDisk(f.Name())
	if err == nil {
		t.Error("loadFromDisk with bad JSON should return error")
	}
}

// ─── Feed.Stats ───────────────────────────────────────────────────────────────

func TestThreatFeed_Stats(t *testing.T) {
	tf := newEnabledFeed()
	tf.totalEntries.Store(42)
	count, _, _ := tf.Stats()
	if count != 42 {
		t.Errorf("Stats count = %d, want 42", count)
	}
}

func TestThreatFeed_SyncStatus_DefaultOK(t *testing.T) {
	tf := newEnabledFeed()
	ok, lastSuccess, errSummary := tf.SyncStatus()
	if !ok || errSummary != "" || !lastSuccess.IsZero() {
		t.Errorf("SyncStatus on fresh feed = (%v, %v, %q), want (true, zero, \"\")", ok, lastSuccess, errSummary)
	}
}

func TestThreatFeed_SyncStatus_ReflectsFailure(t *testing.T) {
	tf := newEnabledFeed()
	// Simulate what Sync() records on a failed attempt: lastSync always
	// advances, but lastSuccess only does when every feed fetched cleanly.
	tf.lastSync = time.Now()
	tf.lastSyncErr = "URLhaus: HTTP 503 from https://urlhaus.abuse.ch/downloads/text/"

	ok, lastSuccess, errSummary := tf.SyncStatus()
	if ok {
		t.Error("SyncStatus ok = true, want false after a recorded failure")
	}
	if errSummary == "" {
		t.Error("SyncStatus errSummary is empty, want the recorded failure")
	}
	if !lastSuccess.IsZero() {
		t.Errorf("SyncStatus lastSuccess = %v, want zero (feed has never synced cleanly)", lastSuccess)
	}

	// A subsequent clean sync clears the error and records the success time.
	now := time.Now()
	tf.mu.Lock()
	tf.lastSync = now
	tf.lastSuccess = now
	tf.lastSyncErr = ""
	tf.mu.Unlock()

	ok, lastSuccess, errSummary = tf.SyncStatus()
	if !ok || errSummary != "" || lastSuccess.IsZero() {
		t.Errorf("SyncStatus after recovery = (%v, %v, %q), want (true, non-zero, \"\")", ok, lastSuccess, errSummary)
	}
}

func TestThreatFeed_ExportURLs(t *testing.T) {
	tf := newEnabledFeed()
	tf.urls["http://evil.com/payload"] = entry{Source: "urlhaus", AddedAt: time.Unix(1700000000, 0)}
	tf.urls["http://bad.com/malware"] = entry{Source: "openphish", AddedAt: time.Unix(1700000001, 0)}

	exported := tf.ExportURLs()
	if len(exported) != 2 {
		t.Fatalf("ExportURLs len = %d, want 2", len(exported))
	}
	if exported["http://evil.com/payload"] != 1700000000 {
		t.Errorf("evil.com timestamp = %d", exported["http://evil.com/payload"])
	}
}

func TestThreatFeed_ExportDomains(t *testing.T) {
	tf := newEnabledFeed()
	tf.domains["evil.com"] = entry{Source: "urlhaus", AddedAt: time.Unix(1700000000, 0)}

	exported := tf.ExportDomains()
	if len(exported) != 1 {
		t.Fatalf("ExportDomains len = %d, want 1", len(exported))
	}
	if exported["evil.com"] != 1700000000 {
		t.Errorf("evil.com timestamp = %d", exported["evil.com"])
	}
}

func TestThreatFeed_ImportFeedData(t *testing.T) {
	tf := newEnabledFeed()
	tf.urls["old.com/page"] = entry{Source: "urlhaus", AddedAt: time.Unix(1600000000, 0)}

	urls := map[string]int64{
		"http://new.com/bad": 1700000000,
	}
	domains := map[string]int64{
		"new-domain.com": 1700000001,
	}

	tf.ImportFeedData(urls, domains)

	if len(tf.urls) != 1 {
		t.Errorf("after import, urls len = %d, want 1", len(tf.urls))
	}
	if _, ok := tf.urls["http://new.com/bad"]; !ok {
		t.Error("expected new URL to be present")
	}
	if _, ok := tf.urls["old.com/page"]; ok {
		t.Error("old URL should have been replaced")
	}
	if len(tf.domains) != 1 {
		t.Errorf("after import, domains len = %d, want 1", len(tf.domains))
	}
	if tf.domains["new-domain.com"].Source != "cluster-sync" {
		t.Errorf("source = %q, want cluster-sync", tf.domains["new-domain.com"].Source)
	}
}

func TestThreatFeed_ImportFeedDataPreservesDomainAllowlistAndURLBlocks(t *testing.T) {
	tf := newEnabledFeed()
	if err := tf.SetDomainAllowlist([]string{"https://www.google.com:443/path"}); err != nil {
		t.Fatalf("SetDomainAllowlist: %v", err)
	}

	tf.ImportFeedData(
		map[string]int64{"https://www.google.com/malware": 1700000000},
		map[string]int64{
			"WWW.Google.COM:443": 1700000001,
			"evil.example.com":   1700000002,
		},
	)

	if _, ok := tf.domains["www.google.com"]; !ok {
		t.Fatal("ImportFeedData should retain allowlisted domain threat intel")
	}
	if hit, _ := tf.CheckDomain("www.google.com"); hit {
		t.Fatal("allowlisted imported domain should not block")
	}
	if hit, src := tf.CheckURL("https://www.google.com/malware"); !hit || src != "cluster-sync" {
		t.Fatalf("exact malicious URL should remain blocked; hit=%v src=%q", hit, src)
	}
	if hit, src := tf.CheckDomain("evil.example.com"); !hit || src != "cluster-sync" {
		t.Fatalf("non-allowlisted imported domain should still block; hit=%v src=%q", hit, src)
	}
	if err := tf.RemoveDomainAllowlist("www.google.com"); err != nil {
		t.Fatalf("RemoveDomainAllowlist: %v", err)
	}
	if hit, src := tf.CheckDomain("www.google.com"); !hit || src != "cluster-sync" {
		t.Fatalf("removing imported-domain allowlist should immediately re-enable block; hit=%v src=%q", hit, src)
	}
}
