package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/KidCarmi/Culvert/internal/audit"
)

// ─── logger.go ────────────────────────────────────────────────────────────────

func TestJSONLogWriter_Write(t *testing.T) {
	var buf bytes.Buffer
	jw := &jsonLogWriter{dst: &buf}
	_, err := jw.Write([]byte("test log message\n"))
	if err != nil {
		t.Errorf("jsonLogWriter.Write error: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "test log message") {
		t.Errorf("jsonLogWriter output missing message: %q", out)
	}
	if !strings.Contains(out, `"time"`) {
		t.Errorf("jsonLogWriter output missing time field: %q", out)
	}
	if !strings.Contains(out, `"msg"`) {
		t.Errorf("jsonLogWriter output missing msg field: %q", out)
	}
}

func TestSetupLogger_PlainText_NoFile(t *testing.T) {
	l, closer, err := setupLogger("", 0, "text")
	if err != nil {
		t.Fatalf("setupLogger error: %v", err)
	}
	if l == nil {
		t.Error("setupLogger returned nil logger")
	}
	if closer != nil {
		_ = closer.Close()
	}
}

func TestSetupLogger_JSON_NoFile(t *testing.T) {
	l, closer, err := setupLogger("", 0, "json")
	if err != nil {
		t.Fatalf("setupLogger JSON error: %v", err)
	}
	if l == nil {
		t.Error("setupLogger JSON returned nil logger")
	}
	if closer != nil {
		_ = closer.Close()
	}
}

func TestSetupLogger_WithFile(t *testing.T) {
	f, err := os.CreateTemp("", "setuplogger*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	l, closer, err := setupLogger(f.Name(), 1, "text")
	if err != nil {
		t.Fatalf("setupLogger with file error: %v", err)
	}
	if l == nil {
		t.Error("setupLogger returned nil logger")
	}
	l.Println("test message")
	if closer != nil {
		_ = closer.Close()
	}
}

func TestSetupLogger_JSONWithFile(t *testing.T) {
	f, err := os.CreateTemp("", "setuplogger_json*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	l, closer, err := setupLogger(f.Name(), 1, "json")
	if err != nil {
		t.Fatalf("setupLogger JSON with file error: %v", err)
	}
	l.Println("json test message")
	if closer != nil {
		_ = closer.Close()
	}
}

// ─── clam.go — parseClamResponse ─────────────────────────────────────────────

// ── Log level tests ──────────────────────────────────────────────────────────

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		in   string
		want LogLevel
	}{
		{"DEBUG", LevelDebug},
		{"debug", LevelDebug},
		{"INFO", LevelInfo},
		{"info", LevelInfo},
		{"", LevelInfo},
		{"WARN", LevelWarn},
		{"WARNING", LevelWarn},
		{"ERROR", LevelError},
		{"unknown", LevelInfo},
	}
	for _, tt := range tests {
		if got := ParseLogLevel(tt.in); got != tt.want {
			t.Errorf("ParseLogLevel(%q) = %v, want %v", tt.in, got, tt.want)
		}
	}
}

func TestLogLevelString(t *testing.T) {
	if LevelDebug.String() != "DEBUG" {
		t.Error("LevelDebug.String() != DEBUG")
	}
	if LevelError.String() != "ERROR" {
		t.Error("LevelError.String() != ERROR")
	}
}

func TestSetGetLogLevel(t *testing.T) {
	old := GetLogLevel()
	defer SetLogLevel(old)

	SetLogLevel(LevelWarn)
	if GetLogLevel() != LevelWarn {
		t.Errorf("GetLogLevel() = %v after SetLogLevel(WARN)", GetLogLevel())
	}
	SetLogLevel(LevelDebug)
	if GetLogLevel() != LevelDebug {
		t.Errorf("GetLogLevel() = %v after SetLogLevel(DEBUG)", GetLogLevel())
	}
}

// clam.go parseClamResponse + ClamAV connection tests moved to internal/clamav
// (ADR-0002) — they use the unexported parseClamResponse + timeout field.

// ─── ca.go — CACertInfo with no cert ─────────────────────────────────────────

func TestCACertInfo_NoCert(t *testing.T) {
	cm := &CertManager{}
	info := cm.CACertInfo()
	ready, _ := info["ready"].(bool)
	if ready {
		t.Error("CACertInfo should return ready=false when no CA loaded")
	}
}

func TestCACertInfo_WithCA(t *testing.T) {
	cm := &CertManager{}
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	info := cm.CACertInfo()
	ready, _ := info["ready"].(bool)
	if !ready {
		t.Error("CACertInfo should return ready=true after InitCA")
	}
	if _, ok := info["fingerprint"]; !ok {
		t.Error("CACertInfo should contain fingerprint")
	}
}

func TestLoadCustomCA_BadPEM(t *testing.T) {
	cm := &CertManager{}
	err := cm.LoadCustomCA([]byte("not pem"), []byte("not key"))
	if err == nil {
		t.Error("LoadCustomCA should fail with bad PEM")
	}
}

func TestParseTLSPair_BadPEM(t *testing.T) {
	cm := &CertManager{}
	_, err := cm.ParseTLSPair([]byte("bad cert"), []byte("bad key"))
	if err == nil {
		t.Error("ParseTLSPair should fail with bad PEM")
	}
}

// ─── config.go — loadFileConfig ───────────────────────────────────────────────

func TestLoadFileConfig_NonExistent(t *testing.T) {
	_, err := loadFileConfig("/tmp/nonexistent_culvert_config_xyz.yaml")
	if err == nil {
		t.Error("loadFileConfig nonexistent file should return error")
	}
}

func TestLoadFileConfig_ValidYAML(t *testing.T) {
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.WriteString("proxy:\n  port: 8080\n")
	f.Close()

	fc, err := loadFileConfig(f.Name())
	if err != nil {
		t.Fatalf("loadFileConfig valid YAML: %v", err)
	}
	if fc == nil {
		t.Error("loadFileConfig should return non-nil FileConfig")
	}
}

func TestLoadFileConfig_BadYAML(t *testing.T) {
	f, err := os.CreateTemp("", "badconfig*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.WriteString("listen: [unclosed\n")
	f.Close()

	_, err = loadFileConfig(f.Name())
	if err == nil {
		t.Error("loadFileConfig bad YAML should return error")
	}
}

// TestLoadFileConfig_DPIKeyCanonicalWins verifies the terminology-governance
// T-10 fix: the canonical dpi_file/dpi_patterns keys take precedence over
// the deprecated content_scan_file/content_scan_patterns aliases when both
// are set, and downstream code keeps reading ContentScanFile/Patterns.
func TestLoadFileConfig_DPIKeyCanonicalWins(t *testing.T) {
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.WriteString("proxy:\n" +
		"  dpi_file: \"/data/dpi.json\"\n" +
		"  dpi_patterns: [\"canonical\"]\n" +
		"  content_scan_file: \"/data/legacy.json\"\n" +
		"  content_scan_patterns: [\"legacy\"]\n")
	f.Close()

	fc, err := loadFileConfig(f.Name())
	if err != nil {
		t.Fatalf("loadFileConfig: %v", err)
	}
	if fc.Proxy.ContentScanFile != "/data/dpi.json" {
		t.Errorf("ContentScanFile = %q, want canonical dpi_file value", fc.Proxy.ContentScanFile)
	}
	if len(fc.Proxy.ContentScanPatterns) != 1 || fc.Proxy.ContentScanPatterns[0] != "canonical" {
		t.Errorf("ContentScanPatterns = %v, want [canonical]", fc.Proxy.ContentScanPatterns)
	}
}

// TestLoadFileConfig_DeprecatedDPIKeyStillWorks verifies the legacy
// content_scan_file/content_scan_patterns keys still parse and populate
// FileConfig when the canonical dpi_* keys are absent (back-compat for
// existing deployed config.yaml files).
func TestLoadFileConfig_DeprecatedDPIKeyStillWorks(t *testing.T) {
	f, err := os.CreateTemp("", "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup
	_, _ = f.WriteString("proxy:\n" +
		"  content_scan_file: \"/data/legacy.json\"\n" +
		"  content_scan_patterns: [\"legacy\"]\n")
	f.Close()

	fc, err := loadFileConfig(f.Name())
	if err != nil {
		t.Fatalf("loadFileConfig: %v", err)
	}
	if fc.Proxy.ContentScanFile != "/data/legacy.json" {
		t.Errorf("ContentScanFile = %q, want /data/legacy.json", fc.Proxy.ContentScanFile)
	}
	if len(fc.Proxy.ContentScanPatterns) != 1 || fc.Proxy.ContentScanPatterns[0] != "legacy" {
		t.Errorf("ContentScanPatterns = %v, want [legacy]", fc.Proxy.ContentScanPatterns)
	}
}

// ─── store.go — InitAuditLog, authCacheStore ──────────────────────────────────

func TestInitAuditLog_ValidPath(t *testing.T) {
	f, err := os.CreateTemp("", "auditlog*.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	// Write some valid audit entries
	_, _ = f.WriteString(`{"ts":1,"action":"test"}` + "\n")
	_, _ = f.WriteString(`{"ts":2,"action":"test2"}` + "\n")
	f.Close()
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	// Isolate the engine's persistence state for this test.
	restore := audit.ResetForTest()
	defer restore()

	if err := InitAuditLog(f.Name()); err != nil {
		t.Fatalf("InitAuditLog valid path: %v", err)
	}
	if !audit.PersistActive() {
		t.Error("InitAuditLog should wire the persistent writer")
	}
	_ = audit.Close()
	audit.ClearPersistForTest() // closed above; restore must not double-close
}

func TestAuthCacheStore_SetAndGet(t *testing.T) {
	store := &authCacheStore{entries: make(map[string]*authCacheEntry)}
	store.set("user1", "pass1", true)
	ok, hit := store.get("user1", "pass1")
	if !hit {
		t.Error("authCacheStore.get should be a cache hit after set")
	}
	if !ok {
		t.Error("authCacheStore.get should return ok=true")
	}
}

func TestAuthCacheStore_Eviction(t *testing.T) {
	store := &authCacheStore{entries: make(map[string]*authCacheEntry)}
	// Fill up to maxAuthCacheSize
	for i := 0; i < maxAuthCacheSize; i++ {
		user := strings.Repeat("u", i%50+1)
		pass := strings.Repeat("p", i%50+1) + string(rune('a'+i%26))
		store.set(user+string(rune(i)), pass, true)
	}
	// Adding one more should trigger eviction
	store.set("evict-trigger-user", "evict-trigger-pass", false)
	// Verify the store size didn't blow up
	store.mu.Lock()
	size := len(store.entries)
	store.mu.Unlock()
	if size > maxAuthCacheSize+1 {
		t.Errorf("authCacheStore grew too large: %d entries", size)
	}
}

func TestLoadUIUsersFile_EmptyPath(t *testing.T) {
	cfg2 := &Config{}
	err := cfg2.LoadUIUsersFile()
	if err != nil {
		t.Errorf("LoadUIUsersFile empty path should return nil, got: %v", err)
	}
}

func TestSaveUIUsersFile_EmptyPath(t *testing.T) {
	cfg2 := &Config{}
	err := cfg2.SaveUIUsersFile()
	if err != nil {
		t.Errorf("SaveUIUsersFile empty path should return nil, got: %v", err)
	}
}

func TestSaveAndLoadUIUsersFile(t *testing.T) {
	f, err := os.CreateTemp("", "uiusers*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())          //nolint:errcheck // test cleanup
	defer os.Remove(f.Name() + ".tmp") //nolint:errcheck // test cleanup

	cfg2 := &Config{}
	cfg2.SetUIUsersFile(f.Name())
	_ = cfg2.SetUIUser("testuser", "TestPass1", RoleAdmin)

	if err := cfg2.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}

	cfg3 := &Config{}
	cfg3.SetUIUsersFile(f.Name())
	if err := cfg3.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}

	role, valid := cfg3.VerifyUIUser("testuser", "TestPass1")
	if !valid {
		t.Error("LoadUIUsersFile should load saved user")
	}
	if role != RoleAdmin {
		t.Errorf("loaded user role = %v, want RoleAdmin", role)
	}
}

func TestTsRecord_CallsSucceed(t *testing.T) {
	// Just call tsRecord a few times — it manipulates global ts struct
	tsRecord()
	tsRecord()
	out, _, _ := tsGet()
	if len(out) != 60 {
		t.Errorf("tsGet should return 60 buckets, got %d", len(out))
	}
}
