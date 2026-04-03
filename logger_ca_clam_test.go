package main

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

// ─── logger.go ────────────────────────────────────────────────────────────────

func TestNewRotatingFile_CreatesFile(t *testing.T) {
	f, err := os.CreateTemp("", "rottest*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name())        //nolint:errcheck // test cleanup
	defer os.Remove(f.Name() + ".1") //nolint:errcheck // test cleanup

	rf, err := newRotatingFile(f.Name(), 1)
	if err != nil {
		t.Fatalf("newRotatingFile: %v", err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup

	n, err := rf.Write([]byte("hello\n"))
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n != 6 {
		t.Errorf("Write returned %d, want 6", n)
	}
}

func TestRotatingFile_Rotate(t *testing.T) {
	f, err := os.CreateTemp("", "rottest*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	path := f.Name()
	defer os.Remove(path)        //nolint:errcheck // test cleanup
	defer os.Remove(path + ".1") //nolint:errcheck // test cleanup

	// maxMB=0 defaults to 50MB, set maxBytes tiny by creating with a raw struct
	rf := &rotatingFile{
		path:     path,
		maxBytes: 10, // force rotation after 10 bytes
		size:     0,
	}
	rf.file, err = os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup

	// Write more than 10 bytes to trigger rotation
	_, err = rf.Write([]byte("this is more than 10 bytes of data"))
	if err != nil {
		t.Errorf("Write after rotation error: %v", err)
	}
}

func TestRotatingFile_DefaultMaxMB(t *testing.T) {
	f, err := os.CreateTemp("", "rottest_default*.log")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	defer os.Remove(f.Name()) //nolint:errcheck // test cleanup

	rf, err := newRotatingFile(f.Name(), 0) // 0 = use default 50MB
	if err != nil {
		t.Fatalf("newRotatingFile with 0 maxMB: %v", err)
	}
	defer rf.Close() //nolint:errcheck // test cleanup
	if rf.maxBytes != 50*1024*1024 {
		t.Errorf("default maxBytes = %d, want %d", rf.maxBytes, 50*1024*1024)
	}
}

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

func TestParseClamResponse_OK(t *testing.T) {
	name, found, err := parseClamResponse("stream: OK")
	if err != nil || found || name != "" {
		t.Errorf("parseClamResponse OK: got name=%q found=%v err=%v", name, found, err)
	}
}

func TestParseClamResponse_Found(t *testing.T) {
	name, found, err := parseClamResponse("stream: Eicar-Test-Signature FOUND")
	if err != nil {
		t.Errorf("parseClamResponse FOUND error: %v", err)
	}
	if !found {
		t.Error("parseClamResponse FOUND: expected found=true")
	}
	if name != "Eicar-Test-Signature" {
		t.Errorf("parseClamResponse FOUND name = %q, want Eicar-Test-Signature", name)
	}
}

func TestParseClamResponse_Error(t *testing.T) {
	_, _, err := parseClamResponse("stream: Access denied ERROR")
	if err == nil {
		t.Error("parseClamResponse ERROR: expected error")
	}
}

func TestParseClamResponse_Empty(t *testing.T) {
	_, _, err := parseClamResponse("")
	if err == nil {
		t.Error("parseClamResponse empty: expected error")
	}
}

func TestParseClamResponse_Unexpected(t *testing.T) {
	_, _, err := parseClamResponse("unexpected response")
	if err == nil {
		t.Error("parseClamResponse unexpected: expected error")
	}
}

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

	// Reset the global audit log file before test
	oldFile := auditLogFile
	auditLogFile = nil
	defer func() { auditLogFile = oldFile }()

	if err := InitAuditLog(f.Name()); err != nil {
		t.Fatalf("InitAuditLog valid path: %v", err)
	}
	if auditLogFile == nil {
		t.Error("InitAuditLog should set auditLogFile")
	}
	auditLogFile.Close()
	auditLogFile = nil
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
	_ = cfg2.SetUIUser("testuser", "testpass123", RoleAdmin)

	if err := cfg2.SaveUIUsersFile(); err != nil {
		t.Fatalf("SaveUIUsersFile: %v", err)
	}

	cfg3 := &Config{}
	cfg3.SetUIUsersFile(f.Name())
	if err := cfg3.LoadUIUsersFile(); err != nil {
		t.Fatalf("LoadUIUsersFile: %v", err)
	}

	role, valid := cfg3.VerifyUIUser("testuser", "testpass123")
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
