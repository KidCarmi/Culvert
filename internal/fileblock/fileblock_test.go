package fileblock

// Engine unit tests for FileBlocker, moved from package main's fileblock_test.go
// during the internal/fileblock extraction (ADR-0002). The proxy-integration
// tests (handleRequest) stay in package main; only the engine tests live here.

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// assertNoTmpLeak is a local copy of package main's shared test helper
// (enroll_util_test.go). Duplicated rather than shared via a new test-util
// package, per the "no new seams" constraint of the extraction.
func assertNoTmpLeak(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), ".tmp.") {
			t.Errorf("orphaned tmp file: %s", e.Name())
		}
	}
}

func freshFB() *FileBlocker {
	return &FileBlocker{extensions: map[string]bool{}}
}

func TestFileBlocker_AddRemoveCount(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add("dll")  // without leading dot — should normalise to ".dll"
	fb.Add(".EXE") // duplicate, case-insensitive — should not increase count

	if fb.Count() != 2 {
		t.Errorf("expected 2 extensions, got %d", fb.Count())
	}

	fb.Remove(".exe")
	if fb.Count() != 1 {
		t.Errorf("expected 1 after remove, got %d", fb.Count())
	}
	if fb.CheckPath("/file.exe") != "" {
		t.Error("expected .exe allowed after remove")
	}
}

func TestFileBlocker_CheckPath(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add(".ps1")

	cases := []struct {
		path    string
		blocked bool
	}{
		{"/download/malware.exe", true},
		{"/scripts/run.ps1", true},
		{"/docs/report.pdf", false},
		{"/page/", false},        // no extension
		{"/file.EXE", true},      // case-insensitive
		{"/file.exe.txt", false}, // extension is .txt, not .exe
	}
	for _, c := range cases {
		got := fb.CheckPath(c.path) != ""
		if got != c.blocked {
			t.Errorf("CheckPath(%q) blocked=%v, want %v", c.path, got, c.blocked)
		}
	}
}

func TestFileBlocker_CheckContentDisposition(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")

	cases := []struct {
		header  string
		blocked bool
	}{
		{`attachment; filename="setup.exe"`, true},
		{`attachment; filename="report.pdf"`, false},
		{`attachment; filename="SETUP.EXE"`, true}, // case-insensitive
		{`inline`, false}, // no filename param
		{``, false},       // empty header
		{`attachment; filename="archive.tar.gz"`, false}, // .gz not blocked
	}
	for _, c := range cases {
		got := fb.CheckContentDisposition(c.header) != ""
		if got != c.blocked {
			t.Errorf("CheckContentDisposition(%q) blocked=%v, want %v", c.header, got, c.blocked)
		}
	}
}

func TestFileBlocker_CheckContentType(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add(".msi")

	cases := []struct {
		ct      string
		blocked bool
		ext     string
	}{
		// Exact dangerous MIME — should block
		{"application/x-msdownload", true, ".exe"},
		{"application/x-dosexec", true, ".exe"},
		{"application/vnd.microsoft.portable-executable", true, ".exe"},
		{"application/x-msi", true, ".msi"},

		// MIME with parameters — should still block
		{"application/x-msdownload; charset=utf-8", true, ".exe"},
		{"application/x-msi; name=setup.msi", true, ".msi"},

		// Dangerous MIME but extension not in block list
		{"application/x-powershell", false, ""},
		{"application/x-bat", false, ""},

		// Safe MIME types — should not block
		{"text/html", false, ""},
		{"application/json", false, ""},
		{"image/png", false, ""},
		{"application/pdf", false, ""},

		// Empty / invalid
		{"", false, ""},
		{";;;invalid", false, ""},
	}
	for _, c := range cases {
		got := fb.CheckContentType(c.ct)
		//nolint:gocritic // boolean-condition chain over two variables, not a value switch
		if c.blocked && got == "" {
			t.Errorf("CheckContentType(%q) expected block (ext=%s), got allowed", c.ct, c.ext)
		} else if !c.blocked && got != "" {
			t.Errorf("CheckContentType(%q) expected allowed, got blocked (ext=%s)", c.ct, got)
		} else if c.blocked && got != c.ext {
			t.Errorf("CheckContentType(%q) expected ext=%s, got %s", c.ct, c.ext, got)
		}
	}
}

func TestFileBlocker_List(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add(".dll")
	list := fb.List()
	if len(list) != 2 {
		t.Errorf("expected 2 in list, got %d", len(list))
	}
}

// closableBuffer wraps bytes.Buffer with a no-op Close for BlockConn.
type closableBuffer struct{ bytes.Buffer }

func (cb *closableBuffer) Close() error { return nil }

func TestFileBlockConn(t *testing.T) {
	var buf closableBuffer
	BlockConn(&buf, "example.com", "/download/script.ps1", ".ps1", "global ext")

	resp := buf.String()
	if !bytes.Contains(buf.Bytes(), []byte("HTTP/1.1 403")) {
		t.Errorf("expected HTTP/1.1 403 in response, got:\n%s", resp)
	}
	if !bytes.Contains(buf.Bytes(), []byte(".ps1")) {
		t.Errorf("expected .ps1 in body, got:\n%s", resp)
	}
	if !bytes.Contains(buf.Bytes(), []byte("Connection: close")) {
		t.Errorf("expected Connection: close header, got:\n%s", resp)
	}
}

// TestFileBlocker_Save_NoTmpLeak verifies the converted writer does not
// leave orphaned *.tmp.* files. fb.Add triggers fb.save internally.
func TestFileBlocker_Save_NoTmpLeak(t *testing.T) {
	dir := t.TempDir()
	fb := &FileBlocker{
		path:       filepath.Join(dir, "fileblock.json"),
		extensions: map[string]bool{},
	}
	fb.Add(".exe")
	assertNoTmpLeak(t, dir)
}
