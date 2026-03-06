package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func freshFB() *FileBlocker {
	return &FileBlocker{extensions: map[string]bool{}}
}

func TestFileBlocker_AddRemoveCount(t *testing.T) {
	fb := freshFB()
	fb.Add(".exe")
	fb.Add("dll") // without leading dot — should normalise to ".dll"
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
		{"/page/", false},       // no extension
		{"/file.EXE", true},    // case-insensitive
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
		{`attachment; filename="SETUP.EXE"`, true},  // case-insensitive
		{`inline`, false},                            // no filename param
		{``, false},                                  // empty header
		{`attachment; filename="archive.tar.gz"`, false}, // .gz not blocked
	}
	for _, c := range cases {
		got := fb.CheckContentDisposition(c.header) != ""
		if got != c.blocked {
			t.Errorf("CheckContentDisposition(%q) blocked=%v, want %v", c.header, got, c.blocked)
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

// TestProxy_FileBlockURL verifies that the proxy serves a 403 block page when
// a request URL ends with a blocked extension.
func TestProxy_FileBlockURL(t *testing.T) {
	setupProxyTest(t)
	fileBlocker.Add(".exe")
	t.Cleanup(func() { fileBlocker.Remove(".exe") })

	ts := httptest.NewServer(http.HandlerFunc(handleRequest))
	defer ts.Close()

	req := makeRequest("GET", "http://example.com/setup.exe", nil)
	rec := httptest.NewRecorder()
	handleRequest(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rec.Code)
	}
}
