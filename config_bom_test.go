package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A config.yaml saved by Windows Notepad (or `Out-File -Encoding utf8` on
// PowerShell 5) starts with a UTF-8 byte-order mark. The YAML decoder does
// not skip it, so the first key was reported as `unknown field "U+FEFFproxy"`
// and the appliance refused to boot on a file that looks correct in any editor.
func TestLoadFileConfig_AcceptsUTF8BOM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := "\xef\xbb\xbfproxy:\n  port: 8080\n  ui_port: 9090\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := loadFileConfig(p)
	if err != nil {
		t.Fatalf("BOM-prefixed config rejected: %v", err)
	}
	if fc.Proxy.Port != 8080 || fc.Proxy.UIPort != 9090 {
		t.Fatalf("values lost: port=%d ui_port=%d", fc.Proxy.Port, fc.Proxy.UIPort)
	}
}

// Control: a BOM-only (otherwise empty) file is the same "nothing configured"
// shape as an empty file and must keep booting with defaults.
func TestLoadFileConfig_BOMOnlyFileIsEmptyConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("\xef\xbb\xbf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFileConfig(p); err != nil {
		t.Fatalf("BOM-only config rejected: %v", err)
	}
}
