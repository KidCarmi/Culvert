package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A config.yaml saved by a Windows editor (Notepad, VS Code "UTF-8 with BOM")
// starts with U+FEFF. It is not part of the YAML content and must not turn the
// first key into an "unknown field" boot failure.
func TestLoadFileConfig_UTF8BOMIsIgnored(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("\xef\xbb\xbfdefault_action: deny\nproxy:\n  port: 8181\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := loadFileConfig(p)
	if err != nil {
		t.Fatalf("BOM-prefixed config must load, got: %v", err)
	}
	if fc.DefaultAction != "deny" || fc.Proxy.Port != 8181 {
		t.Fatalf("BOM must not alter parsed values: default_action=%q port=%d", fc.DefaultAction, fc.Proxy.Port)
	}
}
