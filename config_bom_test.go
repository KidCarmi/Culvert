package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A UTF-8 byte-order mark is prepended by Windows editors (Notepad, some
// PowerShell redirections). It is not part of the YAML content, so an
// otherwise valid config must still load instead of failing startup with a
// misleading unknown-field error naming the BOM-prefixed first key.
func TestLoadFileConfig_UTF8BOM(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	body := "\xef\xbb\xbfdefault_action: deny\nproxy:\n  port: 8081\n"
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	fc, err := loadFileConfig(p)
	if err != nil {
		t.Fatalf("loadFileConfig with UTF-8 BOM: %v", err)
	}
	if fc.DefaultAction != "deny" || fc.Proxy.Port != 8081 {
		t.Fatalf("BOM config misparsed: default_action=%q port=%d", fc.DefaultAction, fc.Proxy.Port)
	}
}
