package main

import (
	"os"
	"path/filepath"
	"testing"
)

// A config.yaml saved by a Windows editor (Notepad, VS Code "UTF-8 with BOM")
// starts with a UTF-8 byte-order mark. It is invisible to the operator, so the
// file must load exactly like its BOM-less twin instead of failing boot with
// `unknown field "U+FEFFproxy"`.
func TestLoadFileConfig_ToleratesUTF8BOM(t *testing.T) {
	const body = "proxy:\n  port: 8080\n  ui_port: 9090\n"
	for name, content := range map[string]string{
		"no_bom":   body,
		"with_bom": "\xef\xbb\xbf" + body,
		"bom_crlf": "\xef\xbb\xbf" + "proxy:\r\n  port: 8080\r\n  ui_port: 9090\r\n",
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
				t.Fatal(err)
			}
			fc, err := loadFileConfig(p)
			if err != nil {
				t.Fatalf("loadFileConfig: %v", err)
			}
			if fc.Proxy.Port != 8080 || fc.Proxy.UIPort != 9090 {
				t.Fatalf("got port=%d ui_port=%d, want 8080/9090", fc.Proxy.Port, fc.Proxy.UIPort)
			}
		})
	}
}

// A BOM-only file is the same "nothing configured" shape as an empty one.
func TestLoadFileConfig_BOMOnlyIsEmptyConfig(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("\xef\xbb\xbf"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadFileConfig(p); err != nil {
		t.Fatalf("BOM-only file should load as empty config: %v", err)
	}
}
