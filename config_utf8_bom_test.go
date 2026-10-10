package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Nightly QA (edge case): a config.yaml saved with a UTF-8 byte-order mark
// must load.
//
// Windows editors (Notepad's "UTF-8" option, PowerShell 5 `Out-File -Encoding
// utf8`) prepend EF BB BF. config.yaml is a bind mount from the operator's
// host, so such a file reaches the proxy as-is. The YAML decoder does not
// skip the BOM; it folds it into the first key, so loadFileConfig fails with
// an unknown-field error naming the first key, and the proxy refuses to start with an error
// that points at a key that looks correct on screen.
func TestLoadFileConfig_UTF8BOMDoesNotError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	body := "\xef\xbb\xbfproxy:\n  port: 8081\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	fc, err := loadFileConfig(path)
	if err != nil {
		t.Fatalf("loadFileConfig(BOM-prefixed file) = %v, want nil (a BOM is an encoding marker, not content)", err)
	}
	if fc.Proxy.Port != 8081 {
		t.Fatalf("proxy.port = %d, want 8081", fc.Proxy.Port)
	}
}
