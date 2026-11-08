package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A control-plane config whose grpc_addr is whitespace-only (e.g. a templated
// `grpc_addr: " "` or an unset placeholder) must be refused at load time, the
// same as an omitted grpc_addr. Otherwise it passes validation, resolves to a
// non-empty CPAddr and the node tries to listen on a blank address.
func TestLoadFileConfig_ControlPlaneBlankGRPCAddrRejected(t *testing.T) {
	for _, addr := range []string{"", `"  "`, `"\t"`} {
		p := filepath.Join(t.TempDir(), "c.yaml")
		body := "cluster:\n  role: control-plane\n  grpc_addr: " + addr + "\n"
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		_, err := loadFileConfig(p)
		if err == nil {
			t.Fatalf("grpc_addr %s: expected validation error, got nil", addr)
		}
		if !strings.Contains(err.Error(), "cluster.grpc_addr is required") {
			t.Fatalf("grpc_addr %s: unexpected error %v", addr, err)
		}
	}
}
