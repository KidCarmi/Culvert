package ca

import "testing"

// TestSignLeaf_ValidCert exercises the unexported leaf-signing path directly
// (moved from package main's ca_test.go with the ADR-0002 extraction). The
// assembled decrypt→sign→re-encrypt data path is covered end-to-end by
// package main's mitm_inspect_e2e_test.go.
func TestSignLeaf_ValidCert(t *testing.T) {
	cm := New()
	if err := cm.InitCA(); err != nil {
		t.Fatalf("InitCA: %v", err)
	}
	cert, err := cm.signLeaf("example.com")
	if err != nil {
		t.Fatalf("signLeaf: %v", err)
	}
	if cert == nil {
		t.Fatal("signLeaf returned nil cert")
	}
}
