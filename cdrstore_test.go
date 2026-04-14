package main

// Tests for cdrstore.go — instance registry persistence, fingerprint
// normalisation, and client lifecycle singleton management.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCDRInstanceRegistry_AddAndPersist(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cdr_instances.json")
	reg := &CDRInstanceRegistry{}
	if err := reg.Load(path); err != nil {
		t.Fatal(err)
	}

	inst, err := reg.Add(CDREnrolledInstance{
		Name:              "sluice-01",
		Endpoint:          "sluice:8443",
		ServerFingerprint: "sha256:A1B2C3D4E5F6",
		CACertPath:        "/data/integrations/sluice/ca.pem",
		ClientCertPath:    "/data/integrations/sluice/client.pem",
		ClientKeyPath:     "/data/integrations/sluice/client.key",
	})
	if err != nil {
		t.Fatalf("Add: %v", err)
	}
	// Fingerprint must be normalised (lowercase, no prefix, no colons).
	if inst.ServerFingerprint != "a1b2c3d4e5f6" {
		t.Errorf("fingerprint not normalised: %q", inst.ServerFingerprint)
	}
	if inst.EnrolledAt.IsZero() {
		t.Error("EnrolledAt was not set on insert")
	}

	// Reload from disk.
	fresh := &CDRInstanceRegistry{}
	if err := fresh.Load(path); err != nil {
		t.Fatal(err)
	}
	list := fresh.List()
	if len(list) != 1 || list[0].Name != "sluice-01" {
		t.Fatalf("reload: %+v", list)
	}
	if list[0].ServerFingerprint != "a1b2c3d4e5f6" {
		t.Errorf("fingerprint lost through persistence round-trip: %q", list[0].ServerFingerprint)
	}
}

func TestCDRInstanceRegistry_AddRejectsDuplicateName(t *testing.T) {
	reg := &CDRInstanceRegistry{}
	if _, err := reg.Add(CDREnrolledInstance{Name: "dup", Endpoint: "sluice:8443"}); err != nil {
		t.Fatal(err)
	}
	_, err := reg.Add(CDREnrolledInstance{Name: "dup", Endpoint: "sluice-2:8443"})
	if err == nil {
		t.Fatal("expected duplicate-name rejection")
	}
	if !strings.Contains(err.Error(), "already enrolled") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCDRInstanceRegistry_AddRejectsEmptyFields(t *testing.T) {
	reg := &CDRInstanceRegistry{}
	if _, err := reg.Add(CDREnrolledInstance{Endpoint: "x:1"}); err == nil {
		t.Fatal("empty name should fail")
	}
	if _, err := reg.Add(CDREnrolledInstance{Name: "x"}); err == nil {
		t.Fatal("empty endpoint should fail")
	}
}

func TestCDRInstanceRegistry_RemoveByName(t *testing.T) {
	reg := &CDRInstanceRegistry{}
	_, _ = reg.Add(CDREnrolledInstance{Name: "a", Endpoint: "1"})
	_, _ = reg.Add(CDREnrolledInstance{Name: "b", Endpoint: "2"})

	ok, err := reg.RemoveByName("a")
	if err != nil || !ok {
		t.Fatalf("remove a: %v, %v", ok, err)
	}
	if got := reg.List(); len(got) != 1 || got[0].Name != "b" {
		t.Fatalf("after remove: %+v", got)
	}

	// Idempotent.
	if ok, err := reg.RemoveByName("ghost"); err != nil || ok {
		t.Fatalf("RemoveByName(ghost) = %v, %v", ok, err)
	}
}

func TestCDRInstanceRegistry_GetAndFirstEnabled(t *testing.T) {
	reg := &CDRInstanceRegistry{}
	disabled := false
	_, _ = reg.Add(CDREnrolledInstance{Name: "off", Endpoint: "1", Enabled: &disabled})
	_, _ = reg.Add(CDREnrolledInstance{Name: "on", Endpoint: "2"})

	if got := reg.Get("off"); got == nil {
		t.Fatal("Get(off) returned nil")
	}
	if got := reg.firstEnabled(); got == nil || got.Name != "on" {
		t.Fatalf("firstEnabled = %+v, want 'on'", got)
	}
}

func TestNormaliseFingerprint(t *testing.T) {
	cases := map[string]string{
		"":                              "",
		"sha256:ABCDEF":                 "abcdef",
		"SHA256:AB:CD:EF":               "abcdef",
		"ab:cd:ef":                      "abcdef",
		"   SHA256:aB:cD:eF  ":          "abcdef",
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": // 64-char pass-through
			"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for in, want := range cases {
		if got := normaliseFingerprint(in); got != want {
			t.Errorf("normaliseFingerprint(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── Client lifecycle ───────────────────────────────────────────────────────

func TestInitCDRClient_DisabledIsNoOp(t *testing.T) {
	resetCDRClient(t)
	if err := initCDRClient(CDRConfig{Enabled: false}); err != nil {
		t.Fatalf("disabled init should succeed: %v", err)
	}
	if cdrActiveClient() != nil {
		t.Fatal("disabled init should not leave a client active")
	}
}

func TestInitCDRClient_NoInstanceNoEndpointFails(t *testing.T) {
	resetCDRClient(t)
	// Make sure registry is empty for this test.
	origInstances := cdrInstances
	cdrInstances = &CDRInstanceRegistry{}
	t.Cleanup(func() { cdrInstances = origInstances })

	err := initCDRClient(CDRConfig{Enabled: true})
	if err == nil {
		t.Fatal("expected error when enabled without instances or endpoint")
	}
	if !strings.Contains(err.Error(), "no enrolled instances") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestInitCDRClient_FallbackToConfigEndpointWithoutCerts(t *testing.T) {
	resetCDRClient(t)
	origInstances := cdrInstances
	cdrInstances = &CDRInstanceRegistry{}
	t.Cleanup(func() { cdrInstances = origInstances })

	// Config supplies endpoint + fingerprint but no cert dir — this is
	// the pre-enrollment bootstrap state.  NewCDRClient requires either
	// fingerprint or CA; with fingerprint it succeeds, even though the
	// connection won't be usable until certs arrive.
	err := initCDRClient(CDRConfig{
		Enabled:           true,
		Endpoint:          "127.0.0.1:8443",
		ServerFingerprint: strings.Repeat("ab", 32), // 64 hex = valid sha256
	})
	if err != nil {
		t.Fatalf("bootstrap init should succeed: %v", err)
	}
	if cdrActiveClient() == nil {
		t.Fatal("client should be active")
	}
}

func TestShutdownCDRClient_Idempotent(t *testing.T) {
	resetCDRClient(t)
	// Double-shutdown must not panic or leak.
	shutdownCDRClient()
	shutdownCDRClient()
	if cdrActiveClient() != nil {
		t.Fatal("client must be nil after shutdown")
	}
}

// resetCDRClient clears the singleton before / after a test.  Tests that
// touch the lifecycle must call this to avoid cross-pollution.
func resetCDRClient(t *testing.T) {
	t.Helper()
	shutdownCDRClient()
	t.Cleanup(shutdownCDRClient)
}

// Integration smoke: register an instance, then firstEnabled picks it.
func TestRegistry_FirstEnabledIntegration(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "cdr_instances.json")
	reg := &CDRInstanceRegistry{}
	if err := reg.Load(path); err != nil {
		t.Fatal(err)
	}
	if _, err := reg.Add(CDREnrolledInstance{
		Name:     "live",
		Endpoint: "sluice:8443",
	}); err != nil {
		t.Fatal(err)
	}
	// Ensure file exists with content.
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		t.Fatalf("registry file not written: %v (len=%d)", err, len(data))
	}
	if got := reg.firstEnabled(); got == nil || got.Name != "live" {
		t.Fatalf("firstEnabled = %+v", got)
	}
}
