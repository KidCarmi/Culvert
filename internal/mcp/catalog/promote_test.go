package catalog

import (
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// fpOf returns the current fingerprint of a tool by name (fails the test if absent).
func fpOf(t *testing.T, c *Catalog, name string) Fingerprint {
	t.Helper()
	rec, ok := c.Current().Get(ToolKey{Server: testServer, Name: name})
	if !ok {
		t.Fatalf("tool %q not present", name)
	}
	return rec.Fingerprint
}

func TestPromote_QuarantinedToUsableOnExactFingerprint(t *testing.T) {
	l := lim(t)
	reg := oneServerReg(t, l)
	c := New(l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	if eligOf(c, "t") != Quarantined {
		t.Fatalf("seeded tool must be quarantined, got %s", eligOf(c, "t"))
	}
	key := ToolKey{Server: testServer, Name: "t"}
	if _, err := c.Promote(key, fpOf(t, c, "t")); err != nil {
		t.Fatalf("Promote: %v", err)
	}
	if eligOf(c, "t") != Usable {
		t.Fatalf("after promote elig = %s, want usable", eligOf(c, "t"))
	}
}

func TestPromote_Idempotent(t *testing.T) {
	l := lim(t)
	reg := oneServerReg(t, l)
	c := New(l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	key := ToolKey{Server: testServer, Name: "t"}
	expected := fpOf(t, c, "t")
	if _, err := c.Promote(key, expected); err != nil {
		t.Fatalf("first promote: %v", err)
	}
	rev1 := c.Current().Revision()
	if _, err := c.Promote(key, expected); err != nil {
		t.Fatalf("idempotent promote: %v", err)
	}
	if c.Current().Revision() != rev1 {
		t.Fatal("idempotent promote must not bump the revision")
	}
	if eligOf(c, "t") != Usable {
		t.Fatal("still usable")
	}
}

func TestPromote_FingerprintMismatchFailsClosed(t *testing.T) {
	l := lim(t)
	reg := oneServerReg(t, l)
	c := New(l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	key := ToolKey{Server: testServer, Name: "t"}
	wrong := fpOf(t, c, "t")
	wrong.Name = "different" // any dimension change ⇒ a different Sum()
	_, err := c.Promote(key, wrong)
	if mcperr.ReasonOf(err) != mcperr.ReasonToolFingerprintMismatch {
		t.Fatalf("reason = %s, want tool_fingerprint_mismatch", mcperr.ReasonOf(err).Code())
	}
	if eligOf(c, "t") != Quarantined {
		t.Fatal("a rug-pull promote must not change eligibility")
	}
}

func TestPromote_ServerDisabledRefused(t *testing.T) {
	l := lim(t)
	reg := oneServerReg(t, l)
	c := New(l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	expected := fpOf(t, c, "t")
	// A server-identity change disables every tool behind it (security override).
	if _, err := c.DisableServer(testServer); err != nil {
		t.Fatalf("DisableServer: %v", err)
	}
	key := ToolKey{Server: testServer, Name: "t"}
	_, err := c.Promote(key, expected)
	if mcperr.ReasonOf(err) != mcperr.ReasonToolNotApprovable {
		t.Fatalf("reason = %s, want tool_not_approvable", mcperr.ReasonOf(err).Code())
	}
	if eligOf(c, "t") != ServerDisabled {
		t.Fatal("server-disabled must survive a promote attempt")
	}
}

func TestPromote_UnknownToolNotFound(t *testing.T) {
	l := lim(t)
	c := New(l)
	_, err := c.Promote(ToolKey{Server: testServer, Name: "ghost"}, Fingerprint{})
	if mcperr.ReasonOf(err) != mcperr.ReasonToolNotFound {
		t.Fatalf("reason = %s, want tool_not_found", mcperr.ReasonOf(err).Code())
	}
}

func TestDemote_UsableBackToQuarantined(t *testing.T) {
	l := lim(t)
	reg := oneServerReg(t, l)
	c := New(l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	key := ToolKey{Server: testServer, Name: "t"}
	if _, err := c.Promote(key, fpOf(t, c, "t")); err != nil {
		t.Fatalf("promote: %v", err)
	}
	if _, err := c.Demote(key); err != nil {
		t.Fatalf("Demote: %v", err)
	}
	if eligOf(c, "t") != Quarantined {
		t.Fatalf("after demote elig = %s, want quarantined", eligOf(c, "t"))
	}
}

func TestDemote_NonUsableIsNoOp(t *testing.T) {
	l := lim(t)
	reg := oneServerReg(t, l)
	c := New(l)
	ingest(t, c, reg, testServer, testIdentity, result(`{"name":"t","inputSchema":{"type":"object"}}`))
	rev := c.Current().Revision()
	key := ToolKey{Server: testServer, Name: "t"}
	if _, err := c.Demote(key); err != nil {
		t.Fatalf("Demote no-op: %v", err)
	}
	if c.Current().Revision() != rev {
		t.Fatal("demoting a non-usable tool must not bump the revision")
	}
	// Absent key is also a clean no-op.
	if _, err := c.Demote(ToolKey{Server: testServer, Name: "ghost"}); err != nil {
		t.Fatalf("Demote absent: %v", err)
	}
}

// TestPromote_DriftAwayThenBack proves the flap-back projection (ADR-0034 D8):
// a promoted tool that drifts loses Usable via the ingest fold, and re-observing
// the EXACT reviewed fingerprint lets a re-promote restore it byte-identically.
func TestPromote_DriftAwayThenBack(t *testing.T) {
	l := lim(t)
	reg := oneServerReg(t, l)
	c := New(l)
	f1 := `{"name":"t","inputSchema":{"type":"object"}}`
	f2 := `{"name":"t","inputSchema":{"type":"object","properties":{"x":{"type":"string"}}}}`
	ingest(t, c, reg, testServer, testIdentity, result(f1))
	key := ToolKey{Server: testServer, Name: "t"}
	f1fp := fpOf(t, c, "t")
	if _, err := c.Promote(key, f1fp); err != nil {
		t.Fatalf("promote f1: %v", err)
	}
	// Drift to F2: the fold moves it off Usable, and a promote bound to F1 refuses.
	ingest(t, c, reg, testServer, testIdentity, result(f2))
	if eligOf(c, "t") == Usable {
		t.Fatal("drift must drop Usable")
	}
	if _, err := c.Promote(key, f1fp); mcperr.ReasonOf(err) != mcperr.ReasonToolFingerprintMismatch {
		t.Fatalf("promote against drifted tool must mismatch, got %s", mcperr.ReasonOf(err).Code())
	}
	// Return to the EXACT F1 fingerprint: a re-promote restores Usable.
	ingest(t, c, reg, testServer, testIdentity, result(f1))
	if _, err := c.Promote(key, f1fp); err != nil {
		t.Fatalf("re-promote f1: %v", err)
	}
	if eligOf(c, "t") != Usable {
		t.Fatal("exact-return must be re-promotable to Usable")
	}
}
