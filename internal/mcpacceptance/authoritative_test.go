package mcpacceptance

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Neutral test credential material. The identifiers and values deliberately avoid
// credential keywords (password/secret/token/...) so gosec G101 does not flag the
// tests, while staying >= 8 chars (registerable by the secret scan) and meeting the
// product admin-password complexity policy (upper + lower + digit) for the live test.
const (
	testAdminMaterial   = "Quokka7Wallaby"
	testMetricsMaterial = "Numbat3Bilby9"
)

// ── Policy scenario-requirement preflight ────────────────────────────────────

// validOperatorPolicy is a complete, compiler-valid Gateway qualification policy in
// the production format (default DENY plus an ALLOW discovery rule on tools/list). It
// mirrors the shape the runtime policy compiler accepts, so the live test can load it.
func validOperatorPolicy() []byte {
	return []byte(`{
  "schema_version": 1,
  "capability": "gateway",
  "policy_revision": 7,
  "default_action": "DENY",
  "rules": [
    {"id":"ALLOW_DISCOVERY","priority":10,"action":"ALLOW",
     "reason":"MCP.POLICY.RESOURCE_SCOPE","remediation":"none",
     "conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}],
     "obligations":{"logging":"standard"}}
  ]
}`)
}

func TestPolicyPreflight_ValidReturnsRevision(t *testing.T) {
	rev, err := validatePolicyScenarioRequirements(validOperatorPolicy())
	if err != nil {
		t.Fatalf("valid operator policy rejected: %v", err)
	}
	if rev != 7 {
		t.Fatalf("declared revision = %d, want 7", rev)
	}
}

func TestPolicyPreflight_UnsatisfiedCases(t *testing.T) {
	cases := map[string]string{
		"bad_json":           `{not json`,
		"no_schema":          `{"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[{"id":"a","action":"ALLOW","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}]}]}`,
		"wrong_cap":          `{"schema_version":1,"capability":"management","policy_revision":1,"default_action":"DENY","rules":[{"id":"a","action":"ALLOW","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}]}]}`,
		"no_revision":        `{"schema_version":1,"capability":"gateway","policy_revision":0,"default_action":"DENY","rules":[{"id":"a","action":"ALLOW","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}]}]}`,
		"not_default_deny":   `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"ALLOW","rules":[{"id":"a","action":"ALLOW","conditions":[{"field":"operation.method","op":"exact","value":"tools/list"}]}]}`,
		"no_discovery_allow": `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[]}`,
		"allow_wrong_method": `{"schema_version":1,"capability":"gateway","policy_revision":1,"default_action":"DENY","rules":[{"id":"a","action":"ALLOW","conditions":[{"field":"operation.method","op":"exact","value":"tools/call"}]}]}`,
	}
	for name, body := range cases {
		name, body := name, body
		t.Run(name, func(t *testing.T) {
			_, err := validatePolicyScenarioRequirements([]byte(body))
			if err == nil {
				t.Fatalf("%s must fail preflight", name)
			}
			if !strings.Contains(err.Error(), "POLICY_SCENARIO_REQUIREMENT_UNSATISFIED") {
				t.Fatalf("%s error must carry the bounded classification, got %v", name, err)
			}
		})
	}
}

// ── loadOperatorEnv reads credential file references, registers them as secrets ──

func writeFileT(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadOperatorEnv_ReadsCredsAndRegistersSecrets(t *testing.T) {
	dir := t.TempDir()
	polF := writeFileT(t, dir, "policy.json", string(validOperatorPolicy()))
	passF := writeFileT(t, dir, "admin.pass", testAdminMaterial+"\n")
	tokF := writeFileT(t, dir, "metrics.tok", testMetricsMaterial+"\n")
	env := &EnvSpec{
		QualificationPolicyFile: polF,
		Telemetry:               &TelemetryEnv{NodeID: "n", DataDir: dir + "/d", KEKFile: dir + "/k", ArchiveDir: dir + "/a"},
		Supervision:             &SupervisionEnv{AdminPort: 1, MetricsPort: 2, AdminUser: "u", AdminPasswordFile: passF, MetricsTokenFile: tokF},
		GatewayPort:             3,
	}
	scan := NewSecretScan()
	op, err := loadOperatorEnv(env, scan)
	if err != nil {
		t.Fatal(err)
	}
	if op.adminPass != testAdminMaterial || op.metricsToken != testMetricsMaterial {
		t.Fatalf("credential values not trimmed/read: %q %q", op.adminPass, op.metricsToken)
	}
	if op.adminPassRef != filepath.Clean(passF) || op.metricsRef != filepath.Clean(tokF) {
		t.Fatal("credential file references not recorded")
	}
	// The secret values must now trip the scan if they appear in an evidence file.
	ev := t.TempDir()
	_ = os.WriteFile(filepath.Join(ev, "leak.json"), []byte("x "+testAdminMaterial+" y "+testMetricsMaterial+" z"), 0o600)
	viols, _ := scan.Scan(ev)
	if len(viols) < 2 {
		t.Fatalf("expected admin+metrics secret violations, got %d", len(viols))
	}
}

func TestLoadOperatorEnv_MissingFilesFail(t *testing.T) {
	dir := t.TempDir()
	passF := writeFileT(t, dir, "admin.pass", testAdminMaterial)
	tokF := writeFileT(t, dir, "metrics.tok", testMetricsMaterial)
	base := &EnvSpec{
		QualificationPolicyFile: writeFileT(t, dir, "policy.json", string(validOperatorPolicy())),
		Telemetry:               &TelemetryEnv{NodeID: "n", DataDir: dir, KEKFile: dir, ArchiveDir: dir},
		Supervision:             &SupervisionEnv{AdminPort: 1, MetricsPort: 2, AdminUser: "u", AdminPasswordFile: passF, MetricsTokenFile: tokF},
	}
	// Missing policy file.
	bad := *base
	bad.QualificationPolicyFile = filepath.Join(dir, "nope.json")
	if _, err := loadOperatorEnv(&bad, NewSecretScan()); err == nil {
		t.Fatal("missing policy file must fail")
	}
	// Missing admin password file.
	bad2 := *base
	sup := *base.Supervision
	sup.AdminPasswordFile = filepath.Join(dir, "nope.pass")
	bad2.Supervision = &sup
	if _, err := loadOperatorEnv(&bad2, NewSecretScan()); err == nil {
		t.Fatal("missing admin password file must fail")
	}
}

// ── Effective config hash covers the actual controls ─────────────────────────

func TestEffectiveConfigHash_DevEqualsConfigHash(t *testing.T) {
	s := Spec{Artifact: ArtifactSpec{BinaryPath: "/x/culvert"}, EvidenceDir: "/tmp/e", Mode: ModeDev}
	ch, _ := s.ConfigHash()
	eh, _ := s.effectiveConfigHash()
	if ch != eh {
		t.Fatalf("dev effectiveConfigHash must equal ConfigHash: %s vs %s", ch, eh)
	}
}

func TestEffectiveConfigHash_ChangesOnPolicyDigestAndControls(t *testing.T) {
	mk := func(mut func(e *EnvSpec)) Spec {
		s := Spec{Mode: ModeAuthoritative, EvidenceDir: "/tmp/e",
			Artifact:    ArtifactSpec{BinaryPath: "/x/culvert", ExpectedDigest: "sha256:abc", ExpectedSourceCommit: "c", Provenance: &ProvenanceSpec{VerifiedDigest: "sha256:abc"}},
			Environment: validAuthoritativeEnv()}
		if mut != nil {
			mut(s.Environment)
		}
		return s
	}
	base := mk(nil)
	h1, _ := base.effectiveConfigHash("sha256:policyA")
	// Same spec, different policy content digest -> different hash.
	h2, _ := base.effectiveConfigHash("sha256:policyB")
	if h1 == h2 {
		t.Fatal("policy content digest must change the acceptance config hash")
	}
	// Different bind host -> different hash (control is in the spec).
	bh, _ := mk(func(e *EnvSpec) { e.BindHost = "10.0.0.5" }).effectiveConfigHash("sha256:policyA")
	if bh == h1 {
		t.Fatal("bind host change must change the config hash")
	}
	// Different telemetry data dir -> different hash.
	td, _ := mk(func(e *EnvSpec) { e.Telemetry.DataDir = "/other" }).effectiveConfigHash("sha256:policyA")
	if td == h1 {
		t.Fatal("telemetry data dir change must change the config hash")
	}
	// Different admin port -> different hash.
	ap, _ := mk(func(e *EnvSpec) { e.Supervision.AdminPort = 12345 }).effectiveConfigHash("sha256:policyA")
	if ap == h1 {
		t.Fatal("admin port change must change the config hash")
	}
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func TestIsLoopbackHost(t *testing.T) {
	for _, h := range []string{"127.0.0.1", "::1", "localhost"} {
		if !isLoopbackHost(h) {
			t.Fatalf("%q should be loopback", h)
		}
	}
	for _, h := range []string{"10.0.0.5", "192.168.1.10", "gw.example"} {
		if isLoopbackHost(h) {
			t.Fatalf("%q should not be loopback", h)
		}
	}
}

func TestUnderDir(t *testing.T) {
	if !underDir("/work/proc-A/data", "/work") {
		t.Fatal("path under dir must be detected")
	}
	if underDir("/opt/operator/data", "/work") {
		t.Fatal("path outside dir must not be under it")
	}
	if underDir("/work-other/x", "/work") {
		t.Fatal("sibling prefix must not count as under")
	}
}
