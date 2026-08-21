package mcpacceptance

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ── Spec ─────────────────────────────────────────────────────────────────────

// validAuthoritativeEnv returns a structurally complete authoritative EnvSpec (the
// values are placeholders; Validate performs no filesystem access — file existence
// is enforced later by the fixture loader).
func validAuthoritativeEnv() *EnvSpec {
	return &EnvSpec{
		BindHost:                "127.0.0.1",
		OAuthIssuer:             "https://idp.example/issuer",
		CanonicalResource:       "https://gw.example/mcp/gateway",
		RequiredScopes:          []string{"gateway.tools.call"},
		AcceptedClientIDs:       []string{"client-gw"},
		TenantA:                 "tenant-a",
		TenantB:                 "tenant-b",
		ServerA:                 "srv-a",
		ServerB:                 "srv-b",
		TLSCertFile:             "/env/tls.crt",
		TLSKeyFile:              "/env/tls.key",
		ServerCAFile:            "/env/ca.crt",
		TrustedJWKS:             "/env/jwks.json",
		SigningKeyFile:          "/env/signer.key",
		SigningKID:              "kid-1",
		GatewayPort:             9443,
		QualificationPolicyFile: "/env/policy.json",
		Telemetry:               &TelemetryEnv{NodeID: "node-a", DataDir: "/env/tel/data", KEKFile: "/env/tel/kek", ArchiveDir: "/env/tel/arch"},
		Supervision:             &SupervisionEnv{AdminPort: 9090, MetricsPort: 9091, AdminUser: "acc-admin", AdminPasswordFile: "/env/admin.pass", MetricsTokenFile: "/env/metrics.tok"},
	}
}

func TestSpec_AuthoritativeRequiresDigestAndProvenance(t *testing.T) {
	base := Spec{Artifact: ArtifactSpec{BinaryPath: "/x/culvert"}, EvidenceDir: "/tmp/e", Mode: ModeAuthoritative}
	if err := base.Validate(); err == nil {
		t.Fatal("authoritative without digest must fail")
	}
	base.Artifact.ExpectedDigest = "sha256:abc"
	if err := base.Validate(); err == nil {
		t.Fatal("authoritative without provenance must fail")
	}
	base.Artifact.Provenance = &ProvenanceSpec{VerifiedDigest: "sha256:abc"}
	if err := base.Validate(); err == nil {
		t.Fatal("authoritative without environment must fail")
	}
	base.Environment = &EnvSpec{}
	if err := base.Validate(); err == nil {
		t.Fatal("authoritative with an empty environment must fail (QUAL-6.1 strictness)")
	}
	base.Environment = validAuthoritativeEnv()
	if err := base.Validate(); err != nil {
		t.Fatalf("valid authoritative spec rejected: %v", err)
	}
}

// TestSpec_AuthoritativeNoFallback pins QUAL-6.1 strictness: every authoritative
// environment control is required, and removing any one fails validation before any
// traffic (no fallback to a dev fixture).
func TestSpec_AuthoritativeNoFallback(t *testing.T) {
	base := func() Spec {
		return Spec{Mode: ModeAuthoritative, EvidenceDir: "/tmp/e",
			Artifact:    ArtifactSpec{BinaryPath: "/x/culvert", ExpectedDigest: "sha256:abc", ExpectedSourceCommit: "c", Provenance: &ProvenanceSpec{VerifiedDigest: "sha256:abc"}},
			Environment: validAuthoritativeEnv()}
	}
	baseline := base()
	if err := baseline.Validate(); err != nil {
		t.Fatalf("baseline valid authoritative spec must pass: %v", err)
	}
	cases := []struct {
		name string
		mut  func(e *EnvSpec)
	}{
		{"missing_bind_host", func(e *EnvSpec) { e.BindHost = "" }},
		{"wildcard_bind_host", func(e *EnvSpec) { e.BindHost = "0.0.0.0" }},
		{"invalid_bind_host", func(e *EnvSpec) { e.BindHost = "not a host/x" }},
		{"missing_gateway_port", func(e *EnvSpec) { e.GatewayPort = 0 }},
		{"missing_policy", func(e *EnvSpec) { e.QualificationPolicyFile = "" }},
		{"missing_telemetry", func(e *EnvSpec) { e.Telemetry = nil }},
		{"missing_telemetry_kek", func(e *EnvSpec) { e.Telemetry.KEKFile = "" }},
		{"missing_telemetry_data", func(e *EnvSpec) { e.Telemetry.DataDir = "" }},
		{"missing_telemetry_archive", func(e *EnvSpec) { e.Telemetry.ArchiveDir = "" }},
		{"missing_telemetry_node", func(e *EnvSpec) { e.Telemetry.NodeID = "" }},
		{"missing_supervision", func(e *EnvSpec) { e.Supervision = nil }},
		{"missing_admin_port", func(e *EnvSpec) { e.Supervision.AdminPort = 0 }},
		{"missing_metrics_port", func(e *EnvSpec) { e.Supervision.MetricsPort = 0 }},
		{"duplicate_ports", func(e *EnvSpec) { e.Supervision.MetricsPort = e.Supervision.AdminPort }},
		{"missing_admin_user", func(e *EnvSpec) { e.Supervision.AdminUser = "" }},
		{"missing_admin_password_file", func(e *EnvSpec) { e.Supervision.AdminPasswordFile = "" }},
		{"missing_metrics_token_file", func(e *EnvSpec) { e.Supervision.MetricsTokenFile = "" }},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			s := base()
			c.mut(s.Environment)
			if err := s.Validate(); err == nil {
				t.Fatalf("authoritative spec with %s must fail validation (no fallback)", c.name)
			}
		})
	}
}

func TestSpec_DevValidAndUnknownModeRejected(t *testing.T) {
	dev := Spec{Artifact: ArtifactSpec{BinaryPath: "/x/culvert"}, EvidenceDir: "/tmp/e", Mode: ModeDev}
	if err := dev.Validate(); err != nil {
		t.Fatalf("dev spec should validate: %v", err)
	}
	bad := Spec{Artifact: ArtifactSpec{BinaryPath: "/x"}, EvidenceDir: "/tmp/e", Mode: "wat"}
	if err := bad.Validate(); err == nil {
		t.Fatal("unknown mode must be rejected")
	}
}

func TestSpec_ConfigHashDeterministic(t *testing.T) {
	s := Spec{Artifact: ArtifactSpec{BinaryPath: "/x/culvert"}, EvidenceDir: "/tmp/e", Mode: ModeDev}
	h1, err := s.ConfigHash()
	if err != nil {
		t.Fatal(err)
	}
	h2, _ := s.ConfigHash()
	if h1 != h2 || !strings.HasPrefix(h1, "sha256:") {
		t.Fatalf("config hash not deterministic: %s vs %s", h1, h2)
	}
}

func TestRunControl_TimeoutsBoundedAndDefaulted(t *testing.T) {
	var rc RunControl
	if rc.startup() != defaultStartupTimeout {
		t.Fatal("zero startup should default")
	}
	rc.StartupTimeout = Duration(maxStartupTimeout * 10)
	if rc.startup() != maxStartupTimeout {
		t.Fatalf("startup must clamp to max, got %v", rc.startup())
	}
}

// ── Artifact binding ─────────────────────────────────────────────────────────

func writeBinary(t *testing.T, content string) (binPath, digest string) {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "culvert")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	dig, err := hashBinary(p)
	if err != nil {
		t.Fatal(err)
	}
	return p, dig
}

func TestArtifact_DevRecordsDigestNonAuthoritative(t *testing.T) {
	p, dig := writeBinary(t, "fake-binary")
	id, err := bindArtifact(&Spec{Mode: ModeDev, Artifact: ArtifactSpec{BinaryPath: p}, EvidenceDir: "/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if id.Authoritative {
		t.Fatal("dev must never be authoritative")
	}
	if id.Digest != dig {
		t.Fatalf("digest mismatch: %s vs %s", id.Digest, dig)
	}
}

func TestArtifact_AuthoritativeWrongDigestFailsPreSpawn(t *testing.T) {
	p, _ := writeBinary(t, "real-binary")
	_, err := bindArtifact(&Spec{Mode: ModeAuthoritative, EvidenceDir: "/tmp",
		Artifact: ArtifactSpec{BinaryPath: p, ExpectedDigest: "sha256:deadbeef", ExpectedSourceCommit: "c",
			Provenance: &ProvenanceSpec{VerifiedDigest: "sha256:deadbeef"}}, Environment: &EnvSpec{}})
	if err == nil {
		t.Fatal("authoritative with wrong expected digest must fail before spawn")
	}
}

func TestArtifact_AuthoritativeMissingProvenanceFails(t *testing.T) {
	p, dig := writeBinary(t, "real-binary")
	_, err := bindArtifact(&Spec{Mode: ModeAuthoritative, EvidenceDir: "/tmp",
		Artifact: ArtifactSpec{BinaryPath: p, ExpectedDigest: dig, ExpectedSourceCommit: "c"}, Environment: &EnvSpec{}})
	if err == nil {
		t.Fatal("authoritative without provenance must fail (no silent downgrade)")
	}
}

func TestArtifact_AuthoritativeMatchBinds(t *testing.T) {
	p, dig := writeBinary(t, "real-binary")
	id, err := bindArtifact(&Spec{Mode: ModeAuthoritative, EvidenceDir: "/tmp",
		Artifact: ArtifactSpec{BinaryPath: p, ExpectedDigest: dig, ExpectedSourceCommit: "abc123",
			Provenance: &ProvenanceSpec{VerifiedDigest: dig, Verifier: "cosign-keyless"}}, Environment: &EnvSpec{}})
	if err != nil {
		t.Fatal(err)
	}
	if !id.Authoritative || id.Verification != "provenance-bound" {
		t.Fatalf("expected authoritative provenance-bound, got %+v", id)
	}
}

func TestArtifact_DevCannotBecomeAuthoritativeByDigest(t *testing.T) {
	// Even if a dev spec supplies a matching expected digest, it stays non-auth.
	p, dig := writeBinary(t, "real-binary")
	id, err := bindArtifact(&Spec{Mode: ModeDev, EvidenceDir: "/tmp", Artifact: ArtifactSpec{BinaryPath: p, ExpectedDigest: dig}})
	if err != nil {
		t.Fatal(err)
	}
	if id.Authoritative {
		t.Fatal("dev mode must never be authoritative regardless of digest")
	}
}

// ── Results ──────────────────────────────────────────────────────────────────

func TestComputeOverall_AllRequiredPass(t *testing.T) {
	crit := []CriterionResult{{ID: "a", Required: true, Status: StatusPass}, {ID: "b", Required: true, Status: StatusPass}}
	ov, missing := computeOverall(crit, []string{"a", "b"}, false, false)
	if ov != StatusPass || len(missing) != 0 {
		t.Fatalf("expected PASS/no-missing, got %s %v", ov, missing)
	}
}

func TestComputeOverall_RequiredFail(t *testing.T) {
	crit := []CriterionResult{{ID: "a", Required: true, Status: StatusFail}}
	ov, _ := computeOverall(crit, []string{"a"}, false, false)
	if ov != StatusFail {
		t.Fatal("a failed required must be FAIL")
	}
}

func TestComputeOverall_RequiredMissing(t *testing.T) {
	crit := []CriterionResult{{ID: "a", Required: true, Status: StatusPass}}
	ov, missing := computeOverall(crit, []string{"a", "b"}, false, false)
	if ov != StatusFail || len(missing) != 1 || missing[0] != "b" {
		t.Fatalf("missing required must FAIL: %s %v", ov, missing)
	}
}

func TestComputeOverall_OptionalSkipDoesNotFail(t *testing.T) {
	crit := []CriterionResult{{ID: "a", Required: true, Status: StatusPass}, {ID: "opt", Required: false, Status: StatusSkip}}
	ov, _ := computeOverall(crit, []string{"a"}, false, false)
	if ov != StatusPass {
		t.Fatal("an optional SKIP must not fail Observe acceptance")
	}
}

func TestComputeOverall_AuthoritativeRequiredButNot(t *testing.T) {
	crit := []CriterionResult{{ID: "a", Required: true, Status: StatusPass}}
	ov, _ := computeOverall(crit, []string{"a"}, false, true)
	if ov != StatusFail {
		t.Fatal("wantAuthoritative && !authoritative must FAIL")
	}
}

// ── Evidence: determinism, manifest, secret scan ─────────────────────────────

func TestCanonicalJSON_Deterministic(t *testing.T) {
	s := Summary{RunID: "r", Overall: StatusPass, Criteria: []CriterionResult{{ID: "x", Status: StatusPass}}}
	a, _ := canonicalJSON(s)
	b, _ := canonicalJSON(s)
	if !bytes.Equal(a, b) {
		t.Fatal("canonical JSON must be byte-stable")
	}
}

func TestManifest_DeterministicAndDetectsMutation(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), []byte(`{"a":1}`), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"b":2}`), 0o600)
	m1, err := buildManifest(dir)
	if err != nil {
		t.Fatal(err)
	}
	m2, _ := buildManifest(dir)
	if m1.ManifestDigest != m2.ManifestDigest {
		t.Fatal("manifest digest must be deterministic")
	}
	_ = os.WriteFile(filepath.Join(dir, "b.json"), []byte(`{"b":3}`), 0o600)
	m3, _ := buildManifest(dir)
	if m3.ManifestDigest == m1.ManifestDigest {
		t.Fatal("manifest digest must change when a file mutates")
	}
}

func TestSecretScan_FindsKnownValueAndPatternsBounded(t *testing.T) {
	dir := t.TempDir()
	scan := NewSecretScan()
	scan.Add("bearer_token", "supersecrettokenvalue12345")
	// Bundle file that leaks a known token and a private key header.
	leak := "token=supersecrettokenvalue12345\n-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----\n"
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), []byte(leak), 0o600)
	viols, err := scan.Scan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(viols) < 2 {
		t.Fatalf("expected >=2 violations, got %d", len(viols))
	}
	// The violation must NOT contain the secret value itself — only a classification.
	for _, v := range viols {
		if strings.Contains(v.Classification, "supersecret") || strings.Contains(v.Location, "supersecret") {
			t.Fatal("violation leaked the secret value")
		}
	}
}

func TestSecretScan_CleanBundlePasses(t *testing.T) {
	dir := t.TempDir()
	scan := NewSecretScan()
	scan.Add("bearer_token", "supersecrettokenvalue12345")
	_ = os.WriteFile(filepath.Join(dir, "summary.json"), []byte(`{"overall":"PASS","observed":"rejected status=401"}`), 0o600)
	viols, _ := scan.Scan(dir)
	if len(viols) != 0 {
		t.Fatalf("clean bundle must have no violations, got %v", viols)
	}
}

func TestSecretScan_ShortValuesIgnored(t *testing.T) {
	scan := NewSecretScan()
	scan.Add("x", "abc") // < 8 bytes, ignored to avoid false positives
	if len(scan.values) != 0 {
		t.Fatal("short values must be ignored")
	}
}

// ── Token minting round-trips a valid JWKS key ───────────────────────────────

func TestMintBearer_ProducesThreeSegmentJWT(t *testing.T) {
	k, err := genEC()
	if err != nil {
		t.Fatal(err)
	}
	tok, err := mintBearer(k, tokenParams{issuer: "i", clientID: "c", audience: "a", scope: "s", tenant: "t", subject: "u", kid: "kid"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tok, ".") != 2 || !strings.HasPrefix(tok, "eyJ") {
		t.Fatalf("not a JWT: %q", tok)
	}
}

// ── Qualification-window guard: the harness must never call rollout/window APIs ─

func TestNoQualificationWindowCalls(t *testing.T) {
	// Call-shaped tokens: prove no CALL path exists (doc-comment mentions of the
	// window/rollout APIs are allowed — the point is the harness never invokes them,
	// which is structurally guaranteed by TestNoInternalMCPImports anyway).
	forbidden := []string{"BeginWindow(", "Promote(", "SetEligibility(", "TransitionTo(", "MarkUsable(", ".Approve("}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f) // #nosec G304 -- test reads package-local source
		if err != nil {
			t.Fatal(err)
		}
		for _, bad := range forbidden {
			if strings.Contains(string(b), bad) {
				t.Fatalf("%s references forbidden qualification/rollout API %q", f, bad)
			}
		}
	}
}

// The harness package must not import any internal/mcp runtime/policy/rollout
// package (it drives the binary at the boundary, never internal constructors).
// The command package (cmd/mcp-observe-acceptance) imports only this library, so
// scanning the package-local sources here is sufficient to cover the boundary.
func TestNoInternalMCPImports(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f) // #nosec G304 -- test reads package-local source
		if strings.Contains(string(b), "KidCarmi/Culvert/internal/mcp/") {
			t.Fatalf("%s imports an internal/mcp package; the harness must use the binary boundary only", f)
		}
	}
}
