//go:build mcpacceptance_live

// Live authoritative-shape integration test. It builds an operator-style environment
// on disk (real PKI, JWKS, signer, an operator qualification policy, credential
// files, and operator-owned telemetry paths) and drives the primary process through
// the QUAL-6.1 effective-environment criteria against the REAL culvert binary.
//
// It deliberately does NOT run the full authoritative Run (which would require a
// provenance-verified signed release and would stamp authoritative:true). It drives
// the env-consumption path directly, so the result is unmistakably NON-authoritative
// (no bundle is emitted, authoritative is never set) while still proving, against a
// real binary, that the operator-selected policy, bind host, telemetry custody, and
// Admin/metrics supervision are actually consumed. It is gated behind
// mcpacceptance_live so standard CI never spawns a binary and never requires a signed
// release.
package mcpacceptance

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeLivePKI generates a CA + server leaf (SAN 127.0.0.1) + a signer key and JWKS
// on disk, returning the file paths the operator EnvSpec references.
func writeLivePKI(t *testing.T) (caFile, serverCert, serverKey, jwksFile, signerKeyFile string) {
	t.Helper()
	dir := t.TempDir()
	ca, caKey, _, err := genCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	sc, sk, err := genLeaf(dir, "server", "127.0.0.1", 2, true, ca, caKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := genEC()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	signerKeyFile = filepath.Join(dir, "signer.key")
	if err := os.WriteFile(signerKeyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	jwk, err := jwkPublic(&signer.PublicKey, "kid-1")
	if err != nil {
		t.Fatal(err)
	}
	jwksFile = filepath.Join(dir, "jwks.json")
	jb, _ := json.MarshalIndent(map[string]any{"keys": []any{jwk}}, "", "  ")
	if err := os.WriteFile(jwksFile, jb, 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "ca.crt"), sc, sk, jwksFile, signerKeyFile
}

// TestAuthoritativeEnvConsumption_Live proves the four closed gaps at the real binary
// boundary: the operator policy is evaluated, the operator bind host is bound, the
// operator telemetry is consumed + preserved, and the operator Admin/metrics
// endpoints are reachable and authenticated.
func TestAuthoritativeEnvConsumption_Live(t *testing.T) {
	if testing.Short() || builtBinary == "" {
		t.Skip("live authoritative test skipped (short mode or binary not built)")
	}
	caF, scF, skF, jwksF, signF := writeLivePKI(t)
	matDir := t.TempDir()
	polF := filepath.Join(matDir, "policy.json")
	if err := os.WriteFile(polF, validOperatorPolicy(), 0o600); err != nil {
		t.Fatal(err)
	}
	passF := filepath.Join(matDir, "admin.pass")
	tokF := filepath.Join(matDir, "metrics.tok")
	// The admin password must satisfy the product complexity policy (upper/lower/digit);
	// this is an operator responsibility in a real run.
	_ = os.WriteFile(passF, []byte(testAdminMaterial), 0o600)
	_ = os.WriteFile(tokF, []byte(testMetricsMaterial), 0o600)
	telRoot := t.TempDir() // operator-owned; outside the harness work root

	gwPort, _ := freePort()
	adminPort, _ := freePort()
	metricsPort, _ := freePort()

	env := &EnvSpec{
		BindHost: "127.0.0.1", OAuthIssuer: "https://idp.acceptance.test/issuer",
		CanonicalResource: "https://gw.test/mcp/gateway", RequiredScopes: []string{"gateway.tools.call"},
		AcceptedClientIDs: []string{"client-gw"}, TenantA: "tenant-a", TenantB: "tenant-b",
		ServerA: "srv-a", ServerB: "srv-b",
		TLSCertFile: scF, TLSKeyFile: skF, ServerCAFile: caF, TrustedJWKS: jwksF,
		SigningKeyFile: signF, SigningKID: "kid-1",
		GatewayPort: gwPort, QualificationPolicyFile: polF,
		Telemetry:   &TelemetryEnv{NodeID: "op-node", DataDir: filepath.Join(telRoot, "data"), KEKFile: filepath.Join(telRoot, "kek", "t.kek"), ArchiveDir: filepath.Join(telRoot, "arch")},
		Supervision: &SupervisionEnv{AdminPort: adminPort, MetricsPort: metricsPort, AdminUser: "acc-admin", AdminPasswordFile: passF, MetricsTokenFile: tokF},
	}

	work := t.TempDir()
	fx, err := NewFixtureFromEnv(filepath.Join(work, "fixture"), env, NewSecretScan())
	if err != nil {
		t.Fatalf("NewFixtureFromEnv: %v", err)
	}
	h := &Harness{
		spec:        &Spec{Mode: ModeAuthoritative, Run: RunControl{StartupTimeout: Duration(60 * time.Second), RequestTimeout: Duration(15 * time.Second), ShutdownTimeout: Duration(20 * time.Second)}},
		binary:      builtBinary,
		workDir:     work,
		evidenceDir: t.TempDir(),
		fixture:     fx,
		secrets:     fx.secrets,
		now:         time.Now,
		summary:     &Summary{SchemaVersion: EvidenceSchemaVersion, RunID: "live-auth"},
	}
	h.start = h.now()
	defer h.cleanup()

	if err := h.preflightAuthoritative(); err != nil {
		t.Fatalf("preflight: %v", err)
	}
	if h.operatorPolicyRevision != 7 {
		t.Fatalf("operator policy revision = %d, want 7", h.operatorPolicyRevision)
	}
	pa, pb, err := h.buildProcesses()
	if err != nil {
		t.Fatalf("buildProcesses: %v", err)
	}
	if err := h.buildClients(); err != nil {
		t.Fatalf("buildClients: %v", err)
	}
	if err := h.mintTokens(); err != nil {
		t.Fatalf("mintTokens: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	if h.procA, err = h.startProcess(ctx, pa); err != nil {
		if b, rerr := os.ReadFile(filepath.Join(filepath.Dir(pa.configPath), "logs", "stderr.log")); rerr == nil {
			t.Logf("proc A stderr:\n%s", string(b))
		}
		if b, rerr := os.ReadFile(pa.configPath); rerr == nil {
			t.Logf("proc A config:\n%s", string(b))
		}
		t.Fatalf("start A: %v", err)
	}
	if h.procB, err = h.startProcess(ctx, pb); err != nil {
		t.Fatalf("start B: %v", err)
	}
	h.buildSupervisionDescriptor()
	h.runAuthoritativeEnv(ctx)

	// Every QUAL-6.1 environment/supervision criterion must PASS at the real binary.
	want := map[string]bool{
		"environment.policy_operator_selected": true,
		"environment.bind_host_effective":      true,
		"environment.telemetry_operator_owned": true,
		"supervision.admin_reachable":          true,
		"supervision.metrics_reachable":        true,
	}
	for _, c := range h.summary.Criteria {
		if _, ok := want[c.ID]; ok {
			if c.Status != StatusPass {
				t.Fatalf("criterion %s = %s (want PASS): observed=%q reason=%q", c.ID, c.Status, c.Observed, c.Reason)
			}
			delete(want, c.ID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing authoritative criteria: %v", want)
	}
	if h.summary.Authoritative {
		t.Fatal("this env-consumption self-test must never set the authoritative bit")
	}
	if h.summary.EffectiveBindHost != "127.0.0.1" || h.summary.OperatorPolicyDigest == "" {
		t.Fatalf("effective env not recorded: host=%q digest=%q", h.summary.EffectiveBindHost, h.summary.OperatorPolicyDigest)
	}
	if h.summary.TelemetrySummary.Ownership != "operator" {
		t.Fatalf("telemetry ownership = %q, want operator", h.summary.TelemetrySummary.Ownership)
	}

	// The operator KEK exists at the operator path (binary created it), and it survives
	// cleanup (operator-owned, outside the work root).
	kekPath := env.Telemetry.KEKFile
	if _, err := os.Stat(kekPath); err != nil {
		t.Fatalf("operator KEK not present: %v", err)
	}
	h.procA.stop(time.Duration(h.spec.Run.ShutdownTimeout)) //nolint:errcheck
	h.procB.stop(time.Duration(h.spec.Run.ShutdownTimeout)) //nolint:errcheck
	h.procA, h.procB = nil, nil
	h.cleanup()
	if _, err := os.Stat(kekPath); err != nil {
		t.Fatalf("operator KEK must survive cleanup: %v", err)
	}
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("harness work root must be removed on cleanup")
	}
}
