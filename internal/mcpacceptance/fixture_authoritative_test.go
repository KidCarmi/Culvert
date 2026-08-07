package mcpacceptance

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

// localOperatorEnv writes the minimal on-disk material NewFixtureFromEnv needs (a
// readable CA, a valid EC signing key, existing policy + credential files) plus
// operator telemetry paths under a dedicated root OUTSIDE the harness work root. It
// returns the EnvSpec and the operator telemetry root.
func localOperatorEnv(t *testing.T) (*EnvSpec, string) {
	t.Helper()
	dir := t.TempDir()
	// A readable CA file (content is not parsed by NewFixtureFromEnv).
	caF := writeFileT(t, dir, "ca.crt", "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
	// A valid EC signing key (SEC1 PEM) so loadES256 succeeds.
	signer, err := genEC()
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(signer)
	if err != nil {
		t.Fatal(err)
	}
	signF := filepath.Join(dir, "signer.key")
	if err := os.WriteFile(signF, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	polF := writeFileT(t, dir, "policy.json", string(validOperatorPolicy()))
	passF := writeFileT(t, dir, "admin.pass", testAdminMaterial)
	tokF := writeFileT(t, dir, "metrics.tok", testMetricsMaterial)
	telRoot := t.TempDir() // operator-owned, deliberately NOT under the work root
	env := &EnvSpec{
		BindHost:                "127.0.0.1",
		OAuthIssuer:             "https://idp.example/issuer",
		CanonicalResource:       "https://gw.example/mcp/gateway",
		RequiredScopes:          []string{"gateway.tools.call"},
		AcceptedClientIDs:       []string{"client-gw"},
		TenantA:                 "tenant-a",
		TenantB:                 "tenant-b",
		ServerA:                 "srv-a",
		ServerB:                 "srv-b",
		TLSCertFile:             filepath.Join(dir, "tls.crt"),
		TLSKeyFile:              filepath.Join(dir, "tls.key"),
		ServerCAFile:            caF,
		TrustedJWKS:             filepath.Join(dir, "jwks.json"),
		SigningKeyFile:          signF,
		SigningKID:              "kid-1",
		GatewayPort:             19443,
		QualificationPolicyFile: polF,
		Telemetry:               &TelemetryEnv{NodeID: "op-node", DataDir: filepath.Join(telRoot, "data"), KEKFile: filepath.Join(telRoot, "kek", "t.kek"), ArchiveDir: filepath.Join(telRoot, "arch")},
		Supervision:             &SupervisionEnv{AdminPort: 19090, MetricsPort: 19091, AdminUser: "acc-admin", AdminPasswordFile: passF, MetricsTokenFile: tokF},
	}
	return env, telRoot
}

func TestBuildProc_AuthoritativePrimaryConsumesOperatorControls(t *testing.T) {
	env, _ := localOperatorEnv(t)
	work := t.TempDir()
	fx, err := NewFixtureFromEnv(filepath.Join(work, "fixture"), env, NewSecretScan())
	if err != nil {
		t.Fatalf("NewFixtureFromEnv: %v", err)
	}
	// Primary: consumes operator telemetry + ports + operator policy.
	pa, err := fx.buildProc(procRole{name: "A", tenant: env.TenantA, serverID: env.ServerA, clientCertMode: "none", tripwireEndpoint: "mcp+https://127.0.0.1:1/mcp", primary: true, operatorPolicy: true})
	if err != nil {
		t.Fatalf("buildProc primary: %v", err)
	}
	if pa.bindHost != "127.0.0.1" {
		t.Fatalf("primary bindHost = %q, want operator host", pa.bindHost)
	}
	if pa.mcpPort != env.GatewayPort || pa.uiPort != env.Supervision.AdminPort || pa.proxyPort != env.Supervision.MetricsPort {
		t.Fatalf("primary did not consume operator ports: mcp=%d ui=%d proxy=%d", pa.mcpPort, pa.uiPort, pa.proxyPort)
	}
	if pa.telemetryOwner != ownerOperator || pa.dataDir != env.Telemetry.DataDir || pa.kekFile != env.Telemetry.KEKFile || pa.archiveDir != env.Telemetry.ArchiveDir || pa.nodeID != env.Telemetry.NodeID {
		t.Fatalf("primary did not consume operator telemetry: owner=%s data=%s", pa.telemetryOwner, pa.dataDir)
	}
	if pa.policyOwner != ownerOperator || pa.policyPath != fx.operator.policyFile {
		t.Fatalf("primary did not consume operator policy: owner=%s path=%s", pa.policyOwner, pa.policyPath)
	}
	if pa.adminUser != env.Supervision.AdminUser || pa.adminPass != testAdminMaterial || pa.metricsToken != testMetricsMaterial {
		t.Fatal("primary did not consume operator credentials")
	}
}

func TestBuildProc_AuxIsolatedButAuthReadsOperatorPolicy(t *testing.T) {
	env, _ := localOperatorEnv(t)
	work := t.TempDir()
	fx, _ := NewFixtureFromEnv(filepath.Join(work, "fixture"), env, NewSecretScan())
	// A non-primary aux with operatorPolicy: harness telemetry (isolated), operator policy.
	aux, err := fx.buildProc(procRole{name: "mtls", tenant: env.TenantA, serverID: env.ServerA, clientCertMode: "require", tripwireEndpoint: "mcp+https://127.0.0.1:1/mcp", primary: false, operatorPolicy: true})
	if err != nil {
		t.Fatal(err)
	}
	if aux.telemetryOwner != ownerHarness {
		t.Fatal("aux telemetry must be harness-owned (isolated spool)")
	}
	if !underDir(aux.dataDir, work) {
		t.Fatalf("aux telemetry must live under the work root, got %s", aux.dataDir)
	}
	if aux.mcpPort == env.GatewayPort {
		t.Fatal("aux must not reuse the operator gateway port")
	}
	if aux.policyOwner != ownerOperator || aux.policyPath != fx.operator.policyFile {
		t.Fatal("aux with operatorPolicy must read the operator policy file")
	}

	// The deny-only negative control uses a harness-owned policy under the work root.
	deny, err := fx.buildProc(procRole{name: "denyonly", tenant: env.TenantA, serverID: env.ServerA, clientCertMode: "none", tripwireEndpoint: "mcp+https://127.0.0.1:1/mcp", primary: false, operatorPolicy: false})
	if err != nil {
		t.Fatal(err)
	}
	if deny.policyOwner != ownerHarness || !underDir(deny.policyPath, work) {
		t.Fatalf("deny-only must use a harness policy under work root, got owner=%s path=%s", deny.policyOwner, deny.policyPath)
	}
}

func TestSetPolicy_RefusesOperatorOwned(t *testing.T) {
	env, _ := localOperatorEnv(t)
	fx, _ := NewFixtureFromEnv(filepath.Join(t.TempDir(), "fixture"), env, NewSecretScan())
	pa, _ := fx.buildProc(procRole{name: "A", tenant: env.TenantA, serverID: env.ServerA, clientCertMode: "none", tripwireEndpoint: "mcp+https://127.0.0.1:1/mcp", primary: true, operatorPolicy: true})
	before, _ := os.ReadFile(fx.operator.policyFile)
	if err := fx.setPolicy(pa, map[string]any{"schema_version": 1, "default_action": "DENY", "rules": []any{}}); err == nil {
		t.Fatal("setPolicy must refuse to rewrite an operator-owned policy file")
	}
	after, _ := os.ReadFile(fx.operator.policyFile)
	if !bytes.Equal(before, after) {
		t.Fatal("operator policy file was mutated despite the refusal")
	}
}

func TestCleanup_PreservesOperatorOwnedTelemetry(t *testing.T) {
	env, telRoot := localOperatorEnv(t)
	work := t.TempDir()
	fx, _ := NewFixtureFromEnv(filepath.Join(work, "fixture"), env, NewSecretScan())
	pa, _ := fx.buildProc(procRole{name: "A", tenant: env.TenantA, serverID: env.ServerA, clientCertMode: "none", tripwireEndpoint: "mcp+https://127.0.0.1:1/mcp", primary: true, operatorPolicy: true})
	// Simulate the binary having written durable operator telemetry.
	if err := os.MkdirAll(pa.dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	durable := filepath.Join(pa.dataDir, "spool.enc")
	if err := os.WriteFile(durable, []byte("durable-operator-evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := &Harness{workDir: work, spec: &Spec{Run: RunControl{}}}
	h.cleanup()
	// The harness work root is gone; operator-owned telemetry survives.
	if _, err := os.Stat(work); !os.IsNotExist(err) {
		t.Fatal("harness work root should be removed on cleanup")
	}
	if _, err := os.Stat(durable); err != nil {
		t.Fatalf("operator-owned telemetry must be preserved on cleanup: %v", err)
	}
	_ = telRoot
}
