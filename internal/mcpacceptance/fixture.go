package mcpacceptance

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"

	yaml "github.com/goccy/go-yaml"
)

// procConfig is one built-binary process instance's fully-resolved configuration.
// Two instances (A and B) form the real two-tenant matrix: each is a genuine
// single-tenant fleet, sharing issuer/canonical-resource/JWKS/scopes/client-ids so
// a valid token for either tenant authenticates on either process — the only
// difference is the tenant that owns the seeded server.
type procConfig struct {
	name             string
	tenant           string
	serverID         string
	bindHost         string
	mcpPort          int
	proxyPort        int
	uiPort           int
	configPath       string
	inventoryPath    string
	policyPath       string
	dataDir          string
	kekFile          string
	archiveDir       string
	adminUser        string
	adminPass        string
	metricsToken     string
	tripwireEndpoint string
	clientCertMode   string // "none" (bearer flow) or "require" (mTLS scenario)
}

// Fixture is the ephemeral, harness-owned qualification environment used for dev /
// self-test runs. For an authoritative run the operator supplies this material
// externally (via EnvSpec); the fixture generator is the non-authoritative path.
type Fixture struct {
	root string

	caPEM          []byte
	caFile         string
	serverCertFile string
	serverKeyFile  string
	clientCertFile string
	clientKeyFile  string

	signer   *ecdsa.PrivateKey
	kid      string
	issuer   string
	jwksFile string

	canonicalResource string
	scope             string
	clientID          string

	tenantA, tenantB string
	serverA, serverB string

	procA procConfig
	procB procConfig

	secrets *SecretScan
}

func genEC() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

func writePEM(path, blockType string, der []byte) error {
	b := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	return os.WriteFile(path, b, 0o600)
}

// genCA creates a self-signed CA and returns its cert DER + key.
func genCA(dir string) (*x509.Certificate, *ecdsa.PrivateKey, []byte, error) {
	key, err := genEC()
	if err != nil {
		return nil, nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "mcp-acceptance-ca"},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, nil, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(filepath.Join(dir, "ca.crt"), caPEM, 0o600); err != nil {
		return nil, nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, nil, err
	}
	return cert, key, caPEM, nil
}

// genLeaf issues a leaf cert (server or client) signed by ca.
func genLeaf(dir, name, cn string, serial int64, server bool, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (string, string, error) {
	key, err := genEC()
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		tmpl.DNSNames = []string{"localhost"}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return "", "", err
	}
	certPath := filepath.Join(dir, name+".crt")
	keyPath := filepath.Join(dir, name+".key")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	if err := writePEM(keyPath, "EC PRIVATE KEY", keyDER); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// randToken returns a base64url random token of n bytes.
func randToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return b64u(b), nil
}

// freePort allocates and immediately releases a localhost TCP port. There is an
// inherent race between release and reuse; the harness binds promptly and treats a
// startup failure as a criterion failure (never an unbounded retry).
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close() //nolint:errcheck
	return l.Addr().(*net.TCPAddr).Port, nil
}

// NewFixture builds a complete ephemeral two-tenant fixture under root.
func NewFixture(root string, secrets *SecretScan) (*Fixture, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	pkiDir := filepath.Join(root, "pki")
	if err := os.MkdirAll(pkiDir, 0o700); err != nil {
		return nil, err
	}
	ca, caKey, caPEM, err := genCA(pkiDir)
	if err != nil {
		return nil, fmt.Errorf("ca: %w", err)
	}
	serverCert, serverKey, err := genLeaf(pkiDir, "server", "127.0.0.1", 2, true, ca, caKey)
	if err != nil {
		return nil, fmt.Errorf("server cert: %w", err)
	}
	clientCert, clientKey, err := genLeaf(pkiDir, "client", "mcp-acceptance-client", 3, false, ca, caKey)
	if err != nil {
		return nil, fmt.Errorf("client cert: %w", err)
	}
	signer, err := genEC()
	if err != nil {
		return nil, err
	}
	kid := "acc-kid"
	issuer := "https://idp.acceptance.test/issuer"
	jwksFile := filepath.Join(pkiDir, "jwks.json")
	jwks := map[string]any{"keys": []any{jwkPublic(&signer.PublicKey, kid)}}
	jb, _ := json.MarshalIndent(jwks, "", "  ")
	if err := os.WriteFile(jwksFile, jb, 0o600); err != nil {
		return nil, err
	}

	f := &Fixture{
		root:              root,
		caPEM:             caPEM,
		caFile:            filepath.Join(pkiDir, "ca.crt"),
		serverCertFile:    serverCert,
		serverKeyFile:     serverKey,
		clientCertFile:    clientCert,
		clientKeyFile:     clientKey,
		signer:            signer,
		kid:               kid,
		issuer:            issuer,
		jwksFile:          jwksFile,
		canonicalResource: "https://gw.test/mcp/gateway",
		scope:             "gateway.tools.call",
		clientID:          "client-gw",
		tenantA:           "tenant-a",
		tenantB:           "tenant-b",
		serverA:           "srv-a",
		serverB:           "srv-b",
		secrets:           secrets,
	}
	// Register the signer private key PEM so the secret scan proves it never leaks.
	if der, err := x509.MarshalECPrivateKey(signer); err == nil {
		f.secrets.Add("signing_private_key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	}
	return f, nil
}

// buildProc allocates ports and renders inventory/policy/config for one process.
// tripwireEndpoint is the address of the non-execution tripwire server the
// inventory points its (never-dialed, in Observe) server endpoint at.
func (f *Fixture) buildProc(name, tenant, serverID, clientCertMode, tripwireEndpoint string) (procConfig, error) {
	dir := filepath.Join(f.root, "proc-"+name)
	for _, sub := range []string{"", "data", "archive", "kek"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return procConfig{}, err
		}
	}
	mcpPort, err := freePort()
	if err != nil {
		return procConfig{}, err
	}
	proxyPort, err := freePort()
	if err != nil {
		return procConfig{}, err
	}
	uiPort, err := freePort()
	if err != nil {
		return procConfig{}, err
	}
	adminPass, err := randToken(24)
	if err != nil {
		return procConfig{}, err
	}
	metricsTok, err := randToken(24)
	if err != nil {
		return procConfig{}, err
	}
	f.secrets.Add("admin_password", adminPass)
	f.secrets.Add("metrics_token", metricsTok)

	pc := procConfig{
		name: name, tenant: tenant, serverID: serverID,
		bindHost: "127.0.0.1", mcpPort: mcpPort, proxyPort: proxyPort, uiPort: uiPort,
		configPath:       filepath.Join(dir, "config.yaml"),
		inventoryPath:    filepath.Join(dir, "inventory.json"),
		policyPath:       filepath.Join(dir, "policy.json"),
		dataDir:          filepath.Join(dir, "data"),
		kekFile:          filepath.Join(dir, "kek", "telemetry.kek"),
		archiveDir:       filepath.Join(dir, "archive"),
		adminUser:        "acc-admin",
		adminPass:        adminPass,
		metricsToken:     metricsTok,
		tripwireEndpoint: tripwireEndpoint,
		clientCertMode:   clientCertMode,
	}
	if err := f.writeInventory(pc); err != nil {
		return procConfig{}, err
	}
	if err := f.writePolicy(pc); err != nil {
		return procConfig{}, err
	}
	if err := f.writeConfig(pc); err != nil {
		return procConfig{}, err
	}
	return pc, nil
}

func (f *Fixture) writeInventory(pc procConfig) error {
	doc := map[string]any{
		"schema_version": 1,
		"tenant":         pc.tenant,
		"servers": []any{
			map[string]any{
				"server_id":          pc.serverID,
				"endpoint":           pc.tripwireEndpoint,
				"pinned_identity":    "spiffe://acceptance/" + pc.serverID,
				"credential_profile": "profile:ro",
				"tools": []any{
					map[string]any{
						"name":              "echo",
						"input_schema":      map[string]any{"type": "object", "properties": map[string]any{"text": map[string]any{"type": "string"}}},
						"description":       "echo tool (quarantined in Observe)",
						"destination_class": "none",
					},
				},
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pc.inventoryPath, b, 0o600)
}

func (f *Fixture) writePolicy(pc procConfig) error {
	doc := map[string]any{
		"schema_version":  1,
		"capability":      "gateway",
		"policy_revision": 1,
		"default_action":  "DENY",
		"rules": []any{
			map[string]any{
				"id": "ALLOW_DISCOVERY", "priority": 10, "action": "ALLOW",
				"reason": "MCP.POLICY.RESOURCE_SCOPE", "remediation": "none",
				"conditions":  []any{map[string]any{"field": "operation.method", "op": "exact", "value": "tools/list"}},
				"obligations": map[string]any{"logging": "standard"},
			},
		},
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pc.policyPath, b, 0o600)
}

// writeConfig renders the minimal FileConfig YAML enabling a Gateway Observe
// listener. It contains ONLY the exact mcp.gateway fields (the binary rejects any
// unknown YAML key). Posture: client_cert_mode as requested + sender_constraint
// bearer, so the OAuth/tenant/policy flow uses a plain bearer while the mTLS
// scenario can require a client cert at the TLS layer.
func (f *Fixture) writeConfig(pc procConfig) error { return f.renderConfig(pc, true) }

// setEnabled re-renders a process's config with the Gateway enabled flag toggled
// (the accepted operational disable mechanism is startup config + restart).
func (f *Fixture) setEnabled(pc procConfig, enabled bool) error { return f.renderConfig(pc, enabled) }

// setPolicy rewrites a process's qualification policy file (used to spin an
// auxiliary deny-only process for the default-deny criterion).
func (f *Fixture) setPolicy(pc procConfig, doc map[string]any) error {
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pc.policyPath, b, 0o600)
}

func (f *Fixture) renderConfig(pc procConfig, enabled bool) error {
	gw := map[string]any{
		"enabled":                      enabled,
		"bind_address":                 pc.bindHost,
		"port":                         pc.mcpPort,
		"protocol_version":             "2025-11-25",
		"allowed_hosts":                []any{"127.0.0.1", "gw.test"},
		"connector_mode":               "local-client",
		"tls_cert_file":                f.serverCertFile,
		"tls_key_file":                 f.serverKeyFile,
		"client_ca_file":               f.serverCAFile(),
		"client_cert_mode":             pc.clientCertMode,
		"canonical_resource":           f.canonicalResource,
		"trusted_issuers":              []any{f.issuer},
		"accepted_client_ids":          []any{f.clientID},
		"required_scopes":              []any{f.scope},
		"sender_constraint":            "bearer",
		"min_assurance":                "low",
		"trusted_jwks_file":            f.jwksFile,
		"resource_name":                "Culvert Acceptance Gateway",
		"qualification_inventory_file": pc.inventoryPath,
		"qualification_policy_file":    pc.policyPath,
		"qualification_telemetry": map[string]any{
			"enabled":  true,
			"node_id":  "acc-node-" + pc.name,
			"data_dir": pc.dataDir,
			"kek_file": pc.kekFile,
			"export": map[string]any{
				"type":        "local-qualification-archive",
				"directory":   pc.archiveDir,
				"batch_size":  16,
				"max_retries": 2,
				"max_bytes":   1 << 20,
			},
		},
	}
	root := map[string]any{"mcp": map[string]any{"gateway": gw}}
	b, err := yaml.Marshal(root)
	if err != nil {
		return err
	}
	return os.WriteFile(pc.configPath, b, 0o600)
}

// serverCAFile returns the CA path (the server's issuing CA, reused as the mTLS
// client CA in the mTLS scenario).
func (f *Fixture) serverCAFile() string { return f.caFile }

// NewFixtureFromEnv builds a fixture from operator-supplied material (authoritative
// mode). It reuses the SAME inventory/policy/config renderers as the ephemeral dev
// path — one strict code path — differing only in the source of the identity
// material. It never generates keys or trust roots; the operator supplies them.
func NewFixtureFromEnv(root string, env *EnvSpec, secrets *SecretScan) (*Fixture, error) {
	if env == nil {
		return nil, fmt.Errorf("acceptance: authoritative run requires an environment")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	req := map[string]string{
		"tls_cert_file": env.TLSCertFile, "tls_key_file": env.TLSKeyFile,
		"server_ca_file": env.ServerCAFile, "trusted_jwks_file": env.TrustedJWKS,
		"signing_key_file": env.SigningKeyFile, "canonical_resource": env.CanonicalResource,
		"oauth_issuer": env.OAuthIssuer, "tenant_a": env.TenantA, "tenant_b": env.TenantB,
		"server_a": env.ServerA, "server_b": env.ServerB,
	}
	for k, v := range req {
		if v == "" {
			return nil, fmt.Errorf("acceptance: environment.%s is required for an authoritative run", k)
		}
	}
	if len(env.RequiredScopes) == 0 || len(env.AcceptedClientIDs) == 0 {
		return nil, fmt.Errorf("acceptance: environment requires required_scopes and accepted_client_ids")
	}
	caPEM, err := os.ReadFile(filepath.Clean(env.ServerCAFile)) // #nosec G304 -- operator path
	if err != nil {
		return nil, fmt.Errorf("read server CA: %w", err)
	}
	signer, kid, err := loadES256(env.SigningKeyFile, env.SigningKID)
	if err != nil {
		return nil, err
	}
	f := &Fixture{
		root:              root,
		caPEM:             caPEM,
		caFile:            env.ServerCAFile,
		serverCertFile:    env.TLSCertFile,
		serverKeyFile:     env.TLSKeyFile,
		clientCertFile:    env.ClientCertFile,
		clientKeyFile:     env.ClientKeyFile,
		signer:            signer,
		kid:               kid,
		issuer:            env.OAuthIssuer,
		jwksFile:          env.TrustedJWKS,
		canonicalResource: env.CanonicalResource,
		scope:             env.RequiredScopes[0],
		clientID:          env.AcceptedClientIDs[0],
		tenantA:           env.TenantA,
		tenantB:           env.TenantB,
		serverA:           env.ServerA,
		serverB:           env.ServerB,
		secrets:           secrets,
	}
	return f, nil
}

// loadES256 loads an ES256 private key (SEC1 or PKCS8 PEM).
func loadES256(path, kid string) (*ecdsa.PrivateKey, string, error) {
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator path
	if err != nil {
		return nil, "", fmt.Errorf("read signing key: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, "", fmt.Errorf("signing key is not PEM")
	}
	if key, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		return key, kid, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("signing key is not an ES256 key")
	}
	ec, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, "", fmt.Errorf("signing key is not ECDSA")
	}
	return ec, kid, nil
}
