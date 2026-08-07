package mcpacceptance

import (
	"context"
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
	"strings"
	"time"

	yaml "github.com/goccy/go-yaml"
)

// ownerClass classifies who owns a piece of on-disk state so cleanup derives from
// ownership, never from path guessing. Harness-owned state (under the work root) is
// removable on cleanup; operator-owned state (supplied in the authoritative
// environment) is NEVER automatically deleted, so a failed run never erases the
// operator's telemetry/KEK/archive needed for diagnosis.
type ownerClass string

const (
	ownerHarness  ownerClass = "harness"
	ownerOperator ownerClass = "operator"
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
	nodeID           string
	adminUser        string
	adminPass        string
	metricsToken     string
	tripwireEndpoint string
	clientCertMode   string // "none" (bearer flow) or "require" (mTLS scenario)
	// telemetryOwner classifies the telemetry data_dir/kek/archive: operator-owned on
	// the authoritative primary (preserved on cleanup), harness-owned otherwise.
	telemetryOwner ownerClass
	// policyOwner classifies the qualification policy file: operator-owned when this
	// process reads the operator policy verbatim (never rewritten), harness-owned when
	// the harness renders the policy under the work root (dev, or the deny-only
	// negative control).
	policyOwner ownerClass
	// primary marks the single operator-supervised process (proc A in authoritative
	// mode): it consumes the operator telemetry custody boundary and the
	// operator-selected admin/metrics listener + credentials.
	primary bool
}

// procRole is the immutable description of one process the harness spawns. It keeps
// buildProc's contract explicit (no positional boolean soup): primary consumes the
// operator telemetry + admin/metrics listener; operatorPolicy reads the operator
// policy file verbatim (false ⇒ the harness renders a policy under the work root,
// used only by the deny-only negative control).
type procRole struct {
	name             string
	tenant           string
	serverID         string
	clientCertMode   string // "none" (bearer flow) or "require" (mTLS scenario)
	tripwireEndpoint string
	primary          bool
	operatorPolicy   bool
}

// operatorEnv carries the operator-owned authoritative controls the harness
// consumes on the primary. It is nil in dev mode. Every field here is a value the
// harness passes into the spawned artifact verbatim; nothing here is a harness
// invention.
type operatorEnv struct {
	policyFile   string // operator qualification policy file (read verbatim, never rewritten)
	telNodeID    string
	telDataDir   string
	telKEKFile   string
	telArchive   string
	adminPort    int
	metricsPort  int
	gatewayPort  int
	adminUser    string
	adminPass    string // read from AdminPasswordFile; registered in the secret scan
	metricsToken string // read from MetricsTokenFile; registered in the secret scan
	adminPassRef string // the FILE path (a safe reference recorded in evidence)
	metricsRef   string // the FILE path (a safe reference recorded in evidence)
}

// Fixture is the ephemeral, harness-owned qualification environment used for dev /
// self-test runs. For an authoritative run the operator supplies this material
// externally (via EnvSpec); the fixture generator is the non-authoritative path.
type Fixture struct {
	root string

	caPEM          []byte
	caFile         string
	clientCAFile   string // mTLS client CA the listener requires (== caFile in dev)
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

	// bindHost is the interface every spawned Gateway listener binds (dev:
	// "127.0.0.1"; authoritative: the operator-selected host). dialHost is the
	// reachable address the MCP clients connect to (== bindHost). serverName is the
	// TLS server name the clients validate the listener cert against.
	bindHost   string
	dialHost   string
	serverName string

	// operator is non-nil in authoritative mode and carries the operator-owned
	// controls consumed on the primary process.
	operator *operatorEnv

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

// genLeaf issues a leaf cert (server or client) signed by ca and returns the
// written cert and key paths.
func genLeaf(dir, name, cn string, serial int64, server bool, ca *x509.Certificate, caKey *ecdsa.PrivateKey) (certPath, keyPath string, err error) {
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
	certPath = filepath.Join(dir, name+".crt")
	keyPath = filepath.Join(dir, name+".key")
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

// freePortOn allocates and immediately releases a TCP port ON THE GIVEN HOST. There
// is an inherent race between release and reuse; the harness binds promptly and
// treats a startup failure as a criterion failure (never an unbounded retry).
// Allocating on the actual bind interface (not loopback) matters when the operator
// bind host is non-loopback: the primary Gateway is bound only on that interface, so
// a loopback probe would not see it and could hand an auxiliary process the same
// port number, which would then fail to bind. Probing the real interface closes that
// window.
func freePortOn(host string) (int, error) {
	var lc net.ListenConfig
	l, err := lc.Listen(context.Background(), "tcp", net.JoinHostPort(host, "0"))
	if err != nil {
		return 0, err
	}
	defer l.Close() //nolint:errcheck // best-effort close of a read-only handle
	return l.Addr().(*net.TCPAddr).Port, nil
}

// freePort allocates a free loopback port (the dev default and the tripwire path).
func freePort() (int, error) { return freePortOn("127.0.0.1") }

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
	jwk, err := jwkPublic(&signer.PublicKey, kid)
	if err != nil {
		return nil, err
	}
	jwks := map[string]any{"keys": []any{jwk}}
	jb, _ := json.MarshalIndent(jwks, "", "  ")
	if err := os.WriteFile(jwksFile, jb, 0o600); err != nil {
		return nil, err
	}

	f := &Fixture{
		root:              root,
		caPEM:             caPEM,
		caFile:            filepath.Join(pkiDir, "ca.crt"),
		clientCAFile:      filepath.Join(pkiDir, "ca.crt"), // dev: one CA issues server + client certs
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
		bindHost:          "127.0.0.1",
		dialHost:          "127.0.0.1",
		serverName:        "127.0.0.1",
		secrets:           secrets,
	}
	// Register the signer private key PEM so the secret scan proves it never leaks.
	if der, err := x509.MarshalECPrivateKey(signer); err == nil {
		f.secrets.Add("signing_private_key", string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})))
	}
	return f, nil
}

// buildProc renders inventory/policy/config for one process according to its role.
// In dev mode every process is harness-owned (ephemeral ports, harness telemetry,
// harness fixture policy). In authoritative mode the PRIMARY consumes the operator
// telemetry custody boundary and the operator-selected admin/metrics listener +
// credentials, and every non-deny-only process reads the operator policy file
// verbatim; the auxiliary/negative-control processes still get isolated harness
// scratch (own ports + own telemetry) because concurrent processes cannot share one
// encrypted spool. tripwireEndpoint is the non-execution tripwire the inventory
// points its (never-dialed, in Observe) server endpoint at.
func (f *Fixture) buildProc(role procRole) (procConfig, error) {
	dir := filepath.Join(f.root, "proc-"+role.name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return procConfig{}, err
	}
	pc := procConfig{
		name: role.name, tenant: role.tenant, serverID: role.serverID,
		bindHost:         f.bindHost,
		configPath:       filepath.Join(dir, "config.yaml"),
		inventoryPath:    filepath.Join(dir, "inventory.json"),
		tripwireEndpoint: role.tripwireEndpoint,
		clientCertMode:   role.clientCertMode,
		primary:          role.primary,
	}
	if err := f.resolvePorts(&pc, role); err != nil {
		return procConfig{}, err
	}
	if err := f.resolveCreds(&pc); err != nil {
		return procConfig{}, err
	}
	if err := f.resolveTelemetry(&pc, dir, role); err != nil {
		return procConfig{}, err
	}
	if err := f.resolvePolicy(&pc, dir, role); err != nil {
		return procConfig{}, err
	}
	if err := f.writeInventory(pc); err != nil {
		return procConfig{}, err
	}
	if err := f.writeConfig(pc); err != nil {
		return procConfig{}, err
	}
	return pc, nil
}

// resolvePorts assigns the MCP/proxy/UI ports. The authoritative primary uses the
// operator-selected gateway/metrics/admin ports (so an external supervisor knows
// where to look); every other process uses ephemeral loopback-allocated ports.
func (f *Fixture) resolvePorts(pc *procConfig, role procRole) error {
	if f.operator != nil && role.primary {
		pc.mcpPort = f.operator.gatewayPort
		pc.proxyPort = f.operator.metricsPort
		pc.uiPort = f.operator.adminPort
		return nil
	}
	// Non-primary/auxiliary processes get ephemeral ports, but must NOT reuse the
	// operator-selected primary ports (gateway/admin/metrics): the primary may not have
	// bound them yet when an auxiliary allocates, so a naive free-port probe could hand
	// out a port the primary will later bind, deterministically failing that process.
	// Avoid the operator's fixed ports explicitly. The MCP port is probed on the actual
	// bind interface so it cannot collide with a non-loopback primary Gateway either.
	avoid := f.operatorReservedPorts()
	var err error
	if pc.mcpPort, err = freePortAvoiding(f.bindHost, avoid); err != nil {
		return err
	}
	avoid[pc.mcpPort] = true
	if pc.proxyPort, err = freePortAvoiding("127.0.0.1", avoid); err != nil {
		return err
	}
	avoid[pc.proxyPort] = true
	if pc.uiPort, err = freePortAvoiding("127.0.0.1", avoid); err != nil {
		return err
	}
	return nil
}

// operatorReservedPorts returns the set of operator-selected primary ports auxiliary
// processes must not reuse (empty in dev mode).
func (f *Fixture) operatorReservedPorts() map[int]bool {
	avoid := map[int]bool{}
	if f.operator != nil {
		avoid[f.operator.gatewayPort] = true
		avoid[f.operator.adminPort] = true
		avoid[f.operator.metricsPort] = true
	}
	return avoid
}

// freePortAvoiding allocates a free port on host that is not in the avoid set,
// retrying a bounded number of times (the avoid set is tiny, so collisions are rare
// and clear quickly). It never loops unboundedly.
func freePortAvoiding(host string, avoid map[int]bool) (int, error) {
	var lastErr error
	for attempt := 0; attempt < 20; attempt++ {
		p, err := freePortOn(host)
		if err != nil {
			lastErr = err
			continue
		}
		if !avoid[p] {
			return p, nil
		}
	}
	if lastErr != nil {
		return 0, lastErr
	}
	return 0, fmt.Errorf("acceptance: could not allocate a free port avoiding the operator ports")
}

// resolveCreds assigns the admin user/password + metrics token. Authoritative runs
// consume the operator-supplied credentials (read from file references, registered
// in the secret scan) on every process so the harness — and the external supervisor
// — authenticate identically. Dev runs generate ephemeral credentials.
func (f *Fixture) resolveCreds(pc *procConfig) error {
	if f.operator != nil {
		pc.adminUser = f.operator.adminUser
		pc.adminPass = f.operator.adminPass
		pc.metricsToken = f.operator.metricsToken
		return nil
	}
	adminPass, err := randToken(24)
	if err != nil {
		return err
	}
	metricsTok, err := randToken(24)
	if err != nil {
		return err
	}
	f.secrets.Add("admin_password", adminPass)
	f.secrets.Add("metrics_token", metricsTok)
	pc.adminUser = "acc-admin"
	pc.adminPass = adminPass
	pc.metricsToken = metricsTok
	return nil
}

// resolveTelemetry assigns the telemetry node id + data/kek/archive paths. The
// authoritative primary consumes the operator custody boundary EXACTLY and is
// classified operator-owned (never auto-deleted; the binary owns the KEK at the
// operator path). Every other process gets isolated harness-owned scratch under the
// work root (removable on cleanup).
func (f *Fixture) resolveTelemetry(pc *procConfig, dir string, role procRole) error {
	if f.operator != nil && role.primary {
		pc.nodeID = f.operator.telNodeID
		pc.dataDir = f.operator.telDataDir
		pc.kekFile = f.operator.telKEKFile
		pc.archiveDir = f.operator.telArchive
		pc.telemetryOwner = ownerOperator
		// The binary (buildMCPTelemetry) creates these operator paths; the harness never
		// pre-creates or writes the KEK.
		return nil
	}
	for _, sub := range []string{"data", "archive", "kek"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return err
		}
	}
	pc.nodeID = "acc-node-" + role.name
	pc.dataDir = filepath.Join(dir, "data")
	pc.kekFile = filepath.Join(dir, "kek", "telemetry.kek")
	pc.archiveDir = filepath.Join(dir, "archive")
	pc.telemetryOwner = ownerHarness
	return nil
}

// resolvePolicy assigns the qualification policy file. When the operator policy is
// used (authoritative, non-deny-only), the harness references the operator file
// verbatim and never rewrites it (operator-owned). Otherwise the harness renders a
// policy under the work root (dev fixture policy, or the deny-only negative
// control) — harness-owned and freely writable.
func (f *Fixture) resolvePolicy(pc *procConfig, dir string, role procRole) error {
	if f.operator != nil && role.operatorPolicy {
		pc.policyPath = f.operator.policyFile
		pc.policyOwner = ownerOperator
		return nil
	}
	pc.policyPath = filepath.Join(dir, "policy.json")
	pc.policyOwner = ownerHarness
	return f.writePolicy(*pc)
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
// auxiliary deny-only process for the default-deny criterion). It refuses to write
// an operator-owned policy file — the operator's qualification policy is never
// mutated behind the operator's back; the deny-only negative control always runs on
// a harness-owned policy path under the work root.
func (f *Fixture) setPolicy(pc procConfig, doc map[string]any) error {
	if pc.policyOwner == ownerOperator {
		return fmt.Errorf("acceptance: refusing to rewrite operator-owned policy file")
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(pc.policyPath, b, 0o600)
}

func (f *Fixture) renderConfig(pc procConfig, enabled bool) error {
	// The app-layer Host allowlist always carries the canonical vhost the clients use
	// ("gw.test") and loopback. In authoritative mode it also carries the operator bind
	// host so the network authority advertised in the supervision descriptor
	// (bind_host:port) is accepted — the runtime host check strips the port before
	// matching, so the host-only entry suffices.
	allowedHosts := []any{"127.0.0.1", "gw.test"}
	if pc.bindHost != "" && pc.bindHost != "127.0.0.1" {
		allowedHosts = append(allowedHosts, pc.bindHost)
	}
	gw := map[string]any{
		"enabled":                      enabled,
		"bind_address":                 pc.bindHost,
		"port":                         pc.mcpPort,
		"protocol_version":             "2025-11-25",
		"allowed_hosts":                allowedHosts,
		"connector_mode":               "local-client",
		"tls_cert_file":                f.serverCertFile,
		"tls_key_file":                 f.serverKeyFile,
		"client_ca_file":               f.clientCAFile,
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
			"node_id":  pc.nodeID,
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
	// The mTLS client CA the listener requires defaults to the server CA when the
	// operator supplies a single trust root, but honors a distinct client_ca_file.
	clientCA := env.ClientCAFile
	if clientCA == "" {
		clientCA = env.ServerCAFile
	}
	op, err := loadOperatorEnv(env, secrets)
	if err != nil {
		return nil, err
	}
	serverName := env.TLSServerName
	if serverName == "" {
		serverName = env.BindHost
	}
	f := &Fixture{
		root:              root,
		caPEM:             caPEM,
		caFile:            env.ServerCAFile,
		clientCAFile:      clientCA,
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
		bindHost:          env.BindHost,
		dialHost:          env.BindHost,
		serverName:        serverName,
		operator:          op,
		secrets:           secrets,
	}
	return f, nil
}

// loadOperatorEnv resolves the QUAL-6.1 operator-owned controls: it validates the
// policy file exists and is a bounded regular file, and reads the admin-password +
// metrics-token FILE references into the secret registry so they are proven never to
// leak into evidence. Their bytes are consumed only to pass them to the spawned
// process via the product's own -pass/-metrics-token flags; only the FILE PATHS are
// recorded as safe references.
func loadOperatorEnv(env *EnvSpec, secrets *SecretScan) (*operatorEnv, error) {
	if err := statRegularFile("qualification_policy_file", env.QualificationPolicyFile, 4<<20); err != nil {
		return nil, err
	}
	adminPass, err := readSecretFile("admin_password_file", env.Supervision.AdminPasswordFile)
	if err != nil {
		return nil, err
	}
	metricsTok, err := readSecretFile("metrics_token_file", env.Supervision.MetricsTokenFile)
	if err != nil {
		return nil, err
	}
	secrets.Add("admin_password", adminPass)
	secrets.Add("metrics_token", metricsTok)
	return &operatorEnv{
		policyFile:   filepath.Clean(env.QualificationPolicyFile),
		telNodeID:    env.Telemetry.NodeID,
		telDataDir:   env.Telemetry.DataDir,
		telKEKFile:   env.Telemetry.KEKFile,
		telArchive:   env.Telemetry.ArchiveDir,
		adminPort:    env.Supervision.AdminPort,
		metricsPort:  env.Supervision.MetricsPort,
		gatewayPort:  env.GatewayPort,
		adminUser:    env.Supervision.AdminUser,
		adminPass:    adminPass,
		metricsToken: metricsTok,
		adminPassRef: filepath.Clean(env.Supervision.AdminPasswordFile),
		metricsRef:   filepath.Clean(env.Supervision.MetricsTokenFile),
	}, nil
}

// statRegularFile asserts that path is an existing, bounded, regular file. It never
// reads the contents (used for the operator policy file, whose digest is computed
// separately by the harness preflight).
func statRegularFile(name, path string, maxBytes int64) error {
	fi, err := os.Stat(filepath.Clean(path))
	if err != nil {
		return fmt.Errorf("acceptance: environment.%s not readable: %w", name, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("acceptance: environment.%s is not a regular file", name)
	}
	if fi.Size() > maxBytes {
		return fmt.Errorf("acceptance: environment.%s exceeds the %d-byte bound", name, maxBytes)
	}
	return nil
}

// readSecretFile reads a bounded credential file (admin password / metrics token)
// supplied by PATH. The value is returned for consumption (passed to the spawned
// process) and registered by the caller in the secret scan; it is never recorded in
// evidence. Trailing newline/whitespace is trimmed so a file written with `echo`
// works.
func readSecretFile(name, path string) (string, error) {
	if err := statRegularFile(name, path, 64<<10); err != nil {
		return "", err
	}
	b, err := os.ReadFile(filepath.Clean(path)) // #nosec G304 -- operator-supplied credential file path
	if err != nil {
		return "", fmt.Errorf("acceptance: read environment.%s: %w", name, err)
	}
	v := strings.TrimSpace(string(b))
	if v == "" {
		return "", fmt.Errorf("acceptance: environment.%s is empty", name)
	}
	return v, nil
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
