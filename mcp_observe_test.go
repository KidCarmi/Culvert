package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
)

// mcpReq builds a context-bound HTTP request (satisfies the noctx linter).
func mcpObserveReq(t *testing.T, method, url, body string) *http.Request {
	t.Helper()
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, url, r)
	if err != nil {
		t.Fatalf("build %s %s: %v", method, url, err)
	}
	return req
}

// expectHandshakeFailure runs a GET expected to fail at the TLS layer and asserts
// it errored; any (unexpected) response body is closed.
func expectHandshakeFailure(t *testing.T, cli *http.Client, url, msg string) {
	t.Helper()
	resp, err := cli.Do(mcpObserveReq(t, http.MethodGet, url, ""))
	if resp != nil {
		_ = resp.Body.Close()
	}
	if err == nil {
		t.Fatal(msg)
	}
}

// --- resolver: purity, determinism, defaults -------------------------------

func TestMCPObserveResolver_DefaultsAndDisabled(t *testing.T) {
	// A zero FileConfig ⇒ disabled with the fail-closed security defaults resolved.
	fc := &FileConfig{}
	sc := resolveMCPObserveStartupConfig(fc)
	if sc.Enabled {
		t.Fatal("must be disabled by default")
	}
	if sc.ClientCertMode != "require" || sc.SenderConstraint != "mtls" || sc.MinAssurance != "high" {
		t.Fatalf("fail-closed defaults not applied: %+v", sc)
	}
}

func TestMCPObserveResolver_DoesNotMutateInput(t *testing.T) {
	fc := &FileConfig{}
	fc.MCP.Gateway.Enabled = true
	fc.MCP.Gateway.AllowedHosts = []string{"gw.test"}
	before := append([]string(nil), fc.MCP.Gateway.AllowedHosts...)
	sc := resolveMCPObserveStartupConfig(fc)
	sc.AllowedHosts[0] = "mutated" // mutate the DTO copy
	if fc.MCP.Gateway.AllowedHosts[0] != before[0] {
		t.Fatal("resolver leaked a shared slice; input was mutated")
	}
}

// --- default-disabled: no bind, SWG untouched ------------------------------

func TestMCPObserve_DisabledBindsNothing(t *testing.T) {
	cfg, act := loadMCPObserveRuntime(mcpObserveStartupConfig{Enabled: false})
	if act.State != mcpObserveDisabled || act.EnableRequested {
		t.Fatalf("expected disabled, got %+v", act)
	}
	if cfg.Enabled() {
		t.Fatal("disabled config must not enable any listener")
	}
	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime(disabled): %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start(disabled): %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(ctxWithTimeout(t)) })
	if rt.Addr(false) != "" || rt.Addr(true) != "" {
		t.Fatal("disabled runtime must bind no socket")
	}
	if len(rt.Health()) != 0 {
		t.Fatal("disabled runtime must expose no listener health")
	}
}

// --- activation gate: fail-closed on every incomplete/invalid config -------

func TestMCPObserve_ActivationGate(t *testing.T) {
	pki := newMCPTestPKI(t)
	res := "https://gw.test/mcp/gateway"

	cases := []struct {
		name   string
		mutate func(*mcpObserveStartupConfig)
		want   string // expected activation reason (State always invalid)
	}{
		{"connector_outbound", func(c *mcpObserveStartupConfig) { c.ConnectorMode = "outbound-connector" }, "connector_mode_rejected"},
		{"connector_dmz", func(c *mcpObserveStartupConfig) { c.ConnectorMode = "dmz-endpoint" }, "connector_mode_rejected"},
		{"bad_protocol", func(c *mcpObserveStartupConfig) { c.ProtocolVersion = "1999-01-01" }, "protocol_version_unsupported"},
		{"bad_client_cert_mode", func(c *mcpObserveStartupConfig) { c.ClientCertMode = "bogus" }, "client_cert_mode_invalid"},
		{"bad_sender", func(c *mcpObserveStartupConfig) { c.SenderConstraint = "bogus" }, "sender_constraint_invalid"},
		{"bad_resource_not_https", func(c *mcpObserveStartupConfig) { c.CanonicalResource = "http://gw.test/mcp/gateway" }, "canonical_resource_invalid"},
		{"missing_resource", func(c *mcpObserveStartupConfig) { c.CanonicalResource = "" }, "canonical_resource_invalid"},
		{"no_issuers", func(c *mcpObserveStartupConfig) { c.TrustedIssuers = nil }, "auth_config_invalid"},
		{"no_scopes", func(c *mcpObserveStartupConfig) { c.RequiredScopes = nil }, "auth_config_invalid"},
		{"empty_string_scope", func(c *mcpObserveStartupConfig) { c.RequiredScopes = []string{""} }, "auth_config_invalid"},
		{"no_keys", func(c *mcpObserveStartupConfig) { c.TrustedJWKSFile = "" }, "no_trusted_keys"},
		{"empty_string_issuer", func(c *mcpObserveStartupConfig) { c.TrustedIssuers = []string{""} }, "auth_config_invalid"},
		{"missing_tls", func(c *mcpObserveStartupConfig) { c.TLSCertFile = ""; c.TLSKeyFile = "" }, "tls_material_unavailable"},
		{"require_without_ca", func(c *mcpObserveStartupConfig) { c.ClientCAFile = "" }, "tls_material_unavailable"},
		{"wildcard_bind", func(c *mcpObserveStartupConfig) { c.BindAddress = "0.0.0.0" }, "listener_config_invalid"},
		{"empty_bind", func(c *mcpObserveStartupConfig) { c.BindAddress = "" }, "listener_config_invalid"},
		{"empty_hosts", func(c *mcpObserveStartupConfig) { c.AllowedHosts = nil }, "listener_config_invalid"},
		{"bad_port", func(c *mcpObserveStartupConfig) { c.Port = 70000 }, "listener_config_invalid"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc := pki.validConfig(t, res, "mtls")
			tc.mutate(&sc)
			cfg, act := loadMCPObserveRuntime(sc)
			if act.State != mcpObserveInvalid {
				t.Fatalf("state = %q, want invalid", act.State)
			}
			if !act.EnableRequested {
				t.Fatal("EnableRequested must be true on an enabled-but-invalid config")
			}
			if act.Reason != tc.want {
				t.Fatalf("reason = %q, want %q", act.Reason, tc.want)
			}
			if cfg.Enabled() {
				t.Fatal("an invalid config must produce a disabled (nothing-binds) runtime config")
			}
		})
	}
}

func TestMCPObserve_ValidConfigIsConfiguredObserveOnly(t *testing.T) {
	pki := newMCPTestPKI(t)
	cfg, act := loadMCPObserveRuntime(pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls"))
	if act.State != mcpObserveConfigured {
		t.Fatalf("state = %q reason=%q, want configured", act.State, act.Reason)
	}
	// Observe-only + capability isolation are STRUCTURAL: no execution/decision/event
	// providers, and no Management listener, can be composed by this slice.
	if cfg.Deps.Executor != nil {
		t.Fatal("executor must NOT be composed (observe-only)")
	}
	if cfg.Deps.Events != nil || cfg.Deps.Policy != nil || cfg.Deps.Inspection != nil {
		t.Fatal("no event/policy/inspection provider may be composed in QUAL-1")
	}
	if cfg.Management.Enabled {
		t.Fatal("Management listener must never be enabled by the gateway config")
	}
	if !cfg.Gateway.Enabled || cfg.Gateway.Capability.String() != "gateway" {
		t.Fatal("gateway capability must be enabled")
	}
	if cfg.Gateway.Metadata == nil || cfg.Gateway.Metadata.Resource != "https://gw.test/mcp/gateway" {
		t.Fatalf("metadata not composed: %+v", cfg.Gateway.Metadata)
	}
}

// --- lifecycle + TLS/mTLS over a real socket -------------------------------

func startObserve(t *testing.T, sc mcpObserveStartupConfig) *mcpruntime.Runtime {
	t.Helper()
	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("not configured: %q/%q", act.State, act.Reason)
	}
	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = rt.Shutdown(ctxWithTimeout(t)) })
	return rt
}

// mtlsClient builds an HTTPS client trusting the test CA and (optionally)
// presenting the client cert for mTLS.
func (p *mcpTestPKI) mtlsClient(t *testing.T, withClientCert bool) *http.Client {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(p.caCertPEM) {
		t.Fatal("append ca")
	}
	tc := &tls.Config{RootCAs: pool, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12}
	if withClientCert {
		cert, err := tls.X509KeyPair(p.clientPEM, pemKey(t, p.clientKey))
		if err != nil {
			t.Fatalf("client keypair: %v", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}
	return &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: tc}}
}

func TestMCPObserve_MTLSListener_ServesMetadataAndChallenges(t *testing.T) {
	pki := newMCPTestPKI(t)
	rt := startObserve(t, pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls"))
	addr := rt.Addr(false)
	if addr == "" {
		t.Fatal("gateway listener not bound")
	}
	base := "https://" + addr

	// Well-known metadata is public (no token) but still over mTLS.
	cli := pki.mtlsClient(t, true)
	resp, err := cli.Do(mcpObserveReq(t, http.MethodGet, base+"/.well-known/oauth-protected-resource/mcp/gateway", ""))
	if err != nil {
		t.Fatalf("metadata GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("metadata status = %d", resp.StatusCode)
	}
	if !strings.Contains(string(body), "https://gw.test/mcp/gateway") {
		t.Fatalf("metadata body = %s", body)
	}

	// A gateway request to an UNREGISTERED server fails closed (404 unregistered) —
	// the read-only inventory is empty in QUAL-1 (population is a later slice), so no
	// request can reach an upstream. It is never a fabricated success/tool result.
	// (The RFC 9728 401 + WWW-Authenticate challenge for a *registered* server with a
	// missing token is proven at the runtime layer: TestListener_Emits401Challenge*.)
	req := mcpObserveReq(t, http.MethodPost, base+"/mcp/gateway/srv-1", `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`)
	req.Host = "gw.test"
	resp2, err := cli.Do(req)
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	tcBody, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	if resp2.StatusCode == 200 {
		t.Fatalf("unregistered tools/call must not succeed; got 200 body=%s", tcBody)
	}
	if strings.Contains(string(tcBody), `"result"`) && strings.Contains(string(tcBody), "content") {
		t.Fatalf("tools/call must never return a fabricated tool result: %s", tcBody)
	}
}

func TestMCPObserve_MTLSRequired_RejectsMissingAndUntrustedClientCert(t *testing.T) {
	pki := newMCPTestPKI(t)
	rt := startObserve(t, pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls"))
	base := "https://" + rt.Addr(false)

	// No client cert → TLS handshake fails (RequireAndVerifyClientCert).
	noCert := pki.mtlsClient(t, false)
	expectHandshakeFailure(t, noCert, base+"/.well-known/oauth-protected-resource/mcp/gateway",
		"expected handshake failure without a client certificate")

	// Untrusted client cert (from a different CA) → handshake fails.
	other := newMCPTestPKI(t)
	untrusted := pki.mtlsClient(t, false)
	cert, err := tls.X509KeyPair(other.clientPEM, pemKey(t, other.clientKey))
	if err != nil {
		t.Fatalf("other keypair: %v", err)
	}
	untrusted.Transport.(*http.Transport).TLSClientConfig.Certificates = []tls.Certificate{cert}
	expectHandshakeFailure(t, untrusted, base+"/.well-known/oauth-protected-resource/mcp/gateway",
		"expected handshake failure with an untrusted client certificate")
}

func TestMCPObserve_Lifecycle_DrainRebindDoubleStart(t *testing.T) {
	pki := newMCPTestPKI(t)
	sc := pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls")

	cfg, _ := loadMCPObserveRuntime(sc)
	rt, err := mcpruntime.NewRuntime(cfg)
	if err != nil {
		t.Fatalf("NewRuntime: %v", err)
	}
	if err := rt.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	port := rt.Addr(false)
	if port == "" {
		t.Fatal("not bound")
	}
	// Double start is rejected (not silently re-bound).
	if err := rt.Start(); err == nil {
		t.Fatal("double Start must be rejected")
	}
	// Graceful drain releases the port.
	if err := rt.Shutdown(ctxWithTimeout(t)); err != nil {
		t.Fatalf("Shutdown: %v", err)
	}
	// A fresh runtime can bind the SAME fixed port again.
	cfg2, _ := loadMCPObserveRuntime(sc)
	rt2, err := mcpruntime.NewRuntime(cfg2)
	if err != nil {
		t.Fatalf("NewRuntime#2: %v", err)
	}
	if err := rt2.Start(); err != nil {
		t.Fatalf("rebind same port failed: %v", err)
	}
	t.Cleanup(func() { _ = rt2.Shutdown(ctxWithTimeout(t)) })
}

func TestMCPObserve_ConcurrentHealthReads(t *testing.T) {
	pki := newMCPTestPKI(t)
	rt := startObserve(t, pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls"))
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); _ = rt.Health() }()
	}
	wg.Wait()
}

// --- health surface truthfulness -------------------------------------------

func TestMCPObserve_HealthTruthfulness(t *testing.T) {
	// disabled
	setMCPObserveStatus(mcpObserveActivation{State: mcpObserveDisabled})
	if h := mcpObserveRuntimeHealth("gateway"); h.State != "disabled" || h.EnableRequested {
		t.Fatalf("disabled health = %+v", h)
	}
	// enable requested but invalid — never reported as disabled or healthy.
	setMCPObserveStatus(mcpObserveActivation{State: mcpObserveInvalid, EnableRequested: true, Reason: "tls_material_unavailable"})
	h := mcpObserveRuntimeHealth("gateway")
	if h.State != "invalid" || !h.EnableRequested || h.Reason != "tls_material_unavailable" || h.ListenerReady {
		t.Fatalf("invalid health = %+v", h)
	}
	// Management is always disabled in this slice (capability isolation).
	if hm := mcpObserveRuntimeHealth("management"); hm.State != "disabled" {
		t.Fatalf("management health = %+v", hm)
	}
	// restore default for other tests
	setMCPObserveStatus(mcpObserveActivation{State: mcpObserveDisabled})
}
