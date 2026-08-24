package main

// QUAL-2 tests: static qualification-inventory composition. They exercise the real
// loader (no stub), the real Registry/Catalog seeding contracts, the real runtime
// listener (mTLS) for the registry-resolution differential, and the real adminapi
// InventoryService for redaction + tenant isolation.

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/KidCarmi/Culvert/internal/mcp/adminapi"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
)

// ── fixtures ─────────────────────────────────────────────────────────────────

const qualTenant = "qualification"

// validInventoryJSON is a minimal valid one-server, one-tool qualification fleet.
func validInventoryJSON() string {
	return `{
  "schema_version": 1,
  "tenant": "qualification",
  "servers": [
    {
      "server_id": "srv-1",
      "endpoint": "mcp+https://srv-1.qual.svc",
      "pinned_identity": "spiffe://qual/srv-1",
      "credential_profile": "profile:ro",
      "tools": [
        {"name": "echo", "input_schema": {"type":"object","properties":{"text":{"type":"string"}}}, "description": "echo", "destination_class": "none"}
      ]
    }
  ]
}`
}

// writeInv writes an inventory document to a temp file and returns its path.
func writeInv(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	return p
}

// scWithInventory returns a valid observe startup config with the inventory path set.
func scWithInventory(t *testing.T, pki *mcpTestPKI, invPath string) mcpObserveStartupConfig {
	sc := pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls")
	sc.QualificationInventoryFile = invPath
	return sc
}

// resetInventory clears the process-global holder so tests do not leak state.
func resetInventory(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { publishMCPInventory(mcpInvNotConfigured, "", nil, nil) })
}

// ── configuration & parsing ──────────────────────────────────────────────────

func TestInventory_AbsentPreservesEmptyRegistry(t *testing.T) {
	resetInventory(t)
	pki := newMCPTestPKI(t)
	sc := pki.validConfig(t, "https://gw.test/mcp/gateway", "mtls") // no inventory file
	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveConfigured {
		t.Fatalf("state=%q reason=%q", act.State, act.Reason)
	}
	if cfg.Deps.Registry == nil || cfg.Deps.Catalog == nil {
		t.Fatal("registry/catalog must be constructed (empty) when no inventory file")
	}
	if cfg.Deps.Registry.Current().Len() != 0 || cfg.Deps.Catalog.Current().Len() != 0 {
		t.Fatal("no inventory file must yield an empty registry/catalog (QUAL-1 behavior)")
	}
	if inventoryStatus().State != string(mcpInvNotConfigured) {
		t.Fatalf("status = %q, want not_configured", inventoryStatus().State)
	}
}

func TestInventory_DisabledIsNotConfigured(t *testing.T) {
	resetInventory(t)
	// A disabled listener with an inventory path set must not seed anything.
	sc := mcpObserveStartupConfig{Enabled: false, QualificationInventoryFile: "/nonexistent"}
	cfg, act := loadMCPObserveRuntime(sc)
	if act.State != mcpObserveDisabled {
		t.Fatalf("state = %q, want disabled", act.State)
	}
	if cfg.Gateway.Enabled {
		t.Fatal("disabled config must not enable the gateway")
	}
	if inventoryStatus().State != string(mcpInvNotConfigured) {
		t.Fatalf("status = %q, want not_configured", inventoryStatus().State)
	}
}

func TestInventory_ValidLoadsAndSeeds(t *testing.T) {
	resetInventory(t)
	pki := newMCPTestPKI(t)
	cfg, act := loadMCPObserveRuntime(scWithInventory(t, pki, writeInv(t, validInventoryJSON())))
	if act.State != mcpObserveConfigured {
		t.Fatalf("state=%q reason=%q", act.State, act.Reason)
	}
	if got := cfg.Deps.Registry.Current().Len(); got != 1 {
		t.Fatalf("registry servers = %d, want 1", got)
	}
	if got := cfg.Deps.Catalog.Current().Len(); got != 1 {
		t.Fatalf("catalog tools = %d, want 1", got)
	}
	rec, ok := cfg.Deps.Registry.Current().Get("srv-1")
	if !ok || !rec.Usable() {
		t.Fatalf("srv-1 not usable: ok=%v rec=%+v", ok, rec)
	}
	if string(rec.OwnerScope) != qualTenant {
		t.Fatalf("owner scope = %q, want %q", rec.OwnerScope, qualTenant)
	}
	// The seeded tool is KNOWN inventory, never automatically usable: Quarantined.
	tr, ok := cfg.Deps.Catalog.Current().Get(catalog.ToolKey{Server: "srv-1", Name: "echo"})
	if !ok || tr.Eligibility != catalog.Quarantined {
		t.Fatalf("echo eligibility = %v ok=%v, want quarantined", tr.Eligibility, ok)
	}
	st := inventoryStatus()
	if st.State != string(mcpInvLoaded) || st.Servers != 1 || st.VerifiedServers != 1 || st.Tools != 1 || st.QuarantinedTools != 1 {
		t.Fatalf("status = %+v", st)
	}
	if st.ExecutionEnabled {
		t.Fatal("execution_enabled must be false")
	}
}

// invalidCases asserts every malformed / unsafe document fails activation closed.
func TestInventory_InvalidDocumentsFailClosed(t *testing.T) {
	base := func(servers string) string {
		return `{"schema_version":1,"tenant":"qualification","servers":` + servers + `}`
	}
	srv := func(body string) string { return base(`[{` + body + `}]`) }
	goodTool := `"tools":[{"name":"echo","input_schema":{"type":"object"}}]`
	goodServer := `"server_id":"s1","endpoint":"e1","pinned_identity":"id1",` + goodTool

	cases := []struct{ name, doc string }{
		{"unknown_schema_version", `{"schema_version":2,"tenant":"t","servers":[{"server_id":"s1","endpoint":"e1","pinned_identity":"id1"}]}`},
		{"unknown_top_field", `{"schema_version":1,"tenant":"t","servers":[],"extra":1}`},
		{"unknown_server_field", srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id1","private_key":"x"`)},
		{"empty_tenant", `{"schema_version":1,"tenant":"","servers":[{"server_id":"s1","endpoint":"e1","pinned_identity":"id1"}]}`},
		{"no_servers", `{"schema_version":1,"tenant":"t","servers":[]}`},
		{"management_capability", srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id1","capability":"management"`)},
		{"missing_identity", srv(`"server_id":"s1","endpoint":"e1"`)},
		{"missing_endpoint", srv(`"server_id":"s1","pinned_identity":"id1"`)},
		{"empty_server_id", srv(`"server_id":"","endpoint":"e1","pinned_identity":"id1"`)},
		{"route_unsafe_slash", srv(`"server_id":"team/srv","endpoint":"e1","pinned_identity":"id1"`)},
		{"route_unsafe_dot", srv(`"server_id":".","endpoint":"e1","pinned_identity":"id1"`)},
		{"route_unsafe_dotdot", srv(`"server_id":"..","endpoint":"e1","pinned_identity":"id1"`)},
		{"missing_input_schema", srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"t"}]`)},
		{"bad_destination_class", srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"t","input_schema":{},"destination_class":"space"}]`)},
		{"input_schema_not_object", srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"t","input_schema":"nope"}]`)},
		{"duplicate_server_id", base(`[{"server_id":"s1","endpoint":"e1","pinned_identity":"id1"},{"server_id":"s1","endpoint":"e2","pinned_identity":"id2"}]`)},
		{"duplicate_endpoint", base(`[{"server_id":"s1","endpoint":"e1","pinned_identity":"id1"},{"server_id":"s2","endpoint":"e1","pinned_identity":"id2"}]`)},
		{"duplicate_tool", srv(`"server_id":"s1","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"t","input_schema":{}},{"name":"t","input_schema":{}}]`)},
		{"trailing_data", base(`[{`+goodServer+`}]`) + `{}`},
		{"malformed_json", `{"schema_version":1,`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resetInventory(t)
			pki := newMCPTestPKI(t)
			cfg, act := loadMCPObserveRuntime(scWithInventory(t, pki, writeInv(t, tc.doc)))
			if act.State != mcpObserveInvalid {
				t.Fatalf("state = %q reason=%q, want invalid (nothing binds)", act.State, act.Reason)
			}
			if act.Reason != "qualification_inventory_invalid" {
				t.Fatalf("reason = %q, want qualification_inventory_invalid", act.Reason)
			}
			if cfg.Gateway.Enabled {
				t.Fatal("an invalid inventory must not bind a listener")
			}
			if inventoryStatus().State != string(mcpInvInvalid) {
				t.Fatalf("status = %q, want invalid", inventoryStatus().State)
			}
		})
	}
}

func TestInventory_MissingFileFailsClosed(t *testing.T) {
	resetInventory(t)
	pki := newMCPTestPKI(t)
	_, act := loadMCPObserveRuntime(scWithInventory(t, pki, filepath.Join(t.TempDir(), "does-not-exist.json")))
	if act.State != mcpObserveInvalid || act.Reason != "qualification_inventory_invalid" {
		t.Fatalf("state=%q reason=%q, want invalid", act.State, act.Reason)
	}
}

func TestInventory_TraversalPathRejected(t *testing.T) {
	if _, err := readInventoryFile("../../etc/passwd"); err == nil {
		t.Fatal("path traversal must be rejected")
	}
}

func TestInventory_OversizedFileRejected(t *testing.T) {
	big := make([]byte, maxInventoryFileBytes+1)
	for i := range big {
		big[i] = ' '
	}
	p := writeInv(t, string(big))
	if _, err := readInventoryFile(p); err == nil {
		t.Fatal("oversized inventory file must be rejected")
	}
}

// ── atomicity ────────────────────────────────────────────────────────────────

func TestInventory_OneBadServerRejectsWhole(t *testing.T) {
	resetInventory(t)
	pki := newMCPTestPKI(t)
	// Two servers; the second has an empty pinned_identity → the WHOLE inventory
	// fails and nothing is published (no partial fleet).
	doc := `{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"good","endpoint":"e1","pinned_identity":"id1","tools":[{"name":"t","input_schema":{}}]},
	  {"server_id":"bad","endpoint":"e2","pinned_identity":""}
	]}`
	_, act := loadMCPObserveRuntime(scWithInventory(t, pki, writeInv(t, doc)))
	if act.State != mcpObserveInvalid {
		t.Fatalf("state = %q, want invalid", act.State)
	}
	if reg, _ := mcpInventory.sharedInventory(); reg != nil {
		t.Fatal("a failed load must publish no registry (no partial fleet)")
	}
}

func TestInventory_OneBadToolRejectsWhole(t *testing.T) {
	resetInventory(t)
	pki := newMCPTestPKI(t)
	doc := `{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"s1","endpoint":"e1","pinned_identity":"id1","tools":[
	    {"name":"ok","input_schema":{}},
	    {"name":"bad"}
	  ]}
	]}`
	_, act := loadMCPObserveRuntime(scWithInventory(t, pki, writeInv(t, doc)))
	if act.State != mcpObserveInvalid {
		t.Fatalf("state = %q, want invalid", act.State)
	}
	if _, cat := mcpInventory.sharedInventory(); cat != nil {
		t.Fatal("a failed tool must publish no catalog")
	}
}

func TestInventory_Deterministic(t *testing.T) {
	// Two documents with the same servers in DIFFERENT order must produce identical
	// registry revisions and identical tool fingerprints (order-independent seeding).
	a := `{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"a","endpoint":"ea","pinned_identity":"ida","tools":[{"name":"t","input_schema":{"type":"object"}}]},
	  {"server_id":"b","endpoint":"eb","pinned_identity":"idb"}
	]}`
	b := `{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"b","endpoint":"eb","pinned_identity":"idb"},
	  {"server_id":"a","endpoint":"ea","pinned_identity":"ida","tools":[{"name":"t","input_schema":{"type":"object"}}]}
	]}`
	docA, err := decodeInventory([]byte(a))
	if err != nil {
		t.Fatalf("decode a: %v", err)
	}
	docB, err := decodeInventory([]byte(b))
	if err != nil {
		t.Fatalf("decode b: %v", err)
	}
	regA, catA, err := seedInventory(docA, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed a: %v", err)
	}
	regB, catB, err := seedInventory(docB, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed b: %v", err)
	}
	if regA.Current().Revision() != regB.Current().Revision() {
		t.Fatalf("registry revisions differ: %d vs %d", regA.Current().Revision(), regB.Current().Revision())
	}
	fpA, _ := catA.Current().Get(catalog.ToolKey{Server: "a", Name: "t"})
	fpB, _ := catB.Current().Get(catalog.ToolKey{Server: "a", Name: "t"})
	if fpA.Fingerprint.Sum() != fpB.Fingerprint.Sum() {
		t.Fatal("tool fingerprints differ across input order")
	}
}

// ── runtime composition (single source + no execution) ───────────────────────

func TestInventory_SingleSourceSharedWithRuntime(t *testing.T) {
	resetInventory(t)
	pki := newMCPTestPKI(t)
	cfg, act := loadMCPObserveRuntime(scWithInventory(t, pki, writeInv(t, validInventoryJSON())))
	if act.State != mcpObserveConfigured {
		t.Fatalf("state=%q reason=%q", act.State, act.Reason)
	}
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		t.Fatal("holder must publish the shared pair")
	}
	// EXACT pointer identity: the runtime Deps and the Admin API holder share the
	// SAME instances (no divergent copy).
	if cfg.Deps.Registry != reg || cfg.Deps.Catalog != cat {
		t.Fatal("runtime Deps and the shared holder must be the identical instances")
	}
	// QUAL-2 must not widen QUAL-1: no policy/events/inspection/executor composed.
	if cfg.Deps.Executor != nil || cfg.Deps.Events != nil || cfg.Deps.Policy != nil || cfg.Deps.Inspection != nil {
		t.Fatal("QUAL-2 must compose no policy/events/inspection/executor (observe-only)")
	}
}

// TestInventory_SeededRequestReachesAuth proves — through the REAL mTLS listener and
// pipeline — that seeding flips the QUAL-1 empty-registry 404 into a step-8 PASS: a
// seeded server resolves and the request reaches authentication (401 missing token),
// while an unseeded server still fails closed with 404 registry-unavailable.
func TestInventory_SeededRequestReachesAuth(t *testing.T) {
	resetInventory(t)
	pki := newMCPTestPKI(t)
	rt := startObserve(t, scWithInventory(t, pki, writeInv(t, validInventoryJSON())))
	base := "https://" + rt.Addr(false)
	cli := pki.mtlsClient(t, true)

	initBody := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`

	// Seeded server: past step-8 registry, opens a session, then fails auth (no token).
	seeded := mcpObserveReq(t, http.MethodPost, base+"/mcp/gateway/srv-1", initBody)
	seeded.Host = "gw.test"
	rs, err := cli.Do(seeded)
	if err != nil {
		t.Fatalf("seeded request: %v", err)
	}
	_ = rs.Body.Close()
	if rs.StatusCode != http.StatusUnauthorized {
		t.Fatalf("seeded server status = %d, want 401 (reached auth past registry)", rs.StatusCode)
	}
	if rs.Header.Get("WWW-Authenticate") == "" {
		t.Fatal("seeded 401 must carry the RFC 9728 challenge")
	}

	// SEC-MCP-06. An unseeded server must NOT be distinguishable from a seeded one by
	// a CREDENTIAL-LESS caller: registry resolution now runs after the credential
	// presence check, so both answer 401. Before that ordering fix this request
	// answered 404 while the seeded one answered 401 — an unauthenticated oracle
	// enumerating a tenant's registered MCP servers.
	unknown := mcpObserveReq(t, http.MethodPost, base+"/mcp/gateway/no-such-server", initBody)
	unknown.Host = "gw.test"
	ru, err := cli.Do(unknown)
	if err != nil {
		t.Fatalf("unknown request: %v", err)
	}
	ub, _ := io.ReadAll(ru.Body)
	_ = ru.Body.Close()
	if ru.StatusCode != rs.StatusCode {
		t.Fatalf("unauthenticated server-existence oracle: unknown=%d body=%s, seeded=%d",
			ru.StatusCode, ub, rs.StatusCode)
	}

	// The registry itself still fails CLOSED — never a default server, never a
	// fabricated success. That is observable one layer in, to a caller that presents
	// a (syntactically well-formed but invalid) credential and so passes the
	// presence check: the seeded server reaches auth and is rejected there, while
	// the unseeded one is still refused at registry resolution.
	withCred := func(path string) int {
		t.Helper()
		r := mcpObserveReq(t, http.MethodPost, base+path, initBody)
		r.Host = "gw.test"
		r.Header.Set("Authorization", "Bearer not-a-real-token")
		resp, derr := cli.Do(r)
		if derr != nil {
			t.Fatalf("request %s: %v", path, derr)
		}
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	if got := withCred("/mcp/gateway/no-such-server"); got != http.StatusNotFound {
		t.Fatalf("unseeded server with a credential = %d, want 404 (registry fails closed)", got)
	}
	if got := withCred("/mcp/gateway/srv-1"); got != http.StatusUnauthorized {
		t.Fatalf("seeded server with a bad credential = %d, want 401 (past registry, rejected at auth)", got)
	}
}

// ── admin API redaction + tenant isolation ───────────────────────────────────

func TestInventory_AdminRedactionAndTenantIsolation(t *testing.T) {
	doc, err := decodeInventory([]byte(validInventoryJSON()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	svc := adminapi.NewInventoryService(mcpRegistrySource{reg: reg}, mcpCatalogSource{cat: cat}, adminapi.DefaultLimits())

	// Correct tenant sees the fleet.
	servers, err := svc.ListServers(qualTenant, 0)
	if err != nil || len(servers) != 1 || servers[0].ServerID != "srv-1" {
		t.Fatalf("ListServers = %+v err=%v", servers, err)
	}
	tools, err := svc.ListTools(qualTenant, "srv-1", 0)
	if err != nil || len(tools) != 1 || tools[0].Name != "echo" {
		t.Fatalf("ListTools = %+v err=%v", tools, err)
	}
	if tools[0].Disposition != "quarantined" || !tools[0].Quarantined {
		t.Fatalf("tool disposition = %+v, want quarantined", tools[0])
	}
	if tools[0].DestinationClass != "none" || tools[0].Fingerprint == "" {
		t.Fatalf("tool view fields = %+v", tools[0])
	}

	// Redaction: the safe views must not carry the raw endpoint, pinned identity, or
	// schema. Marshal and scan for the raw secret-adjacent values.
	blob, _ := json.Marshal(map[string]any{"servers": servers, "tools": tools})
	for _, leak := range []string{"srv-1.qual.svc", "spiffe://qual/srv-1", "mcp+https", "properties"} {
		if strings.Contains(string(blob), leak) {
			t.Fatalf("admin views leaked %q: %s", leak, blob)
		}
	}
	// EndpointConfigured is a bool, not the raw endpoint; credential_profile is a ref.
	if !servers[0].EndpointConfigured {
		t.Fatal("endpoint_configured must be true")
	}

	// Wrong tenant: no data + uniform not-found on exact lookup (no existence leak).
	if got, _ := svc.ListServers("other", 0); len(got) != 0 {
		t.Fatalf("wrong tenant ListServers = %+v, want empty", got)
	}
	if _, err := svc.GetServer("other", "srv-1"); err == nil {
		t.Fatal("wrong-tenant GetServer must be not-found")
	}
	if _, err := svc.GetTool("other", "srv-1", "echo"); err == nil {
		t.Fatal("wrong-tenant GetTool must be not-found")
	}
}

func TestInventory_DisabledServerRegisteredButNotUsable(t *testing.T) {
	doc, err := decodeInventory([]byte(`{"schema_version":1,"tenant":"qualification","servers":[
	  {"server_id":"off","endpoint":"e-off","pinned_identity":"id-off","enabled":false,
	   "tools":[{"name":"t","input_schema":{"type":"object"}}]}
	]}`))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	// A disabled server is REGISTERED and visible, but not Usable — the pipeline still
	// 404s it (step 8 requires Enabled && verified). Its tools are ingested (visible)
	// while it was enabled, so the admin can see the disabled fleet truthfully.
	rec, ok := reg.Current().Get("off")
	if !ok {
		t.Fatal("disabled server must still be registered")
	}
	if rec.Enabled || rec.Usable() {
		t.Fatalf("disabled server must not be usable: %+v", rec)
	}
	if rec.Verification.String() != "verified" {
		t.Fatalf("disabled server should remain verified: %s", rec.Verification)
	}
	if cat.Current().Len() != 1 {
		t.Fatal("tools of a disabled server are still ingested + visible")
	}
}

// TestInventory_AdminSourcesReflectSharedHolder proves the exact wiring getMCPAdmin
// uses: when a loaded inventory is published, mcpAdminInventorySources returns the
// shared read seams, an adminapi.Service built from them enumerates the seeded fleet
// tenant-scoped, and its health counts reflect the fleet. When nothing is loaded the
// sources are nil and the Service Inventory stays disabled (empty views).
func TestInventory_AdminSourcesReflectSharedHolder(t *testing.T) {
	resetInventory(t)
	// Not loaded ⇒ nil sources ⇒ disabled Inventory service.
	publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
	if rs, cs, ic := mcpAdminInventorySources(); rs != nil || cs != nil || ic != nil {
		t.Fatal("no inventory loaded must yield nil admin sources")
	}
	if buildAdminService(nil, nil, nil).Inventory != nil {
		t.Fatal("Service.Inventory must be nil when no source is wired")
	}

	// Load + publish a fleet, then assert the admin sources reflect it.
	doc, err := decodeInventory([]byte(validInventoryJSON()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)

	rs, cs, ic := mcpAdminInventorySources()
	if rs == nil || cs == nil || ic == nil {
		t.Fatal("loaded inventory must yield non-nil admin sources")
	}
	svc := buildAdminService(rs, cs, ic)
	if svc.Inventory == nil {
		t.Fatal("Service.Inventory must be wired when a fleet is loaded")
	}
	servers, err := svc.Inventory.ListServers(qualTenant, 0)
	if err != nil || len(servers) != 1 || servers[0].ServerID != "srv-1" {
		t.Fatalf("admin ListServers = %+v err=%v", servers, err)
	}
	if got, _ := svc.Inventory.ListServers("other-tenant", 0); len(got) != 0 {
		t.Fatalf("wrong tenant must see no servers, got %+v", got)
	}
	if s, _, _ := ic.Counts("gateway"); s != 1 {
		t.Fatalf("gateway server count = %d, want 1", s)
	}
}

// buildAdminService mirrors getMCPAdmin's service construction for the sources under
// test, without the sync.Once singleton (so the wiring can be asserted directly).
func buildAdminService(rs adminapi.RegistrySource, cs adminapi.CatalogSource, ic adminapi.InventoryCounts) *adminapi.Service {
	p := adminapi.Params{Limits: adminapi.DefaultLimits()}
	if rs != nil {
		p.Registry, p.Catalog = rs, cs
		p.Health = adminapi.HealthSources{Inventory: ic}
	}
	return adminapi.NewService(p)
}

// TestInventory_GetMCPAdminBindsSharedInventory drives the ACTUAL getMCPAdmin
// singleton path: after an inventory is published, a freshly built admin singleton
// must expose a non-nil, tenant-scoped Inventory backed by the seeded fleet. It
// resets the singleton so the assertion is order-independent and restores it on
// cleanup so no other admin test is polluted.
func TestInventory_GetMCPAdminBindsSharedInventory(t *testing.T) {
	resetInventory(t)
	resetMCPAdminSingleton()
	t.Cleanup(resetMCPAdminSingleton) // rebuild fresh (disabled) for later tests

	doc, err := decodeInventory([]byte(validInventoryJSON()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	publishMCPInventory(mcpInvLoaded, "", reg, cat)

	m := getMCPAdmin() // builds the singleton AFTER publish
	if m.svc.Inventory == nil {
		t.Fatal("getMCPAdmin must wire Inventory from the published holder (single source)")
	}
	servers, err := m.svc.Inventory.ListServers(qualTenant, 0)
	if err != nil || len(servers) != 1 || servers[0].ServerID != "srv-1" {
		t.Fatalf("singleton ListServers = %+v err=%v", servers, err)
	}
	// Health counts flow from the same shared source.
	if g := m.svc.Health.Snapshot().Gateway; g.Servers != 1 {
		t.Fatalf("gateway health servers = %d, want 1", g.Servers)
	}
}

// resetMCPAdminSingleton clears the lazily-built admin singleton so the next
// getMCPAdmin rebuilds it from the current inventory holder (whitebox test seam).
func resetMCPAdminSingleton() {
	mcpAdmin = nil
	mcpAdminOnce = sync.Once{}
}

func TestInventory_GatewayNotVisibleAsManagement(t *testing.T) {
	doc, err := decodeInventory([]byte(validInventoryJSON()))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reg, cat, err := seedInventory(doc, limits.DefaultCatalog())
	if err != nil {
		t.Fatalf("seed: %v", err)
	}
	counts := mcpInventoryCounts{reg: reg, cat: cat}
	if s, q, d := counts.Counts("gateway"); s != 1 || q != 1 || d != 0 {
		t.Fatalf("gateway counts = (%d,%d,%d), want (1,1,0)", s, q, d)
	}
	if s, q, d := counts.Counts("management"); s != 0 || q != 0 || d != 0 {
		t.Fatalf("management counts = (%d,%d,%d), want all zero (gateway inventory is not management)", s, q, d)
	}
}
