package main

// QUAL-2 — static qualification-inventory composition for the Gateway Observe
// listener. This file loads a bounded, node-local JSON inventory document ONCE at
// startup and seeds it through the EXISTING Registry and Catalog contracts, so a
// correctly authenticated Model-A request for a seeded server/tool can pass
// registry resolution (pipeline step 8) and reach the QUAL-1 Observe-only decision
// boundary — while composing NO policy, events, executor, upstream client, or
// broker (QUAL-2 does not widen QUAL-1 beyond inventory resolution).
//
// It NEVER writes internal Registry/Catalog maps or fields directly: every server
// is seeded via registry.Register + registry.VerifyIdentity (identity confirmed to
// the exact accepted VerifyVerified state), and every tool via catalog.Ingest
// (which recomputes the existing fingerprint from the tool's own bounded schema —
// no second fingerprint format is invented — and lands the tool Quarantined, the
// correct record-only-Observe disposition; a seeded tool is KNOWN inventory, never
// automatically trusted for execution).
//
// Loading is ALL-OR-NOTHING: the candidate is parsed and every server + tool is
// validated and seeded into a FRESH private Registry/Catalog pair, and that pair is
// published to the runtime + Admin API only after every item succeeds. Any failure
// leaves the active composition empty and the activation invalid (fail closed) —
// never a partially loaded fleet. The same instances back the runtime pipeline AND
// the read-only MCP Servers/Tools Admin API (single source of truth).

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/KidCarmi/Culvert/internal/mcp/adminapi"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// maxInventoryFileBytes bounds the qualification inventory document read from disk
// BEFORE decoding (a fail-closed memory-DoS guard on hostile operator input). The
// per-schema / per-tool / per-server bounds are enforced by the existing catalog
// limits during catalog.Ingest; this only caps the whole file.
const maxInventoryFileBytes = 1 << 20 // 1 MiB

// qualInventorySchemaVersion is the only supported inventory schema version. An
// unknown version fails closed (no silent forward/backward compatibility).
const qualInventorySchemaVersion = 1

// ── inventory state (holder) ─────────────────────────────────────────────────

// mcpInventoryState classifies the node-local qualification-inventory outcome for
// the read-only admin/health surface. It distinguishes a genuinely empty fleet
// from a failed load so an invalid inventory is NEVER rendered as an empty healthy
// fleet.
type mcpInventoryState string

const (
	// mcpInvNotConfigured — the Gateway listener is disabled, or enabled with no
	// qualification_inventory_file set (QUAL-1 posture). No fleet is expected.
	mcpInvNotConfigured mcpInventoryState = "not_configured"
	// mcpInvLoaded — a present, valid inventory file was seeded atomically.
	mcpInvLoaded mcpInventoryState = "loaded"
	// mcpInvInvalid — a present inventory file failed to load/seed; the listener did
	// not bind (fail closed). The lists are empty but the state is NOT "loaded".
	mcpInvInvalid mcpInventoryState = "invalid"
)

// mcpInventoryHolder is the node-local shared inventory published once at startup.
// The SAME reg/cat pointers are handed to the runtime Deps and the Admin API, so
// there is exactly one source of truth. Guarded because startup publishes it and
// the lazily-built admin singleton + health reads consume it.
type mcpInventoryHolder struct {
	mu     sync.RWMutex
	state  mcpInventoryState
	reason string // bounded, secret-free classification when state == invalid
	reg    *registry.Registry
	cat    *catalog.Catalog
}

var mcpInventory = &mcpInventoryHolder{state: mcpInvNotConfigured}

// publishMCPInventory records the node-local inventory outcome. A loaded state MUST
// carry both a registry and a catalog; every other state clears them so the Admin
// API never wires a stale source.
func publishMCPInventory(state mcpInventoryState, reason string, reg *registry.Registry, cat *catalog.Catalog) {
	mcpInventory.mu.Lock()
	defer mcpInventory.mu.Unlock()
	mcpInventory.state = state
	mcpInventory.reason = reason
	if state == mcpInvLoaded {
		mcpInventory.reg, mcpInventory.cat = reg, cat
	} else {
		mcpInventory.reg, mcpInventory.cat = nil, nil
	}
}

// sharedInventory returns the published registry/catalog pair (both nil unless a
// valid inventory is loaded). The runtime and the Admin API both call this so they
// observe the identical instances.
func (h *mcpInventoryHolder) sharedInventory() (*registry.Registry, *catalog.Catalog) {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.reg, h.cat
}

// ── Admin API source adapters (single source of truth) ───────────────────────
// These adapt the SAME *registry.Registry / *catalog.Catalog the runtime pipeline
// reads into the narrow adminapi read seams, so the Admin API and the listener can
// never diverge. They are read-only (snapshot loads); they never mutate.

// mcpRegistrySource adapts the shared registry to adminapi.RegistrySource.
type mcpRegistrySource struct{ reg *registry.Registry }

func (s mcpRegistrySource) Servers() []registry.ServerRecord { return s.reg.Current().Servers() }
func (s mcpRegistrySource) RegistryRevision() uint64         { return s.reg.Current().Revision() }

// mcpCatalogSource adapts the shared catalog to adminapi.CatalogSource.
type mcpCatalogSource struct{ cat *catalog.Catalog }

func (s mcpCatalogSource) Tools() []catalog.ToolRecord { return s.cat.Current().Records() }
func (s mcpCatalogSource) CatalogRevision() uint64     { return s.cat.Current().Revision() }

// mcpInventoryCounts adapts the shared pair to adminapi.InventoryCounts for the
// per-capability health surface. Only Gateway carries inventory in QUAL-2.
type mcpInventoryCounts struct {
	reg *registry.Registry
	cat *catalog.Catalog
}

func (c mcpInventoryCounts) Counts(capability string) (servers, quarantined, drifted int) {
	if capability != protocol.Gateway.String() {
		return 0, 0, 0
	}
	servers = c.reg.Current().Len()
	// Index-based range: ToolRecord is a wide struct (gocritic rangeValCopy).
	tools := c.cat.Current().Records()
	for i := range tools {
		switch tools[i].Eligibility {
		case catalog.Quarantined:
			quarantined++
		case catalog.ReviewRequired:
			drifted++
		}
	}
	return servers, quarantined, drifted
}

// mcpAdminInventorySources returns the adminapi read seams over the SHARED
// inventory, or (nil, nil, nil) when no inventory is loaded. getMCPAdmin consumes
// this so the read-only Servers/Tools Admin API reads the identical
// registry/catalog the runtime pipeline resolves against — the single source of
// truth. Both-nil ⇒ the adminapi Inventory service stays disabled (empty views),
// byte-identical to the QUAL-1 default. Isolating the wiring here makes the
// single-source contract directly testable (see mcp_inventory_test.go), instead of
// only through the lazily-built admin singleton.
func mcpAdminInventorySources() (adminapi.RegistrySource, adminapi.CatalogSource, adminapi.InventoryCounts) {
	reg, cat := mcpInventory.sharedInventory()
	if reg == nil || cat == nil {
		return nil, nil, nil
	}
	return mcpRegistrySource{reg: reg}, mcpCatalogSource{cat: cat}, mcpInventoryCounts{reg: reg, cat: cat}
}

// InventoryStatus is the safe, read-only inventory readiness surfaced on the admin
// overview. It distinguishes not_configured / loaded / invalid and reports counts,
// but never labels the subsystem Observe-/qualification-/production-ready (inventory
// is only ONE dependency).
type InventoryStatus struct {
	State               string `json:"state"` // not_configured | loaded | invalid
	Reason              string `json:"reason,omitempty"`
	Servers             int    `json:"servers"`
	VerifiedServers     int    `json:"verified_servers"`
	Tools               int    `json:"tools"`
	QuarantinedTools    int    `json:"quarantined_tools"`
	ReviewRequiredTools int    `json:"review_required_tools"`
	// ExecutionEnabled is always false: QUAL-2 composes no executor. Surfaced so the
	// UI can keep stating that upstream execution is disabled.
	ExecutionEnabled bool `json:"execution_enabled"`
}

// inventoryStatus builds the safe status view from the published holder.
func inventoryStatus() InventoryStatus {
	mcpInventory.mu.RLock()
	state, reason, reg, cat := mcpInventory.state, mcpInventory.reason, mcpInventory.reg, mcpInventory.cat
	mcpInventory.mu.RUnlock()

	st := InventoryStatus{State: string(state), Reason: reason, ExecutionEnabled: false}
	if reg != nil {
		// Index-based range: ServerRecord is a wide struct; avoid the per-iteration
		// value copy (gocritic rangeValCopy).
		servers := reg.Current().Servers()
		st.Servers = len(servers)
		for i := range servers {
			if servers[i].Usable() {
				st.VerifiedServers++
			}
		}
	}
	if cat != nil {
		tools := cat.Current().Records()
		st.Tools = len(tools)
		for i := range tools {
			switch tools[i].Eligibility {
			case catalog.Quarantined:
				st.QuarantinedTools++
			case catalog.ReviewRequired:
				st.ReviewRequiredTools++
			}
		}
	}
	return st
}

// ── inventory file DTO ───────────────────────────────────────────────────────

// qualInventoryDoc is the top-level qualification inventory document. It describes
// exactly ONE Gateway qualification fleet under one dedicated tenant. Unknown
// members are rejected (strict decode) so a typo or an injected field fails closed.
type qualInventoryDoc struct {
	SchemaVersion int               `json:"schema_version"`
	Tenant        string            `json:"tenant"`
	Servers       []qualServerEntry `json:"servers"`
}

// qualServerEntry carries only the values needed to construct + verify an existing
// Registry record. It never accepts raw credentials, tokens, keys, an
// operator-selected revision, a verification status, or an arbitrary/Management
// capability.
type qualServerEntry struct {
	ServerID          string          `json:"server_id"`
	Endpoint          string          `json:"endpoint"`
	PinnedIdentity    string          `json:"pinned_identity"`
	Capability        string          `json:"capability,omitempty"` // optional; must equal "gateway"
	CredentialProfile string          `json:"credential_profile,omitempty"`
	Enabled           *bool           `json:"enabled,omitempty"` // nil ⇒ true
	Tools             []qualToolEntry `json:"tools,omitempty"`
}

// qualToolEntry carries the tool's own bounded tools/list metadata. The fingerprint
// is recomputed by catalog.Ingest from these fields — no precomputed hash and no
// second fingerprint format is accepted. input_schema/output_schema/annotations are
// JSON Schema / annotation OBJECTS (tool definitions, not arguments or outputs), and
// are re-encoded verbatim into a tools/list result for the real ingestion path.
type qualToolEntry struct {
	Name             string          `json:"name"`
	InputSchema      json.RawMessage `json:"input_schema"`
	OutputSchema     json.RawMessage `json:"output_schema,omitempty"`
	Description      string          `json:"description,omitempty"`
	Title            string          `json:"title,omitempty"`
	Annotations      json.RawMessage `json:"annotations,omitempty"`
	DestinationClass string          `json:"destination_class,omitempty"` // none|approved|internal|arbitrary|unknown
}

// errInventory builds a bounded, secret-free inventory error. The message is a
// fixed phrase (never a path, identity, credential, or file content).
func errInventory(msg string) error { return errors.New("mcp qualification inventory: " + msg) }

// ── loader ───────────────────────────────────────────────────────────────────

// loadQualificationInventory resolves the qualification inventory for the resolved
// startup config. It returns the fresh registry/catalog pair the caller wires into
// BOTH the runtime Deps and the Admin API, plus the node-local state. Contracts:
//
//   - listener disabled ⇒ (empty reg, empty cat, not_configured, nil): QUAL-1
//     byte-identical empty-registry behavior;
//   - enabled, no file ⇒ (empty reg, empty cat, not_configured, nil);
//   - enabled, file present + valid ⇒ (populated reg, populated cat, loaded, nil);
//   - enabled, file present + invalid ⇒ (nil, nil, invalid, err): the caller fails
//     activation closed (nothing binds) and surfaces the bounded reason.
//
// The empty pair is always constructed with limits.DefaultCatalog() so the disabled
// / no-file path is identical to QUAL-1's assembleGatewayConfig.
func loadQualificationInventory(sc mcpObserveStartupConfig) (*registry.Registry, *catalog.Catalog, mcpInventoryState, error) {
	lim := limits.DefaultCatalog()
	if !sc.Enabled || sc.QualificationInventoryFile == "" {
		return registry.New(lim), catalog.New(lim), mcpInvNotConfigured, nil
	}
	raw, err := readInventoryFile(sc.QualificationInventoryFile)
	if err != nil {
		return nil, nil, mcpInvInvalid, err
	}
	doc, err := decodeInventory(raw)
	if err != nil {
		return nil, nil, mcpInvInvalid, err
	}
	reg, cat, err := seedInventory(doc, lim)
	if err != nil {
		return nil, nil, mcpInvInvalid, err
	}
	return reg, cat, mcpInvLoaded, nil
}

// readInventoryFile reads the operator-supplied inventory path after rejecting a
// directory-traversal path (mirrors readFileClean) and bounding the size BEFORE the
// full read (LimitReader one byte past the cap so an over-cap file is detected). It
// never echoes the path or contents.
func readInventoryFile(path string) ([]byte, error) {
	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return nil, errInventory("path traversal not allowed")
	}
	f, err := os.Open(cleaned) // #nosec G304 -- admin-provided startup path, ".." rejected above
	if err != nil {
		return nil, errInventory("inventory file is not readable")
	}
	defer f.Close() //nolint:errcheck // read-only handle
	raw, err := io.ReadAll(io.LimitReader(f, maxInventoryFileBytes+1))
	if err != nil {
		return nil, errInventory("inventory file is not readable")
	}
	if len(raw) > maxInventoryFileBytes {
		return nil, errInventory("inventory file exceeds byte bound")
	}
	if len(raw) == 0 {
		return nil, errInventory("inventory file is empty")
	}
	return raw, nil
}

// decodeInventory strictly decodes the inventory bytes into the DTO: unknown members
// are rejected, trailing data is rejected, and the schema version + tenant + server
// count are validated. It performs no seeding.
func decodeInventory(raw []byte) (*qualInventoryDoc, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc qualInventoryDoc
	if err := dec.Decode(&doc); err != nil {
		return nil, errInventory("inventory document is malformed or has unknown fields")
	}
	if dec.More() {
		return nil, errInventory("inventory document has trailing data")
	}
	if doc.SchemaVersion != qualInventorySchemaVersion {
		return nil, errInventory("unsupported inventory schema_version")
	}
	if err := validateOpaqueField(doc.Tenant, "tenant"); err != nil {
		return nil, err
	}
	if len(doc.Servers) == 0 {
		return nil, errInventory("inventory has no servers")
	}
	return &doc, nil
}

// seedInventory builds a FRESH registry/catalog pair and seeds every server + tool
// atomically. Servers and tools are sorted deterministically so identical input
// yields identical revisions regardless of file order. Any failure returns an error
// and the freshly-built (discarded) pair is never published.
func seedInventory(doc *qualInventoryDoc, lim limits.CatalogLimits) (*registry.Registry, *catalog.Catalog, error) {
	reg := registry.New(lim)
	cat := catalog.New(lim)

	servers := append([]qualServerEntry(nil), doc.Servers...)
	sort.Slice(servers, func(i, j int) bool { return servers[i].ServerID < servers[j].ServerID })

	seenServer := make(map[string]struct{}, len(servers))
	for i := range servers {
		s := servers[i]
		if _, dup := seenServer[s.ServerID]; dup {
			return nil, nil, errInventory("duplicate server_id")
		}
		seenServer[s.ServerID] = struct{}{}
		if err := seedServer(reg, cat, s, doc.Tenant); err != nil {
			return nil, nil, err
		}
	}
	return reg, cat, nil
}

// seedServer validates one server entry and seeds it through the real Registry +
// Catalog flow: Register → VerifyIdentity (must confirm VerifyVerified) → Ingest
// tools (while enabled+verified) → optionally disable. It force-binds the Gateway
// capability and the dedicated tenant, and rejects any raw-credential / Management /
// operator-revision input by construction (the DTO never carries those fields).
func seedServer(reg *registry.Registry, cat *catalog.Catalog, s qualServerEntry, tenant string) error {
	if err := validateOpaqueField(s.ServerID, "server_id"); err != nil {
		return err
	}
	// Route round-trip safety: the server id is carried as a SINGLE path segment in
	// `/mcp/gateway/<server-id>`, and the runtime's parseGatewayServerID stops at the
	// first '/'. An id containing '/' (or the path-canonicalization-sensitive '.'/'..',
	// or a percent/query/fragment byte) would be registered but permanently
	// unreachable via the route (silently 404). Reject it at seed time so a seeded
	// server is always resolvable (raised in review).
	if err := validateRouteSafeSegment(s.ServerID); err != nil {
		return err
	}
	if s.Capability != "" && s.Capability != protocol.Gateway.String() {
		// Only Gateway is seedable; a Management (or arbitrary) capability fails closed.
		return errInventory("server capability must be gateway")
	}
	if s.PinnedIdentity == "" {
		return errInventory("server pinned_identity is required")
	}
	identity := registry.Identity(s.PinnedIdentity)

	// 1. Register through the real contract (stamps Enabled=true, VerifyVerified, the
	//    revision, and force-binds Gateway + the qualification tenant). A malformed
	//    field, duplicate id, duplicate endpoint, or capacity overrun fails closed.
	if _, err := reg.Register(registry.Registration{
		ID:                registry.ServerID(s.ServerID),
		Endpoint:          registry.Endpoint(s.Endpoint),
		PinnedIdentity:    identity,
		Capability:        protocol.Gateway,
		CredentialProfile: registry.CredentialProfile(s.CredentialProfile),
		OwnerScope:        registry.OwnerScope(tenant),
		// CreatedAt/UpdatedAt intentionally zero: node-local metadata, not surfaced and
		// not security-relevant; a zero value keeps seeding clock-free + deterministic.
	}); err != nil {
		return errInventory("server registration failed: " + registrationReason(err))
	}

	// 2. Confirm the pinned identity verifies to the exact accepted state. The file
	//    provides one identity, so an exact match is expected; any non-verified result
	//    fails the whole inventory closed (defense-in-depth over the register stamp).
	verif, rec, err := reg.VerifyIdentity(registry.ServerID(s.ServerID), identity)
	if err != nil || verif != registry.VerifyVerified || !rec.Usable() {
		return errInventory("server identity did not verify to the accepted state")
	}

	// 3. Seed the tools (while the server is enabled+verified so Ingest accepts it).
	if err := seedTools(reg, cat, s, identity); err != nil {
		return err
	}

	// 4. Honor an explicit disabled state AFTER tools are ingested (a disabled server
	//    is registered + visible but not Usable, so the pipeline still 404s it).
	if s.Enabled != nil && !*s.Enabled {
		if _, err := reg.SetEnabled(registry.ServerID(s.ServerID), false); err != nil {
			return errInventory("server could not be disabled")
		}
	}
	return nil
}

// seedTools ingests one server's tools through the real catalog.Ingest path: it
// re-encodes the bounded tool metadata into a tools/list result and lets Ingest
// recompute the existing fingerprint and land each tool Quarantined (record-only
// Observe). A server with no tools is valid (a resolvable server with an empty
// catalog). Duplicate (server,name) keys and unsupported destination classes fail
// closed.
func seedTools(reg *registry.Registry, cat *catalog.Catalog, s qualServerEntry, identity registry.Identity) error {
	if len(s.Tools) == 0 {
		return nil
	}
	dests := make(map[string]catalog.DestinationClass, len(s.Tools))
	seen := make(map[string]struct{}, len(s.Tools))
	wire := struct {
		Tools []toolWire `json:"tools"`
	}{Tools: make([]toolWire, 0, len(s.Tools))}

	tools := append([]qualToolEntry(nil), s.Tools...)
	sort.Slice(tools, func(i, j int) bool { return tools[i].Name < tools[j].Name })
	for i := range tools {
		t := tools[i]
		if t.Name == "" {
			return errInventory("tool name is required")
		}
		if _, dup := seen[t.Name]; dup {
			return errInventory("duplicate tool key")
		}
		seen[t.Name] = struct{}{}
		if len(t.InputSchema) == 0 {
			return errInventory("tool input_schema is required")
		}
		dc, ok := parseDestinationClass(t.DestinationClass)
		if !ok {
			return errInventory("tool has an unsupported destination_class")
		}
		if dc != catalog.DestUnknown {
			dests[t.Name] = dc
		}
		wire.Tools = append(wire.Tools, toolWire{
			Name:         t.Name,
			InputSchema:  t.InputSchema,
			OutputSchema: t.OutputSchema,
			Description:  t.Description,
			Title:        t.Title,
			Annotations:  t.Annotations,
		})
	}
	rawList, err := json.Marshal(wire)
	if err != nil {
		return errInventory("tool metadata could not be encoded")
	}
	if _, _, err := cat.Ingest(reg, catalog.DiscoveryInput{
		ServerID:     registry.ServerID(s.ServerID),
		Identity:     identity,
		Raw:          rawList,
		Destinations: dests,
	}); err != nil {
		return errInventory("tool ingestion failed: " + ingestReason(err))
	}
	return nil
}

// toolWire is the exact tools/list tool-object shape catalog.Ingest accepts. Only
// the strict member allowlist (name/inputSchema/outputSchema/description/annotations/
// title) is emitted, so the re-encoded result round-trips through the ingest parser.
type toolWire struct {
	Name         string          `json:"name"`
	InputSchema  json.RawMessage `json:"inputSchema"`
	OutputSchema json.RawMessage `json:"outputSchema,omitempty"`
	Description  string          `json:"description,omitempty"`
	Annotations  json.RawMessage `json:"annotations,omitempty"`
	Title        string          `json:"title,omitempty"`
}

// parseDestinationClass maps the safe config label to the catalog enum. An empty
// value is DestUnknown (a tool absent from the destinations map). An unknown label
// is rejected.
func parseDestinationClass(s string) (catalog.DestinationClass, bool) {
	switch s {
	case "", "unknown":
		return catalog.DestUnknown, true
	case "none":
		return catalog.DestNone, true
	case "approved":
		return catalog.DestApproved, true
	case "internal":
		return catalog.DestInternal, true
	case "arbitrary":
		return catalog.DestArbitrary, true
	default:
		return catalog.DestUnknown, false
	}
}

// validateOpaqueField applies a minimal safe gate to a required opaque identifier
// (non-empty, byte-bounded, no ASCII control characters, no surrounding whitespace)
// before it reaches the Registry validator. It never echoes the value.
func validateOpaqueField(s, name string) error {
	if s == "" {
		return errInventory(name + " is required")
	}
	if len(s) > 1024 {
		return errInventory(name + " exceeds byte bound")
	}
	if s != strings.TrimSpace(s) {
		return errInventory(name + " has surrounding whitespace")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return errInventory(name + " contains a control character")
		}
	}
	return nil
}

// validateRouteSafeSegment rejects a server id that cannot round-trip as a single
// URL path segment in `/mcp/gateway/<server-id>`: no '/' (the route splits on it),
// not '.'/'..' (HTTP path canonicalization rewrites them), and no byte that would be
// percent-encoded or reinterpreted by URL parsing ('%', '?', '#', '\\', space). The
// broader opaque-token charset the registry accepts is intentionally narrowed HERE
// for the route-embedded id only; tool names (carried in the JSON-RPC body, never the
// path) keep the wider charset.
func validateRouteSafeSegment(id string) error {
	if id == "." || id == ".." {
		return errInventory("server_id must not be '.' or '..' (route-unsafe)")
	}
	for i := 0; i < len(id); i++ {
		switch id[i] {
		case '/', '%', '?', '#', '\\', ' ':
			return errInventory("server_id must be a single route-safe path segment")
		}
	}
	return nil
}

// registrationReason maps a registry registration error to a bounded classification
// (never the raw detail, which is already safe but kept uniform here).
func registrationReason(err error) string {
	switch {
	case err == nil:
		return "ok"
	case strings.Contains(err.Error(), "already registered"):
		return "duplicate server or endpoint"
	case strings.Contains(err.Error(), "capacity"):
		return "server capacity reached"
	default:
		return "invalid server registration"
	}
}

// ingestReason maps a catalog ingest error to a bounded classification.
func ingestReason(err error) string {
	switch {
	case err == nil:
		return "ok"
	case strings.Contains(err.Error(), "capacity"):
		return "tool capacity reached"
	case strings.Contains(err.Error(), "duplicate"):
		return "duplicate tool"
	case strings.Contains(err.Error(), "identity"):
		return "identity mismatch"
	default:
		return "malformed tool metadata"
	}
}
