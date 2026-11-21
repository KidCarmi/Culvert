package qualinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
)

// MaxFileBytes bounds the qualification inventory document read from disk
// BEFORE decoding (a fail-closed memory-DoS guard on hostile operator input). The
// per-schema / per-tool / per-server bounds are enforced by the existing catalog
// limits during catalog.Ingest; this only caps the whole file.
const MaxFileBytes = 1 << 20 // 1 MiB

// schemaVersion is the only supported inventory schema version. An
// unknown version fails closed (no silent forward/backward compatibility).
const schemaVersion = 1

// ── inventory file DTO ───────────────────────────────────────────────────────

// Doc is the top-level qualification inventory document. It describes
// exactly ONE Gateway qualification fleet under one dedicated tenant. Unknown
// members are rejected (strict decode) so a typo or an injected field fails closed.
type Doc struct {
	SchemaVersion int           `json:"schema_version"`
	Tenant        string        `json:"tenant"`
	Servers       []ServerEntry `json:"servers"`
}

// ServerEntry carries only the values needed to construct + verify an existing
// Registry record. It never accepts raw credentials, tokens, keys, an
// operator-selected revision, a verification status, or an arbitrary/Management
// capability.
type ServerEntry struct {
	ServerID          string      `json:"server_id"`
	Endpoint          string      `json:"endpoint"`
	PinnedIdentity    string      `json:"pinned_identity"`
	Capability        string      `json:"capability,omitempty"` // optional; must equal "gateway"
	CredentialProfile string      `json:"credential_profile,omitempty"`
	Enabled           *bool       `json:"enabled,omitempty"` // nil ⇒ true
	Tools             []ToolEntry `json:"tools,omitempty"`
}

// ToolEntry carries the tool's own bounded tools/list metadata. The fingerprint
// is recomputed by catalog.Ingest from these fields — no precomputed hash and no
// second fingerprint format is accepted. input_schema/output_schema/annotations are
// JSON Schema / annotation OBJECTS (tool definitions, not arguments or outputs), and
// are re-encoded verbatim into a tools/list result for the real ingestion path.
type ToolEntry struct {
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

// ReadFile reads the operator-supplied inventory path after rejecting a
// directory-traversal path (mirrors readFileClean) and bounding the size BEFORE the
// full read (LimitReader one byte past the cap so an over-cap file is detected). It
// never echoes the path or contents.
func ReadFile(path string) ([]byte, error) {
	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return nil, errInventory("path traversal not allowed")
	}
	f, err := os.Open(cleaned) // #nosec G304 -- admin-provided startup path, ".." rejected above
	if err != nil {
		return nil, errInventory("inventory file is not readable")
	}
	defer f.Close() //nolint:errcheck // read-only handle
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	if err != nil {
		return nil, errInventory("inventory file is not readable")
	}
	if len(raw) > MaxFileBytes {
		return nil, errInventory("inventory file exceeds byte bound")
	}
	if len(raw) == 0 {
		return nil, errInventory("inventory file is empty")
	}
	return raw, nil
}

// Decode strictly decodes the inventory bytes into the DTO: unknown members
// are rejected, trailing data is rejected, and the schema version + tenant + server
// count are validated. It performs no seeding.
func Decode(raw []byte) (*Doc, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var doc Doc
	if err := dec.Decode(&doc); err != nil {
		return nil, errInventory("inventory document is malformed or has unknown fields")
	}
	if dec.More() {
		return nil, errInventory("inventory document has trailing data")
	}
	if doc.SchemaVersion != schemaVersion {
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

// Seed builds a FRESH registry/catalog pair and seeds every server + tool
// atomically. Servers and tools are sorted deterministically so identical input
// yields identical revisions regardless of file order. Any failure returns an error
// and the freshly-built (discarded) pair is never published.
func Seed(doc *Doc, lim limits.CatalogLimits) (*registry.Registry, *catalog.Catalog, error) {
	reg := registry.New(lim)
	cat := catalog.New(lim)

	servers := append([]ServerEntry(nil), doc.Servers...)
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
func seedServer(reg *registry.Registry, cat *catalog.Catalog, s ServerEntry, tenant string) error {
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
func seedTools(reg *registry.Registry, cat *catalog.Catalog, s ServerEntry, identity registry.Identity) error {
	if len(s.Tools) == 0 {
		return nil
	}
	dests := make(map[string]catalog.DestinationClass, len(s.Tools))
	seen := make(map[string]struct{}, len(s.Tools))
	wire := struct {
		Tools []toolWire `json:"tools"`
	}{Tools: make([]toolWire, 0, len(s.Tools))}

	tools := append([]ToolEntry(nil), s.Tools...)
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
