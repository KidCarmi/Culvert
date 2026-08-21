package limits

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// CatalogLimits is the immutable, validated bound set for the PR-2 server
// registry and tool catalog. It mirrors the Limits pattern exactly (unexported
// Config read through accessors, single Validate gate, hard-cap ceilings, no
// mutable singleton) but bounds a different surface: entity counts (servers,
// tools, catalog entries) and discovery-result / schema / description sizes,
// rather than JSON-RPC wire frames.
//
// A hostile server must not be able to force unbounded allocation, recursion,
// sorting or catalog growth: every quantity a discovery result can drive is
// bounded here, and construction fails closed on any zero, negative,
// inconsistent, or over-ceiling value.

// Hard-cap ceilings for the catalog surface. A CatalogConfig value above its
// ceiling fails validation regardless of how a caller configures the defaults.
const (
	capServers         = 1 << 20  // 1,048,576 registered servers
	capToolsPerServer  = 1 << 16  // 65,536 tools behind one server
	capCatalogEntries  = 1 << 20  // 1,048,576 total (server,tool) records
	capDiscoveryBytes  = 64 << 20 // 64 MiB of one tools/list result
	capSchemaBytes     = 4 << 20  // 4 MiB of one canonical schema
	capDescBytes       = 256 << 10
	capSchemaDepth     = 256
	capCatObjectMembs  = 1 << 16
	capCatArrayElems   = 1 << 16
	capDiffOps         = 1 << 20 // bound on field-diff operations per classification
	capNameBytes       = 512     // an individual tool-name byte bound (≤ MaxMethodBytes reuse where possible)
	capEndpointBytes   = 2048
	capIdentityBytes   = 4096
	capServerIDBytes   = 256
	capCredProfBytes   = 256
	capOwnerScopeBytes = 512
)

// CatalogConfig is the mutable input to NewCatalog. A zero CatalogConfig is
// invalid; every field must be set.
type CatalogConfig struct {
	MaxServers          int // max registered servers in one registry snapshot
	MaxToolsPerServer   int // max tools behind a single server
	MaxCatalogEntries   int // max (server,tool) records in one catalog snapshot (also bounds snapshot publication work)
	MaxDiscoveryBytes   int // max bytes of one raw tools/list discovery result
	MaxSchemaBytes      int // max bytes of one tool input/output schema
	MaxDescriptionBytes int // max bytes of one tool description
	MaxSchemaDepth      int // max JSON nesting depth inside a schema/discovery result
	MaxObjectMembers    int // max members in any one JSON object during canonicalization
	MaxArrayElements    int // max elements in any one JSON array during canonicalization
	MaxDiffOps          int // max field-level diff operations per drift classification
	MaxNameBytes        int // max bytes of a tool name
	MaxEndpointBytes    int // max bytes of a canonical endpoint identity
	MaxIdentityBytes    int // max bytes of a pinned/verified identity representation
	MaxServerIDBytes    int // max bytes of an opaque server registry id
	MaxCredProfileBytes int // max bytes of an opaque credential-profile reference
	MaxOwnerScopeBytes  int // max bytes of an ownership/tenant scope token
}

// CatalogLimits is an immutable, validated catalog bound set.
type CatalogLimits struct{ c CatalogConfig }

// MaxServers returns the maximum registered servers in one registry snapshot.
func (l CatalogLimits) MaxServers() int { return l.c.MaxServers }

// MaxToolsPerServer returns the maximum tools behind a single server.
func (l CatalogLimits) MaxToolsPerServer() int { return l.c.MaxToolsPerServer }

// MaxCatalogEntries returns the maximum (server,tool) records in one catalog
// snapshot; it also bounds snapshot publication work (publication is O(entries)).
func (l CatalogLimits) MaxCatalogEntries() int { return l.c.MaxCatalogEntries }

// MaxDiscoveryBytes returns the maximum bytes of one raw discovery result.
func (l CatalogLimits) MaxDiscoveryBytes() int { return l.c.MaxDiscoveryBytes }

// MaxSchemaBytes returns the maximum bytes of one tool schema.
func (l CatalogLimits) MaxSchemaBytes() int { return l.c.MaxSchemaBytes }

// MaxDescriptionBytes returns the maximum bytes of one tool description.
func (l CatalogLimits) MaxDescriptionBytes() int { return l.c.MaxDescriptionBytes }

// MaxSchemaDepth returns the maximum JSON nesting depth inside a schema.
func (l CatalogLimits) MaxSchemaDepth() int { return l.c.MaxSchemaDepth }

// MaxObjectMembers returns the maximum members in any one JSON object.
func (l CatalogLimits) MaxObjectMembers() int { return l.c.MaxObjectMembers }

// MaxArrayElements returns the maximum elements in any one JSON array.
func (l CatalogLimits) MaxArrayElements() int { return l.c.MaxArrayElements }

// MaxDiffOps returns the maximum field-level diff operations per classification.
func (l CatalogLimits) MaxDiffOps() int { return l.c.MaxDiffOps }

// MaxNameBytes returns the maximum bytes of a tool name.
func (l CatalogLimits) MaxNameBytes() int { return l.c.MaxNameBytes }

// MaxEndpointBytes returns the maximum bytes of a canonical endpoint identity.
func (l CatalogLimits) MaxEndpointBytes() int { return l.c.MaxEndpointBytes }

// MaxIdentityBytes returns the maximum bytes of a pinned/verified identity.
func (l CatalogLimits) MaxIdentityBytes() int { return l.c.MaxIdentityBytes }

// MaxServerIDBytes returns the maximum bytes of an opaque server registry id.
func (l CatalogLimits) MaxServerIDBytes() int { return l.c.MaxServerIDBytes }

// MaxCredProfileBytes returns the maximum bytes of a credential-profile reference.
func (l CatalogLimits) MaxCredProfileBytes() int { return l.c.MaxCredProfileBytes }

// MaxOwnerScopeBytes returns the maximum bytes of an ownership/tenant scope token.
func (l CatalogLimits) MaxOwnerScopeBytes() int { return l.c.MaxOwnerScopeBytes }

// Validate reports whether the CatalogConfig is safe and internally consistent.
func (c CatalogConfig) Validate() error {
	for _, ck := range []struct {
		v, ceil int
		name    string
	}{
		{c.MaxServers, capServers, "MaxServers"},
		{c.MaxToolsPerServer, capToolsPerServer, "MaxToolsPerServer"},
		{c.MaxCatalogEntries, capCatalogEntries, "MaxCatalogEntries"},
		{c.MaxDiscoveryBytes, capDiscoveryBytes, "MaxDiscoveryBytes"},
		{c.MaxSchemaBytes, capSchemaBytes, "MaxSchemaBytes"},
		{c.MaxDescriptionBytes, capDescBytes, "MaxDescriptionBytes"},
		{c.MaxSchemaDepth, capSchemaDepth, "MaxSchemaDepth"},
		{c.MaxObjectMembers, capCatObjectMembs, "MaxObjectMembers"},
		{c.MaxArrayElements, capCatArrayElems, "MaxArrayElements"},
		{c.MaxDiffOps, capDiffOps, "MaxDiffOps"},
		{c.MaxNameBytes, capNameBytes, "MaxNameBytes"},
		{c.MaxEndpointBytes, capEndpointBytes, "MaxEndpointBytes"},
		{c.MaxIdentityBytes, capIdentityBytes, "MaxIdentityBytes"},
		{c.MaxServerIDBytes, capServerIDBytes, "MaxServerIDBytes"},
		{c.MaxCredProfileBytes, capCredProfBytes, "MaxCredProfileBytes"},
		{c.MaxOwnerScopeBytes, capOwnerScopeBytes, "MaxOwnerScopeBytes"},
	} {
		if err := posCap(ck.v, ck.ceil, ck.name); err != nil {
			return err
		}
	}
	// Internal consistency: a single schema/description can never exceed the whole
	// discovery result; per-server tools can never exceed the total catalog; and a
	// tool name can never exceed the schema/discovery envelope it arrives in.
	if c.MaxSchemaBytes > c.MaxDiscoveryBytes {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "MaxSchemaBytes > MaxDiscoveryBytes")
	}
	if c.MaxDescriptionBytes > c.MaxDiscoveryBytes {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "MaxDescriptionBytes > MaxDiscoveryBytes")
	}
	if c.MaxNameBytes > c.MaxDiscoveryBytes {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "MaxNameBytes > MaxDiscoveryBytes")
	}
	if c.MaxToolsPerServer > c.MaxCatalogEntries {
		return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", "MaxToolsPerServer > MaxCatalogEntries")
	}
	return nil
}

// NewCatalog validates c and returns an immutable CatalogLimits, or an error.
func NewCatalog(c CatalogConfig) (CatalogLimits, error) {
	if err := c.Validate(); err != nil {
		return CatalogLimits{}, err
	}
	return CatalogLimits{c: c}, nil
}

// catalogConfig is the conservative safe-default for the Gateway registry +
// catalog surface (PR-2 is Gateway-only).
var catalogConfig = CatalogConfig{
	MaxServers:          4096,
	MaxToolsPerServer:   1024,
	MaxCatalogEntries:   1 << 16, // 65,536
	MaxDiscoveryBytes:   4 << 20, // 4 MiB
	MaxSchemaBytes:      256 << 10,
	MaxDescriptionBytes: 16 << 10,
	MaxSchemaDepth:      64,
	MaxObjectMembers:    4096,
	MaxArrayElements:    4096,
	MaxDiffOps:          1 << 16,
	MaxNameBytes:        128, // matches the PR-1 method-token bound (MaxMethodBytes)
	MaxEndpointBytes:    2048,
	MaxIdentityBytes:    4096,
	MaxServerIDBytes:    256,
	MaxCredProfileBytes: 256,
	MaxOwnerScopeBytes:  512,
}

// DefaultCatalog returns the validated Gateway registry + catalog default bounds.
func DefaultCatalog() CatalogLimits {
	l, err := NewCatalog(catalogConfig)
	if err != nil {
		panic("mcp/limits: catalog default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}
