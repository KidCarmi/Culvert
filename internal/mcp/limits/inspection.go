package limits

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// InspectionLimits is the immutable, validated bound set for the PR-7 inspection
// layer (semantic schema validation, DLP/redaction, destination/SSRF/DNS/redirect,
// output/injection). It mirrors the Limits / CatalogLimits pattern exactly
// (unexported Config read through accessors, a single Validate gate, hard-cap
// ceilings, no mutable singleton) but bounds the inspection surface: schema
// compile/validation work, bytes scanned, findings, extracted destinations, DNS
// and redirect work, and safe-result size.
//
// Gateway and Management carry INDEPENDENT inspection limit sets: one
// capability's bound never affects the other (capability isolation, asserted by
// tests). A hostile argument/output/schema/URL must never be able to force
// unbounded allocation, recursion, scanning, resolution or redirect work: every
// quantity a peer can drive is bounded here, and construction fails closed on any
// zero, negative, inconsistent, or over-ceiling value. There is NO per-finding or
// per-destination goroutine — these bounds cap sequential work.

// Hard-cap ceilings for the inspection surface. An InspectionConfig value above
// its ceiling fails validation regardless of how a caller configures the defaults.
const (
	capInspSchemaBytes        = 4 << 20  // 4 MiB — one tool input/output schema
	capInspSchemaNodes        = 1 << 16  // compiled schema nodes
	capInspSchemaAlts         = 4096     // anyOf/enum alternatives across a schema
	capInspValidationOps      = 1 << 20  // value-validation operations
	capInspArgNodes           = 1 << 16  // nodes in a decoded argument value
	capInspOutputBytes        = 16 << 20 // 16 MiB — one upstream response body
	capInspOutputNodes        = 1 << 16  // nodes in a decoded output value
	capInspStringsScanned     = 1 << 16  // string leaves scanned in one value
	capInspBytesPerString     = 1 << 20  // bytes scanned in any one string leaf
	capInspTotalScanBytes     = 64 << 20 // total bytes scanned across one value
	capInspFindings           = 4096     // DLP/injection findings in one value
	capInspRedactions         = 4096     // redactions applied in one transform
	capInspExtractionPaths    = 1024     // compiled destination-extraction paths
	capInspExtractedDests     = 256      // destinations extracted from one value
	capInspURLBytes           = 8192     // one destination URL
	capInspHostBytes          = 1024     // one destination host
	capInspQueryBytes         = 4096     // one destination query string
	capInspDNSConcurrency     = 64       // concurrent DNS resolutions
	capInspDNSAddresses       = 64       // addresses accepted per DNS answer
	capInspDNSWork            = 64       // CNAME/lookup work units per resolution
	capInspRedirectHops       = 32       // redirect hops in one chain
	capInspRedirectEvidence   = 32       // recorded redirect-hop evidence entries
	capInspInjectionOps       = 1 << 20  // injection-detector operations
	capInspTransformedBytes   = 16 << 20 // transformed output bytes
	capInspSafeResultBytes    = 256 << 10
	capInspTruncatedTextBytes = 256 << 10 // max text a display truncation may keep
)

// InspectionConfig is the mutable input to NewInspection. A zero InspectionConfig
// is invalid; every field must be set.
type InspectionConfig struct {
	MaxSchemaBytes        int // max bytes of one tool input/output schema
	MaxSchemaNodes        int // max compiled schema nodes
	MaxSchemaAlternatives int // max anyOf/enum alternatives across a schema
	MaxValidationOps      int // max value-validation operations
	MaxArgNodes           int // max nodes in a decoded argument value
	MaxOutputBytes        int // max bytes of one upstream response body
	MaxOutputNodes        int // max nodes in a decoded output value
	MaxStringsScanned     int // max string leaves scanned in one value
	MaxBytesPerString     int // max bytes scanned in any one string leaf
	MaxTotalScanBytes     int // max total bytes scanned across one value
	MaxFindings           int // max DLP/injection findings in one value
	MaxRedactions         int // max redactions applied in one transform
	MaxExtractionPaths    int // max compiled destination-extraction paths
	MaxExtractedDests     int // max destinations extracted from one value
	MaxURLBytes           int // max bytes of one destination URL
	MaxHostBytes          int // max bytes of one destination host
	MaxQueryBytes         int // max bytes of one destination query string
	MaxDNSConcurrency     int // max concurrent DNS resolutions
	MaxDNSAddresses       int // max addresses accepted per DNS answer
	MaxDNSWork            int // max CNAME/lookup work units per resolution
	MaxRedirectHops       int // max redirect hops in one chain
	MaxRedirectEvidence   int // max recorded redirect-hop evidence entries
	MaxInjectionOps       int // max injection-detector operations
	MaxTransformedBytes   int // max transformed output bytes
	MaxSafeResultBytes    int // max bytes of a sanitized safe result
	MaxTruncatedTextBytes int // max text a display truncation may keep
}

// InspectionLimits is an immutable, validated inspection bound set.
type InspectionLimits struct{ c InspectionConfig }

// MaxSchemaBytes returns the maximum bytes of one tool schema.
func (l InspectionLimits) MaxSchemaBytes() int { return l.c.MaxSchemaBytes }

// MaxSchemaNodes returns the maximum compiled schema nodes.
func (l InspectionLimits) MaxSchemaNodes() int { return l.c.MaxSchemaNodes }

// MaxSchemaAlternatives returns the maximum anyOf/enum alternatives.
func (l InspectionLimits) MaxSchemaAlternatives() int { return l.c.MaxSchemaAlternatives }

// MaxValidationOps returns the maximum value-validation operations.
func (l InspectionLimits) MaxValidationOps() int { return l.c.MaxValidationOps }

// MaxArgNodes returns the maximum nodes in a decoded argument value.
func (l InspectionLimits) MaxArgNodes() int { return l.c.MaxArgNodes }

// MaxOutputBytes returns the maximum bytes of one upstream response body.
func (l InspectionLimits) MaxOutputBytes() int { return l.c.MaxOutputBytes }

// MaxOutputNodes returns the maximum nodes in a decoded output value.
func (l InspectionLimits) MaxOutputNodes() int { return l.c.MaxOutputNodes }

// MaxStringsScanned returns the maximum string leaves scanned in one value.
func (l InspectionLimits) MaxStringsScanned() int { return l.c.MaxStringsScanned }

// MaxBytesPerString returns the maximum bytes scanned in any one string leaf.
func (l InspectionLimits) MaxBytesPerString() int { return l.c.MaxBytesPerString }

// MaxTotalScanBytes returns the maximum total bytes scanned across one value.
func (l InspectionLimits) MaxTotalScanBytes() int { return l.c.MaxTotalScanBytes }

// MaxFindings returns the maximum DLP/injection findings in one value.
func (l InspectionLimits) MaxFindings() int { return l.c.MaxFindings }

// MaxRedactions returns the maximum redactions applied in one transform.
func (l InspectionLimits) MaxRedactions() int { return l.c.MaxRedactions }

// MaxExtractionPaths returns the maximum compiled destination-extraction paths.
func (l InspectionLimits) MaxExtractionPaths() int { return l.c.MaxExtractionPaths }

// MaxExtractedDests returns the maximum destinations extracted from one value.
func (l InspectionLimits) MaxExtractedDests() int { return l.c.MaxExtractedDests }

// MaxURLBytes returns the maximum bytes of one destination URL.
func (l InspectionLimits) MaxURLBytes() int { return l.c.MaxURLBytes }

// MaxHostBytes returns the maximum bytes of one destination host.
func (l InspectionLimits) MaxHostBytes() int { return l.c.MaxHostBytes }

// MaxQueryBytes returns the maximum bytes of one destination query string.
func (l InspectionLimits) MaxQueryBytes() int { return l.c.MaxQueryBytes }

// MaxDNSConcurrency returns the maximum concurrent DNS resolutions.
func (l InspectionLimits) MaxDNSConcurrency() int { return l.c.MaxDNSConcurrency }

// MaxDNSAddresses returns the maximum addresses accepted per DNS answer.
func (l InspectionLimits) MaxDNSAddresses() int { return l.c.MaxDNSAddresses }

// MaxDNSWork returns the maximum CNAME/lookup work units per resolution.
func (l InspectionLimits) MaxDNSWork() int { return l.c.MaxDNSWork }

// MaxRedirectHops returns the maximum redirect hops in one chain.
func (l InspectionLimits) MaxRedirectHops() int { return l.c.MaxRedirectHops }

// MaxRedirectEvidence returns the maximum recorded redirect-hop evidence entries.
func (l InspectionLimits) MaxRedirectEvidence() int { return l.c.MaxRedirectEvidence }

// MaxInjectionOps returns the maximum injection-detector operations.
func (l InspectionLimits) MaxInjectionOps() int { return l.c.MaxInjectionOps }

// MaxTransformedBytes returns the maximum transformed output bytes.
func (l InspectionLimits) MaxTransformedBytes() int { return l.c.MaxTransformedBytes }

// MaxSafeResultBytes returns the maximum bytes of a sanitized safe result.
func (l InspectionLimits) MaxSafeResultBytes() int { return l.c.MaxSafeResultBytes }

// MaxTruncatedTextBytes returns the maximum text a display truncation may keep.
func (l InspectionLimits) MaxTruncatedTextBytes() int { return l.c.MaxTruncatedTextBytes }

// Validate reports whether the InspectionConfig is safe and internally
// consistent. Zero, negative, over-cap, or inconsistent limits are rejected.
func (c InspectionConfig) Validate() error {
	for _, ck := range []struct {
		v, ceil int
		name    string
	}{
		{c.MaxSchemaBytes, capInspSchemaBytes, "MaxSchemaBytes"},
		{c.MaxSchemaNodes, capInspSchemaNodes, "MaxSchemaNodes"},
		{c.MaxSchemaAlternatives, capInspSchemaAlts, "MaxSchemaAlternatives"},
		{c.MaxValidationOps, capInspValidationOps, "MaxValidationOps"},
		{c.MaxArgNodes, capInspArgNodes, "MaxArgNodes"},
		{c.MaxOutputBytes, capInspOutputBytes, "MaxOutputBytes"},
		{c.MaxOutputNodes, capInspOutputNodes, "MaxOutputNodes"},
		{c.MaxStringsScanned, capInspStringsScanned, "MaxStringsScanned"},
		{c.MaxBytesPerString, capInspBytesPerString, "MaxBytesPerString"},
		{c.MaxTotalScanBytes, capInspTotalScanBytes, "MaxTotalScanBytes"},
		{c.MaxFindings, capInspFindings, "MaxFindings"},
		{c.MaxRedactions, capInspRedactions, "MaxRedactions"},
		{c.MaxExtractionPaths, capInspExtractionPaths, "MaxExtractionPaths"},
		{c.MaxExtractedDests, capInspExtractedDests, "MaxExtractedDests"},
		{c.MaxURLBytes, capInspURLBytes, "MaxURLBytes"},
		{c.MaxHostBytes, capInspHostBytes, "MaxHostBytes"},
		{c.MaxQueryBytes, capInspQueryBytes, "MaxQueryBytes"},
		{c.MaxDNSConcurrency, capInspDNSConcurrency, "MaxDNSConcurrency"},
		{c.MaxDNSAddresses, capInspDNSAddresses, "MaxDNSAddresses"},
		{c.MaxDNSWork, capInspDNSWork, "MaxDNSWork"},
		{c.MaxRedirectHops, capInspRedirectHops, "MaxRedirectHops"},
		{c.MaxRedirectEvidence, capInspRedirectEvidence, "MaxRedirectEvidence"},
		{c.MaxInjectionOps, capInspInjectionOps, "MaxInjectionOps"},
		{c.MaxTransformedBytes, capInspTransformedBytes, "MaxTransformedBytes"},
		{c.MaxSafeResultBytes, capInspSafeResultBytes, "MaxSafeResultBytes"},
		{c.MaxTruncatedTextBytes, capInspTruncatedTextBytes, "MaxTruncatedTextBytes"},
	} {
		if err := posCap(ck.v, ck.ceil, ck.name); err != nil {
			return err
		}
	}
	// Internal consistency: a single string leaf can never be scanned beyond the
	// total scan budget or the whole output; the host/query can never exceed the
	// whole URL; a display truncation can never keep more than the output; and the
	// redirect evidence can never exceed the hop cap.
	if c.MaxBytesPerString > c.MaxTotalScanBytes {
		return inspLimitErr("MaxBytesPerString > MaxTotalScanBytes")
	}
	if c.MaxHostBytes > c.MaxURLBytes || c.MaxQueryBytes > c.MaxURLBytes {
		return inspLimitErr("host/query larger than URL")
	}
	if c.MaxTruncatedTextBytes > c.MaxOutputBytes {
		return inspLimitErr("MaxTruncatedTextBytes > MaxOutputBytes")
	}
	if c.MaxRedirectEvidence > c.MaxRedirectHops {
		return inspLimitErr("MaxRedirectEvidence > MaxRedirectHops")
	}
	return nil
}

func inspLimitErr(detail string) error {
	return mcperr.New(mcperr.ReasonResourceLimit, "limits.validate", detail)
}

// NewInspection validates c and returns an immutable InspectionLimits, or an error.
func NewInspection(c InspectionConfig) (InspectionLimits, error) {
	if err := c.Validate(); err != nil {
		return InspectionLimits{}, err
	}
	return InspectionLimits{c: c}, nil
}

// gatewayInspectionConfig is the conservative safe-default for the Gateway
// inspection surface (business tool traffic — the higher-throughput surface with
// arguments and destinations).
var gatewayInspectionConfig = InspectionConfig{
	MaxSchemaBytes:        256 << 10,
	MaxSchemaNodes:        8192,
	MaxSchemaAlternatives: 512,
	MaxValidationOps:      1 << 18,
	MaxArgNodes:           8192,
	MaxOutputBytes:        4 << 20,
	MaxOutputNodes:        8192,
	MaxStringsScanned:     8192,
	MaxBytesPerString:     256 << 10,
	MaxTotalScanBytes:     8 << 20,
	MaxFindings:           1024,
	MaxRedactions:         1024,
	MaxExtractionPaths:    256,
	MaxExtractedDests:     64,
	MaxURLBytes:           4096,
	MaxHostBytes:          512,
	MaxQueryBytes:         2048,
	MaxDNSConcurrency:     16,
	MaxDNSAddresses:       32,
	MaxDNSWork:            16,
	MaxRedirectHops:       8,
	MaxRedirectEvidence:   8,
	MaxInjectionOps:       1 << 18,
	MaxTransformedBytes:   4 << 20,
	MaxSafeResultBytes:    64 << 10,
	MaxTruncatedTextBytes: 32 << 10,
}

// managementInspectionConfig is the conservative safe-default for the Management
// inspection surface — deliberately tighter and INDEPENDENT of the Gateway set.
// Management operations carry no business tool arguments and resolve no Gateway
// destinations, so its destination/DNS/redirect budgets are minimal.
var managementInspectionConfig = InspectionConfig{
	MaxSchemaBytes:        128 << 10,
	MaxSchemaNodes:        4096,
	MaxSchemaAlternatives: 256,
	MaxValidationOps:      1 << 17,
	MaxArgNodes:           4096,
	MaxOutputBytes:        1 << 20,
	MaxOutputNodes:        4096,
	MaxStringsScanned:     4096,
	MaxBytesPerString:     128 << 10,
	MaxTotalScanBytes:     2 << 20,
	MaxFindings:           512,
	MaxRedactions:         512,
	MaxExtractionPaths:    64,
	MaxExtractedDests:     16,
	MaxURLBytes:           2048,
	MaxHostBytes:          512,
	MaxQueryBytes:         1024,
	MaxDNSConcurrency:     4,
	MaxDNSAddresses:       16,
	MaxDNSWork:            8,
	MaxRedirectHops:       4,
	MaxRedirectEvidence:   4,
	MaxInjectionOps:       1 << 17,
	MaxTransformedBytes:   1 << 20,
	MaxSafeResultBytes:    32 << 10,
	MaxTruncatedTextBytes: 16 << 10,
}

// DefaultGatewayInspection returns the validated Gateway inspection default bounds.
func DefaultGatewayInspection() InspectionLimits {
	l, err := NewInspection(gatewayInspectionConfig)
	if err != nil {
		panic("mcp/limits: gateway inspection default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}

// DefaultManagementInspection returns the validated Management inspection default bounds.
func DefaultManagementInspection() InspectionLimits {
	l, err := NewInspection(managementInspectionConfig)
	if err != nil {
		panic("mcp/limits: management inspection default invalid: " + err.Error()) // unreachable; guarded by a test
	}
	return l
}
