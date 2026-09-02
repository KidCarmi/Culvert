package inspection

import (
	"time"

	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/destination"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/dlp"
	"github.com/KidCarmi/Culvert/internal/mcp/inspection/schema"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// RedactionProfile is an immutable redaction obligation target. Classes lists the
// data classifications the profile removes; Mandatory means a failure to fully
// redact fails closed (no partial transform published).
type RedactionProfile struct {
	Ref       string
	Revision  uint64
	classes   map[dlp.Classification]struct{}
	Mandatory bool
}

// Redacts reports whether the profile removes classification c.
func (rp RedactionProfile) Redacts(c dlp.Classification) bool {
	_, ok := rp.classes[c]
	return ok
}

// NewRedactionProfile builds an immutable RedactionProfile from a ref, revision and
// the classifications it removes. The classes slice is copied into an internal set,
// so the caller cannot mutate the profile after construction.
func NewRedactionProfile(ref string, revision uint64, classes []dlp.Classification, mandatory bool) RedactionProfile {
	set := make(map[dlp.Classification]struct{}, len(classes))
	for _, c := range classes {
		set[c] = struct{}{}
	}
	return RedactionProfile{Ref: ref, Revision: revision, classes: set, Mandatory: mandatory}
}

// Profile is an immutable, capability-local inspection profile. Gateway and
// Management get SEPARATE Profile values with independent limits, destination
// policy, resolver, dispositions, redaction profiles and revision — nothing
// mutable is shared, so one capability can never mutate or exhaust the other.
type Profile struct {
	capability             string
	lim                    limits.InspectionLimits
	destPolicy             destination.Policy
	extraction             destination.ExtractionRules
	resolver               destination.Resolver // optional; nil ⇒ literal-only classification
	dispositions           map[dlp.Classification]Disposition
	injectionBlockSeverity dlp.Severity
	redactionProfiles      map[string]RedactionProfile
	revision               uint64
	pinTTL                 time.Duration
	allowTextTruncation    bool
}

// ProfileConfig is the mutable input to NewProfile.
type ProfileConfig struct {
	Capability             string
	Limits                 limits.InspectionLimits
	DestPolicy             destination.Policy
	Extraction             destination.ExtractionRules
	Resolver               destination.Resolver
	Dispositions           map[dlp.Classification]Disposition // nil ⇒ safe defaults
	InjectionBlockSeverity dlp.Severity                       // SevUnset ⇒ injection is labeled, never hard-blocked
	RedactionProfiles      []RedactionProfile
	Revision               uint64
	PinTTL                 time.Duration
	AllowTextTruncation    bool
}

// defaultDispositions is the safe default classification→disposition policy:
// secrets/private-keys block, financial redacts, PII labels, oversized blocks.
func defaultDispositions() map[dlp.Classification]Disposition {
	return map[dlp.Classification]Disposition{
		dlp.ClassCredentialSecret:  DispBlock,
		dlp.ClassPrivateKey:        DispBlock,
		dlp.ClassBearerToken:       DispBlock,
		dlp.ClassPasswordOrAPIKey:  DispBlock,
		dlp.ClassSourceCodeSecret:  DispBlock,
		dlp.ClassFinancial:         DispRedact,
		dlp.ClassPII:               DispLabel,
		dlp.ClassInternalOnly:      DispLabel,
		dlp.ClassPossibleInjection: DispLabel,
		dlp.ClassOversizedUnknown:  DispBlock,
	}
}

// NewProfile validates cfg and returns an immutable Profile.
func NewProfile(cfg ProfileConfig) (Profile, error) {
	if cfg.Capability == "" {
		return Profile{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "inspection.profile", "missing capability")
	}
	if cfg.Revision == 0 {
		return Profile{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "inspection.profile", "missing revision")
	}
	disp := cfg.Dispositions
	if disp == nil {
		disp = defaultDispositions()
	} else {
		// Copy so the caller cannot mutate the profile's map after construction.
		cp := make(map[dlp.Classification]Disposition, len(disp))
		for k, v := range disp {
			cp[k] = v
		}
		disp = cp
	}
	rp := make(map[string]RedactionProfile, len(cfg.RedactionProfiles))
	for _, r := range cfg.RedactionProfiles {
		if r.Ref == "" {
			return Profile{}, mcperr.New(mcperr.ReasonListenerConfigInvalid, "inspection.profile", "redaction profile requires a ref")
		}
		rp[r.Ref] = r
	}
	ttl := cfg.PinTTL
	if ttl <= 0 {
		ttl = 30 * time.Second
	}
	return Profile{
		capability:             cfg.Capability,
		lim:                    cfg.Limits,
		destPolicy:             cfg.DestPolicy,
		extraction:             cfg.Extraction,
		resolver:               cfg.Resolver,
		dispositions:           disp,
		injectionBlockSeverity: cfg.InjectionBlockSeverity,
		redactionProfiles:      rp,
		revision:               cfg.Revision,
		pinTTL:                 ttl,
		allowTextTruncation:    cfg.AllowTextTruncation,
	}, nil
}

// argBounds derives the canonical decode bounds for a tool-call argument value
// from the profile's inspection limits (bounds authority stays in the profile).
func (p Profile) argBounds() canonical.Bounds {
	return canonical.Bounds{
		MaxBytes:         p.lim.MaxTotalScanBytes(),
		MaxDepth:         64,
		MaxObjectMembers: p.lim.MaxArgNodes(),
		MaxArrayElements: p.lim.MaxArgNodes(),
		MaxStringBytes:   p.lim.MaxBytesPerString(),
	}
}

// DecodeArgs performs the SINGLE strict decode of a tool-call arguments value under
// the profile's bounds, returning the canonical tree the inspector operates on. A
// nil/empty input yields a nil node (no arguments). It reuses canonical.Decode —
// the one strict decode path — so there is no second, differently-behaving parser.
func (p Profile) DecodeArgs(raw []byte) (*canonical.Node, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	return canonical.Decode(raw, p.argBounds())
}

// CompileSchema compiles a tool schema node under the profile's inspection limits.
// A caller uses the returned *schema.Compiled both to validate arguments and to
// re-validate a redaction transform.
func (p Profile) CompileSchema(node *canonical.Node) (*schema.Compiled, error) {
	return schema.Compile(node, p.lim)
}

// disposition returns the profile disposition for a classification, failing closed
// (DispBlock) for any unmapped class.
func (p Profile) disposition(c dlp.Classification) Disposition {
	if d, ok := p.dispositions[c]; ok {
		return d
	}
	return DispBlock
}

// Capability returns the profile's capability label.
func (p Profile) Capability() string { return p.capability }

// Revision returns the inspection revision.
func (p Profile) Revision() uint64 { return p.revision }

// MaxOutputBytes exposes the response-inspection output-size bound. A zero value means the profile
// carries no usable inspection limits (a zero-value or limits-less profile): every non-empty upstream
// response would then exceed the bound and be reported oversized AFTER the irreversible call, so a
// composition that requires real response DLP must reject such a profile.
func (p Profile) MaxOutputBytes() int { return p.lim.MaxOutputBytes() }

// RedactionProfile looks up an immutable redaction profile by ref.
func (p Profile) RedactionProfile(ref string) (profile RedactionProfile, ok bool) {
	rp, ok := p.redactionProfiles[ref]
	return rp, ok
}

// DefaultGatewayProfile returns a validated Gateway inspection profile: Gateway
// inspection limits, https-only destination policy, an empty extraction rule set
// (explicit rules are supplied per operation), no resolver (literal-only
// classification in the decision-only default path), safe dispositions, and
// injection LABELED (not hard-blocked) by default.
func DefaultGatewayProfile(rev uint64) Profile {
	rules, _ := destination.CompileRules(nil, true, limits.DefaultGatewayInspection())
	p, err := NewProfile(ProfileConfig{
		Capability: "gateway",
		Limits:     limits.DefaultGatewayInspection(),
		DestPolicy: destination.DefaultGatewayPolicy(),
		Extraction: rules,
		Revision:   rev,
	})
	if err != nil {
		panic("inspection: gateway default profile invalid: " + err.Error())
	}
	return p
}

// DefaultManagementProfile returns a validated Management inspection profile. It
// carries NO resolver and NO extraction rules — Management inspection never
// resolves Gateway destinations or treats a Management operation as a business
// tool — and uses the independent Management inspection limits.
func DefaultManagementProfile(rev uint64) Profile {
	empty, _ := destination.CompileRules(nil, false, limits.DefaultManagementInspection())
	p, err := NewProfile(ProfileConfig{
		Capability: "management",
		Limits:     limits.DefaultManagementInspection(),
		DestPolicy: destination.DefaultGatewayPolicy(), // unused (no resolver, no extraction)
		Extraction: empty,
		Revision:   rev,
	})
	if err != nil {
		panic("inspection: management default profile invalid: " + err.Error())
	}
	return p
}
