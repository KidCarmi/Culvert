package rollout

import "github.com/KidCarmi/Culvert/internal/mcp/mcperr"

// SignedConfig is the distributable, capability-local rollout configuration that
// rides INSIDE a PR-10 cpdp signed snapshot payload (GatewayPayload /
// ManagementPayload). It is fully JSON-serializable and map-free so it is covered
// by the snapshot content hash and signature with no extra plumbing. It carries
// ONLY reviewed decision state (mode + scope + connector mode) — never a secret,
// token, credential, or raw request/response.
//
// Presence semantics on the wire: a nil *SignedConfig on a payload means "no
// rollout change — keep local rollout state" (an older/rolled-back CP that
// predates rollout never wipes a DP's mode). An intended change is an explicit
// non-nil config at a new scope revision.
type SignedConfig struct {
	// SelectorSchema is the scope selector-schema version the CP built this under. A
	// DP that supports a LOWER schema rejects the whole config (fail closed) rather
	// than silently under-matching an unknown selector.
	SelectorSchema int `json:"selector_schema"`
	// Capability MUST match the payload's capability (Gateway/Management isolation).
	Capability Capability `json:"capability"`
	// Mode is the published mode for this capability.
	Mode Mode `json:"mode"`
	// Scope is the serializable rollout scope spec (recompiled + revalidated on the
	// DP). Empty ⇒ matches nothing (the safe default).
	Scope ScopeSpec `json:"scope"`
	// ScopeRevision is the monotonic revision of the scope (a scope change — including
	// a percentage change — is a new revision).
	ScopeRevision uint64 `json:"scope_revision"`
	// ShadowScope is the OPTIONAL Shadow-scope fallback used only when Mode is
	// Canary/Production: a subject outside the Canary scope but inside this Shadow
	// scope retains Shadow behavior (never fleet-wide enforcement). Empty ⇒ Observe
	// behavior outside the Canary scope. Ignored when Mode is Shadow (Scope is the
	// shadow scope then).
	ShadowScope ScopeSpec `json:"shadow_scope,omitempty"`
	// ShadowScopeRevision is the revision of ShadowScope.
	ShadowScopeRevision uint64 `json:"shadow_scope_revision,omitempty"`
	// ConnectorMode is Gateway-only; it MUST be "local-client" (Model A). Ignored for
	// Management (which is inbound-only and has no connector topology).
	ConnectorMode string `json:"connector_mode,omitempty"`
}

// Validate checks the config is well-formed and safe to apply: a supported
// selector schema, a valid mode, a matching capability, an accepted connector mode
// (Gateway), and a compilable scope. It is pure and fails closed.
func (c SignedConfig) Validate(capability Capability, lim Limits) error {
	if !SupportsSelectorSchema(c.SelectorSchema) {
		return mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.config", "unsupported selector schema (fail closed)")
	}
	if c.Capability != capability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "rollout.config", "config capability mismatch")
	}
	if !c.Mode.Valid() {
		return mcperr.New(mcperr.ReasonRolloutModeInvalid, "rollout.config", "invalid mode")
	}
	if c.Scope.Capability != capability {
		return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "rollout.config", "scope capability mismatch")
	}
	if capability == CapabilityGateway {
		if err := ValidateConnectorMode(c.ConnectorMode); err != nil {
			return err
		}
	} else if c.ConnectorMode != "" {
		// Management has no connector topology; a non-empty value is a config error.
		return mcperr.New(mcperr.ReasonRolloutConnectorModeRejected, "rollout.config", "management has no connector mode")
	}
	if _, err := c.CompileScope(lim); err != nil {
		return err
	}
	if c.hasShadowScope() {
		if c.ShadowScope.Capability != capability {
			return mcperr.New(mcperr.ReasonSnapshotCapabilityMismatch, "rollout.config", "shadow scope capability mismatch")
		}
		if _, err := c.CompileShadowScope(lim); err != nil {
			return err
		}
	}
	// Shadow, Canary and Production all require an ENUMERABLE scope — one with concrete
	// inclusion selectors, not a pure-percentage "N% of everything" and not empty. For
	// Canary/Production this bounds enforcement; for Shadow it is the "no scope = no
	// Shadow" contract (SHADOW-ACTIVATION.md §5): an empty or percentage-only Shadow scope
	// used to validate and then silently behave as Observe (matches nothing), so a
	// mis-scoped activation looked accepted while shadowing nothing — and, worse, a future
	// widening could not be reasoned about from "the scope is empty". Requiring an
	// enumerable scope makes a Shadow activation name the exact bounded target it evaluates
	// and makes "missing scope shadows everything" structurally impossible (the empty scope
	// matches nothing AND the config is now rejected fail-closed at validation).
	if c.Mode == ModeShadow || c.Mode == ModeCanary || c.Mode == ModeProduction {
		sc, _ := c.CompileScope(lim)
		if !sc.Enumerable() {
			return mcperr.New(mcperr.ReasonRolloutScopeInvalid, "rollout.config", "shadow/canary/production requires an enumerable scope (no empty or percentage-only scope)")
		}
	}
	return nil
}

// hasShadowScope reports whether a non-empty shadow-scope fallback is configured.
func (c SignedConfig) hasShadowScope() bool {
	s := c.ShadowScope
	return len(s.Tenants)+len(s.Servers)+len(s.ToolFingerprints)+len(s.Tools)+len(s.Principals)+
		len(s.Agents)+len(s.Clients)+len(s.Groups)+len(s.Environments) > 0 || s.Percent > 0
}

// CompileScope compiles the embedded scope spec into an immutable Scope at the
// config's scope revision.
func (c SignedConfig) CompileScope(lim Limits) (Scope, error) {
	return Compile(c.Scope, c.ScopeRevision, lim)
}

// CompileShadowScope compiles the optional shadow-scope fallback. Returns an empty
// scope (matches nothing) when no shadow scope is configured.
func (c SignedConfig) CompileShadowScope(lim Limits) (Scope, error) {
	if !c.hasShadowScope() {
		return EmptyScope(c.Capability), nil
	}
	return Compile(c.ShadowScope, c.ShadowScopeRevision, lim)
}

// ScopeHash returns the deterministic content hash of the compiled scope, or ""
// if the scope does not compile.
func (c SignedConfig) ScopeHash(lim Limits) string {
	sc, err := c.CompileScope(lim)
	if err != nil {
		return ""
	}
	return sc.Hash()
}

// DisabledConfig returns the safe-default config for a capability: Disabled mode,
// empty scope, local-client connector (Gateway).
func DisabledConfig(capability Capability) SignedConfig {
	c := SignedConfig{
		SelectorSchema: selectorSchema,
		Capability:     capability,
		Mode:           ModeDisabled,
		Scope:          ScopeSpec{Capability: capability},
		ScopeRevision:  0,
	}
	if capability == CapabilityGateway {
		c.ConnectorMode = ConnectorLocalClient
	}
	return c
}
