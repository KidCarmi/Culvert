package main

// QUAL-1 — loader half of the MCP Gateway "Observe" startup slice. It consumes the
// pure DTO from resolveMCPObserveStartupConfig and performs the side-effecting
// composition: resolve TLS material through the existing controlplane_tls loaders,
// build the PR-3 OAuth resource-validation config + a static trusted-key resolver,
// build the RFC 9728 Protected Resource Metadata, and assemble a disabled-by-default
// mcpruntime.Config for the Gateway capability ONLY, in Observe posture.
//
// It composes NO executor, NO upstream client, NO credential broker, NO event
// manager, NO publication coordinator, and NO Management listener — so a bound
// listener can parse, identify, authenticate and record, but can never execute an
// upstream tool call. Every failure on the enable path is fail-closed: the runtime
// config is left empty (nothing binds) and a bounded, secret-free classification is
// returned for the health surface; the Secure Web Gateway path is never affected.

import (
	"context"
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/canonical"
	"github.com/KidCarmi/Culvert/internal/mcp/catalog"
	"github.com/KidCarmi/Culvert/internal/mcp/identity"
	"github.com/KidCarmi/Culvert/internal/mcp/jose"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
	"github.com/KidCarmi/Culvert/internal/mcp/registry"
	"github.com/KidCarmi/Culvert/internal/mcp/rollout"
	mcpruntime "github.com/KidCarmi/Culvert/internal/mcp/runtime"
	"github.com/KidCarmi/Culvert/internal/mcp/senderconstraint"
)

// mcpObserveState classifies the Gateway observe listener's activation outcome. It
// is the authoritative, node-local truth the health surface reflects — distinct
// from the live listener Phase, which the runtime reports once it is bound.
type mcpObserveState string

const (
	// mcpObserveDisabled — the default: the operator did not enable the listener.
	mcpObserveDisabled mcpObserveState = "disabled"
	// mcpObserveInvalid — enablement was REQUESTED but the security configuration is
	// incomplete/invalid, so nothing was bound (fail closed).
	mcpObserveInvalid mcpObserveState = "invalid"
	// mcpObserveConfigured — a complete, valid config; the runtime should bind it.
	mcpObserveConfigured mcpObserveState = "configured"
)

// mcpObserveActivation is the bounded, secret-free activation summary surfaced to
// the admin health API. It carries only safe metadata: never a key, token, cert,
// tenant, or raw error/path.
type mcpObserveActivation struct {
	State           mcpObserveState
	EnableRequested bool
	Reason          string // fixed classification code (never raw error text or a path)
	BindAddress     string
	Port            int
	ClientCertMode  string
	SenderProfile   string
	ProtocolVersion string
	CanonicalURL    string // the advertised canonical resource (public, non-secret)
	MetadataURL     string // the RFC 9728 metadata URL (public, non-secret)
	TrustedKeyCount int
}

// composeGatewayTelemetry builds the QUAL-3 durable telemetry plane and returns the
// runtime EventProvider to inject into Deps. Disabled ⇒ (nil, not_configured, nil, nil)
// so the caller keeps QUAL-2 behavior; enabled-but-invalid ⇒ (nil, invalid, nil, err)
// so the caller fails activation closed. Returning the concrete *events.Manager as the
// provider only when non-nil avoids the nil-interface trap.
func composeGatewayTelemetry(tc mcpTelemetryStartupConfig) (*telemetryRuntime, mcpTelemetryState, mcpruntime.EventProvider, error) {
	tel, telState, err := buildMCPTelemetry(tc)
	if err != nil {
		return nil, mcpTelemInvalid, nil, err
	}
	var ev mcpruntime.EventProvider
	if tel != nil {
		ev = tel.Manager()
	}
	return tel, telState, ev, nil
}

// loadMCPObserveRuntime builds the runtime config + activation summary from the
// resolved startup config. A disabled config returns an empty runtime config
// (byte-identical disabled-by-default behavior). An enabled-but-invalid config
// returns an empty runtime config plus an mcpObserveInvalid summary so the caller
// binds nothing and the health surface reports the truthful reason.
func loadMCPObserveRuntime(sc mcpObserveStartupConfig) (mcpruntime.Config, mcpObserveActivation) {
	if !sc.Enabled {
		publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
		publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
		_ = publishMCPPolicy(mcpPolNotConfigured, "", nil)
		return mcpruntime.Config{}, mcpObserveActivation{State: mcpObserveDisabled}
	}
	// Reset the node-local inventory + telemetry + policy holders until this
	// activation succeeds, so a failed enable never leaves a stale fleet/telemetry/
	// policy runtime visible to the Admin API.
	publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
	publishMCPTelemetry(mcpTelemNotConfigured, "", nil)
	_ = publishMCPPolicy(mcpPolNotConfigured, "", nil)
	act := mcpObserveActivation{
		State: mcpObserveInvalid, EnableRequested: true,
		BindAddress: sc.BindAddress, Port: sc.Port, ClientCertMode: sc.ClientCertMode,
		SenderProfile: sc.SenderConstraint, ProtocolVersion: sc.ProtocolVersion,
	}
	invalid := func(reason string, err error) (mcpruntime.Config, mcpObserveActivation) {
		act.Reason = reason
		if err != nil {
			logger.Printf("MCP gateway observe listener not activated (%s): %v", reason, sanitizeLog(err.Error()))
		} else {
			logger.Printf("MCP gateway observe listener not activated (%s)", reason)
		}
		return mcpruntime.Config{}, act
	}

	// Model A only — an outbound-connector / dmz-endpoint mode is rejected before any
	// resource is touched (reuses the authoritative rollout validator).
	if err := rollout.ValidateConnectorMode(sc.ConnectorMode); err != nil {
		return invalid("connector_mode_rejected", err)
	}
	protoVer, err := resolveGatewayProtocol(sc.ProtocolVersion)
	if err != nil {
		return invalid("protocol_version_unsupported", nil)
	}
	act.ProtocolVersion = string(protoVer)

	modes, reason, err := resolveGatewayModes(sc)
	if err != nil {
		return invalid(reason, err)
	}

	// RFC 9728 metadata — also normalizes the canonical resource (the exact token
	// audience) so the advertised resource and the validator agree byte-for-byte.
	meta, err := mcpruntime.NewProtectedResourceMetadata(sc.CanonicalResource, sc.TrustedIssuers, sc.ResourceName)
	if err != nil {
		return invalid("canonical_resource_invalid", err)
	}
	act.CanonicalURL, act.MetadataURL = meta.Resource, meta.MetadataURL

	authCfg, err := buildGatewayAuthConfig(sc, modes, meta.Resource)
	if err != nil {
		return invalid("auth_config_invalid", err)
	}

	// Trusted verification keys (static, operator-supplied — authn does no JWKS
	// fetch). At least one key is required so a token can actually validate; a JWKS
	// carrying private material is rejected by jose.ParsePublicJWK.
	keys, keyCount, err := mcpLoadTrustedKeys(sc.TrustedJWKSFile, sc.TrustedIssuers)
	if err != nil {
		return invalid("trusted_keys_invalid", err)
	}
	if keyCount == 0 {
		return invalid("no_trusted_keys", nil)
	}
	act.TrustedKeyCount = keyCount

	tlsCfg, err := mcpBuildServerTLS(sc.TLSCertFile, sc.TLSKeyFile, sc.ClientCAFile, modes.certMode)
	if err != nil {
		return invalid("tls_material_unavailable", err)
	}

	// QUAL-2: resolve the static qualification inventory (empty when no file) and
	// fail activation closed on a present-but-invalid file — nothing binds and no
	// partially-seeded fleet is ever published.
	reg, cat, invState, err := loadQualificationInventory(sc)
	if err != nil {
		publishMCPInventory(mcpInvInvalid, "qualification_inventory_invalid", nil, nil)
		return invalid("qualification_inventory_invalid", err)
	}

	// QUAL-3: compose the durable telemetry plane (KEK + encrypted spool + archive
	// exporter). Disabled ⇒ nil manager (QUAL-2 behavior). An enabled-but-invalid block
	// fails activation closed — nothing binds, no partial manager/exporter, no fallback.
	tel, telState, ev, terr := composeGatewayTelemetry(sc.Telemetry)
	if terr != nil {
		publishMCPTelemetry(mcpTelemInvalid, "qualification_telemetry_invalid", nil)
		return invalid("qualification_telemetry_invalid", terr)
	}

	// QUAL-4: compile the node-local Gateway policy source (if any). Disabled/absent ⇒
	// nil provider (Deps.Policy stays nil ⇒ decision-point path is observe-only and
	// decision telemetry stays pending-policy). A present-but-invalid source fails
	// activation closed — nothing binds and no partial snapshot is ever published.
	polSnap, polProvider, polState, polReason, perr := composeGatewayPolicy(sc)
	if perr != nil {
		_ = publishMCPPolicy(mcpPolInvalid, polReason, nil)
		_ = tel.Close(context.Background()) // nil-safe; release the opened spool/exporter
		return invalid("qualification_policy_invalid", perr)
	}

	cfg := assembleGatewayConfig(sc, modes, tlsCfg, authCfg, meta, keys, reg, cat, ev, polProvider)
	// Classify the transactional runtime validation (bind/port/wildcard/TLS/hosts) as
	// an activation outcome rather than a hard failure, so an invalid listener config
	// fails closed to "invalid" instead of aborting startup.
	if err := cfg.Validate(); err != nil {
		// tel.Close is nil-safe (nil receiver ⇒ no-op); closing the opened
		// spool/exporter so an invalid listener leaks nothing. Policy stays reset to
		// not_configured (never published), so no snapshot is left active.
		_ = tel.Close(context.Background())
		return invalid("listener_config_invalid", err)
	}
	// Publish the compiled policy snapshot into the shared store FIRST (the single
	// source of truth for the runtime evaluator, the /api/mcp/policy active read, the
	// simulator Compare baseline, and the decision-evidence snapshot hash). For a fresh
	// store + a validated Gateway snapshot this cannot fail; treat any error as
	// fail-closed (nothing binds; inventory/telemetry stay reset to not_configured).
	if err := publishMCPPolicy(polState, polReason, polSnap); err != nil {
		_ = tel.Close(context.Background())
		return invalid("qualification_policy_invalid", err)
	}
	// Controlled Shadow activation (SHADOW-ACTIVATION.md §4): when the operator has
	// explicitly opted this node into Shadow readiness, compose the NON-EXECUTING Shadow
	// evaluator and inject it as Deps.Executor. It holds no upstream client and no
	// materialize-capable broker, so the Gateway can EVALUATE an in-scope Shadow request
	// (formal ShadowDecision + durable evidence) while remaining structurally incapable
	// of an upstream side effect. Disabled by default: with CULVERT_MCP_SHADOW_READY
	// unset the executor is nil and the runtime keeps its byte-identical Observe path.
	// A record-only disposition (out-of-scope / Observe mode) still runs the runtime's
	// inline Observe evidence path (see runtime.ExecutionProvider.RecordsOnly), so
	// composing the evaluator never drops decision evidence for traffic it does not
	// evaluate. It requires the durable events manager (tel.Manager()); fail-closed to a
	// nil executor otherwise. Metrics are the bounded Shadow sink (nil ⇒ no-op).
	composeGatewayShadowIntoConfig(&cfg, mcpShadowReadyEnabled(), tel.Manager())
	// Controlled LIVE production dependency composition (§3/§4): when the operator has
	// explicitly opted this node into the live-tier dependency graph
	// (CULVERT_MCP_LIVE_DEPS), compose the REAL upstream/broker/durable-events/response-DLP
	// graph and install the guarded live executor via the same composition seam. Disabled by
	// default: unset ⇒ nothing composed and the Shadow/Observe executor above is untouched
	// (byte-identical). It NEVER arms — arming is a separate, node-readiness-gated act. When
	// both this and Shadow are enabled the live executor supersedes the Shadow one (it embeds
	// its own capability-reduced Shadow evaluator, so no Shadow evaluation is lost). Requires
	// the durable events manager (tel.Manager()); fail-closed to "not composed" otherwise. The
	// env is read HERE (the shim) and passed to the pure resolver, so the resolver stays pure.
	composeProductionGatewayLiveTier(
		&cfg,
		resolveMCPLiveProductionConfig(os.Getenv(mcpLiveDepsEnvVar), os.Getenv(mcpLiveCredentialKEKEnvVar)),
		reg, cat, tel.Manager(),
	)
	// Publish the seeded inventory + telemetry as the single sources of truth ONLY
	// after the whole activation is valid, so the Admin API and runtime observe the
	// identical instances.
	publishMCPInventory(invState, "", reg, cat)
	publishMCPTelemetry(telState, "", tel)
	act.State = mcpObserveConfigured
	return cfg, act
}

// assembleGatewayConfig builds the disabled-nowhere Gateway runtime config from the
// resolved pieces. Deps carry the read paths (trusted keys, read-only
// registry/catalog, DPoP replay cache when required), the QUAL-3 event provider, and
// the QUAL-4 policy provider — but NO executor, upstream client, credential broker, or
// inspection provider, so a decision-point method is EVALUATED (and its true decision
// recorded) while the effective runtime stays Observe-only and can never execute an
// upstream tool call.
func assembleGatewayConfig(sc mcpObserveStartupConfig, modes gatewayModes, tlsCfg *tls.Config, authCfg authn.CapabilityAuthConfig, meta *mcpruntime.ProtectedResourceMetadata, keys authn.KeyResolver, reg *registry.Registry, cat *catalog.Catalog, ev mcpruntime.EventProvider, pol mcpruntime.PolicyProvider) mcpruntime.Config {
	canaryBreach, canaryGeneration := gatewayCanarySeams()
	deps := mcpruntime.Deps{
		Keys:     keys,
		Registry: reg, // QUAL-2: shared read-only inventory (empty when no qualification file)
		Catalog:  cat, // the SAME instances back the MCP Servers/Tools Admin API
		// QUAL-3: the durable event manager (nil unless telemetry is composed). When set,
		// denial-lane events commit on live requests, and (with QUAL-4 policy composed) an
		// ALLOW-class decision durably commits a full decision event before the
		// still-not-implemented response.
		Events: ev,
		// QUAL-4: the node-local Gateway policy provider (nil unless a policy source is
		// composed). When set, decision-point methods are EVALUATED against the shared
		// snapshot and the true result recorded; the evaluated action is NOT execution
		// authorization — with no executor an ALLOW returns execution_state=not_implemented
		// and no credential/upstream/broker/side-effect runs. Still Observe-only.
		Policy: pol,
		// Blocker 7: the pipeline refuses a drifted decision BEFORE the executor is reached, and
		// that refusal is an authoritative whole-Canary breach as much as the one the admission
		// gate reports. The funnel is generation-strict and capability-scoped, and it trips nothing
		// when no activation is running — so on an Observe-only node (the default posture) this
		// wire is inert (Codex round 14).
		//
		// ONE funnel serves both seams, and the breach seam is the ORDINARY generation-bound
		// Breach — the same authority the admission and settle paths use, which discards a stale
		// generation under the same lock that latches. The pipeline snapshots the generation via
		// Generation at its single rollout-resolution point and carries it here, so a request that
		// outlived its activation cannot stop the next one (Codex round 16).
		CanaryBreach:     canaryBreach,
		CanaryGeneration: canaryGeneration,
	}
	if modes.senderProfile.RequiresDPoP() {
		deps.Replay = senderconstraint.NewReplayCache(limits.DefaultAuth(), nil)
	}
	return mcpruntime.Config{
		Gateway: mcpruntime.ListenerConfig{
			Enabled:        true,
			Capability:     protocol.Gateway,
			BindAddress:    sc.BindAddress,
			Port:           sc.Port,
			TLS:            tlsCfg,
			ClientCertMode: modes.certMode,
			AllowedHosts:   sc.AllowedHosts,
			AllowedOrigins: sc.AllowedOrigins,
			RequireOrigin:  sc.RequireOrigin,
			AuthConfig:     authCfg,
			Limits:         mcpruntime.DefaultLimits(),
			Metadata:       meta,
		},
		Deps: deps,
	}
}

// gatewayModes bundles the resolved security-mode enums for the listener.
type gatewayModes struct {
	certMode      mcpruntime.ClientCertMode
	senderProfile senderconstraint.Profile
	assurance     identity.AssuranceLevel
}

// resolveGatewayProtocol resolves the protocol-version policy: an explicitly
// configured version must be in the frozen supported allowlist; empty ⇒ primary.
func resolveGatewayProtocol(v string) (protocol.Version, error) {
	if v == "" {
		return protocol.VersionPrimary, nil
	}
	pv := protocol.Version(v)
	if !protocol.IsSupported(pv) {
		return "", errMCPConfig("unsupported protocol version")
	}
	return pv, nil
}

// resolveGatewayModes resolves the client-cert / sender-constraint / assurance
// enums, returning a bounded classification code on the first unknown value.
func resolveGatewayModes(sc mcpObserveStartupConfig) (gatewayModes, string, error) {
	certMode, err := mcpResolveClientCertMode(sc.ClientCertMode)
	if err != nil {
		return gatewayModes{}, "client_cert_mode_invalid", err
	}
	senderProfile, err := mcpResolveSenderProfile(sc.SenderConstraint)
	if err != nil {
		return gatewayModes{}, "sender_constraint_invalid", err
	}
	assurance, err := mcpResolveAssurance(sc.MinAssurance)
	if err != nil {
		return gatewayModes{}, "min_assurance_invalid", err
	}
	return gatewayModes{certMode: certMode, senderProfile: senderProfile, assurance: assurance}, "", nil
}

// buildGatewayAuthConfig assembles the PR-3 OAuth resource-validation config. It
// filters empty-string entries from the issuer/client-id/scope lists FIRST, so a
// value like `required_scopes: [""]` (which NewCapabilityConfig's length check
// would otherwise admit while dropping the empty string, leaving no effective
// required scope) fails closed here instead of silently disabling scope enforcement.
func buildGatewayAuthConfig(sc mcpObserveStartupConfig, m gatewayModes, canonicalResource string) (authn.CapabilityAuthConfig, error) {
	requiredScopes := nonEmptyStrings(sc.RequiredScopes)
	if len(requiredScopes) == 0 {
		return authn.CapabilityAuthConfig{}, errMCPConfig("at least one non-empty required scope is required")
	}
	return authn.NewCapabilityConfig(authn.CapabilityConfigInput{
		Capability:        protocol.Gateway,
		TrustedIssuers:    nonEmptyStrings(sc.TrustedIssuers),
		AcceptedClientIDs: nonEmptyStrings(sc.AcceptedClientIDs),
		CanonicalResource: canonicalResource,
		RequiredScopes:    requiredScopes,
		AllowedScopes:     nonEmptyStrings(sc.AllowedScopes),
		SenderProfile:     m.senderProfile,
		MinAssurance:      m.assurance,
		Limits:            limits.DefaultAuth(),
	})
}

// nonEmptyStrings returns the input with empty strings removed (nil-safe).
func nonEmptyStrings(xs []string) []string {
	var out []string
	for _, x := range xs {
		if x != "" {
			out = append(out, x)
		}
	}
	return out
}

// mcpResolveClientCertMode maps the config string to the runtime mode. The blank
// default is resolved earlier to "require"; an unknown value fails closed.
func mcpResolveClientCertMode(s string) (mcpruntime.ClientCertMode, error) {
	switch s {
	case "require":
		return mcpruntime.ClientCertRequire, nil
	case "request":
		return mcpruntime.ClientCertRequest, nil
	case "none":
		return mcpruntime.ClientCertNone, nil
	default:
		return mcpruntime.ClientCertNone, errMCPConfig("unknown client_cert_mode")
	}
}

// mcpResolveSenderProfile maps the config string to a sender-constraint profile.
// The zero (unset) profile is never producible here — an unknown value fails closed.
func mcpResolveSenderProfile(s string) (senderconstraint.Profile, error) {
	switch s {
	case "mtls":
		return senderconstraint.MTLSRequired, nil
	case "dpop":
		return senderconstraint.DPoPRequired, nil
	case "mtls-or-dpop", "dpop-or-mtls":
		return senderconstraint.DPoPOrMTLSRequired, nil
	case "bearer":
		return senderconstraint.BearerControlled, nil
	default:
		return senderconstraint.ProfileUnset, errMCPConfig("unknown sender_constraint")
	}
}

// mcpResolveAssurance maps the config string to an assurance level.
func mcpResolveAssurance(s string) (identity.AssuranceLevel, error) {
	switch s {
	case "low":
		return identity.AssuranceLow, nil
	case "medium":
		return identity.AssuranceMedium, nil
	case "high":
		return identity.AssuranceHigh, nil
	default:
		return identity.AssuranceUnknown, errMCPConfig("unknown min_assurance")
	}
}

// mcpBuildServerTLS resolves the server certificate/key and (for a require-cert
// listener) the client-CA trust pool into an HTTP server *tls.Config. It reuses the
// existing controlplane loaders (tls.LoadX509KeyPair via the traversal-safe path,
// loadCertPool for the CA bundle) and never sets InsecureSkipVerify. The runtime
// sets ClientAuth from the resolved mode when it clones this config.
func mcpBuildServerTLS(certFile, keyFile, caFile string, mode mcpruntime.ClientCertMode) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, errMCPConfig("tls cert and key are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	// mTLS (require or request) needs a client-CA pool to verify presented certs. A
	// require-cert listener without a CA bundle fails closed.
	if mode == mcpruntime.ClientCertRequire || mode == mcpruntime.ClientCertRequest {
		if caFile == "" {
			return nil, errMCPConfig("client certificate mode requires a client CA bundle")
		}
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		cfg.ClientCAs = pool
	}
	return cfg, nil
}

// mcpLoadTrustedKeys parses a static JWKS document (PUBLIC keys only) and registers
// each key under every trusted issuer in an in-memory resolver. A missing/blank
// file yields zero keys (the caller treats that as a fail-closed activation error).
// jose.ParsePublicJWK rejects any key carrying private material.
func mcpLoadTrustedKeys(jwksFile string, issuers []string) (*authn.StaticKeyResolver, int, error) {
	resolver := authn.NewStaticKeyResolver()
	if jwksFile == "" {
		return resolver, 0, nil
	}
	raw, err := readFileClean(jwksFile)
	if err != nil {
		return nil, 0, err
	}
	node, err := canonical.Decode(raw, canonical.Bounds{
		MaxBytes: 1 << 20, MaxDepth: 12, MaxObjectMembers: 64, MaxArrayElements: 64, MaxStringBytes: 16384,
	})
	if err != nil {
		return nil, 0, err
	}
	keysNode, ok := node.Get("keys")
	if !ok || keysNode.Kind != canonical.KindArray {
		return nil, 0, errMCPConfig("jwks has no keys array")
	}
	count := 0
	for _, jwk := range keysNode.Arr {
		pub, err := jose.ParsePublicJWK(jwk)
		if err != nil {
			return nil, 0, err // includes rejection of private-key material
		}
		kidNode, _ := jwk.Get("kid")
		kid := ""
		if kidNode != nil && kidNode.Kind == canonical.KindString {
			kid = kidNode.Str
		}
		// Count a key only when it is actually registered under at least one non-empty
		// trusted issuer. A trusted_issuers list of only empty strings therefore yields
		// zero registered keys, so the caller's no_trusted_keys gate fires — the
		// listener never reports "ready" with keys that can validate nothing.
		registered := false
		for _, iss := range issuers {
			if iss == "" {
				continue
			}
			resolver.Add(iss, kid, pub)
			registered = true
		}
		if registered {
			count++
		}
	}
	return resolver, count, nil
}

// errMCPConfig builds a bounded configuration error. The message is a fixed,
// secret-free phrase (never a path or key); the health surface further reduces it
// to a stable classification code.
func errMCPConfig(msg string) error { return errors.New("mcp gateway config: " + msg) }

// readFileClean reads an operator-supplied startup-config file after rejecting a
// directory-traversal path (mirrors loadCertPool's guard).
func readFileClean(path string) ([]byte, error) {
	cleaned := filepath.Clean(path)
	if strings.Contains(cleaned, "..") {
		return nil, errMCPConfig("path traversal not allowed")
	}
	return os.ReadFile(cleaned) // #nosec G304 -- admin-provided startup-config path, ".." rejected above
}

// gatewayCanarySeams returns the two Canary seams the gateway pipeline is wired with: the breach
// reporter and the generation snapshot.
//
// It is a named function, and not two inline field assignments, so the wiring itself is testable.
// The pipeline seam is gated in internal/mcp/runtime, but that gate cannot see how the composition
// layer fills it in — and this is exactly a place where two paths reach one code and either can be
// broken alone (the M70 lesson). The invariant it exists to hold:
//
//   - ONE funnel serves both seams. Two funnels would be two objects that agree by construction
//     today and are free to disagree later, when the whole point is that the generation the
//     pipeline snapshots and the authority that latches on it are the same thing.
//   - The breach seam is the ORDINARY generation-bound Breach. It must FORWARD the generation it is
//     handed, never re-resolve one: a request that resolved under a since-demoted activation would
//     otherwise stop whatever replaced it (Codex round 16).
func gatewayCanarySeams() (breach func(capability string, gen uint64, code string), generation func(capability string) uint64) {
	f := newCanarySafetyFunnel(rollout.CapabilityGateway)
	return f.Breach, f.Generation
}
