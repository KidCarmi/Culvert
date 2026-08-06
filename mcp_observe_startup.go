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

// loadMCPObserveRuntime builds the runtime config + activation summary from the
// resolved startup config. A disabled config returns an empty runtime config
// (byte-identical disabled-by-default behavior). An enabled-but-invalid config
// returns an empty runtime config plus an mcpObserveInvalid summary so the caller
// binds nothing and the health surface reports the truthful reason.
func loadMCPObserveRuntime(sc mcpObserveStartupConfig) (mcpruntime.Config, mcpObserveActivation) {
	if !sc.Enabled {
		publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
		return mcpruntime.Config{}, mcpObserveActivation{State: mcpObserveDisabled}
	}
	// Reset the node-local inventory holder until this activation succeeds, so a
	// failed enable never leaves a stale "loaded" fleet visible to the Admin API.
	publishMCPInventory(mcpInvNotConfigured, "", nil, nil)
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

	cfg := assembleGatewayConfig(sc, modes, tlsCfg, authCfg, meta, keys, reg, cat)
	// Classify the transactional runtime validation (bind/port/wildcard/TLS/hosts) as
	// an activation outcome rather than a hard failure, so an invalid listener config
	// fails closed to "invalid" instead of aborting startup.
	if err := cfg.Validate(); err != nil {
		return invalid("listener_config_invalid", err)
	}
	// Publish the seeded inventory as the single source of truth ONLY after the whole
	// activation is valid, so the Admin API and runtime observe the identical pair.
	publishMCPInventory(invState, "", reg, cat)
	act.State = mcpObserveConfigured
	return cfg, act
}

// assembleGatewayConfig builds the disabled-nowhere Gateway runtime config from the
// resolved pieces. Deps deliberately carry ONLY the read paths (trusted keys, empty
// read-only registry/catalog, and a DPoP replay cache when required) — no executor,
// policy, inspection, or event provider, so the listener can never execute upstream.
func assembleGatewayConfig(sc mcpObserveStartupConfig, modes gatewayModes, tlsCfg *tls.Config, authCfg authn.CapabilityAuthConfig, meta *mcpruntime.ProtectedResourceMetadata, keys authn.KeyResolver, reg *registry.Registry, cat *catalog.Catalog) mcpruntime.Config {
	deps := mcpruntime.Deps{
		Keys:     keys,
		Registry: reg, // QUAL-2: shared read-only inventory (empty when no qualification file)
		Catalog:  cat, // the SAME instances back the MCP Servers/Tools Admin API
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
