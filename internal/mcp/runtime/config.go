package runtime

import (
	"crypto/tls"
	"net"
	"strconv"

	"github.com/KidCarmi/Culvert/internal/mcp/authn"
	"github.com/KidCarmi/Culvert/internal/mcp/limits"
	"github.com/KidCarmi/Culvert/internal/mcp/protocol"
)

// ClientCertMode is how a listener treats client certificates.
type ClientCertMode uint8

const (
	// ClientCertNone — no client certificate is requested.
	ClientCertNone ClientCertMode = iota
	// ClientCertRequest — request but do not require a client certificate.
	ClientCertRequest
	// ClientCertRequire — require and verify a client certificate (mTLS); the
	// canonical SHA-256 thumbprint is derived and passed to PR-3 as observed
	// binding metadata.
	ClientCertRequire
)

func (m ClientCertMode) tlsAuth() tls.ClientAuthType {
	switch m {
	case ClientCertRequest:
		return tls.VerifyClientCertIfGiven
	case ClientCertRequire:
		return tls.RequireAndVerifyClientCert
	default:
		return tls.NoClientCert
	}
}

// ListenerConfig is one capability's dedicated listener configuration. Management and
// Gateway each have their OWN ListenerConfig — nothing (socket, port, pool, session
// manager, auth config, resource, limits, queue, counters, observe partition) is
// shared between them.
type ListenerConfig struct {
	Enabled        bool
	Capability     protocol.Capability
	BindAddress    string // interface/IP to bind (e.g. "127.0.0.1"); empty ⇒ invalid unless AllowWildcard
	Port           int
	TLS            *tls.Config // caller-supplied server TLS config (certs already loaded); never mutated
	ClientCertMode ClientCertMode
	AllowedHosts   []string // Host/:authority allowlist (mandatory, non-empty when enabled)
	AllowedOrigins []string
	RequireOrigin  bool
	AuthConfig     authn.CapabilityAuthConfig // this capability's immutable PR-3 config
	Limits         Limits                     // this capability's immutable runtime bounds (listener/HTTP bounds)
	// SessionLimits are the PR-1 kernel session/wire bounds for this capability's
	// dedicated session.Manager (distinct from the listener HTTP bounds above). A
	// zero value (MaxSessions()==0) is resolved to the capability default at
	// construction so an operator need not restate the kernel bounds.
	SessionLimits limits.Limits
	// AllowWildcard permits a 0.0.0.0/:: bind. Off by default — a wildcard bind is
	// rejected unless explicitly allowed by the accepted config.
	AllowWildcard bool
	// AllowInsecure permits a non-TLS listener. It is a TEST/loopback seam only
	// (httptest supplies its own TLS); a non-test deployment requires TLS. It never
	// weakens an enabled TLS config and is documented as the ownership boundary for
	// the (later-slice) production TLS wiring.
	AllowInsecure bool
	// Metadata is the OPTIONAL published OAuth 2.0 Protected Resource Metadata (RFC
	// 9728) for this capability. When set, the listener serves the bounded PUBLIC
	// document at its well-known path and advertises it in the WWW-Authenticate
	// challenge on a 401. Nil ⇒ no metadata document and no challenge header (the
	// pre-QUAL-1 behavior, byte-identical). It never carries a secret — only the
	// public resource identifier and authorization-server issuer URLs.
	Metadata *ProtectedResourceMetadata
}

// Addr returns the host:port bind address.
func (c ListenerConfig) Addr() string {
	return net.JoinHostPort(c.BindAddress, strconv.Itoa(c.Port))
}

// sessionLimits resolves the kernel session bounds: the caller-supplied
// SessionLimits when set (a non-zero session cap proves it was constructed), else
// the per-capability default. It never returns a zero (unusable) limit set.
func (c ListenerConfig) sessionLimits() limits.Limits {
	if c.SessionLimits.MaxSessions() > 0 {
		return c.SessionLimits
	}
	if c.Capability == protocol.Management {
		return limits.DefaultManagement()
	}
	return limits.DefaultGateway()
}

// Config is the whole MCP runtime configuration: two independent listeners
// plus the shared IMMUTABLE libraries (registry/catalog/auth-deps) they read. The
// listeners never share mutable state.
type Config struct {
	Gateway    ListenerConfig
	Management ListenerConfig
	Deps       Deps
}

// Enabled reports whether ANY MCP listener is enabled. When false the runtime binds
// nothing and starts no goroutine (disabled-by-default).
func (c Config) Enabled() bool { return c.Gateway.Enabled || c.Management.Enabled }

func cfgErr(detail string) error { return limErr(detail) }

// Validate checks both listener configurations transactionally BEFORE anything binds:
// unsafe/zero/negative/wildcard/conflicting configurations fail here. A disabled
// listener is not validated (it binds nothing).
func (c Config) Validate() error {
	if c.Gateway.Enabled {
		if c.Gateway.Capability != protocol.Gateway {
			return cfgErr("gateway listener config is not the Gateway capability")
		}
		if err := c.Gateway.validate(); err != nil {
			return err
		}
	}
	if c.Management.Enabled {
		if c.Management.Capability != protocol.Management {
			return cfgErr("management listener config is not the Management capability")
		}
		if err := c.Management.validate(); err != nil {
			return err
		}
	}
	// The two listeners must never share an address/port.
	if c.Gateway.Enabled && c.Management.Enabled {
		if equalAddr(c.Gateway, c.Management) {
			return cfgErr("management and gateway listeners share an address/port")
		}
		if c.Gateway.AuthConfig.CanonicalResource() == c.Management.AuthConfig.CanonicalResource() && c.Gateway.AuthConfig.CanonicalResource() != "" {
			return cfgErr("management and gateway listeners share a canonical resource")
		}
	}
	return nil
}

// equalAddr reports whether two listeners resolve to the same bind endpoint. An
// ephemeral (port 0) bind can never statically conflict — the real port is chosen
// at bind time — so it is never treated as equal.
func equalAddr(a, b ListenerConfig) bool {
	if a.Port == 0 || b.Port == 0 {
		return false
	}
	return a.Port == b.Port && normalizeBind(a.BindAddress) == normalizeBind(b.BindAddress)
}

func normalizeBind(s string) string {
	if s == "" || s == "0.0.0.0" || s == "::" {
		return "*"
	}
	return s
}

func (c ListenerConfig) validate() error {
	if err := c.validateBind(); err != nil {
		return err
	}
	if len(c.AllowedHosts) == 0 {
		return cfgErr("listener host allowlist is mandatory (empty is not permitted)")
	}
	if c.TLS == nil && !c.AllowInsecure {
		return cfgErr("listener requires TLS (no server TLS config supplied)")
	}
	if c.ClientCertMode == ClientCertRequire && c.TLS == nil {
		return cfgErr("mTLS-required listener needs a TLS config with a client CA pool")
	}
	return nil
}

// validateBind checks the port + bind-address rules (extracted to keep validate
// under the cyclomatic-complexity bound).
func (c ListenerConfig) validateBind() error {
	// Port 0 is an ephemeral-port bind, permitted only under the AllowInsecure
	// test/loopback seam (a production listener binds a fixed, declared port).
	if c.Port == 0 && !c.AllowInsecure {
		return cfgErr("listener port is required")
	}
	if c.Port < 0 || c.Port > 65535 {
		return cfgErr("listener port is out of range")
	}
	if c.BindAddress == "" {
		return cfgErr("listener bind address is empty")
	}
	if isWildcard(c.BindAddress) && !c.AllowWildcard {
		return cfgErr("wildcard bind address is not permitted")
	}
	if net.ParseIP(c.BindAddress) == nil && !isWildcard(c.BindAddress) {
		// Allow a hostname bind only if it resolves syntactically; a bare interface
		// name or malformed address fails closed.
		if _, err := net.ResolveTCPAddr("tcp", c.Addr()); err != nil {
			return cfgErr("listener bind address is not a valid IP/interface")
		}
	}
	return nil
}

func isWildcard(s string) bool { return s == "0.0.0.0" || s == "::" || s == "[::]" }
