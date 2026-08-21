// Package hostcheck implements MCP-INSP-008: the pure, listener-independent
// Origin/Host validation decision primitive for inbound MCP requests.
//
// It is a DECISION FUNCTION, not a listener. It takes already-parsed header
// values (the Host / :authority and the Origin) plus a configured allowlist and
// returns an ALLOW / REJECT decision with a stable reason. It binds no socket,
// performs no network or DNS I/O, and is fully unit-testable without a server.
// The listener-side binding + per-request/per-HTTP2-stream enforcement and the
// end-to-end DNS-rebinding proof are MCP-INSP-009 (PR-5) and are deliberately
// NOT in this package.
//
// The reviewed V1 posture (ADR-0024 §D-9) this primitive encodes:
//
//   - Host allowlisting is MANDATORY. A request whose Host / :authority is absent
//     or not on the allowlist is rejected.
//   - A PRESENT Origin must be well-formed and allowlisted; a present-but-invalid
//     or non-allowlisted Origin is rejected.
//   - An ABSENT Origin is allowed by default: Culvert does NOT force every
//     non-browser client to send Origin — unless the deployment/protocol revision
//     opts in via RequireOrigin.
package hostcheck

import (
	"net/url"
	"strings"

	"github.com/KidCarmi/Culvert/internal/mcp/mcperr"
)

// Decision is the outcome of a Host/Origin check.
type Decision int

const (
	// Reject is the zero value so a mis-constructed or zero Result fails closed.
	Reject Decision = iota
	// Allow permits the request (host allowlisted; origin acceptable).
	Allow
)

// String returns the decision label (allow/reject).
func (d Decision) String() string {
	if d == Allow {
		return "allow"
	}
	return "reject"
}

// Stable machine reasons. ReasonAllowed accompanies an Allow; the rest accompany
// a Reject and are part of the package contract.
const (
	ReasonAllowed          = "allowed"
	ReasonHostMissing      = "host_missing"
	ReasonHostNotAllowed   = "host_not_allowlisted"
	ReasonOriginRequired   = "origin_required"
	ReasonOriginInvalid    = "origin_invalid"
	ReasonOriginNotAllowed = "origin_not_allowlisted"
)

// Result is the decision plus a stable reason string.
type Result struct {
	Decision Decision
	Reason   string
}

func allow() Result          { return Result{Decision: Allow, Reason: ReasonAllowed} }
func reject(r string) Result { return Result{Decision: Reject, Reason: r} }

// Allowed reports whether the result is an ALLOW (convenience for callers).
func (r Result) Allowed() bool { return r.Decision == Allow }

// Config configures a Validator. AllowedHosts and AllowedOrigins are matched
// exactly (case-insensitively) after normalization. AllowedHosts entries may be
// "host" or "host:port". AllowedOrigins entries are full origins
// ("scheme://host[:port]"). RequireOrigin makes a missing Origin a rejection.
type Config struct {
	AllowedHosts   []string
	AllowedOrigins []string
	RequireOrigin  bool
}

// Validator is an immutable Host/Origin decision primitive.
type Validator struct {
	hosts         map[string]struct{}
	origins       map[string]struct{}
	requireOrigin bool
}

// New validates cfg and returns an immutable Validator. An empty host allowlist
// is rejected: host allowlisting is mandatory, so a validator that would allow
// every host is a configuration error, not a permissive default.
func New(cfg Config) (*Validator, error) {
	if len(cfg.AllowedHosts) == 0 {
		return nil, mcperr.New(mcperr.ReasonInvalidLifecycle, "hostcheck.new", "empty host allowlist (host allowlisting is mandatory)")
	}
	v := &Validator{
		hosts:         make(map[string]struct{}, len(cfg.AllowedHosts)),
		origins:       make(map[string]struct{}, len(cfg.AllowedOrigins)),
		requireOrigin: cfg.RequireOrigin,
	}
	for _, h := range cfg.AllowedHosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" {
			return nil, mcperr.New(mcperr.ReasonInvalidLifecycle, "hostcheck.new", "blank host allowlist entry")
		}
		v.hosts[h] = struct{}{}
	}
	for _, o := range cfg.AllowedOrigins {
		norm, ok := normalizeOrigin(o)
		if !ok {
			return nil, mcperr.New(mcperr.ReasonInvalidLifecycle, "hostcheck.new", "invalid origin allowlist entry")
		}
		v.origins[norm] = struct{}{}
	}
	return v, nil
}

// Check evaluates a request.
//
//   - host is the Host or HTTP/2 :authority value (already extracted from the
//     request). It is MANDATORY and must be on the allowlist.
//   - originPresent reports whether an Origin header was sent; origin is its
//     value. A present Origin must be well-formed and allowlisted. An absent
//     Origin is allowed unless the Validator was built with RequireOrigin.
//
// Check is a pure function of its inputs and the Validator's immutable state.
func (v *Validator) Check(host string, originPresent bool, origin string) Result {
	nh := strings.ToLower(strings.TrimSpace(host))
	if nh == "" {
		return reject(ReasonHostMissing)
	}
	if !v.hostAllowed(nh) {
		return reject(ReasonHostNotAllowed)
	}
	if !originPresent {
		if v.requireOrigin {
			return reject(ReasonOriginRequired)
		}
		return allow()
	}
	norm, ok := normalizeOrigin(origin)
	if !ok {
		return reject(ReasonOriginInvalid)
	}
	if _, ok := v.origins[norm]; !ok {
		return reject(ReasonOriginNotAllowed)
	}
	return allow()
}

// hostAllowed matches the full authority and, if it carries a port, the bare
// host — so an allowlist may list either "example.com" or "example.com:8443".
func (v *Validator) hostAllowed(nh string) bool {
	if _, ok := v.hosts[nh]; ok {
		return true
	}
	if i := strings.LastIndexByte(nh, ':'); i > 0 && !strings.Contains(nh[i:], "]") {
		if _, ok := v.hosts[nh[:i]]; ok {
			return true
		}
	}
	return false
}

// normalizeOrigin parses and canonicalizes an Origin header value. A valid
// Origin is an absolute http/https URL with a host and NOTHING else (no path,
// query, fragment or userinfo). The literal "null" is treated as invalid — it is
// only ever acceptable if an operator explicitly allowlists it via a
// scheme-bearing entry, which "null" is not, so it fails closed. Returns the
// lowercased "scheme://host[:port]" and ok=false on any malformed input.
func normalizeOrigin(o string) (string, bool) {
	o = strings.TrimSpace(o)
	if o == "" || strings.EqualFold(o, "null") {
		return "", false
	}
	u, err := url.Parse(o)
	if err != nil {
		return "", false
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", false
	}
	if u.Host == "" || u.User != nil {
		return "", false
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", false
	}
	return scheme + "://" + strings.ToLower(u.Host), true
}
