package main

// sso_surrogate.go — IP-bound sign-in: the opt-in browser-to-proxy identity
// transport (F-SSO-SCOPE-1, #1528). The engine is internal/ipsurrogate; this
// file decides WHEN a login may bind, what a binding authorises on the proxy,
// and owns the admin surface + persistence.
//
// The rules, each load-bearing:
//   - OFF by default. With it off, the proxy does not redirect browsers to
//     sign in at all (uiSelectURL): a browser SSO session is a cookie on the
//     admin UI host and authenticates no proxied traffic, so a redirect could
//     only ever end in a sign-in loop. The challenge says why instead.
//   - A binding is created only by a COMPLETED interactive login (OIDC
//     callback, SAML completion) — after the browser binding check — keyed by
//     the client address the admin UI saw (realClientIP: X-Forwarded-For only
//     from a configured trusted proxy).
//   - Never for a loopback/unspecified address: such a login reached the UI
//     from the appliance itself (e.g. through its own proxy), and binding it
//     would attribute the appliance's own address to one user.
//   - Never for an excluded source range: everyone behind one NAT address, a
//     terminal server or a shared jump host is one "browser" to an IP
//     surrogate. The proxy also withholds the sign-in redirect from those
//     sources, so they never loop. (Loopback is refused at BIND time only:
//     the proxy-side address of a local client says nothing about where its
//     sign-in will come from.)
//   - On the proxy, a binding is consulted ONLY for a request that presents no
//     credential at all (no session cookie, no Proxy-Authorization), keyed by
//     the raw socket peer — the same address the proxy enforces on.
//   - Bindings expire (TTL), are removed at logout (every binding of that
//     subject), when the transport is turned off, and by an admin. They are
//     node-local and volatile: a restart means signing in again.

import (
	"errors"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"

	"github.com/KidCarmi/Culvert/internal/ipsurrogate"
)

const (
	ssoSurrogateMaxBindings    = 65536
	ssoSurrogateTTLDefaultMins = 60
	ssoSurrogateTTLMinMins     = 5
	ssoSurrogateTTLMaxMins     = 1440
	ssoSurrogateMaxExclude     = 256
)

// ssoSurrogateSettings is the admin-governed configuration.
type ssoSurrogateSettings struct {
	Enabled      bool     `json:"enabled"`
	TTLMinutes   int      `json:"ttlMinutes"`
	ExcludeCIDRs []string `json:"excludeCidrs"`
}

// ssoSurrogateRuntime is the published, parsed form.
type ssoSurrogateRuntime struct {
	settings ssoSurrogateSettings
	exclude  []netip.Prefix
	saved    bool
}

var (
	ssoSurrogate    = ipsurrogate.New(ssoSurrogateMaxBindings)
	ssoSurrogateCfg atomic.Pointer[ssoSurrogateRuntime]

	ssoSurrogateBinds   [ssoBindOutcomes]atomic.Int64
	ssoSurrogateRevoked atomic.Int64

	// ssoSurrogateSelfAddr reports whether a is one of this appliance's own
	// interface addresses. A sign-in that reached the admin UI FROM the
	// appliance itself (a browser whose proxy settings route the UI host
	// through Culvert) carries an address that identifies no browser, so it
	// is never bound. A seam so the browser journey, whose "client" runs on
	// the same host, can stand in for a client on another machine.
	ssoSurrogateSelfAddr = isOwnInterfaceAddr
)

func isOwnInterfaceAddr(a netip.Addr) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, x := range addrs {
		if n, ok := x.(*net.IPNet); ok {
			if b, ok := netip.AddrFromSlice(n.IP); ok && b.Unmap() == a {
				return true
			}
		}
	}
	return false
}

func init() {
	rt, _ := resolveSSOSurrogateSettings(ssoSurrogateSettings{})
	ssoSurrogateCfg.Store(rt)
}

// resolveSSOSurrogateSettings validates and normalises (TTL 0 ⇒ default;
// canonical CIDRs, deduplicated in order).
func resolveSSOSurrogateSettings(in ssoSurrogateSettings) (*ssoSurrogateRuntime, error) {
	if in.TTLMinutes == 0 {
		in.TTLMinutes = ssoSurrogateTTLDefaultMins
	}
	if in.TTLMinutes < ssoSurrogateTTLMinMins || in.TTLMinutes > ssoSurrogateTTLMaxMins {
		return nil, fmt.Errorf("ttlMinutes must be between %d and %d", ssoSurrogateTTLMinMins, ssoSurrogateTTLMaxMins)
	}
	if len(in.ExcludeCIDRs) > ssoSurrogateMaxExclude {
		return nil, fmt.Errorf("at most %d excluded ranges", ssoSurrogateMaxExclude)
	}
	rt := &ssoSurrogateRuntime{settings: ssoSurrogateSettings{Enabled: in.Enabled, TTLMinutes: in.TTLMinutes, ExcludeCIDRs: []string{}}}
	seen := map[netip.Prefix]bool{}
	for _, c := range in.ExcludeCIDRs {
		c = strings.TrimSpace(c)
		p, err := netip.ParsePrefix(c)
		if err != nil {
			a, aerr := netip.ParseAddr(c)
			if aerr != nil {
				return nil, fmt.Errorf("excluded range %q is not a CIDR or an address", c)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		p = netip.PrefixFrom(p.Addr().Unmap(), unmappedBits(p)).Masked()
		if seen[p] {
			continue
		}
		seen[p] = true
		rt.exclude = append(rt.exclude, p)
		rt.settings.ExcludeCIDRs = append(rt.settings.ExcludeCIDRs, p.String())
	}
	return rt, nil
}

// unmappedBits converts a prefix length on a ::ffff:a.b.c.d/N address to its
// IPv4 length (N-96), so a mapped range excludes the plain IPv4 clients.
func unmappedBits(p netip.Prefix) int {
	if p.Addr().Is4In6() {
		if b := p.Bits() - 96; b >= 0 {
			return b
		}
		return 0
	}
	return p.Bits()
}

// applySSOSurrogate publishes rt.
//   - OFF: lookups stop first, then every binding is removed.
//   - OFF→ON: the table is emptied BEFORE lookups start, so a bind that raced
//     the earlier disable (checked "on", inserted after the clear) can never
//     come back to life.
//   - ON→ON (a settings change): bindings inside a newly excluded range are
//     removed and every expiry is clamped to the new lifetime — a live binding
//     must never escape a setting the operator just tightened.
func applySSOSurrogate(rt *ssoSurrogateRuntime) {
	ssoSurrogateCfg.Store(rt)
	if !rt.settings.Enabled {
		ssoSurrogate.SetEnabled(false)
		ssoSurrogateRevoked.Add(int64(ssoSurrogate.Clear()))
		return
	}
	if !ssoSurrogate.Enabled() {
		ssoSurrogate.Clear()
	}
	n := ssoSurrogate.RemoveIf(func(a netip.Addr, _ ipsurrogate.Identity) bool { return ssoSurrogateExcluded(a) })
	ssoSurrogateRevoked.Add(int64(n))
	ssoSurrogate.ClampExpiry(time.Now().Add(time.Duration(rt.settings.TTLMinutes) * time.Minute))
	ssoSurrogate.SetEnabled(true)
}

func ssoSurrogateExcluded(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range ssoSurrogateCfg.Load().exclude {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func parseClientAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

// ssoBindOutcome classifies a login's bind attempt (bounded label set).
type ssoBindOutcome int

const (
	ssoBindBound   ssoBindOutcome = iota
	ssoBindRebound                // bound, displacing a live binding of ANOTHER identity
	ssoBindDisabled
	ssoBindExcluded
	ssoBindLocal
	ssoBindFull
	ssoBindInvalid
	ssoBindOutcomes
)

var ssoBindOutcomeNames = [ssoBindOutcomes]string{"bound", "rebound", "disabled", "excluded", "local", "full", "invalid"}

func (o ssoBindOutcome) bound() bool { return o == ssoBindBound || o == ssoBindRebound }

func (o ssoBindOutcome) String() string { return ssoBindOutcomeNames[o] }

// ssoSurrogateBindLogin binds the client of a just-completed interactive
// login. Called after the browser binding check and the session cookie.
func ssoSurrogateBindLogin(r *http.Request, id *Identity) ssoBindOutcome {
	o, prev := ssoSurrogateBind(r, id)
	ssoSurrogateBinds[o].Add(1)
	switch {
	case o == ssoBindRebound && prev != nil:
		// The most recent login wins, but a takeover of a LIVE binding is how
		// a shared address (NAT, terminal server) shows itself: say so loudly.
		logger.Printf("WARN SSO_IP_BIND outcome=rebound client=%q user=%q provider=%q displaced_user=%q displaced_provider=%q — traffic from this address is now attributed to the new user; if several people share it, exclude it (Settings → Identity Providers → IP-bound sign-in)",
			sanitizeLog(realClientIP(r)), sanitizeLog(id.Sub), sanitizeLog(id.Provider), sanitizeLog(prev.Sub), sanitizeLog(prev.Provider))
	case o != ssoBindDisabled:
		logger.Printf("SSO_IP_BIND outcome=%s client=%q user=%q provider=%q", o, sanitizeLog(realClientIP(r)), sanitizeLog(id.Sub), sanitizeLog(id.Provider))
	}
	return o
}

func ssoSurrogateBind(r *http.Request, id *Identity) (ssoBindOutcome, *ipsurrogate.Identity) {
	if !ssoSurrogate.Enabled() {
		return ssoBindDisabled, nil
	}
	if id == nil || strings.TrimSpace(id.Sub) == "" {
		return ssoBindInvalid, nil
	}
	a, ok := parseClientAddr(realClientIP(r))
	switch {
	case !ok:
		return ssoBindInvalid, nil
	case a.IsLoopback() || a.IsUnspecified() || ssoSurrogateSelfAddr(a):
		return ssoBindLocal, nil
	case ssoSurrogateExcluded(a):
		return ssoBindExcluded, nil
	}
	// A binding never outlives the sign-in session it came from: sign-out
	// revokes through that session, so a binding longer than the session
	// would be one nobody can sign out of.
	ttl := time.Duration(ssoSurrogateCfg.Load().settings.TTLMinutes) * time.Minute
	if st := getSessionTTL(); st > 0 && st < ttl {
		ttl = st
	}
	prev, err := ssoSurrogate.Bind(a, ipsurrogate.Identity{Sub: id.Sub, Email: id.Email, Provider: id.Provider, Groups: id.Groups}, ttl, time.Now())
	switch {
	case errors.Is(err, ipsurrogate.ErrFull):
		return ssoBindFull, nil
	case err != nil:
		return ssoBindInvalid, nil
	case prev != nil:
		return ssoBindRebound, prev
	}
	return ssoBindBound, nil
}

// ssoSurrogateLookupFor answers the proxy, AFTER the Stage-1 rule match d:
// the identity bound to the socket peer of a request that presented no
// credential. One atomic load when off. A binding is evidence of an earlier
// browser sign-in and nothing more, so:
//   - it never satisfies a CredentialRequired rule (that rule demands a
//     credential presented on THIS request);
//   - under an SSORequired rule with providerRefs it counts only when the
//     sign-in came from one of those providers;
//   - it counts only while its IdP profile is still enabled (a deleted or
//     disabled IdP's identities stop being attributed at once, whatever path
//     changed the registry).
func ssoSurrogateLookupFor(r *http.Request, clientIP string, d AuthDecision) (ipsurrogate.Identity, bool) {
	if !ssoSurrogate.Enabled() || r.Header.Get("Proxy-Authorization") != "" || d.Outcome == OutcomeCredentialRequired {
		return ipsurrogate.Identity{}, false
	}
	a, ok := parseClientAddr(clientIP)
	if !ok {
		return ipsurrogate.Identity{}, false
	}
	id, hit := ssoSurrogate.Lookup(a, time.Now())
	if !hit || !idpRegistry.ProfileEnabled(id.Provider) {
		return ipsurrogate.Identity{}, false
	}
	if d.Outcome == OutcomeSSORequired && d.Rule != nil && d.Rule.Auth != nil && len(d.Rule.Auth.ProviderRefs) > 0 &&
		!slices.Contains(d.Rule.Auth.ProviderRefs, id.Provider) {
		return ipsurrogate.Identity{}, false
	}
	return id, true
}

// ssoSurrogateRevokeAtLogout ends every binding of the subject whose SSO
// session is being cleared.
func ssoSurrogateRevokeAtLogout(r *http.Request) {
	sess, err := readSessionCookie(r)
	if err != nil || sess == nil || sess.Sub == "" {
		return
	}
	if n := ssoSurrogate.RevokeIdentity(sess.Provider, sess.Sub); n > 0 {
		ssoSurrogateRevoked.Add(int64(n))
		logger.Printf("SSO_IP_UNBIND reason=logout user=%q bindings=%d", sanitizeLog(sess.Sub), n)
	}
}

// ssoSignInWithheld reports why the proxy will not send this request's
// client to sign in ("" = it may). The redirect is withheld when sign-in
// could not authenticate the client's proxied traffic, so a browser is never
// sent into a loop.
func ssoSignInWithheld(clientIP string) string {
	if !ssoSurrogate.Enabled() {
		return "IP-bound sign-in is disabled"
	}
	if a, ok := parseClientAddr(clientIP); ok && ssoSurrogateExcluded(a) {
		return "your address is excluded from IP-bound sign-in"
	}
	return ""
}

// ssoSignInExplanation is the challenge body when sign-in is withheld.
func ssoSignInExplanation(reason string) string {
	return "Browser single sign-on cannot authenticate this proxy connection (" + reason +
		"). Ask your administrator: the proxy identifies browsers by sign-in only when IP-bound sign-in is enabled for your address (Settings → Identity Providers)."
}

func currentSSOSurrogateSettings() ssoSurrogateSettings {
	s := ssoSurrogateCfg.Load().settings
	s.ExcludeCIDRs = append([]string{}, s.ExcludeCIDRs...)
	return s
}

// ── persistence (admin_settings.json, sentinel-gated, node-local) ──────────

func applyAdminSSOSurrogate(s *AdminSettings) {
	if !s.SSOSurrogateSaved {
		return
	}
	rt, err := resolveSSOSurrogateSettings(ssoSurrogateSettings{Enabled: s.SSOSurrogateEnabled, TTLMinutes: s.SSOSurrogateTTLMinutes, ExcludeCIDRs: s.SSOSurrogateExcludeCIDRs})
	if err != nil {
		// Fail closed: a damaged saved setting must never turn the transport ON.
		logger.Printf("WARN AdminSettings: IP-bound sign-in settings invalid (%v); transport stays OFF", err)
		rt, _ = resolveSSOSurrogateSettings(ssoSurrogateSettings{})
	}
	rt.saved = true
	applySSOSurrogate(rt)
}

func snapshotSSOSurrogate(s *AdminSettings, override *ssoSurrogateRuntime) {
	rt := ssoSurrogateCfg.Load()
	if override != nil {
		rt = override
	}
	if !rt.saved && override == nil {
		return
	}
	s.SSOSurrogateSaved = true
	s.SSOSurrogateEnabled = rt.settings.Enabled
	s.SSOSurrogateTTLMinutes = rt.settings.TTLMinutes
	s.SSOSurrogateExcludeCIDRs = append([]string{}, rt.settings.ExcludeCIDRs...)
}

// ── admin API ───────────────────────────────────────────────────────────────

// GET viewer: settings + counters. PUT admin: full replacement (persist, then
// apply; a persist failure changes nothing).
func apiSSOSurrogate(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		jsonOK(w, ssoSurrogateStatus())
	case http.MethodPut:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		var in ssoSurrogateSettings
		if err := decodeJSON(r, &in); err != nil {
			http.Error(w, "invalid JSON body", http.StatusBadRequest)
			return
		}
		rt, err := resolveSSOSurrogateSettings(in)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		rt.saved = true
		old := currentSSOSurrogateSettings()
		// Turning the transport OFF reduces who is attributed to whom, so it
		// takes effect NOW and never waits on the disk; turning it on (or any
		// other change) is persisted first, then applied.
		if !rt.settings.Enabled {
			applySSOSurrogate(rt)
		}
		err = saveAdminSettingsWithOverrides(adminSaveOverrides{
			ssoSurrogate:   rt,
			applyOnSuccess: func() { applySSOSurrogate(rt) },
		})
		if errors.Is(err, fileutil.ErrReplacedNotSynced) {
			applySSOSurrogate(rt) // the file already holds the new settings
		}
		if err != nil {
			logger.Printf("IP-bound sign-in: persist failed: %v", err)
			msg := "failed to persist settings; the running settings are unchanged"
			switch {
			case errors.Is(err, fileutil.ErrReplacedNotSynced):
				msg = "settings applied, but their durability is not confirmed"
			case !rt.settings.Enabled:
				msg = "IP-bound sign-in is OFF now, but that was not saved: it comes back on at the next restart unless saved"
			}
			http.Error(w, msg, http.StatusInternalServerError)
			return
		}
		auditEventDiff(r, "auth.sso_ip_binding.settings", "sso-ip-binding", "updated IP-bound sign-in settings", old, rt.settings)
		jsonOK(w, ssoSurrogateStatus())
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func ssoSurrogateStatus() map[string]any {
	binds := map[string]int64{}
	for i := ssoBindOutcome(0); i < ssoBindOutcomes; i++ {
		binds[i.String()] = ssoSurrogateBinds[i].Load()
	}
	return map[string]any{
		"settings":    currentSSOSurrogateSettings(),
		"bindings":    ssoSurrogate.LiveCount(time.Now()),
		"maxBindings": ssoSurrogate.Max(),
		"binds":       binds,
		"hits":        ssoSurrogate.Hits(),
		"revoked":     ssoSurrogateRevoked.Load(),
		"bounds":      map[string]int{"ttlMinutesMin": ssoSurrogateTTLMinMins, "ttlMinutesMax": ssoSurrogateTTLMaxMins, "excludeMax": ssoSurrogateMaxExclude},
		"scope":       "node-local, volatile: bindings live on the node that served the sign-in and are cleared by a restart",
	}
}

type ssoSurrogateBindingDTO struct {
	Addr     string   `json:"addr"`
	Subject  string   `json:"subject"`
	Email    string   `json:"email,omitempty"`
	Provider string   `json:"provider"`
	Groups   []string `json:"groups"`
	Bound    string   `json:"bound"`
	Expires  string   `json:"expires"`
}

// GET admin: the live bindings. DELETE admin: ?addr= one binding, ?all=1 every
// binding.
func apiSSOSurrogateBindings(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		list := ssoSurrogate.List(time.Now())
		out := make([]ssoSurrogateBindingDTO, 0, len(list))
		for i := range list {
			e := &list[i]
			out = append(out, ssoSurrogateBindingDTO{Addr: e.Addr.String(), Subject: e.Identity.Sub, Email: e.Identity.Email, Provider: e.Identity.Provider,
				Groups: append([]string{}, e.Identity.Groups...), Bound: e.Bound.UTC().Format(time.RFC3339), Expires: e.Expires.UTC().Format(time.RFC3339)})
		}
		jsonOK(w, map[string]any{"bindings": out})
	case http.MethodDelete:
		q := r.URL.Query()
		var n int
		target := "all"
		switch {
		case q.Get("all") == "1":
			n = ssoSurrogate.Clear()
		case q.Get("addr") != "":
			a, ok := parseClientAddr(strings.TrimSpace(q.Get("addr")))
			if !ok || net.ParseIP(a.String()) == nil {
				http.Error(w, "addr must be an IP address", http.StatusBadRequest)
				return
			}
			if ssoSurrogate.Revoke(a) {
				n = 1
			}
			target = a.String()
		default:
			http.Error(w, "give addr=<ip> or all=1", http.StatusBadRequest)
			return
		}
		ssoSurrogateRevoked.Add(int64(n))
		auditEvent(r, "auth.sso_ip_binding.revoke", "sso-ip-binding", fmt.Sprintf("target=%s removed=%d", target, n))
		jsonOK(w, map[string]any{"removed": n})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ssoSurrogateBindRefused binds a just-completed login and, when the
// transport is ON but this login could not be bound, answers with a page that
// says so (and returns true) instead of sending the browser back to its
// destination, where it would be challenged again — a loop with no reason
// given. With the transport OFF it never interferes.
func ssoSurrogateBindRefused(w http.ResponseWriter, r *http.Request, id *Identity) bool {
	o := ssoSurrogateBindLogin(r, id)
	if o.bound() || o == ssoBindDisabled {
		return false
	}
	why := map[ssoBindOutcome]string{
		ssoBindExcluded: "your network address is excluded from IP-bound sign-in (shared or translated addresses cannot identify one person)",
		ssoBindLocal:    "the sign-in reached the appliance from its own address (is the admin UI host routed through the proxy?), which cannot identify your browser",
		ssoBindFull:     "the appliance's sign-in binding table is full",
		ssoBindInvalid:  "your network address could not be determined",
	}[o]
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Culvert — Signed in</title>
<style>body{font-family:sans-serif;max-width:520px;margin:80px auto;padding:0 16px}</style></head><body>
<h1>Signed in, but not for web access</h1><p>Your sign-in succeeded, but this proxy cannot use it to identify your web traffic: %s.</p>
<p>Ask your administrator. Web access through the proxy will keep asking for authentication.</p></body></html>`, html.EscapeString(why))
	return true
}

// writeSSOSurrogateMetrics emits the IP-bound sign-in series. The enabled
// gauge is always present (0 is a real answer); the rest only while enabled,
// so a flat zero never stands in for "not configured".
func writeSSOSurrogateMetrics(w io.Writer) {
	en := 0
	if ssoSurrogate.Enabled() {
		en = 1
	}
	_, _ = fmt.Fprintf(w, "\n# HELP culvert_sso_ip_binding_enabled 1 when IP-bound sign-in (browser SSO as a proxy credential) is enabled\n# TYPE culvert_sso_ip_binding_enabled gauge\nculvert_sso_ip_binding_enabled %d\n", en)
	if en == 0 {
		return
	}
	_, _ = fmt.Fprintf(w, "# HELP culvert_sso_ip_binding_bindings Live client-address bindings\n# TYPE culvert_sso_ip_binding_bindings gauge\nculvert_sso_ip_binding_bindings %d\n", ssoSurrogate.LiveCount(time.Now()))
	_, _ = fmt.Fprintf(w, "# HELP culvert_sso_ip_binding_binds_total Completed SSO logins by binding outcome (excluded/local/full/invalid logins were NOT bound)\n# TYPE culvert_sso_ip_binding_binds_total counter\n")
	for i := ssoBindOutcome(0); i < ssoBindOutcomes; i++ {
		_, _ = fmt.Fprintf(w, "culvert_sso_ip_binding_binds_total{outcome=%q} %d\n", i.String(), ssoSurrogateBinds[i].Load())
	}
	_, _ = fmt.Fprintf(w, "# HELP culvert_sso_ip_binding_hits_total Proxied requests attributed to an identity through a binding\n# TYPE culvert_sso_ip_binding_hits_total counter\nculvert_sso_ip_binding_hits_total %d\n", ssoSurrogate.Hits())
}
