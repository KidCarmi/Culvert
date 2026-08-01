package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// ldapDialTimeout bounds establishing the TCP (and, for ldaps://, TLS)
// connection to the directory.
const ldapDialTimeout = 10 * time.Second

// ldapOpTimeout bounds each LDAP operation AFTER the connect — the service
// bind, the user search, and the user bind. See the SetTimeout call in
// verify() for why the dial timeout alone is not enough.
//
// A var rather than a const solely so the deadline can be proven: the test
// that asserts a stalling directory is actually released shrinks this, because
// waiting out the production value would make the suite unusable.
var ldapOpTimeout = 10 * time.Second

// LDAPConfig holds all settings needed to authenticate against an LDAP/AD server.
// Supported directory services: Microsoft Active Directory, OpenLDAP, FreeIPA.
type LDAPConfig struct {
	// URL of the LDAP server.
	// Examples: "ldap://dc.corp.com:389", "ldaps://dc.corp.com:636"
	URL string `yaml:"url"`

	// BindDN is the service-account DN used to search for users.
	// Leave empty for anonymous bind (not recommended for AD).
	// Example: "CN=svc-proxy,OU=ServiceAccounts,DC=corp,DC=com"
	BindDN string `yaml:"bind_dn"`

	// BindPassword is the service-account password.
	BindPassword string `yaml:"bind_password"`

	// BaseDN is the LDAP subtree to search for users.
	// Example: "OU=Users,DC=corp,DC=com"
	BaseDN string `yaml:"base_dn"`

	// UserFilter is an LDAP search filter template; %s is replaced with the
	// escaped username supplied by the client.
	// Active Directory: "(sAMAccountName=%s)"
	// OpenLDAP / FreeIPA: "(uid=%s)"
	UserFilter string `yaml:"user_filter"`

	// RequiredGroup is an optional group DN.  When non-empty the user must be
	// a direct member of this group to be allowed access.
	// Example: "CN=ProxyUsers,OU=Groups,DC=corp,DC=com"
	RequiredGroup string `yaml:"required_group"`

	// StartTLS upgrades a plain-text ldap:// connection with STARTTLS.
	// Ignored for ldaps:// connections (always TLS).
	StartTLS bool `yaml:"start_tls"`

	// TLSSkipVerify disables certificate verification.
	// Only use in development/test environments.
	TLSSkipVerify bool `yaml:"tls_skip_verify"`

	// CacheTTL is how long a successful (or failed) auth result is cached.
	// Defaults to 5 minutes when zero.
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// ldapCacheEntry stores the result of one LDAP authentication attempt.
type ldapCacheEntry struct {
	ok     bool
	expiry time.Time
}

// LDAPAuth authenticates users against an LDAP / Active Directory server.
type LDAPAuth struct {
	cfg   LDAPConfig
	ttl   time.Duration
	mu    sync.Mutex
	cache map[string]*ldapCacheEntry // key = cacheKey(user, pass)
}

// NewLDAPAuth validates the config and returns a ready-to-use LDAPAuth.
func NewLDAPAuth(cfg LDAPConfig) (*LDAPAuth, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("ldap: URL is required")
	}
	if cfg.BaseDN == "" {
		return nil, fmt.Errorf("ldap: base_dn is required")
	}
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(sAMAccountName=%s)" // sensible default for AD
	}
	ttl := cfg.CacheTTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	// Warn about plaintext LDAP connections.
	if strings.HasPrefix(strings.ToLower(cfg.URL), "ldap://") && !cfg.StartTLS {
		logWarnf("LDAP: using plaintext ldap:// without StartTLS — credentials will be transmitted unencrypted. Use ldaps:// or set start_tls: true")
	}
	if cfg.TLSSkipVerify {
		logWarnf("LDAP: TLS certificate verification DISABLED (tls_skip_verify) — credentials traverse an unverified channel vulnerable to MITM; intended for self-signed dev directories only") // RISK-009
	}
	return &LDAPAuth{cfg: cfg, ttl: ttl, cache: map[string]*ldapCacheEntry{}}, nil
}

func (a *LDAPAuth) Name() string { return "ldap" }

// Verify authenticates user against LDAP using a two-step bind:
//  1. Bind with service account to locate the user's DN.
//  2. Bind with user DN + supplied password to verify the credential.
//
// Optionally checks group membership if RequiredGroup is configured.
//
// Results are cached for CacheTTL to protect the LDAP server from load — but
// ONLY when the directory actually answered. An attempt the directory did not
// answer (unreachable, refusing to serve, connection lost mid-operation) is
// denied for this request and deliberately NOT cached: caching it would record
// an infrastructure fault as if it were a statement about the user's password,
// so a two-second outage would keep denying that user for the full TTL after
// the directory recovered (CHAOS-16). See idpResult in auth_health.go.
func (a *LDAPAuth) Verify(username, password string) bool {
	if password == "" {
		return false // never permit empty passwords
	}

	k := cacheKey(username, password)
	if ok, hit := a.cacheGet(k); hit {
		return ok
	}

	res, reason := a.verify(username, password)
	if res == idpUnavailable {
		// Fail closed for THIS request — posture is unchanged — but leave no
		// trace in the cache, so the very next request re-asks the directory
		// and recovery is immediate rather than TTL-delayed.
		noteIdPUnavailable("ldap", reason)
		logger.Printf("LDAP auth UNAVAILABLE: user=%q reason=%q — denied (directory did not answer; result not cached)",
			sanitizeLog(username), sanitizeLog(reason))
		return false
	}

	ok := res == idpAllowed
	a.cacheSet(k, ok)
	noteIdPAnswered("ldap")
	if ok {
		logger.Printf("LDAP auth OK: user=%q", sanitizeLog(username))
	} else {
		logger.Printf("LDAP auth FAIL: user=%q", sanitizeLog(username))
	}
	return ok
}

// connect dials the directory, arms the per-operation deadline, and performs
// the optional STARTTLS upgrade. It returns a non-empty reason (and a nil
// conn) when the directory could not be reached — every failure here is
// definitionally an unavailability, since nothing has been asked yet.
func (a *LDAPAuth) connect() (*ldap.Conn, string) {
	tlsCfg := &tls.Config{InsecureSkipVerify: a.cfg.TLSSkipVerify} // #nosec G402 -- TLSSkipVerify is an explicit admin opt-in for self-signed LDAP certs

	// Dial with timeout to prevent DoS from hung LDAP servers.
	conn, err := ldap.DialURL(a.cfg.URL,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(&net.Dialer{Timeout: ldapDialTimeout}),
	)
	if err != nil {
		logger.Printf("LDAP dial error: %v", err)
		return nil, "dial_failed"
	}

	// CHAOS-16: bound every operation that follows the TCP connect. The dialer
	// timeout above covers ONLY establishing the connection; without this, a
	// directory that completes the TCP handshake and then stalls — an
	// overloaded DC, a half-open connection surviving a firewall state-table
	// flush, a stateful middlebox black-holing the reply — leaves Bind and
	// Search blocked forever, pinning a proxy request goroutine (and its
	// client socket) with no upper bound. Under a reconnect storm against a
	// sick directory that is unbounded goroutine growth on the request path.
	conn.SetTimeout(ldapOpTimeout)

	// Optional STARTTLS upgrade.
	if a.cfg.StartTLS && !strings.HasPrefix(strings.ToLower(a.cfg.URL), "ldaps") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			logger.Printf("LDAP STARTTLS error: %v", err)
			conn.Close()
			return nil, "starttls_failed"
		}
	}
	return conn, ""
}

// verify performs the two-step bind and classifies the outcome.
//
// The second return value is a fixed-vocabulary reason, non-empty only when
// the result is idpUnavailable. It is never a raw error string — see the
// disclosure note on noteIdPUnavailable.
func (a *LDAPAuth) verify(username, password string) (idpResult, string) {
	conn, reason := a.connect()
	if reason != "" {
		return idpUnavailable, reason
	}
	defer conn.Close()

	// Step 1: bind with service account to search for the user's DN.
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			// Never cacheable, whatever the cause. A service-account bind
			// failure is either a broken directory or a misconfigured service
			// credential — in both cases we failed to ASK the question about
			// this user, so it is not an answer about them.
			logger.Printf("LDAP service bind error: %v", err)
			return idpUnavailable, "service_bind_failed"
		}
	} else if a.cfg.RequiredGroup != "" {
		logWarnf("LDAP: anonymous bind with RequiredGroup=%q — group resolution may fail", sanitizeLog(a.cfg.RequiredGroup))
	}

	filter := fmt.Sprintf(a.cfg.UserFilter, ldap.EscapeFilter(username))
	req := ldap.NewSearchRequest(
		a.cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases,
		0, 0, false,
		filter,
		[]string{"dn", "memberOf"},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		logger.Printf("LDAP search error: %v", err)
		return idpUnavailable, "search_failed"
	}
	if len(res.Entries) != 1 {
		// The directory answered: this user does not exist, or the filter is
		// ambiguous. A definitive deny, and cacheable.
		logger.Printf("LDAP: user %q not found (entries=%d)", username, len(res.Entries))
		return idpDenied, ""
	}

	userDN := res.Entries[0].DN

	// Step 2: bind with user DN + password to verify credential.
	if err := conn.Bind(userDN, password); err != nil {
		if ldapErrorIsTransport(err) {
			// The connection died between the search and the bind (reset,
			// server shutting down, request timeout). We never learned whether
			// the password was right, so this must not be remembered as
			// "wrong password".
			logger.Printf("LDAP user bind transport error: %v", err)
			return idpUnavailable, "bind_transport_failed"
		}
		// A protocol-level rejection from the server IS an answer — wrong
		// password (49), disabled/locked account (53), and friends. Cacheable,
		// and deliberately NOT alerted: a locked-out account must not page the
		// directory team. Not logged, to avoid credential leakage.
		return idpDenied, ""
	}

	// Optional group membership check.
	if a.cfg.RequiredGroup != "" {
		if !a.isMember(res.Entries[0], a.cfg.RequiredGroup) {
			logger.Printf("LDAP: user %q not in required group %s", username, a.cfg.RequiredGroup)
			return idpDenied, ""
		}
	}

	return idpAllowed, ""
}

// ldapErrorIsTransport reports whether err means the directory never gave us
// an answer, as opposed to answering "no".
//
// The line is drawn at go-ldap's own result codes. Anything the SERVER sent as
// an LDAP result code is an answer about the operation — including the
// rejections a healthy directory issues every day (invalid credentials,
// account disabled, insufficient rights) — and those must stay cacheable and
// must never page an operator. The codes below are the ones that mean the
// exchange did not complete:
//
//   - ErrorNetwork / ErrorUnexpectedMessage / ErrorUnexpectedResponse (200,
//     204, 205) are go-ldap's CLIENT-side pseudo-codes for a dead, confused or
//     timed-out connection. The per-request timeout armed by SetTimeout
//     surfaces here, as a closed response channel wrapped in ErrorNetwork.
//   - ServerDown / LocalError / Timeout / ConnectError (81, 82, 85, 91) are
//     the classic client-side codes carried over from libldap.
//   - Busy / Unavailable (51, 52) ARE sent by the server, but they say "I
//     cannot serve you right now" — explicitly a refusal to answer, not an
//     answer.
//
// Anything else — and only anything else — is treated as an answer. A non-LDAP
// error (a bare net.Error, a context deadline) is treated as transport, which
// is the safe direction: the cost of misclassifying an answer as no-answer is
// one uncached lookup, while the cost of the reverse is a cached denial that
// outlives the outage, which is the entire defect this fixes.
func ldapErrorIsTransport(err error) bool {
	if err == nil {
		return false
	}
	return ldap.IsErrorAnyOf(err,
		ldap.ErrorNetwork,
		ldap.ErrorUnexpectedMessage,
		ldap.ErrorUnexpectedResponse,
		ldap.LDAPResultServerDown,
		ldap.LDAPResultLocalError,
		ldap.LDAPResultTimeout,
		ldap.LDAPResultConnectError,
		ldap.LDAPResultBusy,
		ldap.LDAPResultUnavailable,
	) || !isLDAPProtocolError(err)
}

// isLDAPProtocolError reports whether err carries a server-issued LDAP result
// code (i.e. is a *ldap.Error at all).
func isLDAPProtocolError(err error) bool {
	var le *ldap.Error
	return errors.As(err, &le)
}

// isMember checks the memberOf attribute for the required group DN.
func (a *LDAPAuth) isMember(entry *ldap.Entry, groupDN string) bool {
	for _, v := range entry.GetAttributeValues("memberOf") {
		if strings.EqualFold(v, groupDN) {
			return true
		}
	}
	return false
}

func (a *LDAPAuth) cacheGet(key string) (ok, hit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, found := a.cache[key]; found && time.Now().Before(e.expiry) {
		return e.ok, true
	}
	return false, false
}

func (a *LDAPAuth) cacheSet(key string, ok bool) {
	a.mu.Lock()
	// Evict a random entry when the cache is full to prevent unbounded growth.
	if len(a.cache) >= maxAuthCacheSize {
		for k := range a.cache {
			delete(a.cache, k)
			break
		}
	}
	a.cache[key] = &ldapCacheEntry{ok: ok, expiry: time.Now().Add(a.ttl)}
	a.mu.Unlock()
}
