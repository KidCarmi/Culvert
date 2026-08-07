package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

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

	// gate arms when the directory is unreachable, so an outage denies without
	// re-dialing and recovers on one probe (CHAOS-47, auth_backend_health.go).
	gate authProbeGate
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
// An AUTHORITATIVE result — the directory answered, and the answer was yes or
// no — is cached for CacheTTL to protect the LDAP server from load. A failure
// to REACH the directory is not (CHAOS-47): the request still fails closed, but
// caching it would keep denying the user for the whole TTL after the directory
// recovered, turning a one-second restart into minutes of lockout for everyone
// who authenticated during it. Instead the backend is gated, so the outage
// costs one probe per cooldown and clears the instant the directory answers.
func (a *LDAPAuth) Verify(username, password string) bool {
	if password == "" {
		return false // never permit empty passwords
	}

	k := cacheKey(username, password)
	if ok, hit := a.cacheGet(k); hit {
		return ok
	}

	if !a.gate.allow() {
		// Directory is in its unreachable cooldown. Deny — the posture is
		// fail-closed — but without a dial, so a hard-down directory cannot
		// turn every request into a full dial timeout.
		noteAuthBackendGatedDenial()
		return false
	}

	ok, err := a.verify(username, password)
	if err != nil {
		a.gate.recordUnavailable()
		noteAuthBackendUnavailable("ldap", err.Error())
		return false
	}
	a.gate.recordReachable()
	noteAuthBackendReachable("ldap")

	a.cacheSet(k, ok)
	if ok {
		logger.Printf("LDAP auth OK: user=%q", sanitizeLog(username))
	} else {
		logger.Printf("LDAP auth FAIL: user=%q", sanitizeLog(username))
	}
	return ok
}

// verify performs one directory round trip.
//
// The returned error is reserved for INFRASTRUCTURE failure — the directory
// could not be reached or could not answer. `(false, nil)` means the directory
// answered and the answer was "no". Only the latter is cacheable, so the split
// is load-bearing rather than stylistic; see Verify.
func (a *LDAPAuth) verify(username, password string) (bool, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: a.cfg.TLSSkipVerify} // #nosec G402 -- TLSSkipVerify is an explicit admin opt-in for self-signed LDAP certs

	// Dial with timeout to prevent DoS from hung LDAP servers.
	conn, err := ldap.DialURL(a.cfg.URL,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}),
	)
	if err != nil {
		logger.Printf("LDAP dial error: %v", err)
		return false, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close of a bind connection

	// Optional STARTTLS upgrade.
	if a.cfg.StartTLS && !strings.HasPrefix(strings.ToLower(a.cfg.URL), "ldaps") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			logger.Printf("LDAP STARTTLS error: %v", err)
			return false, fmt.Errorf("starttls: %w", err)
		}
	}

	// Step 1: bind with service account to search for the user's DN.
	// A service-bind failure is never a statement about the END USER's
	// credential — it is a wrong/expired service account or a directory that
	// stopped answering — so it is infrastructure, not a deny to remember.
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			logger.Printf("LDAP service bind error: %v", err)
			return false, fmt.Errorf("service bind: %w", err)
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
		return false, fmt.Errorf("search: %w", err)
	}
	if len(res.Entries) != 1 {
		// The directory answered: no such user (or an ambiguous filter). That
		// is an authoritative deny and stays cacheable.
		logger.Printf("LDAP: user %q not found (entries=%d)", username, len(res.Entries))
		return false, nil
	}

	userDN := res.Entries[0].DN

	// Step 2: bind with user DN + password to verify credential.
	// Only result code 49 (invalidCredentials) is the directory REJECTING the
	// password. Anything else here — the connection dropped mid-bind, the
	// server returned unavailable/busy — is infrastructure and must not be
	// remembered as a bad password.
	if err := conn.Bind(userDN, password); err != nil {
		if !ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			// The directory's diagnostic text is server-controlled, so it goes
			// through the CWE-117 barrier before it reaches the log.
			logger.Printf("LDAP user bind error: %q", sanitizeLog(err.Error()))
			return false, fmt.Errorf("user bind: %w", err)
		}
		return false, nil // wrong password — not logged to avoid credential leakage
	}

	// Optional group membership check.
	if a.cfg.RequiredGroup != "" {
		if !a.isMember(res.Entries[0], a.cfg.RequiredGroup) {
			logger.Printf("LDAP: user %q not in required group %s", username, a.cfg.RequiredGroup)
			return false, nil
		}
	}

	return true, nil
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
