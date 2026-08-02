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

// ldapOpTimeout bounds the LDAP operations that run AFTER a successful dial.
//
// DialWithDialer's timeout covers the TCP connect only. A directory that
// accepts the connection and then stalls — a wedged AD replica, a firewall that
// blackholes established flows, a server under GC pause — left Bind and Search
// with no deadline at all, so the request goroutine hung indefinitely holding a
// connection. Conn.SetTimeout applies to every subsequent request on the
// connection, which is what turns that hang into a bounded, classifiable
// network error (CHAOS-16 / F-11).
const ldapOpTimeout = 10 * time.Second

// ldapCacheEntry stores the result of one LDAP authentication attempt.
type ldapCacheEntry struct {
	ok     bool
	expiry time.Time
	// indeterminate marks an entry created from a backend FAILURE rather than
	// from a credential decision. It carries the short authIndeterminateTTL
	// instead of the configured CacheTTL, so an outage cannot outlive itself.
	indeterminate bool
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
// Caching (CHAOS-16 / F-11): a directory ANSWER — this credential is good, this
// credential is bad, this user does not exist — is cached for CacheTTL as
// before. A directory FAILURE is not: it says nothing about the credential, and
// pinning it for the full TTL is what used to make a momentary LDAP outage deny
// valid logins for five minutes after the directory came back. A failure denies
// the request (fail closed) and is remembered only for authIndeterminateTTL, as
// a load guard on a directory that is already struggling.
func (a *LDAPAuth) Verify(username, password string) bool {
	if password == "" {
		return false // never permit empty passwords
	}

	k := cacheKey(username, password)
	if ok, hit := a.cacheGet(k); hit {
		return ok
	}

	outcome, reason := a.verify(username, password)
	a.cacheSet(k, outcome)
	noteAuthOutcome(a.Name(), outcome, redactAuthReason(reason, a.cfg.URL))
	switch outcome {
	case backendAllow:
		logger.Printf("LDAP auth OK: user=%q", sanitizeLog(username))
	case backendDeny:
		logger.Printf("LDAP auth FAIL: user=%q", sanitizeLog(username))
	case backendIndeterminate:
		// No per-request log line: noteAuthBackendUnreachable already logs the
		// outage at a rate gate. Logging one line per denied request here would
		// turn an outage into a log flood, and the flood would be indexed as
		// authentication failures.
	}
	return outcome.allowed()
}

// connectAndBindService dials the directory, bounds every subsequent operation,
// optionally upgrades to STARTTLS, and binds the service account.
//
// Every failure it can produce is INFRASTRUCTURE — connectivity, our TLS, our
// service credentials — so a nil connection always means indeterminate, never a
// verdict on the end user's password. Returns (conn, "") on success and
// (nil, reason) on failure; the caller owns Close.
func (a *LDAPAuth) connectAndBindService() (*ldap.Conn, string) {
	tlsCfg := &tls.Config{InsecureSkipVerify: a.cfg.TLSSkipVerify} // #nosec G402 -- TLSSkipVerify is an explicit admin opt-in for self-signed LDAP certs

	// Dial with timeout to prevent DoS from hung LDAP servers.
	conn, err := ldap.DialURL(a.cfg.URL,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}),
	)
	if err != nil {
		logger.Printf("LDAP dial error: %v", err)
		return nil, fmt.Sprintf("dial: %v", err)
	}

	// Bound every operation that follows the dial. Without this a server that
	// accepts the connection and then stalls hangs the request goroutine
	// forever — the dial timeout above does not apply to Bind or Search.
	conn.SetTimeout(ldapOpTimeout)

	// Optional STARTTLS upgrade.
	if a.cfg.StartTLS && !strings.HasPrefix(strings.ToLower(a.cfg.URL), "ldaps") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			logger.Printf("LDAP STARTTLS error: %v", err)
			conn.Close()
			return nil, fmt.Sprintf("starttls: %v", err)
		}
	}

	// Bind with the service account so the user's DN can be searched for.
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			logger.Printf("LDAP service bind error: %v", err)
			conn.Close()
			return nil, fmt.Sprintf("service bind: %v", err)
		}
	} else if a.cfg.RequiredGroup != "" {
		logWarnf("LDAP: anonymous bind with RequiredGroup=%q — group resolution may fail", sanitizeLog(a.cfg.RequiredGroup))
	}
	return conn, ""
}

// verify searches for the user, binds as them, and classifies the result.
//
// The second return value is the reason text for an indeterminate outcome
// (empty otherwise). It is an infrastructure error — a dial failure, a stalled
// search — and never contains the supplied credential.
func (a *LDAPAuth) verify(username, password string) (authBackendOutcome, string) {
	conn, reason := a.connectAndBindService()
	if conn == nil {
		return backendIndeterminate, reason
	}
	defer conn.Close()

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
		return backendIndeterminate, fmt.Sprintf("search: %v", err)
	}
	if len(res.Entries) != 1 {
		// The directory answered; it just has no single match. That IS a
		// decision about this username (absent, or an ambiguous filter), and it
		// is stable until the directory changes — cacheable.
		logger.Printf("LDAP: user %q not found (entries=%d)", sanitizeLog(username), len(res.Entries))
		return backendDeny, ""
	}

	userDN := res.Entries[0].DN

	// Step 2: bind with user DN + password to verify credential.
	if err := conn.Bind(userDN, password); err != nil {
		// Only a credentials rejection is a decision. A network error on this
		// bind (the connection dropped mid-exchange, the op deadline expired)
		// is the same outage class as the dial — classifying it as "wrong
		// password" would re-introduce the finding at the last possible step.
		if isLDAPCredentialRejection(err) {
			return backendDeny, "" // wrong password — reason not logged to avoid credential leakage
		}
		logger.Printf("LDAP user bind error: %v", err)
		return backendIndeterminate, fmt.Sprintf("user bind: %v", err)
	}

	// Optional group membership check.
	if a.cfg.RequiredGroup != "" {
		if !a.isMember(res.Entries[0], a.cfg.RequiredGroup) {
			logger.Printf("LDAP: user %q not in required group %s", sanitizeLog(username), sanitizeLog(a.cfg.RequiredGroup))
			return backendDeny, ""
		}
	}

	return backendAllow, ""
}

// isLDAPCredentialRejection reports whether err is the directory REJECTING the
// credential rather than failing to process the request.
//
// LDAPResultInvalidCredentials (49) is the credential verdict — Active
// Directory also folds account-disabled, expired-password and locked-out into
// it via sub-codes, all of which are genuine decisions about this account.
// LDAPResultInappropriateAuthentication (48) is the directory refusing this
// form of authentication for this entry: also a decision, also stable.
// Everything else (ErrorNetwork, a timeout, unavailable, busy, unwilling to
// perform, a protocol error) is infrastructure. Unrecognised errors fall
// through to indeterminate deliberately: an unclassified failure must not
// become a cached denial, and the cost of being wrong in that direction is one
// extra bind per credential per authIndeterminateTTL.
func isLDAPCredentialRejection(err error) bool {
	return ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) ||
		ldap.IsErrorWithCode(err, ldap.LDAPResultInappropriateAuthentication)
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

// cacheSet stores the outcome. A determinate outcome (the directory answered)
// gets the configured CacheTTL; an indeterminate one (the directory failed)
// gets authIndeterminateTTL, so an outage is not remembered as a credential
// decision for minutes after it ends.
func (a *LDAPAuth) cacheSet(key string, outcome authBackendOutcome) {
	ttl := a.ttl
	if !outcome.determinate() {
		ttl = authIndeterminateTTL
	}
	a.mu.Lock()
	// Evict a random entry when the cache is full to prevent unbounded growth.
	if len(a.cache) >= maxAuthCacheSize {
		for k := range a.cache {
			delete(a.cache, k)
			break
		}
	}
	a.cache[key] = &ldapCacheEntry{
		ok:            outcome.allowed(),
		expiry:        time.Now().Add(ttl),
		indeterminate: !outcome.determinate(),
	}
	a.mu.Unlock()
}
