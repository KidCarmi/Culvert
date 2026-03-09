package main

import (
	"crypto/tls"
	"fmt"
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
	return &LDAPAuth{cfg: cfg, ttl: ttl, cache: map[string]*ldapCacheEntry{}}, nil
}

func (a *LDAPAuth) Name() string { return "ldap" }

// Verify authenticates user against LDAP using a two-step bind:
//  1. Bind with service account to locate the user's DN.
//  2. Bind with user DN + supplied password to verify the credential.
//
// Optionally checks group membership if RequiredGroup is configured.
// Results are cached for CacheTTL to protect the LDAP server from load.
func (a *LDAPAuth) Verify(username, password string) bool {
	if password == "" {
		return false // never permit empty passwords
	}

	k := cacheKey(username, password)
	if ok, hit := a.cacheGet(k); hit {
		return ok
	}

	ok := a.verify(username, password)
	a.cacheSet(k, ok)
	if ok {
		logger.Printf("LDAP auth OK: user=%s", username)
	} else {
		logger.Printf("LDAP auth FAIL: user=%s", username)
	}
	return ok
}

func (a *LDAPAuth) verify(username, password string) bool {
	tlsCfg := &tls.Config{InsecureSkipVerify: a.cfg.TLSSkipVerify} //nolint:gosec

	// Dial.
	conn, err := ldap.DialURL(a.cfg.URL, ldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		logger.Printf("LDAP dial error: %v", err)
		return false
	}
	defer conn.Close()

	// Optional STARTTLS upgrade.
	if a.cfg.StartTLS && !strings.HasPrefix(strings.ToLower(a.cfg.URL), "ldaps") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			logger.Printf("LDAP STARTTLS error: %v", err)
			return false
		}
	}

	// Step 1: bind with service account to search for the user's DN.
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			logger.Printf("LDAP service bind error: %v", err)
			return false
		}
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
		return false
	}
	if len(res.Entries) != 1 {
		logger.Printf("LDAP: user %q not found (entries=%d)", username, len(res.Entries))
		return false
	}

	userDN := res.Entries[0].DN

	// Step 2: bind with user DN + password to verify credential.
	if err := conn.Bind(userDN, password); err != nil {
		return false // wrong password — not logged to avoid credential leakage
	}

	// Optional group membership check.
	if a.cfg.RequiredGroup != "" {
		if !a.isMember(res.Entries[0], a.cfg.RequiredGroup) {
			logger.Printf("LDAP: user %q not in required group %s", username, a.cfg.RequiredGroup)
			return false
		}
	}

	return true
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
