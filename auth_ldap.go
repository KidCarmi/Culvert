package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// ldapTLSConfig builds the client TLS config for a directory connection,
// deriving ServerName from the configured URL's hostname. This is
// load-bearing for the StartTLS path: go-ldap's Conn.StartTLS hands the
// config verbatim to tls.Client, and crypto/tls refuses a handshake with
// neither ServerName nor InsecureSkipVerify — without it, the RECOMMENDED
// secure StartTLS configuration (startTls=true, tlsSkipVerify=false) could
// never authenticate. ldaps:// dials fill ServerName from the dial address
// on their own, so setting it explicitly only changes the StartTLS path.
func ldapTLSConfig(rawURL string, skipVerify bool) *tls.Config {
	cfg := &tls.Config{InsecureSkipVerify: skipVerify} // #nosec G402 -- skipVerify is an explicit admin opt-in for self-signed LDAP certs
	if u, err := url.Parse(rawURL); err == nil && u.Hostname() != "" {
		cfg.ServerName = u.Hostname()
	}
	return cfg
}

// ── Directory round-trip bounds (CHAOS-57) ───────────────────────────────────
//
// ldapRoundTripBudget bounds ONE directory round trip END TO END — dial,
// optional StartTLS, service bind, search, user bind — as a single envelope
// rather than a per-step allowance. It is deliberately the SAME budget this
// process already gives one identity resolution against an OIDC IdP
// (`auth_oidc.go`, `auth_oidc_flow.go`: `http.Client{Timeout: 10s}` covers
// dial + handshake + request + response). Two identity backends answering the
// same question on the same request path must not disagree about how long that
// decision may take — the CHAOS-53 rule for the two body-scan back ends,
// applied to the two credential back ends. Dial is a COMPONENT of the
// envelope, so the historical 10 s dial timeout becomes the ceiling for the
// whole flow instead of for its first step.
//
// It is a var, not a const, purely so the chaos gates can drive it down
// instead of sleeping for the production budget. Never mutated in production.
var ldapRoundTripBudget = 10 * time.Second

// errLDAPBudgetExhausted is returned when the round-trip envelope is spent
// before an operation could be attempted. It is deliberately NOT an
// *ldap.Error: ldapUserBindIsUnreachable treats a non-*ldap.Error as
// unreachable (fail safe), which is the correct classification — a directory
// that consumed the whole budget without answering did not answer.
var errLDAPBudgetExhausted = errors.New("ldap: directory round-trip budget exhausted")

// ldapCloseTimeout bounds a teardown that happens after the round-trip budget
// is already spent, so the close itself cannot become the next unbounded wait.
const ldapCloseTimeout = time.Second

// armLDAPConnWatchdog closes conn if it is still open after d, returning the
// canceller.
//
// This is the SECOND of two non-redundant layers, and it exists because
// go-ldap's own request timer structurally cannot reach every blocking wait.
// `conn.SetTimeout` arms a per-message timer that covers Bind, Search and the
// StartTLS extended-RESPONSE wait; it does NOT cover the post-response
// `tls.Conn.Handshake()` that `Conn.StartTLS` runs on the RAW socket, outside
// the message loop. A directory that ACKs StartTLS and then never negotiates
// TLS therefore hangs forever with SetTimeout armed — proven directly against
// the library by TestChaos57_SetTimeoutDoesNotBoundStartTLSHandshake, so a
// go-ldap upgrade that changed this would fail the build rather than silently
// leave the backstop guarding nothing.
//
// CLOSING is what unblocks a deadline-less read — the same reason
// idleCopyCounted hard-closes both conns on idle (CHAOS-03) rather than
// relying on a deadline the peer goroutine may not be able to observe.
// go-ldap's Close is idempotent (setClosing) and takes messageMutex, which no
// in-flight operation holds across its network wait (sendMessageWithFlags
// releases it before waiting; the StartTLS handshake runs with it released),
// so firing this from a timer goroutine cannot deadlock the operation it is
// rescuing.
func armLDAPConnWatchdog(conn *ldap.Conn, d time.Duration, backend string) func() {
	t := time.AfterFunc(d, func() {
		// Bounded reason class only: the directory's address and any
		// server-controlled diagnostic stay out of this line, which is a
		// per-request path.
		logger.Printf("LDAP: directory %q did not complete an operation within %s — closing the connection so the request goroutine is released",
			sanitizeLog(backend), d)
		_ = conn.Close() //nolint:errcheck // best-effort rescue close
	})
	return func() { t.Stop() }
}

// errLDAPAccountRejected marks a user-bind the directory ANSWERED but did not
// accept for a reason that is not "wrong password" — a locked, disabled or
// expired account, an entry with no bindable credential, a referral. It is the
// LDAP twin of auth_oidc.go's errIntrospectClient and exists for the same
// reason: the directory is demonstrably REACHABLE, so such a rejection must
// never arm the provider-wide unreachable cooldown.
//
// Without this split an unauthenticated attacker who knows a single username —
// or who simply brute-forces one account past the directory's own lockout
// threshold — can make every subsequent bind for that account answer with a
// non-49 result code, arming the CHAOS-47 gate on every attempt and denying
// authentication for EVERY OTHER USER without the proxy ever dialing the
// directory. On an in-line Secure Web Gateway that is a full egress outage
// driven from outside the trust boundary. See ldapUserBindIsUnreachable.
var errLDAPAccountRejected = errors.New("ldap: directory rejected the account (not a reachability failure)")

// go-ldap reports its OWN client-side faults (dial failure, malformed packet,
// unexpected message) as *ldap.Error values in a reserved high code space
// beginning at ErrorNetwork. RFC 4511 result codes a server can actually put on
// the wire are all below it, so the range is the reliable "did the directory
// answer at all?" discriminator.
const (
	ldapClientErrorFloor = ldap.ErrorNetwork       // 200
	ldapClientErrorCeil  = ldap.ErrorEmptyPassword // 206
)

// ldapUserBindIsUnreachable reports whether a step-2 user-bind error means the
// DIRECTORY could not be reached, as opposed to the directory answering with a
// verdict about that one account.
//
// The distinction decides whether the error is allowed to arm the CHAOS-47
// provider-wide cooldown (auth_backend_health.go), so it is a blast-radius
// control, not a cosmetic classification:
//
//   - Not an *ldap.Error at all (context cancellation, a raw net error) ⇒
//     unreachable. Fail safe: an unclassifiable fault is treated as the backend's.
//   - A go-ldap client-space code (200–206, incl. ErrorNetwork) ⇒ unreachable.
//     Nothing came back from the server.
//   - LDAPResultBusy (51) / LDAPResultUnavailable (52) ⇒ unreachable. The server
//     answered, but only to say it cannot serve — the exact analogue of the
//     HTTP 429/408 carve-out isIntrospectClientError makes on the OIDC leg, and
//     not something a single account's state can provoke.
//   - Every other result code ⇒ REACHABLE. 49 (invalidCredentials) is a wrong
//     password; 19 (constraintViolation), 48 (inappropriateAuthentication) and
//     53 (unwillingToPerform) are how OpenLDAP/ppolicy, FreeIPA and AD report a
//     locked, disabled, expired or non-bindable account. All of them are
//     attacker-provokable per account, so none may gate.
func ldapUserBindIsUnreachable(err error) bool {
	var le *ldap.Error
	if !errors.As(err, &le) {
		return true
	}
	switch le.ResultCode {
	case ldap.LDAPResultBusy, ldap.LDAPResultUnavailable:
		return true
	}
	return le.ResultCode >= ldapClientErrorFloor && le.ResultCode <= ldapClientErrorCeil
}

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
// id is populated only by the identity-resolving (IdP registry) engine; the
// legacy boolean provider stores nil. Cached identities are only ever handed
// out via cloneIdentity so callers can't mutate the cached groups slice.
type ldapCacheEntry struct {
	ok     bool
	id     *Identity
	expiry time.Time
}

// ldapIdentityAttrs names the directory attributes the identity-resolving
// engine maps into Identity fields (ADR-0027). Zero value = legacy mode: the
// engine requests only dn+memberOf and never builds an Identity, keeping the
// legacy YAML provider's wire behavior and semantics byte-identical.
type ldapIdentityAttrs struct {
	email string // Identity.Email source (default "mail")
	name  string // Identity.Name source (default "displayName"; falls back to cn, then username)
	group string // Identity.Groups source (default "memberOf"; values kept verbatim — full group DNs)
}

func (a ldapIdentityAttrs) enabled() bool { return a.group != "" }

// LDAPAuth authenticates users against an LDAP / Active Directory server.
// It is both the legacy boolean provider (Verify) and the shared directory
// engine behind the registry LDAPIdPProvider (resolveIdentity) — the
// dial/StartTLS/service-bind/search/user-bind flow and the CHAOS-47 gating
// are deliberately single-sourced here.
type LDAPAuth struct {
	cfg   LDAPConfig
	ttl   time.Duration
	attrs ldapIdentityAttrs // zero = legacy boolean mode
	// backendName labels this directory on the identity_backend health plane
	// ("ldap" for the legacy provider, "ldap:<profile-id>" for registry
	// profiles — mirroring the CHAOS-49 "oidc:<profile-id>" convention).
	backendName string
	// providerID is the IdP profile ID for registry engines ("" = legacy);
	// stamped as Identity.Provider so authSource resolves to the profile.
	providerID string
	mu         sync.Mutex
	cache      map[string]*ldapCacheEntry // key = cacheKey(user, pass)

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
	return &LDAPAuth{cfg: cfg, ttl: ttl, backendName: "ldap", cache: map[string]*ldapCacheEntry{}}, nil
}

func (a *LDAPAuth) Name() string { return "ldap" }

// searchAttributes returns the attribute list requested from the directory.
// Legacy mode keeps the historical dn+memberOf request byte-identical; the
// identity-resolving engine adds the configured identity attributes plus cn
// (the display-name fallback).
func (a *LDAPAuth) searchAttributes() []string {
	if !a.attrs.enabled() {
		return []string{"dn", "memberOf"}
	}
	attrs := []string{"dn", a.attrs.group, "cn"}
	if a.attrs.email != "" {
		attrs = append(attrs, a.attrs.email)
	}
	if a.attrs.name != "" && a.attrs.name != "cn" {
		attrs = append(attrs, a.attrs.name)
	}
	return attrs
}

// groupAttribute is the attribute consulted for group membership — both for
// Identity.Groups and for the RequiredGroup direct-membership check.
func (a *LDAPAuth) groupAttribute() string {
	if a.attrs.enabled() {
		return a.attrs.group
	}
	return "memberOf"
}

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
	_, ok := a.authenticate(username, password)
	return ok
}

// resolveIdentity is the identity-resolving twin of Verify, consumed by the
// registry LDAPIdPProvider. Same cache, same gate, same fail-closed posture;
// the only difference is that the resolved Identity is returned (cloned, so
// callers can't mutate the cached groups slice).
func (a *LDAPAuth) resolveIdentity(username, password string) (*Identity, bool) {
	id, ok := a.authenticate(username, password)
	if !ok {
		return nil, false
	}
	return cloneIdentity(id), true
}

// authenticate runs the shared cache → gate → directory round-trip pipeline.
// The returned Identity is non-nil only for identity-resolving engines
// (attrs.enabled()); the legacy boolean provider always yields (nil, ok).
func (a *LDAPAuth) authenticate(username, password string) (*Identity, bool) {
	if password == "" {
		return nil, false // never permit empty passwords
	}

	k := cacheKey(username, password)
	if e, hit := a.cacheGet(k); hit {
		return e.id, e.ok
	}

	if !a.gate.allow() {
		// Directory is in its unreachable cooldown. Deny — the posture is
		// fail-closed — but without a dial, so a hard-down directory cannot
		// turn every request into a full dial timeout.
		noteAuthBackendGatedDenial()
		return nil, false
	}

	id, ok, err := a.verify(username, password)
	if err != nil {
		a.noteVerifyError(err)
		return nil, false
	}
	a.gate.recordReachable()
	noteAuthBackendReachable(a.backendName)

	a.cacheSet(k, ok, id)
	if ok {
		logger.Printf("LDAP auth OK: user=%q", sanitizeLog(username))
	} else {
		logger.Printf("LDAP auth FAIL: user=%q", sanitizeLog(username))
	}
	return id, ok
}

// noteVerifyError applies the CHAOS-47 gating policy to a verify() failure.
//
// Every path here denies the in-flight request — the posture is fail-closed and
// unconditional. What is decided is only whether OTHER users pay for it: an
// account-scoped rejection is the directory answering, so it must not arm the
// provider-wide cooldown nor be reported as an outage, exactly as
// ResolveIdentity does for errIntrospectClient on the OIDC leg. It is also not
// cached, so a since-unlocked account authenticates on its very next attempt.
//
// An account rejection is also POSITIVE evidence of reachability, and must be
// recorded as such — not merely excused from arming the gate. Skipping the
// clear leaves a second, subtler denial of service: once a genuine outage has
// armed the gate, the attacker's rejection consumes each half-open probe
// without ever clearing it, so the gate re-arms for another cooldown and every
// other user stays denied. A client attempting one locked account in a loop
// would then hold a fully recovered directory in a permanent outage — turning a
// three-second network blip into an indefinite one. `recordReachable` is
// documented as "the backend answered, authoritatively, in either direction",
// and this is exactly that. (Found by Codex review on PR #1077.)
func (a *LDAPAuth) noteVerifyError(err error) {
	if errors.Is(err, errLDAPAccountRejected) {
		a.gate.recordReachable()
		noteAuthBackendReachable(a.backendName)
		logger.Printf("LDAP auth DENY (directory rejected the account) — not a backend outage; " +
			"the answer is evidence the directory is reachable, so any cooldown is cleared")
		return
	}
	a.gate.recordUnavailable()
	noteAuthBackendUnavailable(a.backendName, err.Error())
}

// dialBounded dials the directory and arms BOTH round-trip bounds, returning
// the connection and the watchdog canceller (which the caller must defer).
//
// The whole round trip runs under ONE envelope (CHAOS-57). A directory that
// ACCEPTS the connection and then stops answering — an overloaded server, a
// firewall that drops after the handshake, a half-open socket after a peer
// reboot — used to block in the REQUEST goroutine, forever: go-ldap's default
// requestTimeout is 0, which arms no timer at all, so Bind and Search waited on
// a response that never came. Every such request pinned a goroutine, an FD and
// a per-IP connection slot until the process was restarted, and because
// CHAOS-47's provider-wide cooldown is armed only by an error that RETURNS, the
// one mitigation designed for an unreachable directory could never see this
// fault class.
func (a *LDAPAuth) dialBounded(tlsCfg *tls.Config) (*ldap.Conn, func(), error) {
	deadline := time.Now().Add(ldapRoundTripBudget)
	conn, err := ldap.DialURL(a.cfg.URL,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(&net.Dialer{Timeout: ldapRoundTripBudget}),
	)
	if err != nil {
		logger.Printf("LDAP dial error: %v", err)
		return nil, nil, fmt.Errorf("dial: %w", err)
	}

	remaining := time.Until(deadline)
	if remaining <= 0 {
		logger.Printf("LDAP: dial consumed the whole %s round-trip budget", ldapRoundTripBudget)
		// Bound the teardown too. go-ldap's Close waits for the message loop to
		// confirm its quit, and it bounds that wait with the SAME requestTimeout
		// this function otherwise sets below — which is still 0 here. The loop is
		// healthy on a freshly dialed conn so it confirms promptly, but leaving
		// one unbounded wait inside a change whose whole purpose is bounding them
		// is the shape this sweep exists to remove.
		conn.SetTimeout(ldapCloseTimeout)
		conn.Close() //nolint:errcheck // best-effort close of a connection we will not use
		return nil, nil, fmt.Errorf("dial: %w", errLDAPBudgetExhausted)
	}
	// Layer 1: go-ldap's own per-message timer. Every message round trip now
	// fails with an ErrorNetwork the CHAOS-47 classifier already reads as
	// unreachable, so a stall arms the cooldown exactly like a refused dial.
	conn.SetTimeout(remaining)
	// Layer 2: the envelope backstop. NOT redundant with layer 1 — see
	// armLDAPConnWatchdog for the StartTLS handshake it is the only bound on.
	return conn, armLDAPConnWatchdog(conn, remaining, a.backendName), nil
}

// verify performs one directory round trip.
//
// The returned error is reserved for INFRASTRUCTURE failure — the directory
// could not be reached or could not answer. `(nil, false, nil)` means the
// directory answered and the answer was "no". Only the latter is cacheable, so
// the split is load-bearing rather than stylistic; see authenticate. The
// Identity is non-nil only on success and only for identity-resolving engines.
func (a *LDAPAuth) verify(username, password string) (*Identity, bool, error) { //nolint:gocognit,cyclop // the two-step-bind decision tree with its blast-radius error classification is inherently branchy; single-sourced for legacy + registry engines
	tlsCfg := ldapTLSConfig(a.cfg.URL, a.cfg.TLSSkipVerify)

	conn, stopWatchdog, err := a.dialBounded(tlsCfg)
	if err != nil {
		return nil, false, err
	}
	// LIFO: stop the watchdog first, then close — so the timer can never fire
	// against a connection this call is already tearing down.
	defer conn.Close() //nolint:errcheck // best-effort close of a bind connection
	defer stopWatchdog()

	// Optional STARTTLS upgrade.
	if a.cfg.StartTLS && !strings.HasPrefix(strings.ToLower(a.cfg.URL), "ldaps") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			logger.Printf("LDAP STARTTLS error: %v", err)
			return nil, false, fmt.Errorf("starttls: %w", err)
		}
	}

	// Step 1: bind with service account to search for the user's DN.
	// A service-bind failure is never a statement about the END USER's
	// credential — it is a wrong/expired service account or a directory that
	// stopped answering — so it is infrastructure, not a deny to remember.
	if a.cfg.BindDN != "" {
		if err := conn.Bind(a.cfg.BindDN, a.cfg.BindPassword); err != nil {
			logger.Printf("LDAP service bind error: %v", err)
			return nil, false, fmt.Errorf("service bind: %w", err)
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
		a.searchAttributes(),
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		logger.Printf("LDAP search error: %v", err)
		return nil, false, fmt.Errorf("search: %w", err)
	}
	if len(res.Entries) != 1 {
		// The directory answered: no such user (or an ambiguous filter). That
		// is an authoritative deny and stays cacheable.
		logger.Printf("LDAP: user %q not found (entries=%d)", username, len(res.Entries))
		return nil, false, nil
	}

	userDN := res.Entries[0].DN

	// Step 2: bind with user DN + password to verify credential.
	//
	// Three outcomes, and the split between the last two is a blast-radius
	// control (see ldapUserBindIsUnreachable):
	//
	//  1. code 49 (invalidCredentials): the directory rejected the password.
	//     Authoritative, cacheable, unremarkable.
	//  2. any other code the SERVER produced — 19/48/53 and friends, i.e. a
	//     locked, disabled, expired or non-bindable account: the directory
	//     answered, so it is demonstrably reachable. Deny closed, but do NOT
	//     let it arm the provider-wide unreachable cooldown, because the
	//     account state behind it is chosen by whoever is attempting the bind.
	//  3. a transport/client fault or a busy/unavailable server: genuine
	//     infrastructure. Deny closed AND gate.
	if err := conn.Bind(userDN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return nil, false, nil // wrong password — not logged to avoid credential leakage
		}
		// The directory's diagnostic text is server-controlled, so it goes
		// through the CWE-117 barrier before it reaches the log.
		if !ldapUserBindIsUnreachable(err) {
			logger.Printf("LDAP user bind rejected by the directory: %q", sanitizeLog(err.Error()))
			return nil, false, fmt.Errorf("%w: %w", errLDAPAccountRejected, err)
		}
		logger.Printf("LDAP user bind error: %q", sanitizeLog(err.Error()))
		return nil, false, fmt.Errorf("user bind: %w", err)
	}

	// Optional group membership check (provider-level legacy gate; the modern
	// authorization path is Access Rules over Identity.Groups).
	if a.cfg.RequiredGroup != "" {
		if !a.isMember(res.Entries[0], a.cfg.RequiredGroup) {
			logger.Printf("LDAP: user %q not in required group %s", username, a.cfg.RequiredGroup)
			return nil, false, nil
		}
	}

	return a.buildIdentity(username, res.Entries[0]), true, nil
}

// buildIdentity maps the directory entry into the normalised Identity
// (identity-resolving engines only; legacy boolean mode returns nil).
// Canonical semantics (ADR-0027): Sub = full user DN (stable, unambiguous),
// Groups = configured group attribute verbatim (full group DNs, direct
// membership only), Provider = IdP profile ID so authSource resolves to
// "ldap:<profile-id>".
func (a *LDAPAuth) buildIdentity(username string, entry *ldap.Entry) *Identity {
	if !a.attrs.enabled() {
		return nil
	}
	name := ""
	if a.attrs.name != "" {
		name = entry.GetAttributeValue(a.attrs.name)
	}
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}
	if name == "" {
		name = username
	}
	email := ""
	if a.attrs.email != "" {
		email = entry.GetAttributeValue(a.attrs.email)
	}
	return &Identity{
		Sub:      entry.DN,
		Email:    email,
		Name:     name,
		Groups:   append([]string(nil), entry.GetAttributeValues(a.attrs.group)...),
		Provider: a.providerID,
	}
}

// isMember checks the group attribute for the required group DN.
func (a *LDAPAuth) isMember(entry *ldap.Entry, groupDN string) bool {
	for _, v := range entry.GetAttributeValues(a.groupAttribute()) {
		if strings.EqualFold(v, groupDN) {
			return true
		}
	}
	return false
}

func (a *LDAPAuth) cacheGet(key string) (e ldapCacheEntry, hit bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if got, found := a.cache[key]; found && time.Now().Before(got.expiry) {
		return *got, true
	}
	return ldapCacheEntry{}, false
}

func (a *LDAPAuth) cacheSet(key string, ok bool, id *Identity) {
	a.mu.Lock()
	// Evict a random entry when the cache is full to prevent unbounded growth.
	if len(a.cache) >= maxAuthCacheSize {
		for k := range a.cache {
			delete(a.cache, k)
			break
		}
	}
	a.cache[key] = &ldapCacheEntry{ok: ok, id: id, expiry: time.Now().Add(a.ttl)}
	a.mu.Unlock()
}
