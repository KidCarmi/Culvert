package main

// ui_auth_ldap.go — Admin API surface for the LDAP/AD IdP (ADR-0027, Slice 3):
//
//   POST /api/idp/test               — staged, candidate-based directory test
//   GET  /api/idp/legacy-ldap        — non-secret summary of the legacy YAML block
//   POST /api/idp/legacy-ldap/import — explicit one-time import into the registry
//
// The test endpoint is the ONLY place Culvert actuates an admin-supplied LDAP
// endpoint on demand: Admin-only, strict JSON, bounded timeouts, sanitized
// errors, audited. Test-user passwords are transient — never persisted,
// logged, cached, or audited.

import (
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	ldap "github.com/go-ldap/ldap/v3"
)

// ─── Legacy YAML config retention (for summary + import) ─────────────────────

var legacyLDAPYAMLState struct {
	mu  sync.RWMutex
	cfg *LDAPConfig
}

// setLegacyLDAPYAMLConfig records the resolved FileConfig.LDAP block at
// startup so the admin API can summarize and import it. Read-only retention —
// the YAML file itself is never re-read or modified.
func setLegacyLDAPYAMLConfig(c LDAPConfig) {
	cp := c
	legacyLDAPYAMLState.mu.Lock()
	legacyLDAPYAMLState.cfg = &cp
	legacyLDAPYAMLState.mu.Unlock()
}

func legacyLDAPYAMLConfig() *LDAPConfig {
	legacyLDAPYAMLState.mu.RLock()
	defer legacyLDAPYAMLState.mu.RUnlock()
	if legacyLDAPYAMLState.cfg == nil {
		return nil
	}
	cp := *legacyLDAPYAMLState.cfg
	return &cp
}

// ─── GET /api/idp/legacy-ldap ────────────────────────────────────────────────

// apiIdPLegacyLDAP reports the legacy YAML LDAP block's presence and
// non-secret settings, plus its authority state, so the GUI can offer the
// explicit "Import legacy LDAP configuration" migration.
func apiIdPLegacyLDAP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	c := legacyLDAPYAMLConfig()
	if c == nil {
		jsonOK(w, map[string]any{"present": false})
		return
	}
	_, legacyActive := cfg.snapshotAuthBackend().provider.(*LDAPAuth)
	jsonOK(w, map[string]any{
		"present": true,
		"active":  legacyActive,
		// retired = the DURABLE authority cutover (survives registry
		// disable/delete + restarts); shadowed = retired or an enabled
		// registry LDAP profile currently exists (the GUI banner condition).
		"retired":                  legacyLDAPRetired(),
		"shadowed":                 legacyLDAPRetired() || (idpRegistry != nil && idpRegistry.HasEnabledLDAP()),
		"url":                      c.URL,
		"baseDn":                   c.BaseDN,
		"bindDn":                   c.BindDN,
		"bindCredentialConfigured": c.BindPassword != "",
		"userFilter":               c.UserFilter,
		"requiredGroup":            c.RequiredGroup,
		"startTls":                 c.StartTLS,
		"tlsSkipVerify":            c.TLSSkipVerify,
		"cacheTtlSeconds":          int(c.CacheTTL / time.Second),
	})
}

// ─── POST /api/idp/legacy-ldap/import ────────────────────────────────────────

// apiIdPLegacyLDAPImport creates a DISABLED LDAP IdP profile from the legacy
// YAML block, copying every security-effective field (including the bind
// credential, which never transits the browser). The admin then tests and
// enables it — the deterministic, downgrade-safe migration path. The YAML
// file is never modified.
func apiIdPLegacyLDAPImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	c := legacyLDAPYAMLConfig()
	if c == nil {
		http.Error(w, "no legacy YAML ldap configuration is present", http.StatusNotFound)
		return
	}
	p := &IdPProfile{
		Name:    "Imported legacy LDAP",
		Type:    IdPTypeLDAP,
		Enabled: false, // explicit test-then-enable; never activates blind
		LDAP:    legacyLDAPToProfileConfig(c),
	}
	if err := idpRegistry.Upsert(p); err != nil {
		http.Error(w, "legacy ldap config cannot be imported: "+err.Error(), idpMutationErrorStatus(err))
		return
	}
	_ = publishCurrentConfigSnapshot()
	auditEventDiff(r, "idp.import", p.ID, "imported legacy YAML LDAP configuration", nil, auditIdPProfile(p))
	logger.Printf("UI: legacy YAML LDAP imported as IdP profile id=%q (disabled; test-then-enable)", sanitizeLog(p.ID))
	jsonOK(w, publicIdPProfile(p))
}

// legacyLDAPToProfileConfig maps the YAML LDAPConfig into the profile shape,
// normalizing the one contradiction the legacy schema tolerated (StartTLS set
// on an ldaps:// URL was silently ignored; the profile validator rejects it).
func legacyLDAPToProfileConfig(c *LDAPConfig) *LDAPProfileConfig {
	startTLS := c.StartTLS
	if strings.HasPrefix(strings.ToLower(c.URL), "ldaps://") {
		startTLS = false
	}
	ttl := int(c.CacheTTL / time.Second)
	if c.CacheTTL <= 0 {
		ttl = 0 // profile default (300s) == legacy default
	}
	return &LDAPProfileConfig{
		URL:           c.URL,
		StartTLS:      startTLS,
		TLSSkipVerify: c.TLSSkipVerify,
		BindDN:        c.BindDN,
		BindPassword:  c.BindPassword,
		BaseDN:        c.BaseDN,
		UserFilter:    c.UserFilter, // empty keeps the shared (sAMAccountName=%s) default
		RequiredGroup: c.RequiredGroup,
		CacheTTLSeconds: func() int {
			if ttl == defLDAPCacheTTLSecs {
				return 0
			}
			return ttl
		}(),
	}
}

// ─── POST /api/idp/test ──────────────────────────────────────────────────────

// ldapTestStep is one stage of the directory test. Error text is sanitized
// and bounded; Action tells the operator what to do about a failure.
type ldapTestStep struct {
	Name       string `json:"name"`
	Label      string `json:"label"`
	OK         bool   `json:"ok"`
	Skipped    bool   `json:"skipped,omitempty"`
	DurationMs int64  `json:"durationMs,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Error      string `json:"error,omitempty"`
	Action     string `json:"action,omitempty"`
}

// ldapTestIdentity summarizes a successful optional user-auth test. Groups is
// a count plus a bounded sample — never the full membership dump.
type ldapTestIdentity struct {
	Sub        string   `json:"sub"`
	Email      string   `json:"email,omitempty"`
	Name       string   `json:"name,omitempty"`
	GroupCount int      `json:"groupCount"`
	Groups     []string `json:"groups,omitempty"` // first ldapTestMaxGroupSample entries
}

type ldapTestReport struct {
	OK       bool              `json:"ok"`
	Steps    []ldapTestStep    `json:"steps"`
	Identity *ldapTestIdentity `json:"identity,omitempty"`
}

const (
	ldapTestDialTimeout    = 5 * time.Second
	ldapTestOpTimeout      = 8 * time.Second
	ldapTestMaxErrLen      = 200
	ldapTestMaxGroupSample = 8
)

// ldapTestTotalBudget is the whole-test envelope (CHAOS-57). ldapTestOpTimeout
// bounds each LDAP MESSAGE round trip, but go-ldap runs the post-StartTLS
// tls.Handshake() on the raw socket outside its request timer, so a directory
// that ACKs StartTLS and then never negotiates TLS hangs with SetTimeout armed.
// This is generous relative to the sum of the stages because an admin
// diagnostic should report a slow directory rather than clip it; its job is to
// guarantee the handler goroutine is released at all.
//
// A var, not a const, purely so the chaos gates can drive it down instead of
// sleeping for the production budget. Never mutated in production.
var ldapTestTotalBudget = 45 * time.Second

// apiIdPTestRequest is the strict request shape for POST /api/idp/test.
// Profile is a full IdP profile candidate (the same shape POST/PUT /api/idp
// accepts) — the test runs BEFORE persistence. An empty ldap.bindPassword on
// a candidate that names an existing profile id reuses the stored credential,
// so testing an edit never requires retyping the secret. TestUsername/
// TestPassword optionally run the full identity test; the password is
// transient by contract.
type apiIdPTestRequest struct {
	Profile      *IdPProfile `json:"profile"`
	TestUsername string      `json:"testUsername,omitempty"`
	TestPassword string      `json:"testPassword,omitempty"`
}

// apiIdPTest runs the staged, candidate-based directory test.
func apiIdPTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var body apiIdPTestRequest
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	p := body.Profile
	if p == nil {
		http.Error(w, "profile is required", http.StatusBadRequest)
		return
	}
	if p.Type != IdPTypeLDAP {
		http.Error(w, "only ldap profiles support the directory test", http.StatusBadRequest)
		return
	}
	if p.LDAP == nil {
		http.Error(w, "ldap config is required", http.StatusBadRequest)
		return
	}
	resolveTestBindCredential(p)
	if err := validateLDAPProfileConfig(p.LDAP); err != nil {
		http.Error(w, "ldap: "+err.Error(), http.StatusBadRequest)
		return
	}
	report := runLDAPDirectoryTest(p.LDAP, body.TestUsername, body.TestPassword)
	// Audit the decision category only — never credentials or raw server blobs.
	auditEvent(r, "idp.test", auditObjectForIdPTest(p), ldapTestAuditDetail(report, body.TestUsername != ""))
	jsonOK(w, report)
}

func auditObjectForIdPTest(p *IdPProfile) string {
	if p.ID != "" {
		return p.ID
	}
	return p.Name
}

func ldapTestAuditDetail(rep *ldapTestReport, userTest bool) string {
	outcome := "ok"
	if !rep.OK {
		outcome = "failed"
		for _, s := range rep.Steps {
			if !s.OK && !s.Skipped {
				outcome = "failed:" + s.Name
				break
			}
		}
	}
	if userTest {
		outcome += " (with user auth test)"
	}
	return outcome
}

// resolveTestBindCredential fills an empty candidate bind credential from the
// stored profile named by the candidate's id — the write-only-secret analogue
// for the test path (the GET projection never returned it to the browser).
func resolveTestBindCredential(p *IdPProfile) {
	if p.LDAP.BindPassword != "" || p.ID == "" {
		return
	}
	if stored := idpRegistry.Get(p.ID); stored != nil && stored.Type == IdPTypeLDAP && stored.LDAP != nil {
		p.LDAP.BindPassword = stored.LDAP.BindPassword
	}
}

// ldapTestErrText sanitizes server-controlled error text (CWE-117) and bounds
// its length so a hostile directory can't stuff the response.
func ldapTestErrText(err error) string {
	if err == nil {
		return ""
	}
	s := sanitizeLog(err.Error())
	if len(s) > ldapTestMaxErrLen {
		s = s[:ldapTestMaxErrLen] + "…"
	}
	return s
}

// ldapDialErrorAction maps a dial/TLS failure to an actionable operator hint.
func ldapDialErrorAction(err error) string {
	msg := err.Error()
	switch {
	case strings.Contains(msg, "x509:") && strings.Contains(msg, "not valid for"):
		return "TLS certificate hostname mismatch — the certificate does not cover this server name."
	case strings.Contains(msg, "x509:"):
		return "TLS certificate is not trusted — install the directory's CA on this appliance or fix the certificate."
	case strings.Contains(msg, "connection refused"):
		return "Directory unreachable — check the server address, port, and firewall."
	case strings.Contains(msg, "timeout") || strings.Contains(msg, "deadline"):
		return "Timeout — the directory did not answer; check network reachability and the port."
	case strings.Contains(msg, "no such host"):
		return "DNS lookup failed — check the server hostname."
	default:
		return "Directory unreachable — check the server address, transport security, and network path."
	}
}

// runLDAPDirectoryTest executes the staged connection test against a
// validated candidate config. Every stage is bounded; a stage failure stops
// the pipeline (later stages are reported as skipped).
func runLDAPDirectoryTest(pc *LDAPProfileConfig, testUsername, testPassword string) *ldapTestReport {
	rep := &ldapTestReport{}
	conn, stopWatchdog, ok := ldapTestConnect(rep, pc)
	if !ok {
		return rep
	}
	// LIFO: stop the watchdog first, then close — so the timer can never fire
	// against a connection the test is already tearing down.
	defer conn.Close() //nolint:errcheck // best-effort close of a test connection
	defer stopWatchdog()

	if !ldapTestServiceBind(rep, conn, pc) {
		return rep
	}
	if !ldapTestBaseDN(rep, conn, pc) {
		return rep
	}
	ldapTestUserLookup(rep, conn, pc, testUsername, testPassword)
	rep.OK = true
	for _, s := range rep.Steps {
		if !s.OK && !s.Skipped {
			rep.OK = false
			break
		}
	}
	return rep
}

// ldapTestConnect performs the reachable + transport-security stages.
//
// It returns the connection AND the canceller for the whole-test watchdog; the
// caller must defer the canceller. The watchdog is armed here rather than in
// runLDAPDirectoryTest because the StartTLS stage — the one stage no per-message
// timer can bound — runs inside this function (CHAOS-57).
func ldapTestConnect(rep *ldapTestReport, pc *LDAPProfileConfig) (*ldap.Conn, func(), bool) {
	isLDAPS := strings.HasPrefix(strings.ToLower(pc.URL), "ldaps://")
	tlsCfg := ldapTLSConfig(pc.URL, pc.TLSSkipVerify)
	start := time.Now()
	conn, err := ldap.DialURL(pc.URL,
		ldap.DialWithTLSConfig(tlsCfg),
		ldap.DialWithDialer(&net.Dialer{Timeout: ldapTestDialTimeout}),
	)
	durMs := time.Since(start).Milliseconds()
	if err != nil {
		rep.Steps = append(rep.Steps, ldapTestStep{
			Name: "reachable", Label: "Server reachable", OK: false, DurationMs: durMs,
			Error: ldapTestErrText(err), Action: ldapDialErrorAction(err),
		})
		return nil, func() {}, false
	}
	conn.SetTimeout(ldapTestOpTimeout)
	// Armed BEFORE StartTLS: the handshake below is the one stage SetTimeout
	// cannot bound (CHAOS-57, armLDAPConnWatchdog).
	stopWatchdog := armLDAPConnWatchdog(conn, ldapTestTotalBudget, "ldap-directory-test")
	rep.Steps = append(rep.Steps, ldapTestStep{Name: "reachable", Label: "Server reachable", OK: true, DurationMs: durMs})

	switch {
	case isLDAPS:
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "tls", Label: "TLS handshake", OK: true,
			Detail: tlsVerifyDetail(pc)})
	case pc.StartTLS:
		if err := conn.StartTLS(tlsCfg); err != nil {
			rep.Steps = append(rep.Steps, ldapTestStep{
				Name: "tls", Label: "StartTLS upgrade", OK: false,
				Error: ldapTestErrText(err), Action: ldapDialErrorAction(err),
			})
			stopWatchdog()
			conn.Close() //nolint:errcheck // test connection teardown after failed upgrade
			return nil, func() {}, false
		}
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "tls", Label: "StartTLS upgrade", OK: true,
			Detail: tlsVerifyDetail(pc)})
	default:
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "tls", Label: "Transport security", OK: true,
			Detail: "Plain LDAP — credentials are transmitted unencrypted. Use LDAPS or StartTLS in production."})
	}
	return conn, stopWatchdog, true
}

func tlsVerifyDetail(pc *LDAPProfileConfig) string {
	if pc.TLSSkipVerify {
		return "Certificate verification is DISABLED (unsafe) — the channel is vulnerable to interception."
	}
	return "Certificate verified"
}

// ldapTestServiceBind performs the service-account bind stage.
func ldapTestServiceBind(rep *ldapTestReport, conn *ldap.Conn, pc *LDAPProfileConfig) bool {
	if pc.BindDN == "" {
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "service_bind", Label: "Service account bind", OK: true, Skipped: true,
			Detail: "Anonymous bind (no service account configured)"})
		return true
	}
	start := time.Now()
	err := conn.Bind(pc.BindDN, pc.BindPassword)
	durMs := time.Since(start).Milliseconds()
	if err != nil {
		action := "Check the service-account DN and credential."
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			action = "Service account credentials rejected — verify the bind DN and replace the credential."
		}
		rep.Steps = append(rep.Steps, ldapTestStep{
			Name: "service_bind", Label: "Service account bind", OK: false, DurationMs: durMs,
			Error: ldapTestErrText(err), Action: action,
		})
		return false
	}
	rep.Steps = append(rep.Steps, ldapTestStep{Name: "service_bind", Label: "Service account bind", OK: true, DurationMs: durMs})
	return true
}

// ldapTestBaseDN verifies the Base DN exists and is searchable.
func ldapTestBaseDN(rep *ldapTestReport, conn *ldap.Conn, pc *LDAPProfileConfig) bool {
	start := time.Now()
	_, err := conn.Search(ldap.NewSearchRequest(
		pc.BaseDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)", []string{"dn"}, nil,
	))
	durMs := time.Since(start).Milliseconds()
	if err != nil {
		action := "Check the Base DN and the service account's read permissions."
		if ldap.IsErrorWithCode(err, ldap.LDAPResultNoSuchObject) {
			action = "Base DN not found — verify the DN (e.g. DC=corp,DC=example)."
		}
		rep.Steps = append(rep.Steps, ldapTestStep{
			Name: "base_dn", Label: "Base DN search", OK: false, DurationMs: durMs,
			Error: ldapTestErrText(err), Action: action,
		})
		return false
	}
	rep.Steps = append(rep.Steps, ldapTestStep{Name: "base_dn", Label: "Base DN search", OK: true, DurationMs: durMs})
	return true
}

// ldapTestUserLookup runs the optional full identity test (user search +
// user bind + identity mapping) when a test username was supplied; otherwise
// it reports the user-lookup configuration as ready.
func ldapTestUserLookup(rep *ldapTestReport, conn *ldap.Conn, pc *LDAPProfileConfig, username, password string) {
	filterTpl := ldapProfileDefault(pc.UserFilter, "(sAMAccountName=%s)")
	if username == "" {
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "user_lookup", Label: "User lookup configuration", OK: true, Skipped: true,
			Detail: fmt.Sprintf("Filter template %s ready — run a user authentication test to verify end to end", filterTpl)})
		return
	}
	groupAttr := ldapProfileDefault(pc.GroupAttribute, "memberOf")
	emailAttr := ldapProfileDefault(pc.EmailAttribute, "mail")
	nameAttr := ldapProfileDefault(pc.NameAttribute, "displayName")

	start := time.Now()
	res, err := conn.Search(ldap.NewSearchRequest(
		pc.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf(filterTpl, ldap.EscapeFilter(username)),
		[]string{"dn", groupAttr, "cn", emailAttr, nameAttr}, nil,
	))
	durMs := time.Since(start).Milliseconds()
	if err != nil {
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "user_lookup", Label: "User lookup", OK: false, DurationMs: durMs,
			Error: ldapTestErrText(err), Action: "Check the user filter and the service account's search permissions."})
		return
	}
	if len(res.Entries) != 1 {
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "user_lookup", Label: "User lookup", OK: false, DurationMs: durMs,
			Detail: fmt.Sprintf("Filter matched %d entries; expected exactly 1", len(res.Entries)),
			Action: "Adjust the user filter so a login name selects exactly one directory entry."})
		return
	}
	entry := res.Entries[0]
	rep.Steps = append(rep.Steps, ldapTestStep{Name: "user_lookup", Label: "User lookup", OK: true, DurationMs: durMs})

	if password == "" {
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "user_auth", Label: "User authentication", OK: true, Skipped: true,
			Detail: "No test password supplied — user bind not attempted"})
		return
	}
	start = time.Now()
	err = conn.Bind(entry.DN, password)
	durMs = time.Since(start).Milliseconds()
	if err != nil {
		action := "The directory rejected the test credential."
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			action = "Wrong password for the test user."
		}
		rep.Steps = append(rep.Steps, ldapTestStep{Name: "user_auth", Label: "User authentication", OK: false, DurationMs: durMs,
			Error: ldapTestErrText(err), Action: action})
		return
	}
	rep.Steps = append(rep.Steps, ldapTestStep{Name: "user_auth", Label: "User authentication", OK: true, DurationMs: durMs})

	groups := entry.GetAttributeValues(groupAttr)
	sample := groups
	if len(sample) > ldapTestMaxGroupSample {
		sample = sample[:ldapTestMaxGroupSample]
	}
	name := entry.GetAttributeValue(nameAttr)
	if name == "" {
		name = entry.GetAttributeValue("cn")
	}
	rep.Identity = &ldapTestIdentity{
		Sub:        entry.DN,
		Email:      entry.GetAttributeValue(emailAttr),
		Name:       name,
		GroupCount: len(groups),
		Groups:     append([]string(nil), sample...),
	}
}

// ─── Activation preflight (safe activation, ADR-0027 §15) ────────────────────

// ldapActivationPreflight gates a profile write behind a live connection test
// when the caller requested it (?preflight=connection). Only meaningful for
// LDAP; other types return nil (their compile path validates what it can
// without network). On failure the caller must NOT mutate anything — the
// currently working provider stays live.
func ldapActivationPreflight(r *http.Request, p *IdPProfile) *ldapTestReport {
	if r.URL.Query().Get("preflight") != "connection" {
		return nil
	}
	if p.Type != IdPTypeLDAP || p.LDAP == nil {
		return nil
	}
	if err := validateLDAPProfileConfig(p.LDAP); err != nil {
		return &ldapTestReport{OK: false, Steps: []ldapTestStep{{
			Name: "validate", Label: "Configuration validation", OK: false, Error: err.Error(),
		}}}
	}
	return runLDAPDirectoryTest(p.LDAP, "", "")
}

// writeLDAPPreflightFailure responds to a failed activation preflight with
// the staged report (422: the candidate is well-formed but the directory
// rejected it) and confirms no mutation occurred.
func writeLDAPPreflightFailure(w http.ResponseWriter, rep *ldapTestReport) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	jsonOK(w, map[string]any{
		"error": "connection preflight failed — the current configuration remains active and unchanged",
		"test":  rep,
	})
}
