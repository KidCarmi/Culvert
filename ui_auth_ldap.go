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
	"crypto/hmac"
	"encoding/json"
	"errors"
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
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	c := legacyLDAPYAMLConfig()
	if c == nil {
		out := map[string]any{"present": false, "retired": legacyLDAPRetired(), "scope": "node-local",
			"cutoverDurability": legacyLDAPCutoverDurability()}
		if rec := legacyLDAPCutover(); rec != nil {
			out["cutover"] = legacyLDAPCutoverReadModel(rec)
		}
		jsonOK(w, out)
		return
	}
	_, legacyActive := cfg.snapshotAuthBackend().provider.(*LDAPAuth)
	out := map[string]any{
		"present": true,
		"active":  legacyActive,
		"scope":   "node-local",
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
		// FE-6A.2: the SERVER-required confirmation value for the authority
		// cutover — a cutover-bearing write must echo it as ?cutoverConfirm=.
		"cutoverConfirmValue": c.URL,
		// Round 3 (Blocker 1): the server-owned keyed commitment over the
		// import source the administrator is reviewing — every security-
		// effective field including the credential VALUE, disclosing none.
		// The import must echo it; "unavailable" when the ledger key is
		// unusable (the import is then refused as operation_ledger_degraded).
		"importSourceRevision": legacyLDAPImportSourceToken(c),
	}
	// FE-6A.0 R7: the operation-identified cutover record (actor,
	// operationId, the enabling profile + registry revision it was bound to)
	// with its DURABILITY truth (correction, Blocker 9): an observed cutover
	// whose sentinel save failed is active at runtime but reported
	// pending_reconciliation, never claimed durable.
	out["cutoverDurability"] = legacyLDAPCutoverDurability()
	if rec := legacyLDAPCutover(); rec != nil {
		out["cutover"] = legacyLDAPCutoverReadModel(rec)
	}
	jsonOK(w, out)
}

// ─── POST /api/idp/legacy-ldap/import ────────────────────────────────────────

// apiIdPLegacyLDAPImport creates a DISABLED LDAP IdP profile from the legacy
// YAML block, copying every security-effective field (including the bind
// credential, which never transits the browser). The admin then tests and
// enables it — the deterministic, downgrade-safe migration path. The YAML
// file is never modified.
//
// FE-6A.2 correction (Blocker 1): the import is a FENCED, OPERATION-
// IDENTIFIED mutation with the create's durable-ledger semantics — never an
// unfenced Upsert:
//
//  1. `?operationId=` (client UUID) is REQUIRED (428 operation_id_required):
//     a lost response is recovered through the ledger (replay / lookup),
//     never by a second import minting a second profile;
//  2. a known operationId REPLAYS its recorded outcome (committed ⇒ the same
//     action-bound answer with replayed:true; aborted / pending / unknown ⇒
//     the contracted 409), and a different candidate under a known id ⇒ 409
//     operation_mismatch;
//  3. `?documentRevision=` is REQUIRED (428 precondition_required with
//     current.documentRevision) and decided INSIDE the registry transaction
//     (409 stale) — a concurrent registry change is refused, nothing written;
//  4. the durable intent (action idp.import, bound to the pre-minted id, the
//     candidate's public digest + keyed secret commitment and the fence) is
//     recorded BEFORE the write; the profile carries the operationId as its
//     provenance; the success audit is part of the operation;
//  5. the answer is ACTION-BOUND: imported:true, the disabled profile's
//     identity/revision, the RESULTING documentRevision, the echoed
//     operationId, the legacy SOURCE identity (never its credential) and the
//     fleet publication fact.
func apiIdPLegacyLDAPImport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	c := legacyLDAPYAMLConfig()
	if c == nil {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "no legacy YAML ldap configuration is present", nil)
		return
	}
	if !requireDurableIdP(w) {
		return
	}
	if idpRegistry.Degraded() != nil {
		writeIdPRefusal(w, errIdPRegistryDegraded)
		return
	}
	opID, ok := idpRequiredOperationID(w, r,
		"the legacy import mints a registry profile: supply a client-generated UUID operationId so a lost response can be recovered without a second import")
	if !ok {
		return
	}
	// Round 3 (Blocker 1): the import is bound to the source the
	// administrator REVIEWED — the token GET /api/idp/legacy-ldap published —
	// never to whatever YAML is current at dispatch time.
	reviewed := strings.TrimSpace(r.URL.Query().Get("importSourceRevision"))
	if reviewed == "" {
		writeRefusal(w, http.StatusPreconditionRequired, refusalImportSourceRequired,
			"supply importSourceRevision — the reviewed legacy source's token from GET /api/idp/legacy-ldap — so the import can only copy the source you reviewed", nil)
		return
	}
	if !strings.HasPrefix(reviewed, idpImportSourcePrefix) || len(reviewed) != len(idpImportSourcePrefix)+64 {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "importSourceRevision must be the token published by GET /api/idp/legacy-ldap", nil)
		return
	}
	ops := idpRegistry.operations()
	if idpReplayKnownImport(w, ops, opID, reviewed) {
		return
	}
	p := legacyLDAPImportCandidate(c)
	specDigest := idpSpecDigest(p)
	commitment := ops.CandidateCommitment(p)
	current := ops.SourceCommitment(p)
	if current == "" {
		writeIdPRefusal(w, errIdPOperationLedgerDegraded) // no usable key: nothing can be bound
		return
	}
	if !hmac.Equal([]byte(current), []byte(reviewed)) {
		writeRefusal(w, http.StatusConflict, refusalImportSourceStale,
			"the legacy source changed since it was reviewed; re-read it and review the current source before importing",
			map[string]any{"importSourceRevision": current})
		return
	}
	docRev, ok := idpCreateDocumentFence(w, r)
	if !ok {
		return
	}
	p.ID = mintIdPID()
	if !idpBeginCreateIntent(w, ops, idpOperation{
		OperationID: opID, Action: "idp.import", Actor: auditActor(r), ProfileName: p.Name,
		ProfileID: p.ID, SpecDigest: specDigest, CandidateCommitment: commitment, RegistryRevision: docRev,
		ImportSourceRevision: reviewed,
	}) {
		return
	}
	if err := idpRegistry.Create(p, docRev, opID, nil); err != nil {
		idpFinishFailedOperation(ops, opID, err)
		writeIdPRefusal(w, err)
		return
	}
	fleet := idpPublishFleet("legacy LDAP import")
	result := idpWithFleet(publicIdPProfile(p), fleet)
	result["imported"] = true
	result["operationId"] = opID
	result["importSourceRevision"] = reviewed
	result["documentRevision"] = idpRegistry.DocumentRevision()
	result["source"] = legacyLDAPImportSource(c)
	detail := "imported legacy YAML LDAP configuration" + fleet.auditSuffix() + " operationId=" + opID
	if !idpRecordCommittedOperation(w, ops, opID, p, result, detail) {
		return
	}
	idpCompleteOperationAudit(r, ops, opID, result)
	logger.Printf("UI: legacy YAML LDAP imported as IdP profile id=%q (disabled; test-then-enable) operationId=%q", sanitizeLog(p.ID), sanitizeLog(opID))
	jsonOK(w, result)
}

// legacyLDAPImportCandidate is the ONE candidate an import of the legacy
// block produces (disabled; the profile shape the registry stores) — the
// same construction the read model's source token commits to.
func legacyLDAPImportCandidate(c *LDAPConfig) *IdPProfile {
	p := &IdPProfile{
		Name:    "Imported legacy LDAP",
		Type:    IdPTypeLDAP,
		Enabled: false, // explicit test-then-enable; never activates blind
		LDAP:    legacyLDAPToProfileConfig(c),
	}
	normalizeIdPProfileWriteInput(p)
	return p
}

// legacyLDAPImportSourceToken is the read model's reviewed-source token:
// the keyed commitment over the import candidate (every security-effective
// field, the credential value included), or "unavailable" when no usable
// ledger key exists on this node.
func legacyLDAPImportSourceToken(c *LDAPConfig) string {
	if idpRegistry == nil {
		return idpImportSourceUnavailable
	}
	if tok := idpRegistry.operations().SourceCommitment(legacyLDAPImportCandidate(c)); tok != "" {
		return tok
	}
	return idpImportSourceUnavailable
}

// legacyLDAPImportSource is the NON-SECRET identity of the legacy block an
// import copied — the same facts GET /api/idp/legacy-ldap publishes, so the
// client can bind the answer to the source it reviewed. Never the credential.
func legacyLDAPImportSource(c *LDAPConfig) map[string]any {
	return map[string]any{
		"url":                      c.URL,
		"baseDn":                   c.BaseDN,
		"bindDn":                   c.BindDN,
		"bindCredentialConfigured": c.BindPassword != "",
		"startTls":                 c.StartTLS,
		"tlsSkipVerify":            c.TLSSkipVerify,
		"userFilter":               c.UserFilter,
		"requiredGroup":            c.RequiredGroup,
	}
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

// ldapTestTotalBudget is the whole-test envelope (CHAOS-58). ldapTestOpTimeout
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
		writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	var body apiIdPTestRequest
	if err := decodeJSON(r, &body); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON", nil)
		return
	}
	p := body.Profile
	if p == nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "profile is required", nil)
		return
	}
	if p.Type != IdPTypeLDAP {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "only ldap profiles support the directory test", nil)
		return
	}
	if p.LDAP == nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "ldap config is required", nil)
		return
	}
	resolveTestBindCredential(p)
	if err := validateLDAPProfileConfig(p.LDAP); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "ldap: "+err.Error(), nil)
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

// ldapTestErrText reduces a directory/transport error to a BOUNDED class
// (FE-6A.0 correction, Blocker 6). The raw text embeds the directory's
// hostname, TLS diagnostics and transport detail, and the admin diagnostic
// report is an API response: only the class crosses the boundary, with the
// Action hint carrying the operator guidance. The raw error is never logged
// or audited either.
func ldapTestErrText(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	var ne net.Error
	switch {
	case errors.As(err, &ne) && ne.Timeout(), strings.Contains(msg, "i/o timeout"), strings.Contains(msg, "deadline exceeded"):
		return "timeout"
	case strings.Contains(msg, "x509:"), strings.Contains(msg, "tls:"), strings.Contains(msg, "TLS"):
		return "tls_failed"
	case strings.Contains(msg, "connection refused"), strings.Contains(msg, "no such host"), strings.Contains(msg, "network is unreachable"), strings.Contains(msg, "dial"):
		return "unreachable"
	case strings.Contains(msg, "Invalid Credentials"), strings.Contains(msg, "Result Code 49"):
		return "invalid_credentials"
	case strings.Contains(msg, "Result Code 32"), strings.Contains(msg, "No Such Object"):
		return "no_such_object"
	case strings.Contains(msg, "Result Code 50"), strings.Contains(msg, "Insufficient Access"):
		return "insufficient_access"
	case strings.Contains(msg, "Result Code"):
		return "directory_error"
	default:
		return "directory_error"
	}
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
// timer can bound — runs inside this function (CHAOS-58).
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
	// cannot bound (CHAOS-58, armLDAPConnWatchdog).
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

// ldapWriteActivationGate is the appliance's ACTIVATION PREFLIGHT at the
// write boundary (ADR-0027 §15; FE-6A.2 correction, Blocker 3 — it is no
// longer opt-in through ?preflight=connection, which is accepted for
// compatibility and ignored). A write QUALIFIES when its candidate is an
// ENABLED LDAP provider that is new, newly enabled, or whose directory
// connection spec changed (URL, transport security, service account, base
// DN); a label/priority/attribute-mapping edit of an already-enabled
// provider does not re-dial the directory. Nil for a non-qualifying write;
// otherwise the live directory test report (bind + base-object search — the
// same stages the admin test surface runs), which the caller must refuse on
// !OK BEFORE recording an intent or writing anything. A malformed candidate
// is left to the registry's own validation (400), never reported as a
// directory failure.
func ldapWriteActivationGate(before, p *IdPProfile) *ldapTestReport {
	if p == nil || !p.Enabled || p.Type != IdPTypeLDAP || p.LDAP == nil {
		return nil
	}
	if before != nil && before.Enabled && before.Type == IdPTypeLDAP && before.LDAP != nil &&
		!ldapConnectionSpecChanged(before.LDAP, p.LDAP) {
		return nil
	}
	if err := validateLDAPProfileConfig(p.LDAP); err != nil {
		return nil
	}
	return runLDAPDirectoryTest(p.LDAP, "", "")
}

// ldapConnectionSpecChanged reports whether the fields the directory
// preflight exercises differ between two LDAP configs.
func ldapConnectionSpecChanged(a, b *LDAPProfileConfig) bool {
	return a.URL != b.URL || a.StartTLS != b.StartTLS || a.TLSSkipVerify != b.TLSSkipVerify ||
		a.BindDN != b.BindDN || a.BindPassword != b.BindPassword || a.BaseDN != b.BaseDN
}

// ldapPreflightFailure returns the first failed stage of a report as the
// bounded (step, reason) pair the refusal carries: step ∈ the closed stage
// vocabulary, reason ∈ ldapTestErrText's closed class vocabulary.
func ldapPreflightFailure(rep *ldapTestReport) (step, reason string) {
	for _, s := range rep.Steps {
		if !s.OK && !s.Skipped {
			return s.Name, s.Error
		}
	}
	return "reachable", "directory_error"
}

// writeLDAPPreflightRefusal answers a failed activation preflight as the
// STRUCTURED 422 preflight_failed refusal: `current.step`/`current.reason`
// are the bounded facts the v2 client renders; the staged report rides
// beside them as `test` for the legacy console. Nothing was written.
func writeLDAPPreflightRefusal(w http.ResponseWriter, rep *ldapTestReport) {
	step, reason := ldapPreflightFailure(rep)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnprocessableEntity)
	_ = json.NewEncoder(w).Encode(map[string]any{ //nolint:errcheck // best-effort refusal body
		"error":   "directory connection preflight failed — the current configuration remains active and unchanged",
		"code":    refusalPreflightFailed,
		"current": map[string]any{"step": step, "reason": reason},
		"test":    rep,
	})
}
