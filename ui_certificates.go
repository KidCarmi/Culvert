package main

// ui_certificates.go — the FE-6B.0 Certificates and CA lifecycle admin
// surface (FRONTEND-MIGRATION-PLAN.md FE-6B.0). Every route here answers
// typed JSON with a closed code vocabulary (ui_refusal.go); nothing on this
// surface uses http.Error or renders a dependency's text.
//
// Mutations (rotate, import, UI replace/delete, OCSP set) share one shape:
//
//	operationId (client UUID, ?operationId=)  428 operation_id_required / 400
//	ledger degraded                           503 operation_ledger_degraded
//	replay by operationId                     200 replayed:true | 409 operation_*
//	candidate validation (pure)               400 candidate_invalid current.reason
//	fence (?caRevision= …)                    428 precondition_required / 409 stale
//	── certOpsMu ──────────────────────────────────────────────────────────
//	fence re-checked against the live object
//	SETTLE every pending intent on the target 503 operation_unsettled if one cannot be made durable
//	intent (Begin, with the non-secret recovery facts) durable before the first write
//	persist → publish → terminal record → operation-keyed audit
//
// A refusal mutates nothing, audits no success and advances no revision. A
// refusal is TERMINAL (persist_failed) only once its aborted record is
// durable; otherwise it is the NON-terminal 500 outcome_unknown with
// current.detail refusal_not_durable (correction round, Blocker 3).

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

// FE-6B.0 refusal codes (beside the shared ones in ui_refusal.go).
const (
	refusalChallengeRequired = "challenge_required"   // 428: the confirm carried no challenge
	refusalChallengeStale    = "challenge_stale"      // 409: the challenge binds different facts (current.changed)
	refusalCandidateInvalid  = "candidate_invalid"    // 400: the certificate candidate was refused (current.reason)
	refusalCandidateDup      = "candidate_duplicate"  // 409: the candidate is already the installed object
	refusalCANotReady        = "ca_not_ready"         // 503: no Root CA is installed
	refusalCAGenerationFail  = "ca_generation_failed" // 500: the fresh root could not be minted
)

// ── shared helpers ──────────────────────────────────────────────────────────

func certMethodRefusal(w http.ResponseWriter) {
	writeRefusal(w, http.StatusMethodNotAllowed, refusalMethodNotAllowed, "method not allowed", nil)
}

// certOperationID resolves the REQUIRED client operationId.
func certOperationID(w http.ResponseWriter, r *http.Request) (string, bool) {
	opID := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("operationId")))
	if opID == "" {
		writeRefusal(w, http.StatusPreconditionRequired, refusalOperationIDRequired,
			"supply a client-generated UUID operationId so a lost response can be recovered without a second mutation", nil)
		return "", false
	}
	if !validIdPOperationID(opID) {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "operationId must be a UUID", nil)
		return "", false
	}
	return opID, true
}

// certLedger returns the ledger or answers the fail-closed 503.
func certLedger(w http.ResponseWriter) (*certOperationStore, bool) {
	s := certOpsStore()
	if d := s.Degraded(); d != nil {
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded,
			"the certificate operation ledger is degraded; operation-identified writes and lookups are refused until it is restored (evidence preserved)",
			map[string]any{"reason": d.Reason})
		return nil, false
	}
	return s, true
}

// certFencePresent reads a fence parameter; absent ⇒ 428 carrying the
// current value under the parameter's own name.
func certFencePresent(w http.ResponseWriter, r *http.Request, param, current string) (string, bool) {
	v := strings.TrimSpace(r.URL.Query().Get(param))
	if v == "" {
		writeRefusal(w, http.StatusPreconditionRequired, refusalPreconditionRequired,
			"precondition required: echo the current "+param+" you loaded", map[string]any{param: current})
		return "", false
	}
	return v, true
}

// certFenceMatches compares an echoed fence with the live value; mismatch
// ⇒ 409 stale carrying the current value.
func certFenceMatches(w http.ResponseWriter, param, echoed, current string) bool {
	if echoed != current {
		writeRefusal(w, http.StatusConflict, refusalStale,
			"stale "+param+": the object changed since you loaded it — reload and retry", map[string]any{param: current})
		return false
	}
	return true
}

// certReplay answers a request whose operationId the ledger already knows.
// sameCandidate reports whether the recorded intent is THIS candidate.
func certReplay(w http.ResponseWriter, prev *certOperation, action string, sameCandidate bool) {
	if prev.Action != action || !sameCandidate {
		writeRefusal(w, http.StatusConflict, refusalOperationMismatch,
			"operationId already used for a different operation or candidate — generate a new operationId",
			map[string]any{"operationId": prev.OperationID, "action": prev.Action, "state": prev.State})
		return
	}
	switch prev.State {
	case certOpCommitted:
		out := map[string]any{}
		if len(prev.Result) > 0 {
			_ = json.Unmarshal(prev.Result, &out)
		}
		out["replayed"] = true
		out["operationId"] = prev.OperationID
		out["recordState"] = certOpCommitted
		if !prev.Audited {
			out["auditState"] = "pending"
		}
		jsonOK(w, out)
	case certOpPending:
		writeRefusal(w, http.StatusConflict, refusalOperationInProgress,
			"this operation is still being decided; poll GET /api/ca/operations/{operationId}",
			map[string]any{"operationId": prev.OperationID, "state": prev.State})
	case certOpAborted:
		writeRefusal(w, http.StatusConflict, refusalOperationAborted,
			"this operation was refused; generate a new operationId to retry",
			map[string]any{"operationId": prev.OperationID, "state": prev.State, "code": prev.Code})
	default:
		writeRefusal(w, http.StatusConflict, refusalOperationUnknown,
			"this operation's outcome is unproven; poll GET /api/ca/operations/{operationId}",
			map[string]any{"operationId": prev.OperationID, "state": prev.State, "code": prev.Code})
	}
}

// certMutationPrelude runs the checks every operation-identified mutation
// shares BEFORE its serialized boundary: the operationId, the ledger posture,
// the replay of a known id (sameCandidate decides mismatch vs replay) and the
// presence of the fence parameter. ok=false means the response was written.
func certMutationPrelude(w http.ResponseWriter, r *http.Request, action, fenceParam, current string, sameCandidate func(prev *certOperation) bool) (opID, echoed string, s *certOperationStore, ok bool) {
	opID, ok = certOperationID(w, r)
	if !ok {
		return "", "", nil, false
	}
	s, ok = certLedger(w)
	if !ok {
		return "", "", nil, false
	}
	if prev, err := s.Get(opID); err == nil && prev != nil {
		certReplay(w, prev, action, sameCandidate(prev))
		return "", "", nil, false
	}
	echoed, ok = certFencePresent(w, r, fenceParam, current)
	if !ok {
		return "", "", nil, false
	}
	return opID, echoed, s, true
}

func sameOperation(*certOperation) bool { return true }

// certBegin records the intent; on a ledger fault it answers the refusal.
func certBegin(w http.ResponseWriter, s *certOperationStore, op certOperation) bool {
	_, created, err := s.Begin(op)
	switch {
	case err == nil && created:
		return true
	case err == nil:
		// Raced by an identical operationId between the replay check and
		// the intent: refuse as in-progress rather than run twice.
		writeRefusal(w, http.StatusConflict, refusalOperationInProgress, "this operation is already being decided", map[string]any{"operationId": op.OperationID})
	case errors.Is(err, errCertOperationLedgerDegraded):
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded, "the certificate operation ledger is degraded", nil)
	case errors.Is(err, errCertOperationLedgerFull):
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationLedgerFull, "every operation-ledger slot holds an unresolved intent; settle them via GET /api/ca/operations/{id} first", nil)
	default:
		writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed, "the operation intent could not be recorded durably; nothing was changed", nil)
	}
	return false
}

// certAbort records a persist-failure refusal DURABLY and reports whether it
// did. A refusal whose record could not be persisted is NOT terminal: the
// pending intent stays the durable truth, the refusal it stood for is
// memorised for the next settlement, and the caller answers
// certRefusalNotDurable instead of persist_failed.
func certAbort(s *certOperationStore, opID string) (durable bool) {
	if err := s.Finish(opID, certOpAborted, refusalPersistFailed, "", nil, ""); err != nil {
		logger.Printf("Certificates: operation %s refusal not recorded durably (%s) — answered non-terminal; settled by the next lookup/boot/writer", sanitizeLog(opID), certBoundedLedgerClass(err))
		noteCertRefusalNotDurable(opID, refusalPersistFailed)
		return false
	}
	return true
}

// certRefusalNotDurable answers a refusal whose aborted record is not
// durable: 500 outcome_unknown, current.detail refusal_not_durable,
// current.state pending, the operationId. The product mutation is absent;
// a repeat of the same operationId replays the refusal once it is durable.
func certRefusalNotDurable(w http.ResponseWriter, opID string) {
	writeRefusal(w, http.StatusInternalServerError, refusalOutcomeUnknown,
		"the operation was refused (nothing was changed) but the refusal could not be recorded durably; the operation is retained as pending and will be settled as this refusal",
		map[string]any{"detail": "refusal_not_durable", "state": certOpPending, "operationId": opID})
}

// certSettleTargetOrRefuse settles every pending intent on target before the
// caller writes it (the writer protocol, inside certOpsMu). An intent that
// cannot be settled durably refuses the write: 503 operation_unsettled with
// the bounded class; nothing is written.
func certSettleTargetOrRefuse(w http.ResponseWriter, s *certOperationStore, target string) bool {
	if err := settleCertTarget(s, target, "writer"); err != nil {
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationUnsettled,
			"an outstanding operation on this object could not be settled durably; retry once the operation ledger is writable (GET /api/ca/operations/{id} settles it)",
			map[string]any{"reason": certBoundedLedgerClass(err)})
		return false
	}
	return true
}

// certCommit records the durable terminal record and completes the
// operation-keyed audit; it decorates result with the truthful recordState
// and auditState.
func certCommit(s *certOperationStore, opID, revision string, result map[string]any, auditDetail string) {
	if caOpsBeforeFinishHook != nil {
		caOpsBeforeFinishHook()
	}
	if err := s.Finish(opID, certOpCommitted, "", revision, result, auditDetail); err != nil {
		logger.Printf("Certificates: operation %s committed but its terminal record is not durable (%s) — settled by the next lookup/boot", sanitizeLog(opID), certBoundedLedgerClass(err))
		result["recordState"] = "pending_reconciliation"
		return
	}
	result["recordState"] = certOpCommitted
	rec, err := s.Get(opID)
	if err != nil || rec == nil {
		result["auditState"] = "pending"
		return
	}
	if err := s.emitOperationAudit(*rec); err != nil {
		logger.Printf("Certificates: operation %s success audit pending (%s)", sanitizeLog(opID), certBoundedLedgerClass(err))
		result["auditState"] = "pending"
	}
}

// caInfoWithRevision is the CA's public projection plus its revision token.
func caInfoWithRevision() map[string]any {
	info := certMgr.CACertInfo()
	info["revision"] = caRevisionToken()
	return info
}

// uiCertReadModel is the persisted admin-UI certificate's public projection.
func uiCertReadModel() map[string]any {
	out := map[string]any{
		"present":  customUITLSFilesPresent(),
		"revision": uiCertRevisionToken(),
		"active":   uiCustomTLSActive,
		"corrupt":  uiCustomTLSCorrupt,
	}
	if leaf := persistedUICertLeaf(); leaf != nil {
		out["fingerprint"] = ca.FingerprintOf(leaf)
		out["subject"] = leaf.Subject.CommonName
		out["notAfter"] = leaf.NotAfter.UTC().Format(time.RFC3339)
	}
	return out
}

// persistedUICertLeaf parses the persisted UI certificate's leaf, or nil.
func persistedUICertLeaf() *x509.Certificate {
	if !customUITLSFilesPresent() {
		return nil
	}
	data, err := os.ReadFile(customUITLSCertPath())
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

// ── GET /api/certificates (viewer) ──────────────────────────────────────────

func apiCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	caM := map[string]any{"present": certMgr.Ready(), "revision": caRevisionToken(), "keyProvider": certMgr.KeyProviderName(),
		"dualCAActive": certMgr.SecondaryCAActive(), "persistenceConfigured": caRuntime.path != "", "encryptedAtRest": caRuntime.passphrase != ""}
	if certMgr.Ready() {
		for k, v := range certMgr.CACertInfo() {
			if k != "ready" {
				caM[k] = v
			}
		}
	}
	if err := certMgr.Usable(); err != nil {
		caM["usable"] = false
		caM["unusableClass"] = caUnusableClass(err)
	} else {
		caM["usable"] = true
	}
	faults := caUsabilityFailures()
	caM["persistDegraded"] = faults.PersistDegraded
	if faults.PersistDegraded && faults.PersistErr != "" {
		caM["persistClass"] = faults.PersistErr
	}
	if c := sslInspectionLoadFailureClass(); c != "" {
		caM["loadFailed"] = true
		caM["loadFailureClass"] = c
	} else {
		caM["loadFailed"] = false
	}
	d := ocspDesiredSnapshot()
	out := map[string]any{
		"scope":          certScopeNodeLocal,
		"ca":             caM,
		"uiCert":         uiCertReadModel(),
		"mtlsClientCert": mtlsClientCertReadModel(),
		"ocsp": map[string]any{
			"revision": ocspRevisionToken(),
			"desired":  map[string]any{"enabled": d.enabled, "source": d.source},
			"runtime":  map[string]any{"enabled": globalOCSP.Enabled()},
			"durable":  d.saved,
		},
		"operations": certOpsStore().readModel(),
		"backup": map[string]any{
			"caBundleArchived":      true,
			"caBundleEncrypted":     caRuntime.passphrase != "",
			"uiCertArchived":        false,
			"operationsArchived":    false,
			"configVersionRollback": false,
		},
	}
	jsonOK(w, out)
}

func mtlsClientCertReadModel() map[string]any {
	mc := mtlsClientCertHealth()
	out := map[string]any{"configured": mc.configured, "loaded": mc.loaded}
	if mc.configured && mc.loaded {
		out["notAfter"] = mc.notAfter.UTC().Format(time.RFC3339)
		out["daysRemaining"] = daysUntil(mc.notAfter)
	}
	if mc.configured && !mc.loaded && mc.reason != "" {
		out["reason"] = mc.reason
	}
	return out
}

// ── GET /api/ca/status (viewer) ─────────────────────────────────────────────

func apiCAStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	info := caInfoWithRevision()
	info["scope"] = certScopeNodeLocal
	info["cacheSize"] = certMgr.CertCacheLen()
	info["cacheMax"] = 10_000
	info["cacheTTL"] = "1h"
	info["leafValidity"] = "24h"
	info["autoRotation"] = true
	info["rotationOverlapDays"] = 30
	info["keyProvider"] = certMgr.KeyProviderName()
	info["persistenceConfigured"] = caRuntime.path != ""
	expiry := certMgr.CAExpiry()
	if !expiry.IsZero() {
		info["expiresIn"] = time.Until(expiry).Round(time.Hour).String()
	}
	// CHAOS-28 usability posture, as a bounded class (FE-6B.0).
	usabilityErr := certMgr.Usable()
	info["usable"] = usabilityErr == nil
	if usabilityErr != nil {
		info["unusableClass"] = caUnusableClass(usabilityErr)
	}
	caFaults := caUsabilityFailures()
	info["inspectBlocked"] = caFaults.Blocks
	info["signRefused"] = certMgr.SignRefusals()
	info["rotationPersistFailures"] = caFaults.PersistFailures
	info["rotationPersistDegraded"] = caFaults.PersistDegraded
	if caFaults.PersistDegraded && caFaults.PersistErr != "" {
		info["rotationPersistClass"] = caFaults.PersistErr
	}
	// CHAOS-50 load/recovery posture, as bounded classes.
	loadClass := sslInspectionLoadFailureClass()
	info["loadFailed"] = loadClass != ""
	if loadClass != "" {
		info["loadFailureClass"] = loadClass
	}
	info["inspectBypassed"] = caInspectBypassCount()
	rec := caLoadRecoveryStatus()
	info["loadRecoveryAttempts"] = rec.Attempts
	info["loadRecoveryGaveUp"] = rec.GaveUp
	if rec.LastErr != "" {
		info["loadRecoveryClass"] = rec.LastErr
	}
	info["dualCAActive"] = certMgr.SecondaryCAActive()
	if secInfo := certMgr.SecondaryCAInfo(); secInfo != nil {
		info["secondaryCA"] = secInfo
	}
	jsonOK(w, info)
}

// ── GET /api/ca-cert, /api/ca/download, /api/ca/key-provider ────────────────

func apiCACert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		if !certMgr.Ready() {
			writeRefusal(w, http.StatusServiceUnavailable, refusalCANotReady, "no Root CA is installed on this node", nil)
			return
		}
		jsonOK(w, caInfoWithRevision())
		return
	}
	writeCACertPEM(w)
}

// writeCACertPEM serves the Root CA certificate as a downloadable PEM file.
// Shared by /api/ca-cert (Certificates panel) and /api/ca/download (CA
// Management panel) — both routes exist for GUI back-compat, but must never
// re-diverge into two independently-maintained copies of this response.
func writeCACertPEM(w http.ResponseWriter) {
	pemBytes := certMgr.CACertPEM()
	if pemBytes == nil {
		writeRefusal(w, http.StatusServiceUnavailable, refusalCANotReady, "no Root CA is installed on this node", nil)
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="culvert-ca.pem"`)
	w.Write(pemBytes) //nolint:errcheck // HTTP response write
}

// apiCADownload is a back-compat alias of apiCACert's PEM-download branch,
// reached from the CA Management panel. See writeCACertPEM.
func apiCADownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	writeCACertPEM(w)
}

// apiCAKeyProvider returns the current key provider status for HSM/KMS UI.
func apiCAKeyProvider(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleViewer) {
		return
	}
	providerName := certMgr.KeyProviderName()
	jsonOK(w, map[string]any{
		"provider":     providerName,
		"isExternal":   providerName != "local",
		"caReady":      certMgr.Ready(),
		"dualCAActive": certMgr.SecondaryCAActive(),
	})
}

// apiCACacheClear flushes the in-memory leaf-certificate LRU cache.
//
// Intentionally OUT of the config-version rollback surface — the leaf cache is
// ephemeral in-memory runtime state (rebuilt on demand from the Root CA), with
// no persistent config to version. Classified runtime-only (category E). Do
// NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §3 (category E).
func apiCACacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	certMgr.ClearCache()
	auditEvent(r, "ca.cache_clear", "leaf_cert_cache", "")
	jsonOK(w, map[string]any{"ok": true})
}

// ── POST /api/ca/rotate/challenge (admin) ───────────────────────────────────

// apiCARotateChallenge issues the server-owned rotation challenge (FE-6B.0
// C4): bound to the actor, the operationId, the CURRENT CA revision and a
// bounded expiry, single-use, consumed only by a fully valid confirm.
func apiCARotateChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	opID, ok := certOperationID(w, r)
	if !ok {
		return
	}
	s, ok := certLedger(w)
	if !ok {
		return
	}
	if prev, err := s.Get(opID); err == nil && prev != nil {
		writeRefusal(w, http.StatusConflict, refusalOperationMismatch,
			"operationId already used; generate a new operationId for a new rotation",
			map[string]any{"operationId": opID, "action": prev.Action, "state": prev.State})
		return
	}
	current := caRevisionToken()
	echoed, ok := certFencePresent(w, r, "caRevision", current)
	if !ok || !certFenceMatches(w, "caRevision", echoed, current) {
		return
	}
	if !certMgr.Ready() {
		writeRefusal(w, http.StatusServiceUnavailable, refusalCANotReady, "no Root CA is installed on this node", nil)
		return
	}
	ch, err := issueCAChallenge(opID, auditActor(r), current)
	if err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusalCAGenerationFail, "the challenge could not be generated", nil)
		return
	}
	// The request for a destructive ceremony is itself an admin action worth
	// recording (not a success claim — the rotation's own audit is the
	// operation-keyed ca.rotate emitted after the durable commit).
	auditEvent(r, "ca.rotate_requested", "root_ca", "rotation challenge issued for operation "+opID)
	jsonOK(w, map[string]any{
		"challenge":        ch.value,
		"operationId":      opID,
		"action":           certActionRotate,
		"caRevision":       current,
		"fingerprint":      certMgr.CACertInfo()["fingerprint"],
		"expiresInSeconds": int(caChallengeTTL / time.Second),
		"expiresAt":        ch.expiresAt.UTC().Format(time.RFC3339),
		"warning": "Rotating the Root CA invalidates every existing leaf certificate and the current trust chain. " +
			"Every client workstation and device must trust the new CA certificate. This action cannot be undone.",
	})
}

// ── POST /api/ca/rotate (admin) ─────────────────────────────────────────────

// apiCARotate rotates the Root CA: fenced, operation-identified,
// challenge-bound, persist-before-publish.
//
// Intentionally OUT of the config-version rollback surface — CA rotation is a
// forward-only trust decision. Do NOT add saveConfigVersion here.
// See roadmap/CA-CLUSTER-ROLLBACK-CLASSIFICATION.md §2 (D-sec).
func apiCARotate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	challenge, ok := readChallengeBody(w, r)
	if !ok {
		return
	}
	opID, echoed, s, ok := certMutationPrelude(w, r, certActionRotate, "caRevision", caRevisionToken(), sameOperation)
	if !ok {
		return
	}
	actor := auditActor(r)

	certOpsMu.Lock()
	defer certOpsMu.Unlock()
	caMutationMu.Lock()
	defer caMutationMu.Unlock()

	current := caRevisionToken()
	if !certFenceMatches(w, "caRevision", echoed, current) {
		return
	}
	if !confirmCAChallenge(w, opID, actor, current, challenge) {
		return
	}
	if caRuntime.path == "" {
		writeRefusal(w, http.StatusServiceUnavailable, refusalPersistenceNotConfigured,
			"no CA bundle path is configured (-ca-path / proxy.ca_path); a rotation would exist in memory only, so it is refused", nil)
		return
	}
	if !certSettleTargetOrRefuse(w, s, "root_ca") {
		return
	}
	cand, err := ca.NewRotationCandidate()
	if err != nil {
		writeRefusal(w, http.StatusInternalServerError, refusalCAGenerationFail, "a fresh Root CA could not be generated; nothing was changed", nil)
		return
	}
	op := certOperation{OperationID: opID, Action: certActionRotate, Actor: actor, Target: "root_ca",
		CandidateDigest: cand.FingerprintHex(), Fence: current, Previous: caPreviousFacts()}
	op.AuditDetail = certAuditDetail(op)
	if !certBegin(w, s, op) {
		return
	}
	consumeCAChallenge(opID)
	if !persistCACandidate(w, s, opID, cand, "CA force-rotate") {
		return
	}
	certMgr.Install(cand)
	noteCARotationPersisted()
	noteSSLInspectionRecovered("force rotation via admin API")
	statCARotations.Add(1)
	result := caOperationResult(op)
	certCommit(s, opID, caRevisionToken(), result, op.AuditDetail)
	jsonOK(w, result)
}

// caPreviousFacts records the CA identity a rotate/import replaces (the
// non-secret recovery fact a committed result names as previous).
func caPreviousFacts() map[string]any {
	prev := caInfoWithRevision()
	return map[string]any{"fingerprint": prev["fingerprint"], "revision": prev["revision"]}
}

// confirmCAChallenge verifies the presented challenge inside the boundary
// (absent ⇒ 428 challenge_required; unbound ⇒ 409 challenge_stale with the
// bounded changed classes). It never consumes the challenge.
func confirmCAChallenge(w http.ResponseWriter, opID, actor, current, challenge string) bool {
	if challenge == "" {
		writeRefusal(w, http.StatusPreconditionRequired, refusalChallengeRequired,
			"obtain a rotation challenge from POST /api/ca/rotate/challenge and echo it", nil)
		return false
	}
	changed, ok := verifyCAChallenge(opID, actor, current, challenge)
	if ok {
		return true
	}
	if changed == nil {
		changed = []string{"challenge"}
	}
	writeRefusal(w, http.StatusConflict, refusalChallengeStale,
		"the challenge does not bind this confirmation; obtain a new one", map[string]any{"changed": changed})
	return false
}

// persistCACandidate writes the candidate's bundle to the configured path
// BEFORE anything is installed; a failure aborts the operation durably and
// answers 500 persist_failed with the bounded class, live CA unchanged.
func persistCACandidate(w http.ResponseWriter, s *certOperationStore, opID string, cand *ca.Candidate, what string) bool {
	err := ca.PersistCandidate(cand, caRuntime.path, caRuntime.passphrase)
	if err == nil {
		return true
	}
	class := ca.PersistFailureClass(err)
	logger.Printf("%s: bundle write failed (%s) — NOT applied", what, class)
	noteCARotationPersistFailure(class)
	if !certAbort(s, opID) {
		certRefusalNotDurable(w, opID)
		return false
	}
	writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed,
		"the Root CA bundle could not be written; the current CA is unchanged", map[string]any{"class": class, "operationId": opID})
	return false
}

// readChallengeBody decodes the optional {challenge} body: absent/empty ⇒
// "", a non-string or malformed body ⇒ 400 invalid_input.
func readChallengeBody(w http.ResponseWriter, r *http.Request) (string, bool) {
	if r.Body == nil {
		return "", true
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil || len(bytes.TrimSpace(raw)) == 0 {
		return "", true
	}
	var body struct {
		Challenge any `json:"challenge"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON body", nil)
		return "", false
	}
	switch v := body.Challenge.(type) {
	case nil:
		return "", true
	case string:
		return strings.TrimSpace(v), true
	default:
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "challenge must be a string", nil)
		return "", false
	}
}

// ── POST /api/certs/upload (admin) ──────────────────────────────────────────

// apiCertsUpload imports a custom MITM CA (target=mitm) or replaces the
// admin-UI certificate pair (target=ui). Both validate the COMPLETE
// candidate before anything is decided; ?dryRun=1 answers the candidate's
// public facts (the T2 review material) without a fence, an intent or a
// write.
//
// Intentionally OUT of the config-version rollback surface — a forward-only
// trust mutation. Do NOT add saveConfigVersion here.
func apiCertsUpload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)        // enforce 1 MB limit before parsing
	if err := r.ParseMultipartForm(1 << 20); err != nil { // #nosec G120 -- body already bounded by MaxBytesReader(1 MiB) on the line above
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "multipart form could not be parsed", nil)
		return
	}
	target := r.FormValue("target")
	if target == "" {
		target = r.URL.Query().Get("target")
	}
	if target != "ui" && target != "mitm" {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, `target must be "ui" or "mitm"`, nil)
		return
	}
	certPEM := multipartField(r, "cert")
	keyPEM := multipartField(r, "key")
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "cert and key are required", nil)
		return
	}
	dryRun := r.URL.Query().Get("dryRun") == "1" || r.FormValue("dryRun") == "1"
	if target == "mitm" {
		apiCertsImportMITM(w, r, certPEM, keyPEM, dryRun)
		return
	}
	apiCertsReplaceUI(w, r, certPEM, keyPEM, dryRun)
}

// multipartField reads a multipart field sent either as a plain value (the
// legacy console's FormData) or as a file part (curl -F name=@file, a
// browser <input type=file>). The body is already bounded by MaxBytesReader.
func multipartField(r *http.Request, name string) []byte {
	if v := r.FormValue(name); v != "" {
		return []byte(v)
	}
	if r.MultipartForm == nil || len(r.MultipartForm.File[name]) == 0 {
		return nil
	}
	f, err := r.MultipartForm.File[name][0].Open()
	if err != nil {
		return nil
	}
	defer f.Close() //nolint:errcheck // read-only multipart part
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return nil
	}
	return data
}

func writeCandidateRefusal(w http.ResponseWriter, err error) {
	var ce *ca.CandidateError
	reason := ca.CandidateMalformedPEM
	if errors.As(err, &ce) {
		reason = ce.Reason
	}
	writeRefusal(w, http.StatusBadRequest, refusalCandidateInvalid,
		"the certificate candidate was refused; nothing was changed", map[string]any{"reason": reason})
}

func apiCertsImportMITM(w http.ResponseWriter, r *http.Request, certPEM, keyPEM []byte, dryRun bool) {
	cand, err := ca.ParseCACandidate(certPEM, keyPEM)
	if err != nil {
		writeCandidateRefusal(w, err)
		return
	}
	if dryRun {
		jsonOK(w, map[string]any{"dryRun": true, "target": "mitm", "action": certActionImport, "candidate": cand.Info(),
			"current": map[string]any{"caRevision": caRevisionToken()}})
		return
	}
	opID, echoed, s, ok := certMutationPrelude(w, r, certActionImport, "caRevision", caRevisionToken(),
		func(prev *certOperation) bool { return prev.CandidateDigest == cand.FingerprintHex() })
	if !ok {
		return
	}
	actor := auditActor(r)

	certOpsMu.Lock()
	defer certOpsMu.Unlock()
	caMutationMu.Lock()
	defer caMutationMu.Unlock()

	current := caRevisionToken()
	if !certFenceMatches(w, "caRevision", echoed, current) {
		return
	}
	if certMgr.LiveCertificateHex() == cand.FingerprintHex() {
		writeRefusal(w, http.StatusConflict, refusalCandidateDup, "this certificate is already the installed Root CA",
			map[string]any{"caRevision": current, "fingerprint": cand.Fingerprint()})
		return
	}
	if caRuntime.path == "" {
		writeRefusal(w, http.StatusServiceUnavailable, refusalPersistenceNotConfigured,
			"no CA bundle path is configured (-ca-path / proxy.ca_path); an imported CA would exist in memory only, so it is refused", nil)
		return
	}
	if !certSettleTargetOrRefuse(w, s, "root_ca") {
		return
	}
	op := certOperation{OperationID: opID, Action: certActionImport, Actor: actor, Target: "root_ca",
		CandidateDigest: cand.FingerprintHex(), Fence: current, Previous: caPreviousFacts()}
	op.AuditDetail = certAuditDetail(op)
	if !certBegin(w, s, op) {
		return
	}
	if !persistCACandidate(w, s, opID, cand, "CA import") {
		return
	}
	certMgr.Install(cand)
	noteCARotationPersisted()
	noteSSLInspectionRecovered("custom MITM CA imported via admin API")
	result := caOperationResult(op)
	certCommit(s, opID, caRevisionToken(), result, op.AuditDetail)
	jsonOK(w, result)
}

func apiCertsReplaceUI(w http.ResponseWriter, r *http.Request, certPEM, keyPEM []byte, dryRun bool) {
	tlsCert, err := ca.ParseTLSCandidate(certPEM, keyPEM)
	if err != nil {
		writeCandidateRefusal(w, err)
		return
	}
	leaf := tlsCert.Leaf
	candidate := map[string]any{
		"fingerprint": ca.FingerprintOf(leaf), "subject": leaf.Subject.CommonName, "issuer": leaf.Issuer.CommonName,
		"notBefore": leaf.NotBefore.UTC().Format(time.RFC3339), "notAfter": leaf.NotAfter.UTC().Format(time.RFC3339),
		"dnsNames": leaf.DNSNames, "chainLength": len(tlsCert.Certificate),
	}
	if dryRun {
		jsonOK(w, map[string]any{"dryRun": true, "target": "ui", "action": certActionUIReplace, "candidate": candidate,
			"current": map[string]any{"uiCertRevision": uiCertRevisionToken()}})
		return
	}
	digest := hexDigest(certPEM)
	opID, echoed, s, ok := certMutationPrelude(w, r, certActionUIReplace, "uiCertRevision", uiCertRevisionToken(),
		func(prev *certOperation) bool { return prev.CandidateDigest == digest })
	if !ok {
		return
	}
	actor := auditActor(r)

	certOpsMu.Lock()
	defer certOpsMu.Unlock()

	current := uiCertRevisionToken()
	if !certFenceMatches(w, "uiCertRevision", echoed, current) {
		return
	}
	if current == "uic1:"+digest && uiKeyOnDiskEquals(keyPEM) {
		writeRefusal(w, http.StatusConflict, refusalCandidateDup, "this certificate pair is already persisted",
			map[string]any{"uiCertRevision": current})
		return
	}
	if !certSettleTargetOrRefuse(w, s, "ui_cert") {
		return
	}
	op := certOperation{OperationID: opID, Action: certActionUIReplace, Actor: actor, Target: "ui_cert",
		CandidateDigest: digest, Fence: current, Candidate: candidate}
	op.AuditDetail = certAuditDetail(op)
	if !certBegin(w, s, op) {
		return
	}
	if err := persistCustomUITLS(certPEM, keyPEM); err != nil {
		uiCertPersistRefusal(w, s, opID, err)
		return
	}
	// The pair just written passed validation, so any PRIOR corruption latch
	// no longer describes what is on disk.
	uiCustomTLSCorrupt = false
	result := uiCertOperationResult(op)
	certCommit(s, opID, uiCertRevisionToken(), result, op.AuditDetail)
	jsonOK(w, result)
}

func uiKeyOnDiskEquals(keyPEM []byte) bool {
	onDisk, err := os.ReadFile(customUITLSKeyPath())
	return err == nil && bytes.Equal(onDisk, keyPEM)
}

// uiCertPersistRefusal answers a failed UI-pair write: a compensating
// rollback that also failed leaves neither pair provably on disk
// (non-terminal 500 outcome_unknown); anything else aborted the operation
// with the previous pair intact (500 persist_failed).
func uiCertPersistRefusal(w http.ResponseWriter, s *certOperationStore, opID string, err error) {
	class := ca.PersistFailureClass(err)
	if errors.Is(err, errUITLSRollbackFailed) {
		logger.Printf("certs upload UI: persist failed AND the previous certificate could not be restored (%s)", class)
		if ferr := s.Finish(opID, certOpOutcomeUnknown, refusalPersistFailed, "", nil, ""); ferr != nil {
			logger.Printf("Certificates: operation %s outcome record not durable (%s)", sanitizeLog(opID), certBoundedLedgerClass(ferr))
		}
		writeRefusal(w, http.StatusInternalServerError, refusalOutcomeUnknown,
			"the certificate could not be saved and the previous certificate could not be restored; do not restart until the data directory is repaired, then re-upload a known-good pair",
			map[string]any{"detail": "rollback_failed", "operationId": opID})
		return
	}
	logger.Printf("certs upload UI: persist failed (%s) — the current UI certificate is unchanged", class)
	if !certAbort(s, opID) {
		certRefusalNotDurable(w, opID)
		return
	}
	writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed,
		"the certificate could not be saved; the current UI certificate is unchanged", map[string]any{"class": class, "operationId": opID})
}

// ── DELETE /api/certs/ui (admin) ────────────────────────────────────────────

// apiCertsUI deletes the persisted admin-UI certificate pair. The running
// listener keeps whatever it loaded at boot (`active` is exposed as the T3
// fact); the next restart falls back to the auto self-signed certificate.
func apiCertsUI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	opID, echoed, s, ok := certMutationPrelude(w, r, certActionUIDelete, "uiCertRevision", uiCertRevisionToken(), sameOperation)
	if !ok {
		return
	}
	actor := auditActor(r)

	certOpsMu.Lock()
	defer certOpsMu.Unlock()

	current := uiCertRevisionToken()
	if !certFenceMatches(w, "uiCertRevision", echoed, current) {
		return
	}
	if current == uiCertRevisionNone {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "no custom UI certificate is persisted on this node", nil)
		return
	}
	if !certSettleTargetOrRefuse(w, s, "ui_cert") {
		return
	}
	op := certOperation{OperationID: opID, Action: certActionUIDelete, Actor: actor, Target: "ui_cert", Fence: current, WasActive: uiCustomTLSActive}
	op.AuditDetail = certAuditDetail(op)
	if !certBegin(w, s, op) {
		return
	}
	if !removeUICertPair(w, s, opID) {
		return
	}
	uiCustomTLSCorrupt = false
	result := uiCertOperationResult(op)
	certCommit(s, opID, uiCertRevisionToken(), result, op.AuditDetail)
	jsonOK(w, result)
}

// removeUICertPair removes the private key FIRST (a crash between the two
// removes leaves a cert-only remnant that customUITLSFilesPresent reads as
// ABSENT), then the certificate. A key-removal failure aborts with nothing
// changed; a certificate-removal failure after the key is gone is the
// non-terminal outcome_unknown.
func removeUICertPair(w http.ResponseWriter, s *certOperationStore, opID string) bool {
	if err := os.Remove(customUITLSKeyPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		if !certAbort(s, opID) {
			certRefusalNotDurable(w, opID)
			return false
		}
		writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed,
			"the private key file could not be removed; nothing was changed", map[string]any{"class": ca.PersistFailureClass(err), "operationId": opID})
		return false
	}
	if err := os.Remove(customUITLSCertPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Printf("certs delete UI: key removed but the certificate file could not be removed (%s)", ca.PersistFailureClass(err))
		if ferr := s.Finish(opID, certOpOutcomeUnknown, refusalPersistFailed, "", nil, ""); ferr != nil {
			logger.Printf("Certificates: operation %s outcome record not durable (%s)", sanitizeLog(opID), certBoundedLedgerClass(ferr))
		}
		writeRefusal(w, http.StatusInternalServerError, refusalOutcomeUnknown,
			"the private key was removed but the certificate file remains; the pair is no longer usable and the next boot falls back to the self-signed certificate",
			map[string]any{"detail": "certificate_file_remains", "operationId": opID})
		return false
	}
	return true
}

// ── GET /api/ca/operations/{id} (admin) ─────────────────────────────────────

// apiCAOperations is the authoritative lost-response lookup: a pending
// intent is settled from its object's own evidence, an owed audit is
// completed exactly once, and the durable record is returned.
func apiCAOperations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		certMethodRefusal(w)
		return
	}
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	id := strings.ToLower(strings.TrimPrefix(r.URL.Path, "/api/ca/operations/"))
	if !validIdPOperationID(id) {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "operationId must be a UUID", nil)
		return
	}
	s, ok := certLedger(w)
	if !ok {
		return
	}
	certOpsMu.Lock()
	defer certOpsMu.Unlock()
	rec, err := s.Get(id)
	if err != nil {
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded, "the certificate operation ledger is degraded", nil)
		return
	}
	if rec == nil {
		writeRefusal(w, http.StatusNotFound, refusalNotFound, "no such operation", nil)
		return
	}
	if rec.State == certOpPending {
		if err := settleCertOperation(s, *rec, "lookup"); err != nil {
			logger.Printf("Certificates: operation %s could not be settled by the lookup (%s)", sanitizeLog(id), certBoundedLedgerClass(err))
		}
	} else if rec.State == certOpCommitted && !rec.Audited {
		if err := s.emitOperationAudit(*rec); err != nil {
			logger.Printf("Certificates: operation %s audit still pending (%s)", sanitizeLog(id), certBoundedLedgerClass(err))
		}
	}
	rec, err = s.Get(id)
	if err != nil || rec == nil {
		writeRefusal(w, http.StatusServiceUnavailable, refusalOperationLedgerDegraded, "the certificate operation ledger is degraded", nil)
		return
	}
	jsonOK(w, rec.lookupReadModel())
}

// ── GET/POST /api/ocsp ──────────────────────────────────────────────────────

// apiOCSPConfig manages the upstream revocation-check posture.
//
// GET publishes the DESIRED (durable) state beside the RUNTIME state, the
// revision fence, the node-local scope and a bounded mTLS client-cert
// reason. POST is fenced (?ocspRevision=), operation-identified and
// persist-before-apply: the durable file records the target under
// adminSettingsMu and the checker is flipped only after the write landed,
// so a 200 always describes a posture that survives a restart.
//
// Intentionally OUT of the config-version rollback surface — relaxing
// revocation checking via rollback would silently re-permit traffic to certs
// the admin deliberately tightened against. Do NOT add saveConfigVersion here.
func apiOCSPConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRoleJSON(w, r, RoleViewer) {
			return
		}
		jsonOK(w, ocspReadModel())
	case http.MethodPost:
		apiOCSPSet(w, r)
	default:
		certMethodRefusal(w)
	}
}

func ocspReadModel() map[string]any {
	var lastFailClosedAt string
	if t := globalOCSP.LastFailClosedAt(); !t.IsZero() {
		lastFailClosedAt = t.Format(time.RFC3339)
	}
	d := ocspDesiredSnapshot()
	resp := map[string]any{
		"enabled":          globalOCSP.Enabled(),
		"revision":         ocspRevisionToken(),
		"scope":            certScopeNodeLocal,
		"desired":          map[string]any{"enabled": d.enabled, "source": d.source},
		"runtime":          map[string]any{"enabled": globalOCSP.Enabled()},
		"durable":          d.saved,
		"cacheLen":         globalOCSP.CacheLen(),
		"failClosedTotal":  globalOCSP.FailClosedTotal(),
		"revokedTotal":     globalOCSP.RevokedTotal(),
		"lastFailClosedAt": lastFailClosedAt,
		// CHAOS-65: which handshakes actually consult the checker.
		"coverage":                   ocspCoverage(),
		"uncheckedEnforcingPaths":    ocspUncheckedEnforcingPaths(),
		"notForCertificateTotal":     globalOCSP.NotForCertificateTotal(),
		"unauthorizedResponderTotal": globalOCSP.UnauthorizedResponderTotal(),
		"malformedResponseTotal":     globalOCSP.MalformedTotal(),
		"staleResponseTotal":         globalOCSP.StaleTotal(),
		"unknownStatusTotal":         globalOCSP.UnknownTotal(),
		"responderBlockedTotal":      globalOCSP.ResponderBlockedTotal(),
		"respondersTruncatedTotal":   globalOCSP.RespondersTruncatedTotal(),
	}
	// Upstream mTLS client-cert health rides the same admin surface as OCSP
	// (both are loaded by loadMTLSAndOCSP) — bounded (FE-6B.0): no path, no
	// loader text.
	if mc := mtlsClientCertHealth(); mc.configured {
		resp["mtlsClientCertConfigured"] = true
		resp["mtlsClientCertLoaded"] = mc.loaded
		if mc.loaded {
			resp["mtlsClientCertNotAfter"] = mc.notAfter.UTC().Format(time.RFC3339)
			resp["mtlsClientCertDaysRemaining"] = daysUntil(mc.notAfter)
		} else if mc.reason != "" {
			resp["mtlsClientCertReason"] = mc.reason
		}
	}
	return resp
}

func apiOCSPSet(w http.ResponseWriter, r *http.Request) {
	if !requireRoleJSON(w, r, RoleAdmin) {
		return
	}
	if _, ok := certOperationID(w, r); !ok {
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := decodeJSON(r, &body); err != nil {
		writeRefusal(w, http.StatusBadRequest, refusalInvalidInput, "invalid JSON body: {enabled: boolean}", nil)
		return
	}
	want := "disabled"
	if body.Enabled {
		want = "enabled"
	}
	opID, echoed, s, ok := certMutationPrelude(w, r, certActionOCSPSet, "ocspRevision", ocspRevisionToken(),
		func(prev *certOperation) bool { return prev.CandidateDigest == want })
	if !ok {
		return
	}
	actor := auditActor(r)

	certOpsMu.Lock()
	defer certOpsMu.Unlock()

	current := ocspRevisionToken()
	if !certFenceMatches(w, "ocspRevision", echoed, current) {
		return
	}
	if !certSettleTargetOrRefuse(w, s, "ocsp") {
		return
	}
	d := ocspDesiredSnapshot()
	// The target posture carries THIS operation as its writer: the
	// provenance lands in the same atomic settings write as the posture.
	target := ocspDesiredState{saved: true, enabled: body.Enabled, generation: d.generation + 1, source: "admin", writeID: opID}
	op := certOperation{OperationID: opID, Action: certActionOCSPSet, Actor: actor, Target: "ocsp",
		CandidateDigest: want, Fence: current, Expect: "gen=" + itoa64(target.generation)}
	op.AuditDetail = certAuditDetail(op)
	if !certBegin(w, s, op) {
		return
	}
	err := saveAdminSettingsWithOverrides(adminSaveOverrides{
		ocspSettings: &target,
		applyOnSuccess: func() {
			setOCSPDesiredAdmin(target.enabled, target.generation, target.writeID)
			ocspApplyRuntime(target.enabled)
		},
	})
	if err != nil {
		logger.Printf("OCSP set: durable write failed (%s) — runtime unchanged", ca.PersistFailureClass(err))
		if !certAbort(s, opID) {
			certRefusalNotDurable(w, opID)
			return
		}
		writeRefusal(w, http.StatusInternalServerError, refusalPersistFailed,
			"the OCSP posture could not be persisted; the running posture is unchanged", map[string]any{"operationId": opID})
		return
	}
	result := ocspOperationResult(op)
	certCommit(s, opID, ocspRevisionToken(), result, op.AuditDetail)
	jsonOK(w, result)
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
