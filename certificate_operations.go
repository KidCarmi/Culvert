package main

// certificate_operations.go — FE-6B.0 Certificates and CA lifecycle backend
// truth: server-owned identities, the durable operation ledger, the bound
// rotation challenge, the OCSP desired state and the bounded fault classes
// the admin surfaces publish instead of raw errors.
//
// IDENTITIES (server-owned, opaque, content-derived):
//
//	caRevision     car1:<sha256 hex of the live Root CA DER>   | car1:none
//	uiCertRevision uic1:<sha256 hex of the persisted UI cert>   | uic1:none
//	ocspRevision   ocr1:<sha256 hex of the durable desired state + generation>
//
// A fenced mutation echoes the token it loaded; absent ⇒ 428
// precondition_required, mismatch ⇒ 409 stale with the current token — and
// the comparison runs INSIDE the serialized mutation boundary (certOpsMu),
// never as a handler check followed by an unlocked write.
//
// THE LEDGER (`<dataDir>/certificate_operations.json`) mirrors the IdP
// operation ledger (idp_operations.go) minus the candidate key: nothing in a
// certificate operation is secret — a candidate is identified by its
// certificate fingerprint, a rotation by the fence it consumed, an OCSP set
// by its target value. Intent before mutation; a terminal state only once
// durable; the success audit part of the record, emitted exactly once by
// AppendOperation and marked durably after; a corrupt or unreadable file is
// FAIL-CLOSED with the evidence preserved.
//
// SETTLEMENT of a pending intent never rests on a guess: a CA intent is
// committed iff the LIVE CA (or the bundle on disk — a crash between the
// durable write and the install is finished by the next boot's load) carries
// the candidate's fingerprint; a UI-cert replace iff the persisted cert has
// the candidate's digest; a UI-cert delete iff no pair is persisted; an OCSP
// set iff the durable settings carry the target at the generation the intent
// advanced to. Anything else is aborted, or unproven ⇒ outcome_unknown.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/ca"
)

const (
	certOperationsFile = "certificate_operations.json"
	certOperationsMax  = 256

	certOpPending        = "pending"
	certOpCommitted      = "committed"
	certOpAborted        = "aborted"
	certOpOutcomeUnknown = "outcome_unknown"

	certActionRotate    = "ca.rotate"
	certActionImport    = "ca.import"
	certActionUIReplace = "cert.ui.replace"
	certActionUIDelete  = "cert.ui.delete"
	certActionOCSPSet   = "ocsp.set"

	caRevisionPrefix   = "car1:"
	uiCertRevisionNone = "uic1:none"
	caRevisionNone     = "car1:none"
	certScopeNodeLocal = "node-local"

	// caChallengeTTL bounds a rotation challenge's life; the issue response
	// states it and an expired confirm is refused with changed:[expired].
	caChallengeTTL = 120 * time.Second
)

// caOpsBeforeFinishHook runs after a CA candidate is durably committed and
// installed and BEFORE the operation's terminal record is persisted (test
// seam for the finalization-failure row; nil in production).
var caOpsBeforeFinishHook func()

// caChallengeClock is the rotation challenge's clock (nil ⇒ time.Now).
var caChallengeClock func() time.Time

func caChallengeNow() time.Time {
	if caChallengeClock != nil {
		return caChallengeClock()
	}
	return time.Now()
}

// certOpsMu serializes EVERY certificate/CA/OCSP mutation end to end
// (fence → intent → persist → publish → terminal record). Outer to
// caMutationMu (the CA paths take both, in that order) and to adminSettingsMu
// (the OCSP path saves under it). Nothing under either may call back here.
var certOpsMu sync.Mutex

// ── revision tokens ─────────────────────────────────────────────────────────

func caRevisionToken() string {
	if hexfp := certMgr.LiveCertificateHex(); hexfp != "" {
		return caRevisionPrefix + hexfp
	}
	return caRevisionNone
}

// uiCertRevisionToken identifies the PERSISTED admin-UI certificate by the
// digest of its certificate file; the key never contributes to a public
// token.
func uiCertRevisionToken() string {
	if !customUITLSFilesPresent() {
		return uiCertRevisionNone
	}
	data, err := os.ReadFile(customUITLSCertPath())
	if err != nil {
		return uiCertRevisionNone
	}
	return "uic1:" + hexDigest(data)
}

func hexDigest(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// ── ledger ──────────────────────────────────────────────────────────────────

// certOperation is one durable intent record. Every field is non-secret.
type certOperation struct {
	OperationID string `json:"operationId"`
	State       string `json:"state"`
	Action      string `json:"action"`
	Actor       string `json:"actor"`
	Target      string `json:"target"` // root_ca | ui_cert | ocsp
	// CandidateDigest identifies WHAT the operation installs: the candidate
	// certificate's hex fingerprint (import, UI replace), "" for a rotation
	// (the candidate is minted server-side) and a UI delete, the target
	// value for an OCSP set ("enabled" | "disabled").
	CandidateDigest string `json:"candidateDigest,omitempty"`
	// Fence is the revision the caller echoed; for an OCSP set also the
	// generation the commit advances to (in Expect).
	Fence      string          `json:"fence"`
	Expect     string          `json:"expect,omitempty"`
	StartedAt  string          `json:"startedAt"`
	FinishedAt string          `json:"finishedAt,omitempty"`
	Code       string          `json:"code,omitempty"`
	Result     json.RawMessage `json:"result,omitempty"`
	// CommittedRevision is the object's revision after the commit.
	CommittedRevision string `json:"committedRevision,omitempty"`
	Audited           bool   `json:"audited"`
	AuditDetail       string `json:"auditDetail,omitempty"`
}

func (op *certOperation) unresolved() bool {
	return op.State == certOpPending || op.State == certOpOutcomeUnknown
}

func (op *certOperation) decided() bool {
	switch op.State {
	case certOpAborted:
		return true
	case certOpCommitted:
		return op.Audited
	default:
		return false
	}
}

type certOpsDegradation struct {
	Reason string `json:"reason"` // corrupt | unreadable
	Detail string `json:"detail"`
}

type certOperationStore struct {
	mu       sync.Mutex
	path     string
	ops      []*certOperation
	degraded *certOpsDegradation
}

var (
	errCertOperationPersist        = errors.New("certificates: operation record could not be persisted")
	errCertOperationLedgerDegraded = errors.New("certificates: operation ledger degraded")
	errCertOperationLedgerFull     = errors.New("certificates: operation ledger full of unresolved intents")
	errCertOperationAuditPending   = errors.New("certificates: operation success audit is pending durability")
)

var certOpsGlobal struct {
	mu    sync.Mutex
	store *certOperationStore
}

// certOpsStore returns the ledger for the CURRENT dataDir, opening it on
// first use (or after the data root moved — a test seam in practice).
func certOpsStore() *certOperationStore {
	certOpsGlobal.mu.Lock()
	defer certOpsGlobal.mu.Unlock()
	want := filepath.Join(dataDir, certOperationsFile)
	if certOpsGlobal.store == nil || certOpsGlobal.store.path != want {
		certOpsGlobal.store = openCertOperationStore(want)
	}
	return certOpsGlobal.store
}

// reopenCertificateOperationsForTest re-reads the ledger from its file (a
// process restart as far as the ledger is concerned).
var reopenCertificateOperationsForTest = func() {
	certOpsGlobal.mu.Lock()
	defer certOpsGlobal.mu.Unlock()
	certOpsGlobal.store = openCertOperationStore(filepath.Join(dataDir, certOperationsFile))
}

func openCertOperationStore(path string) *certOperationStore {
	s := &certOperationStore{path: path}
	data, err := os.ReadFile(path)
	switch {
	case err == nil:
		var ops []*certOperation
		if jerr := json.Unmarshal(data, &ops); jerr != nil {
			s.degraded = &certOpsDegradation{Reason: "corrupt",
				Detail: "the certificate operation ledger is corrupt; operation-identified writes and lookups are refused until the file is restored (or removed, which starts an empty ledger) and the node restarted"}
			logger.Printf("Certificates: operation ledger CORRUPT — fail-closed (evidence preserved at %s)", sanitizeLog(certOperationsFile))
			return s
		}
		for _, op := range ops {
			if op != nil {
				s.ops = append(s.ops, op)
			}
		}
	case errors.Is(err, fs.ErrNotExist):
		// empty ledger
	default:
		s.degraded = &certOpsDegradation{Reason: "unreadable",
			Detail: "the certificate operation ledger cannot be read; operation-identified writes and lookups are refused until the file is restored (or removed, which starts an empty ledger) and the node restarted"}
		logger.Printf("Certificates: operation ledger UNREADABLE — fail-closed (evidence preserved at %s)", sanitizeLog(certOperationsFile))
	}
	return s
}

func (s *certOperationStore) Degraded() *certOpsDegradation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded == nil {
		return nil
	}
	d := *s.degraded
	return &d
}

func (s *certOperationStore) persistCandidate(ops []*certOperation) error {
	data, err := json.MarshalIndent(ops, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.path, data, 0o600)
}

func (s *certOperationStore) cloneWith(id string, rec *certOperation) []*certOperation {
	out := make([]*certOperation, 0, len(s.ops)+1)
	replaced := false
	for _, op := range s.ops {
		if op.OperationID == id {
			out = append(out, rec)
			replaced = true
			continue
		}
		out = append(out, op)
	}
	if !replaced {
		out = append(out, rec)
	}
	return out
}

func (s *certOperationStore) findLocked(id string) *certOperation {
	for _, op := range s.ops {
		if op != nil && op.OperationID == id {
			return op
		}
	}
	return nil
}

// Get returns a copy of the recorded operation, or nil. A degraded ledger
// answers nil with the error — never "unknown".
func (s *certOperationStore) Get(id string) (*certOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return nil, errCertOperationLedgerDegraded
	}
	if op := s.findLocked(id); op != nil {
		cp := *op
		return &cp, nil
	}
	return nil, nil
}

// Unresolved returns copies of every record still awaiting its verdict.
func (s *certOperationStore) Unresolved() []certOperation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []certOperation
	for _, op := range s.ops {
		if op.unresolved() {
			out = append(out, *op)
		}
	}
	return out
}

func (s *certOperationStore) Counts() (total, unresolved int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, op := range s.ops {
		total++
		if op.unresolved() {
			unresolved++
		}
	}
	return total, unresolved
}

func (s *certOperationStore) evictDecidedLocked() (fits bool) {
	if len(s.ops) < certOperationsMax {
		return true
	}
	kept := make([]*certOperation, 0, len(s.ops))
	need := len(s.ops) - certOperationsMax + 1
	for _, op := range s.ops {
		if need > 0 && op.decided() {
			need--
			continue
		}
		kept = append(kept, op)
	}
	if need > 0 {
		return false
	}
	s.ops = kept
	return true
}

// Begin records intent BEFORE the first irreversible write. A known id
// returns the recorded operation and created=false. A new intent is durable
// before Begin returns; a persist failure records nothing.
//
// Deliberately the same shape as idpOperationStore.Begin: the two ledgers
// hold different record types and are kept independent on purpose (the IdP
// one carries a keyed secret commitment this one must never grow), so the
// duplication is the contract, not an oversight.
//
//nolint:dupl // mirrors idpOperationStore.Begin by design (see above)
func (s *certOperationStore) Begin(op certOperation) (existing *certOperation, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return nil, false, errCertOperationLedgerDegraded
	}
	if prev := s.findLocked(op.OperationID); prev != nil {
		cp := *prev
		return &cp, false, nil
	}
	before := s.ops
	if !s.evictDecidedLocked() {
		return nil, false, errCertOperationLedgerFull
	}
	op.State = certOpPending
	op.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	rec := op
	candidate := append(append([]*certOperation(nil), s.ops...), &rec)
	if err := s.persistCandidate(candidate); err != nil {
		s.ops = before
		return nil, false, fmt.Errorf("%w: %v", errCertOperationPersist, err)
	}
	s.ops = candidate
	return nil, true, nil
}

// Finish records the terminal outcome DURABLY. On a persist failure nothing
// changes in memory and errCertOperationPersist is returned.
func (s *certOperationStore) Finish(id, state, code, committedRevision string, result any, auditDetail string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return errCertOperationLedgerDegraded
	}
	op := s.findLocked(id)
	if op == nil {
		return nil
	}
	rec := *op
	rec.State = state
	rec.Code = code
	rec.CommittedRevision = committedRevision
	rec.FinishedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if state == certOpCommitted {
		if result != nil {
			if b, err := json.Marshal(result); err == nil {
				rec.Result = b
			}
		}
		rec.AuditDetail = auditDetail
	}
	candidate := s.cloneWith(id, &rec)
	if err := s.persistCandidate(candidate); err != nil {
		return fmt.Errorf("%w: %v", errCertOperationPersist, err)
	}
	s.ops = candidate
	return nil
}

func (s *certOperationStore) MarkAudited(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return errCertOperationLedgerDegraded
	}
	op := s.findLocked(id)
	if op == nil || op.Audited {
		return nil
	}
	rec := *op
	rec.Audited = true
	candidate := s.cloneWith(id, &rec)
	if err := s.persistCandidate(candidate); err != nil {
		return fmt.Errorf("%w: %v", errCertOperationPersist, err)
	}
	s.ops = candidate
	return nil
}

// emitOperationAudit completes the success audit of a committed operation
// EXACTLY ONCE (audit.AppendOperation is idempotent on action+operationId)
// and marks it durably after; any failure leaves the operation
// committed-but-audit-pending for the next lookup/boot to retry.
func (s *certOperationStore) emitOperationAudit(op certOperation) error {
	if op.State != certOpCommitted || op.Audited {
		return nil
	}
	_, err := audit.AppendOperation(audit.Entry{
		TS:          time.Now().UnixMilli(),
		Time:        time.Now().Format("2006-01-02 15:04:05"),
		Actor:       op.Actor,
		Action:      op.Action,
		Object:      op.Target,
		Detail:      op.AuditDetail,
		OperationID: op.OperationID,
	})
	if err != nil {
		return fmt.Errorf("%w: append: %v", errCertOperationAuditPending, err)
	}
	if err := s.MarkAudited(op.OperationID); err != nil {
		return fmt.Errorf("%w: marker: %v", errCertOperationAuditPending, err)
	}
	return nil
}

// lookupReadModel is the GET /api/ca/operations/{id} projection.
func (op *certOperation) lookupReadModel() map[string]any {
	out := map[string]any{
		"operationId": op.OperationID,
		"state":       op.State,
		"action":      op.Action,
		"actor":       op.Actor,
		"target":      op.Target,
		"fence":       op.Fence,
		"startedAt":   op.StartedAt,
		"audited":     op.Audited,
	}
	if op.State == certOpCommitted && !op.Audited {
		out["auditState"] = "pending"
	}
	if op.CandidateDigest != "" && op.Action != certActionOCSPSet {
		out["candidateFingerprint"] = op.CandidateDigest
	}
	if op.FinishedAt != "" {
		out["finishedAt"] = op.FinishedAt
	}
	if op.Code != "" {
		out["code"] = op.Code
	}
	if op.CommittedRevision != "" {
		out["committedRevision"] = op.CommittedRevision
	}
	if len(op.Result) > 0 {
		out["result"] = op.Result
	}
	return out
}

// readModel is the ledger posture on GET /api/certificates.
func (s *certOperationStore) readModel() map[string]any {
	total, unresolved := s.Counts()
	sink := "memory"
	if audit.PersistActive() {
		sink = "file"
	}
	out := map[string]any{"degraded": false, "retained": total, "unresolved": unresolved, "capacity": certOperationsMax, "auditSink": sink}
	if d := s.Degraded(); d != nil {
		out["degraded"] = true
		out["degradedReason"] = d.Reason
		out["degradedDetail"] = d.Detail
	}
	return out
}

// ── settlement ──────────────────────────────────────────────────────────────

// settleCertOperation decides one unresolved intent DURABLY from the
// object's own evidence (see the file header) and completes its audit. why
// is "lookup" or "reconciled". Errors leave the record as it was.
func settleCertOperation(s *certOperationStore, op certOperation, why string) error {
	if op.State != certOpPending {
		return nil
	}
	verdict, revision := certOperationVerdict(op)
	switch verdict {
	case certOpCommitted:
		if err := s.Finish(op.OperationID, certOpCommitted, why+"_committed", revision, op.Result, op.AuditDetail); err != nil {
			return err
		}
	case certOpAborted:
		return s.Finish(op.OperationID, certOpAborted, why+"_absent", "", nil, "")
	default:
		return s.Finish(op.OperationID, certOpOutcomeUnknown, why+"_unproven", "", nil, "")
	}
	settled, err := s.Get(op.OperationID)
	if err != nil || settled == nil {
		return err
	}
	return s.emitOperationAudit(*settled)
}

// certOperationVerdict is the pure evidence check behind settlement.
func certOperationVerdict(op certOperation) (verdict, revision string) {
	switch op.Action {
	case certActionRotate, certActionImport:
		return caOperationVerdict(op)
	case certActionUIReplace, certActionUIDelete:
		return uiCertOperationVerdict(op)
	case certActionOCSPSet:
		return ocspOperationVerdict(op)
	}
	return certOpOutcomeUnknown, ""
}

// caOperationVerdict: committed iff the LIVE CA — or the bundle on disk, for a
// crash between the durable write and the install that the next boot's load
// finishes — carries the candidate's fingerprint.
func caOperationVerdict(op certOperation) (verdict, revision string) {
	if op.CandidateDigest == "" {
		return certOpOutcomeUnknown, ""
	}
	if live := certMgr.LiveCertificateHex(); live == op.CandidateDigest {
		return certOpCommitted, caRevisionPrefix + live
	}
	if onDisk := bundleFingerprintHex(); onDisk == op.CandidateDigest {
		return certOpCommitted, caRevisionPrefix + onDisk
	}
	return certOpAborted, ""
}

// uiCertOperationVerdict: a replace is committed iff the persisted cert
// carries the candidate digest, a delete iff no pair is persisted; the
// fenced-on revision still present ⇒ aborted; anything else is unproven.
func uiCertOperationVerdict(op certOperation) (verdict, revision string) {
	cur := uiCertRevisionToken()
	committed := cur == "uic1:"+op.CandidateDigest
	if op.Action == certActionUIDelete {
		committed = cur == uiCertRevisionNone
	}
	switch {
	case committed:
		return certOpCommitted, cur
	case cur == op.Fence:
		return certOpAborted, ""
	default:
		return certOpOutcomeUnknown, ""
	}
}

// ocspOperationVerdict: committed iff the durable posture carries the target
// at the generation the intent advanced to.
func ocspOperationVerdict(op certOperation) (verdict, revision string) {
	d := ocspDesiredSnapshot()
	want := op.CandidateDigest == "enabled"
	switch {
	case d.saved && d.generation == parseGenerationExpect(op.Expect) && d.enabled == want:
		return certOpCommitted, ocspRevisionToken()
	case ocspRevisionToken() == op.Fence:
		return certOpAborted, ""
	default:
		return certOpOutcomeUnknown, ""
	}
}

// bundleFingerprintHex reads the configured bundle (never installs) and
// returns its certificate fingerprint, or "" when unreadable/undecodable.
func bundleFingerprintHex() string {
	if caRuntime.path == "" {
		return ""
	}
	probe := ca.New()
	if err := probe.LoadCA(caRuntime.path, caRuntime.passphrase); err != nil {
		return ""
	}
	return probe.LiveCertificateHex()
}

// reconcileCertificateOperations settles every pending intent at boot
// (called once the CA, the UI-cert store and the admin settings are loaded)
// and completes owed audits. Never mutates an object.
func reconcileCertificateOperations() {
	s := certOpsStore()
	if s.Degraded() != nil {
		return
	}
	unresolved := s.Unresolved()
	for i := range unresolved {
		if err := settleCertOperation(s, unresolved[i], "reconciled"); err != nil {
			logger.Printf("Certificates: operation %s not settled at boot (%s)", sanitizeLog(unresolved[i].OperationID), certBoundedLedgerClass(err))
		}
	}
	s.mu.Lock()
	var owed []certOperation
	for _, op := range s.ops {
		if op.State == certOpCommitted && !op.Audited {
			owed = append(owed, *op)
		}
	}
	s.mu.Unlock()
	for i := range owed {
		if err := s.emitOperationAudit(owed[i]); err != nil {
			logger.Printf("Certificates: operation %s audit still pending at boot (%s)", sanitizeLog(owed[i].OperationID), certBoundedLedgerClass(err))
		}
	}
}

func certBoundedLedgerClass(err error) string {
	switch {
	case errors.Is(err, errCertOperationLedgerDegraded):
		return "ledger_degraded"
	case errors.Is(err, errCertOperationPersist):
		return "ledger_not_durable"
	case errors.Is(err, errCertOperationAuditPending):
		return "audit_pending"
	default:
		return "settle_failed"
	}
}

// ── rotation challenge ──────────────────────────────────────────────────────

// caChallenge is one server-issued rotation challenge, bound to the
// operation, the actor, the CA revision it was issued against and its
// expiry. Process-local by design: a challenge is a ceremony token, not a
// durable fact, and a restart simply requires a fresh one.
type caChallenge struct {
	operationID string
	actor       string
	caRevision  string
	value       string
	issuedAt    time.Time
	expiresAt   time.Time
}

var caChallenges struct {
	mu   sync.Mutex
	byOp map[string]*caChallenge
}

// issueCAChallenge mints (or replaces) the challenge for opID.
func issueCAChallenge(opID, actor, caRevision string) (*caChallenge, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	now := caChallengeNow()
	ch := &caChallenge{operationID: opID, actor: actor, caRevision: caRevision,
		value: hex.EncodeToString(b[:]), issuedAt: now, expiresAt: now.Add(caChallengeTTL)}
	caChallenges.mu.Lock()
	if caChallenges.byOp == nil {
		caChallenges.byOp = map[string]*caChallenge{}
	}
	// Bounded: expired entries are swept on every issue.
	for k, v := range caChallenges.byOp {
		if now.After(v.expiresAt) {
			delete(caChallenges.byOp, k)
		}
	}
	caChallenges.byOp[opID] = ch
	caChallenges.mu.Unlock()
	return ch, nil
}

// verifyCAChallenge checks a confirm against the issued challenge WITHOUT
// consuming it. changed lists the bounded classes that differ (empty ⇒ the
// challenge binds this exact confirm); ok=false with changed==nil means no
// challenge is known for the operation at all.
func verifyCAChallenge(opID, actor, caRevision, presented string) (changed []string, ok bool) {
	now := caChallengeNow()
	caChallenges.mu.Lock()
	defer caChallenges.mu.Unlock()
	ch := caChallenges.byOp[opID]
	if ch == nil {
		// A challenge value that belongs to ANOTHER operation names the
		// class the caller got wrong.
		for _, v := range caChallenges.byOp {
			if subtle.ConstantTimeCompare([]byte(v.value), []byte(presented)) == 1 {
				return []string{"operation"}, false
			}
		}
		return nil, false
	}
	if now.After(ch.expiresAt) {
		return []string{"expired"}, false
	}
	if subtle.ConstantTimeCompare([]byte(ch.value), []byte(presented)) != 1 {
		changed = append(changed, "challenge")
	}
	if ch.actor != actor {
		changed = append(changed, "actor")
	}
	if ch.caRevision != caRevision {
		changed = append(changed, "ca_revision")
	}
	return changed, len(changed) == 0
}

// consumeCAChallenge deletes the challenge (single use). Called only after
// verifyCAChallenge answered ok, inside the mutation boundary.
func consumeCAChallenge(opID string) {
	caChallenges.mu.Lock()
	delete(caChallenges.byOp, opID)
	caChallenges.mu.Unlock()
}

// ── OCSP desired state ──────────────────────────────────────────────────────

// ocspDesiredState is the DURABLE desired posture of upstream revocation
// checking on this node. source records who set it: "default" (nothing),
// "yaml" (proxy.ocsp_check), "admin" (a fenced, operation-identified
// POST /api/ocsp persisted in admin_settings.json — which wins on load).
type ocspDesiredState struct {
	saved      bool
	enabled    bool
	generation int64
	source     string
}

var ocspDesired struct {
	mu    sync.Mutex
	state ocspDesiredState
}

func ocspDesiredSnapshot() ocspDesiredState {
	ocspDesired.mu.Lock()
	defer ocspDesired.mu.Unlock()
	d := ocspDesired.state
	if d.source == "" {
		d.source = "default"
	}
	return d
}

// noteOCSPYAMLDesired records the YAML-sourced desired state at startup
// (before admin settings load; an admin-saved state replaces it).
func noteOCSPYAMLDesired(enabled bool) {
	ocspDesired.mu.Lock()
	defer ocspDesired.mu.Unlock()
	if ocspDesired.state.saved {
		return
	}
	ocspDesired.state.enabled = enabled
	if enabled {
		ocspDesired.state.source = "yaml"
	}
}

func setOCSPDesiredAdmin(enabled bool, generation int64) {
	ocspDesired.mu.Lock()
	ocspDesired.state = ocspDesiredState{saved: true, enabled: enabled, generation: generation, source: "admin"}
	ocspDesired.mu.Unlock()
}

// resetOCSPDesiredForTest clears the desired-state record.
func resetOCSPDesiredForTest() {
	ocspDesired.mu.Lock()
	ocspDesired.state = ocspDesiredState{}
	ocspDesired.mu.Unlock()
}

// ocspRevisionToken is the fence for POST /api/ocsp: opaque, derived from
// the durable desired state AND its generation, so an A→B→A toggle never
// returns to an earlier token.
func ocspRevisionToken() string {
	d := ocspDesiredSnapshot()
	return "ocr1:" + hexDigest([]byte(fmt.Sprintf("gen=%d|enabled=%t|source=%s", d.generation, d.enabled, d.source)))
}

func parseGenerationExpect(s string) int64 {
	var g int64
	_, _ = fmt.Sscanf(s, "gen=%d", &g)
	return g
}

// ocspApplyRuntime publishes the desired posture to the running upstream
// transport. Infallible; called only after the desired state is durable.
func ocspApplyRuntime(enabled bool) {
	if !enabled {
		globalOCSP.Disable()
		return
	}
	globalOCSP.Enable()
	// P5.3: route through swapUpstreamTransport so the OCSP verify
	// callbacks land on the operator's TLS template (upstreamOpTLSCfg).
	// The swap attaches a Clone of the updated template to the new
	// transport — the stdlib's lazy h2 setup mutates the clone, not the
	// template.
	swapUpstreamTransport(ocspTransportUpdate)
	// CHAOS-65 / OCSP-8: the admin enabling this must learn the same thing
	// the startup banner says — the check does not reach inspected HTTPS.
	logOCSPCoverageWarning()
}

// applyAdminOCSP restores the admin-saved desired OCSP posture at boot
// (persistent_admin_state slice, AFTER the YAML slice) — the durable desired
// state wins over the YAML/default runtime.
func applyAdminOCSP(s *AdminSettings) {
	if !s.OCSPSettingsSaved {
		return
	}
	setOCSPDesiredAdmin(s.OCSPCheckEnabled, s.OCSPSettingsGeneration)
	ocspApplyRuntime(s.OCSPCheckEnabled)
}

// snapshotOCSPDesired writes the desired state into the settings snapshot —
// the TARGET when a fenced set is in flight, else the live desired record.
func snapshotOCSPDesired(s *AdminSettings, target *ocspDesiredState) {
	d := ocspDesiredSnapshot()
	if target != nil {
		d = *target
	}
	if !d.saved {
		return
	}
	s.OCSPSettingsSaved = true
	s.OCSPCheckEnabled = d.enabled
	s.OCSPSettingsGeneration = d.generation
}

// ── mTLS client-cert bounded reason ─────────────────────────────────────────

// mtlsClientCertReasonOf maps a load failure onto the bounded vocabulary the
// viewer surface publishes: cert_file_missing | key_file_missing |
// load_failed. Neither a path nor the loader's text ever leaves the node.
func mtlsClientCertReasonOf(certFile, keyFile string) string {
	switch {
	case certFile == "":
		return "cert_file_missing"
	case keyFile == "":
		return "key_file_missing"
	}
	if _, err := os.Stat(certFile); errors.Is(err, fs.ErrNotExist) {
		return "cert_file_missing"
	}
	if _, err := os.Stat(keyFile); errors.Is(err, fs.ErrNotExist) {
		return "key_file_missing"
	}
	return "load_failed"
}

// ── bounded CA fault classes ────────────────────────────────────────────────

// caFaultClass maps a CA load/init/persist error onto a bounded class.
func caFaultClass(err error) string {
	if err == nil {
		return ""
	}
	var errno syscall.Errno
	switch {
	case errors.Is(err, ca.ErrCAUnusable):
		return "expired"
	case errors.Is(err, fs.ErrPermission):
		return "permission_denied"
	case errors.Is(err, fs.ErrNotExist):
		return "not_found"
	case errors.As(err, &errno):
		return ca.PersistFailureClass(err)
	case errors.Is(err, ca.ErrBundleDecrypt):
		return "decrypt_failed"
	case errors.Is(err, ca.ErrBundleMalformed):
		return "bundle_malformed"
	}
	return "load_failed"
}

// caUnusableClass maps the Usable predicate onto the bounded vocabulary.
func caUnusableClass(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "no Root CA"):
		return "no_ca"
	case strings.Contains(msg, "not valid until"):
		return "not_yet_valid"
	default:
		return "expired"
	}
}
