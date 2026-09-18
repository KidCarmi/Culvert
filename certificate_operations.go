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
// advanced to AND record the intent as the writer (per-target provenance
// co-written atomically with the posture). Anything else is aborted, or
// unproven ⇒ outcome_unknown.
//
// CURRENT CONTENT IS EVIDENCE ONLY UNTIL SOMEONE ELSE WRITES (correction
// round, Blocker 1). Content equality proves an intent's commit only while
// no later writer has changed that target, so EVERY writer of a target —
// the admin handlers, automatic rotation, the CA recovery loop — settles
// each pending intent on that target DURABLY before it writes
// (settleCertTarget, under certOpsMu), and is refused or deferred with
// nothing written when the settlement cannot be made durable
// (errCertTargetUnsettled). A pending intent therefore never outlives the
// evidence that decides it, a competitor's identical content is never
// credited to an earlier intent (the earlier intent was settled — absent —
// before the competitor wrote), and a commit whose terminal record failed is
// settled committed, with its action-bound result reconstructed from the
// intent's non-secret facts and the object's state, before the competitor
// replaces it.
//
// EVIDENCE IS NEVER GUESSED (round 3). Three rules close the round-3
// blockers. (B1) A POST-RENAME synchronisation failure of the CA bundle or
// of a UI pair file means the replacement IS on disk (fileutil.
// ErrReplacedNotSynced): the writer installs/completes it — a split
// live/disk state is never published — and answers the NON-terminal 500
// outcome_unknown with current.detail durability_unproven and the intent
// still pending; every settlement of a CA or UI intent RE-SYNCHRONISES the
// object's directory before it credits a commit (a resync that fails is
// <why>_durability_unproven, recoverable). (B2) The UI pair is a staged,
// marker-committed transition (ui_tls_custom.go) recovered at boot and at
// every settlement; a replace is credited only for a COMPLETE, VALID pair
// whose certificate is the candidate, and a delete credited from an
// incomplete cleanup completes the cleanup first and says so
// (result.cleanup = completed_at_settlement, else complete). (B3) Evidence
// that is UNAVAILABLE (unreadable path, undecodable bundle) or INVALID
// (malformed bundle) is distinguished from POSITIVE ABSENCE: only absence
// aborts; the others are recorded as the recoverable outcome_unknown codes
// <why>_evidence_unavailable / <why>_evidence_invalid, re-evaluated by every
// later settlement (lookup, boot, a recovered CA load, a writer), and an
// unavailable-evidence or unproven-durability intent BLOCKS every writer of
// its target (errCertTargetUnsettled) so the evidence is never destroyed
// before it can decide. A commit decided from the bundle on disk builds its
// action-bound result from THAT bundle, never from a different live CA.
//
// A REFUSAL IS TERMINAL ONLY ONCE DURABLE (Blocker 3): an aborted record
// that cannot be persisted leaves the pending intent as the durable truth,
// the caller gets the NON-terminal 500 outcome_unknown
// (current.detail refusal_not_durable, current.state pending) and the next
// settlement — lookup, boot, or a later writer of the target — records the
// refusal it stood for (certRefusalMemo) or the bounded absent verdict.
//
// THE BOOT IS ORDERED (Blocker 2): the auto-rotation loop's first round
// waits for the certificate-lifecycle boot gate, which LoadAdminSettings
// releases on every load path after reconciling the ledger — never by
// startup timing.

import (
	"context"
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
	"github.com/KidCarmi/Culvert/internal/fileutil"
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

	// Round-3 UI-cert revision tokens that are NOT identities: the pair
	// could not be examined, or only one of its two files exists. Neither
	// ever equals uic1:none, so unavailable evidence can never prove a
	// pending delete.
	uiCertRevisionUnavailable = "uic1:unavailable"
	uiCertRevisionIncomplete  = "uic1:incomplete"

	// Recoverable outcome_unknown code suffixes (round 3). A record carrying
	// one is re-evaluated by every later settlement; the first two also
	// BLOCK writers of the target.
	certCodeEvidenceUnavailable = "evidence_unavailable"
	certCodeDurabilityUnproven  = "durability_unproven"
	certCodeCleanupIncomplete   = "cleanup_incomplete"
	certCodeEvidenceInvalid     = "evidence_invalid"
	certCodeUnproven            = "unproven"

	certCleanupComplete     = "complete"
	certCleanupAtSettlement = "completed_at_settlement"

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
// token. Evidence that cannot be examined is uic1:unavailable and a single
// remnant file is uic1:incomplete — distinct from uic1:none, which is
// positive absence (round 3, Blocker 3).
func uiCertRevisionToken() string {
	return uiCertRevisionTokenOf(uiPairEvidenceNow())
}

func uiCertRevisionTokenOf(ev uiPairEvidence) string {
	switch ev.class {
	case uiPairAbsent:
		return uiCertRevisionNone
	case uiPairComplete:
		return "uic1:" + ev.certDigest
	case uiPairIncomplete:
		return uiCertRevisionIncomplete
	default:
		return uiCertRevisionUnavailable
	}
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
	// Recovery facts (correction round, Blocker 4): every NON-secret fact a
	// committed result needs beyond the object's own state, recorded with
	// the intent so a commit whose terminal record failed replays the same
	// action-bound result the client would have received. Previous is the
	// CA identity before a rotate/import; Candidate the public facts of a
	// UI-cert candidate; WasActive whether the running listener used the
	// UI pair a delete removed. Never a key, a passphrase or raw PEM input.
	Previous  map[string]any `json:"previous,omitempty"`
	Candidate map[string]any `json:"candidate,omitempty"`
	WasActive bool           `json:"wasActive,omitempty"`
}

func (op *certOperation) unresolved() bool {
	return op.State == certOpPending || op.State == certOpOutcomeUnknown
}

// recoverable reports whether a later settlement may still decide the
// record: pending, or outcome_unknown for a reason that new evidence, a
// resync or a completed cleanup can resolve. A handler-recorded
// outcome_unknown (persist_failed) is not re-decided.
func (op *certOperation) recoverable() bool {
	if op.State == certOpPending {
		return true
	}
	if op.State != certOpOutcomeUnknown {
		return false
	}
	for _, suffix := range []string{certCodeEvidenceUnavailable, certCodeDurabilityUnproven, certCodeCleanupIncomplete, certCodeEvidenceInvalid} {
		if strings.HasSuffix(op.Code, "_"+suffix) {
			return true
		}
	}
	return false
}

// blocksWriters reports whether a writer of the record's target must wait:
// the intent is undecided (pending), or its evidence is temporarily
// unavailable, its durability unproven or its cleanup incomplete — states a
// later write would destroy the evidence of. An invalid bundle does NOT
// block (only a writer can repair it) and neither does a plain unproven
// verdict (out-of-band content that no evidence will ever decide).
func (op *certOperation) blocksWriters() bool {
	if op.State == certOpPending {
		return true
	}
	if op.State != certOpOutcomeUnknown {
		return false
	}
	for _, suffix := range []string{certCodeEvidenceUnavailable, certCodeDurabilityUnproven, certCodeCleanupIncomplete} {
		if strings.HasSuffix(op.Code, "_"+suffix) {
			return true
		}
	}
	return false
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
	errCertTargetUnsettled         = errors.New("certificates: an outstanding intent on the target could not be settled durably")
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
		if auditDetail != "" {
			rec.AuditDetail = auditDetail
		}
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

// certVerdict is one settlement decision: the durable state to record, the
// bounded code suffix for an outcome_unknown, the object's revision and the
// ACTION-BOUND result of a commit, built from the evidence that decided it.
type certVerdict struct {
	state    string
	code     string // outcome_unknown only: one of the certCode* suffixes
	revision string
	result   map[string]any
	cleanup  string // UI delete: complete | completed_at_settlement
}

func certVerdictUnknown(code string) certVerdict {
	return certVerdict{state: certOpOutcomeUnknown, code: code}
}

// settleCertOperation decides one recoverable intent DURABLY from the
// object's own evidence (see the file header) and completes its audit. why
// is "lookup", "reconciled" (boot, or a recovered CA load) or "writer" (a
// later writer of the same target, before it writes). Errors leave the
// record as it was; a record that already carries the same non-terminal
// verdict is not rewritten.
//
// A committed verdict carries the ACTION-BOUND result built from the
// evidence that decided it (the live CA, the bundle on disk, the settled
// pair) — never from a different live object. An aborted verdict records
// the refusal the operation stood for when its own refusal record could not
// be persisted (certRefusalMemo), else the bounded <why>_absent.
func settleCertOperation(s *certOperationStore, op certOperation, why string) error {
	if !op.recoverable() {
		return nil
	}
	v := certOperationVerdict(op)
	switch v.state {
	case certOpCommitted:
		if err := s.Finish(op.OperationID, certOpCommitted, why+"_committed", v.revision, v.result, certAuditDetail(op)); err != nil {
			return err
		}
	case certOpAborted:
		code := takeCertRefusalMemo(op.OperationID)
		if code == "" {
			code = why + "_absent"
		}
		return s.Finish(op.OperationID, certOpAborted, code, "", nil, "")
	default:
		if op.State == certOpOutcomeUnknown && strings.HasSuffix(op.Code, "_"+v.code) {
			return nil // the same non-terminal verdict (whoever first recorded it); nothing new to record
		}
		return s.Finish(op.OperationID, certOpOutcomeUnknown, why+"_"+v.code, "", nil, "")
	}
	settled, err := s.Get(op.OperationID)
	if err != nil || settled == nil {
		return err
	}
	return s.emitOperationAudit(*settled)
}

// settleCertTarget settles EVERY recoverable intent on target durably before
// a writer changes it (the writer protocol; caller holds certOpsMu). An
// intent that still blocks afterwards — undecided, its evidence
// unavailable, its durability unproven, its cleanup incomplete, or the
// ledger degraded — is errCertTargetUnsettled: the writer must refuse or
// defer with nothing written, because writing would destroy the evidence
// that decides the intent. Audit completion failures are not fatal here
// (the record is durable; the audit is retried by the next lookup/boot).
func settleCertTarget(s *certOperationStore, target, why string) error {
	if d := s.Degraded(); d != nil {
		return fmt.Errorf("%w: ledger %s", errCertTargetUnsettled, d.Reason)
	}
	pending := s.Unresolved()
	for i := range pending {
		op := pending[i]
		if op.Target != target || !op.recoverable() {
			continue
		}
		if err := settleCertOperation(s, op, why); err != nil && !errors.Is(err, errCertOperationAuditPending) {
			return fmt.Errorf("%w: operation %s (%s)", errCertTargetUnsettled, op.OperationID, certBoundedLedgerClass(err))
		}
		// The durable truth decides, never the settler's return value.
		rec, err := s.Get(op.OperationID)
		if err != nil || rec == nil || rec.blocksWriters() {
			return fmt.Errorf("%w: operation %s", errCertTargetUnsettled, op.OperationID)
		}
	}
	return nil
}

// certRefusalMemo remembers, in this process only, the refusal an operation
// stood for when its aborted record could not be persisted: the next
// settlement records THAT code instead of the bounded absent verdict. A
// restart loses the memo (the record then carries reconciled_absent — still
// terminal, still a refusal).
var certRefusalMemo struct {
	mu    sync.Mutex
	codes map[string]string
}

func noteCertRefusalNotDurable(opID, code string) {
	certRefusalMemo.mu.Lock()
	if certRefusalMemo.codes == nil {
		certRefusalMemo.codes = map[string]string{}
	}
	certRefusalMemo.codes[opID] = code
	certRefusalMemo.mu.Unlock()
}

func takeCertRefusalMemo(opID string) string {
	certRefusalMemo.mu.Lock()
	defer certRefusalMemo.mu.Unlock()
	code := certRefusalMemo.codes[opID]
	delete(certRefusalMemo.codes, opID)
	return code
}

// certOperationVerdict is the evidence check behind settlement. It may
// REPAIR (never guess): a UI settlement first completes or abandons an
// interrupted pair transition and completes an interrupted cleanup.
func certOperationVerdict(op certOperation) certVerdict {
	switch op.Action {
	case certActionRotate, certActionImport:
		return caOperationVerdict(op)
	case certActionUIReplace, certActionUIDelete:
		return uiCertOperationVerdict(op)
	case certActionOCSPSet:
		verdict, revision := ocspOperationVerdict(op)
		v := certVerdict{state: verdict, revision: revision, code: certCodeUnproven}
		if verdict == certOpCommitted {
			v.result = ocspOperationResult(op)
		}
		return v
	}
	return certVerdictUnknown(certCodeUnproven)
}

// caOperationVerdict: committed iff the LIVE CA — or the bundle on disk, for
// a crash between the durable write and the install that the next boot's
// load finishes — carries the candidate's fingerprint, AND the bundle's
// directory can be re-synchronised (a commit is credited only once its
// durability is resolved). An unavailable or invalid bundle beside a live CA
// that is not the candidate is NOT absence: the verdict is the recoverable
// outcome_unknown, decided again once the evidence can be read. Only a
// positively absent bundle (or a readable bundle carrying something else)
// aborts. A commit decided from the bundle names THAT bundle in its result.
func caOperationVerdict(op certOperation) certVerdict {
	if op.CandidateDigest == "" {
		return certVerdictUnknown(certCodeUnproven)
	}
	if live := certMgr.LiveCertificateHex(); live == op.CandidateDigest {
		if !caBundleDirDurable() {
			return certVerdictUnknown(certCodeDurabilityUnproven)
		}
		return certVerdict{state: certOpCommitted, revision: caRevisionPrefix + live, result: caOperationResult(op, caInfoWithRevision())}
	}
	ev := caBundleEvidenceNow()
	switch ev.class {
	case caBundleReadable:
		if ev.digest != op.CandidateDigest {
			return certVerdict{state: certOpAborted}
		}
		if !caBundleDirDurable() {
			return certVerdictUnknown(certCodeDurabilityUnproven)
		}
		info := ev.probe.CACertInfo()
		info["revision"] = caRevisionPrefix + ev.digest
		return certVerdict{state: certOpCommitted, revision: caRevisionPrefix + ev.digest, result: caOperationResult(op, info)}
	case caBundleUnavailable:
		return certVerdictUnknown(certCodeEvidenceUnavailable)
	case caBundleInvalid:
		return certVerdictUnknown(certCodeEvidenceInvalid)
	default:
		return certVerdict{state: certOpAborted}
	}
}

// caBundleDirDurable re-synchronises the configured bundle's directory so a
// replacement whose post-rename sync failed is proven before it is credited.
func caBundleDirDurable() bool {
	if caRuntime.path == "" {
		return true
	}
	return fileutil.SyncParentDir(caRuntime.path) == nil
}

// caBundleClass is the bounded state of the configured bundle on disk.
const (
	caBundleAbsent      = "absent"      // no path configured, or the file does not exist
	caBundleReadable    = "readable"    // decoded; digest and probe carry it
	caBundleUnavailable = "unavailable" // cannot be read (permissions, a directory at the path, I/O) or decrypted under the node's passphrase
	caBundleInvalid     = "invalid"     // readable and decodable but not a CA bundle
)

type caBundleEvidence struct {
	class  string
	digest string
	probe  *ca.Manager
}

// caBundleEvidenceNow examines the configured bundle WITHOUT installing it.
// A decrypt failure is unavailability (the bytes may be intact; the node
// booted with a different passphrase), a malformed plaintext is invalid, a
// missing file is absent — three states that used to collapse into "".
func caBundleEvidenceNow() caBundleEvidence {
	if caRuntime.path == "" {
		return caBundleEvidence{class: caBundleAbsent}
	}
	if _, err := os.Stat(caRuntime.path); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return caBundleEvidence{class: caBundleAbsent}
		}
		return caBundleEvidence{class: caBundleUnavailable}
	}
	probe := ca.New()
	err := probe.LoadCA(caRuntime.path, caRuntime.passphrase)
	switch {
	case err == nil:
		return caBundleEvidence{class: caBundleReadable, digest: probe.LiveCertificateHex(), probe: probe}
	case errors.Is(err, ca.ErrBundleMalformed):
		return caBundleEvidence{class: caBundleInvalid}
	case errors.Is(err, fs.ErrNotExist):
		return caBundleEvidence{class: caBundleAbsent}
	default:
		return caBundleEvidence{class: caBundleUnavailable}
	}
}

// uiCertOperationVerdict settles a UI-cert intent from the SETTLED pair:
// an interrupted transition is completed or abandoned first, then a replace
// is committed iff the pair is COMPLETE, VALID and its certificate is the
// candidate (the key is proven by the pair parsing, never by a key digest),
// and a delete iff nothing is persisted — an incomplete cleanup (one remnant
// file) is completed here and credited as completed_at_settlement. Both
// re-synchronise the directory before crediting. Unavailable evidence is
// the recoverable outcome_unknown; the fenced-on revision still present is
// aborted; anything else is unproven.
func uiCertOperationVerdict(op certOperation) certVerdict {
	rec := recoverUITLSTransition()
	if rec.Err != nil {
		if errors.Is(rec.Err, errUITLSTransitionIncomplete) {
			return certVerdictUnknown(certCodeCleanupIncomplete)
		}
		return certVerdictUnknown(certCodeEvidenceUnavailable)
	}
	ev := uiPairEvidenceNow()
	if ev.class == uiPairUnavailable {
		return certVerdictUnknown(certCodeEvidenceUnavailable)
	}
	if op.Action == certActionUIDelete {
		return uiDeleteVerdict(op, ev, rec)
	}
	if ev.class == uiPairComplete && ev.valid && ev.certDigest == op.CandidateDigest {
		if fileutil.SyncParentDir(customUITLSCertPath()) != nil {
			return certVerdictUnknown(certCodeDurabilityUnproven)
		}
		return certVerdict{state: certOpCommitted, revision: uiCertRevisionTokenOf(ev), result: uiCertOperationResult(op, "")}
	}
	if uiCertRevisionTokenOf(ev) == op.Fence {
		return certVerdict{state: certOpAborted}
	}
	return certVerdictUnknown(certCodeUnproven)
}

func uiDeleteVerdict(op certOperation, ev uiPairEvidence, rec uiTLSRecovery) certVerdict {
	cleanup := certCleanupComplete
	if rec.Completed && rec.Kind == uiTLSTransitionDelete {
		cleanup = certCleanupAtSettlement
	}
	switch ev.class {
	case uiPairIncomplete:
		// The key or the certificate was removed and the process died before
		// the other: finish the cleanup the intent committed to.
		if err := removeIfExists(customUITLSKeyPath()); err != nil {
			return certVerdictUnknown(certCodeCleanupIncomplete)
		}
		if err := removeIfExists(customUITLSCertPath()); err != nil {
			return certVerdictUnknown(certCodeCleanupIncomplete)
		}
		cleanup = certCleanupAtSettlement
	case uiPairComplete:
		if uiCertRevisionTokenOf(ev) == op.Fence {
			return certVerdict{state: certOpAborted}
		}
		return certVerdictUnknown(certCodeUnproven)
	}
	if fileutil.SyncParentDir(customUITLSCertPath()) != nil {
		return certVerdictUnknown(certCodeDurabilityUnproven)
	}
	return certVerdict{state: certOpCommitted, revision: uiCertRevisionNone, result: uiCertOperationResult(op, cleanup), cleanup: cleanup}
}

// ocspOperationVerdict: committed iff the durable posture carries the target
// at the generation the intent advanced to AND names this operation as its
// writer (the provenance admin_settings.json co-writes with the posture).
// The same target state written by ANOTHER writer is the refusal, never a
// commit; a posture with no recorded writer (a file that predates the
// provenance) is unproven.
func ocspOperationVerdict(op certOperation) (verdict, revision string) {
	d := ocspDesiredSnapshot()
	want := op.CandidateDigest == "enabled"
	switch {
	case d.saved && d.generation == parseGenerationExpect(op.Expect) && d.enabled == want:
		switch d.writeID {
		case op.OperationID:
			return certOpCommitted, ocspRevisionToken()
		case "":
			return certOpOutcomeUnknown, ""
		default:
			return certOpAborted, ""
		}
	case ocspRevisionToken() == op.Fence:
		return certOpAborted, ""
	default:
		return certOpOutcomeUnknown, ""
	}
}

// reconcileCertificateOperations settles every recoverable intent at boot
// (called once the CA, the UI-cert store and the admin settings are loaded)
// and completes owed audits. Never mutates an object beyond completing an
// interrupted UI pair transition or cleanup the intent already committed to.
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
	case errors.Is(err, errCertTargetUnsettled):
		return "target_unsettled"
	default:
		return "settle_failed"
	}
}

// ── certificate-lifecycle boot gate ─────────────────────────────────────────

// certLifecycleBootGate orders the boot explicitly (correction round,
// Blocker 2): the auto-rotation loop's IMMEDIATE round — started by the
// root-CA slice, which runs before the admin-settings slice — waits here
// until LoadAdminSettings has reconciled the operation ledger, on EVERY of
// its load paths (finishCertificateLifecycleBoot is deferred). Armed at
// process start and re-armed by loadRootCA (a fresh boot); released exactly
// once per arming. Nothing else waits on it: a released gate is a closed
// channel, and a rotation round that also settles its own target before
// writing is correct with or without the gate — the gate is what makes the
// ORDER a stated contract rather than a timing accident.
var certLifecycleBootGate struct {
	mu       sync.Mutex
	ch       chan struct{}
	released bool
}

func init() { armCertLifecycleBootGate() }

func armCertLifecycleBootGate() {
	certLifecycleBootGate.mu.Lock()
	certLifecycleBootGate.ch = make(chan struct{})
	certLifecycleBootGate.released = false
	certLifecycleBootGate.mu.Unlock()
}

func releaseCertLifecycleBootGate() {
	certLifecycleBootGate.mu.Lock()
	if !certLifecycleBootGate.released {
		certLifecycleBootGate.released = true
		close(certLifecycleBootGate.ch)
	}
	certLifecycleBootGate.mu.Unlock()
}

// awaitCertLifecycleBootGate blocks until the gate is released or ctx ends;
// it returns false when ctx ended first. caRotationBootGateObserver (a test
// seam, nil in production) is invoked once when the caller actually has to
// wait.
func awaitCertLifecycleBootGate(ctx context.Context) bool {
	certLifecycleBootGate.mu.Lock()
	ch, released := certLifecycleBootGate.ch, certLifecycleBootGate.released
	certLifecycleBootGate.mu.Unlock()
	if released {
		return true
	}
	if caRotationBootGateObserver != nil {
		caRotationBootGateObserver()
	}
	select {
	case <-ch:
		return true
	case <-ctx.Done():
		return false
	}
}

// finishCertificateLifecycleBoot is LoadAdminSettings' deferred tail:
// reconcile the ledger (the CA, the UI-cert store and the durable OCSP
// posture are loaded by then, or known unloadable), then release the gate.
func finishCertificateLifecycleBoot() {
	reconcileCertificateOperations()
	releaseCertLifecycleBootGate()
}

// Test seams (nil-safe in production): the loop reports when it waits; a
// test re-arms or releases the gate to stand in for a boot.
var (
	caRotationBootGateObserver          func()
	certLifecycleBootGateArmForTest     = armCertLifecycleBootGate
	certLifecycleBootGateReleaseForTest = releaseCertLifecycleBootGate
)

// ── action-bound results and bounded audit details ──────────────────────────

// certAuditDetail is the bounded success-audit detail of an action; recorded
// with the intent and emitted verbatim by the live commit and by a recovered
// one.
func certAuditDetail(op certOperation) string {
	switch op.Action {
	case certActionRotate:
		return "force rotation via admin API (challenge-bound)"
	case certActionImport:
		return "custom MITM CA imported via admin API"
	case certActionUIReplace:
		return "custom UI certificate replaced (restart required to activate)"
	case certActionUIDelete:
		return "custom UI certificate deleted (self-signed fallback at the next restart)"
	case certActionOCSPSet:
		return "enabled=" + op.CandidateDigest
	}
	return ""
}

// The action-bound result of a COMMITTED operation is built from the
// intent's recorded facts and the EVIDENCE that decided the commit. The live
// handlers call the same builders right after their write, so a replayed or
// recovered result is byte-for-byte the response the client would have
// received — and a commit decided from the bundle on disk names that
// bundle's CA, never a different live one (round 3, Blocker 3).

// caOperationResult builds a rotate/import result; caInfo is the deciding
// CA's public projection with its revision token.
func caOperationResult(op certOperation, caInfo map[string]any) map[string]any {
	res := map[string]any{
		"persisted":   true,
		"operationId": op.OperationID,
		"action":      op.Action,
		"scope":       certScopeNodeLocal,
		"ca":          caInfo,
		"previous":    map[string]any{"fingerprint": op.Previous["fingerprint"], "revision": op.Previous["revision"]},
	}
	if op.Action == certActionRotate {
		res["rotated"] = true
	} else {
		res["imported"] = true
		res["target"] = "mitm"
	}
	return res
}

// uiCertOperationResult builds a replace/delete result; cleanup is the
// delete's bounded cleanup fact (complete | completed_at_settlement).
func uiCertOperationResult(op certOperation, cleanup string) map[string]any {
	res := map[string]any{
		"operationId": op.OperationID,
		"action":      op.Action,
		"target":      "ui",
		"scope":       certScopeNodeLocal,
		"uiCert":      uiCertReadModel(),
	}
	if op.Action == certActionUIReplace {
		res["replaced"] = true
		res["persisted"] = true
		res["activation"] = "restart_required"
		res["candidate"] = op.Candidate
		return res
	}
	res["deleted"] = true
	if cleanup == "" {
		cleanup = certCleanupComplete
	}
	res["cleanup"] = cleanup
	if op.WasActive {
		res["activation"] = "restart_required"
	}
	return res
}

func ocspOperationResult(op certOperation) map[string]any {
	nd := ocspDesiredSnapshot()
	return map[string]any{
		"ok":          true,
		"enabled":     globalOCSP.Enabled(),
		"durable":     true,
		"revision":    ocspRevisionToken(),
		"scope":       certScopeNodeLocal,
		"operationId": op.OperationID,
		"action":      op.Action,
		"desired":     map[string]any{"enabled": nd.enabled, "source": nd.source},
		"runtime":     map[string]any{"enabled": globalOCSP.Enabled()},
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
	// writeID is the operationId of the fenced set that produced this
	// posture — per-target writer provenance, co-written atomically with
	// the posture in admin_settings.json (correction round, Blocker 1).
	// Empty on a posture that predates the provenance.
	writeID string
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

func setOCSPDesiredAdmin(enabled bool, generation int64, writeID string) {
	ocspDesired.mu.Lock()
	ocspDesired.state = ocspDesiredState{saved: true, enabled: enabled, generation: generation, source: "admin", writeID: writeID}
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
	setOCSPDesiredAdmin(s.OCSPCheckEnabled, s.OCSPSettingsGeneration, s.OCSPSettingsWriteID)
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
	s.OCSPSettingsWriteID = d.writeID
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
