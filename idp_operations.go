package main

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/fileutil"
)

// idp_operations.go — durable, operation-identified IdP write intents
// (FE-6A.0 correction, Blocker 9; hardened in the round-3 correction).
//
// THE DEFECT IT CLOSES: a legacy-LDAP cutover is a once-ever authority
// transition that the ENABLING registry write carries. A client whose
// response was lost could only re-send, and a re-send was a SECOND create
// with a SECOND minted profile id.
//
// THE MODEL: the client supplies a UUID `operationId`. Before the first
// irreversible write the registry persists a NON-SECRET intent bound to
// the actor, the action, the candidate's pre-minted identity and a digest of
// its public spec, and the registry document revision the caller fenced on.
// The intent moves pending → committed | aborted | outcome_unknown.
//
// THE LEDGER IS AUTHORITATIVE ONLY WHEN IT IS DURABLE (round 3):
//
//   - A terminal state is REPORTED only once its durable proof exists:
//     Finish/Resolve/MarkAudited persist a CANDIDATE ring and swap it in
//     only after the atomic write landed. A persist failure changes nothing
//     in memory and is returned, so a handler answers the NON-terminal
//     500 outcome_unknown and GET keeps reporting `pending`.
//   - Historical attribution never rests on profile PRESENCE: the create
//     stamps its operationId on the profile as PROVENANCE, co-written in
//     the same atomic registry write, so a pending intent is proven
//     committed only by a profile carrying that provenance. Every writer
//     that would change or remove a profile settles an outstanding intent
//     on it FIRST (durably) or refuses without mutation (mutate/settle).
//   - The success audit is part of the operation: the record carries the
//     audit facts and an `audited` flag, so a crash between the durable
//     terminal record and the audit is completed EXACTLY ONCE by
//     settlement/reconciliation, and a replay never audits again.
//   - The ring evicts ONLY durably decided records (committed+audited,
//     aborted). `pending`/`outcome_unknown` are never evicted; when the
//     unresolved population fills the ring, Begin refuses truthfully.
//   - A corrupt or unreadable ledger is a DURABLE, FAIL-CLOSED posture:
//     the file is left exactly where it is (evidence preserved), nothing is
//     written to that path, every operation-identified write and every
//     lookup is refused, and the read model reports the posture. It never
//     becomes an empty authoritative ledger.
//
// Secrets NEVER enter the ledger: the spec digest is over the public
// projection, the recorded result is the response the client received, and
// the audit `after` is the public profile projection.
//
// THE OPERATION BINDS THE EXACT SUBMITTED SECRET (FE-6A.2 correction,
// Blocker 2): the public spec digest cannot tell secret A from secret B, so
// the same operationId re-sent with a DIFFERENT secret used to REPLAY the
// first write's success. Every intent now also carries a CANDIDATE
// COMMITMENT — an HMAC-SHA256 over the length-framed secret material
// (OIDC clientSecret, LDAP bindPassword, inline SAML metadata) under a
// NODE-LOCAL key (`.idp_candidate_key`, 0600, beside the ledger, never
// archived — the same rule as `.upstream_cred_key`). The commitment reveals
// nothing without the key and the key never travels with the ledger; a
// replay must match BOTH the public digest and the commitment, else it is
// 409 operation_mismatch with nothing written. An intent recorded before
// this field existed carries no commitment and is compared by digest only.

const (
	idpOperationsFile = "idp_operations.json"
	idpOperationsMax  = 256
	// idpCandidateKeyFileName is the node-local HMAC key the candidate
	// commitments are computed under (beside idp_operations.json). Excluded
	// from every backup archive by name (backup.go) and never restored.
	idpCandidateKeyFileName = ".idp_candidate_key"
	idpCandidateKeyLen      = 32
	// idpImportSourcePrefix tags the reviewed-source token grammar
	// (`isr1:<64 hex>`); idpImportSourceUnavailable is the read model's
	// bounded value when the key is unusable (the import is then refused as
	// operation_ledger_degraded).
	idpImportSourcePrefix      = "isr1:"
	idpImportSourceUnavailable = "unavailable"

	idpOpPending        = "pending"
	idpOpCommitted      = "committed"
	idpOpAborted        = "aborted"
	idpOpOutcomeUnknown = "outcome_unknown"
)

// idpOperationIDPattern accepts RFC 4122 UUIDs, case-insensitive.
var idpOperationIDPattern = regexp.MustCompile(`^(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

// validIdPOperationID reports whether s is an acceptable client operationId.
func validIdPOperationID(s string) bool { return idpOperationIDPattern.MatchString(s) }

// idpOperation is one durable intent record. Every field is non-secret.
type idpOperation struct {
	OperationID string `json:"operationId"`
	State       string `json:"state"`
	Action      string `json:"action"` // idp.create | idp.update (FE-6A.2: a cutover through PUT)
	Actor       string `json:"actor"`
	ProfileID   string `json:"profileId"`
	ProfileName string `json:"profileName,omitempty"`
	SpecDigest  string `json:"specDigest"`
	// CandidateCommitment binds the EXACT submitted secret material to the
	// intent (HMAC under the node-local candidate key); "" on records that
	// predate the field. Never the secret, never reversible without the key.
	CandidateCommitment string `json:"candidateCommitment,omitempty"`
	// ImportSourceRevision (idp.import only, round 3 — Blocker 1) is the
	// server-owned keyed commitment over the legacy source the administrator
	// REVIEWED; the intent is bound to it and a replay must name it.
	ImportSourceRevision string          `json:"importSourceRevision,omitempty"`
	RegistryRevision     string          `json:"registryRevision"` // the document revision the caller fenced on
	Cutover              bool            `json:"cutover"`          // the write carried the legacy-LDAP cutover
	StartedAt            string          `json:"startedAt"`
	FinishedAt           string          `json:"finishedAt,omitempty"`
	Code                 string          `json:"code,omitempty"`   // refusal code of an aborted/unknown outcome, or the settlement reason
	Result               json.RawMessage `json:"result,omitempty"` // the recorded success response (replayed verbatim)
	// CommittedRevision is the registry document revision AFTER the commit.
	CommittedRevision string `json:"committedRevision,omitempty"`
	// Audited records that the success audit for a committed operation has
	// been emitted; AuditDetail/AuditAfter are the facts needed to emit it
	// at settlement or reconciliation (round 3).
	Audited     bool            `json:"audited"`
	AuditDetail string          `json:"auditDetail,omitempty"`
	AuditAfter  json.RawMessage `json:"auditAfter,omitempty"`
}

// unresolved reports whether the record still awaits its durable verdict.
func (op *idpOperation) unresolved() bool {
	return op.State == idpOpPending || op.State == idpOpOutcomeUnknown
}

// decided reports whether the record may be evicted: its verdict AND (for a
// commit) its audit are durable — nothing about it is still owed.
func (op *idpOperation) decided() bool {
	switch op.State {
	case idpOpAborted:
		return true
	case idpOpCommitted:
		return op.Audited
	default:
		return false
	}
}

// idpOpsDegradation is the durable fail-closed posture of a damaged ledger.
type idpOpsDegradation struct {
	Reason string `json:"reason"` // corrupt | unreadable
	Detail string `json:"detail"`
}

// idpOperationStore is the bounded, atomically-written intent ring.
type idpOperationStore struct {
	mu       sync.Mutex
	path     string // "" = in-memory (a non-persisted registry)
	ops      []*idpOperation
	degraded *idpOpsDegradation
	// commitKey is the node-local candidate-commitment key (Blocker 2):
	// loaded from `.idp_candidate_key` beside the ledger, minted 0600 when
	// absent (a fresh key cannot lock anything out — an intent it cannot
	// verify is refused as a mismatch, never replayed), random per process
	// for an in-memory ledger. An UNREADABLE key file is the same fail-closed
	// degraded posture as an unreadable ledger.
	commitKey []byte
}

var (
	// errIdPOperationPersist: a durable ledger write failed; nothing changed
	// in memory. On Begin it means the write was never attempted (500
	// persist_failed); on a terminal record it means the outcome is NOT yet
	// provable (500 outcome_unknown).
	errIdPOperationPersist = errors.New("idp: operation record could not be persisted")
	// errIdPOperationLedgerDegraded: the ledger is damaged and fail-closed.
	errIdPOperationLedgerDegraded = errors.New("idp: operation ledger degraded")
	// errIdPOperationLedgerFull: every slot holds an unresolved intent.
	errIdPOperationLedgerFull = errors.New("idp: operation ledger full of unresolved intents")
	// errIdPOperationUnsettled: a writer touched a profile whose outstanding
	// intent could not be settled durably; nothing was written.
	errIdPOperationUnsettled = errors.New("idp: outstanding operation on the target could not be settled")
	// errIdPOperationAuditPending: the success audit of a committed operation
	// could not be made durable (or its marker could not be persisted); the
	// operation stays committed-but-audit-pending and is retried by every
	// lookup, settlement and boot until the durable record holds it once.
	errIdPOperationAuditPending = errors.New("idp: operation success audit is pending durability")
)

// idpSpecDigest is the non-secret identity of a candidate profile spec: the
// public projection with the server-owned id/revision/provenance zeroed.
func idpSpecDigest(p *IdPProfile) string {
	pub := publicIdPProfile(p)
	if pub == nil {
		return ""
	}
	pub.ID, pub.Revision, pub.OperationID = "", 0, ""
	b, _ := json.Marshal(pub)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// errIdPCandidateKeyMissing: the ledger already holds commitment-bearing
// records and its key is gone — a replacement key would verify none of
// them (every exact-candidate replay would answer operation_mismatch), so
// the store must fail CLOSED instead of re-keying (round 3, Blocker 2).
var errIdPCandidateKeyMissing = errors.New("idp: candidate key missing beside a commitment-bearing ledger")

// idpLoadOrMintCandidateKey reads the node-local candidate key, publishing
// a fresh one when none exists (the mint-permitted path).
func idpLoadOrMintCandidateKey(path string) ([]byte, error) {
	return idpLoadCandidateKey(path, true)
}

// idpLoadCandidateKey reads the node-local candidate key. A read error
// other than absence is returned: the caller fails closed rather than
// committing under a key it cannot verify later. A short/long file is
// unreadable (never silently re-minted over — that would orphan every
// commitment it produced). When the key is absent and mayMint is set, ONE
// generation is published DURABLY and EXCLUSIVELY (fileutil.PublishExclusive:
// temp + fsync + link(2) + directory fsync; a concurrent minter loses the
// link and reads the winner's bytes); a failed publication is an error —
// never a key of unknown durability. With mayMint false an absent key is
// errIdPCandidateKeyMissing.
func idpLoadCandidateKey(path string, mayMint bool) ([]byte, error) {
	read := func() ([]byte, error) {
		key, err := os.ReadFile(path) // #nosec G304 -- beside the operator-configured registry file
		if err != nil {
			return nil, err
		}
		if len(key) != idpCandidateKeyLen {
			return nil, fmt.Errorf("candidate key: unexpected length %d", len(key))
		}
		return key, nil
	}
	key, err := read()
	switch {
	case err == nil:
		return key, nil
	case !os.IsNotExist(err):
		return nil, err
	case !mayMint:
		return nil, errIdPCandidateKeyMissing
	}
	fresh := make([]byte, idpCandidateKeyLen)
	if _, rerr := rand.Read(fresh); rerr != nil {
		return nil, rerr
	}
	created, perr := fileutil.PublishExclusive(path, fresh, 0o600)
	if perr != nil {
		return nil, perr
	}
	if created {
		return fresh, nil
	}
	// Another generation won the publication: read it (it is complete —
	// the winner linked only after its fsync).
	return read()
}

// hasCandidateCommitments reports whether any record carries a keyed
// commitment — the records a fresh key could never verify.
func hasCandidateCommitments(ops []*idpOperation) bool {
	for _, op := range ops {
		if op != nil && op.CandidateCommitment != "" {
			return true
		}
	}
	return false
}

// CandidateCommitment is the keyed commitment over the EXACT secret
// material of a candidate: length-framed type + OIDC clientSecret + LDAP
// bindPassword + inline SAML metadata, HMAC-SHA256 under the node-local key.
// The public spec digest carries the rest of the identity; together they
// name exactly one submitted candidate.
func (s *idpOperationStore) CandidateCommitment(p *IdPProfile) string {
	if p == nil {
		return ""
	}
	s.mu.Lock()
	key := s.commitKey
	s.mu.Unlock()
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	frame := func(v string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		mac.Write(n[:])
		mac.Write([]byte(v))
	}
	frame("idp-candidate-v1")
	frame(string(p.Type))
	if p.OIDC != nil {
		frame(p.OIDC.ClientSecret)
	} else {
		frame("")
	}
	if p.LDAP != nil {
		frame(p.LDAP.BindPassword)
	} else {
		frame("")
	}
	if p.SAML != nil {
		frame(p.SAML.MetadataXML)
	} else {
		frame("")
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// SourceCommitment is the server-owned, keyed, NON-DISCLOSING identity of
// a legacy import source (round 3, Blocker 1): "isr1:" + hex HMAC-SHA256
// under the node-local candidate key over the import candidate's public
// spec digest AND its exact secret material (the bind credential value).
// Any change to any security-effective imported field — the credential
// included — yields a different token; the token discloses nothing.
// Empty when the key is unusable (the ledger is degraded).
func (s *idpOperationStore) SourceCommitment(p *IdPProfile) string {
	if p == nil {
		return ""
	}
	s.mu.Lock()
	key := s.commitKey
	s.mu.Unlock()
	if len(key) == 0 {
		return ""
	}
	mac := hmac.New(sha256.New, key)
	frame := func(v string) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(v)))
		mac.Write(n[:])
		mac.Write([]byte(v))
	}
	frame("idp-import-source-v1")
	frame(idpSpecDigest(p))
	frame(s.CandidateCommitment(p))
	return idpImportSourcePrefix + hex.EncodeToString(mac.Sum(nil))
}

// matchesImportSource reports whether a recorded import intent was bound
// to the reviewed source token a re-dispatch names (constant time).
func (op *idpOperation) matchesImportSource(reviewed string) bool {
	return op.ImportSourceRevision != "" && hmac.Equal([]byte(op.ImportSourceRevision), []byte(reviewed))
}

// matchesCandidate reports whether a recorded intent names the same
// candidate as the (digest, commitment) pair of a re-dispatch: the public
// digest must match, and — for every record carrying a commitment — the
// exact secret material must match too.
func (op *idpOperation) matchesCandidate(specDigest, commitment string) bool {
	if op.SpecDigest != specDigest {
		return false
	}
	if op.CandidateCommitment == "" {
		return true // pre-commitment record: digest-only identity
	}
	return hmac.Equal([]byte(op.CandidateCommitment), []byte(commitment))
}

// newIdPOperationStore binds the store beside the registry file (or keeps
// it in memory when the registry itself is not persisted) and loads it. A
// damaged ledger enters the DURABLE degraded posture: the file is left in
// place as evidence and the store refuses every operation.
func newIdPOperationStore(registryPath string) *idpOperationStore {
	s := &idpOperationStore{}
	if registryPath == "" {
		s.commitKey = make([]byte, idpCandidateKeyLen)
		_, _ = rand.Read(s.commitKey) // in-memory ledger: a per-process key
		return s
	}
	s.path = filepath.Join(filepath.Dir(registryPath), idpOperationsFile)
	// The LEDGER is read first: whether its key may be minted depends on
	// what the ledger already holds (round 3, Blocker 2).
	var ops []*idpOperation
	data, err := os.ReadFile(s.path)
	switch {
	case err == nil:
		if err := json.Unmarshal(data, &ops); err != nil {
			s.degraded = &idpOpsDegradation{Reason: "corrupt",
				Detail: "the operation ledger is corrupt; operation-identified writes and lookups are refused until the file is restored (or removed, which starts an empty ledger) and the node restarted"}
			logger.Printf("IdP: operation ledger CORRUPT — fail-closed (evidence preserved at %s)", sanitizeLog(filepath.Base(s.path)))
			return s
		}
	case os.IsNotExist(err):
		// empty ledger
	default:
		s.degraded = &idpOpsDegradation{Reason: "unreadable",
			Detail: "the operation ledger cannot be read; operation-identified writes and lookups are refused until the file is restored (or removed, which starts an empty ledger) and the node restarted"}
		logger.Printf("IdP: operation ledger UNREADABLE — fail-closed (evidence preserved at %s)", sanitizeLog(filepath.Base(s.path)))
		return s
	}
	keyPath := filepath.Join(filepath.Dir(registryPath), idpCandidateKeyFileName)
	key, kerr := idpLoadCandidateKey(keyPath, !hasCandidateCommitments(ops))
	if kerr != nil {
		detail := "the operation ledger's node-local candidate key cannot be read or published durably; operation-identified writes and lookups are refused until the key file is restored and the node restarted"
		if errors.Is(kerr, errIdPCandidateKeyMissing) {
			detail = "the operation ledger's node-local candidate key is MISSING beside a ledger that carries keyed commitments; a replacement key would verify none of them, so operation-identified writes and lookups are refused until the original key file is restored and the node restarted (evidence preserved)"
		}
		s.degraded = &idpOpsDegradation{Reason: "unreadable", Detail: detail}
		logger.Printf("IdP: candidate-commitment key UNUSABLE — operation ledger fail-closed (%s: %v)", sanitizeLog(filepath.Base(idpCandidateKeyFileName)), kerr)
		return s
	}
	s.commitKey = key
	for _, op := range ops {
		if op != nil {
			s.ops = append(s.ops, op)
		}
	}
	return s
}

// Degraded returns the fail-closed posture, or nil when healthy.
func (s *idpOperationStore) Degraded() *idpOpsDegradation {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded == nil {
		return nil
	}
	d := *s.degraded
	return &d
}

// persistCandidate writes ops atomically; the caller swaps it in ONLY on
// success. Never truncates an unresolved record.
func (s *idpOperationStore) persistCandidate(ops []*idpOperation) error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(ops, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(s.path, data, 0o600)
}

// cloneWith returns a copy of the ring where the record with id is replaced
// by rec (or appended when absent).
func (s *idpOperationStore) cloneWith(id string, rec *idpOperation) []*idpOperation {
	out := make([]*idpOperation, 0, len(s.ops)+1)
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

func (s *idpOperationStore) findLocked(id string) *idpOperation {
	for _, op := range s.ops {
		if op != nil && op.OperationID == id {
			return op
		}
	}
	return nil
}

// Get returns a copy of the recorded operation, or nil. A degraded ledger
// answers nil with the error — never "unknown".
func (s *idpOperationStore) Get(id string) (*idpOperation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return nil, errIdPOperationLedgerDegraded
	}
	if op := s.findLocked(id); op != nil {
		cp := *op
		return &cp, nil
	}
	return nil, nil
}

// Unresolved returns copies of every record still awaiting its verdict.
func (s *idpOperationStore) Unresolved() []idpOperation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []idpOperation
	for _, op := range s.ops {
		if op.unresolved() {
			out = append(out, *op)
		}
	}
	return out
}

// UnauditedCommits returns copies of committed records whose success audit
// is still owed.
func (s *idpOperationStore) UnauditedCommits() []idpOperation {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []idpOperation
	for _, op := range s.ops {
		if op.State == idpOpCommitted && !op.Audited {
			out = append(out, *op)
		}
	}
	return out
}

// Counts reports the ring occupancy for the read model.
func (s *idpOperationStore) Counts() (total, unresolved int) {
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

// evictDecidedLocked drops the oldest DECIDED records until the ring has
// room for one more; unresolved records are never evicted.
func (s *idpOperationStore) evictDecidedLocked() (fits bool) {
	if len(s.ops) < idpOperationsMax {
		return true
	}
	kept := make([]*idpOperation, 0, len(s.ops))
	need := len(s.ops) - idpOperationsMax + 1
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

// Begin records intent BEFORE the first irreversible write. When the id is
// already known it returns the recorded operation and created=false. A new
// intent is durable before Begin returns; a persist failure records nothing.
func (s *idpOperationStore) Begin(op idpOperation) (existing *idpOperation, created bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return nil, false, errIdPOperationLedgerDegraded
	}
	if prev := s.findLocked(op.OperationID); prev != nil {
		cp := *prev
		return &cp, false, nil
	}
	before := s.ops
	if !s.evictDecidedLocked() {
		return nil, false, errIdPOperationLedgerFull
	}
	op.State = idpOpPending
	op.StartedAt = time.Now().UTC().Format(time.RFC3339Nano)
	rec := op
	candidate := append(append([]*idpOperation(nil), s.ops...), &rec)
	if err := s.persistCandidate(candidate); err != nil {
		s.ops = before
		return nil, false, fmt.Errorf("%w: %v", errIdPOperationPersist, err)
	}
	s.ops = candidate
	return nil, true, nil
}

// Finish records the terminal outcome DURABLY. On a persist failure nothing
// changes in memory and errIdPOperationPersist is returned — the caller
// must answer non-terminally (outcome_unknown) and leave the durable
// pending state as the truth.
func (s *idpOperationStore) Finish(id, state, code, committedRevision string, result any, auditDetail string, auditAfter any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return errIdPOperationLedgerDegraded
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
	if state == idpOpCommitted {
		rec.recordCommitFacts(result, auditDetail, auditAfter)
	}
	candidate := s.cloneWith(id, &rec)
	if err := s.persistCandidate(candidate); err != nil {
		return fmt.Errorf("%w: %v", errIdPOperationPersist, err)
	}
	s.ops = candidate
	return nil
}

// recordCommitFacts stores the replayable result and the audit facts of a
// committed operation (non-secret by construction: the public projections).
func (op *idpOperation) recordCommitFacts(result any, auditDetail string, auditAfter any) {
	if result != nil {
		if b, err := json.Marshal(result); err == nil {
			op.Result = b
		}
	}
	op.AuditDetail = auditDetail
	if auditAfter != nil {
		if b, err := json.Marshal(auditAfter); err == nil {
			op.AuditAfter = b
		}
	}
}

// MarkAudited records durably that the success audit was emitted.
func (s *idpOperationStore) MarkAudited(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degraded != nil {
		return errIdPOperationLedgerDegraded
	}
	op := s.findLocked(id)
	if op == nil || op.Audited {
		return nil
	}
	rec := *op
	rec.Audited = true
	candidate := s.cloneWith(id, &rec)
	if err := s.persistCandidate(candidate); err != nil {
		return fmt.Errorf("%w: %v", errIdPOperationPersist, err)
	}
	s.ops = candidate
	return nil
}

// emitOperationAudit completes the success audit of a committed operation
// from its recorded facts (no request context — the handler, settlement,
// reconciliation and the lookup path all reach it) EXACTLY ONCE and then
// marks it durably (round 4):
//
//  1. audit.AppendOperation appends the operation-KEYED entry only if the
//     durable record does not already hold it (a retry after a crash between
//     the append and the marker appends nothing);
//  2. the marker is persisted ONLY after the entry is durably present (or,
//     without a durable audit sink, present once in the ring — the whole
//     record of that appliance);
//  3. any failure leaves the operation committed-but-audit-pending; the
//     next retry re-runs only the step that is still missing.
func (s *idpOperationStore) emitOperationAudit(op idpOperation) error {
	if op.State != idpOpCommitted || op.Audited {
		return nil
	}
	_, err := audit.AppendOperation(audit.Entry{
		TS:          time.Now().UnixMilli(),
		Time:        time.Now().Format("2006-01-02 15:04:05"),
		Actor:       op.Actor,
		Action:      op.Action,
		Object:      op.ProfileID,
		Detail:      op.AuditDetail,
		After:       string(op.AuditAfter),
		OperationID: op.OperationID,
	})
	if err != nil {
		return fmt.Errorf("%w: append: %v", errIdPOperationAuditPending, err)
	}
	if err := s.MarkAudited(op.OperationID); err != nil {
		return fmt.Errorf("%w: marker: %v", errIdPOperationAuditPending, err)
	}
	return nil
}

// lookupReadModel is the GET /api/idp/operations/{id} projection.
func (op *idpOperation) lookupReadModel() map[string]any {
	out := map[string]any{
		"operationId":      op.OperationID,
		"state":            op.State,
		"action":           op.Action,
		"actor":            op.Actor,
		"profileId":        op.ProfileID,
		"registryRevision": op.RegistryRevision,
		"cutover":          op.Cutover,
		"startedAt":        op.StartedAt,
		"audited":          op.Audited,
	}
	if op.State == idpOpCommitted && !op.Audited {
		out["auditState"] = "pending" // committed; the durable success audit is still owed
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

// readModel is the ledger posture on GET /api/idp.
func (s *idpOperationStore) readModel() map[string]any {
	total, unresolved := s.Counts()
	sink := "memory"
	if audit.PersistActive() {
		sink = "file"
	}
	out := map[string]any{"degraded": false, "retained": total, "unresolved": unresolved, "capacity": idpOperationsMax, "auditSink": sink}
	if d := s.Degraded(); d != nil {
		out["degraded"] = true
		out["degradedReason"] = d.Reason
		out["degradedDetail"] = d.Detail
	}
	return out
}
