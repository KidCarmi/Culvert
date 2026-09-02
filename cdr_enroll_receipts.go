package main

// cdr_enroll_receipts.go — identifiable unknown-outcome recovery for
// enrollment (2E-C trust-lifecycle correction, R8; binding immutability +
// fail-closed loading, round 2 R12).
//
// Sluice consumes the single-use token and issues the credential in ONE
// exchange, so a lost response used to leave the appliance with no way to
// learn whether a credential now exists on the Sluice side, let alone to
// revoke it. Three durable, non-secret pieces close that:
//
//  1. Every enrollment carries a client-minted 128-bit OPERATION ID that
//     Sluice v0.3 binds durably to the issued fingerprint before it
//     responds (EnrollRequest.operation_id / EnrollStatus).
//  2. The appliance persists a RECEIPT (operation id, instance name,
//     endpoint, TOFU pin, actor, state) BEFORE the RPC is dispatched. If
//     the receipt cannot be persisted, NOTHING is sent. The receipt never
//     carries the token or any key material.
//  3. A local commit failure after Sluice issued the credential upgrades
//     the receipt to issued_not_stored WITH the fingerprint and emits an
//     audit record, so the only handle for revoking the orphan survives.
//
// R12 — the binding `operationId → name + endpoint + serverFingerprint +
// actor` is IMMUTABLE once created: creation is atomic create-if-absent
// (a second dispatch of the same operation id — concurrent or serial,
// any name, any endpoint — performs no RPC and is refused), Update can
// change only the lifecycle state / issued fingerprint / note, recovery
// always uses the bound endpoint + pin (caller values that conflict are
// refused before any network activity), an unresolved receipt cannot be
// deleted, and a receipt file that carries duplicate ids, bad grammar,
// impossible states, missing identity fields or more than the cap loads
// as DEGRADED (fail closed: no new operation is created until repaired).
//
// POST /api/cdr/instances/enroll/recover performs a FRESH authoritative
// resolution through EnrollStatus and classifies the operation:
//
//	LANDED_AND_STORED     issued, and the fingerprint is in the registry
//	ISSUED_BUT_NOT_STORED issued, not held locally — an exact revocation
//	                      path is returned (API by fingerprint, or the
//	                      Sluice CLI when no pooled client can issue it)
//	NOT_ISSUED            Sluice authoritatively reports no credential
//	AMBIGUOUS             Sluice could not be asked (retry later)

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/fileutil"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	cdrReceiptDispatched      = "dispatched"
	cdrReceiptStored          = "stored"
	cdrReceiptIssuedNotStored = "issued_not_stored"
	cdrReceiptNotIssued       = "not_issued"
	cdrReceiptRevoked         = "revoked"

	// cdrMaxEnrollReceipts bounds the durable receipt list. Terminal
	// receipts (stored / not_issued / revoked) are pruned oldest-first at
	// creation; unresolved ones (dispatched / issued_not_stored) are never
	// pruned — at the cap with only unresolved receipts, a NEW enrollment
	// is refused until the operator resolves one. A file holding MORE
	// than the cap is degraded.
	cdrMaxEnrollReceipts = 64

	cdrEnrollRecoverPath = "/api/cdr/instances/enroll/recover"
	cdrEnrollReceiptsAPI = "/api/cdr/instances/enroll/receipts"
)

// CDREnrollReceipt is one durable, non-secret enrollment operation record.
// OperationID, Name, Endpoint, ServerFingerprint and Actor are IMMUTABLE
// after creation.
type CDREnrollReceipt struct {
	OperationID       string    `json:"operationId"`
	Name              string    `json:"name"`
	Endpoint          string    `json:"endpoint"`
	ServerFingerprint string    `json:"serverFingerprint"`
	State             string    `json:"state"`
	Fingerprint       string    `json:"fingerprint,omitempty"` // issued client-cert fingerprint, when known
	Actor             string    `json:"actor,omitempty"`
	StartedAt         time.Time `json:"startedAt"`
	UpdatedAt         time.Time `json:"updatedAt"`
	Note              string    `json:"note,omitempty"`
}

func cdrReceiptStateValid(s string) bool {
	switch s {
	case cdrReceiptDispatched, cdrReceiptStored, cdrReceiptIssuedNotStored, cdrReceiptNotIssued, cdrReceiptRevoked:
		return true
	}
	return false
}

func (r CDREnrollReceipt) terminal() bool {
	switch r.State {
	case cdrReceiptStored, cdrReceiptNotIssued, cdrReceiptRevoked:
		return true
	}
	return false
}

// CDREnrollReceiptIntegrity is the read-surface truth about the receipt
// file (R12.8). OK=false ⇒ DEGRADED: no new operation may be created until
// the offending records are repaired by position.
type CDREnrollReceiptIntegrity struct {
	OK     bool                             `json:"ok"`
	Issues []CDREnrollReceiptIntegrityIssue `json:"issues"`
}

// CDREnrollReceiptIntegrityIssue names one defect: duplicate_operation |
// invalid_operation_id | invalid_state | missing_identity | over_capacity |
// unparsable_file.
type CDREnrollReceiptIntegrityIssue struct {
	Kind        string `json:"kind"`
	OperationID string `json:"operationId,omitempty"`
	Positions   []int  `json:"positions"`
}

func computeReceiptIntegrity(items []CDREnrollReceipt) CDREnrollReceiptIntegrity {
	out := CDREnrollReceiptIntegrity{OK: true, Issues: []CDREnrollReceiptIntegrityIssue{}}
	add := func(kind, op string, pos ...int) {
		out.OK = false
		out.Issues = append(out.Issues, CDREnrollReceiptIntegrityIssue{Kind: kind, OperationID: op, Positions: pos})
	}
	byID := map[string][]int{}
	for i, it := range items {
		if !cdrOperationIDRE.MatchString(it.OperationID) {
			add("invalid_operation_id", "", i)
		} else {
			byID[it.OperationID] = append(byID[it.OperationID], i)
		}
		if !cdrReceiptStateValid(it.State) {
			add("invalid_state", it.OperationID, i)
		}
		if strings.TrimSpace(it.Name) == "" || strings.TrimSpace(it.Endpoint) == "" ||
			strings.TrimSpace(it.ServerFingerprint) == "" || strings.TrimSpace(it.Actor) == "" {
			add("missing_identity", it.OperationID, i)
		}
	}
	ids := make([]string, 0, len(byID))
	for id, pos := range byID {
		if len(pos) > 1 {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		add("duplicate_operation", id, byID[id]...)
	}
	if len(items) > cdrMaxEnrollReceipts {
		over := make([]int, 0, len(items)-cdrMaxEnrollReceipts)
		for i := cdrMaxEnrollReceipts; i < len(items); i++ {
			over = append(over, i)
		}
		add("over_capacity", "", over...)
	}
	return out
}

// cdrEnrollReceiptStore is the JSON-backed, persist-before-publish
// receipt list. Path "" = in-memory (tests).
type cdrEnrollReceiptStore struct {
	mu        sync.RWMutex
	path      string
	items     []CDREnrollReceipt
	integrity CDREnrollReceiptIntegrity
	evaluated bool // integrity computed at least once (Load)
}

var cdrEnrollReceipts = &cdrEnrollReceiptStore{}

var (
	errCDRReceiptsFull      = errors.New("cdr enrollment receipts: too many unresolved operations; resolve or remove one before enrolling again")
	errCDRReceiptsDegraded  = errors.New("cdr enrollment receipts: the receipt file is degraded (duplicate, malformed or excess records); repair it before enrolling again")
	errCDRReceiptExists     = errors.New("cdr enrollment receipts: operation already exists")
	errCDRReceiptMissing    = errors.New("cdr enrollment receipts: operation not found")
	errCDRReceiptUnresolved = errors.New("cdr enrollment receipts: the operation is unresolved (dispatched or issued_not_stored); resolve it before removing the receipt")
	errCDRReceiptInvalid    = errors.New("cdr enrollment receipts: invalid receipt")
)

// Load reads the receipts from disk. Missing file = empty. A corrupt file
// (unparsable, or carrying integrity defects) loads what it can VERBATIM
// and marks the store DEGRADED (fail closed for creation).
func (s *cdrEnrollReceiptStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	s.evaluated = true
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			s.items = nil
			s.integrity = CDREnrollReceiptIntegrity{OK: true, Issues: []CDREnrollReceiptIntegrityIssue{}}
			return nil
		}
		s.integrity = CDREnrollReceiptIntegrity{OK: false, Issues: []CDREnrollReceiptIntegrityIssue{{Kind: "unparsable_file", Positions: []int{}}}}
		return fmt.Errorf("cdr enrollment receipts: read %q: %w", sanitizeLog(path), err)
	}
	var list []CDREnrollReceipt
	if err := json.Unmarshal(data, &list); err != nil {
		s.items = nil
		s.integrity = CDREnrollReceiptIntegrity{OK: false, Issues: []CDREnrollReceiptIntegrityIssue{{Kind: "unparsable_file", Positions: []int{}}}}
		return fmt.Errorf("cdr enrollment receipts: parse %q: %w", sanitizeLog(path), err)
	}
	s.items = list
	s.integrity = computeReceiptIntegrity(list)
	return nil
}

// Integrity returns the current receipt-file truth.
func (s *cdrEnrollReceiptStore) Integrity() CDREnrollReceiptIntegrity {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.evaluated {
		return CDREnrollReceiptIntegrity{OK: true, Issues: []CDREnrollReceiptIntegrityIssue{}}
	}
	return s.integrity
}

func (s *cdrEnrollReceiptStore) degradedLocked() bool {
	return s.evaluated && !s.integrity.OK
}

func (s *cdrEnrollReceiptStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.items, "", "  ")
	if err != nil {
		return fmt.Errorf("cdr enrollment receipts: marshal: %w", err)
	}
	if err := fileutil.AtomicWrite(s.path, data, 0o600); err != nil {
		return fmt.Errorf("cdr enrollment receipts: %w", err)
	}
	return nil
}

// Create is the ATOMIC create-if-absent (R12.1/4): under the store lock
// the operation id is checked and the receipt appended + persisted in one
// critical section, so two dispatches with the same id — concurrent or
// serial, whatever their name/endpoint — cannot both create. Refused on a
// degraded store. Durable-or-nothing.
func (s *cdrEnrollReceiptStore) Create(r CDREnrollReceipt) error {
	r.UpdatedAt = time.Now().UTC()
	if r.StartedAt.IsZero() {
		r.StartedAt = r.UpdatedAt
	}
	if !cdrOperationIDRE.MatchString(r.OperationID) || !cdrReceiptStateValid(r.State) ||
		strings.TrimSpace(r.Name) == "" || strings.TrimSpace(r.Endpoint) == "" ||
		strings.TrimSpace(r.ServerFingerprint) == "" || strings.TrimSpace(r.Actor) == "" {
		return errCDRReceiptInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.degradedLocked() {
		return errCDRReceiptsDegraded
	}
	for _, it := range s.items {
		if it.OperationID == r.OperationID {
			return errCDRReceiptExists
		}
	}
	prev := s.items
	next := append(append([]CDREnrollReceipt(nil), prev...), r)
	for len(next) > cdrMaxEnrollReceipts {
		pruned := false
		for i, it := range next {
			if it.terminal() && it.OperationID != r.OperationID {
				next = append(next[:i:i], next[i+1:]...)
				pruned = true
				break
			}
		}
		if !pruned {
			return errCDRReceiptsFull
		}
	}
	s.items = next
	if err := s.saveLocked(); err != nil {
		s.items = prev
		return err
	}
	return nil
}

// Put is the pre-R12 name for Create and carries EXACTLY its create-if-
// absent semantics (an existing operation id is refused, never replaced).
func (s *cdrEnrollReceiptStore) Put(r CDREnrollReceipt) error { return s.Create(r) }

// Update applies fn to the receipt for operationID and persists durable-
// or-nothing. Only State, Fingerprint and Note may change: the identity
// binding is restored after fn (R12.2). An absent operation is an error
// (a failed lifecycle transition is never silently ignored — R12.11).
func (s *cdrEnrollReceiptStore) Update(operationID string, fn func(r *CDREnrollReceipt)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.items {
		if s.items[i].OperationID == operationID {
			idx = i
		}
	}
	if idx < 0 {
		return errCDRReceiptMissing
	}
	prev := s.items[idx]
	fn(&s.items[idx])
	s.items[idx].OperationID = prev.OperationID
	s.items[idx].Name = prev.Name
	s.items[idx].Endpoint = prev.Endpoint
	s.items[idx].ServerFingerprint = prev.ServerFingerprint
	s.items[idx].Actor = prev.Actor
	s.items[idx].StartedAt = prev.StartedAt
	if !cdrReceiptStateValid(s.items[idx].State) {
		s.items[idx] = prev
		return errCDRReceiptInvalid
	}
	s.items[idx].UpdatedAt = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		s.items[idx] = prev
		return err
	}
	return nil
}

// Get returns a copy of the receipt for operationID.
func (s *cdrEnrollReceiptStore) Get(operationID string) (CDREnrollReceipt, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, it := range s.items {
		if it.OperationID == operationID {
			return it, true
		}
	}
	return CDREnrollReceipt{}, false
}

// List returns a copy of every receipt, oldest first.
func (s *cdrEnrollReceiptStore) List() []CDREnrollReceipt {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]CDREnrollReceipt(nil), s.items...)
}

// Delete removes ONE terminal receipt, durable-or-nothing. An unresolved
// receipt (dispatched / issued_not_stored) is refused (R12.9): it is the
// only durable identity of an operation whose credential may exist.
func (s *cdrEnrollReceiptStore) Delete(operationID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := -1
	for i := range s.items {
		if s.items[i].OperationID == operationID {
			idx = i
			break
		}
	}
	if idx < 0 {
		return false, nil
	}
	if !s.items[idx].terminal() {
		return false, errCDRReceiptUnresolved
	}
	return s.removeAtLocked(idx)
}

// DeleteAt is the degraded-store repair: removes the record at `position`
// (0-based) whose verbatim operation id equals `expected`, ONLY while the
// store is degraded. Re-evaluates integrity afterwards.
func (s *cdrEnrollReceiptStore) DeleteAt(position int, expected string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.degradedLocked() {
		return errors.New("cdr enrollment receipts: positional removal is only available while the store is degraded")
	}
	if position < 0 || position >= len(s.items) {
		return fmt.Errorf("cdr enrollment receipts: no record at position %d", position)
	}
	if s.items[position].OperationID != expected {
		return fmt.Errorf("cdr enrollment receipts: the record at position %d is not the expected operation", position)
	}
	_, err := s.removeAtLocked(position)
	return err
}

func (s *cdrEnrollReceiptStore) removeAtLocked(idx int) (bool, error) {
	prev := s.items
	prevIntegrity := s.integrity
	next := make([]CDREnrollReceipt, 0, len(prev)-1)
	next = append(next, prev[:idx]...)
	next = append(next, prev[idx+1:]...)
	s.items = next
	if s.evaluated {
		s.integrity = computeReceiptIntegrity(next)
	}
	if err := s.saveLocked(); err != nil {
		s.items = prev
		s.integrity = prevIntegrity
		return false, err
	}
	return true, nil
}

// markReceiptFingerprintRevoked records a PROVEN revocation on every
// receipt naming fp (the orphan-revocation path closes the loop). Returns
// the operation ids whose transition could NOT be persisted (R12.11).
func markReceiptFingerprintRevoked(fp string) []string {
	var failed []string
	for _, it := range cdrEnrollReceipts.List() {
		if it.Fingerprint != fp || it.State == cdrReceiptRevoked {
			continue
		}
		if err := cdrEnrollReceipts.Update(it.OperationID, func(r *CDREnrollReceipt) { r.State = cdrReceiptRevoked }); err != nil {
			logger.Printf("CDR: enrollment receipt %s: record revocation: %v", it.OperationID, err)
			failed = append(failed, it.OperationID)
		}
	}
	return failed
}

// ─── RPC seams (tests stub these) ───────────────────────────────────────────

var (
	cdrEnrollRPC       = Enroll
	cdrEnrollStatusRPC = EnrollStatus
)

// cdrEnrollOutcomeUnknown reports whether an Enroll RPC error leaves the
// Sluice-side outcome UNKNOWN (the credential may have been issued). A
// definite pre-issuance refusal is anything Sluice answered with a
// client/precondition code.
func cdrEnrollOutcomeUnknown(err error) bool {
	st, ok := status.FromError(err) // walks the wrap chain (GRPCStatus)
	if !ok || st == nil {
		return true
	}
	switch st.Code() {
	case codes.InvalidArgument, codes.PermissionDenied, codes.Unauthenticated,
		codes.NotFound, codes.FailedPrecondition, codes.ResourceExhausted:
		return false
	}
	return true
}

// cdrEnrollAlreadyIssued reports whether Sluice refused the dispatch
// because this operation id already issued a credential (v0.3 at-most-
// once): the credential EXISTS and must be resolved, not retried.
func cdrEnrollAlreadyIssued(err error) bool {
	st, ok := status.FromError(err)
	return ok && st != nil && st.Code() == codes.AlreadyExists
}

// ─── Recovery classification ────────────────────────────────────────────────

const (
	cdrRecoverLanded    = "LANDED_AND_STORED"
	cdrRecoverNotStored = "ISSUED_BUT_NOT_STORED"
	cdrRecoverNotIssued = "NOT_ISSUED"
	cdrRecoverAmbiguous = "AMBIGUOUS"
)

// cdrRegistryHoldsFingerprint reports whether any enrolled instance's
// lineage (or legacy record) names fp.
func cdrRegistryHoldsFingerprint(fp string) (string, bool) {
	for _, inst := range cdrInstances.SnapshotView() {
		if inst.ClientCertFingerprint == fp {
			return inst.Name, true
		}
		for _, g := range inst.Credentials {
			if g.Fingerprint == fp {
				return inst.Name, true
			}
		}
	}
	return "", false
}

// cdrOrphanRevocationPath describes EXACTLY how an issued-but-not-stored
// credential can be revoked from here: the API path by fingerprint when a
// pooled client can issue the call, else the Sluice-host CLI command.
func cdrOrphanRevocationPath(fp string) map[string]any {
	out := map[string]any{
		"fingerprint": fp,
		"cli":         "sluice node revoke --reason orphaned-enrollment " + fp,
		"api": map[string]any{
			"method": http.MethodPost,
			"path":   "/api/cdr/instances/revoke",
			"body":   map[string]string{"fingerprint": fp, "reason": "orphaned enrollment"},
		},
	}
	out["apiAvailable"] = cdrPickClientNotHolding(fp) != nil
	return out
}

// cdrPickClientNotHolding returns a pooled client whose instance does not
// hold fp among its live credentials (Sluice refuses self-revocation).
func cdrPickClientNotHolding(fp string) *CDRClient {
	now := time.Now()
	for _, pc := range cdrPool.List() {
		if !pc.Breaker.Allow() {
			continue
		}
		if inst, ok := cdrInstances.GetCopy(pc.Name); ok {
			holds := false
			for _, live := range inst.LiveFingerprints(now) {
				if live == fp {
					holds = true
				}
			}
			if holds {
				continue
			}
		}
		return pc.Client
	}
	return nil
}

// cdrRecoverRequest is the JSON body for POST /api/cdr/instances/enroll/recover.
// endpoint + serverFingerprint are accepted ONLY for a receipt-less
// recovery (the browser marker carries them); when a receipt exists its
// bound values are authoritative and a conflicting value is refused.
type cdrRecoverRequest struct {
	OperationID       string `json:"operationId"`
	Endpoint          string `json:"endpoint,omitempty"`
	ServerFingerprint string `json:"serverFingerprint,omitempty"`
}

// apiCDREnrollRecover performs a fresh authoritative resolution of one
// enrollment operation and returns its classification (admin only; every
// call is audited — it is a trust-lifecycle decision input). A failed
// receipt transition is reported (receiptUpdated=false + receiptError),
// never hidden; the previous durable state stays for a later retry.
func apiCDREnrollRecover(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	var req cdrRecoverRequest
	if err := decodeStrictJSONBody(r, &req, 4<<10); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	opID := strings.TrimSpace(req.OperationID)
	if !cdrOperationIDRE.MatchString(opID) {
		http.Error(w, "operationId must be 16-64 characters of [A-Za-z0-9._-]", http.StatusBadRequest)
		return
	}
	receipt, hasReceipt := cdrEnrollReceipts.Get(opID)
	endpoint := strings.TrimSpace(req.Endpoint)
	serverFP := strings.TrimSpace(req.ServerFingerprint)
	if hasReceipt {
		// R12.5/6: the bound endpoint + pin are authoritative; a caller
		// value that conflicts is refused BEFORE any network activity.
		if endpoint != "" && endpoint != receipt.Endpoint {
			http.Error(w, fmt.Sprintf("operation %s is bound to endpoint %s; the supplied endpoint conflicts and is refused", opID, receipt.Endpoint), http.StatusConflict)
			return
		}
		if serverFP != "" && normaliseFingerprint(serverFP) != normaliseFingerprint(receipt.ServerFingerprint) {
			http.Error(w, fmt.Sprintf("operation %s is bound to a different server fingerprint; the supplied pin conflicts and is refused", opID), http.StatusConflict)
			return
		}
		endpoint = receipt.Endpoint
		serverFP = receipt.ServerFingerprint
	}
	if endpoint == "" || serverFP == "" {
		http.Error(w, "no receipt for that operation; endpoint and serverFingerprint are required to resolve it", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out := map[string]any{
		"operationId":    opID,
		"endpoint":       endpoint,
		"name":           receipt.Name,
		"receiptState":   receipt.State,
		"hasReceipt":     hasReceipt,
		"revoked":        false,
		"retryable":      false,
		"receiptUpdated": true,
	}
	transition := func(fn func(rc *CDREnrollReceipt)) {
		if !hasReceipt {
			return
		}
		if err := cdrEnrollReceipts.Update(opID, fn); err != nil {
			out["receiptUpdated"] = false
			out["receiptError"] = sanitizeLog(err.Error())
			logger.Printf("CDR: enrollment receipt %s: transition failed (previous durable state kept): %v", opID, err)
		}
	}
	st, err := cdrEnrollStatusRPC(ctx, endpoint, serverFP, opID)
	classification := cdrRecoverAmbiguous
	switch {
	case err != nil:
		out["retryable"] = true
		out["error"] = sanitizeLog(err.Error())
	case st.GetOutcome() == pb.EnrollOutcome_ENROLL_NOT_ISSUED:
		classification = cdrRecoverNotIssued
		if hasReceipt && !receipt.terminal() {
			transition(func(rc *CDREnrollReceipt) { rc.State = cdrReceiptNotIssued })
		}
	case st.GetOutcome() == pb.EnrollOutcome_ENROLL_ISSUED:
		fp := st.GetClientCertFingerprint()
		out["fingerprint"] = fp
		out["revoked"] = st.GetRevoked()
		if name, held := cdrRegistryHoldsFingerprint(fp); held {
			classification = cdrRecoverLanded
			out["name"] = name
			if hasReceipt && receipt.State == cdrReceiptDispatched {
				transition(func(rc *CDREnrollReceipt) { rc.State = cdrReceiptStored; rc.Fingerprint = fp })
			}
		} else {
			classification = cdrRecoverNotStored
			out["revocation"] = cdrOrphanRevocationPath(fp)
			if hasReceipt && !receipt.terminal() {
				state := cdrReceiptIssuedNotStored
				if st.GetRevoked() {
					state = cdrReceiptRevoked
				}
				transition(func(rc *CDREnrollReceipt) { rc.State = state; rc.Fingerprint = fp })
			}
		}
	default:
		// A v0.2 server answers UNSPECIFIED — it cannot resolve operations.
		out["retryable"] = false
		out["error"] = "the Sluice server does not support operation resolution (v0.2); resolve it on the Sluice host (sluice node list)"
	}
	out["classification"] = classification
	if rc, ok := cdrEnrollReceipts.Get(opID); ok {
		out["receiptState"] = rc.State
	}
	auditEvent(r, "cdr.instance.enroll.recover", opID,
		fmt.Sprintf("classification=%s fingerprint=%v receiptUpdated=%v", classification, out["fingerprint"], out["receiptUpdated"]))
	jsonOK(w, out)
}

// apiCDREnrollReceipts lists (viewer) or removes (admin) recovery receipts.
// GET carries the file's integrity truth; DELETE refuses unresolved
// receipts (409) and, while the store is degraded, accepts the fenced
// positional repair `?position=N&operationId=<verbatim>`.
func apiCDREnrollReceipts(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if !requireRole(w, r, RoleViewer) {
			return
		}
		list := cdrEnrollReceipts.List()
		unresolved := 0
		for _, it := range list {
			if !it.terminal() {
				unresolved++
			}
		}
		jsonOK(w, map[string]any{"receipts": list, "count": len(list), "unresolved": unresolved, "integrity": cdrEnrollReceipts.Integrity()})
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		opID := r.URL.Query().Get("operationId")
		if pos := strings.TrimSpace(r.URL.Query().Get("position")); pos != "" {
			position, perr := strconv.Atoi(pos)
			if perr != nil {
				http.Error(w, "position must be an integer", http.StatusBadRequest)
				return
			}
			if err := cdrEnrollReceipts.DeleteAt(position, opID); err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			auditEvent(r, "cdr.instance.enroll.receipt.remove", opID, fmt.Sprintf("removed receipt record at position %d (degraded-store repair)", position))
			jsonOK(w, map[string]any{"removed": opID, "position": position, "integrity": cdrEnrollReceipts.Integrity()})
			return
		}
		opID = strings.TrimSpace(opID)
		if !cdrOperationIDRE.MatchString(opID) {
			http.Error(w, "operationId is required", http.StatusBadRequest)
			return
		}
		ok, err := cdrEnrollReceipts.Delete(opID)
		if err != nil {
			if errors.Is(err, errCDRReceiptUnresolved) {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !ok {
			http.Error(w, "receipt not found", http.StatusNotFound)
			return
		}
		auditEvent(r, "cdr.instance.enroll.receipt.remove", opID, "removed enrollment recovery receipt")
		jsonOK(w, map[string]any{"removed": opID})
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
