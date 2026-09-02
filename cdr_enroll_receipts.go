package main

// cdr_enroll_receipts.go — identifiable unknown-outcome recovery for
// enrollment (2E-C trust-lifecycle correction, R8).
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
	// receipts (stored / not_issued / revoked) are pruned oldest-first;
	// unresolved ones (dispatched / issued_not_stored) are never pruned —
	// at the cap with only unresolved receipts, a NEW enrollment is
	// refused until the operator resolves one.
	cdrMaxEnrollReceipts = 64

	cdrEnrollRecoverPath = "/api/cdr/instances/enroll/recover"
	cdrEnrollReceiptsAPI = "/api/cdr/instances/enroll/receipts"
)

// CDREnrollReceipt is one durable, non-secret enrollment operation record.
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

func (r CDREnrollReceipt) terminal() bool {
	switch r.State {
	case cdrReceiptStored, cdrReceiptNotIssued, cdrReceiptRevoked:
		return true
	}
	return false
}

// cdrEnrollReceiptStore is the JSON-backed, persist-before-publish
// receipt list. Path "" = in-memory (tests).
type cdrEnrollReceiptStore struct {
	mu    sync.RWMutex
	path  string
	items []CDREnrollReceipt
}

var cdrEnrollReceipts = &cdrEnrollReceiptStore{}

var errCDRReceiptsFull = errors.New("cdr enrollment receipts: too many unresolved operations; resolve or remove one before enrolling again")

// Load reads the receipts from disk. Missing file = empty.
func (s *cdrEnrollReceiptStore) Load(path string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.path = path
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("cdr enrollment receipts: read %q: %w", sanitizeLog(path), err)
	}
	var list []CDREnrollReceipt
	if err := json.Unmarshal(data, &list); err != nil {
		return fmt.Errorf("cdr enrollment receipts: parse %q: %w", sanitizeLog(path), err)
	}
	s.items = list
	return nil
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

// Put inserts or replaces the receipt for r.OperationID, durable-or-
// nothing (memory is untouched when the write fails).
func (s *cdrEnrollReceiptStore) Put(r CDREnrollReceipt) error {
	r.UpdatedAt = time.Now().UTC()
	if r.StartedAt.IsZero() {
		r.StartedAt = r.UpdatedAt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.items
	next := make([]CDREnrollReceipt, 0, len(prev)+1)
	replaced := false
	for _, it := range prev {
		if it.OperationID == r.OperationID {
			next = append(next, r)
			replaced = true
			continue
		}
		next = append(next, it)
	}
	if !replaced {
		next = append(next, r)
	}
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

// Update applies fn to the receipt for operationID (no-op when absent)
// and persists durable-or-nothing.
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
		return nil
	}
	prev := s.items[idx]
	fn(&s.items[idx])
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

// Delete removes one receipt, durable-or-nothing.
func (s *cdrEnrollReceiptStore) Delete(operationID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev := s.items
	next := make([]CDREnrollReceipt, 0, len(prev))
	found := false
	for _, it := range prev {
		if it.OperationID == operationID {
			found = true
			continue
		}
		next = append(next, it)
	}
	if !found {
		return false, nil
	}
	s.items = next
	if err := s.saveLocked(); err != nil {
		s.items = prev
		return false, err
	}
	return true, nil
}

// markReceiptFingerprintRevoked records a PROVEN revocation on every
// receipt naming fp (the orphan-revocation path closes the loop).
func markReceiptFingerprintRevoked(fp string) {
	for _, it := range cdrEnrollReceipts.List() {
		if it.Fingerprint != fp {
			continue
		}
		if err := cdrEnrollReceipts.Update(it.OperationID, func(r *CDREnrollReceipt) { r.State = cdrReceiptRevoked }); err != nil {
			logger.Printf("CDR: enrollment receipt %s: record revocation: %v", it.OperationID, err)
		}
	}
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
// endpoint + serverFingerprint are optional overrides for a receipt-less
// recovery (the browser marker carries them).
type cdrRecoverRequest struct {
	OperationID       string `json:"operationId"`
	Endpoint          string `json:"endpoint,omitempty"`
	ServerFingerprint string `json:"serverFingerprint,omitempty"`
}

// apiCDREnrollRecover performs a fresh authoritative resolution of one
// enrollment operation and returns its classification (admin only; every
// call is audited — it is a trust-lifecycle decision input).
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
		if endpoint == "" {
			endpoint = receipt.Endpoint
		}
		if serverFP == "" {
			serverFP = receipt.ServerFingerprint
		}
	}
	if endpoint == "" || serverFP == "" {
		http.Error(w, "no receipt for that operation; endpoint and serverFingerprint are required to resolve it", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	out := map[string]any{
		"operationId":  opID,
		"endpoint":     endpoint,
		"name":         receipt.Name,
		"receiptState": receipt.State,
		"hasReceipt":   hasReceipt,
		"revoked":      false,
		"retryable":    false,
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
			_ = cdrEnrollReceipts.Update(opID, func(rc *CDREnrollReceipt) { rc.State = cdrReceiptNotIssued })
		}
	case st.GetOutcome() == pb.EnrollOutcome_ENROLL_ISSUED:
		fp := st.GetClientCertFingerprint()
		out["fingerprint"] = fp
		out["revoked"] = st.GetRevoked()
		if name, held := cdrRegistryHoldsFingerprint(fp); held {
			classification = cdrRecoverLanded
			out["name"] = name
			if hasReceipt && receipt.State == cdrReceiptDispatched {
				_ = cdrEnrollReceipts.Update(opID, func(rc *CDREnrollReceipt) { rc.State = cdrReceiptStored; rc.Fingerprint = fp })
			}
		} else {
			classification = cdrRecoverNotStored
			out["revocation"] = cdrOrphanRevocationPath(fp)
			if hasReceipt && !receipt.terminal() {
				state := cdrReceiptIssuedNotStored
				if st.GetRevoked() {
					state = cdrReceiptRevoked
				}
				_ = cdrEnrollReceipts.Update(opID, func(rc *CDREnrollReceipt) { rc.State = state; rc.Fingerprint = fp })
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
		fmt.Sprintf("classification=%s fingerprint=%v", classification, out["fingerprint"]))
	jsonOK(w, out)
}

// apiCDREnrollReceipts lists (viewer) or removes (admin) recovery receipts.
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
		jsonOK(w, map[string]any{"receipts": list, "count": len(list), "unresolved": unresolved})
	case http.MethodDelete:
		if !requireRole(w, r, RoleAdmin) {
			return
		}
		opID := strings.TrimSpace(r.URL.Query().Get("operationId"))
		if !cdrOperationIDRE.MatchString(opID) {
			http.Error(w, "operationId is required", http.StatusBadRequest)
			return
		}
		ok, err := cdrEnrollReceipts.Delete(opID)
		if err != nil {
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
