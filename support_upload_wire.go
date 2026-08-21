package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// support_upload_wire.go — M6 Secure Upload, PR-5: the CONSENT GATE that connects
// an approved bundle to the outbound path, plus the real uploadFunc the background
// worker drains through.
//
// This is the slice where egress becomes reachable, so every precondition is
// checked before anything is enqueued (SECURE-UPLOAD-ARCHITECTURE.md §2/§4):
//   - admin role,
//   - upload explicitly enabled (uploadEnabled(), PR-1),
//   - a TAC recipient trust key configured (tacTrustConfigured(), PR-4),
//   - the bundle is READY (the mandatory privacy-preview/approval gate, M4),
//   - an explicit per-bundle, per-case consent action (confirm + case_id).
//
// On consent the bundle is sealed to TAC's public key ONCE and written to disk
// (upload.csb.sealed), then enqueued (PR-3). Sealing once is REQUIRED: sealbox is
// non-deterministic (ephemeral key), so re-sealing per attempt would change the
// bytes' hash and break resumable transfer + the gateway's complete-time hash
// check. The persisted sealed blob is what the worker transfers, so retries and
// cross-restart resume operate on identical bytes.
//
// No outbound call lives here: the seal is in-memory crypto, and the actual dials
// happen inside internal/supportupload (the no-egress source wall scans this file
// and finds no outbound marker). The worker (support_upload_worker.go) is the only
// caller of realUploadFunc.

// sealedUploadPath is the on-disk location of a bundle's sealed-to-TAC blob,
// alongside its other artifacts under bundles/<id>/.
func sealedUploadPath(bundleID string) string {
	return filepath.Join(supportBundlesDir(), bundleID, "upload.csb.sealed")
}

// consentUploadReq is the explicit per-bundle upload consent body.
type consentUploadReq struct {
	CaseID  string `json:"case_id"`
	Confirm bool   `json:"confirm"`
}

// apiSupportBundleUpload is the per-bundle upload surface:
//   - POST (admin): the explicit consent action — seal the READY bundle to TAC and
//     enqueue it for the background worker. Fails closed if upload is not enabled,
//     no TAC trust key is configured, the bundle is not READY, or consent/case is
//     missing.
//   - GET (viewer): this bundle's upload status + signed receipt (from the durable
//     queue entry); 404 if the bundle was never enqueued for upload.
func apiSupportBundleUpload(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleBundleUploadConsent(w, r)
	case http.MethodGet:
		handleBundleUploadStatus(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// apiSupportUploads lists the whole upload queue (GET, viewer) for the status
// panel — states, attempts, and receipts; no secret fields.
func apiSupportUploads(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleViewer) {
		return
	}
	entries := listUploadQueue()
	views := make([]map[string]any, 0, len(entries))
	for i := range entries {
		views = append(views, uploadEntryView(entries[i]))
	}
	jsonOK(w, map[string]any{"uploads": views, "max": maxUploadQueue})
}

// handleBundleUploadStatus returns one bundle's upload record (viewer).
func handleBundleUploadStatus(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleViewer) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	e, ok := loadUploadQueueEntry(id)
	if !ok {
		http.Error(w, "bundle not queued for upload", http.StatusNotFound)
		return
	}
	jsonOK(w, uploadEntryView(e))
}

// handleBundleUploadConsent is the explicit admin consent → seal → enqueue path.
func handleBundleUploadConsent(w http.ResponseWriter, r *http.Request) {
	if !requireRole(w, r, RoleAdmin) {
		return
	}
	id := r.PathValue("id")
	if !supportBundleIDRe.MatchString(id) {
		http.Error(w, "invalid bundle id", http.StatusBadRequest)
		return
	}
	// Preconditions — each a distinct fail-closed gate before any egress state.
	if !uploadEnabled() {
		http.Error(w, "upload is not enabled — configure and enable it first (POST /api/support/upload/config)", http.StatusConflict)
		return
	}
	if !tacTrustConfigured() {
		http.Error(w, "no TAC recipient trust key configured — encrypt-to-TAC unavailable", http.StatusConflict)
		return
	}
	if readBundleState(id).State != bundleStateReady {
		http.Error(w, "bundle pending approval — an admin must review the redaction report and approve before upload", http.StatusConflict)
		return
	}

	var req consentUploadReq
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if !req.Confirm {
		http.Error(w, "explicit consent required (confirm=true)", http.StatusBadRequest)
		return
	}
	caseID, err := resolveUploadCase(id, req.CaseID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	// Binding the bundle to the case makes it retention-evidence (exempt from
	// auto-eviction), so an in-flight upload cannot be janitored away mid-transfer.
	// Best-effort: a write failure does not block the consented upload.
	if st := readBundleState(id); st.CaseID == "" {
		st.CaseID = caseID
		if werr := writeBundleState(id, st); werr != nil {
			logger.Printf("support: bind case for %q failed: %v", sanitizeLog(id), werr)
		}
	}

	entry, err := sealAndEnqueueUpload(id, caseID, time.Now())
	if err != nil {
		// A seal/persist failure is server-side; the specific cause is logged, not
		// leaked. tacTrustConfigured() already passed, so errNoTACTrustKey here is a
		// concurrent config change — still fail closed.
		logger.Printf("support: upload consent for %q failed: %v", sanitizeLog(id), err)
		http.Error(w, "could not prepare bundle for upload", http.StatusInternalServerError)
		return
	}

	auditEvent(r, "support.upload", id, caseID)
	w.WriteHeader(http.StatusAccepted)
	jsonOK(w, uploadEntryView(entry))
}

// resolveUploadCase enforces the per-case consent rule: a case_id is mandatory, and
// if the bundle was created bound to a case it must match (an operator cannot
// redirect an evidence bundle to a different case at upload time).
func resolveUploadCase(bundleID, reqCase string) (string, error) {
	if !validSupportCaseID(reqCase) {
		return "", errors.New("a valid case_id is required for upload consent")
	}
	if bound := readBundleState(bundleID).CaseID; bound != "" && bound != reqCase {
		return "", fmt.Errorf("case_id %q does not match the bundle's case", sanitizeLog(reqCase))
	}
	return reqCase, nil
}

// uploadConsentMu serializes the seal→write→enqueue sequence so two concurrent
// consent POSTs for the same bundle cannot race (one re-sealing a new blob while
// the other's hash is committed to the queue). Consent is a rare admin action, so
// a single global lock is free.
var uploadConsentMu sync.Mutex

// sealAndEnqueueUpload seals the READY bundle to the active TAC key ONCE, persists
// the sealed blob, and enqueues it. Returns the queue entry. Pure local work (seal
// + file write + enqueue) — no network.
//
// Idempotency (the seal is nondeterministic, so re-sealing must be avoided when it
// would desync the on-disk blob from the persisted hash): if the bundle is already
// queued/uploading/uploaded, this is a no-op that returns the existing entry
// WITHOUT overwriting upload.csb.sealed. Only a new bundle or a deferred/rejected
// re-arm re-seals — and the re-arm adopts the fresh hash (enqueueUpload).
func sealAndEnqueueUpload(bundleID, caseID string, now time.Time) (uploadQueueEntry, error) {
	uploadConsentMu.Lock()
	defer uploadConsentMu.Unlock()

	if existing, ok := loadUploadQueueEntry(bundleID); ok {
		switch existing.State {
		case uploadStateQueued, uploadStateUploading, uploadStateUploaded:
			return existing, nil // already pending or delivered — do NOT re-seal
		}
	}

	tgz, err := os.ReadFile(filepath.Join(supportBundlesDir(), bundleID, "bundle.csb.tgz"))
	if err != nil {
		return uploadQueueEntry{}, fmt.Errorf("read bundle: %w", err)
	}
	sealed, keyID, err := sealBundleToTAC(tgz)
	if err != nil {
		return uploadQueueEntry{}, err
	}
	if err := writeSealedUpload(bundleID, sealed); err != nil {
		return uploadQueueEntry{}, err
	}
	sum := sha256.Sum256(sealed)
	return enqueueUpload(bundleID, caseID, keyID, hex.EncodeToString(sum[:]), now)
}

// writeSealedUpload atomically persists the sealed blob at 0600 next to the bundle.
func writeSealedUpload(bundleID string, sealed []byte) error {
	path := sealedUploadPath(bundleID)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, sealed, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// removeSealedUpload deletes the sealed blob once an entry reaches a terminal state
// (uploaded/rejected) — the encrypted bytes are no longer needed on disk.
func removeSealedUpload(bundleID string) {
	_ = os.Remove(sealedUploadPath(bundleID)) //nolint:errcheck // best-effort cleanup
}

// uploadEntryView is the redacted read model for a queue entry (no secret fields on
// it, but keep the surface explicit).
func uploadEntryView(e uploadQueueEntry) map[string]any {
	m := map[string]any{
		"bundle_id":  e.BundleID,
		"case_id":    e.CaseID,
		"state":      string(e.State),
		"attempts":   e.Attempts,
		"key_id":     e.KeyID,
		"updated_at": e.UpdatedAt,
	}
	if e.LastError != "" {
		m["last_error"] = e.LastError
	}
	if e.Receipt != nil {
		m["receipt"] = map[string]any{
			"bundle_sha256": e.Receipt.BundleSHA256,
			"received_at":   e.Receipt.ReceivedAt,
			"sig":           e.Receipt.Sig,
		}
	}
	return m
}

// uploadTransport is the subset of the PR-2 client the resume-aware transfer uses.
// *supportupload.Client satisfies it; tests supply an in-memory gateway (the real
// client's SSRF origin-guard refuses loopback, so it cannot target an httptest
// server).
type uploadTransport interface {
	Init(ctx context.Context, m supportupload.Meta) (uploadID string, chunkSize int64, err error)
	Status(ctx context.Context, uploadID string) (receivedOffset int64, err error)
	PutChunk(ctx context.Context, uploadID string, offset int64, chunk []byte) (receivedOffset int64, err error)
	Complete(ctx context.Context, uploadID, bundleSHA256 string) (supportupload.Receipt, error)
}

// newUploadTransport builds the real SSRF-guarded client. A var so tests inject a
// fake gateway without reaching the real network.
var newUploadTransport = func(cfg supportupload.Config) (uploadTransport, error) {
	return supportupload.NewClient(cfg)
}

// realUploadFunc is the queue's uploadFunc (PR-3) wired to the real client: it
// transfers a bundle's persisted sealed blob to the TAC gateway and returns the
// signed receipt plus the gateway session id. Resume-aware (the queue drives resume
// via the client's exposed Init/Status/PutChunk/Complete, per PR-2): an entry that
// already carries an UploadID resumes that session instead of re-initing, and the
// (possibly new) session id is returned even on a transient error so the next
// attempt — including one after a restart — resumes from the received offset.
//
// MUST NOT be called under uploadQueueMu (it does network I/O).
func realUploadFunc(ctx context.Context, e uploadQueueEntry) (*supportupload.Receipt, string, error) {
	cfg := uploadConfigGet()
	if !cfg.Enabled || cfg.Origin == "" {
		return nil, "", errors.New("upload not enabled")
	}
	client, err := newUploadTransport(supportupload.Config{Origin: cfg.Origin, Credential: cfg.Credential})
	if err != nil {
		return nil, "", err
	}
	f, err := os.Open(sealedUploadPath(e.BundleID))
	if err != nil {
		return nil, "", fmt.Errorf("open sealed bundle: %w", err)
	}
	defer f.Close() //nolint:errcheck // read-only
	fi, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	meta := supportupload.Meta{
		CaseID:       e.CaseID,
		BundleID:     e.BundleID,
		BundleSHA256: e.BundleSHA256,
		Size:         fi.Size(),
		KeyID:        e.KeyID,
	}
	return transferSealed(ctx, client, meta, e.UploadID, f, fi.Size())
}

// transferSealed runs the resume-aware transfer and returns (receipt, uploadID,
// err). The uploadID is threaded back on every path so a drop after init persists
// the resume point.
func transferSealed(ctx context.Context, client uploadTransport, meta supportupload.Meta, uploadID string, ra io.ReaderAt, size int64) (*supportupload.Receipt, string, error) {
	var chunkSize int64
	if uploadID == "" {
		id, cs, err := client.Init(ctx, meta)
		if err != nil {
			return nil, "", err
		}
		uploadID, chunkSize = id, cs
	} else {
		chunkSize = supportUploadResumeChunk // resuming: the gateway accepts any offset
	}
	offset, err := client.Status(ctx, uploadID)
	if err != nil {
		return nil, uploadID, err
	}
	buf := make([]byte, chunkSize)
	for offset < size {
		n := chunkSize
		if rem := size - offset; rem < n {
			n = rem
		}
		if _, rerr := ra.ReadAt(buf[:n], offset); rerr != nil && rerr != io.EOF {
			return nil, uploadID, fmt.Errorf("read chunk at %d: %w", offset, rerr)
		}
		recv, perr := client.PutChunk(ctx, uploadID, offset, buf[:n])
		if perr != nil {
			return nil, uploadID, perr
		}
		if recv <= offset {
			return nil, uploadID, fmt.Errorf("gateway did not advance past offset %d", offset)
		}
		offset = recv
	}
	rec, err := client.Complete(ctx, uploadID, meta.BundleSHA256)
	if err != nil {
		return nil, uploadID, err
	}
	// Defense in depth: the receipt must attest the exact bytes we uploaded. The
	// real client re-checks this in Complete too, but re-checking here means the
	// wire layer rejects a mis-issued receipt independent of the transport.
	if rec.BundleSHA256 != meta.BundleSHA256 {
		return nil, uploadID, fmt.Errorf("receipt hash %q does not match uploaded bundle hash %q", rec.BundleSHA256, meta.BundleSHA256)
	}
	return &rec, uploadID, nil
}
