package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/sealbox"
	"github.com/KidCarmi/Culvert/internal/supportupload"
)

// ── fixtures ────────────────────────────────────────────────────────────────

// writeReadyBundle creates a READY bundle on disk (bundle.csb.tgz + state.json)
// so the consent path can seal and enqueue it. caseID may be "" (unbound).
func writeReadyBundle(t *testing.T, id, caseID string) {
	t.Helper()
	dir := filepath.Join(supportBundlesDir(), id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bundle.csb.tgz"), []byte("redacted-bundle-bytes-"+id), 0o600); err != nil {
		t.Fatalf("write tgz: %v", err)
	}
	st := supportBundleStateFile{State: bundleStateReady, CaseID: caseID, CreatedAt: "2026-01-01T00:00:00Z"}
	b, _ := json.MarshalIndent(st, "", "  ")
	if err := os.WriteFile(supportBundleStatePath(id), b, 0o600); err != nil {
		t.Fatalf("write state: %v", err)
	}
}

// enableUploadForTest turns on the upload posture with a fake public-looking origin.
func enableUploadForTest(t *testing.T) {
	t.Helper()
	uploadConfigMu.Lock()
	err := saveUploadConfigLocked(uploadConfig{Enabled: true, Origin: "https://tac.example.com"})
	uploadConfigMu.Unlock()
	if err != nil {
		t.Fatalf("enable upload: %v", err)
	}
}

// fakeGateway is an in-memory uploadTransport (the real client refuses loopback).
type fakeGateway struct {
	initCalls int
	received  []byte
	sig       string
	badSig    string // if set, Complete returns this as the receipt hash (mismatch)
	failPutAt int    // if >0, PutChunk fails once the received length reaches it
}

func (g *fakeGateway) Init(_ context.Context, _ supportupload.Meta) (uploadID string, chunkSize int64, err error) {
	g.initCalls++
	return "sess-1", 8, nil // tiny chunk so multi-chunk transfer is exercised
}
func (g *fakeGateway) Status(_ context.Context, _ string) (int64, error) {
	return int64(len(g.received)), nil
}
func (g *fakeGateway) PutChunk(_ context.Context, _ string, offset int64, chunk []byte) (int64, error) {
	if g.failPutAt > 0 && len(g.received) >= g.failPutAt {
		return 0, errors.New("connection reset")
	}
	if int(offset) != len(g.received) {
		return 0, errors.New("non-contiguous offset")
	}
	g.received = append(g.received, chunk...)
	return int64(len(g.received)), nil
}
func (g *fakeGateway) Complete(_ context.Context, _, bundleSHA256 string) (supportupload.Receipt, error) {
	h := bundleSHA256
	if g.badSig != "" {
		h = g.badSig
	}
	return supportupload.Receipt{BundleSHA256: h, ReceivedAt: "2026-01-01T00:00:01Z", Sig: g.sig}, nil
}

// withFakeTransport swaps newUploadTransport for the test.
func withFakeTransport(t *testing.T, g *fakeGateway) {
	t.Helper()
	prev := newUploadTransport
	newUploadTransport = func(_ supportupload.Config) (uploadTransport, error) { return g, nil }
	t.Cleanup(func() { newUploadTransport = prev })
}

// ── consent gate ────────────────────────────────────────────────────────────

func TestUploadConsent_Preconditions(t *testing.T) {
	withTempUploadDir(t)
	id := csbID("con")
	writeReadyBundle(t, id, "")

	post := func(role UIRole, body any) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := roleReq(role, http.MethodPost, "/api/support/bundles/"+id+"/upload", body)
		req.SetPathValue("id", id)
		apiSupportBundleUpload(rec, req)
		return rec
	}

	// viewer POST → 403
	if rec := post(RoleViewer, map[string]any{"confirm": true, "case_id": "C1"}); rec.Code != http.StatusForbidden {
		t.Fatalf("viewer POST = %d, want 403", rec.Code)
	}
	// upload not enabled → 409
	if rec := post(RoleAdmin, map[string]any{"confirm": true, "case_id": "C1"}); rec.Code != http.StatusConflict {
		t.Fatalf("not-enabled POST = %d, want 409", rec.Code)
	}

	enableUploadForTest(t)
	// upload enabled but no TAC trust → 409
	if rec := post(RoleAdmin, map[string]any{"confirm": true, "case_id": "C1"}); rec.Code != http.StatusConflict {
		t.Fatalf("no-trust POST = %d, want 409", rec.Code)
	}

	_, _, pubB64 := newTACKey(t)
	withBakedTACKeys(t, tacKeyJSON("tac-1", pubB64))
	t.Setenv(envTACTrustKeys, "")
	t.Setenv(envTACActiveKeyID, "")

	// no confirm → 400
	if rec := post(RoleAdmin, map[string]any{"case_id": "C1"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("no-confirm POST = %d, want 400", rec.Code)
	}
	// no case → 400
	if rec := post(RoleAdmin, map[string]any{"confirm": true}); rec.Code != http.StatusBadRequest {
		t.Fatalf("no-case POST = %d, want 400", rec.Code)
	}

	// all preconditions met → 202, sealed blob written, queued with matching hash.
	rec := post(RoleAdmin, map[string]any{"confirm": true, "case_id": "CASE-9"})
	if rec.Code != http.StatusAccepted {
		t.Fatalf("valid POST = %d, want 202 (body=%q)", rec.Code, rec.Body.String())
	}
	sealed, err := os.ReadFile(sealedUploadPath(id))
	if err != nil {
		t.Fatalf("sealed blob not written: %v", err)
	}
	if !sealbox.IsSealed(sealed) {
		t.Fatal("persisted blob is not a sealbox envelope")
	}
	e, ok := loadUploadQueueEntry(id)
	if !ok || e.State != uploadStateQueued || e.CaseID != "CASE-9" || e.KeyID != "tac-1" {
		t.Fatalf("queue entry = %+v ok=%v", e, ok)
	}
	sum := sha256.Sum256(sealed)
	if e.BundleSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("queued hash != sha256(sealed blob)")
	}
	// Consent bound the previously-unbound bundle to the case (retention-evidence),
	// so an in-flight upload cannot be evicted mid-transfer.
	if readBundleState(id).CaseID != "CASE-9" {
		t.Fatalf("consent did not bind the bundle to its case: %q", readBundleState(id).CaseID)
	}
}

func TestUploadConsent_CaseMismatchRefused(t *testing.T) {
	withTempUploadDir(t)
	enableUploadForTest(t)
	_, _, pubB64 := newTACKey(t)
	withBakedTACKeys(t, tacKeyJSON("tac-1", pubB64))
	t.Setenv(envTACTrustKeys, "")
	t.Setenv(envTACActiveKeyID, "")

	id := csbID("bnd")
	writeReadyBundle(t, id, "CASE-A") // bound to CASE-A at creation

	rec := httptest.NewRecorder()
	req := roleReq(RoleAdmin, http.MethodPost, "/api/support/bundles/"+id+"/upload", map[string]any{"confirm": true, "case_id": "CASE-B"})
	req.SetPathValue("id", id)
	apiSupportBundleUpload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("case-mismatch POST = %d, want 400", rec.Code)
	}
}

func TestUploadConsent_PendingBundleRefused(t *testing.T) {
	withTempUploadDir(t)
	enableUploadForTest(t)
	_, _, pubB64 := newTACKey(t)
	withBakedTACKeys(t, tacKeyJSON("tac-1", pubB64))
	t.Setenv(envTACTrustKeys, "")
	t.Setenv(envTACActiveKeyID, "")

	id := csbID("pnd")
	writeReadyBundle(t, id, "")
	// Flip it back to pending.
	st := supportBundleStateFile{State: bundleStatePending}
	b, _ := json.MarshalIndent(st, "", "  ")
	_ = os.WriteFile(supportBundleStatePath(id), b, 0o600)

	rec := httptest.NewRecorder()
	req := roleReq(RoleAdmin, http.MethodPost, "/api/support/bundles/"+id+"/upload", map[string]any{"confirm": true, "case_id": "C1"})
	req.SetPathValue("id", id)
	apiSupportBundleUpload(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("pending-bundle POST = %d, want 409", rec.Code)
	}
}

func TestUploadStatus_GET(t *testing.T) {
	withTempUploadDir(t)
	id := csbID("sts")
	// Unknown → 404.
	rec := httptest.NewRecorder()
	req := roleReq(RoleViewer, http.MethodGet, "/api/support/bundles/"+id+"/upload", nil)
	req.SetPathValue("id", id)
	apiSupportBundleUpload(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown GET = %d, want 404", rec.Code)
	}
	// After enqueue → 200 with state.
	if _, err := enqueueUpload(id, "C1", "tac-1", "hash", time.Now()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	rec2 := httptest.NewRecorder()
	req2 := roleReq(RoleViewer, http.MethodGet, "/api/support/bundles/"+id+"/upload", nil)
	req2.SetPathValue("id", id)
	apiSupportBundleUpload(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("known GET = %d, want 200", rec2.Code)
	}
	var body map[string]any
	_ = json.Unmarshal(rec2.Body.Bytes(), &body)
	if body["state"] != "queued" || body["case_id"] != "C1" {
		t.Fatalf("status body = %+v", body)
	}
}

func TestAPISupportUploads_List(t *testing.T) {
	withTempUploadDir(t)
	if _, err := enqueueUpload(csbID("ula"), "C1", "tac-1", "h1", time.Now()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	if _, err := enqueueUpload(csbID("ulb"), "C2", "tac-1", "h2", time.Now()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	// non-GET → 405
	mRec := httptest.NewRecorder()
	apiSupportUploads(mRec, roleReq(RoleAdmin, http.MethodPost, "/api/support/uploads", nil))
	if mRec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST = %d, want 405", mRec.Code)
	}
	// GET viewer → the queue list
	rec := httptest.NewRecorder()
	apiSupportUploads(rec, roleReq(RoleViewer, http.MethodGet, "/api/support/uploads", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d, want 200", rec.Code)
	}
	var body struct {
		Uploads []map[string]any `json:"uploads"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if len(body.Uploads) != 2 {
		t.Fatalf("listed %d uploads, want 2", len(body.Uploads))
	}
}

func TestStartSupportUploadWorker_StopsOnContext(t *testing.T) {
	withTempUploadDir(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { startSupportUploadWorker(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("worker did not stop on ctx cancel")
	}
}

// ── transfer + worker ───────────────────────────────────────────────────────

func TestRealUploadFunc_RoundTrip(t *testing.T) {
	withTempUploadDir(t)
	enableUploadForTest(t)
	g := &fakeGateway{sig: "SIG-OK"}
	withFakeTransport(t, g)

	id := csbID("rup")
	sealed := []byte("this-is-a-sealed-bundle-blob-longer-than-one-chunk")
	if err := writeSealedUpload(id, sealed); err != nil {
		t.Fatalf("write sealed: %v", err)
	}
	sum := sha256.Sum256(sealed)
	e := uploadQueueEntry{BundleID: id, CaseID: "C1", KeyID: "tac-1", BundleSHA256: hex.EncodeToString(sum[:]), State: uploadStateQueued}

	rec, uploadID, err := realUploadFunc(context.Background(), e)
	if err != nil {
		t.Fatalf("realUploadFunc: %v", err)
	}
	if rec == nil || rec.Sig != "SIG-OK" || uploadID != "sess-1" {
		t.Fatalf("receipt=%+v uploadID=%q", rec, uploadID)
	}
	if !bytes.Equal(g.received, sealed) {
		t.Fatalf("gateway received %q, want the sealed blob", g.received)
	}
}

func TestTransferSealed_ResumeSkipsInit(t *testing.T) {
	g := &fakeGateway{sig: "s"}
	sealed := []byte("abcdefghijklmnop")
	meta := supportupload.Meta{BundleID: "b", BundleSHA256: sha256hex(sealed)}
	// A pre-existing UploadID ⇒ resume: Init must NOT be called.
	_, uploadID, err := transferSealed(context.Background(), g, meta, "prior-sess", newReaderAt(sealed), int64(len(sealed)))
	if err != nil {
		t.Fatalf("resume transfer: %v", err)
	}
	if g.initCalls != 0 {
		t.Fatalf("resume must skip Init, got %d calls", g.initCalls)
	}
	if uploadID != "prior-sess" {
		t.Fatalf("resume uploadID = %q, want prior-sess", uploadID)
	}
	// A fresh transfer ⇒ Init IS called.
	g2 := &fakeGateway{sig: "s"}
	if _, _, err := transferSealed(context.Background(), g2, meta, "", newReaderAt(sealed), int64(len(sealed))); err != nil {
		t.Fatalf("fresh transfer: %v", err)
	}
	if g2.initCalls != 1 {
		t.Fatalf("fresh transfer Init calls = %d, want 1", g2.initCalls)
	}
}

func TestTransferSealed_ReceiptHashMismatchRejected(t *testing.T) {
	sealed := []byte("payload-bytes")
	g := &fakeGateway{sig: "s", badSig: "deadbeef"} // Complete returns a wrong hash
	meta := supportupload.Meta{BundleID: "b", BundleSHA256: sha256hex(sealed)}
	if _, _, err := transferSealed(context.Background(), g, meta, "", newReaderAt(sealed), int64(len(sealed))); err == nil {
		t.Fatal("a receipt whose hash differs from the uploaded bundle must be rejected")
	}
}

func TestDrainDueUploads_SuccessCleansSealedAndAudits(t *testing.T) {
	withTempUploadDir(t)
	enableUploadForTest(t)
	id := csbID("drn")
	sealed := []byte("sealed-blob-bytes")
	if err := writeSealedUpload(id, sealed); err != nil {
		t.Fatalf("write sealed: %v", err)
	}
	if _, err := enqueueUpload(id, "CASE-7", "tac-1", sha256hex(sealed), time.Now()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	baseline := time.Now().UnixMilli()
	up := func(_ context.Context, e uploadQueueEntry) (*supportupload.Receipt, string, error) {
		return &supportupload.Receipt{BundleSHA256: e.BundleSHA256, Sig: "SIG"}, "sess-1", nil
	}
	drainDueUploads(context.Background(), up)

	e, _ := loadUploadQueueEntry(id)
	if e.State != uploadStateUploaded || e.Receipt == nil || e.Receipt.Sig != "SIG" {
		t.Fatalf("entry after drain = %+v", e)
	}
	if _, err := os.Stat(sealedUploadPath(id)); !os.IsNotExist(err) {
		t.Fatalf("sealed blob should be removed after upload, stat err = %v", err)
	}
	if !hasMatchingAuditEntry(auditGet(), "system", "support.bundle.upload", id, baseline) {
		t.Error("expected a support.bundle.upload system audit entry")
	}
}

func TestDrainDueUploads_DisabledIsInert(t *testing.T) {
	withTempUploadDir(t)
	// Upload NOT enabled.
	id := csbID("ina")
	if _, err := enqueueUpload(id, "C1", "tac-1", "h", time.Now()); err != nil {
		t.Fatalf("enqueue: %v", err)
	}
	called := false
	up := func(_ context.Context, e uploadQueueEntry) (*supportupload.Receipt, string, error) {
		called = true
		return &supportupload.Receipt{}, "", nil
	}
	drainDueUploads(context.Background(), up)
	if called {
		t.Fatal("worker must not upload while upload is disabled")
	}
	if e, _ := loadUploadQueueEntry(id); e.State != uploadStateQueued {
		t.Fatalf("entry state = %q, want still queued", e.State)
	}
}

// ── credential redaction ────────────────────────────────────────────────────

func TestUploadCredential_RedactPreserveClear(t *testing.T) {
	withTempUploadDir(t)
	put := func(body any) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		apiSupportUploadConfig(rec, roleReq(RoleAdmin, http.MethodPut, "/api/support/upload/config", body))
		return rec
	}
	// Set enabled+origin+credential.
	if rec := put(map[string]any{"enabled": true, "origin": "https://tac.example.com", "credential": "s3cr3t-bearer"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT set = %d, want 200 (%s)", rec.Code, rec.Body.String())
	}
	if uploadConfigGet().Credential != "s3cr3t-bearer" {
		t.Fatal("credential not persisted")
	}
	// GET never echoes the credential value.
	gRec := httptest.NewRecorder()
	apiSupportUploadConfig(gRec, roleReq(RoleViewer, http.MethodGet, "/api/support/upload/config", nil))
	if body := gRec.Body.String(); strings.Contains(body, "s3cr3t-bearer") {
		t.Fatalf("GET leaked the credential: %s", body)
	}
	var st map[string]any
	_ = json.Unmarshal(gRec.Body.Bytes(), &st)
	if st["credential_set"] != true {
		t.Fatalf("credential_set = %v, want true", st["credential_set"])
	}
	// A posture flip WITHOUT a credential preserves the stored one.
	if rec := put(map[string]any{"enabled": false, "origin": "https://tac.example.com"}); rec.Code != http.StatusOK {
		t.Fatalf("PUT flip = %d, want 200", rec.Code)
	}
	if uploadConfigGet().Credential != "s3cr3t-bearer" {
		t.Fatal("posture flip wiped the credential")
	}
	// Explicit clear removes it.
	if rec := put(map[string]any{"enabled": false, "origin": "https://tac.example.com", "clear_credential": true}); rec.Code != http.StatusOK {
		t.Fatalf("PUT clear = %d, want 200", rec.Code)
	}
	if uploadConfigGet().Credential != "" {
		t.Fatal("clear_credential did not remove the credential")
	}
}

// ── small helpers ───────────────────────────────────────────────────────────

func sha256hex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func newReaderAt(b []byte) io.ReaderAt { return bytes.NewReader(b) }
