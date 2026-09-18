package main

// FE-6B.0 — Certificates and CA lifecycle BACKEND-TRUTH GATE: deterministic
// RED matrix, written against the merged baseline f1db3633 BEFORE any
// product change. Every row drives the real handlers (directly or through
// registerSecurityRoutes' mux, so a route that does not exist yet fails as
// a 404 rather than a compile error) and pins, on every refusal, ZERO
// partial mutation (live CA fingerprint + bundle bytes + UI cert files),
// ZERO success audit and NO revision advancement.
//
// Seams this file declared on the baseline (nil, never called) and the
// correction moved beside the code they instrument (the FE-6A.2 round-5
// precedent): caOpsBeforeFinishHook (between the durable CA commit and the
// terminal operation record), reopenCertificateOperationsForTest (a
// "restart" of the operation ledger from its file), caChallengeClock (the
// challenge's clock).
//
// Rows (the directive's 18):
//
//	R01 stale/missing fences ⇒ 428/409 with zero disk/runtime/audit mutation
//	R02 persist failure BEFORE publication ⇒ 500 persist_failed, live CA unchanged
//	R03 finalisation failure AFTER a proven durable commit ⇒ truthful committed /
//	    pending_reconciliation, settled exactly once by the lookup
//	R04 lost response: replay by operationId, also across a ledger restart
//	R05 same operationId + different candidate ⇒ 409 operation_mismatch
//	R06 CA challenge bound to actor, action, revision, candidate, operationId
//	R07 challenge reuse, expiry and non-consumption by unrelated/malformed attempts
//	R08 key mismatch / malformed chain / not-a-CA ⇒ atomic typed refusal
//	R09 secret + raw-error + path leak sweep (response, log, audit, ledger)
//	R10 referenced replace/delete refused under a concurrent state change
//	R11 OCSP toggle durability + restart truth; persist failure leaves runtime
//	R12 OCSP viewer response carries no path and no raw error
//	R13 durable exactly-once audit across an append failure
//	R14 corrupt ledger ⇒ fail-closed, evidence preserved, zero mutation
//	R15 backup/restore + rollback implications
//	R16 node-local vs cluster publication facts
//	R17 legacy console speaks the corrected contract
//	R18 controls: every valid operation still succeeds
//
// On f1db3633: R01–R14, R15 (read model), R16 (read model), R17 and R18
// FAIL; the backup-manifest and ConfigSnapshot halves of R15/R16 pass as
// controls.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"github.com/KidCarmi/Culvert/internal/ca"
)

// ── seams ───────────────────────────────────────────────────────────────────
// caOpsBeforeFinishHook, reopenCertificateOperationsForTest and
// caChallengeClock were declared here on the baseline (nil, never called) and
// now live in certificate_operations.go beside the code they instrument.

const fe6b0LedgerFile = "certificate_operations.json"

// ── fixtures ────────────────────────────────────────────────────────────────

// fe6b0Node is one appliance: a fresh inspection CA persisted to a bundle
// under a temp dataDir, its own UI-cert store, OCSP globals reset, the
// admin-settings path pointed at a temp file.
func fe6b0Node(t *testing.T) (dir string) {
	t.Helper()
	dir = withTempDataDirForUITLS(t)
	swapInspectionCA(t)
	if err := certMgr.InitCA(); err != nil {
		t.Fatal(err)
	}
	caRuntime.path = filepath.Join(dir, "ca.bundle")
	caRuntime.passphrase = ""
	if err := certMgr.SaveCA(caRuntime.path, ""); err != nil {
		t.Fatal(err)
	}
	resetMTLSOCSPGlobals(t)
	resetOCSPDesiredForTest()
	t.Cleanup(resetOCSPDesiredForTest)
	fe6a3cSettingsPath(t, filepath.Join(dir, "admin_settings.json"))
	prevHook, prevClock := caOpsBeforeFinishHook, caChallengeClock
	caOpsBeforeFinishHook, caChallengeClock = nil, nil
	t.Cleanup(func() { caOpsBeforeFinishHook, caChallengeClock = prevHook, prevClock })
	return dir
}

func fe6b0Mux() *http.ServeMux {
	mux := http.NewServeMux()
	registerSecurityRoutes(mux)
	return mux
}

func fe6b0Fingerprint() string {
	fp, _ := certMgr.CACertInfo()["fingerprint"].(string)
	return fp
}

func fe6b0Bundle(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(caRuntime.path)
	if err != nil {
		t.Fatalf("bundle: %v", err)
	}
	return b
}

func fe6b0Decode(w *httptest.ResponseRecorder) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &m)
	return m
}

// fe6b0Do sends a JSON request (admin context) through the mux.
func fe6b0Do(mux *http.ServeMux, method, path string, body any) (status int, m map[string]any, w *httptest.ResponseRecorder) {
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, jsonReq(method, path, body))
	return w.Code, fe6b0Decode(w), w
}

// fe6b0DoAs is fe6b0Do with a different peer address (a different actor).
func fe6b0DoAs(mux *http.ServeMux, addr, method, path string, body any) (status int, m map[string]any) {
	r := jsonReq(method, path, body)
	r.RemoteAddr = addr
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Code, fe6b0Decode(w)
}

func fe6b0Status(t *testing.T) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	apiCAStatus(w, getReq("/api/ca/status"))
	if w.Code != http.StatusOK {
		t.Fatalf("ca status = %d %s", w.Code, w.Body.String())
	}
	return fe6b0Decode(w)
}

// fe6b0Revision is the server-owned CA revision token (round 0: absent).
func fe6b0Revision(t *testing.T) string {
	t.Helper()
	rev, _ := fe6b0Status(t)["revision"].(string)
	return rev
}

// fe6b0CAPair mints an ECDSA CA certificate + key (PEM) with the given CN.
func fe6b0CAPair(t *testing.T, cn string, isCA bool) (certPEM, keyPEM []byte, fingerprint string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: cn, Organization: []string{"FE-6B.0"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour),
		IsCA: isCA, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
	}
	if !isCA {
		tpl.KeyUsage = x509.KeyUsageDigitalSignature
		tpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tpl.DNSNames = []string{"ui.example"}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	sum := sha256.Sum256(der)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		hex.EncodeToString(sum[:])
}

// fe6b0Upload POSTs a multipart certificate upload through the mux.
func fe6b0Upload(t *testing.T, mux *http.ServeMux, query string, fields map[string]string) (status int, m map[string]any, w *httptest.ResponseRecorder) {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	for k, v := range fields {
		_ = mw.WriteField(k, v)
	}
	_ = mw.Close()
	r := httptest.NewRequest(http.MethodPost, "/api/certs/upload"+query, &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	r.RemoteAddr = "127.0.0.1:9999"
	r = adminCtx(r)
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w.Code, fe6b0Decode(w), w
}

// fe6b0Audits counts audit entries of action since the watermark, returning
// their structural operation ids.
func fe6b0Audits(since int64, action string) (n int, opIDs []string) {
	entries := auditGet()
	for i := range entries {
		e := &entries[i]
		if e.TS < since || e.Action != action {
			continue
		}
		n++
		opIDs = append(opIDs, e.OperationID)
	}
	return n, opIDs
}

// fe6b0Challenge obtains the server-issued rotation challenge for opID at rev.
func fe6b0Challenge(t *testing.T, mux *http.ServeMux, opID, rev string) (challenge string, issued map[string]any) {
	t.Helper()
	code, m, w := fe6b0Do(mux, http.MethodPost, "/api/ca/rotate/challenge?operationId="+opID+"&caRevision="+rev, nil)
	if code != http.StatusOK {
		t.Fatalf("challenge = %d %s", code, w.Body.String())
	}
	challenge, _ = m["challenge"].(string)
	if challenge == "" {
		t.Fatalf("no challenge in %v", m)
	}
	return challenge, m
}

func fe6b0Rotate(mux *http.ServeMux, opID, rev, challenge string) (status int, m map[string]any, w *httptest.ResponseRecorder) {
	return fe6b0Do(mux, http.MethodPost, "/api/ca/rotate?operationId="+opID+"&caRevision="+rev, map[string]any{"challenge": challenge})
}

// fe6b0RotateOK performs a complete valid rotation and returns the new revision.
func fe6b0RotateOK(t *testing.T, mux *http.ServeMux, opID string) (newRev string, resp map[string]any) {
	t.Helper()
	rev := fe6b0Revision(t)
	ch, _ := fe6b0Challenge(t, mux, opID, rev)
	code, m, w := fe6b0Rotate(mux, opID, rev, ch)
	if code != http.StatusOK || m["rotated"] != true {
		t.Fatalf("rotate = %d %s", code, w.Body.String())
	}
	return fe6b0Revision(t), m
}

// fe6b0AssertUnchanged pins zero mutation + zero success audit.
func fe6b0AssertUnchanged(t *testing.T, fp, rev string, bundle []byte, since int64) {
	t.Helper()
	if got := fe6b0Fingerprint(); got != fp {
		t.Fatalf("live CA CHANGED on a refused operation: %s → %s", fp, got)
	}
	if got := fe6b0Revision(t); got != rev {
		t.Fatalf("revision advanced on a refused operation: %q → %q", rev, got)
	}
	if !bytes.Equal(fe6b0Bundle(t), bundle) {
		t.Fatal("bundle bytes changed on a refused operation")
	}
	for _, a := range []string{"ca.rotate", "ca.import", "cert.ui.replace", "cert.ui.delete", "ocsp.set", "certs.upload_mitm", "certs.upload_ui", "ocsp.toggle"} {
		if n, ids := fe6b0Audits(since, a); n != 0 {
			t.Fatalf("a refused operation emitted a %s audit: %d %v", a, n, ids)
		}
	}
}

func fe6b0Lookup(mux *http.ServeMux, opID string) (status int, m map[string]any) {
	code, m, _ := fe6b0Do(mux, http.MethodGet, "/api/ca/operations/"+opID, nil)
	return code, m
}

func fe6b0OpID() string { return strings.ToLower(uuidv4ForTest()) }

// uuidv4ForTest formats 16 random bytes as an RFC 4122 v4 UUID.
func uuidv4ForTest() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// ── R01 fences ──────────────────────────────────────────────────────────────

func TestFE6B0_R01_StaleOrMissingFencesMutateNothing(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	fp, rev, bundle, since := fe6b0Fingerprint(), fe6b0Revision(t), fe6b0Bundle(t), fe6aSince()
	if rev == "" {
		t.Fatal("GET /api/ca/status publishes no server-owned revision token")
	}
	op := fe6b0OpID()
	// missing fence on the challenge and on the rotation
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ca/rotate/challenge?operationId="+op, nil); code != http.StatusPreconditionRequired || m["code"] != refusalPreconditionRequired {
		t.Fatalf("challenge without caRevision = %d %v, want 428 precondition_required", code, m)
	}
	if code, m, _ := fe6b0Rotate(mux, op, "", "x"); code != http.StatusPreconditionRequired {
		t.Fatalf("rotate without caRevision = %d %v", code, m)
	}
	// missing operation identity
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ca/rotate/challenge?caRevision="+rev, nil); code != http.StatusPreconditionRequired || m["code"] != refusalOperationIDRequired {
		t.Fatalf("challenge without operationId = %d %v, want 428 operation_id_required", code, m)
	}
	// stale fence
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ca/rotate/challenge?operationId="+op+"&caRevision=car1:"+strings.Repeat("0", 64), nil); code != http.StatusConflict || m["code"] != refusalStale {
		t.Fatalf("stale challenge fence = %d %v, want 409 stale", code, m)
	} else if cur, _ := m["current"].(map[string]any); cur["caRevision"] != rev {
		t.Fatalf("stale refusal must carry current.caRevision=%s: %v", rev, m)
	}
	// import: stale fence
	certPEM, keyPEM, _ := fe6b0CAPair(t, "Stale Import CA", true)
	if code, m, _ := fe6b0Upload(t, mux, "?target=mitm&operationId="+fe6b0OpID()+"&caRevision=car1:"+strings.Repeat("1", 64), map[string]string{"target": "mitm", "cert": string(certPEM), "key": string(keyPEM)}); code != http.StatusConflict || m["code"] != refusalStale {
		t.Fatalf("stale import fence = %d %v", code, m)
	}
	// import: missing fence + missing operation id
	if code, m, _ := fe6b0Upload(t, mux, "?target=mitm", map[string]string{"target": "mitm", "cert": string(certPEM), "key": string(keyPEM)}); code != http.StatusPreconditionRequired {
		t.Fatalf("unfenced import = %d %v, want 428", code, m)
	}
	// OCSP: missing fence
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ocsp?operationId="+fe6b0OpID(), map[string]any{"enabled": true}); code != http.StatusPreconditionRequired {
		t.Fatalf("unfenced OCSP toggle = %d %v, want 428", code, m)
	}
	// UI cert delete: missing fence
	if code, m, _ := fe6b0Do(mux, http.MethodDelete, "/api/certs/ui?operationId="+fe6b0OpID(), nil); code != http.StatusPreconditionRequired {
		t.Fatalf("unfenced UI cert delete = %d %v, want 428", code, m)
	}
	fe6b0AssertUnchanged(t, fp, rev, bundle, since)
	if globalOCSP.Enabled() {
		t.Fatal("the refused OCSP toggle changed the runtime")
	}
}

// ── R02 persist failure BEFORE publication ─────────────────────────────────

func TestFE6B0_R02_PersistFailureBeforePublicationLeavesLiveCAUntouched(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	fp, rev, since := fe6b0Fingerprint(), fe6b0Revision(t), fe6aSince()
	// The bundle path is a DIRECTORY: every write fails, nothing else does.
	bad := filepath.Join(dir, "bundle-dir")
	if err := os.Mkdir(bad, 0o700); err != nil {
		t.Fatal(err)
	}
	good := caRuntime.path
	caRuntime.path = bad
	t.Cleanup(func() { caRuntime.path = good })

	op := fe6b0OpID()
	ch, _ := fe6b0Challenge(t, mux, op, rev)
	code, m, w := fe6b0Rotate(mux, op, rev, ch)
	if code != http.StatusInternalServerError || m["code"] != refusalPersistFailed {
		t.Fatalf("rotate with an unwritable bundle = %d %s, want 500 persist_failed", code, w.Body.String())
	}
	if m["rotated"] == true || m["persisted"] == false {
		t.Fatalf("a failed persist must not be reported as a rotation: %v", m)
	}
	if got := fe6b0Fingerprint(); got != fp {
		t.Fatalf("INSTALL PRECEDED THE DURABLE COMMIT: the live CA changed (%s → %s) although the bundle could not be written", fp, got)
	}
	if got := fe6b0Revision(t); got != rev {
		t.Fatalf("revision advanced: %q → %q", rev, got)
	}
	if n, ids := fe6b0Audits(since, "ca.rotate"); n != 0 {
		t.Fatalf("success audit on a failed persist: %d %v", n, ids)
	}
	if code, l := fe6b0Lookup(mux, op); code != http.StatusOK || l["state"] != "aborted" || l["code"] != refusalPersistFailed {
		t.Fatalf("lookup after a failed persist = %d %v, want aborted/persist_failed", code, l)
	}
	// Import has the same boundary.
	certPEM, keyPEM, _ := fe6b0CAPair(t, "Import CA", true)
	op2 := fe6b0OpID()
	code, m, w = fe6b0Upload(t, mux, "?target=mitm&operationId="+op2+"&caRevision="+rev, map[string]string{"target": "mitm", "cert": string(certPEM), "key": string(keyPEM)})
	if code != http.StatusInternalServerError || m["code"] != refusalPersistFailed {
		t.Fatalf("import with an unwritable bundle = %d %s", code, w.Body.String())
	}
	if got := fe6b0Fingerprint(); got != fp {
		t.Fatalf("import INSTALLED before the durable commit: %s → %s", fp, got)
	}
}

// ── R03 finalisation failure AFTER a durable commit ─────────────────────────

func TestFE6B0_R03_FinalizationFailureAfterDurableCommitIsTruthfulAndSettlesOnce(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	fp, rev, since := fe6b0Fingerprint(), fe6b0Revision(t), fe6aSince()
	ledger := filepath.Join(dir, fe6b0LedgerFile)
	ran := false
	caOpsBeforeFinishHook = func() {
		ran = true
		// The ledger becomes unwritable AFTER the bundle landed and the CA is live.
		_ = os.Rename(ledger, ledger+".aside")
		_ = os.Mkdir(ledger, 0o700)
	}
	op := fe6b0OpID()
	ch, _ := fe6b0Challenge(t, mux, op, rev)
	code, m, w := fe6b0Rotate(mux, op, rev, ch)
	if !ran {
		t.Fatal("the durable-commit/terminal-record seam did not run (correction absent)")
	}
	if code != http.StatusOK || m["rotated"] != true {
		t.Fatalf("a rotation whose bundle landed must report the truthful committed state, got %d %s", code, w.Body.String())
	}
	if m["recordState"] != "pending_reconciliation" {
		t.Fatalf("terminal record not durable ⇒ recordState pending_reconciliation, got %v", m)
	}
	newFP := fe6b0Fingerprint()
	if newFP == fp {
		t.Fatal("the committed rotation is not live")
	}
	// The bundle on disk IS the new CA.
	probe := ca.New()
	if err := probe.LoadCA(caRuntime.path, ""); err != nil {
		t.Fatal(err)
	}
	if got, _ := probe.CACertInfo()["fingerprint"].(string); got != newFP {
		t.Fatalf("bundle fingerprint %s ≠ live %s", got, newFP)
	}
	if n, _ := fe6b0Audits(since, "ca.rotate"); n != 0 {
		t.Fatalf("a success audit was emitted while the terminal record is not durable: %d", n)
	}
	// Storage recovers: the lookup settles the intent EXACTLY ONCE.
	_ = os.Remove(ledger)
	_ = os.Rename(ledger+".aside", ledger)
	caOpsBeforeFinishHook = nil
	for i := 0; i < 2; i++ {
		code, l := fe6b0Lookup(mux, op)
		if code != http.StatusOK || l["state"] != "committed" {
			t.Fatalf("lookup %d = %d %v, want committed", i, code, l)
		}
		if l["auditState"] == "pending" && i == 1 {
			t.Fatalf("the audit is still owed after two lookups: %v", l)
		}
	}
	if n, ids := fe6b0Audits(since, "ca.rotate"); n != 1 || ids[0] != op {
		t.Fatalf("audits after settlement = %d %v, want exactly one keyed on %s", n, ids, op)
	}
	if got := fe6b0Fingerprint(); got != newFP {
		t.Fatalf("settlement re-rotated: %s → %s", newFP, got)
	}
}

// ── R04 lost response + replay across restart ───────────────────────────────

func TestFE6B0_R04_LostResponseReplaysByOperationIdAcrossRestart(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	op := fe6b0OpID()
	newRev, first := fe6b0RotateOK(t, mux, op)
	fp := fe6b0Fingerprint()
	// The response was lost: the client re-sends the SAME operation.
	code, again, w := fe6b0Rotate(mux, op, newRev, "")
	if code != http.StatusOK || again["replayed"] != true {
		t.Fatalf("replay = %d %s, want 200 replayed:true", code, w.Body.String())
	}
	if got := fe6b0Fingerprint(); got != fp {
		t.Fatalf("the replay ROTATED AGAIN: %s → %s", fp, got)
	}
	if again["operationId"] != op || first["ca"] == nil {
		t.Fatalf("replay does not echo the operation: %v / %v", again, first)
	}
	// Restart the ledger from its file.
	if reopenCertificateOperationsForTest == nil {
		t.Fatal("no ledger restart seam (correction absent)")
	}
	reopenCertificateOperationsForTest()
	if code, l := fe6b0Lookup(mux, op); code != http.StatusOK || l["state"] != "committed" || l["action"] != "ca.rotate" {
		t.Fatalf("lookup after restart = %d %v", code, l)
	}
	if code, m, _ := fe6b0Rotate(mux, op, newRev, ""); code != http.StatusOK || m["replayed"] != true {
		t.Fatalf("replay after restart = %d %v", code, m)
	}
	if n, ids := fe6b0Audits(since, "ca.rotate"); n != 1 || ids[0] != op {
		t.Fatalf("audits = %d %v, want exactly one keyed on %s", n, ids, op)
	}
}

// ── R05 same operationId, different candidate ───────────────────────────────

func TestFE6B0_R05_SameOperationIdDifferentCandidateIsAMismatch(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	rev := fe6b0Revision(t)
	certA, keyA, fpA := fe6b0CAPair(t, "Import A", true)
	certB, keyB, _ := fe6b0CAPair(t, "Import B", true)
	op := fe6b0OpID()
	code, m, w := fe6b0Upload(t, mux, "?target=mitm&operationId="+op+"&caRevision="+rev, map[string]string{"target": "mitm", "cert": string(certA), "key": string(keyA)})
	if code != http.StatusOK || m["imported"] != true {
		t.Fatalf("import A = %d %s", code, w.Body.String())
	}
	liveA := fe6b0Fingerprint()
	if strings.ReplaceAll(strings.ToLower(liveA), ":", "") != fpA {
		t.Fatalf("live CA %s is not the imported A %s", liveA, fpA)
	}
	rev2 := fe6b0Revision(t)
	code, m, w = fe6b0Upload(t, mux, "?target=mitm&operationId="+op+"&caRevision="+rev2, map[string]string{"target": "mitm", "cert": string(certB), "key": string(keyB)})
	if code != http.StatusConflict || m["code"] != refusalOperationMismatch {
		t.Fatalf("same operationId + different candidate = %d %s, want 409 operation_mismatch", code, w.Body.String())
	}
	if got := fe6b0Fingerprint(); got != liveA {
		t.Fatalf("the mismatch MUTATED: %s → %s", liveA, got)
	}
	// Rotation: the same operationId with a different fence/candidate is a mismatch too.
	rop := fe6b0OpID()
	fe6b0RotateOK(t, mux, rop)
	if code, m, _ := fe6b0Upload(t, mux, "?target=mitm&operationId="+rop+"&caRevision="+fe6b0Revision(t), map[string]string{"target": "mitm", "cert": string(certB), "key": string(keyB)}); code != http.StatusConflict || m["code"] != refusalOperationMismatch {
		t.Fatalf("rotation operationId reused for an import = %d %v", code, m)
	}
}

// ── R06 challenge binding ───────────────────────────────────────────────────

func TestFE6B0_R06_ChallengeIsBoundToActorActionRevisionAndOperation(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	fp, rev, bundle, since := fe6b0Fingerprint(), fe6b0Revision(t), fe6b0Bundle(t), fe6aSince()
	op := fe6b0OpID()
	ch, issued := fe6b0Challenge(t, mux, op, rev)
	if issued["operationId"] != op || issued["caRevision"] != rev || issued["fingerprint"] != fp {
		t.Fatalf("the challenge must state the facts it binds: %v", issued)
	}
	changed := func(m map[string]any) []string {
		cur, _ := m["current"].(map[string]any)
		raw, _ := cur["changed"].([]any)
		out := make([]string, 0, len(raw))
		for _, v := range raw {
			s, _ := v.(string)
			out = append(out, s)
		}
		return out
	}
	// a different actor
	if code, m := fe6b0DoAs(mux, "10.9.9.9:4444", http.MethodPost, "/api/ca/rotate?operationId="+op+"&caRevision="+rev, map[string]any{"challenge": ch}); code != http.StatusConflict || m["code"] != "challenge_stale" || !fe6b0Has(changed(m), "actor") {
		t.Fatalf("another actor confirming = %d %v, want 409 challenge_stale changed:[actor]", code, m)
	}
	// a different operation
	if code, m, _ := fe6b0Rotate(mux, fe6b0OpID(), rev, ch); code != http.StatusConflict || m["code"] != "challenge_stale" || !fe6b0Has(changed(m), "operation") {
		t.Fatalf("another operation confirming = %d %v, want changed:[operation]", code, m)
	}
	fe6b0AssertUnchanged(t, fp, rev, bundle, since)
	// The bound confirm still succeeds: the unrelated attempts consumed nothing.
	if code, m, w := fe6b0Rotate(mux, op, rev, ch); code != http.StatusOK || m["rotated"] != true {
		t.Fatalf("bound confirm after unrelated attempts = %d %s", code, w.Body.String())
	}
	// A challenge issued against a revision that then moved is stale (revision).
	op2 := fe6b0OpID()
	rev2 := fe6b0Revision(t)
	ch2, _ := fe6b0Challenge(t, mux, op2, rev2)
	fe6b0RotateOK(t, mux, fe6b0OpID()) // moves the revision underneath
	if code, m, _ := fe6b0Rotate(mux, op2, rev2, ch2); code != http.StatusConflict || m["code"] != refusalStale && m["code"] != "challenge_stale" {
		t.Fatalf("confirm on a moved revision = %d %v, want stale", code, m)
	} else if m["code"] == "challenge_stale" && !fe6b0Has(changed(m), "ca_revision") {
		t.Fatalf("stale challenge must name the changed class: %v", m)
	}
	for _, c := range changed(map[string]any{}) {
		if strings.Contains(c, "/") || strings.Contains(c, ":") {
			t.Fatalf("changed-field class is not bounded: %q", c)
		}
	}
}

func fe6b0Has(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// ── R07 reuse, expiry, non-consumption ──────────────────────────────────────

func TestFE6B0_R07_ChallengeReuseExpiryAndNonConsumption(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	rev := fe6b0Revision(t)
	op := fe6b0OpID()
	ch, _ := fe6b0Challenge(t, mux, op, rev)
	// malformed attempts do not consume it
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ca/rotate?operationId="+op+"&caRevision="+rev, map[string]any{"challenge": 12345}); code != http.StatusBadRequest || m["code"] != refusalInvalidInput {
		t.Fatalf("malformed challenge body = %d %v, want 400 invalid_input", code, m)
	}
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ca/rotate?operationId="+op+"&caRevision="+rev, nil); code != http.StatusPreconditionRequired || m["code"] != "challenge_required" {
		t.Fatalf("confirm without a challenge = %d %v, want 428 challenge_required", code, m)
	}
	if code, m, _ := fe6b0Rotate(mux, op, rev, "not-the-challenge"); code != http.StatusConflict || m["code"] != "challenge_stale" {
		t.Fatalf("wrong challenge = %d %v", code, m)
	}
	code, m, w := fe6b0Rotate(mux, op, rev, ch)
	if code != http.StatusOK || m["rotated"] != true {
		t.Fatalf("the genuine confirm was consumed by an unrelated attempt: %d %s", code, w.Body.String())
	}
	// Reuse under a NEW operation is refused (single use).
	if code, m, _ := fe6b0Rotate(mux, fe6b0OpID(), fe6b0Revision(t), ch); code != http.StatusConflict {
		t.Fatalf("challenge reuse = %d %v, want 409", code, m)
	}
	// Expiry: the clock moves past the challenge's lifetime.
	if caChallengeClock == nil {
		base := time.Now()
		caChallengeClock = func() time.Time { return base }
	}
	op3, rev3 := fe6b0OpID(), fe6b0Revision(t)
	ch3, issued := fe6b0Challenge(t, mux, op3, rev3)
	secs, _ := issued["expiresInSeconds"].(float64)
	if secs <= 0 || secs > 600 {
		t.Fatalf("challenge lifetime must be bounded and stated: %v", issued)
	}
	base := caChallengeClock()
	caChallengeClock = func() time.Time { return base.Add(time.Duration(secs+1) * time.Second) }
	code, m, _ = fe6b0Rotate(mux, op3, rev3, ch3)
	if code != http.StatusConflict || m["code"] != "challenge_stale" {
		t.Fatalf("expired challenge = %d %v, want 409 challenge_stale", code, m)
	}
	cur, _ := m["current"].(map[string]any)
	if raw, _ := cur["changed"].([]any); len(raw) != 1 || raw[0] != "expired" {
		t.Fatalf("expired refusal must name exactly [expired]: %v", m)
	}
}

// ── R08 candidate validation is atomic and typed ────────────────────────────

func TestFE6B0_R08_KeyMismatchAndMalformedChainAreAtomicTypedRefusals(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	fp, rev, bundle, since := fe6b0Fingerprint(), fe6b0Revision(t), fe6b0Bundle(t), fe6aSince()
	certA, _, _ := fe6b0CAPair(t, "A", true)
	_, keyB, _ := fe6b0CAPair(t, "B", true)
	leaf, leafKey, _ := fe6b0CAPair(t, "leaf", false)
	rows := []struct {
		name, target, cert, key, reason string
	}{
		{"key_mismatch", "mitm", string(certA), string(keyB), "key_mismatch"},
		{"malformed_pem", "mitm", "-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n", string(keyB), "malformed_pem"},
		{"not_ca", "mitm", string(leaf), string(leafKey), "not_ca"},
		{"chain_invalid", "mitm", string(certA) + "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n", string(keyB), "chain_invalid"},
		{"ui_key_mismatch", "ui", string(leaf), string(keyB), "key_mismatch"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			q := "?target=" + row.target + "&operationId=" + fe6b0OpID() + "&caRevision=" + rev + "&uiCertRevision=uic1:none"
			code, m, w := fe6b0Upload(t, mux, q, map[string]string{"target": row.target, "cert": row.cert, "key": row.key})
			if code != http.StatusBadRequest || m["code"] != "candidate_invalid" {
				t.Fatalf("%s = %d %s, want 400 candidate_invalid", row.name, code, w.Body.String())
			}
			cur, _ := m["current"].(map[string]any)
			if cur["reason"] != row.reason {
				t.Fatalf("%s reason = %v, want %s", row.name, cur["reason"], row.reason)
			}
			if strings.Contains(w.Body.String(), "PRIVATE KEY") || strings.Contains(w.Body.String(), "x509:") || strings.Contains(w.Body.String(), "tls:") {
				t.Fatalf("refusal leaks material or a raw parser error: %s", w.Body.String())
			}
		})
	}
	fe6b0AssertUnchanged(t, fp, rev, bundle, since)
	if _, err := os.Stat(filepath.Join(dir, customUITLSCertFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused UI upload wrote a certificate file")
	}
	if _, err := os.Stat(filepath.Join(dir, customUITLSKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused UI upload wrote a key file")
	}
}

// ── R09 leak sweep ──────────────────────────────────────────────────────────

func TestFE6B0_R09_NoSecretPathOrRawErrorCrossesAnySurface(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	sink := captureLoggerForTest(t)
	since := fe6aSince()
	restoreAudit := audit.SwapRingForTest()
	t.Cleanup(restoreAudit)
	// 1. a mismatched import (the raw parser error would name the fault)
	certA, _, _ := fe6b0CAPair(t, "A", true)
	_, keyB, _ := fe6b0CAPair(t, "B", true)
	_, _, w1 := fe6b0Upload(t, mux, "?target=mitm&operationId="+fe6b0OpID()+"&caRevision="+fe6b0Revision(t), map[string]string{"target": "mitm", "cert": string(certA), "key": string(keyB)})
	// 2. a misconfigured mTLS client cert (the file path + raw load error)
	missing := filepath.Join(dir, "client.crt")
	loadMTLSClientCert(mtlsOCSPStartupConfig{ClientCertFile: missing, ClientKeyFile: filepath.Join(dir, "client.key")})
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, viewerCtx(getReq("/api/ocsp")))
	// 3. a recorded CA load failure (the bundle path + raw error)
	prevErr := sslInspectionLoadFailure()
	noteSSLInspectionUnavailable(caRuntime.path, errors.New("open "+caRuntime.path+": permission denied"))
	t.Cleanup(func() { sslInspectionLoadError.Store(prevErr) })
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, viewerCtx(getReq("/api/ca/status")))
	w4 := httptest.NewRecorder()
	mux.ServeHTTP(w4, viewerCtx(getReq("/api/certificates")))
	// 4. a successful import + rotation (audit + ledger content)
	certC, keyC, _ := fe6b0CAPair(t, "C", true)
	sslInspectionLoadError.Store("")
	_, _, w5 := fe6b0Upload(t, mux, "?target=mitm&operationId="+fe6b0OpID()+"&caRevision="+fe6b0Revision(t), map[string]string{"target": "mitm", "cert": string(certC), "key": string(keyC)})
	if w5.Code != http.StatusOK {
		t.Fatalf("import C = %d %s", w5.Code, w5.Body.String())
	}
	fe6b0RotateOK(t, mux, fe6b0OpID())
	ledger, _ := os.ReadFile(filepath.Join(dir, fe6b0LedgerFile))
	var audits strings.Builder
	for _, e := range auditGet() {
		if e.TS >= since {
			b, _ := json.Marshal(e)
			audits.Write(b)
		}
	}
	surfaces := map[string]string{
		"import refusal": w1.Body.String(), "ocsp GET": w2.Body.String(), "ca status": w3.Body.String(),
		"certificates": w4.Body.String(), "import result": w5.Body.String(), "ledger": string(ledger), "audit": audits.String(), "log": sink.String(),
	}
	forbidden := []string{"PRIVATE KEY", dir, "permission denied", "x509:", "tls: failed", "no such file"}
	for name, body := range surfaces {
		for _, f := range forbidden {
			if strings.Contains(body, f) {
				t.Errorf("%s contains %q", name, f)
			}
		}
	}
	if m := fe6b0Decode(w2); m["mtlsClientCertFile"] != nil || m["mtlsClientCertLastError"] != nil {
		t.Errorf("OCSP viewer response carries the file path / raw error: %v", m)
	}
	if m := fe6b0Decode(w3); m["loadFailureReason"] != nil || m["rotationPersistError"] != nil || m["unusableReason"] != nil || m["loadRecoveryError"] != nil {
		t.Errorf("CA status carries raw error strings: %v", m)
	} else if m["loadFailureClass"] == nil {
		t.Errorf("CA status must report the load failure as a bounded class: %v", m)
	}
}

// ── R10 concurrent state change ─────────────────────────────────────────────

func TestFE6B0_R10_ReferencedReplaceOrDeleteRefusedUnderConcurrentChange(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	// UI cert: A persisted; B replaces it; a delete fenced on A's revision is stale.
	leafA, keyA, _ := fe6b0CAPair(t, "ui-a", false)
	leafB, keyB, _ := fe6b0CAPair(t, "ui-b", false)
	code, m, w := fe6b0Upload(t, mux, "?target=ui&operationId="+fe6b0OpID()+"&uiCertRevision=uic1:none", map[string]string{"target": "ui", "cert": string(leafA), "key": string(keyA)})
	if code != http.StatusOK || m["replaced"] != true {
		t.Fatalf("ui upload A = %d %s", code, w.Body.String())
	}
	uc, _ := m["uiCert"].(map[string]any)
	revA, _ := uc["revision"].(string)
	if revA == "" || revA == "uic1:none" {
		t.Fatalf("no UI cert revision after A: %v", m)
	}
	code, m, w = fe6b0Upload(t, mux, "?target=ui&operationId="+fe6b0OpID()+"&uiCertRevision="+revA, map[string]string{"target": "ui", "cert": string(leafB), "key": string(keyB)})
	if code != http.StatusOK || m["replaced"] != true {
		t.Fatalf("ui upload B = %d %s", code, w.Body.String())
	}
	uc, _ = m["uiCert"].(map[string]any)
	revB, _ := uc["revision"].(string)
	onDisk, _ := os.ReadFile(filepath.Join(dir, customUITLSCertFile))
	code, m, w = fe6b0Do(mux, http.MethodDelete, "/api/certs/ui?operationId="+fe6b0OpID()+"&uiCertRevision="+revA, nil)
	if code != http.StatusConflict || m["code"] != refusalStale {
		t.Fatalf("delete fenced on a superseded revision = %d %s, want 409 stale", code, w.Body.String())
	}
	if cur, _ := m["current"].(map[string]any); cur["uiCertRevision"] != revB {
		t.Fatalf("stale delete must carry current.uiCertRevision=%s: %v", revB, m)
	}
	if now, _ := os.ReadFile(filepath.Join(dir, customUITLSCertFile)); !bytes.Equal(now, onDisk) {
		t.Fatal("the refused delete changed the UI cert on disk")
	}
	if n, _ := fe6b0Audits(since, "cert.ui.delete"); n != 0 {
		t.Fatal("a refused delete emitted a success audit")
	}
	// A replace fenced on A's revision is stale too.
	if code, m, _ := fe6b0Upload(t, mux, "?target=ui&operationId="+fe6b0OpID()+"&uiCertRevision="+revA, map[string]string{"target": "ui", "cert": string(leafA), "key": string(keyA)}); code != http.StatusConflict || m["code"] != refusalStale {
		t.Fatalf("replace fenced on a superseded revision = %d %v", code, m)
	}
	// Inspection CA: an import fenced on the pre-rotation revision is stale.
	rev := fe6b0Revision(t)
	fe6b0RotateOK(t, mux, fe6b0OpID())
	fp := fe6b0Fingerprint()
	certC, keyC, _ := fe6b0CAPair(t, "C", true)
	if code, m, _ := fe6b0Upload(t, mux, "?target=mitm&operationId="+fe6b0OpID()+"&caRevision="+rev, map[string]string{"target": "mitm", "cert": string(certC), "key": string(keyC)}); code != http.StatusConflict || m["code"] != refusalStale {
		t.Fatalf("import fenced on the pre-rotation revision = %d %v", code, m)
	}
	if got := fe6b0Fingerprint(); got != fp {
		t.Fatalf("stale import mutated: %s → %s", fp, got)
	}
	// The inspection CA is ALWAYS referenced by TLS inspection: there is no delete route.
	if code, _, _ := fe6b0Do(mux, http.MethodDelete, "/api/ca/status", nil); code == http.StatusOK {
		t.Fatal("a delete of the inspection CA must not exist")
	}
}

// ── R11 OCSP durability + restart truth ─────────────────────────────────────

func TestFE6B0_R11_OCSPToggleIsDurableAndRestartStable(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	settings := filepath.Join(dir, "admin_settings.json")
	since := fe6aSince()
	globalOCSP.Disable()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/ocsp")))
	g := fe6b0Decode(w)
	rev, _ := g["revision"].(string)
	if rev == "" || g["scope"] != "node-local" {
		t.Fatalf("GET /api/ocsp publishes no revision / scope: %v", g)
	}
	op := fe6b0OpID()
	code, m, w2 := fe6b0Do(mux, http.MethodPost, "/api/ocsp?operationId="+op+"&ocspRevision="+rev, map[string]any{"enabled": true})
	if code != http.StatusOK || m["durable"] != true || m["enabled"] != true {
		t.Fatalf("toggle = %d %s, want durable:true enabled:true", code, w2.Body.String())
	}
	adminSettingsSaveWG.Wait()
	data, err := os.ReadFile(settings)
	if err != nil || !bytes.Contains(data, []byte(`"ocsp_settings_saved": true`)) || !bytes.Contains(data, []byte(`"ocsp_check_enabled": true`)) {
		t.Fatalf("the toggle is not durable: %v %s", err, data)
	}
	if n, ids := fe6b0Audits(since, "ocsp.set"); n != 1 || ids[0] != op {
		t.Fatalf("ocsp.set audits = %d %v, want exactly one keyed on %s", n, ids, op)
	}
	// Restart: the desired state wins over the runtime default.
	globalOCSP.Disable()
	LoadAdminSettings(settings)
	adminSettingsSaveWG.Wait()
	if !globalOCSP.Enabled() {
		t.Fatal("the durable desired state was not restored at boot")
	}
	w3 := httptest.NewRecorder()
	mux.ServeHTTP(w3, viewerCtx(getReq("/api/ocsp")))
	g3 := fe6b0Decode(w3)
	des, _ := g3["desired"].(map[string]any)
	rt, _ := g3["runtime"].(map[string]any)
	if des["enabled"] != true || des["source"] != "admin" || rt["enabled"] != true || g3["durable"] != true {
		t.Fatalf("truthful durable vs runtime state missing: %v", g3)
	}
	// Persist failure: the settings path is unwritable ⇒ refused, runtime unchanged.
	rev3, _ := g3["revision"].(string)
	restore := fe6a4cMakeUnreadable(t, settings)
	code, m, _ = fe6b0Do(mux, http.MethodPost, "/api/ocsp?operationId="+fe6b0OpID()+"&ocspRevision="+rev3, map[string]any{"enabled": false})
	restore()
	if code != http.StatusInternalServerError || m["code"] != refusalPersistFailed {
		t.Fatalf("toggle with an unwritable settings file = %d %v, want 500 persist_failed", code, m)
	}
	if !globalOCSP.Enabled() {
		t.Fatal("a failed persist changed the runtime")
	}
	// Stale fence after the change.
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ocsp?operationId="+fe6b0OpID()+"&ocspRevision="+rev, map[string]any{"enabled": false}); code != http.StatusConflict || m["code"] != refusalStale {
		t.Fatalf("stale OCSP fence = %d %v", code, m)
	}
}

// ── R12 OCSP viewer response ────────────────────────────────────────────────

func TestFE6B0_R12_OCSPViewerResponseCarriesNoPathAndNoRawError(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	loadMTLSClientCert(mtlsOCSPStartupConfig{ClientCertFile: filepath.Join(dir, "missing.crt"), ClientKeyFile: filepath.Join(dir, "missing.key")})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/ocsp")))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/ocsp = %d", w.Code)
	}
	m := fe6b0Decode(w)
	if strings.Contains(w.Body.String(), dir) {
		t.Fatalf("viewer response carries a filesystem path: %s", w.Body.String())
	}
	if m["mtlsClientCertFile"] != nil || m["mtlsClientCertLastError"] != nil {
		t.Fatalf("viewer response carries the path / raw error fields: %v", m)
	}
	if m["mtlsClientCertConfigured"] != true || m["mtlsClientCertLoaded"] != false {
		t.Fatalf("configured-but-failed must stay distinguishable: %v", m)
	}
	reason, _ := m["mtlsClientCertReason"].(string)
	switch reason {
	case "load_failed", "cert_file_missing", "key_file_missing":
	default:
		t.Fatalf("mtlsClientCertReason must be a bounded class, got %q (%v)", reason, m)
	}
	// One-sided config: a bounded class, never the field name of a file.
	loadMTLSClientCert(mtlsOCSPStartupConfig{ClientCertFile: filepath.Join(dir, "only.crt")})
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, viewerCtx(getReq("/api/ocsp")))
	if m2 := fe6b0Decode(w2); m2["mtlsClientCertReason"] != "key_file_missing" || strings.Contains(w2.Body.String(), dir) {
		t.Fatalf("one-sided config = %v", m2)
	}
}

// ── R13 durable exactly-once audit ──────────────────────────────────────────

func TestFE6B0_R13_AuditIsExactlyOnceAcrossAnAppendFailure(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	restoreSink := audit.SetPersistForTest(&bytes.Buffer{}) // unsyncable: AppendOperation refuses
	op := fe6b0OpID()
	rev := fe6b0Revision(t)
	ch, _ := fe6b0Challenge(t, mux, op, rev)
	code, m, w := fe6b0Rotate(mux, op, rev, ch)
	restoreSink()
	if code != http.StatusOK || m["rotated"] != true {
		t.Fatalf("rotate = %d %s", code, w.Body.String())
	}
	if m["auditState"] != "pending" {
		t.Fatalf("an unappendable audit must be reported pending, got %v", m)
	}
	if n, ids := fe6b0Audits(since, "ca.rotate"); n != 0 {
		t.Fatalf("an unkeyed/best-effort audit was emitted while the boundary refused: %d %v", n, ids)
	}
	// The sink is healthy again: the lookup completes the audit exactly once.
	for i := 0; i < 3; i++ {
		if code, l := fe6b0Lookup(mux, op); code != http.StatusOK || l["state"] != "committed" {
			t.Fatalf("lookup = %d %v", code, l)
		}
	}
	n, ids := fe6b0Audits(since, "ca.rotate")
	if n != 1 || ids[0] != op {
		t.Fatalf("audits = %d %v, want exactly one keyed on %s", n, ids, op)
	}
	if code, l := fe6b0Lookup(mux, op); code != http.StatusOK || l["audited"] != true {
		t.Fatalf("audited marker not durable: %d %v", code, l)
	}
}

// ── R14 corrupt ledger ──────────────────────────────────────────────────────

func TestFE6B0_R14_CorruptLedgerFailsClosedWithEvidencePreserved(t *testing.T) {
	dir := fe6b0Node(t)
	ledger := filepath.Join(dir, fe6b0LedgerFile)
	garbage := []byte("{not json")
	if err := os.WriteFile(ledger, garbage, 0o600); err != nil {
		t.Fatal(err)
	}
	if reopenCertificateOperationsForTest == nil {
		t.Fatal("no ledger restart seam (correction absent)")
	}
	reopenCertificateOperationsForTest()
	mux := fe6b0Mux()
	fp, rev, bundle, since := fe6b0Fingerprint(), fe6b0Revision(t), fe6b0Bundle(t), fe6aSince()
	op := fe6b0OpID()
	code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ca/rotate/challenge?operationId="+op+"&caRevision="+rev, nil)
	if code != http.StatusServiceUnavailable || m["code"] != refusalOperationLedgerDegraded {
		t.Fatalf("challenge on a corrupt ledger = %d %v, want 503 operation_ledger_degraded", code, m)
	}
	certC, keyC, _ := fe6b0CAPair(t, "C", true)
	if code, m, _ := fe6b0Upload(t, mux, "?target=mitm&operationId="+op+"&caRevision="+rev, map[string]string{"target": "mitm", "cert": string(certC), "key": string(keyC)}); code != http.StatusServiceUnavailable || m["code"] != refusalOperationLedgerDegraded {
		t.Fatalf("import on a corrupt ledger = %d %v", code, m)
	}
	fe6b0AssertUnchanged(t, fp, rev, bundle, since)
	if now, _ := os.ReadFile(ledger); !bytes.Equal(now, garbage) {
		t.Fatal("the corrupt ledger was replaced (evidence destroyed)")
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/certificates")))
	c := fe6b0Decode(w)
	ops, _ := c["operations"].(map[string]any)
	if ops["degraded"] != true {
		t.Fatalf("the read model must report the degraded ledger: %v", c)
	}
}

// ── R15 backup / restore / rollback ────────────────────────────────────────

func TestFE6B0_R15_BackupRestoreAndRollbackImplications(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	names := map[string]bool{}
	for _, a := range defaultBackupArtifacts(dir) {
		names[a.TarPath] = true
	}
	if !names["data/ca.bundle"] {
		t.Fatal("the CA bundle is not in the backup manifest")
	}
	for _, n := range []string{"data/" + customUITLSKeyFile, "data/" + fe6b0LedgerFile} {
		if names[n] {
			t.Fatalf("%s must not be archived (node-local / write-only)", n)
		}
	}
	// The read model states what a restore brings back: the CA (present), no
	// custom UI cert (absent — never archived), node-local scope.
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/certificates")))
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/certificates = %d %s", w.Code, w.Body.String())
	}
	c := fe6b0Decode(w)
	caM, _ := c["ca"].(map[string]any)
	ui, _ := c["uiCert"].(map[string]any)
	if caM["present"] != true || caM["revision"] == nil || ui["present"] != false || c["scope"] != "node-local" {
		t.Fatalf("certificate read model = %v", c)
	}
	// Rollback: CA rotation, certificate import and the OCSP toggle stay OFF the
	// config-version rollback surface (forward-only trust decisions).
	for _, row := range configSurfaces {
		if row.Rollback && (strings.Contains(strings.ToLower(row.ID), "ocsp") || strings.Contains(strings.ToLower(row.ID), "ca_")) {
			t.Fatalf("surface %s must not be on the rollback surface", row.ID)
		}
	}
	found := false
	for _, row := range configSurfaces {
		if row.ID == "ocsp_settings_saved" && row.AdminDurable && !row.Rollback {
			found = true
		}
	}
	if !found {
		t.Fatal("the OCSP desired state has no AdminDurable-only configSurfaces row")
	}
}

// ── R16 node-local vs cluster ───────────────────────────────────────────────

func TestFE6B0_R16_NodeLocalVersusClusterPublicationFacts(t *testing.T) {
	fe6b0Node(t)
	mux := fe6b0Mux()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/certificates")))
	c := fe6b0Decode(w)
	if c["scope"] != "node-local" {
		t.Fatalf("scope = %v, want node-local", c["scope"])
	}
	// The CP→DP snapshot carries no inspection-CA, UI-cert or OCSP material.
	b, _ := json.Marshal(ConfigSnapshot{})
	lower := strings.ToLower(string(b))
	for _, f := range []string{"ca_bundle", "inspection_ca", "mitm", "ui_cert", "ocsp", "private"} {
		if strings.Contains(lower, f) {
			t.Fatalf("ConfigSnapshot carries %q — the surface is node-local", f)
		}
	}
	rev := fe6b0Revision(t)
	fe6b0RotateOK(t, mux, fe6b0OpID())
	w2 := httptest.NewRecorder()
	mux.ServeHTTP(w2, viewerCtx(getReq("/api/certificates")))
	c2 := fe6b0Decode(w2)
	caM, _ := c2["ca"].(map[string]any)
	if caM["revision"] == rev {
		t.Fatal("the read model revision did not move with the rotation")
	}
}

// ── R17 legacy console ──────────────────────────────────────────────────────

func TestFE6B0_R17_LegacyConsoleSpeaksTheCorrectedContract(t *testing.T) {
	src, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Skip("legacy console not present")
	}
	s := string(src)
	for _, stale := range []string{"confirmation_token", "mtlsClientCertFile", "mtlsClientCertLastError", "rotationPersistError", "loadFailureReason", "loadRecoveryError", "ca.unusableReason"} {
		if strings.Contains(s, stale) {
			t.Errorf("legacy console still uses the retired field/flow %q", stale)
		}
	}
	for _, want := range []string{"/api/ca/rotate/challenge", "crypto.randomUUID", "caRevision", "ocspRevision", "mtlsClientCertReason"} {
		if !strings.Contains(s, want) {
			t.Errorf("legacy console does not use %q", want)
		}
	}
}

// ── R18 controls ────────────────────────────────────────────────────────────

func TestFE6B0_R18_ControlsValidOperationsSucceed(t *testing.T) {
	dir := fe6b0Node(t)
	mux := fe6b0Mux()
	since := fe6aSince()
	// rotation
	op := fe6b0OpID()
	before := fe6b0Fingerprint()
	newRev, m := fe6b0RotateOK(t, mux, op)
	caM, _ := m["ca"].(map[string]any)
	prev, _ := m["previous"].(map[string]any)
	if m["persisted"] != true || caM["revision"] != newRev || prev["fingerprint"] != before || m["operationId"] != op {
		t.Fatalf("rotate result = %v", m)
	}
	if n, ids := fe6b0Audits(since, "ca.rotate"); n != 1 || ids[0] != op {
		t.Fatalf("rotate audits = %d %v", n, ids)
	}
	// import (dry run first: the T2 facts, nothing written)
	certC, keyC, fpC := fe6b0CAPair(t, "Corp Issuing CA", true)
	code, d, w := fe6b0Upload(t, mux, "?target=mitm&dryRun=1", map[string]string{"target": "mitm", "cert": string(certC), "key": string(keyC)})
	if code != http.StatusOK || d["dryRun"] != true {
		t.Fatalf("dry run = %d %s", code, w.Body.String())
	}
	cand, _ := d["candidate"].(map[string]any)
	if got, _ := cand["fingerprint"].(string); strings.ReplaceAll(strings.ToLower(got), ":", "") != fpC || cand["subject"] != "Corp Issuing CA" || cand["isCA"] != true || cand["keyAlgorithm"] == nil || cand["notAfter"] == nil {
		t.Fatalf("dry-run candidate facts = %v", cand)
	}
	if got := fe6b0Fingerprint(); strings.ReplaceAll(strings.ToLower(got), ":", "") == fpC {
		t.Fatal("dry run mutated")
	}
	iop := fe6b0OpID()
	code, m, w = fe6b0Upload(t, mux, "?target=mitm&operationId="+iop+"&caRevision="+newRev, map[string]string{"target": "mitm", "cert": string(certC), "key": string(keyC)})
	if code != http.StatusOK || m["imported"] != true || m["persisted"] != true {
		t.Fatalf("import = %d %s", code, w.Body.String())
	}
	if got := fe6b0Fingerprint(); strings.ReplaceAll(strings.ToLower(got), ":", "") != fpC {
		t.Fatalf("imported CA not live: %s", got)
	}
	if n, ids := fe6b0Audits(since, "ca.import"); n != 1 || ids[0] != iop {
		t.Fatalf("import audits = %d %v", n, ids)
	}
	// UI cert replace + delete
	leaf, key, _ := fe6b0CAPair(t, "ui", false)
	uop := fe6b0OpID()
	code, m, w = fe6b0Upload(t, mux, "?target=ui&operationId="+uop+"&uiCertRevision=uic1:none", map[string]string{"target": "ui", "cert": string(leaf), "key": string(key)})
	if code != http.StatusOK || m["replaced"] != true || m["activation"] != "restart_required" {
		t.Fatalf("ui replace = %d %s", code, w.Body.String())
	}
	uc, _ := m["uiCert"].(map[string]any)
	urev, _ := uc["revision"].(string)
	if !customUITLSFilesPresent() {
		t.Fatal("ui files not persisted")
	}
	dop := fe6b0OpID()
	code, m, w = fe6b0Do(mux, http.MethodDelete, "/api/certs/ui?operationId="+dop+"&uiCertRevision="+urev, nil)
	if code != http.StatusOK || m["deleted"] != true {
		t.Fatalf("ui delete = %d %s", code, w.Body.String())
	}
	if customUITLSFilesPresent() {
		t.Fatal("ui files still present after the delete")
	}
	if _, err := os.Stat(filepath.Join(dir, customUITLSKeyFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("the private key file survived the delete")
	}
	if n, ids := fe6b0Audits(since, "cert.ui.delete"); n != 1 || ids[0] != dop {
		t.Fatalf("delete audits = %d %v", n, ids)
	}
	// cache clear + reads stay typed
	if code, m, _ := fe6b0Do(mux, http.MethodPost, "/api/ca/cache-clear", nil); code != http.StatusOK || m["ok"] != true {
		t.Fatalf("cache-clear = %d %v", code, m)
	}
	if code, m, _ := fe6b0Do(mux, http.MethodPut, "/api/ca/cache-clear", nil); code != http.StatusMethodNotAllowed || m["code"] != refusalMethodNotAllowed {
		t.Fatalf("method refusal must be typed JSON: %d %v", code, m)
	}
	w = httptest.NewRecorder()
	r := getReq("/api/ca-cert")
	r.Header.Set("Accept", "application/json")
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK || fe6b0Decode(w)["fingerprint"] == nil {
		t.Fatalf("ca-cert JSON = %d %s", w.Code, w.Body.String())
	}
}
