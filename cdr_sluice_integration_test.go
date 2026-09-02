package main

// cdr_sluice_integration_test.go — REAL Sluice integration for the 2E-C
// trust-lifecycle contract. The daemon is built from the PINNED module in
// go.mod (github.com/KidCarmi/Sluice/cmd/sluice) and run as a subprocess
// with real mTLS, a real client ledger and a real restart, so the proofs
// below hold against the exact version the appliance ships with — not
// against a fake:
//
//   - Enroll binds the operation id; EnrollStatus resolves it; a lost
//     enrollment is recoverable (NOT_ISSUED vs ISSUED + fingerprint)
//   - RenewCert names the issued fingerprint and binds its operation id;
//     a duplicate renewal is ALREADY_EXISTS with the same fingerprint
//   - RevokeClient outcomes: REVOKED, ALREADY_REVOKED, TOMBSTONED (an
//     unknown fingerprint becomes a durable deny); the revoked credential
//     is refused; the deny SURVIVES a daemon restart
//   - the appliance's own handlers drive the same daemon end to end
//     (enroll → renew → revoke by name with proof)
//
// Skipped under -short (the daemon build is a real compile).

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/KidCarmi/Sluice/pkg/sluiceauth"
	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	sluiceBinOnce sync.Once
	sluiceBinPath string
	sluiceBinErr  error
)

// buildPinnedSluice compiles the pinned Sluice daemon once per test binary.
func buildPinnedSluice(t *testing.T) string {
	t.Helper()
	sluiceBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "culvert-sluice-bin-")
		if err != nil {
			sluiceBinErr = err
			return
		}
		sluiceBinPath = filepath.Join(dir, "sluice")
		cmd := exec.Command("go", "build", "-o", sluiceBinPath, "github.com/KidCarmi/Sluice/cmd/sluice")
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			sluiceBinErr = fmt.Errorf("build pinned sluice: %v\n%s", err, out)
		}
	})
	if sluiceBinErr != nil {
		t.Fatalf("%v", sluiceBinErr)
	}
	return sluiceBinPath
}

// sluiceDaemon is one running pinned Sluice process.
type sluiceDaemon struct {
	t        *testing.T
	bin      string
	dataDir  string
	cfgPath  string
	addr     string
	cmd      *exec.Cmd
	serverFP string
	token    string
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	return addr
}

// startSluiceDaemon boots a daemon on a fresh data dir. Every boot with no
// token file mints ONE first-boot enrollment token (tokens are in-memory
// per process — the documented v0.2/v0.3 behaviour).
func startSluiceDaemon(t *testing.T) *sluiceDaemon {
	t.Helper()
	if testing.Short() {
		t.Skip("real Sluice integration skipped under -short")
	}
	// The CLI unix socket path must fit sockaddr_un (108 bytes).
	root, err := os.MkdirTemp("/tmp", "cvsl-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	d := &sluiceDaemon{t: t, bin: buildPinnedSluice(t), dataDir: root, addr: freeTCPPort(t)}
	d.cfgPath = filepath.Join(root, "config.yaml")
	cfg := fmt.Sprintf(`server:
  grpc_addr: %q
  http_addr: "127.0.0.1:0"
  tls:
    cert_file: %q
    key_file: %q
    ca_file: %q
enrollment:
  enabled: true
  token_file: %q
cli:
  socket_path: %q
logging:
  format: json
  level: warn
`, d.addr, filepath.Join(root, "server.pem"), filepath.Join(root, "server-key.pem"), filepath.Join(root, "ca.pem"),
		filepath.Join(root, "enrollment_token"), filepath.Join(root, "s.sock"))
	if err := os.WriteFile(d.cfgPath, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	d.boot()
	return d
}

func (d *sluiceDaemon) boot() {
	d.t.Helper()
	_ = os.Remove(filepath.Join(d.dataDir, "enrollment_token"))
	cmd := exec.Command(d.bin, "-config", d.cfgPath)
	logPath := filepath.Join(d.dataDir, "sluice.log")
	logf, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		d.t.Fatal(err)
	}
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		d.t.Fatalf("start sluice: %v", err)
	}
	d.cmd = cmd
	d.t.Cleanup(func() { d.stop() })
	deadline := time.Now().Add(60 * time.Second)
	for {
		if time.Now().After(deadline) {
			logs, _ := os.ReadFile(logPath)
			d.t.Fatalf("sluice did not come up on %s:\n%s", d.addr, logs)
		}
		tok, terr := os.ReadFile(filepath.Join(d.dataDir, "enrollment_token"))
		conn, cerr := net.DialTimeout("tcp", d.addr, 500*time.Millisecond)
		if cerr == nil {
			_ = conn.Close()
		}
		if terr == nil && cerr == nil && len(tok) > 0 {
			d.token = strings.TrimSpace(string(tok))
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	pemBytes, err := os.ReadFile(filepath.Join(d.dataDir, "server.pem"))
	if err != nil {
		d.t.Fatal(err)
	}
	fp, err := sluiceauth.Fingerprint(pemBytes)
	if err != nil {
		d.t.Fatal(err)
	}
	d.serverFP = strings.TrimPrefix(fp, "sha256:")
}

func (d *sluiceDaemon) stop() {
	if d.cmd == nil || d.cmd.Process == nil {
		return
	}
	_ = d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _ = d.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		_ = d.cmd.Process.Kill()
		<-done
	}
	d.cmd = nil
}

// restart stops the daemon and boots it again on the same data dir + port
// (a fresh first-boot token is minted because the token file is removed).
func (d *sluiceDaemon) restart() {
	d.t.Helper()
	d.stop()
	d.boot()
}

func (d *sluiceDaemon) client(t *testing.T, resp *pb.EnrollResponse, clientCert, clientKey []byte) *CDRClient {
	t.Helper()
	c, err := NewCDRClient(CDRClientConfig{
		Endpoint: d.addr, ServerFingerprintHx: d.serverFP,
		CACertPEM: resp.CaCert, ClientCertPEM: clientCert, ClientKeyPEM: clientKey,
		Timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSluiceIntegration_TrustLifecycleContract(t *testing.T) {
	d := startSluiceDaemon(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Enrollment binds the operation id; EnrollStatus resolves it.
	const enrollOp = "it-enroll-0123456789abcdef01"
	if st, err := EnrollStatus(ctx, d.addr, d.serverFP, enrollOp); err != nil || st.Outcome != pb.EnrollOutcome_ENROLL_NOT_ISSUED {
		t.Fatalf("pre-enroll status = (%+v, %v), want NOT_ISSUED", st, err)
	}
	resp, err := Enroll(ctx, d.addr, d.serverFP, d.token, enrollOp)
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	fpA, err := sluiceauth.Fingerprint(resp.ClientCert)
	if err != nil {
		t.Fatal(err)
	}
	if resp.ClientCertFingerprint != fpA || resp.OperationId != enrollOp {
		t.Fatalf("enroll response identity: %s / %s (want %s / %s)", resp.ClientCertFingerprint, resp.OperationId, fpA, enrollOp)
	}
	st, err := EnrollStatus(ctx, d.addr, d.serverFP, enrollOp)
	if err != nil || st.Outcome != pb.EnrollOutcome_ENROLL_ISSUED || st.ClientCertFingerprint != fpA || st.Revoked {
		t.Fatalf("post-enroll status = (%+v, %v)", st, err)
	}
	// A repeated dispatch of the SAME operation is refused (the token is
	// consumed anyway, so this proves the at-most-once refusal path the
	// appliance maps to 409 + issued_not_stored).
	if _, err := Enroll(ctx, d.addr, d.serverFP, "some-other-token", enrollOp); !cdrEnrollAlreadyIssued(err) {
		t.Fatalf("duplicate operation: %v, want AlreadyExists", err)
	}

	clientA := d.client(t, resp, resp.ClientCert, resp.ClientKey)
	if h, err := clientA.Health(ctx); err != nil || !h.Healthy {
		t.Fatalf("Health with the enrolled cert: (%+v, %v)", h, err)
	}

	// Renewal names the issued fingerprint + binds its operation id.
	const renewOp = "it-renew-0123456789abcdef012"
	rr, err := clientA.RenewCert(ctx, &pb.RenewCertRequest{OperationId: renewOp})
	if err != nil {
		t.Fatalf("RenewCert: %v", err)
	}
	fpB, _ := sluiceauth.Fingerprint(rr.ClientCert)
	if rr.ClientCertFingerprint != fpB || rr.OperationId != renewOp {
		t.Fatalf("renew response identity: %s / %s", rr.ClientCertFingerprint, rr.OperationId)
	}
	if _, err := clientA.RenewCert(ctx, &pb.RenewCertRequest{OperationId: renewOp}); status.Code(err) != codes.AlreadyExists || !strings.Contains(err.Error(), fpB) {
		t.Fatalf("duplicate renewal: %v", err)
	}
	if st, err := clientA.EnrollStatus(ctx, renewOp); err != nil || st.Outcome != pb.EnrollOutcome_ENROLL_ISSUED || st.ClientCertFingerprint != fpB {
		t.Fatalf("renewal status = (%+v, %v)", st, err)
	}
	clientB := d.client(t, resp, rr.ClientCert, rr.ClientKey)
	if _, err := clientB.Health(ctx); err != nil {
		t.Fatalf("Health with the renewed cert: %v", err)
	}

	// Revocation outcomes are explicit and proven; the predecessor (A) is
	// revoked FROM the successor (B) — target ≠ presenting cert.
	rv, err := clientB.RevokeClient(ctx, &pb.RevokeClientRequest{Fingerprint: fpA, Reason: "it"})
	if err != nil || rv.Outcome != pb.RevokeOutcome_REVOKE_OUTCOME_REVOKED || !rv.Revoked {
		t.Fatalf("revoke A: (%+v, %v)", rv, err)
	}
	if outcome, ok := cdrRevocationProven(rv); !ok || outcome != "revoked" {
		t.Fatalf("appliance proof reading: %s %v", outcome, ok)
	}
	rv, err = clientB.RevokeClient(ctx, &pb.RevokeClientRequest{Fingerprint: fpA})
	if err != nil || rv.Outcome != pb.RevokeOutcome_REVOKE_OUTCOME_ALREADY_REVOKED || rv.Revoked {
		t.Fatalf("revoke A again: (%+v, %v)", rv, err)
	}
	unknown := "sha256:" + strings.Repeat("77", 32)
	rv, err = clientB.RevokeClient(ctx, &pb.RevokeClientRequest{Fingerprint: unknown})
	if err != nil || rv.Outcome != pb.RevokeOutcome_REVOKE_OUTCOME_TOMBSTONED || rv.Revoked {
		t.Fatalf("revoke unknown: (%+v, %v)", rv, err)
	}
	if _, err := clientA.Health(ctx); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("revoked cert still accepted: %v", err)
	}
	if st, _ := EnrollStatus(ctx, d.addr, d.serverFP, enrollOp); st == nil || !st.Revoked {
		t.Fatalf("enroll status must report the revocation: %+v", st)
	}

	// Restart: the deny, the tombstone and the operation bindings persist.
	d.restart()
	ctx2, cancel2 := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel2()
	clientA2 := d.client(t, resp, resp.ClientCert, resp.ClientKey)
	if _, err := clientA2.Health(ctx2); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("after restart the revoked cert is accepted again: %v", err)
	}
	clientB2 := d.client(t, resp, rr.ClientCert, rr.ClientKey)
	if _, err := clientB2.Health(ctx2); err != nil {
		t.Fatalf("after restart the live cert is refused: %v", err)
	}
	if rv, err := clientB2.RevokeClient(ctx2, &pb.RevokeClientRequest{Fingerprint: unknown}); err != nil || rv.Outcome != pb.RevokeOutcome_REVOKE_OUTCOME_ALREADY_REVOKED {
		t.Fatalf("tombstone did not survive the restart: (%+v, %v)", rv, err)
	}
	if st, err := EnrollStatus(ctx2, d.addr, d.serverFP, renewOp); err != nil || st.Outcome != pb.EnrollOutcome_ENROLL_ISSUED || st.ClientCertFingerprint != fpB {
		t.Fatalf("renewal binding did not survive the restart: (%+v, %v)", st, err)
	}
}

// The appliance's own handlers against the real daemon: two enrollments
// (one per daemon boot — tokens are per-process), a renewal through the
// production renewal transaction, then a revoke-by-name that must cover
// the whole lineage with proof from the OTHER instance.
func TestSluiceIntegration_ApplianceHandlersEndToEnd(t *testing.T) {
	resetCDRState(t)
	redirectSentinelToTempDir(t)
	if err := cdrInstances.Load(filepath.Join(t.TempDir(), "cdr_instances.json")); err != nil {
		t.Fatal(err)
	}
	if err := cdrEnrollReceipts.Load(filepath.Join(t.TempDir(), "receipts.json")); err != nil {
		t.Fatal(err)
	}
	if _, err := cdrInstanceCertsDir("it-check"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cdrCertsRoot, 0o700); err != nil {
		t.Skipf("cannot write %s (test env restricted): %v", cdrCertsRoot, err)
	}
	d := startSluiceDaemon(t)

	enroll := func(name, token string) CDREnrolledInstance {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"name": name, "endpoint": d.addr, "serverFingerprint": d.serverFP, "token": token})
		w := httptest.NewRecorder()
		apiCDREnroll(w, newAdminRequest(http.MethodPost, "/api/cdr/instances/enroll", body))
		if w.Code != http.StatusOK {
			t.Fatalf("enroll %s: %d %s", name, w.Code, w.Body.String())
		}
		inst, ok := cdrInstances.GetCopy(name)
		if !ok {
			t.Fatal("enrolled instance missing")
		}
		t.Cleanup(func() { shredCDRCerts(&inst) })
		return inst
	}
	const nameA, nameB = "it-appliance-a", "it-appliance-b"
	instA := enroll(nameA, d.token)
	if len(instA.Credentials) != 1 || instA.Credentials[0].State != cdrCredActive || instA.Credentials[0].OperationID == "" {
		t.Fatalf("lineage after enroll: %+v", instA.Credentials)
	}
	rc, ok := cdrEnrollReceipts.Get(instA.Credentials[0].OperationID)
	if !ok || rc.State != cdrReceiptStored || rc.Fingerprint != instA.ClientCertFingerprint {
		t.Fatalf("receipt after enroll: %+v", rc)
	}
	d.restart() // second first-boot token
	enroll(nameB, d.token)

	// The pool now dials both with real mTLS.
	if err := initCDRClient(CDRConfig{Enabled: true, TimeoutSec: 10}); err != nil {
		t.Fatalf("init pool: %v", err)
	}
	pcA := cdrPool.Get(nameA)
	if pcA == nil {
		t.Fatal("instance A not pooled")
	}
	oldFP := instA.ClientCertFingerprint
	runRenewFor(pcA, instA)
	cur, _ := cdrInstances.GetCopy(nameA)
	live := cur.LiveFingerprints(time.Now())
	if len(live) != 2 || live[1] != oldFP || cur.ClientCertFingerprint == oldFP {
		t.Fatalf("lineage after real renewal: live=%v dial=%s", live, cur.ClientCertFingerprint)
	}
	newFP := cur.ClientCertFingerprint

	// Revoke A by name: BOTH generations, proven by the daemon, issued
	// from B; then A's credentials are refused and A is pruned.
	w := tlRevokeByName(t, nameA, "integration")
	if w.Code != http.StatusOK {
		t.Fatalf("revoke: %d %s", w.Code, w.Body.String())
	}
	var got struct {
		Fingerprints []string          `json:"fingerprints"`
		Outcomes     map[string]string `json:"outcomes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if len(got.Fingerprints) != 2 || got.Outcomes[oldFP] != "revoked" || got.Outcomes[newFP] != "revoked" {
		t.Fatalf("revoke result: %s", w.Body.String())
	}
	if cdrInstances.Get(nameA) != nil {
		t.Error("A not pruned after proven revocation")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	pcB := cdrPool.Get(nameB)
	if pcB == nil {
		t.Fatal("instance B not pooled after reinit")
	}
	for _, fp := range []string{oldFP, newFP} {
		rv, err := pcB.Client.RevokeClient(ctx, &pb.RevokeClientRequest{Fingerprint: fp})
		if err != nil || rv.Outcome != pb.RevokeOutcome_REVOKE_OUTCOME_ALREADY_REVOKED {
			t.Fatalf("daemon truth for %s: (%+v, %v)", fp, rv, err)
		}
	}
}
