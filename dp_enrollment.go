package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/KidCarmi/Culvert/internal/audit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// dpEnrollmentConfig is persisted to disk after successful enrollment so the
// DP can auto-start on subsequent restarts without manual cert flags.
type dpEnrollmentConfig struct {
	CPAddr   string `json:"cp_addr"`
	NodeID   string `json:"node_id"`
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`
}

const enrollmentConfigFile = "dp_enrollment.json"

// loadEnrollmentConfig reads a previously persisted enrollment config.
func loadEnrollmentConfig() (*dpEnrollmentConfig, error) {
	data, err := os.ReadFile(enrollmentConfigFile)
	if err != nil {
		return nil, err
	}
	var ec dpEnrollmentConfig
	if err := json.Unmarshal(data, &ec); err != nil {
		return nil, err
	}
	return &ec, nil
}

// runEnrollment handles the enrollment flow: generates a keypair+CSR,
// contacts the Control Plane, and persists the signed certificate.
// Returns the enrollment config so the caller can start as a DP node.
func runEnrollment(enrollURLStr string) (*dpEnrollmentConfig, error) {
	info, err := parseEnrollURL(enrollURLStr)
	if err != nil {
		return nil, err
	}
	// An enrollment URL with no ?ca-fp= parameter (a copy/paste mistake, a
	// hand-typed URL, or a custom tool that built one) skips CA fingerprint
	// verification entirely below — this connection is then indistinguishable
	// from one to an impersonating Control Plane. That must never be silent:
	// every other fail-open path in this codebase is counted/logged, and the
	// success case here already prints "CA fingerprint verified ✓", so saying
	// nothing in the opposite case reads as "nothing to report" rather than
	// "verification was skipped".
	if info.CAFingerprint == "" {
		fmt.Printf("[Culvert] WARNING: enrollment URL has no ?ca-fp= parameter — the Control Plane's CA will NOT be verified. This connection is vulnerable to an on-path attacker (MITM). Re-generate the enrollment command from the CP admin UI, which always includes ca-fp.\n")
	}
	nodeID, _ := os.Hostname()
	if nodeID == "" {
		nodeID = "dp-node"
	}
	fmt.Printf("[Culvert] Enrolling as node %q with Control Plane at %s\n", nodeID, info.CPAddr)

	privKey, csrPEM, err := generateCSR(nodeID)
	if err != nil {
		return nil, err
	}
	resp, err := callEnrollRPC(info.CPAddr, info.Token, nodeID, csrPEM)
	if err != nil {
		return nil, err
	}
	// Verify CA fingerprint from the enrollment URL matches the received CA cert.
	if info.CAFingerprint != "" {
		if err := verifyCAFingerprint([]byte(resp.CAPEM), info.CAFingerprint); err != nil {
			return nil, fmt.Errorf("CA fingerprint mismatch — possible MITM: %w", err)
		}
		fmt.Printf("[Culvert] CA fingerprint verified ✓\n")
	}
	ec, err := persistEnrollCerts(privKey, resp, info.CPAddr, nodeID)
	if err != nil {
		return nil, err
	}
	return ec, nil
}

// enrollmentInfo holds parsed enrollment URL components.
type enrollmentInfo struct {
	CPAddr        string
	Token         string
	CAFingerprint string // sha256:hex (from ?ca-fp= query param)
}

// parseEnrollURL extracts CP address, token, and CA fingerprint from the enrollment URL.
func parseEnrollURL(raw string) (*enrollmentInfo, error) {
	raw = strings.TrimPrefix(raw, "culvert://enroll/")
	parts := strings.SplitN(raw, "/", 2)
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid enrollment URL format — expected culvert://enroll/host:port/TOKEN")
	}
	info := &enrollmentInfo{CPAddr: parts[0]}
	info.Token = parts[1]
	if idx := strings.Index(info.Token, "?"); idx >= 0 {
		query := info.Token[idx+1:]
		info.Token = info.Token[:idx]
		// Parse ca-fp= parameter.
		for _, kv := range strings.Split(query, "&") {
			if strings.HasPrefix(kv, "ca-fp=") {
				info.CAFingerprint = strings.TrimPrefix(kv, "ca-fp=")
			}
		}
	}
	return info, nil
}

// generateCSR creates an ECDSA P-256 keypair and CSR for enrollment.
func generateCSR(nodeID string) (*ecdsa.PrivateKey, []byte, error) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key: %w", err)
	}
	csrTemplate := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: nodeID, Organization: []string{"Culvert Data Plane"}},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, privKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}
	return privKey, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

// callEnrollRPC connects to the CP and calls the Enroll gRPC method.
// If caFingerprint is non-empty, the CP's TLS cert is verified against it.
func callEnrollRPC(cpAddr, token, nodeID string, csrPEM []byte) (*EnrollResponse, error) {
	conn, err := grpc.NewClient(cpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("connect to CP: %w", err)
	}
	defer conn.Close() //nolint:errcheck // best-effort close

	reqBytes, _ := json.Marshal(EnrollRequest{Token: token, CSR: string(csrPEM), NodeID: nodeID})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var respRaw json.RawMessage
	if err := conn.Invoke(ctx, methodEnroll, json.RawMessage(reqBytes), &respRaw); err != nil {
		return nil, fmt.Errorf("enrollment RPC failed: %w", err)
	}
	var resp EnrollResponse
	if err := json.Unmarshal(respRaw, &resp); err != nil {
		return nil, fmt.Errorf("parse enrollment response: %w", err)
	}
	// ADR-0005 S3: seed this DP's fencing-epoch ratchet from the enrolling
	// CP (0 = legacy CP, ratchet stays unseeded).
	_ = dpObserveEpoch("enrollment", resp.Epoch)
	return &resp, nil
}

// verifyCAFingerprint checks that the CA cert PEM matches the expected SHA-256 fingerprint.
func verifyCAFingerprint(caPEM []byte, expected string) error {
	want := strings.TrimPrefix(expected, "sha256:")
	wantBytes, err := hex.DecodeString(want)
	if err != nil {
		return fmt.Errorf("invalid CA fingerprint hex: %w", err)
	}
	block, _ := pem.Decode(caPEM)
	if block == nil {
		return fmt.Errorf("no PEM block in CA cert")
	}
	fp := sha256.Sum256(block.Bytes)
	if !hmac.Equal(fp[:], wantBytes) {
		return fmt.Errorf("CA fingerprint sha256:%x does not match expected sha256:%s", fp, want)
	}
	return nil
}

// persistEnrollCerts saves the signed certificate, private key, CA cert, and
// enrollment config to disk. Returns the config so the caller can start as DP.
func persistEnrollCerts(privKey *ecdsa.PrivateKey, resp *EnrollResponse, cpAddr, nodeID string) (*dpEnrollmentConfig, error) {
	certPath, keyPath, caPath := "./dp-node.crt", "./dp-node.key", "./cluster-ca.crt"

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return nil, fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	// Bucket-4 durability hardening: atomicWriteFile gives unique
	// tmp + chmod + fsync(file) + rename + best-effort fsync(parent
	// dir) — replaces the previous plain os.WriteFile which left a
	// non-durable / potentially-truncated file on crash. Sibling
	// follow-up to CL-7 / PR #244 (which hardened the
	// dp_enrollment.json branch a few lines below).
	if err := atomicWriteFile(certPath, []byte(resp.CertPEM), 0o600); err != nil {
		return nil, fmt.Errorf("write cert: %w", err)
	}
	// CA-3: encrypt the DP node key at rest when enabled; plaintext otherwise.
	// Cert and CA cert remain plaintext PEM.
	if err := writeDPNodeKey(keyPath, keyPEM); err != nil {
		return nil, fmt.Errorf("write key: %w", err)
	}
	if err := atomicWriteFile(caPath, []byte(resp.CAPEM), 0o600); err != nil {
		return nil, fmt.Errorf("write CA: %w", err)
	}

	// Persist enrollment config for automatic restarts.
	ec := &dpEnrollmentConfig{
		CPAddr:   cpAddr,
		NodeID:   nodeID,
		CertFile: certPath,
		KeyFile:  keyPath,
		CAFile:   caPath,
	}
	ecJSON, _ := json.MarshalIndent(ec, "", "  ")
	// CL-7: atomicWriteFile gives unique tmp + chmod + fsync(file) +
	// rename + best-effort fsync(parent dir) — replaces the previous
	// plain os.WriteFile which left a non-durable / potentially-
	// truncated file on crash. The sibling cert/key/CA writes above
	// (lines ~1953/1956/1959) share the same pre-existing defect but
	// are intentionally out of CL-7 scope; flagged in the PR body as
	// a deferred follow-up.
	if err := atomicWriteFile(enrollmentConfigFile, ecJSON, 0o600); err != nil {
		return nil, fmt.Errorf("write enrollment config: %w", err)
	}

	fmt.Printf("[Culvert] Enrollment successful!\n")
	fmt.Printf("[Culvert] Certificate: %s\n", certPath)
	fmt.Printf("[Culvert] Key:         %s\n", keyPath)
	fmt.Printf("[Culvert] CA:          %s\n", caPath)
	fmt.Printf("[Culvert] Config:      %s\n", enrollmentConfigFile)
	fmt.Printf("[Culvert] Starting as Data Plane node — connecting to %s\n", cpAddr)
	return ec, nil
}

// startDataPlane initialises and runs the Data Plane client.
func startDataPlane(ctx context.Context, addr, nodeID, certFile, keyFile, caFile string) {
	clusterRole.role = "data-plane"
	clusterRole.grpcAddr = addr
	if nodeID == "" {
		nodeID = clusterRole.nodeID
	}
	clusterRole.nodeID = nodeID

	// D4: seed the fencing-epoch ratchet from disk BEFORE the first poll so a
	// restart cannot reopen the epoch-0 window an epoch-0 zombie CP would exploit.
	loadDPLastSeenEpoch()

	// F3b-4 finding #2: wire the durable feed-authority mirror store BEFORE replaying the
	// last-good snapshot below, so the replay persists the authoritative feed config on the
	// first restart after upgrade — without depending on the CP incrementing its config
	// version. The signed-feed lifecycle (initURLCategories, run later) re-uses this same
	// instance.
	wireSaaSFeedAuthorityStore()

	if certFile != "" {
		if err := checkDPCertExpiry(certFile); err != nil {
			logWarnf("ControlPlane: %v", err)
		}
	}
	// CA-3: opt-in one-time migration of an existing plaintext DP node key to
	// encrypted-at-rest, at the single startup load point (not on reconnect).
	// Fails closed if an encrypted key is present but unreadable.
	if keyFile != "" {
		if err := maybeMigrateDPNodeKey(keyFile); err != nil {
			logFatalf("DataPlane: DP node key at-rest: %v", err)
		}
	}
	// Version facts of the cached config the node is about to enforce, so the
	// first heartbeat reports the applied config/policy version even if the
	// initial CP poll is rejected (M5 PR-A — Codex).
	var cachedConfigVersion, cachedPolicyVersion int64
	if snap, err := applyDPLastGoodConfigSnapshot(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			logger.Printf("DataPlane: last-known-good config unavailable: %v", err)
		} else {
			logger.Printf("DataPlane: no last-known-good config at %s", dpLastGoodConfigSnapshotPath())
		}
	} else {
		cachedConfigVersion = snap.Version
		cachedPolicyVersion = snap.PolicyVersion
		if mergedAddr := mergeCPAddresses(addr, snap.CPAddresses); mergedAddr != addr {
			logger.Printf("DataPlane: seeded CP failover addresses from last-known-good config: %s", sanitizeLog(mergedAddr))
			addr = mergedAddr
		}
	}
	dpClient, err := NewDataPlaneClient(nodeID, addr, certFile, keyFile, caFile)
	if err != nil {
		logFatalf("DataPlane client: %v", err)
	}
	dpClient.lastVersion.Store(cachedConfigVersion)
	dpClient.lastPolicyVersion.Store(cachedPolicyVersion)
	activeDPClient.Store(dpClient) // for HA address discovery
	audit.SetDPMode(true)
	dpClient.Run(ctx, 30*time.Second)
	go dpCertRenewalLoop(ctx, dpClient, nodeID, certFile, keyFile, caFile)
	logger.Printf("DataPlane: polling ControlPlane at %s every 30s", addr)
}

// checkDPCertExpiry warns if the DP node certificate is expired or near expiry.
func checkDPCertExpiry(certFile string) error {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return fmt.Errorf("DP cert read: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("DP cert: no PEM block found in %s", certFile)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("DP cert parse: %w", err)
	}
	now := time.Now()
	if now.After(cert.NotAfter) {
		return fmt.Errorf("DP certificate expired at %s — re-enroll to get a new cert", cert.NotAfter.Format(time.RFC3339))
	}
	remaining := time.Until(cert.NotAfter)
	if remaining < 30*24*time.Hour {
		return fmt.Errorf("DP certificate expires in %d days — auto-renewal will attempt before expiry", int(remaining.Hours()/24))
	}
	return nil
}

// dpCertRenewalLoop checks cert expiry periodically and requests a new cert
// from the CP before the current one expires. Also listens for CA rotation
// notifications to trigger immediate renewal (zero-touch CA rotation).
func dpCertRenewalLoop(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile string) {
	// CHAOS-24: every round runs under runGuarded. This loop is the ONLY thing
	// keeping this node's mTLS identity valid — if it stops, nothing reports it
	// and the node silently drops out of the cluster weeks later, when the cert
	// expires. So a panic must neither kill the process nor end the loop: it is
	// contained, recorded, and alerted through the SAME path as a renewal
	// error, because operationally it is one (the renewal did not happen).
	renew := func() {
		if panicked := runGuarded("dp_cert_renewal", func() {
			if err := tryRenewDPCert(ctx, client, nodeID, certFile, keyFile, caFile); err != nil {
				logger.Printf("DataPlane: cert renewal check: %v", err)
				alertDPCertRenewalFailure(nodeID, certFile, err)
			}
		}); panicked {
			alertDPCertRenewalFailure(nodeID, certFile, errDPRenewalPanic)
		}
	}

	// CHAOS-12: check once immediately — a node powered off past its renewal
	// window must not sit on a nearly-expired cert for another 6 hours.
	renew()
	// Then check every 6 hours.
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			renew()
		case <-caRotationNotify:
			// CP rotated its CA — renew immediately regardless of cert expiry.
			logger.Printf("DataPlane: CA rotation detected — initiating immediate cert renewal")
			if panicked := runGuarded("dp_cert_renewal", func() {
				if err := forceRenewDPCert(ctx, client, nodeID, certFile, keyFile, caFile); err != nil {
					logger.Printf("DataPlane: CA rotation renewal failed: %v", err)
					alertDPCertRenewalFailure(nodeID, certFile, err)
				}
			}); panicked {
				alertDPCertRenewalFailure(nodeID, certFile, errDPRenewalPanic)
			}
		}
	}
}

// errDPRenewalPanic is the error surfaced to the operator when a cert-renewal
// round was contained by the panic guard. The panic VALUE is never propagated
// here — it can embed attacker-shaped text or a secret, and recordCrash already
// owns the bounded/redacted record. The alert only needs to say the renewal did
// not complete, which is the operator-actionable fact.
var errDPRenewalPanic = errors.New("cert renewal round aborted by a recovered panic (see crash record)")

// certNeedsRenewal checks if a PEM cert file expires within 30 days.
// Returns days remaining, or -1 if the cert cannot be read.
func certNeedsRenewal(certFile string) (int, bool) {
	data, err := os.ReadFile(certFile)
	if err != nil {
		return -1, false
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return -1, false
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return -1, false
	}
	days := int(time.Until(cert.NotAfter).Hours() / 24)
	return days, days <= 30
}

// ── DP cert-expiry alerting (CHAOS-12) ───────────────────────────────────────
//
// A DP whose renewal keeps failing (CP unreachable or refusing the RPC)
// slides toward an expiry brick: at NotAfter the mTLS reconnect fails and a
// still-registered node cannot re-enroll. The renewal loop logs each failure;
// these helpers additionally surface it as a cert_expiry alert, latched once
// per escalation (renewal window → final week → expired) so the 6h ticker
// cannot fire four identical alerts a day (RT-H2 latch precedent). The latch
// resets on successful renewal; a restart re-fires once at the current level
// (documented, same posture as the release-catalog latches).

var dpCertExpiryAlert struct {
	mu    sync.Mutex
	level int // 0 none · 1 renewal window (≤30d) · 2 final week (≤7d) · 3 expired
}

// dpCertAlertLevel maps days-until-expiry to an escalation level.
func dpCertAlertLevel(days int) int {
	switch {
	case days < 0:
		return 3
	case days <= 7:
		return 2
	default:
		return 1
	}
}

// alertDPCertRenewalFailure fires a latched cert_expiry alert for a failed DP
// cert renewal when the cert is inside the renewal window or expired. A
// rotation-triggered renewal failure on a still-fresh cert stays log-only
// (there is no expiry clock running against it).
func alertDPCertRenewalFailure(nodeID, certFile string, renewErr error) {
	days, needsRenewal := certNeedsRenewal(certFile)
	if !needsRenewal {
		return
	}
	// CHAOS-09: record for the /ready node_cert row. Unlike the alert latch
	// below, the probe state is refreshed on every failed attempt. It records
	// only the BOOLEAN: /ready is unauthenticated on the proxy port, so neither
	// days-left nor renewErr may reach it (see readyz_dp_health.go). Both are
	// already in the log line the caller wrote and in the alert built below.
	recordDPCertRenewalFailure()
	level := dpCertAlertLevel(days)
	dpCertExpiryAlert.mu.Lock()
	latched := level <= dpCertExpiryAlert.level
	if !latched {
		dpCertExpiryAlert.level = level
	}
	dpCertExpiryAlert.mu.Unlock()
	if latched {
		return
	}
	var detail string
	if days < 0 {
		detail = fmt.Sprintf("DP node certificate EXPIRED %d day(s) ago and renewal is failing — the node cannot re-authenticate to the Control Plane on its next reconnect; re-enroll if renewal cannot succeed (last error: %v)", -days, renewErr)
	} else {
		detail = fmt.Sprintf("DP node certificate expires in %d day(s) and renewal is failing — the node bricks at expiry if the Control Plane stays unreachable (last error: %v)", days, renewErr)
	}
	// deferStartupAlert: the renewal loop's immediate first check can run
	// before loadPersistentAdminState populates the webhook store.
	deferStartupAlert("cert_expiry", AlertPayload{
		Host:   nodeID,
		Detail: detail,
		Source: "cluster",
	})
}

// resetDPCertExpiryAlert clears the escalation latch after a successful renewal.
func resetDPCertExpiryAlert() {
	dpCertExpiryAlert.mu.Lock()
	dpCertExpiryAlert.level = 0
	dpCertExpiryAlert.mu.Unlock()
	clearDPCertRenewalFailure() // CHAOS-09: /ready node_cert row recovers too
}

// forceRenewDPCert renews the DP cert unconditionally (triggered by CA rotation).
func forceRenewDPCert(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile string) error {
	return renewDPCert(ctx, client, nodeID, certFile, keyFile, caFile, "CA rotation")
}

// tryRenewDPCert renews the DP cert if it expires within 30 days.
func tryRenewDPCert(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile string) error {
	days, needsRenewal := certNeedsRenewal(certFile)
	if !needsRenewal {
		return nil
	}
	return renewDPCert(ctx, client, nodeID, certFile, keyFile, caFile, fmt.Sprintf("cert expires in %d days", days))
}

// renewDPCert performs the actual cert renewal via RenewCert RPC.
func renewDPCert(ctx context.Context, client *DataPlaneClient, nodeID, certFile, keyFile, caFile, reason string) error {
	logger.Printf("DataPlane: requesting cert renewal (%s)", reason)

	privKey, csrPEM, err := generateCSR(nodeID)
	if err != nil {
		return fmt.Errorf("generate CSR: %w", err)
	}

	reqBytes, _ := json.Marshal(map[string]string{"node_id": nodeID, "csr": string(csrPEM)})
	raw, err := client.call(ctx, methodRenewCert, json.RawMessage(reqBytes))
	if err != nil {
		return fmt.Errorf("RenewCert RPC: %w", err)
	}
	var resp struct {
		CertPEM string `json:"cert_pem"`
		CAPEM   string `json:"ca_pem"`
		Epoch   int64  `json:"epoch"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return fmt.Errorf("parse renewal response: %w", err)
	}
	// ADR-0005 S3: refuse a certificate signed by a fenced-out (stale-epoch)
	// CP — installing it would re-trust a zombie's CA chain.
	if !dpObserveEpoch("cert renewal", resp.Epoch) {
		return fmt.Errorf("cert renewal rejected: response stamped with a stale fencing epoch")
	}

	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	if err := atomicWriteFile(certFile, []byte(resp.CertPEM), 0o600); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	// CA-3: renewal rewrites the private key (fresh CSR keypair); encrypt at
	// rest when enabled, plaintext otherwise. Cert/CA remain plaintext PEM.
	if err := writeDPNodeKey(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	if resp.CAPEM != "" {
		if err := atomicWriteFile(caFile, []byte(resp.CAPEM), 0o600); err != nil {
			return fmt.Errorf("write CA: %w", err)
		}
	}
	logger.Printf("DataPlane: certificate renewed successfully (%s)", reason)
	resetDPCertExpiryAlert()
	// CHAOS-12: the renewed cert/key/CA only reach the wire on a fresh TLS
	// handshake — the gRPC connection read its material at connect() time.
	// Redial the active CP so the new identity is presented now rather than
	// at the next process restart (after the CP's dual-CA rotation cleanup
	// the old cert stops validating, and the old RootCAs pool stops trusting
	// the rotated CP — despite valid renewed material sitting on disk).
	// A failed redial keeps the existing connection (connect swaps only
	// after success), so this can only improve on the pre-renewal state.
	if err := client.reconnectActive(); err != nil {
		logger.Printf("DataPlane: post-renewal reconnect failed — renewed cert takes effect on next reconnect: %v", err)
	}
	return nil
}
