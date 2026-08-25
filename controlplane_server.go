package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	_ "google.golang.org/grpc/encoding/gzip" // registers the gzip compressor for the config stream
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ─── Control Plane gRPC server ────────────────────────────────────────────────

type controlPlaneServer struct{}

// verifyNode extracts the peer TLS certificate from the gRPC context,
// matches it to an enrolled node by cert serial, verifies the self-reported
// nodeID matches the certificate identity, and checks revocation status.
// Returns the verified node ID or an error.
func verifyNode(ctx context.Context, claimedNodeID string) error {
	if claimedNodeID == "" {
		return status.Errorf(codes.InvalidArgument, "node_id required")
	}

	// In mTLS mode, verify cert serial matches enrolled node.
	if err := verifyNodeCert(ctx, claimedNodeID); err != nil {
		return err
	}

	// Check revocation regardless of TLS mode.
	node, exists := globalClusterStore.GetNode(claimedNodeID)
	if exists && globalClusterStore.IsRevoked(node.CertSerial) {
		return status.Errorf(codes.PermissionDenied, "node %q is revoked", claimedNodeID)
	}
	return nil
}

// verifyNodeCert extracts the peer TLS cert serial and matches it to the enrolled node.
// Fails closed when no TLS peer certificate is present, unless the
// --cluster-insecure flag has been set explicitly (dev-mode opt-in). The
// previous implicit "no peer info ⇒ skip cert pinning" fall-through was a
// footgun: if the CP's gRPC listener was ever started without TLS by
// mistake, every RPC would auth as any claimed node. (H3 fix.)
func verifyNodeCert(ctx context.Context, claimedNodeID string) error {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		if clusterInsecure {
			return nil // explicit dev-mode opt-in via --cluster-insecure
		}
		return status.Errorf(codes.Unauthenticated, "mTLS required: no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		if clusterInsecure {
			return nil
		}
		return status.Errorf(codes.Unauthenticated, "mTLS required: no peer certificate")
	}
	peerSerial := tlsInfo.State.PeerCertificates[0].SerialNumber.Text(16)
	node, exists := globalClusterStore.GetNode(claimedNodeID)
	if !exists {
		return status.Errorf(codes.NotFound, "node %q not enrolled", claimedNodeID)
	}
	if node.CertSerial != peerSerial {
		return status.Errorf(codes.PermissionDenied,
			"cert serial mismatch: node %q expects %s, peer presented %s",
			claimedNodeID, node.CertSerial, peerSerial)
	}
	return nil
}

func (s *controlPlaneServer) GetConfig(ctx context.Context, req json.RawMessage) (json.RawMessage, error) {
	// P0-3 version-conditional fast path: the DP sends the version it already
	// holds. If it is current, return a tiny "unchanged" sentinel instead of
	// re-marshaling and re-sending the whole (~60 MiB at 2 M hosts) snapshot on
	// every poll — the dominant steady-state CP CPU/egress cost the 10x cap
	// raise amplified. This preserves the DP's existing semantics exactly: the
	// DP already returns before applyConfigSnapshot when snap.Version <=
	// lastVersion, so nothing (incl. CA-rotation detection, which lives in
	// apply) fires on an unchanged version today either. An old DP omits the
	// field (KnownVersion 0) and always gets the full snapshot, and an old CP
	// ignores the request body and always returns full — so this is
	// backward-compatible in both rollout directions.
	// Refuse to distribute an empty config when the initial publish was rejected
	// (nothing valid was ever published) — a fresh DP must not be handed a zero
	// snapshot. The DP treats Unavailable as a poll failure and keeps its
	// last-good; the operator sees the reason and trims the oversized config.
	if ok, reason := globalConfigStore.ServableConfig(); !ok {
		return nil, status.Errorf(codes.Unavailable, "control plane has no valid config to distribute: %s", reason)
	}
	var greq getConfigRequest
	_ = json.Unmarshal(req, &greq) // tolerate empty/"{}"/garbage → KnownVersion 0
	if greq.KnownVersion > 0 && greq.KnownVersion >= globalConfigStore.Version() {
		return json.Marshal(configUnchangedReply{ConfigUnchanged: true, Version: greq.KnownVersion})
	}

	// GetConfig is called during initial poll before enrollment completes, so
	// it must remain reachable without a full node-identity check. However,
	// the snapshot carries secrets (SessionHMAC) that must NOT leak to
	// unenrolled callers. We redact those fields unless the peer's TLS cert
	// serial matches an enrolled, non-revoked node. (C1 fix.)
	fp := globalClusterCA.CACertFingerprint()

	// T2 CP-side marshal cache: on a config change every enrolled DP polls once
	// for the new version and the CP re-marshaled the full (~60 MiB at 2 M hosts)
	// snapshot PER DP. The cache marshals it ONCE per (version, CA-fingerprint)
	// and serves all enrolled pollers from the shared bytes. Only the ENROLLED
	// (full) variant is cached; the rare unenrolled bootstrap path is never
	// cached, so the redacted-response path can never serve a secret-bearing
	// cached blob (defense-in-depth over the redaction below).
	if callerIsEnrolledNode(ctx) {
		return gcMarshalCache.serve(fp)
	}

	// T2 exfil hardening: the config is non-secret but reveals the org's
	// blocklist, policy rules, and threat-intel sources. The design serves it to
	// UNENROLLED callers (the bootstrap contract — C1: redacted, no SessionHMAC),
	// and the cheap version-conditional poll made bulk pulls low-cost. Throttle
	// the unenrolled FULL-snapshot pull per peer IP: a legitimate node pulls the
	// config a handful of times before enrolling, then polls as an enrolled peer;
	// an exfil loop is rate-limited. Enrolled peers (above) are never throttled.
	if ip := peerSourceIP(ctx); ip != "" && !unenrolledConfigPullAllow(ip) {
		return nil, status.Errorf(codes.ResourceExhausted, "unenrolled config-pull rate exceeded; enroll to poll without limit")
	}

	snap := globalConfigStore.Get()
	if fp != "" {
		snap.CAFingerprint = fp
	}
	// Redact secrets from unenrolled callers. We are already in the unenrolled
	// branch (the enrolled case returned above), so this guard is always true
	// here — it is kept as an explicit !callerIsEnrolledNode block as
	// defense-in-depth. The actual field zeroing lives in redactUnenrolledSnapshot
	// (shared with GetConfigDelta) so the redaction-parity test
	// (config_surfaces_test.go: TestConfigSurfaces_SnapshotRedaction) pins ONE
	// place both unenrolled-reachable surfaces route through.
	if !callerIsEnrolledNode(ctx) {
		redactUnenrolledSnapshot(&snap)
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

// redactUnenrolledSnapshot zeroes every Sensitive ConfigSnapshot field before the
// snapshot is served to an UNENROLLED caller. It is the single source of truth for
// unenrolled redaction, shared by GetConfig and GetConfigDelta so the redaction-
// parity test (config_surfaces_test.go: TestConfigSurfaces_SnapshotRedaction) pins
// one place and every unenrolled-reachable surface stays covered. When a new
// Sensitive synced field is added, zero it HERE and both surfaces are protected.
func redactUnenrolledSnapshot(snap *ConfigSnapshot) {
	snap.SessionHMAC = ""
	snap.IdPProfiles = nil
}

// peerSourceIP returns the client IP of the gRPC peer, or "" when unavailable.
func peerSourceIP(ctx context.Context) string {
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil {
		return host
	}
	return ""
}

// unenrolledConfigPull throttles unenrolled full-snapshot pulls per peer IP.
var unenrolledConfigPull = struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
}{attempts: map[string][]time.Time{}}

// unenrolledConfigPullAllow reports whether ip may pull the full unenrolled
// config now, sliding-window rate-limited. Generous enough for a bootstrapping
// node's retries, tight enough to make bulk exfiltration slow.
func unenrolledConfigPullAllow(ip string) bool {
	const (
		maxPulls = 10
		window   = time.Minute
	)
	unenrolledConfigPull.mu.Lock()
	defer unenrolledConfigPull.mu.Unlock()
	now := time.Now()
	recent := unenrolledConfigPull.attempts[ip][:0]
	for _, t := range unenrolledConfigPull.attempts[ip] {
		if now.Sub(t) < window {
			recent = append(recent, t)
		}
	}
	unenrolledConfigPull.attempts[ip] = recent
	if len(recent) >= maxPulls {
		return false
	}
	unenrolledConfigPull.attempts[ip] = append(unenrolledConfigPull.attempts[ip], now)
	return true
}

// gcMarshalCache caches the marshaled FULL (enrolled) config snapshot keyed on
// (version, CA-fingerprint) so N enrolled DPs polling the same config change
// share ONE marshal instead of forcing N. It never holds a redacted variant, so
// it cannot leak a secret-bearing blob to an unenrolled caller.
var gcMarshalCache configMarshalCache

type configMarshalCache struct {
	mu      sync.Mutex
	version int64
	caFP    string
	bytes   json.RawMessage
}

// serve returns the marshaled full snapshot for the current published version
// and CA fingerprint, marshaling (and caching) exactly once per change. The
// marshal runs under the lock so concurrent first-pollers on a fresh version
// produce ONE marshal (bounding transient memory to a single copy) rather than
// N; subsequent pollers return the cached bytes. Lock order is cache→store
// (Get takes the store RLock); nothing takes the store lock then this one.
func (c *configMarshalCache) serve(fp string) (json.RawMessage, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	snap := globalConfigStore.Get()
	if fp != "" {
		snap.CAFingerprint = fp
	}
	if c.bytes != nil && c.version == snap.Version && c.caFP == fp {
		return c.bytes, nil
	}
	b, err := json.Marshal(snap)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	c.version, c.caFP, c.bytes = snap.Version, fp, b
	return b, nil
}

// reset clears the cache. Production never needs it (globalConfigStore is a
// version-monotonic singleton); tests that swap globalConfigStore call it so a
// version number reused by a fresh store cannot serve a prior store's bytes.
func (c *configMarshalCache) reset() {
	c.mu.Lock()
	c.version, c.caFP, c.bytes = 0, "", nil
	c.mu.Unlock()
}

// callerIsEnrolledNode returns true when the gRPC peer presented a TLS
// certificate whose serial matches an enrolled, non-revoked cluster node.
// Used by GetConfig to decide whether to redact cluster secrets from the
// response.
//
// Unlike verifyNodeCert this is a POSITIVE check (caller must prove
// enrolment) — a missing peer cert or missing TLS info yields false, so
// unauthenticated bootstrap callers are correctly treated as unenrolled.
func callerIsEnrolledNode(ctx context.Context) bool {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return false
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok || len(tlsInfo.State.PeerCertificates) == 0 {
		return false
	}
	serial := tlsInfo.State.PeerCertificates[0].SerialNumber.Text(16)
	if globalClusterStore.IsRevoked(serial) {
		return false
	}
	nodes := globalClusterStore.ListNodes()
	for i := range nodes { // index-based: EnrolledNode is 176 bytes (rangeValCopy)
		if nodes[i].CertSerial == serial {
			return true
		}
	}
	return false
}

func (s *controlPlaneServer) PushMetrics(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var report MetricsReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}

	// Verify node identity (cert pinning) and check revocation.
	if err := verifyNode(ctx, report.NodeID); err != nil {
		return nil, err
	}

	nodeMetricsMu.Lock()
	nodeMetrics[report.NodeID] = report
	nodeMetricsMu.Unlock()

	// Update heartbeat. M5 PR-B: carry the DP's reported build version so the
	// cluster node list shows which culvert version each node is actually on.
	globalClusterStore.UpdateNodeSeen(report.NodeID, "", report.CulvertVersion)

	logger.Printf("ControlPlane: metrics from node %s (total=%d)", report.NodeID, report.Total)
	// ADR-0005 S3: piggyback the fencing epoch on every heartbeat reply so
	// DPs track leadership changes between config polls.
	reply, _ := json.Marshal(dpHeartbeatReply{OK: true, Epoch: globalHA.CurrentEpoch()})
	return reply, nil
}

// SyncRateLimits receives hot-IP deltas from a DP node and returns cluster-wide
// totals (excluding the requesting node) for distributed rate limiting.
func (s *controlPlaneServer) SyncRateLimits(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var gossip RateLimitGossip
	if err := json.Unmarshal(raw, &gossip); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}
	if err := verifyNode(ctx, gossip.NodeID); err != nil {
		return nil, err
	}

	// Store this node's hot-IP counts.
	globalRLAggregator.Update(gossip.NodeID, gossip.Deltas)

	// Return cluster totals minus this node's own counts.
	remote := globalRLAggregator.ClusterTotalsExcluding(gossip.NodeID)
	broadcast := RateLimitBroadcast{RemoteCounts: remote}
	b, err := json.Marshal(broadcast)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

// SyncRevocations receives revoked session tokens from a DP node and returns
// the merged list from all other nodes, enabling cluster-wide session invalidation.
func (s *controlPlaneServer) SyncRevocations(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	// ADR-0005 S3: revocation merge is a cluster-state write — fenced.
	if ok, reason := haIssuanceAllowed(); !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "revocation sync fenced: %s", reason)
	}
	var req struct {
		NodeID  string            `json:"node_id"`
		Entries []RevocationEntry `json:"entries"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}
	if err := verifyNode(ctx, req.NodeID); err != nil {
		return nil, err
	}
	globalRevAggregator.Update(req.NodeID, req.Entries)
	remote := globalRevAggregator.MergedExcluding(req.NodeID)
	b, err := json.Marshal(map[string]any{"entries": remote})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal: %v", err)
	}
	return b, nil
}

// PushAuditEvents receives audit events from a DP node for centralized logging.
func (s *controlPlaneServer) PushAuditEvents(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req struct {
		NodeID string       `json:"node_id"`
		Events []AuditEntry `json:"events"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}
	if err := verifyNode(ctx, req.NodeID); err != nil {
		return nil, err
	}
	if len(req.Events) > 0 {
		globalClusterAudit.Append(req.NodeID, req.Events)
	}
	return json.RawMessage(`{"ok":true}`), nil
}

// Enroll handles node enrollment: validates token, signs CSR, registers node.
func (s *controlPlaneServer) Enroll(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	// ADR-0005 S3: CA issuance is fenced — a zombie leader must not sign.
	if ok, reason := haIssuanceAllowed(); !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "enrollment fenced: %s", reason)
	}
	req, tokInfo, priorNode, err := admitEnrollment(ctx, raw)
	if err != nil {
		return nil, err
	}
	if err := validateEnrollCSR(req.CSR, req.NodeID); err != nil {
		return nil, err
	}

	// Sign the CSR.
	if !globalClusterCA.Ready() {
		return nil, status.Errorf(codes.FailedPrecondition, "cluster CA not initialized")
	}
	certPEM, serial, expiry, err := globalClusterCA.SignCSR([]byte(req.CSR), req.NodeID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "sign CSR: %v", err)
	}

	// Register the node (persists to disk).
	node := &EnrolledNode{
		NodeID:     req.NodeID,
		CertSerial: serial,
		CertExpiry: expiry,
		EnrolledAt: time.Now(),
		LastSeen:   time.Now(),
		Status:     "connected",
		EnrolledBy: tokInfo.CreatedBy,
	}
	if priorNode != nil {
		// Expired-node re-enrollment: admin-assigned labels are config, not
		// enrollment state — dropping them would silently detach the node
		// from its node groups (and their bandwidth/QoS policies).
		node.Labels = priorNode.Labels
		// Preserve an operator-set maintenance (draining) state across
		// re-enrollment. If the node was put into maintenance with
		// SetNodeDraining before its cert expired, a recovery-token
		// re-enrollment must not silently return it to active service —
		// carry the draining status forward so an explicit undrain is still
		// required. A normal (connected) prior record stays connected.
		if priorNode.Status == "draining" {
			node.Status = "draining"
		}
	}
	globalClusterStore.RegisterNode(node)

	if priorNode != nil {
		recordExpiredNodeReenrollment(ctx, priorNode, node)
	}

	logger.Printf("Enrollment: node %q enrolled (serial=%s, expires=%s)", req.NodeID, serial, expiry.Format("2006-01-02"))

	resp := EnrollResponse{
		CertPEM: string(certPEM),
		CAPEM:   string(globalClusterCA.CACertPEM()),
		NodeID:  req.NodeID,
		CPAddr:  clusterRole.grpcAddr,
		Epoch:   globalHA.CurrentEpoch(), // ADR-0005 S3: seed the DP's epoch ratchet
	}
	b, _ := json.Marshal(resp)
	return b, nil
}

// admitEnrollment parses and admission-checks an Enroll request: shape,
// required fields, per-IP rate limit, duplicate-node check, and atomic
// token consumption (persisted). Returns the parsed request, the consumed
// token's metadata, and — for an expired-node re-enrollment — a snapshot of
// the registration being superseded. Extracted from Enroll (cyclop).
func admitEnrollment(ctx context.Context, raw json.RawMessage) (EnrollRequest, TokenInfo, *EnrolledNode, error) {
	var req EnrollRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return req, TokenInfo{}, nil, status.Errorf(codes.InvalidArgument, "unmarshal: %v", err)
	}
	if req.Token == "" || req.CSR == "" || req.NodeID == "" {
		return req, TokenInfo{}, nil, status.Errorf(codes.InvalidArgument, "token, csr, and node_id are required")
	}

	// Rate limit enrollment attempts per IP.
	sourceIP := ""
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		sourceIP, _, _ = net.SplitHostPort(p.Addr.String())
	}
	if sourceIP != "" && !enrollRateLimitAllow(sourceIP) {
		return req, TokenInfo{}, nil, status.Errorf(codes.ResourceExhausted, "enrollment rate limited — try again later")
	}

	// Check if node ID is already registered and not revoked.
	// Use a generic error message to avoid leaking enrolled node names.
	//
	// CHAOS-12 remainder: a registered node whose cert has EXPIRED cannot
	// present it (the TLS handshake rejects expired certs) and cannot renew
	// (RenewCert requires that handshake) — a blanket denial here left the
	// node permanently bricked with no recovery short of the revoke +
	// re-enroll dance. An expired cert is exactly as unusable as a revoked
	// one, so it is re-admitted on the same terms as a revoked node: a
	// fresh, admin-issued enrollment token. The gate opens only once the
	// mTLS path is provably dead per the CP clock — the same clock the CP's
	// handshake uses — so at no moment can both a live cert and a token
	// claim the same node ID. The denial stays byte-identical and the token
	// stays unconsumed on the deny path.
	var priorNode *EnrolledNode
	if existing, ok := globalClusterStore.GetNode(req.NodeID); ok && existing.Status != "revoked" {
		if !nodeCertExpired(existing) {
			return req, TokenInfo{}, nil, status.Errorf(codes.PermissionDenied, "enrollment denied")
		}
		snapshot := *existing
		priorNode = &snapshot
	}

	// CHAOS-50: refuse an unusable cluster CA BEFORE the one-time token is spent.
	//
	// Enrollment tokens are single-use and their consumption is persisted, so a
	// precondition failure AFTER this point costs the caller their credential
	// permanently: once the CA is repaired the node retries with a token the CP
	// has already marked used, and an admin has to mint and distribute a
	// replacement. A failure that is not the caller's fault must not spend the
	// caller's credential — the same applies to the pre-existing "not
	// initialized" check further down in Enroll, which had the same shape.
	// Deliberately placed AFTER the per-IP rate limiter, so an unauthenticated
	// flood cannot drive the refusal counter or the alert gate. (Ported from
	// the competing CHAOS-50 implementation on PR #1179.)
	if err := clusterCAIssuancePrecondition(); err != nil {
		return req, TokenInfo{}, nil, err
	}

	// Validate and consume the enrollment token atomically (persisted to disk).
	// Returns token metadata so we don't need to re-access the map.
	tokInfo, err := globalClusterStore.ValidateAndConsumeToken(req.Token, req.NodeID, sourceIP)
	if err != nil {
		logger.Printf("Enrollment: rejected node %q: %v", sanitizeLog(req.NodeID), err)
		return req, TokenInfo{}, nil, status.Errorf(codes.PermissionDenied, "enrollment denied: %v", err)
	}
	return req, tokInfo, priorNode, nil
}

// clusterCAIssuancePrecondition reports whether the cluster CA can issue a
// certificate right now, as a gRPC status error ready to return.
//
// It is the token-preserving front half of the CHAOS-50 fail-closed contract:
// the authoritative guard still lives in SignCSR (which RenewCert also reaches,
// and which no caller can bypass), but running the same check here — before the
// token is spent — means a refusal costs the operator a retry rather than a
// credential. A refusal is counted exactly once because this path returns
// before SignCSR is reached.
func clusterCAIssuancePrecondition() error {
	if !globalClusterCA.Ready() {
		return status.Errorf(codes.FailedPrecondition, "cluster CA not initialized")
	}
	if err := globalClusterCA.Usable(); err != nil {
		noteClusterCASignRefused(err.Error())
		return status.Errorf(codes.FailedPrecondition, "cluster CA cannot issue certificates: %v — %s",
			err, clusterCAUnusableRemediation(clusterCAUnusableKind(err)))
	}
	return nil
}

// nodeCertExpired reports whether an enrolled node's certificate is past its
// expiry per the CP clock. A zero CertExpiry (unknown — e.g. a legacy or
// hand-edited registration) is treated as NOT expired: fail closed on
// missing data, keeping the blanket enrollment denial for such nodes.
func nodeCertExpired(n *EnrolledNode) bool {
	return !n.CertExpiry.IsZero() && time.Now().After(n.CertExpiry)
}

// enrollAlertFire is the alert seam for enrollment-path alerts (test hook,
// mirroring releaseAlertFire in release_alerts.go).
var enrollAlertFire = fireAlert

// recordExpiredNodeReenrollment leaves the evidence trail for an
// expired-node re-enrollment (the CHAOS-12 recovery path): the superseded
// serial goes on the CRL (cert-serial pinning in verifyNodeCert already
// excludes it — the CRL entry is defense-in-depth and the durable record
// that the old identity was retired), and the identity swap is logged,
// audited, and alerted so a token-holder replacing a bricked node is never
// invisible to the operator.
func recordExpiredNodeReenrollment(ctx context.Context, prior, replacement *EnrolledNode) {
	sourceIP := "unknown"
	if p, ok := peer.FromContext(ctx); ok && p.Addr != nil {
		if host, _, err := net.SplitHostPort(p.Addr.String()); err == nil && host != "" {
			sourceIP = host
		}
	}
	if prior.CertSerial != "" && !globalClusterStore.IsRevoked(prior.CertSerial) {
		if err := globalClusterStore.RevokeSerial(prior.CertSerial, prior.NodeID, "system", "superseded by expired-node re-enrollment"); err != nil {
			logger.Printf("Enrollment: failed to add superseded serial %s to CRL for node %q: %v",
				prior.CertSerial, sanitizeLog(prior.NodeID), err)
		}
	}
	detail := fmt.Sprintf("expired cert (serial=%s, expired %s) superseded by token re-enrollment (new serial=%s); old serial added to CRL",
		prior.CertSerial, prior.CertExpiry.Format("2006-01-02"), replacement.CertSerial)
	logger.Printf("Enrollment: node %q RE-ENROLLED after cert expiry from %q — %s",
		sanitizeLog(prior.NodeID), sanitizeLog(sourceIP), detail)
	now := time.Now()
	auditAdd(AuditEntry{
		TS:     now.UnixMilli(),
		Time:   now.Format("2006-01-02 15:04:05"),
		Actor:  strings.ReplaceAll(sourceIP, `"`, ""),
		Action: "cluster.node.reenroll-expired",
		Object: strings.ReplaceAll(prior.NodeID, `"`, ""),
		Detail: detail,
	})
	enrollAlertFire("cluster_node_reenrolled", AlertPayload{
		Actor:  sourceIP,
		Host:   prior.NodeID,
		Detail: detail,
		Source: "cluster",
	})
}

// validateEnrollCSR checks the CSR parses and that its CommonName matches
// the claimed node ID (identity-spoofing guard). Extracted from Enroll
// (cyclop).
func validateEnrollCSR(csrPEM, nodeID string) error {
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		return status.Errorf(codes.InvalidArgument, "invalid CSR: no PEM block found")
	}
	csr, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return status.Errorf(codes.InvalidArgument, "invalid CSR: %v", err)
	}
	if csr.Subject.CommonName != nodeID {
		return status.Errorf(codes.InvalidArgument,
			"CSR CommonName %q does not match claimed node_id %q", csr.Subject.CommonName, nodeID)
	}
	return nil
}

// RenewCert handles certificate renewal requests from enrolled DP nodes.
// The node must be enrolled and not revoked. A new cert is signed from the CSR.
func (s *controlPlaneServer) RenewCert(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	// ADR-0005 S3: CA issuance is fenced — a zombie leader must not sign.
	if ok, reason := haIssuanceAllowed(); !ok {
		return nil, status.Errorf(codes.FailedPrecondition, "cert renewal fenced: %s", reason)
	}
	var req struct {
		NodeID string `json:"node_id"`
		CSR    string `json:"csr"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}
	if req.NodeID == "" || req.CSR == "" {
		return nil, fmt.Errorf("node_id and csr are required")
	}

	// Verify the caller is the enrolled node (cert pinning).
	if err := verifyNode(ctx, req.NodeID); err != nil {
		return nil, fmt.Errorf("RenewCert: %w", err)
	}

	// Sign the new CSR.
	certPEM, serial, expiry, err := globalClusterCA.SignCSR([]byte(req.CSR), req.NodeID)
	if err != nil {
		return nil, fmt.Errorf("sign CSR: %w", err)
	}

	// Update the enrolled node's cert serial and expiry.
	// Hold lock through saveLocked() to prevent race with concurrent mutations (B14).
	globalClusterStore.mu.Lock()
	if node, ok := globalClusterStore.st.Nodes[req.NodeID]; ok {
		node.CertSerial = serial
		node.CertExpiry = expiry
		globalClusterStore.st.Nodes[req.NodeID] = node
	}
	if err := globalClusterStore.saveLocked(); err != nil {
		logger.Printf("RenewCert: failed to persist updated node: %v", err)
	}
	globalClusterStore.mu.Unlock()

	logger.Printf("RenewCert: renewed cert for node %q (serial=%s, expires=%s)", req.NodeID, serial, expiry.Format("2006-01-02"))

	// Track renewal progress if a CA rotation is active.
	globalClusterStore.RecordNodeRenewed(req.NodeID)

	resp, _ := json.Marshal(map[string]any{
		"cert_pem": string(certPEM),
		"ca_pem":   string(globalClusterCA.AllCACertsPEM()),
		"epoch":    globalHA.CurrentEpoch(), // ADR-0005 S3: DP rejects below-ratchet issuance
	})
	return resp, nil
}

// HAStateBundle is the full state package sent from leader to standby CP.
// Contains everything the standby needs to promote to leader if needed.
// The CA private key is encrypted with AES-256-GCM using the HA token as
// passphrase (1.6 fix: never transmit CA key in plaintext).
//
// CA-3 PR5: the deprecated plaintext CAKeyPEM field has been removed. The CA
// key is carried ONLY as CAKeyEncrypted (HA-token-wrapped, in transit); the
// standby fails closed if it is missing/invalid rather than accepting plaintext.
type HAStateBundle struct {
	ClusterState   json.RawMessage `json:"cluster_state"`
	CACertPEM      string          `json:"ca_cert_pem"`
	CAKeyEncrypted string          `json:"ca_key_encrypted,omitempty"` // base64(salt + nonce + ciphertext)
	Config         ConfigSnapshot  `json:"config"`
	Version        int64           `json:"version"`
	// PromoteRequested signals the standby to perform a COORDINATED planned
	// promotion (ADR-0004 Slice 1e) — e.g. before a CP rolling update takes the
	// leader down. Honored even when auto-failover is OFF, because it is an
	// explicit leader-initiated handoff, not an unattended auto-failover.
	PromoteRequested bool `json:"promote_requested,omitempty"`
	// LeaderTerm carries the leader's current epoch so the standby can seed its
	// own term (ADR-0004 Slice 1c, Codex P2) and a promotion yields a strictly
	// higher epoch — making the /healthz split-brain signal meaningful.
	LeaderTerm uint64 `json:"leader_term,omitempty"`
	// Epoch is the leader's fencing epoch (ADR-0005 S3; 0 = legacy mode).
	// The PULLER verifies it against its own lease backend before importing
	// (Finding 7 — a zombie leader serving stale state cannot be imported).
	Epoch int64 `json:"epoch,omitempty"`
}

// normalizeAdvertisedAddr turns a standby's advertised address into one the
// leader can actually dial (ADR-0005 S0; PR #529 review). The standby commonly
// advertises its BIND address — ":50051" or "0.0.0.0:50051" — because the HA
// deploy command reuses --cp-grpc-addr, and a bind address is not reachable
// from the leader. When the advertised host is empty or a wildcard, substitute
// the peer IP observed on this gRPC connection, keeping the advertised port.
// A concrete host:port passes through verbatim (explicit operator intent);
// non-host:port values also pass through verbatim (pre-existing behavior for
// custom inputs). Returns "" (record nothing) when a wildcard cannot be
// resolved against an observed peer — a knowingly-undialable target is worse
// than none.
func normalizeAdvertisedAddr(ctx context.Context, adv string) string {
	if adv == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(adv)
	if err != nil {
		return adv
	}
	if host != "" && host != "0.0.0.0" && host != "::" {
		return adv
	}
	p, ok := peer.FromContext(ctx)
	if !ok || p.Addr == nil {
		return ""
	}
	peerHost, _, err := net.SplitHostPort(p.Addr.String())
	if err != nil {
		return ""
	}
	return net.JoinHostPort(peerHost, port)
}

// haEncryptKey encrypts data with AES-256-GCM using a key derived from the
// HA token via PBKDF2-SHA256. Returns base64(salt + nonce + ciphertext).
func haEncryptKey(plaintext []byte, token string) (string, error) {
	salt := make([]byte, 32)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	aesKey := pbkdf2.Key([]byte(token), salt, 100_000, 32, sha256.New)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := make([]byte, 0, len(salt)+len(nonce)+len(ct))
	out = append(out, salt...)
	out = append(out, nonce...)
	out = append(out, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// haDecryptKey decrypts a base64-encoded (salt + nonce + ciphertext) blob
// using the HA token as passphrase.
func haDecryptKey(encoded string, token string) ([]byte, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	if len(data) < 32+12 {
		return nil, errors.New("ha decrypt: data too short")
	}
	salt := data[:32]
	nonce := data[32:44]
	ct := data[44:]
	aesKey := pbkdf2.Key([]byte(token), salt, 100_000, 32, sha256.New)
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ct, nil)
}

// HASync returns the full state bundle for HA standby replication.
// Authenticated via a shared HA token (not node cert pinning).
func (s *controlPlaneServer) HASync(ctx context.Context, raw json.RawMessage) (json.RawMessage, error) {
	var req struct {
		Token       string `json:"token"`
		StandbyAddr string `json:"standby_addr"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		return nil, fmt.Errorf("invalid request: %w", err)
	}

	// Verify HA token.
	if !globalHA.VerifyToken(req.Token) {
		return nil, status.Errorf(codes.PermissionDenied, "invalid HA token")
	}

	// Refuse to replicate an empty config to a standby when the leader's initial
	// publish was rejected (nothing valid ever published) — applyHABundle would
	// otherwise apply the zero snapshot and wipe the standby's config.
	if ok, reason := globalConfigStore.ServableConfig(); !ok {
		return nil, status.Errorf(codes.Unavailable, "leader has no valid config to replicate: %s", reason)
	}

	// ADR-0005 S0: record the standby's advertised address as the failback
	// target (only after the token check, so an unauthenticated caller cannot
	// poison it). The advertised value is normalised against the OBSERVED peer
	// of this connection (PR #529 review): the standby commonly advertises its
	// BIND address (":50051" / "0.0.0.0:50051", copied from --cp-grpc-addr by
	// the deploy command), which the leader cannot dial — substitute the peer
	// IP, keep the advertised port. No-op unless we are the leader and the
	// address changed.
	globalHA.RecordStandbyAddr(normalizeAdvertisedAddr(ctx, req.StandbyAddr))

	// Build state bundle.
	stateJSON, err := globalClusterStore.ExportState()
	if err != nil {
		return nil, fmt.Errorf("export cluster state: %w", err)
	}

	// 1.6 fix: encrypt CA private key with HA token before transmission.
	var caKeyEncrypted string
	if keyPEM := globalClusterCA.CAKeyPEM(); len(keyPEM) > 0 {
		enc, encErr := haEncryptKey(keyPEM, req.Token)
		if encErr != nil {
			return nil, fmt.Errorf("encrypt CA key for HA sync: %w", encErr)
		}
		caKeyEncrypted = enc
	}

	// Replicate the PUBLISHED snapshot (globalConfigStore.Get()), NOT a fresh
	// CurrentConfigSnapshot(): the published snapshot is the one commit-time
	// validation already accepted, so the standby always receives a
	// within-cap, version-CONSISTENT config. A fresh rebuild could be over-cap
	// (rejected at publish, so never distributed to DPs) yet get stamped with
	// the old published Version — the standby would then hold config the fleet
	// never had, mismatched to its version floor.
	published := globalConfigStore.Get()
	bundle := HAStateBundle{
		ClusterState:     stateJSON,
		CACertPEM:        string(globalClusterCA.CACertPEM()),
		CAKeyEncrypted:   caKeyEncrypted,
		Config:           published,
		Version:          published.Version,
		PromoteRequested: globalHA.plannedPromotion.Load(), // ADR-0004 Slice 1e: coordinated handoff
		LeaderTerm:       globalHA.Status().Term,           // ADR-0004 Slice 1c/P2: seed standby epoch
		Epoch:            globalHA.CurrentEpoch(),          // ADR-0005 S3: puller-side fence input
	}

	resp, _ := json.Marshal(bundle)
	return resp, nil
}

// StartControlPlaneGRPC starts the gRPC server for the Control Plane.
// addr example: ":50051"
// certFile/keyFile: mTLS certificate paths.  Pass empty strings for insecure
// (development only — never in production).
// clusterInsecure controls whether the CP allows insecure (non-TLS) gRPC.
// Set via --cluster-insecure flag. When false (default), CP startup fails
// without TLS certificates to prevent accidental production exposure.
var clusterInsecure bool

// cpServerOption returns the gRPC server option for the Control Plane based on
// available TLS certs or the --cluster-insecure flag.
func cpServerOption(addr, certFile, keyFile, caFile string) (grpc.ServerOption, error) {
	switch {
	case certFile != "" && keyFile != "":
		creds, err := buildServerTLS(certFile, keyFile, caFile)
		if err != nil {
			return nil, fmt.Errorf("gRPC TLS: %w", err)
		}
		logger.Printf("ControlPlane: gRPC %s (mTLS)", strings.ReplaceAll(addr, "\n", ""))
		return grpc.Creds(creds), nil
	case clusterInsecure:
		logWarnf("ControlPlane: gRPC %s (insecure — all cluster data unencrypted!)", strings.ReplaceAll(addr, "\n", ""))
		return grpc.EmptyServerOption{}, nil
	default:
		return nil, fmt.Errorf("TLS certificates required for Control Plane (use --cluster-insecure to override for development)")
	}
}

func StartControlPlaneGRPC(addr, certFile, keyFile, caFile string) error {
	serverOpt, err := cpServerOption(addr, certFile, keyFile, caFile)
	if err != nil {
		return err
	}

	srv := grpc.NewServer(
		serverOpt,
		// Match the DP client's frame budget so an enterprise-scale
		// ConfigSnapshot (2 M blocked hosts + IP list + URL categories) fits
		// uncompressed. gRPC's 4 MiB default receive limit is what capped the
		// old snapshot at ~200 k hosts. Importing
		// google.golang.org/grpc/encoding/gzip (blank import above) registers
		// the codec so the server ALWAYS accepts gzip requests and echoes gzip
		// on those responses — but never REQUIRES it. This is what makes the
		// DP's opt-in compression (CULVERT_CLUSTER_GRPC_COMPRESSION) a safe,
		// CP-first migration: an upgraded CP handles both compressed and
		// uncompressed DPs, so enabling compression never depends on rollout
		// order the way an unconditional client-side compressor would.
		// Asymmetric by direction: the big config snapshot only flows OUTBOUND
		// (GetConfig / HASync responses), so the server SENDS large but RECEIVES
		// tight — every inbound RPC is small, so a 16 MiB recv cap shrinks the
		// CP's inbound allocation surface instead of inheriting the 128 MiB frame.
		grpc.MaxRecvMsgSize(maxClusterInboundMsgSize),
		grpc.MaxSendMsgSize(maxClusterGRPCMsgSize),
	)
	registerConfigService(srv)

	lc := net.ListenConfig{}
	ln, err := lc.Listen(context.Background(), "tcp", addr)
	if err != nil {
		return fmt.Errorf("gRPC listen: %w", err)
	}
	clusterRole.grpcSrv = srv

	go func() {
		if err := srv.Serve(ln); err != nil {
			logger.Printf("ControlPlane gRPC error: %v", err)
		}
	}()
	return nil
}

// registerConfigService registers the hand-rolled ConfigService (JSON over
// gRPC, no protoc) on srv. Shared by StartControlPlaneGRPC and the bufconn
// round-trip test so the test exercises the EXACT production registration —
// the registration that used to panic at startup (see the nil impl below).
//
// The impl argument to RegisterService is nil, NOT a *controlPlaneServer: every
// handler is bound via wrapUnary(svc.Method) and closes over svc, so the impl
// is unused at dispatch. grpc.RegisterService reflect-checks a NON-nil impl
// against HandlerType, and HandlerType here is a concrete struct
// (*controlPlaneServer) rather than an interface, so a non-nil impl panics with
// "reflect: non-interface type passed to Type.Implements". Passing nil takes
// grpc's legacy no-typecheck path and lets the server actually start.
func registerConfigService(srv grpc.ServiceRegistrar) {
	svc := &controlPlaneServer{}
	srv.RegisterService(&grpc.ServiceDesc{
		ServiceName: configServiceName,
		HandlerType: (*controlPlaneServer)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "GetConfig", Handler: wrapUnary(svc.GetConfig)},
			{MethodName: "GetConfigDelta", Handler: wrapUnary(svc.GetConfigDelta)},
			{MethodName: "PushMetrics", Handler: wrapUnary(svc.PushMetrics)},
			{MethodName: "Enroll", Handler: wrapUnary(svc.Enroll)},
			{MethodName: "SyncRateLimits", Handler: wrapUnary(svc.SyncRateLimits)},
			{MethodName: "SyncRevocations", Handler: wrapUnary(svc.SyncRevocations)},
			{MethodName: "PushAuditEvents", Handler: wrapUnary(svc.PushAuditEvents)},
			{MethodName: "RenewCert", Handler: wrapUnary(svc.RenewCert)},
			{MethodName: "HASync", Handler: wrapUnary(svc.HASync)},
		},
		Streams: []grpc.StreamDesc{},
	}, nil)
}

// cpGRPCGracefulStopBudget bounds the graceful half of the gRPC shutdown.
// Every method on ConfigService is UNARY (see registerConfigService — Streams
// is empty), so against a live peer the drain is sub-second: the longest RPC
// is a GetConfig writing one ConfigSnapshot, and a DP that loses it re-fetches
// on its next sync tick. Sized above grpc-go's own 5s GOAWAY ping-ack timer
// (measured 6.0s end to end on v1.83.1) so a peer that is merely unresponsive
// still completes the graceful path. CHAOS-56.
const cpGRPCGracefulStopBudget = 8 * time.Second

// StopControlPlaneGRPC stops the gRPC server, draining in-flight RPCs, and
// force-closes anything still holding a transport once the graceful budget is
// spent. Called during SIGTERM/SIGINT shutdown.
//
// CHAOS-56 — GracefulStop used to be called bare, from the early shutdown
// phase, which ran under context.Background() and was documented as "not
// subject to any shutdown timeout". GracefulStop blocks in
// `for len(s.conns) != 0 { s.cv.Wait() }` (grpc-go server.go), and a transport
// leaves that map only once its ACTIVE STREAMS are done: grpc-go's
// outgoingGoAwayHandler bounds the idle case at a 5s ping-ack timer — measured
// at 6.0s against a silent HTTP/2 peer on v1.83.1 — but when the second GOAWAY
// finds `len(t.activeStreams) != 0` it deliberately leaves the connection open
// with no timer at all. Two ordinary faults produce a stream that never
// finishes, and neither surfaces an error to abort it:
//
//   - A handler that does not return. Enroll and RenewCert sign a CSR and
//     write it out; PushAuditEvents appends to a fileutil.RotatingFile. On a
//     wedged volume — the hung NFS mount and slow-filesystem cases the rest of
//     this review's storage work is built around — the handler blocks in a
//     write(2) that never completes.
//   - A response the peer stops reading. GetConfig returns up to a 128 MiB
//     ConfigSnapshot; a DP that freezes mid-read leaves the server blocked on
//     HTTP/2 flow control over a TCP zero-window, and the kernel's persist
//     timer retries that indefinitely rather than ever erroring out.
//
// So one wedged DP held the CP's SIGTERM open with no bound whatsoever, until
// the container's 60s stop_grace_period ran out and SIGKILL skipped every hook
// behind it — the cluster-store flush, the request-log queue drain, a clean
// badger close, and the log-sink flush that would have said why.
//
// The bounded pattern is the canonical one: run GracefulStop on its own
// goroutine, wait out the budget, then Stop() to force-close. Force-closing is
// safe by construction here — an interrupted unary RPC is retried by the
// caller's own sync loop, which is the same recovery path a mid-flight CP
// restart already exercises. The budget is above the 6s idle-drain figure so a
// fleet of merely-unresponsive peers still drains gracefully; it is the
// unbounded active-stream case the force-close exists for.
func StopControlPlaneGRPC() {
	srv := clusterRole.grpcSrv
	if srv == nil {
		return
	}
	logger.Printf("ControlPlane: graceful gRPC shutdown...")
	if gracefulStopBounded(srv, cpGRPCGracefulStopBudget) {
		logger.Printf("ControlPlane: gRPC stopped")
		return
	}
	logger.Printf("ControlPlane: gRPC drain exceeded %s — force-closed connections", cpGRPCGracefulStopBudget)
}

// gracefulStopBounded runs srv.GracefulStop under a budget and falls back to
// srv.Stop when it expires. Reports whether the graceful drain completed
// within the budget. Split out from StopControlPlaneGRPC so the bound is
// testable against a real wedged stream without touching the clusterRole
// global. CHAOS-56.
//
// On the force path it deliberately does NOT join the GracefulStop goroutine.
// grpc-go's stop(graceful=true) finishes with s.handlersWG.Wait(), so it does
// not return until every HANDLER has returned — and the handler that has not
// returned is exactly the fault being escaped (a write(2) into a wedged
// volume). Joining it would reintroduce the unbounded wait one level down,
// which is what the first draft of this function did and what
// TestChaos56_GracefulStopIsBoundedAgainstAWedgedStream caught.
//
// Abandoning it is safe: Stop closes the listeners and every connection, so
// the server is fully stopped when this returns, and the parked goroutine
// costs one stack in a process that is exiting. This is also why the hook-
// level watchdog in shutdownRegistry.RunAll is not redundant with this bound —
// each catches a stall the other cannot.
func gracefulStopBounded(srv *grpc.Server, budget time.Duration) bool {
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		srv.GracefulStop()
	}()
	timer := time.NewTimer(budget)
	defer timer.Stop()
	select {
	case <-drained:
		return true
	case <-timer.C:
		srv.Stop()
		return false
	}
}

// wrapUnary adapts our JSON handler signature to grpc.methodHandler.
func wrapUnary(fn func(context.Context, json.RawMessage) (json.RawMessage, error)) func(any, context.Context, func(any) error, grpc.UnaryServerInterceptor) (any, error) {
	return func(_ any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
		var raw json.RawMessage
		if err := dec(&raw); err != nil {
			return nil, err
		}
		return fn(ctx, raw)
	}
}
