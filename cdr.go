package main

// Sluice CDR client — Phase 1.
//
// This file implements a single-instance streaming gRPC client to the Sluice
// CDR (Content Disarm & Reconstruction) engine. It handles:
//
//   - mTLS dial with TOFU (trust-on-first-use) server-cert pinning
//   - Bidirectional streaming Sanitize: header + chunks → result + chunks
//   - Unary Health and Enroll RPCs
//   - Per-call context deadlines; never bare time.Sleep
//
// What this file deliberately does NOT do yet (Phase 2+):
//   - Connection pool across multiple Sluice instances
//   - Load balancing (round-robin / least-conn / weighted)
//   - Circuit breaker per instance
//   - Integration with handleTunnelInspect
//   - Policy engine (cdrpolicy.go)
//
// The wire contract lives in sluicev1/sluice.proto. Until upstream Sluice
// tags v0.1.0, that directory is a LOCAL STUB referenced via a replace
// directive in go.mod. When Sluice publishes v0.1.0, drop the replace and
// `go get github.com/KidCarmi/Sluice/proto/sluicev1@v0.1.0`.

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
)

// ─── Tunables ────────────────────────────────────────────────────────────────

const (
	// cdrDefaultTimeout is the per-file deadline (Sluice's own hard cap is 30s
	// per file; we add a 5s buffer so our context expires last and we surface
	// a meaningful error rather than a connection reset).
	cdrDefaultTimeout = 35 * time.Second

	// cdrChunkSize is the streaming payload per gRPC message.  Kept well under
	// MaxSendMsgSize (4 MiB) so Sluice-side frame limits never bite.
	cdrChunkSize = 64 * 1024

	// cdrMaxFileSize matches Sluice's application-level cap.  Larger payloads
	// are rejected client-side before any byte crosses the wire.
	cdrMaxFileSize = 50 * 1024 * 1024
)

// ─── Observability counters ─────────────────────────────────────────────────

// Flat atomic counters, wired into metrics.go in a later phase.  Exported
// as vars so tests can reset them.
var (
	statCDRSanitizeTotal    int64
	statCDRSanitizeErrors   int64
	statCDRThreatsDetected  int64
	statCDRBytesSent        int64
	statCDRBytesReceived    int64
	statCDRFingerprintFails int64
)

// ─── Result type (decoupled from proto) ─────────────────────────────────────

// CDRThreat is Culvert's view of a single threat Sluice detected.
// We don't expose the proto type directly so callers (handleTunnelInspect,
// auditEvent, UI) get a stable shape even if the wire message gains fields.
type CDRThreat struct {
	Type        string
	Location    string
	Description string
	Severity    string // one of: low | medium | high | critical
}

// CDRResult is the full outcome of a single Sanitize call.
type CDRResult struct {
	Status          pb.Status
	OriginalType    string
	OriginalSize    int64
	SanitizedSize   int64
	Threats         []CDRThreat
	ErrorMessage    string
	SanitizedSHA256 string // hex-encoded for easy logging / cache keys
	DurationMs      int64
	// SanitizedData holds the bytes returned by Sluice.  In ENFORCE mode this
	// is the sanitized payload; in REPORT_ONLY / BYPASS_WITH_REPORT it equals
	// the original bytes Culvert sent.  Nil when the caller passed io.Discard.
	SanitizedData []byte
}

// ─── Client ─────────────────────────────────────────────────────────────────

// CDRClientConfig holds the minimum wiring needed to talk to one Sluice.
type CDRClientConfig struct {
	Endpoint            string        // host:port, e.g. "sluice:8443"
	Timeout             time.Duration // per-file deadline (0 = cdrDefaultTimeout)
	ChunkSize           int           // bytes per stream message (0 = cdrChunkSize)
	ServerFingerprintHx string        // TOFU-pinned sha256 of server cert, hex-encoded
	ClientCertPEM       []byte        // from Enroll()
	ClientKeyPEM        []byte        // from Enroll()
	CACertPEM           []byte        // from Enroll()

	// SecondaryFingerprintHx is the previous server-cert fingerprint
	// accepted during a rotation grace window.  Populated from
	// HealthResponse.rotated_fingerprint by the health poller and
	// reused across reconnects until SecondaryValidUntil passes.
	// Empty string = no active rotation (single-pin mode).
	SecondaryFingerprintHx string
	SecondaryValidUntil    time.Time
}

// CDRClient is a pooled mTLS gRPC client to a single Sluice instance.
type CDRClient struct {
	cfg  CDRClientConfig
	conn *grpc.ClientConn
	stub pb.SluiceServiceClient

	// mu guards mutable state.  Intentionally minimal in Phase 1; Phase 2
	// adds the circuit breaker + health state that earns its keep.
	mu       sync.RWMutex
	closedAt time.Time
}

// NewCDRClient dials Sluice with mTLS and TOFU fingerprint verification.
// The returned client owns the underlying gRPC connection — call Close.
//
// Note: grpc.NewClient is non-blocking (no dial happens until the first RPC),
// so no dial-time context is needed.  Callers pass per-RPC contexts when they
// actually use the client.  Phase 2 will likely add a dial-time Health probe
// that takes a context; until then we keep the signature minimal.
func NewCDRClient(cfg CDRClientConfig) (*CDRClient, error) {
	if cfg.Endpoint == "" {
		return nil, errors.New("cdr: endpoint required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = cdrDefaultTimeout
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = cdrChunkSize
	}

	tlsCfg, err := buildCDRTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("cdr: tls config: %w", err)
	}

	conn, err := grpc.NewClient(
		cfg.Endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(4<<20),
			grpc.MaxCallSendMsgSize(4<<20),
		),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second,
			Timeout:             10 * time.Second,
			PermitWithoutStream: true,
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("cdr: dial %s: %w", sanitizeLog(cfg.Endpoint), err)
	}

	return &CDRClient{
		cfg:  cfg,
		conn: conn,
		stub: pb.NewSluiceServiceClient(conn),
	}, nil
}

// Close tears down the gRPC connection.
func (c *CDRClient) Close() error {
	if c == nil || c.conn == nil {
		return nil
	}
	c.mu.Lock()
	c.closedAt = time.Now()
	c.mu.Unlock()
	return c.conn.Close()
}

// newCDRClientFromConn builds a client around an already-dialed gRPC
// connection.  Used by tests (bufconn) and by Phase 2's connection pool.
// The caller retains ownership of conn; Close on the returned client WILL
// close conn, so don't share it.
func newCDRClientFromConn(conn *grpc.ClientConn, cfg CDRClientConfig) *CDRClient {
	if cfg.Timeout == 0 {
		cfg.Timeout = cdrDefaultTimeout
	}
	if cfg.ChunkSize <= 0 {
		cfg.ChunkSize = cdrChunkSize
	}
	return &CDRClient{
		cfg:  cfg,
		conn: conn,
		stub: pb.NewSluiceServiceClient(conn),
	}
}

// ─── TLS / TOFU fingerprint pinning ─────────────────────────────────────────

// buildCDRTLSConfig constructs a *tls.Config that:
//   - enforces TLS 1.3 (matches Sluice's minimum)
//   - presents the enrolled client cert for mTLS
//   - verifies the server cert by SHA-256 fingerprint (TOFU pin) OR by CA
//   - skips stdlib hostname verification (Sluice may be accessed by IP in
//     docker-compose); fingerprint pin is the authoritative identity check
func buildCDRTLSConfig(cfg CDRClientConfig) (*tls.Config, error) {
	// Client cert (mTLS).  Optional for the Enroll bootstrap path (chicken-
	// and-egg) — callers that don't have certs yet pass nil and rely on the
	// fingerprint pin alone.
	var clientCerts []tls.Certificate
	if len(cfg.ClientCertPEM) > 0 && len(cfg.ClientKeyPEM) > 0 {
		cert, err := tls.X509KeyPair(cfg.ClientCertPEM, cfg.ClientKeyPEM)
		if err != nil {
			return nil, fmt.Errorf("client keypair: %w", err)
		}
		clientCerts = []tls.Certificate{cert}
	}

	// CA pool — used only when CACertPEM is supplied.  When fingerprint pin
	// is set, the pin is authoritative and CA is advisory.
	var rootPool *x509.CertPool
	if len(cfg.CACertPEM) > 0 {
		rootPool = x509.NewCertPool()
		if !rootPool.AppendCertsFromPEM(cfg.CACertPEM) {
			return nil, errors.New("ca bundle: invalid PEM")
		}
	}

	fp := strings.TrimSpace(cfg.ServerFingerprintHx)
	fp = strings.TrimPrefix(fp, "sha256:")
	fp = strings.TrimPrefix(fp, "SHA256:")
	fp = strings.ReplaceAll(fp, ":", "")

	if fp == "" {
		// No pin — fall back to CA-only validation.  Only safe when
		// CACertPEM is populated, and stdlib verification is ON.
		if rootPool == nil {
			return nil, errors.New("either server_fingerprint or ca_cert is required")
		}
		return &tls.Config{
			MinVersion:   tls.VersionTLS13,
			Certificates: clientCerts,
			RootCAs:      rootPool,
		}, nil
	}

	expected, err := hex.DecodeString(fp)
	if err != nil {
		return nil, fmt.Errorf("server_fingerprint: invalid hex: %w", err)
	}
	if len(expected) != sha256.Size {
		return nil, fmt.Errorf("server_fingerprint: expected %d bytes, got %d", sha256.Size, len(expected))
	}

	// Optional secondary fingerprint for Sluice server-cert rotation
	// (Sluice v0.2 dual-pin grace window).  When populated and within
	// the validity window, the verify callbacks accept EITHER digest
	// so Culvert keeps talking during the operator's rotation window.
	var secondary []byte
	if sfp := normalisePinHex(cfg.SecondaryFingerprintHx); sfp != "" && time.Now().Before(cfg.SecondaryValidUntil) {
		if raw, err := hex.DecodeString(sfp); err == nil && len(raw) == sha256.Size {
			secondary = raw
		}
	}

	// Build the pin-based tls.Config as a single struct literal.  The
	// "InsecureSkipVerify: true" is required to bypass the stdlib's hostname
	// + chain checks (Sluice is typically reached by IP in docker-compose and
	// presents a self-signed cert until enrollment completes).  It is
	// replaced by verifyPinnedFingerprint, which performs a constant-time
	// equality check on the leaf cert's SHA-256.  This is the canonical TOFU
	// pinning pattern used by SSH, Tailscale, and kubelet.
	//
	// SessionTicketsDisabled + explicit ClientSessionCache=nil guard against
	// gosec G123: on TLS 1.3 or 1.2, a resumed session may skip
	// VerifyPeerCertificate entirely, so the fingerprint check would not
	// re-run.  Disabling resumption forces a full handshake each time, which
	// is fine for our traffic profile (few long-lived connections) and
	// closes the gap.  VerifyConnection provides a second layer that runs
	// even if resumption is somehow enabled upstream.
	return &tls.Config{
		MinVersion:             tls.VersionTLS13,
		Certificates:           clientCerts,
		RootCAs:                rootPool,
		InsecureSkipVerify:     true, // #nosec G402 -- pin-verified below (see VerifyPeerCertificate)
		VerifyPeerCertificate:  verifyPinnedFingerprint(expected, secondary),
		VerifyConnection:       verifyConnectionWithFingerprint(expected, secondary),
		SessionTicketsDisabled: true,
		ClientSessionCache:     nil,
	}, nil
}

// normalisePinHex strips common prefixes + colons + whitespace and
// lowercases hex.  Empty string in → empty string out.
func normalisePinHex(fp string) string {
	s := strings.TrimSpace(fp)
	s = strings.TrimPrefix(s, "sha256:")
	s = strings.TrimPrefix(s, "SHA256:")
	s = strings.ReplaceAll(s, ":", "")
	return strings.ToLower(s)
}

// verifyConnectionWithFingerprint is the VerifyConnection hook — runs
// on EVERY handshake (including resumed sessions), closing the gosec
// G123 gap where a resumed session could bypass VerifyPeerCertificate.
// Accepts EITHER the primary OR secondary fingerprint; secondary is
// populated during a Sluice dual-pin rotation grace window.
func verifyConnectionWithFingerprint(primary, secondary []byte) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		if len(cs.PeerCertificates) == 0 {
			atomic.AddInt64(&statCDRFingerprintFails, 1)
			return errors.New("sluice server presented no certificate (resumed session)")
		}
		sum := sha256.Sum256(cs.PeerCertificates[0].Raw)
		if fingerprintMatches(sum[:], primary) || fingerprintMatches(sum[:], secondary) {
			return nil
		}
		atomic.AddInt64(&statCDRFingerprintFails, 1)
		return fmt.Errorf("sluice server fingerprint mismatch on resumption (got sha256:%s)", hex.EncodeToString(sum[:]))
	}
}

// verifyPinnedFingerprint returns a VerifyPeerCertificate callback that
// enforces a strict SHA-256 equality check on the leaf server cert.
// Accepts EITHER the primary OR secondary fingerprint; secondary is
// non-empty only during a Sluice dual-pin rotation grace window.
func verifyPinnedFingerprint(primary, secondary []byte) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			atomic.AddInt64(&statCDRFingerprintFails, 1)
			return errors.New("sluice server presented no certificate")
		}
		sum := sha256.Sum256(rawCerts[0])
		if fingerprintMatches(sum[:], primary) || fingerprintMatches(sum[:], secondary) {
			return nil
		}
		atomic.AddInt64(&statCDRFingerprintFails, 1)
		return fmt.Errorf("sluice server fingerprint mismatch (got sha256:%s)", hex.EncodeToString(sum[:]))
	}
}

// fingerprintMatches does a constant-time equality check between two
// SHA-256 digests.  Returns false for any length mismatch (including
// a nil `expected` slice — used by verify callbacks as "no secondary
// pin configured").
func fingerprintMatches(got, expected []byte) bool {
	if len(expected) != sha256.Size || len(got) != sha256.Size {
		return false
	}
	var diff byte
	for i := range got {
		diff |= got[i] ^ expected[i]
	}
	return diff == 0
}

// ─── Sanitize (streaming) ───────────────────────────────────────────────────

// Sanitize streams `body` to Sluice with the given header and collects the
// full sanitized response into memory.  Enforces cdrMaxFileSize client-side.
//
// Context deadline is derived from c.cfg.Timeout unless ctx already has a
// deadline sooner than that.
func (c *CDRClient) Sanitize(ctx context.Context, header *pb.SanitizeHeader, body io.Reader) (*CDRResult, error) {
	if header == nil {
		return nil, errors.New("cdr: header required")
	}
	if header.ContentLength > cdrMaxFileSize {
		atomic.AddInt64(&statCDRSanitizeErrors, 1)
		return nil, fmt.Errorf("file_too_large: %d bytes exceeds client cap %d", header.ContentLength, cdrMaxFileSize)
	}

	// Apply our timeout unless caller's deadline is tighter.
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.cfg.Timeout)
		defer cancel()
	}

	stream, err := c.stub.Sanitize(ctx)
	if err != nil {
		atomic.AddInt64(&statCDRSanitizeErrors, 1)
		return nil, fmt.Errorf("cdr: open stream: %w", err)
	}

	if err := sendSanitizeHeader(stream, header); err != nil {
		return nil, err
	}
	if err := sendSanitizeBody(stream, body, c.cfg.ChunkSize); err != nil {
		return nil, err
	}
	return recvSanitizeResponse(stream)
}

// sendSanitizeHeader sends the opening header frame and records an error
// counter on failure.  The header MUST be the first client-to-server message.
func sendSanitizeHeader(stream pb.SluiceService_SanitizeClient, header *pb.SanitizeHeader) error {
	if err := stream.Send(&pb.SanitizeRequest{
		Payload: &pb.SanitizeRequest_Header{Header: header},
	}); err != nil {
		atomic.AddInt64(&statCDRSanitizeErrors, 1)
		return fmt.Errorf("cdr: send header: %w", err)
	}
	return nil
}

// sendSanitizeBody pumps `body` into the stream as chunks of `chunkSize`
// bytes.  Enforces cdrMaxFileSize mid-stream in case the caller lied in the
// header (our body-scanning guard is defence-in-depth here).
func sendSanitizeBody(stream pb.SluiceService_SanitizeClient, body io.Reader, chunkSize int) error {
	buf := make([]byte, chunkSize)
	var sentBytes int64
	for {
		n, rerr := io.ReadFull(body, buf)
		if n > 0 {
			if sentBytes+int64(n) > cdrMaxFileSize {
				_ = stream.CloseSend()
				atomic.AddInt64(&statCDRSanitizeErrors, 1)
				return fmt.Errorf("file_too_large: body exceeded %d bytes mid-stream", cdrMaxFileSize)
			}
			if err := stream.Send(&pb.SanitizeRequest{
				Payload: &pb.SanitizeRequest_Chunk{Chunk: append([]byte(nil), buf[:n]...)},
			}); err != nil {
				atomic.AddInt64(&statCDRSanitizeErrors, 1)
				return fmt.Errorf("cdr: send chunk: %w", err)
			}
			sentBytes += int64(n)
			atomic.AddInt64(&statCDRBytesSent, int64(n))
		}
		if rerr == io.EOF || rerr == io.ErrUnexpectedEOF {
			break
		}
		if rerr != nil {
			atomic.AddInt64(&statCDRSanitizeErrors, 1)
			return fmt.Errorf("cdr: read body: %w", rerr)
		}
	}
	if err := stream.CloseSend(); err != nil {
		atomic.AddInt64(&statCDRSanitizeErrors, 1)
		return fmt.Errorf("cdr: close send: %w", err)
	}
	return nil
}

// recvSanitizeResponse reads the result frame (always first), then drains
// any following chunk frames, and converts the whole reply into a CDRResult.
// Callers get a stable shape decoupled from the protobuf generated types.
func recvSanitizeResponse(stream pb.SluiceService_SanitizeClient) (*CDRResult, error) {
	first, err := stream.Recv()
	if err != nil {
		atomic.AddInt64(&statCDRSanitizeErrors, 1)
		return nil, fmt.Errorf("cdr: recv result: %w", err)
	}
	resMsg, ok := first.Payload.(*pb.SanitizeResponse_Result)
	if !ok || resMsg == nil || resMsg.Result == nil {
		atomic.AddInt64(&statCDRSanitizeErrors, 1)
		return nil, errors.New("cdr: first response was not a SanitizeResult")
	}
	raw := resMsg.Result

	sanitized, err := drainSanitizedChunks(stream, raw.SanitizedSize)
	if err != nil {
		return nil, err
	}

	threats := make([]CDRThreat, 0, len(raw.ThreatsRemoved))
	for _, t := range raw.ThreatsRemoved {
		if t == nil {
			continue
		}
		threats = append(threats, CDRThreat{
			Type:        t.Type,
			Location:    t.Location,
			Description: t.Description,
			Severity:    t.Severity,
		})
	}
	atomic.AddInt64(&statCDRSanitizeTotal, 1)
	atomic.AddInt64(&statCDRThreatsDetected, int64(len(threats)))

	out := &CDRResult{
		Status:        raw.Status,
		OriginalType:  raw.OriginalType,
		OriginalSize:  raw.OriginalSize,
		SanitizedSize: raw.SanitizedSize,
		Threats:       threats,
		ErrorMessage:  raw.ErrorMessage,
		DurationMs:    raw.DurationMs,
		SanitizedData: sanitized,
	}
	if len(raw.SanitizedSha256) == sha256.Size {
		out.SanitizedSHA256 = hex.EncodeToString(raw.SanitizedSha256)
	}
	return out, nil
}

// drainSanitizedChunks reads chunk frames until EOF, accumulating bytes.
// Enforces cdrMaxFileSize so a misbehaving server can't balloon our memory.
// Any non-chunk frame after the result is a protocol violation.
func drainSanitizedChunks(stream pb.SluiceService_SanitizeClient, hintSize int64) ([]byte, error) {
	var out []byte
	if hintSize > 0 {
		out = make([]byte, 0, hintSize)
	}
	for {
		msg, rerr := stream.Recv()
		if rerr == io.EOF {
			return out, nil
		}
		if rerr != nil {
			atomic.AddInt64(&statCDRSanitizeErrors, 1)
			return nil, fmt.Errorf("cdr: recv chunk: %w", rerr)
		}
		chunkMsg, ok := msg.Payload.(*pb.SanitizeResponse_Chunk)
		if !ok {
			atomic.AddInt64(&statCDRSanitizeErrors, 1)
			return nil, errors.New("cdr: unexpected second Result in stream")
		}
		out = append(out, chunkMsg.Chunk...)
		atomic.AddInt64(&statCDRBytesReceived, int64(len(chunkMsg.Chunk)))
		if int64(len(out)) > cdrMaxFileSize {
			atomic.AddInt64(&statCDRSanitizeErrors, 1)
			return nil, fmt.Errorf("cdr: sanitized response exceeded client cap %d", cdrMaxFileSize)
		}
	}
}

// IsFileTooLarge reports whether err represents Sluice's oversize rejection.
// The Sluice dev agreed to return either codes.InvalidArgument with message
// prefix "file_too_large:" OR codes.ResourceExhausted with structured detail.
// Callers use this to skip the circuit breaker — oversize is not a server
// overload signal, it is an application-layer policy refusal.
func IsFileTooLarge(err error) bool {
	if err == nil {
		return false
	}
	if strings.Contains(err.Error(), "file_too_large") {
		return true
	}
	if st, ok := status.FromError(err); ok && st.Code() == codes.InvalidArgument {
		return strings.HasPrefix(st.Message(), "file_too_large")
	}
	return false
}

// ─── Health ─────────────────────────────────────────────────────────────────

// Health returns Sluice's current status, capabilities, and profile list.
func (c *CDRClient) Health(ctx context.Context) (*pb.HealthResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}
	return c.stub.Health(ctx, &pb.HealthRequest{})
}

// RenewCert mints a fresh client cert over the existing mTLS channel.
// The Sluice server reads the caller's current cert from peer auth info,
// validates it against the CA + revocation set, then returns a new cert
// with the same CN.  The old cert keeps working until its NotAfter —
// Sluice does NOT revoke on renewal (would break in-flight streams).
//
// Culvert's health poller calls this when daysUntilExpiry < 30.  See
// cdr_health.go:runRenewFor for the atomic persist path.
func (c *CDRClient) RenewCert(ctx context.Context, req *pb.RenewCertRequest) (*pb.RenewCertResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
	}
	return c.stub.RenewCert(ctx, req)
}

// RevokeClient synchronously revokes a Sluice-side client cert by
// SHA-256 fingerprint.  After it returns, the revoked client's next
// RPC will fail with PermissionDenied.  Self-revocation is refused
// by Sluice (InvalidArgument) — the caller must always target
// ANOTHER client's fingerprint.
func (c *CDRClient) RevokeClient(ctx context.Context, req *pb.RevokeClientRequest) (*pb.RevokeClientResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	return c.stub.RevokeClient(ctx, req)
}

// ─── Enroll ─────────────────────────────────────────────────────────────────

// Enroll is a one-shot bootstrap that exchanges a token for mTLS client
// certificates.  It opens its own short-lived gRPC connection (no persistent
// client yet — certs are what we're about to get) and verifies the server
// cert by the admin-provided fingerprint (TOFU pin).
//
// On success, caller must persist {CaCert, ClientCert, ClientKey, Endpoint}
// and use them for all subsequent RPCs.
//
// operationID (2E-C R8, Sluice v0.3) is the client-minted 128-bit
// operation identity Sluice binds DURABLY to the issued fingerprint
// before responding, so a lost response can be resolved through
// EnrollStatus. Empty = legacy v0.2 exchange with no recovery identity.
func Enroll(ctx context.Context, endpoint, fingerprintHx, token, operationID string) (*pb.EnrollResponse, error) {
	if endpoint == "" {
		return nil, errors.New("cdr.enroll: endpoint required")
	}
	if fingerprintHx == "" {
		return nil, errors.New("cdr.enroll: fingerprint required for TOFU verification")
	}
	if token == "" {
		return nil, errors.New("cdr.enroll: token required")
	}
	conn, ctx, cancel, err := dialCDRBootstrap(ctx, endpoint, fingerprintHx, "cdr.enroll")
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = conn.Close() }()

	resp, err := pb.NewSluiceServiceClient(conn).Enroll(ctx, &pb.EnrollRequest{Token: token, OperationId: operationID})
	if err != nil {
		return nil, fmt.Errorf("cdr.enroll: rpc: %w", err)
	}
	if len(resp.GetClientCert()) == 0 || len(resp.GetClientKey()) == 0 || len(resp.GetCaCert()) == 0 {
		return nil, errors.New("cdr.enroll: server returned incomplete cert bundle")
	}
	return resp, nil
}

// EnrollStatus asks Sluice (v0.3) for the authoritative outcome of an
// enrollment or renewal operation over the same bootstrap channel Enroll
// uses (TOFU pin, no client credential — EnrollStatus is allowed without
// one). Idempotent and side-effect free on the Sluice side.
func EnrollStatus(ctx context.Context, endpoint, fingerprintHx, operationID string) (*pb.EnrollStatusResponse, error) {
	if endpoint == "" || fingerprintHx == "" {
		return nil, errors.New("cdr.enrollstatus: endpoint and fingerprint required")
	}
	if !cdrOperationIDRE.MatchString(operationID) {
		return nil, errors.New("cdr.enrollstatus: invalid operation id")
	}
	conn, ctx, cancel, err := dialCDRBootstrap(ctx, endpoint, fingerprintHx, "cdr.enrollstatus")
	if err != nil {
		return nil, err
	}
	defer cancel()
	defer func() { _ = conn.Close() }()
	resp, err := pb.NewSluiceServiceClient(conn).EnrollStatus(ctx, &pb.EnrollStatusRequest{OperationId: operationID})
	if err != nil {
		return nil, fmt.Errorf("cdr.enrollstatus: rpc: %w", err)
	}
	return resp, nil
}

// dialCDRBootstrap opens the short-lived, fingerprint-pinned, credential-
// less connection shared by Enroll and EnrollStatus.
func dialCDRBootstrap(ctx context.Context, endpoint, fingerprintHx, op string) (*grpc.ClientConn, context.Context, context.CancelFunc, error) {
	tlsCfg, err := buildCDRTLSConfig(CDRClientConfig{ServerFingerprintHx: fingerprintHx})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%s: tls: %w", op, err)
	}
	cancel := context.CancelFunc(func() {})
	if _, ok := ctx.Deadline(); !ok {
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(tlsCfg)))
	if err != nil {
		cancel()
		return nil, nil, nil, fmt.Errorf("%s: dial %s: %w", op, sanitizeLog(endpoint), err)
	}
	return conn, ctx, cancel, nil
}

// EnrollStatus resolves an operation over the pooled mTLS channel (used
// by the health poller to reconcile a renewal whose response was lost).
func (c *CDRClient) EnrollStatus(ctx context.Context, operationID string) (*pb.EnrollStatusResponse, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
	}
	return c.stub.EnrollStatus(ctx, &pb.EnrollStatusRequest{OperationId: operationID})
}
