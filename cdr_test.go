package main

// Phase 1 tests for the Sluice CDR client.
//
// Strategy:
//   - Most functional tests run against a fake Sluice gRPC server over
//     bufconn (in-memory, no TLS).  This validates the wire contract:
//     header-first, result-first-then-chunks, Mode handling, error paths.
//   - TOFU fingerprint verification is exercised in a separate block that
//     spins up a real TLS listener on localhost with a self-signed cert.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/KidCarmi/Sluice/proto/sluicev1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// ─── Fake Sluice server ──────────────────────────────────────────────────────

// fakeSluice is a scripted gRPC server used by the bufconn tests.  The test
// sets Script before making the call.
type fakeSluice struct {
	pb.UnimplementedSluiceServiceServer

	mu sync.Mutex

	// Header received from the client during the last Sanitize call.
	lastHeader *pb.SanitizeHeader
	// Concatenated body bytes received from the client.
	lastBody []byte

	// Result to send.
	result *pb.SanitizeResult
	// Chunks to stream after the result.  If nil, no chunks are sent
	// (matches CLEAN / BLOCKED / ERROR / UNSUPPORTED cases).
	replyChunks [][]byte

	// Health response to return.
	health *pb.HealthResponse
	// Enroll response to return.
	enroll *pb.EnrollResponse
	// Force Enroll to return an error.
	enrollErr error
}

func (f *fakeSluice) Sanitize(stream pb.SluiceService_SanitizeServer) error {
	// 1) First client message must be a header.
	first, err := stream.Recv()
	if err != nil {
		return err
	}
	hdr, ok := first.Payload.(*pb.SanitizeRequest_Header)
	if !ok || hdr == nil {
		return status.Error(codes.InvalidArgument, "first message must be header")
	}
	f.mu.Lock()
	f.lastHeader = hdr.Header
	f.lastBody = nil
	f.mu.Unlock()

	// 2) Drain chunks.
	var body []byte
	for {
		msg, rerr := stream.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return rerr
		}
		chunk, ok := msg.Payload.(*pb.SanitizeRequest_Chunk)
		if !ok {
			return status.Error(codes.InvalidArgument, "expected chunk")
		}
		body = append(body, chunk.Chunk...)
	}
	f.mu.Lock()
	f.lastBody = body
	res := f.result
	chunks := f.replyChunks
	f.mu.Unlock()

	if res == nil {
		res = &pb.SanitizeResult{Status: pb.Status_CLEAN}
	}

	// 3) Result-first, then chunks.
	if err := stream.Send(&pb.SanitizeResponse{
		Payload: &pb.SanitizeResponse_Result{Result: res},
	}); err != nil {
		return err
	}
	for _, c := range chunks {
		if err := stream.Send(&pb.SanitizeResponse{
			Payload: &pb.SanitizeResponse_Chunk{Chunk: c},
		}); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeSluice) Health(ctx context.Context, _ *pb.HealthRequest) (*pb.HealthResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.health != nil {
		return f.health, nil
	}
	return &pb.HealthResponse{Healthy: true, Version: "test"}, nil
}

func (f *fakeSluice) Enroll(ctx context.Context, _ *pb.EnrollRequest) (*pb.EnrollResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.enrollErr != nil {
		return nil, f.enrollErr
	}
	if f.enroll != nil {
		return f.enroll, nil
	}
	return &pb.EnrollResponse{
		CaCert:     []byte("CA"),
		ClientCert: []byte("CLIENT"),
		ClientKey:  []byte("KEY"),
		Endpoint:   "sluice:8443",
	}, nil
}

// RevokeClient is a minimal success stub used by the
// cdr_revoke_rpc_no_versioning_test. It returns the v0.3 durable-deny
// PROOF (outcome REVOKED) without validating the request body; the test
// that depends on this exercises the apiCDRRevokeRPC handler's success
// path past the gRPC call. An EMPTY response is deliberately no longer
// the default — 2E-C R6 refuses it as unproven (see tlFakeSluice).
func (f *fakeSluice) RevokeClient(_ context.Context, _ *pb.RevokeClientRequest) (*pb.RevokeClientResponse, error) {
	return &pb.RevokeClientResponse{Revoked: true, Outcome: pb.RevokeOutcome_REVOKE_OUTCOME_REVOKED}, nil
}

// startFakeSluice brings up a bufconn-backed gRPC server with the given
// server impl and returns a dialed CDRClient.  The caller defers stop.
func startFakeSluice(t *testing.T, srv *fakeSluice) (client *CDRClient, stop func()) {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	s := grpc.NewServer()
	pb.RegisterSluiceServiceServer(s, srv)
	go func() { _ = s.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	client = newCDRClientFromConn(conn, CDRClientConfig{
		Endpoint:  "bufnet",
		Timeout:   5 * time.Second,
		ChunkSize: 1024,
	})
	return client, func() {
		_ = client.Close()
		s.Stop()
		_ = lis.Close()
	}
}

// ─── Tests: Sanitize wire contract ──────────────────────────────────────────

func TestCDRClient_Sanitize_Clean(t *testing.T) {
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:       pb.Status_CLEAN,
			OriginalType: "DOCX",
			OriginalSize: 512,
			DurationMs:   12,
		},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	body := bytes.Repeat([]byte{0x42}, 512)
	res, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		Filename:      "clean.docx",
		ContentType:   "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
		ContentLength: int64(len(body)),
		RequestId:     "req-1",
		ProfileName:   "default",
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if res.Status != pb.Status_CLEAN {
		t.Fatalf("status = %v, want CLEAN", res.Status)
	}
	if len(res.SanitizedData) != 0 {
		t.Fatalf("expected no sanitized data for CLEAN, got %d bytes", len(res.SanitizedData))
	}
	if res.DurationMs != 12 {
		t.Fatalf("duration_ms = %d, want 12", res.DurationMs)
	}
	if got := srv.lastHeader.GetFilename(); got != "clean.docx" {
		t.Fatalf("server saw filename=%q, want clean.docx", got)
	}
	if !bytes.Equal(srv.lastBody, body) {
		t.Fatalf("server body mismatch")
	}
}

func TestCDRClient_Sanitize_WithThreatsAndSHA256(t *testing.T) {
	clean := []byte("CLEAN_DOCUMENT_BYTES")
	sum := sha256.Sum256(clean)
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:          pb.Status_SANITIZED,
			OriginalType:    "DOCM",
			OriginalSize:    int64(len(clean)) + 100,
			SanitizedSize:   int64(len(clean)),
			SanitizedSha256: sum[:],
			DurationMs:      47,
			ThreatsRemoved: []*pb.Threat{
				{Type: "macro", Location: "Module1", Description: "VBA AutoOpen", Severity: "high"},
			},
		},
		replyChunks: [][]byte{clean[:10], clean[10:]},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	res, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		Filename:      "macro.docm",
		ContentLength: int64(len(clean)) + 100,
		ProfileName:   "default",
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader(make([]byte, int(len(clean))+100)))
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if res.Status != pb.Status_SANITIZED {
		t.Fatalf("status = %v, want SANITIZED", res.Status)
	}
	if !bytes.Equal(res.SanitizedData, clean) {
		t.Fatalf("sanitized body mismatch")
	}
	if len(res.Threats) != 1 || res.Threats[0].Type != "macro" || res.Threats[0].Severity != "high" {
		t.Fatalf("threats = %+v, want 1 macro/high", res.Threats)
	}
	if want := hex.EncodeToString(sum[:]); res.SanitizedSHA256 != want {
		t.Fatalf("sha256 = %q, want %q", res.SanitizedSHA256, want)
	}
}

func TestCDRClient_Sanitize_Blocked(t *testing.T) {
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:       pb.Status_BLOCKED,
			ErrorMessage: "file_entirely_macro",
		},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	res, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		Filename:      "trojan.docm",
		ContentLength: 256,
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader(make([]byte, 256)))
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if res.Status != pb.Status_BLOCKED {
		t.Fatalf("status = %v, want BLOCKED", res.Status)
	}
	if res.ErrorMessage == "" {
		t.Fatalf("expected error_message to propagate")
	}
}

func TestCDRClient_Sanitize_Error(t *testing.T) {
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:       pb.Status_ERROR,
			ErrorMessage: "unknown_profile: vip-relaxed",
		},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	res, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		ContentLength: 32,
		ProfileName:   "vip-relaxed",
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader(make([]byte, 32)))
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if res.Status != pb.Status_ERROR {
		t.Fatalf("status = %v, want ERROR", res.Status)
	}
	if !strings.HasPrefix(res.ErrorMessage, "unknown_profile:") {
		t.Fatalf("error_message = %q", res.ErrorMessage)
	}
}

func TestCDRClient_Sanitize_ReportOnlyReturnsOriginal(t *testing.T) {
	// Simulate REPORT_ONLY semantics: server echoes original bytes as
	// "sanitized" and populates threats without mutation.
	original := []byte("ORIGINAL_BYTES_ABCDEFGHIJKLMN")
	sum := sha256.Sum256(original)
	srv := &fakeSluice{
		result: &pb.SanitizeResult{
			Status:          pb.Status_SANITIZED,
			OriginalSize:    int64(len(original)),
			SanitizedSize:   int64(len(original)),
			SanitizedSha256: sum[:],
			ThreatsRemoved: []*pb.Threat{
				{Type: "javascript", Severity: "medium"},
			},
		},
		replyChunks: [][]byte{original},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	res, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		ContentLength: int64(len(original)),
		Mode:          pb.Mode_REPORT_ONLY,
	}, bytes.NewReader(original))
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if !bytes.Equal(res.SanitizedData, original) {
		t.Fatalf("REPORT_ONLY must return original bytes byte-for-byte")
	}
	if srv.lastHeader.GetMode() != pb.Mode_REPORT_ONLY {
		t.Fatalf("server saw mode=%v, want REPORT_ONLY", srv.lastHeader.GetMode())
	}
	if len(res.Threats) != 1 {
		t.Fatalf("threats missing in REPORT_ONLY mode")
	}
}

func TestCDRClient_Sanitize_UnsupportedPassesThrough(t *testing.T) {
	srv := &fakeSluice{
		result: &pb.SanitizeResult{Status: pb.Status_UNSUPPORTED},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	res, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		ContentLength: 10,
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader([]byte("1234567890")))
	if err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if res.Status != pb.Status_UNSUPPORTED {
		t.Fatalf("status = %v, want UNSUPPORTED", res.Status)
	}
}

func TestCDRClient_Sanitize_RejectsOversizeClientSide(t *testing.T) {
	// Server should never see this — client aborts on header inspection.
	srv := &fakeSluice{}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	_, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		ContentLength: cdrMaxFileSize + 1,
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader(nil))
	if err == nil || !strings.Contains(err.Error(), "file_too_large") {
		t.Fatalf("expected file_too_large error, got %v", err)
	}
	if srv.lastHeader != nil {
		t.Fatalf("server should not have received the header")
	}
}

func TestCDRClient_Sanitize_StreamChunksAtChunkSize(t *testing.T) {
	// Body larger than ChunkSize => multiple stream messages.
	body := bytes.Repeat([]byte("x"), 10_000)
	srv := &fakeSluice{
		result: &pb.SanitizeResult{Status: pb.Status_CLEAN, OriginalSize: int64(len(body))},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()
	c.cfg.ChunkSize = 1024 // force ~10 chunks

	if _, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		ContentLength: int64(len(body)),
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader(body)); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if !bytes.Equal(srv.lastBody, body) {
		t.Fatalf("chunked body mismatch: got %d bytes, want %d", len(srv.lastBody), len(body))
	}
}

// ─── Tests: helpers ─────────────────────────────────────────────────────────

func TestIsFileTooLarge(t *testing.T) {
	if IsFileTooLarge(nil) {
		t.Fatal("nil should not match")
	}
	if !IsFileTooLarge(errors.New("file_too_large: 99 bytes")) {
		t.Fatal("plain error prefix missed")
	}
	if !IsFileTooLarge(status.Error(codes.InvalidArgument, "file_too_large: over cap")) {
		t.Fatal("gRPC InvalidArgument prefix missed")
	}
	if IsFileTooLarge(status.Error(codes.InvalidArgument, "bad_argument: other")) {
		t.Fatal("unrelated InvalidArgument must not match")
	}
	if IsFileTooLarge(status.Error(codes.Unavailable, "server down")) {
		t.Fatal("Unavailable must not match")
	}
}

// ─── Tests: Health + Enroll ─────────────────────────────────────────────────

func TestCDRClient_Health_IncludesProfiles(t *testing.T) {
	srv := &fakeSluice{
		health: &pb.HealthResponse{
			Healthy: true,
			Version: "v0.1.0",
			Profiles: []*pb.Profile{
				{Name: "default", Description: "baseline", MaxFileSizeBytes: 52428800},
			},
		},
	}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	resp, err := c.Health(context.Background())
	if err != nil {
		t.Fatalf("Health: %v", err)
	}
	if !resp.Healthy || resp.Version != "v0.1.0" {
		t.Fatalf("health response unexpected: %+v", resp)
	}
	if len(resp.Profiles) != 1 || resp.Profiles[0].Name != "default" {
		t.Fatalf("profiles = %+v", resp.Profiles)
	}
}

// ─── Tests: TOFU fingerprint pinning over real TLS ──────────────────────────

// generateSelfSignedECDSA creates a minimal self-signed ECDSA P-256 cert
// valid for 1h with SAN "localhost" and IP 127.0.0.1.
func generateSelfSignedECDSA(t *testing.T) (certPEM, keyPEM []byte, der []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "sluice-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err = x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	return
}

func TestCDRClient_Fingerprint_MatchAccepts(t *testing.T) {
	certPEM, keyPEM, der := generateSelfSignedECDSA(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fpBytes := sha256.Sum256(der)
	fpHex := hex.EncodeToString(fpBytes[:])

	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	pb.RegisterSluiceServiceServer(srv, &fakeSluice{
		health: &pb.HealthResponse{Healthy: true, Version: "fp-ok"},
	})

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewCDRClient(CDRClientConfig{
		Endpoint:            lis.Addr().String(),
		ServerFingerprintHx: fpHex,
	})
	if err != nil {
		t.Fatalf("NewCDRClient: %v", err)
	}
	defer c.Close()

	resp, err := c.Health(ctx)
	if err != nil {
		t.Fatalf("Health over TLS: %v", err)
	}
	if resp.Version != "fp-ok" {
		t.Fatalf("unexpected response: %+v", resp)
	}
}

func TestCDRClient_Fingerprint_MismatchRejects(t *testing.T) {
	certPEM, keyPEM, _ := generateSelfSignedECDSA(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	// Wrong fingerprint — 32 zero bytes.
	wrong := strings.Repeat("00", 32)

	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	pb.RegisterSluiceServiceServer(srv, &fakeSluice{})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, err := NewCDRClient(CDRClientConfig{
		Endpoint:            lis.Addr().String(),
		ServerFingerprintHx: wrong,
	})
	if err != nil {
		t.Fatalf("NewCDRClient: %v", err)
	}
	defer c.Close()

	_, err = c.Health(ctx)
	if err == nil {
		t.Fatal("expected fingerprint mismatch to fail the handshake")
	}
	if !strings.Contains(err.Error(), "fingerprint mismatch") &&
		!strings.Contains(err.Error(), "certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildCDRTLSConfig_RequiresPinOrCA(t *testing.T) {
	_, err := buildCDRTLSConfig(CDRClientConfig{})
	if err == nil {
		t.Fatal("expected error when neither fingerprint nor CA is supplied")
	}
}

func TestBuildCDRTLSConfig_InvalidFingerprint(t *testing.T) {
	_, err := buildCDRTLSConfig(CDRClientConfig{ServerFingerprintHx: "not-hex"})
	if err == nil {
		t.Fatal("expected invalid-hex error")
	}
	// Too short
	_, err = buildCDRTLSConfig(CDRClientConfig{ServerFingerprintHx: "abcd"})
	if err == nil {
		t.Fatal("expected length error")
	}
}

// TestFingerprintMatches — constant-time comparator behaves correctly
// for matching, mismatching, and zero-length inputs.
func TestFingerprintMatches(t *testing.T) {
	a := sha256.Sum256([]byte("hello"))
	b := sha256.Sum256([]byte("world"))
	if !fingerprintMatches(a[:], a[:]) {
		t.Fatal("same digest must match")
	}
	if fingerprintMatches(a[:], b[:]) {
		t.Fatal("different digests must not match")
	}
	if fingerprintMatches(a[:], nil) {
		t.Fatal("nil secondary must not match")
	}
	if fingerprintMatches(nil, a[:]) {
		t.Fatal("nil got must not match")
	}
}

// TestDualPin_VerifyAcceptsEither — verify callback accepts either the
// primary or secondary fingerprint, rejects all others.
func TestDualPin_VerifyAcceptsEither(t *testing.T) {
	primary := sha256.Sum256([]byte("primary"))
	secondary := sha256.Sum256([]byte("secondary"))
	other := sha256.Sum256([]byte("other"))

	verify := verifyPinnedFingerprint(primary[:], secondary[:])

	// Primary cert bytes: fake raw bytes whose sha256 happens to be
	// `primary` — we can't construct arbitrary preimages, so test via
	// the raw bytes directly: the verify fn hashes rawCerts[0], so
	// a cert whose raw == "primary" should produce digest == primary.
	if err := verify([][]byte{[]byte("primary")}, nil); err != nil {
		t.Fatalf("primary must verify: %v", err)
	}
	if err := verify([][]byte{[]byte("secondary")}, nil); err != nil {
		t.Fatalf("secondary must verify: %v", err)
	}
	if err := verify([][]byte{[]byte("other")}, nil); err == nil {
		t.Fatal("unrelated cert must NOT verify")
	}
	_ = other // keep linter happy
}

// TestDualPin_EmptySecondaryIsSinglePin — when no secondary is provided,
// behaviour is identical to single-pin: only primary accepted.
func TestDualPin_EmptySecondaryIsSinglePin(t *testing.T) {
	primary := sha256.Sum256([]byte("primary"))
	verify := verifyPinnedFingerprint(primary[:], nil)

	if err := verify([][]byte{[]byte("primary")}, nil); err != nil {
		t.Fatalf("primary must verify: %v", err)
	}
	if err := verify([][]byte{[]byte("other")}, nil); err == nil {
		t.Fatal("without secondary, only primary should verify")
	}
}

// TestBuildCDRTLSConfig_SecondaryWithinWindow — when secondary is set
// AND within the validity window, the resulting tls.Config's verify
// callback accepts both digests.  We can't introspect the callback's
// closure, so test behaviour indirectly by checking the config was
// built without error.
func TestBuildCDRTLSConfig_SecondaryWithinWindow(t *testing.T) {
	primary := sha256.Sum256([]byte("a"))
	secondary := sha256.Sum256([]byte("b"))
	cfg, err := buildCDRTLSConfig(CDRClientConfig{
		ServerFingerprintHx:    hex.EncodeToString(primary[:]),
		SecondaryFingerprintHx: hex.EncodeToString(secondary[:]),
		SecondaryValidUntil:    time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if cfg.VerifyPeerCertificate == nil {
		t.Fatal("verify callback missing")
	}
	if err := cfg.VerifyPeerCertificate([][]byte{[]byte("a")}, nil); err != nil {
		t.Fatalf("primary must verify: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{[]byte("b")}, nil); err != nil {
		t.Fatalf("secondary must verify within window: %v", err)
	}
}

// TestBuildCDRTLSConfig_SecondaryExpiredIgnored — expired secondary is
// silently dropped; only primary accepted.
func TestBuildCDRTLSConfig_SecondaryExpiredIgnored(t *testing.T) {
	primary := sha256.Sum256([]byte("a"))
	secondary := sha256.Sum256([]byte("b"))
	cfg, err := buildCDRTLSConfig(CDRClientConfig{
		ServerFingerprintHx:    hex.EncodeToString(primary[:]),
		SecondaryFingerprintHx: hex.EncodeToString(secondary[:]),
		SecondaryValidUntil:    time.Now().Add(-time.Minute), // expired
	})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{[]byte("a")}, nil); err != nil {
		t.Fatalf("primary must verify: %v", err)
	}
	if err := cfg.VerifyPeerCertificate([][]byte{[]byte("b")}, nil); err == nil {
		t.Fatal("secondary past window must NOT verify")
	}
}

// TestNormalisePinHex — covers colon stripping, prefix stripping, case.
func TestNormalisePinHex(t *testing.T) {
	cases := map[string]string{
		"":             "",
		"  aB:cD  ":    "abcd",
		"sha256:aB:cD": "abcd",
		"SHA256:ABCD":  "abcd",
		"abcd":         "abcd",
	}
	for in, want := range cases {
		if got := normalisePinHex(in); got != want {
			t.Errorf("normalisePinHex(%q) = %q, want %q", in, got, want)
		}
	}
}

// ─── Tests: Enroll ──────────────────────────────────────────────────────────

func TestEnroll_ReturnsCertBundle(t *testing.T) {
	// Real TLS listener + bootstrap fingerprint.
	certPEM, keyPEM, der := generateSelfSignedECDSA(t)
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	fpBytes := sha256.Sum256(der)
	fpHex := hex.EncodeToString(fpBytes[:])

	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	pb.RegisterSluiceServiceServer(srv, &fakeSluice{
		enroll: &pb.EnrollResponse{
			CaCert:     []byte("CA-PEM"),
			ClientCert: []byte("CLIENT-PEM"),
			ClientKey:  []byte("KEY-PEM"),
			Endpoint:   "sluice:8443",
		},
	})
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() { _ = srv.Serve(lis) }()
	defer srv.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := Enroll(ctx, lis.Addr().String(), fpHex, "one-time-token", "")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if string(resp.ClientCert) != "CLIENT-PEM" || string(resp.ClientKey) != "KEY-PEM" {
		t.Fatalf("enroll response missing certs: %+v", resp)
	}
}

func TestEnroll_RejectsEmptyInputs(t *testing.T) {
	ctx := context.Background()
	if _, err := Enroll(ctx, "", "fp", "tok", ""); err == nil {
		t.Fatal("empty endpoint must fail")
	}
	if _, err := Enroll(ctx, "host:1", "", "tok", ""); err == nil {
		t.Fatal("empty fingerprint must fail")
	}
	if _, err := Enroll(ctx, "host:1", strings.Repeat("ab", 32), "", ""); err == nil {
		t.Fatal("empty token must fail")
	}
}

// Sanity: ensure counters actually move — non-zero delta after a call.
func TestCDRClient_CountersMove(t *testing.T) {
	srv := &fakeSluice{result: &pb.SanitizeResult{Status: pb.Status_CLEAN}}
	c, stop := startFakeSluice(t, srv)
	defer stop()

	before := statCDRSanitizeTotal
	if _, err := c.Sanitize(context.Background(), &pb.SanitizeHeader{
		ContentLength: 4,
		Mode:          pb.Mode_ENFORCE,
	}, bytes.NewReader([]byte("data"))); err != nil {
		t.Fatalf("Sanitize: %v", err)
	}
	if statCDRSanitizeTotal <= before {
		t.Fatalf("statCDRSanitizeTotal did not advance (before=%d after=%d)", before, statCDRSanitizeTotal)
	}
}

// Compile-time assertion that fakeSluice satisfies the interface — catches
// regressions if the generated server surface changes with a proto update.
var _ pb.SluiceServiceServer = (*fakeSluice)(nil)

// Suppress unused import warnings if parts of this file are commented out
// during iteration.
var _ = fmt.Sprintf
