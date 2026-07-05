package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"google.golang.org/grpc/credentials"
)

// ─── TLS helpers ──────────────────────────────────────────────────────────────

// cpTLSConfig holds a reference to the server TLS config so that the cert
// pool can be rebuilt dynamically when the cluster CA is rotated.
var cpTLSConfig struct {
	mu      sync.Mutex
	cfg     *tls.Config
	baseCAF string // path to base CA file (operator-provided)
}

// rebuildCPCertPool rebuilds the TLS client CA pool with the base CA file
// plus all active cluster CAs (primary + secondary overlap).
// Called by globalClusterCA.onRotate after import or cleanup.
func rebuildCPCertPool() {
	cpTLSConfig.mu.Lock()
	defer cpTLSConfig.mu.Unlock()
	if cpTLSConfig.cfg == nil {
		return
	}
	pool := x509.NewCertPool()
	if cpTLSConfig.baseCAF != "" {
		caPath := filepath.Clean(cpTLSConfig.baseCAF)
		if !strings.Contains(caPath, "..") {
			if pemData, err := os.ReadFile(caPath); err == nil { // #nosec G304 -- admin CLI flag, ".." rejected
				pool.AppendCertsFromPEM(pemData)
			}
		}
	}
	if allCA := globalClusterCA.AllCACertsPEM(); len(allCA) > 0 {
		pool.AppendCertsFromPEM(allCA)
	}
	cpTLSConfig.cfg.ClientCAs = pool
	logger.Printf("ControlPlane: TLS client CA pool rebuilt")
}

// getCPTLSConfigForClient is the per-handshake snapshot hook for the
// CP-side TLS config. Invoked by the stdlib once per ClientHello.
// CA-7 fix: the stdlib was previously reading cpTLSConfig.cfg.ClientCAs
// directly during the handshake (unsynchronized) while rebuildCPCertPool
// wrote that same field under cpTLSConfig.mu — confirmed data race in
// TestCA7_CpTLSConfig_ClientCAsConcurrentReadVsWrite_Race pre-fix.
// Routing the read through this callback takes cpTLSConfig.mu and
// returns a Clone() whose ClientCAs is a pointer to the (immutable
// post-publication) *x509.CertPool. A concurrent rebuild assigns a
// NEW pool to the original cfg.ClientCAs field; the clone keeps the
// pointer to the OLD pool — different memory location, no race.
func getCPTLSConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	cpTLSConfig.mu.Lock()
	defer cpTLSConfig.mu.Unlock()
	if cpTLSConfig.cfg == nil {
		return nil, nil // stdlib falls back to listener cfg
	}
	return cpTLSConfig.cfg.Clone(), nil
}

func buildServerTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	if strings.Contains(certFile, "..") || strings.Contains(keyFile, "..") || strings.Contains(caFile, "..") {
		return nil, fmt.Errorf("invalid cert/key/ca path: directory traversal not allowed")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		// Add all active cluster CAs (primary + secondary overlap).
		if allCA := globalClusterCA.AllCACertsPEM(); len(allCA) > 0 {
			pool.AppendCertsFromPEM(allCA)
		}
		tlsCfg.ClientCAs = pool
		// VerifyClientCertIfGiven allows unenrolled nodes to call Enroll
		// without a client cert, while still verifying certs from enrolled nodes.
		tlsCfg.ClientAuth = tls.VerifyClientCertIfGiven

		// CA-7 fix: route per-handshake reads through getCPTLSConfigForClient
		// so concurrent rebuildCPCertPool writes cannot race with the
		// stdlib's cfg.ClientCAs read inside processCertsFromClient.
		tlsCfg.GetConfigForClient = getCPTLSConfigForClient

		// Store reference for dynamic cert pool rebuild on CA rotation.
		cpTLSConfig.mu.Lock()
		cpTLSConfig.cfg = tlsCfg
		cpTLSConfig.baseCAF = caFile
		cpTLSConfig.mu.Unlock()

		// Wire up the rotation callback so ImportCA/CleanupSecondary
		// rebuild the pool automatically.
		globalClusterCA.mu.Lock()
		globalClusterCA.onRotate = rebuildCPCertPool
		globalClusterCA.mu.Unlock()
	}
	return credentials.NewTLS(tlsCfg), nil
}

func buildClientTLS(certFile, keyFile, caFile string) (credentials.TransportCredentials, error) {
	// CA-3: the DP node key may be encrypted at rest (PSCA envelope). The
	// loader decrypts it when needed (content-driven, fail closed); a plaintext
	// key is loaded unchanged. The cert is always plaintext PEM.
	cert, err := loadDPNodeKeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, err
		}
		tlsCfg.RootCAs = pool
	}
	return credentials.NewTLS(tlsCfg), nil
}

func loadCertPool(caFile string) (*x509.CertPool, error) {
	// Guard: reject directory traversal in CLI-provided CA path.
	cleaned := filepath.Clean(caFile)
	if strings.Contains(cleaned, "..") {
		return nil, fmt.Errorf("invalid CA path: directory traversal not allowed")
	}
	pool := x509.NewCertPool()
	pemData, err := os.ReadFile(cleaned) // #nosec G304 -- admin-provided CLI flag, ".." rejected above
	if err != nil {
		return nil, err
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("no valid certificates in %s", sanitizeLog(caFile))
	}
	return pool, nil
}
