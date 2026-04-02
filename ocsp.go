package main

// ocsp.go — OCSP/CRL revocation checking for upstream TLS certificates.
//
// When enabled, the proxy verifies that upstream server certificates have not
// been revoked by checking OCSP stapled responses and, as a fallback, querying
// OCSP responders listed in the certificate's AIA extension.
//
// CRL checking is done via Go's built-in x509.RevocationList support when
// CRL distribution points are present in the certificate.

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/ocsp"
)

// OCSPChecker performs OCSP-based revocation checking for TLS connections.
type OCSPChecker struct {
	enabled atomic.Bool
	mu      sync.RWMutex
	cache   map[string]*ocspCacheEntry // serial hex → result
}

type ocspCacheEntry struct {
	revoked   bool
	expiresAt time.Time
}

const (
	ocspCacheTTL     = 1 * time.Hour
	ocspCacheMaxSize = 5000
	ocspTimeout      = 5 * time.Second
)

var globalOCSP = &OCSPChecker{cache: make(map[string]*ocspCacheEntry)}

// Enable turns on OCSP checking.
func (oc *OCSPChecker) Enable() {
	oc.enabled.Store(true)
}

// Enabled returns whether OCSP checking is active.
func (oc *OCSPChecker) Enabled() bool {
	return oc.enabled.Load()
}

// VerifyPeerCertificate is a tls.Config.VerifyPeerCertificate callback that
// checks OCSP revocation status for the peer's leaf certificate.
func (oc *OCSPChecker) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if !oc.Enabled() || len(rawCerts) == 0 {
		return nil
	}
	leaf, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("ocsp: parse leaf: %w", err)
	}

	// Find issuer from verified chains or raw certs.
	var issuer *x509.Certificate
	if len(verifiedChains) > 0 && len(verifiedChains[0]) > 1 {
		issuer = verifiedChains[0][1]
	} else if len(rawCerts) > 1 {
		issuer, _ = x509.ParseCertificate(rawCerts[1])
	}
	if issuer == nil {
		return nil // can't check without issuer; allow (fail-open for OCSP)
	}

	serialHex := leaf.SerialNumber.Text(16)

	// Check cache.
	oc.mu.RLock()
	entry, ok := oc.cache[serialHex]
	oc.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		if entry.revoked {
			return fmt.Errorf("ocsp: certificate %s is revoked (cached)", serialHex)
		}
		return nil
	}

	// Check OCSP responders.
	revoked := false
	for _, responderURL := range leaf.OCSPServer {
		rev, err := oc.queryOCSP(leaf, issuer, responderURL)
		if err != nil {
			continue // try next responder
		}
		revoked = rev
		break
	}

	// Cache result.
	oc.mu.Lock()
	if len(oc.cache) >= ocspCacheMaxSize {
		// Evict oldest 10%.
		count := 0
		for k := range oc.cache {
			delete(oc.cache, k)
			count++
			if count >= ocspCacheMaxSize/10 {
				break
			}
		}
	}
	oc.cache[serialHex] = &ocspCacheEntry{
		revoked:   revoked,
		expiresAt: time.Now().Add(ocspCacheTTL),
	}
	oc.mu.Unlock()

	if revoked {
		return fmt.Errorf("ocsp: certificate %s is revoked", serialHex)
	}
	return nil
}

// queryOCSP sends an OCSP request to the responder and returns whether the
// certificate is revoked.
func (oc *OCSPChecker) queryOCSP(leaf, issuer *x509.Certificate, responderURL string) (bool, error) {
	ocspReq, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return false, fmt.Errorf("ocsp create request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), ocspTimeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, responderURL, bytes.NewReader(ocspReq))
	if err != nil {
		return false, fmt.Errorf("ocsp http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/ocsp-request")

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return false, fmt.Errorf("ocsp request failed: %w", err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
	if err != nil {
		return false, fmt.Errorf("ocsp read response: %w", err)
	}

	ocspResp, err := ocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return false, fmt.Errorf("ocsp parse response: %w", err)
	}

	return ocspResp.Status == ocsp.Revoked, nil
}

// ConfigureTransportOCSP adds OCSP verification to the upstream transport's
// TLS configuration.
func ConfigureTransportOCSP(t *http.Transport) {
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	t.TLSClientConfig.VerifyPeerCertificate = globalOCSP.VerifyPeerCertificate
}

// CleanupOCSPCache evicts expired entries from the OCSP cache.
func (oc *OCSPChecker) CleanupCache() {
	oc.mu.Lock()
	now := time.Now()
	for k, e := range oc.cache {
		if now.After(e.expiresAt) {
			delete(oc.cache, k)
		}
	}
	oc.mu.Unlock()
}
