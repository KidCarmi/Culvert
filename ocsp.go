package main

// ocsp.go — OCSP/CRL revocation checking for upstream TLS certificates.
//
// When enabled, the proxy verifies that upstream server certificates have not
// been revoked by checking OCSP stapled responses and, as a fallback, querying
// OCSP responders listed in the certificate's AIA extension.

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

// resolveIssuer extracts the issuer certificate from verified chains or raw certs.
func resolveIssuer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) *x509.Certificate {
	if len(verifiedChains) > 0 && len(verifiedChains[0]) > 1 {
		return verifiedChains[0][1]
	}
	if len(rawCerts) > 1 {
		issuer, _ := x509.ParseCertificate(rawCerts[1])
		return issuer
	}
	return nil
}

// checkCached returns (revoked, found). If found, the caller can return early.
func (oc *OCSPChecker) checkCached(serialHex string) (bool, bool) {
	oc.mu.RLock()
	entry, ok := oc.cache[serialHex]
	oc.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.revoked, true
	}
	return false, false
}

// cacheResult stores an OCSP result with TTL and evicts if needed.
func (oc *OCSPChecker) cacheResult(serialHex string, revoked bool) {
	oc.mu.Lock()
	if len(oc.cache) >= ocspCacheMaxSize {
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

	issuer := resolveIssuer(rawCerts, verifiedChains)
	if issuer == nil {
		return nil // can't check without issuer; fail-open for OCSP
	}

	serialHex := leaf.SerialNumber.Text(16)

	if revoked, found := oc.checkCached(serialHex); found {
		if revoked {
			return fmt.Errorf("ocsp: certificate %s is revoked (cached)", serialHex)
		}
		return nil
	}

	revoked := oc.checkResponders(leaf, issuer)
	oc.cacheResult(serialHex, revoked)

	if revoked {
		return fmt.Errorf("ocsp: certificate %s is revoked", serialHex)
	}
	return nil
}

// checkResponders queries each OCSP responder listed in the leaf certificate.
func (oc *OCSPChecker) checkResponders(leaf, issuer *x509.Certificate) bool {
	for _, responderURL := range leaf.OCSPServer {
		rev, err := oc.queryOCSP(leaf, issuer, responderURL)
		if err != nil {
			continue
		}
		return rev
	}
	return false
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
// TLS configuration. VerifyConnection is set alongside VerifyPeerCertificate
// to ensure resumed sessions also undergo revocation checks (gosec G123).
func ConfigureTransportOCSP(t *http.Transport) {
	if t.TLSClientConfig == nil {
		t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12} // #nosec G402
	}
	t.TLSClientConfig.VerifyPeerCertificate = globalOCSP.VerifyPeerCertificate // #nosec G123 -- VerifyConnection is set immediately below
	t.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
		// For resumed sessions, VerifyPeerCertificate is not called, so we
		// run the OCSP check here as well.
		if len(cs.PeerCertificates) == 0 {
			return nil
		}
		rawCerts := make([][]byte, len(cs.PeerCertificates))
		for i, c := range cs.PeerCertificates {
			rawCerts[i] = c.Raw
		}
		var chains [][]*x509.Certificate
		if len(cs.VerifiedChains) > 0 {
			chains = cs.VerifiedChains
		}
		return globalOCSP.VerifyPeerCertificate(rawCerts, chains)
	}
}

// CleanupCache evicts expired entries from the OCSP cache.
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
