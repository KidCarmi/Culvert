// Package ocsp is the OCSP revocation-checking engine for upstream TLS
// certificates: a TTL'd verdict cache plus the responder query pipeline
// behind a tls.Config VerifyPeerCertificate callback. Extracted from package
// main per ADR-0002; the transport wiring (ConfigureTLSConfigOCSP /
// ConfigureTransportOCSP, under the P5.3 upstream-transport ownership
// contract) and the globalOCSP singleton stay in main (ocsp.go shim).
//
// When enabled, the proxy verifies that upstream server certificates have not
// been revoked by checking OCSP stapled responses and, as a fallback, querying
// OCSP responders listed in the certificate's AIA extension.
package ocsp

import (
	"bytes"
	"context"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/KidCarmi/Culvert/internal/obs"
	cryptoocsp "golang.org/x/crypto/ocsp"
)

// Checker performs OCSP-based revocation checking for TLS connections.
type Checker struct {
	enabled atomic.Bool
	mu      sync.RWMutex
	cache   map[string]*cacheEntry // serial hex → result
}

type cacheEntry struct {
	revoked   bool
	expiresAt time.Time
}

const (
	cacheTTL     = 1 * time.Hour
	cacheMaxSize = 5000
	queryTimeout = 5 * time.Second
)

// New returns a Checker with an empty verdict cache (disabled until Enable).
func New() *Checker {
	return &Checker{cache: make(map[string]*cacheEntry)}
}

// Enable turns on OCSP checking.
func (oc *Checker) Enable() {
	oc.enabled.Store(true)
}

// Disable turns off OCSP checking.
func (oc *Checker) Disable() {
	oc.enabled.Store(false)
}

// Enabled returns whether OCSP checking is active.
func (oc *Checker) Enabled() bool {
	return oc.enabled.Load()
}

// CacheLen returns the number of entries in the OCSP cache.
func (oc *Checker) CacheLen() int {
	oc.mu.RLock()
	defer oc.mu.RUnlock()
	return len(oc.cache)
}

// resolveIssuer extracts the issuer certificate from verified chains or raw certs.
func resolveIssuer(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) *x509.Certificate {
	if len(verifiedChains) > 0 && len(verifiedChains[0]) > 1 {
		return verifiedChains[0][1]
	}
	if len(rawCerts) > 1 {
		issuer, err := x509.ParseCertificate(rawCerts[1])
		if err != nil {
			obs.Printf("OCSP: failed to parse issuer cert: %v", err)
		}
		return issuer
	}
	return nil
}

// checkCached returns (revoked, found). If found, the caller can return early.
func (oc *Checker) checkCached(serialHex string) (revoked, found bool) {
	oc.mu.RLock()
	entry, ok := oc.cache[serialHex]
	oc.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.revoked, true
	}
	return false, false
}

// cacheResult stores an OCSP result with TTL and evicts if needed.
func (oc *Checker) cacheResult(serialHex string, revoked bool) {
	oc.mu.Lock()
	if len(oc.cache) >= cacheMaxSize {
		// Evict expired entries first, then oldest 10% if still over capacity.
		now := time.Now()
		for k, e := range oc.cache {
			if now.After(e.expiresAt) {
				delete(oc.cache, k)
			}
		}
		if len(oc.cache) >= cacheMaxSize {
			count := 0
			for k := range oc.cache {
				delete(oc.cache, k)
				count++
				if count >= cacheMaxSize/10 {
					break
				}
			}
		}
	}
	oc.cache[serialHex] = &cacheEntry{
		revoked:   revoked,
		expiresAt: time.Now().Add(cacheTTL),
	}
	oc.mu.Unlock()
}

// VerifyPeerCertificate is a tls.Config.VerifyPeerCertificate callback that
// checks OCSP revocation status for the peer's leaf certificate.
func (oc *Checker) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
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
// Fail-closed: returns true (revoked) if ALL responders fail, preventing
// acceptance of certificates when revocation status cannot be determined.
func (oc *Checker) checkResponders(leaf, issuer *x509.Certificate) bool {
	anyResponded := false
	for _, responderURL := range leaf.OCSPServer {
		rev, err := oc.queryOCSP(leaf, issuer, responderURL)
		if err != nil {
			continue
		}
		anyResponded = true
		if rev {
			return true // confirmed revoked
		}
	}
	if !anyResponded && len(leaf.OCSPServer) > 0 {
		obs.Printf("OCSP: all %d responder(s) unreachable for cert %s — fail-closed (treating as revoked)",
			len(leaf.OCSPServer), leaf.SerialNumber.Text(16))
		return true // fail-closed: treat as revoked when no responder reachable
	}
	return false
}

// queryOCSP sends an OCSP request to the responder and returns whether the
// certificate is revoked.
func (oc *Checker) queryOCSP(leaf, issuer *x509.Certificate, responderURL string) (bool, error) {
	ocspReq, err := cryptoocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return false, fmt.Errorf("ocsp create request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
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

	ocspResp, err := cryptoocsp.ParseResponse(respBytes, issuer)
	if err != nil {
		return false, fmt.Errorf("ocsp parse response: %w", err)
	}

	return ocspResp.Status == cryptoocsp.Revoked, nil
}

// CleanupCache evicts expired entries from the OCSP cache.
func (oc *Checker) CleanupCache() {
	oc.mu.Lock()
	now := time.Now()
	for k, e := range oc.cache {
		if now.After(e.expiresAt) {
			delete(oc.cache, k)
		}
	}
	oc.mu.Unlock()
}
