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

	// Fail-closed / revocation counters (P-blindspot: surfaced via
	// /api/ocsp so an admin can see mass HTTPS breakage caused by
	// unreachable OCSP responders without grepping logs for
	// "fail-closed").
	failClosedTotal   atomic.Int64
	revokedTotal      atomic.Int64
	lastFailClosedUTC atomic.Int64 // unix seconds; 0 = never
}

type cacheEntry struct {
	revoked    bool
	failClosed bool // revoked BECAUSE responders were unreachable (not a confirmed revocation)
	expiresAt  time.Time
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

// FailClosedTotal returns the number of times a peer certificate was treated
// as revoked because every OCSP responder listed on it was unreachable.
func (oc *Checker) FailClosedTotal() int64 {
	return oc.failClosedTotal.Load()
}

// RevokedTotal returns the number of times an OCSP responder confirmed a
// peer certificate as actually revoked.
func (oc *Checker) RevokedTotal() int64 {
	return oc.revokedTotal.Load()
}

// LastFailClosedAt returns the time of the most recent fail-closed event, or
// the zero time if none has occurred.
func (oc *Checker) LastFailClosedAt() time.Time {
	ts := oc.lastFailClosedUTC.Load()
	if ts == 0 {
		return time.Time{}
	}
	return time.Unix(ts, 0).UTC()
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

// checkCached returns (revoked, failClosed, found). If found, the caller can
// return early. failClosed distinguishes a cached fail-closed verdict (all
// responders were unreachable) from a cached confirmed revocation, so the
// caller can keep the fail-closed counter/timestamp current across the whole
// outage rather than only at the first cache miss.
func (oc *Checker) checkCached(serialHex string) (revoked, failClosed, found bool) {
	oc.mu.RLock()
	entry, ok := oc.cache[serialHex]
	oc.mu.RUnlock()
	if ok && time.Now().Before(entry.expiresAt) {
		return entry.revoked, entry.failClosed, true
	}
	return false, false, false
}

// cacheResult stores an OCSP result with TTL and evicts if needed.
func (oc *Checker) cacheResult(serialHex string, revoked, failClosed bool) {
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
		revoked:    revoked,
		failClosed: failClosed,
		expiresAt:  time.Now().Add(cacheTTL),
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

	if revoked, failClosed, found := oc.checkCached(serialHex); found {
		if revoked {
			if failClosed {
				// Sustained outage: the cache short-circuits checkResponders,
				// so without this the fail-closed counter/timestamp would
				// reflect only the FIRST cache miss and the panel would
				// under-report a still-ongoing outage. Count every cached
				// fail-closed block and keep last-occurrence current.
				oc.failClosedTotal.Add(1)
				oc.lastFailClosedUTC.Store(time.Now().Unix())
				return fmt.Errorf("ocsp: certificate %s is revoked (fail-closed, cached)", serialHex)
			}
			return fmt.Errorf("ocsp: certificate %s is revoked (cached)", serialHex)
		}
		return nil
	}

	revoked, failClosed := oc.checkResponders(leaf, issuer)
	oc.cacheResult(serialHex, revoked, failClosed)

	if revoked {
		return fmt.Errorf("ocsp: certificate %s is revoked", serialHex)
	}
	return nil
}

// checkResponders queries each OCSP responder listed in the leaf certificate.
// Fail-closed: returns revoked=true if ALL responders fail, preventing
// acceptance of certificates when revocation status cannot be determined.
// failClosed reports whether that revoked verdict came from the outage path
// (all responders unreachable) rather than a confirmed revocation, so the
// caller can cache the reason. This first-miss path increments the counters;
// the caller re-increments on subsequent cached fail-closed hits.
func (oc *Checker) checkResponders(leaf, issuer *x509.Certificate) (revoked, failClosed bool) {
	anyResponded := false
	for _, responderURL := range leaf.OCSPServer {
		rev, err := oc.queryOCSP(leaf, issuer, responderURL)
		if err != nil {
			continue
		}
		anyResponded = true
		if rev {
			oc.revokedTotal.Add(1)
			return true, false // confirmed revoked
		}
	}
	if !anyResponded && len(leaf.OCSPServer) > 0 {
		obs.Printf("OCSP: all %d responder(s) unreachable for cert %s — fail-closed (treating as revoked)",
			len(leaf.OCSPServer), leaf.SerialNumber.Text(16))
		oc.failClosedTotal.Add(1)
		oc.lastFailClosedUTC.Store(time.Now().Unix())
		return true, true // fail-closed: treat as revoked when no responder reachable
	}
	return false, false
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
