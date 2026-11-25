package main

// mtls_client_cert_retry.go — automatic completion of a configured upstream
// mTLS client certificate (proxy.client_cert_file + proxy.client_key_file)
// that could not be loaded at STARTUP.
//
// loadMTLSAndOCSP tolerates the failure: it logs it and upstream connections
// proceed WITHOUT a client certificate. Until this file that was permanent.
// An upstream that requires mutual TLS rejects every connection from the
// node, and the upstream_mtls_client_cert row told the operator to replace
// the files AND restart Culvert. The restart was toil: reading the two
// configured paths is exactly what startup already tried, and a secret volume
// that mounts a moment after the process, a certificate an issuer had not
// written yet or a key with the wrong ownership are all fixed on disk.
//
// This loop re-attempts the SAME two paths on the cadence the deferred
// audit-log open uses (audit_persist_retry.go). It chooses nothing, touches no
// settings and creates no configuration version. Once the pair loads, the
// node presents it exactly as it would have after the restart.
//
// It is NOT a rotation. A certificate that loaded at startup is never
// re-read: an expired or replaced file on a node whose certificate loaded
// still needs a restart, as before. The installation is re-checked under the
// upstream-transport write lock (swapUpstreamTransport), and refuses when the
// operator's TLS template already carries a client certificate.
//
// Refusal boundaries, re-checked on every attempt: nothing armed (startup
// loaded the pair, none is configured, or only one of the two files is
// configured — a configuration error no file on disk can repair), a client
// certificate is already installed, or the lifecycle context is cancelled.
//
// One difference from a restart, on the strict side: the TLS floor is never
// lowered. Startup's mTLS branch sets TLS 1.2 on an unset floor before the
// OCSP branch can set TLS 1.3; when the certificate failed at startup and
// OCSP checking is on, the floor is already TLS 1.3 and stays there until the
// next restart.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// crashComponentMTLSClientCertRetry names the deferred client-certificate
// load in the crash plane.
const crashComponentMTLSClientCertRetry = "mtls_client_cert_load_retry"

// mtlsDeferredLoad is the armed intent. mu serializes attempts and guards the
// two paths; both are "" when nothing is armed. armed mirrors "certFile is
// set" so the diagnostics page can read it without waiting behind an attempt
// that is blocked reading a stalled volume.
var mtlsDeferredLoad struct {
	mu       sync.Mutex
	certFile string
	keyFile  string
	armed    atomic.Bool
}

// setMTLSDeferredLoadLocked replaces the armed intent. Caller holds mu.
func setMTLSDeferredLoadLocked(certFile, keyFile string) {
	mtlsDeferredLoad.certFile, mtlsDeferredLoad.keyFile = certFile, keyFile
	mtlsDeferredLoad.armed.Store(certFile != "")
}

// armMTLSClientCertDeferredLoad records that the configured pair whose
// startup load just failed should be loaded once it becomes readable. Called
// only from the boot path (loadMTLSClientCert), and only when BOTH files are
// configured.
func armMTLSClientCertDeferredLoad(certFile, keyFile string) {
	if certFile == "" || keyFile == "" {
		return
	}
	mtlsDeferredLoad.mu.Lock()
	setMTLSDeferredLoadLocked(certFile, keyFile)
	mtlsDeferredLoad.mu.Unlock()
	logger.Printf("mTLS: retrying the configured client certificate automatically; it is presented to upstreams once it loads, with no restart")
}

// mtlsClientCertDeferredLoadPending reports whether a deferred load is armed.
// It takes no lock and does no I/O.
func mtlsClientCertDeferredLoadPending() bool {
	return mtlsDeferredLoad.armed.Load()
}

// mtlsLeafNotAfter returns the expiry of c's leaf, or the zero time when the
// leaf does not parse (the load itself already succeeded).
func mtlsLeafNotAfter(c *tls.Certificate) time.Time {
	if len(c.Certificate) == 0 {
		return time.Time{}
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return time.Time{}
	}
	return leaf.NotAfter
}

// installMTLSClientCertIfAbsent puts c on the operator's TLS template and
// publishes a transport carrying it, but only while the template has no
// client certificate. The check and the write happen inside one swap closure,
// under the upstream-transport write lock, so a concurrent OCSP toggle cannot
// interleave. Reports whether it installed.
func installMTLSClientCertIfAbsent(c *tls.Certificate) bool {
	installed := false
	swapUpstreamTransport(func(old *http.Transport) *http.Transport {
		if upstreamOpTLSCfg != nil && len(upstreamOpTLSCfg.Certificates) > 0 {
			return nil // already installed: no swap, nothing replaced
		}
		if upstreamOpTLSCfg == nil {
			upstreamOpTLSCfg = &tls.Config{} // #nosec G402 -- MinVersion set on the next line
		}
		// Same floor as the startup mTLS branch, and like it only on an
		// unset floor: an existing floor (TLS 1.3 from OCSP) is kept.
		if upstreamOpTLSCfg.MinVersion == 0 {
			upstreamOpTLSCfg.MinVersion = tls.VersionTLS12
		}
		upstreamOpTLSCfg.Certificates = []tls.Certificate{*c}
		installed = true
		// The swap attaches a Clone of the updated template.
		return cloneTransport(old)
	})
	return installed
}

// tryMTLSClientCertDeferredLoad makes one attempt to load the armed pair. It
// returns loaded=true with the certificate path once the node presents it.
// loaded=false with a nil error means nothing is pending any more (never
// armed, or a client certificate is already installed) and the caller should
// stop. A non-nil error means the pair still cannot be loaded; the intent
// stays armed and the failure is recorded for the admin API.
func tryMTLSClientCertDeferredLoad() (certFile string, loaded bool, err error) {
	mtlsDeferredLoad.mu.Lock()
	defer mtlsDeferredLoad.mu.Unlock()
	certFile, keyFile := mtlsDeferredLoad.certFile, mtlsDeferredLoad.keyFile
	if certFile == "" {
		return "", false, nil
	}
	c, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		recordMTLSClientCertStatus(certFile, false, time.Time{}, err.Error())
		return certFile, false, fmt.Errorf("mtls client certificate load: %w", err)
	}
	setMTLSDeferredLoadLocked("", "")
	if !installMTLSClientCertIfAbsent(&c) {
		return certFile, false, nil
	}
	recordMTLSClientCertStatus(certFile, true, mtlsLeafNotAfter(&c), "")
	return certFile, true, nil
}

// startMTLSClientCertLoadRetry runs the deferred load until it succeeds, is
// disarmed, or ctx is cancelled. Started from the background-services slice.
// Returns at once (no timer) when startup loaded the pair or none is
// configured.
func startMTLSClientCertLoadRetry(ctx context.Context) {
	// Same bounded cadence as the audit log: 10s doubling to 2m, 25% jitter.
	runMTLSClientCertLoadRetry(ctx, auditOpenRetryDelay)
}

// runMTLSClientCertLoadRetry is the loop with the backoff injected so tests
// drive it without wall-clock waits. Single goroutine; attempts are
// additionally serialized inside tryMTLSClientCertDeferredLoad.
func runMTLSClientCertLoadRetry(ctx context.Context, delay func(attempt int) time.Duration) {
	for failed := 0; mtlsClientCertDeferredLoadPending(); failed++ {
		wait := time.NewTimer(delay(failed))
		select {
		case <-wait.C:
		case <-ctx.Done():
			wait.Stop()
			return
		}
		// Per-ROUND guard (CHAOS-118): this loop is `go`-detached, so an
		// unrecovered panic would take the gateway down over a certificate
		// read. Every lock here is released by defer, so a recovered round
		// simply counts as a failed attempt.
		finished := false
		panicked := runGuarded(crashComponentMTLSClientCertRetry, func() {
			finished = attemptMTLSClientCertLoadRetry(ctx, failed+1)
		})
		if finished && !panicked {
			return
		}
	}
}

// attemptMTLSClientCertLoadRetry makes one attempt. It reports true when the
// loop is finished: the certificate is now presented, or nothing is pending
// any more.
func attemptMTLSClientCertLoadRetry(ctx context.Context, attempt int) bool {
	if ctx.Err() != nil {
		return true
	}
	certFile, loaded, err := tryMTLSClientCertDeferredLoad()
	switch {
	case err != nil:
		if attempt == 1 || attempt%auditOpenRetryLogEvery == 0 {
			logger.Printf("mTLS: automatic load attempt %d of the configured client certificate failed (%q) — still retrying; upstream connections proceed without a client certificate until it loads",
				attempt, sanitizeLog(err.Error()))
		}
		return false
	case !loaded:
		return true
	}
	logger.Printf("mTLS: the configured client certificate %q became loadable — loaded automatically on attempt %d; new upstream connections now present it",
		sanitizeLog(certFile), attempt)
	// Attributed to "system": no human asked for this load at this moment.
	auditSystem("upstream_mtls.client_cert.auto_load", certFile,
		fmt.Sprintf("upstream mTLS client certificate loaded automatically: the certificate and key configured at startup could not be loaded and became loadable on attempt %d; upstream connections carried no client certificate before this point", attempt))
	return true
}
