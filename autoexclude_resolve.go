package main

// autoexclude_resolve.go — the proxy hot-path glue for the adaptive
// decryption-exclusion cache. It owns three responsibilities that must NOT live
// in the pure engine (internal/autoexclude):
//
//  1. resolveFailOpen — reads the matched rule's decryption profile to decide
//     whether this session may fail open. It gates BOTH the learn (Observe) and
//     the read (Contains), so a fail-close rule never populates OR consults the
//     cache — the never-exclude control (critical hosts on fail-close rules are
//     un-poisonable by construction).
//
//  2. classify{Origin,Client}InspectFailure — maps a TLS handshake error to a
//     LEARNABLE reason, or reports "do not learn". It is deliberately fail-safe:
//     only a positive match on a can't-decrypt signal learns; an untrusted/
//     expired origin cert (a Block signal, and the poisoning vector) and every
//     unrecognized error keep today's 502. Misclassification can therefore only
//     ever fail CLOSED (inspect/block), never wrongly bypass.
//
//  3. recordAutoExclude — records a qualifying failure with its client IP and,
//     on the confirm-count promotion, fires the audit + alert + metric that make
//     the "inspection just went dark for this host" event loud (not just a table
//     an operator has to remember to check).

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// resolveFailOpen reports whether the matched rule's decryption profile opts into
// fail-open (OnInspectError=="fail-open"). Fail-safe at eval: a dangling profile
// ref resolves to false (fail-close), so a bad/absent reference can never
// newly-enable auto-exclusion — consistent with the existing invariant that a
// dangling profile can never newly-disable inspection.
func resolveFailOpen(match *PolicyMatch) bool {
	p := resolveDecryptionProfile(match)
	return p != nil && p.OnInspectError == "fail-open"
}

// classifyOriginInspectFailure maps an UPSTREAM (origin-leg) inspect-handshake
// error to a learnable reason. Returns learn=false for the cases that must NOT
// auto-exclude:
//
//   - cert verification failure (untrusted issuer / expired / hostname mismatch)
//     ⇒ this is a Block decision; auto-bypassing it is the exfil vector.
//   - EOF / RST / timeout / anything unrecognized ⇒ fail-closed default.
//
// It learns only the genuine "we cannot decrypt this even though we want to"
// signals: the origin demanded a client certificate, or the TLS parameters are
// unsupported.
func classifyOriginInspectFailure(err error) (AutoExcludeReason, bool) {
	if err == nil {
		return "", false
	}
	if isOriginCertVerifyErr(err) {
		return "", false // Block signal — never learn.
	}
	msg := strings.ToLower(err.Error())
	// Origin requires a client certificate we cannot present (server-observed,
	// non-spoofable). Go surfaces the origin's alert as "tls: certificate required".
	if containsAny(msg, "certificate required", "certificate needed") {
		return autoExReasonClientCert, true
	}
	// Unsupported TLS version/cipher/parameters — the canonical exclusion trigger.
	if containsAny(msg,
		"protocol version not supported", "no supported versions", "unsupported",
		"no cipher suite supported", "handshake failure", "no application protocol") {
		return autoExReasonUnsupported, true
	}
	// Everything else (EOF, reset, timeout, unrecognized) ⇒ do not learn.
	return "", false
}

// isOriginCertVerifyErr reports whether err is an origin certificate VERIFICATION
// failure (untrusted issuer / expired / hostname mismatch) — the class that must
// never be auto-excluded (it is a Block decision, and the poisoning vector). Go
// wraps these in tls.CertificateVerificationError (Go 1.20+) over the x509 types.
func isOriginCertVerifyErr(err error) bool {
	var cve *x509.CertificateInvalidError
	var uae x509.UnknownAuthorityError
	var hne x509.HostnameError
	if errors.As(err, &cve) || errors.As(err, &uae) || errors.As(err, &hne) {
		return true
	}
	msg := strings.ToLower(err.Error())
	if containsAny(msg, "certificate signed by unknown authority", "certificate has expired",
		"certificate is not valid", "certificate is valid for" /* hostname mismatch */) {
		return true
	}
	return strings.Contains(msg, "x509:") && strings.Contains(msg, "verif")
}

// containsAny reports whether s contains any of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// classifyClientInspectFailure maps a CLIENT-leg (forged-leaf) handshake error to
// a learnable reason. It learns ONLY when the client aborted with a certificate
// alert (a genuine pinning rejection): a plain EOF/RST/timeout is not a pinning
// signal and must not populate the cache. This is the spoofable class, so the
// caller additionally requires the confirm-count over distinct client IPs.
func classifyClientInspectFailure(err error) (AutoExcludeReason, bool) {
	if err == nil {
		return "", false
	}
	msg := strings.ToLower(err.Error())
	// TLS alerts a pinning client sends when it rejects our forged leaf.
	if containsAny(msg,
		"bad certificate", "unknown certificate authority", "certificate required",
		"certificate expired", "certificate unknown", "certificate revoked",
		"unknown ca", "access denied", "no application protocol") {
		return autoExReasonClientPinned, true
	}
	return "", false
}

// recordAutoExclude records a qualifying inspect failure and, when the observation
// PROMOTES the host to an active exclusion (confirm-count of distinct client IPs
// reached), fires the audit + alert + metric. Safe to call on any failure site;
// it no-ops if the reason is empty. host is host-only-normalized inside the engine.
func recordAutoExclude(host string, reason AutoExcludeReason, clientIP string) {
	if reason == "" {
		return
	}
	if !autoExclude.Observe(host, reason, clientIP) {
		return // still gathering confirmation, or already excluded
	}
	// Promotion: inspection is now OFF for this host until the entry expires.
	autoExcludeLearns.record(string(reason))
	safeHost := strings.ReplaceAll(host, `"`, "")
	logger.Printf("SSL_AUTOEXCLUDE_LEARN %s -> %q (reason=%s) — inspection bypassed until TTL",
		sanitizeLog(clientIP), sanitizeLog(safeHost), reason)
	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  strings.ReplaceAll(clientIP, `"`, ""),
		Action: "decryption.autoexclude.learn",
		Object: safeHost,
		Detail: fmt.Sprintf("reason=%s; SSL inspection auto-disabled for host until TTL", reason),
	})
	go fireAlert("decryption_autoexclude", AlertPayload{
		Host:   safeHost,
		Detail: fmt.Sprintf("SSL inspection auto-disabled (reason=%s)", reason),
		Source: "proxy",
	})
}

// maybeFailOpenOrigin handles an UPSTREAM (origin-leg) inspect-handshake failure
// under a fail-open profile. It classifies the error, learns a qualifying host,
// and reports whether the caller should RESCUE the current session as a
// transparent bypass (true) instead of returning 502. Learn+rescue happen ONLY
// for the server-observed can't-decrypt signals (unsupported / client-cert-
// required — non-spoofable, so rescuing the current session is safe); a cert-
// verify or unrecognized failure returns false (keep today's 502) and never
// learns. host is the host-only form.
func maybeFailOpenOrigin(r *http.Request, host string, match *PolicyMatch, err error) bool {
	if !resolveFailOpen(match) {
		return false
	}
	reason, learn := classifyOriginInspectFailure(err)
	if !learn {
		return false
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	recordAutoExclude(host, reason, clientIP)
	return true
}

// maybeFailOpenClient learns a CLIENT-leg pinning rejection under a fail-open
// profile. Learn-only: the client already aborted its handshake against our
// forged leaf, so the current session cannot be rescued — the NEXT session to the
// host self-heals via the cache once the confirm-count of distinct clients is met.
func maybeFailOpenClient(r *http.Request, host string, match *PolicyMatch, err error) {
	if !resolveFailOpen(match) {
		return
	}
	reason, learn := classifyClientInspectFailure(err)
	if !learn {
		return
	}
	clientIP, _, _ := net.SplitHostPort(r.RemoteAddr)
	recordAutoExclude(host, reason, clientIP)
}

// autoExcludeHitCounter counts sessions bypassed because of a learned exclusion
// (the self-heal read path). Exposed via metrics.go.
var autoExcludeHitCounter int64

func recordAutoExcludeHit() { atomic.AddInt64(&autoExcludeHitCounter, 1) }

// autoExcludeLearnCounter is a cardinality-capped per-reason learn counter,
// mirroring decProfMintlsRejects. The reason set is a bounded engine enum, but
// the label is inline-sanitized so CodeQL sees the guard.
type autoExcludeLearnCounter struct {
	mu     sync.RWMutex
	counts map[string]*int64
	order  []string
}

var autoExcludeLearns = &autoExcludeLearnCounter{counts: make(map[string]*int64)}

func (c *autoExcludeLearnCounter) record(reason string) {
	if reason == "" {
		return
	}
	c.mu.RLock()
	ctr, ok := c.counts[reason]
	c.mu.RUnlock()
	if ok {
		atomic.AddInt64(ctr, 1)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ctr, ok = c.counts[reason]; ok {
		atomic.AddInt64(ctr, 1)
		return
	}
	var n int64 = 1
	c.counts[reason] = &n
	c.order = append(c.order, reason)
}

func (c *autoExcludeLearnCounter) writePrometheus(w *strings.Builder) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.order) == 0 {
		return
	}
	w.WriteString("\n# HELP culvert_decrypt_autoexclude_total Hosts auto-excluded from SSL inspection (fail-open learn events), by reason\n")
	w.WriteString("# TYPE culvert_decrypt_autoexclude_total counter\n")
	for _, r := range c.order {
		safe := strings.ReplaceAll(r, `"`, "")
		fmt.Fprintf(w, "culvert_decrypt_autoexclude_total{reason=%q} %d\n", safe, atomic.LoadInt64(c.counts[r]))
	}
}
