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
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// failOpenFootprint reports how many decryption profiles opt into fail-open and
// how many DISTINCT policy rules reference such a profile. It is the affirmative
// "can this deployment auto-disable inspection at all" evidence an auditor asks
// for: 0 profiles / 0 rules means the auto-exclusion cache is not just empty but
// inert (nothing can ever learn), which an empty cache alone does not prove. It
// also surfaces over-adoption — a broad rule bound to a fail-open profile shows
// up as a high rule count.
func failOpenFootprint() (profiles, rules int) {
	seen := make(map[string]bool)
	list := globalDecryptionProfiles.List()
	for i := range list { // index-based: Profile is 160 bytes (gocritic rangeValCopy)
		if list[i].OnInspectError != "fail-open" {
			continue
		}
		profiles++
		_, refs := objectReferences("decryption-profile", list[i].Name)
		for j := range refs {
			if key := refs[j].ID; key != "" && !seen[key] {
				seen[key] = true
				rules++
			}
		}
	}
	return profiles, rules
}

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
// error to a learnable reason PLUS whether that reason may LIVE-RESCUE the
// triggering session. It is deliberately narrow (B2/B3): an origin controls its
// own TLS alerts, so a generic origin-emitted failure is NOT proof of decryption
// incompatibility and must never trigger a bypass. Only two signals are trusted:
//
//   - client-cert-required (learn=true, rescue=true): the origin sent a
//     CertificateRequest we structurally cannot satisfy — a specific TLS alert.
//     This is the ONE origin-leg reason permitted to live-rescue the triggering
//     session (B3). Residual risk documented in the operator guide: an
//     attacker-controlled origin under a fail-open rule can demand a client cert
//     to force a bypass — which is why fail-open is an explicit per-profile opt-in
//     and critical hosts belong on fail-close rules.
//   - unsupported-params (learn=true, rescue=false): a genuine TLS-parameter
//     incompatibility our OWN stack detected locally (no version/cipher overlap),
//     not an origin-emitted generic alert. Learn-only — it enters pending
//     learning but never bypasses the triggering session.
//
// Everything else — cert-verify failures (Block signal), generic/origin-emitted
// alerts (handshake_failure, no_application_protocol), EOF/RST/timeout, wrapped
// or ambiguous errors — returns learn=false: fail-closed. Misclassification can
// therefore only ever keep inspecting, never wrongly bypass.
func classifyOriginInspectFailure(err error) (reason AutoExcludeReason, learn, rescue bool) {
	if err == nil || isOriginCertVerifyErr(err) {
		return "", false, false
	}
	msg := strings.ToLower(err.Error())
	// Origin demands a client certificate (specific TLS alert: certificate_required).
	if strings.Contains(msg, "certificate required") {
		return autoExReasonClientCert, true, true
	}
	// The origin selected a TLS version our inspection config does not support — a
	// genuine PER-ORIGIN incompatibility our own (client-side) stack detects, not
	// an origin-emitted generic alert. Learn-only (rescue=false). We deliberately
	// do NOT match "no supported versions satisfy MinVersion and MaxVersion" (a
	// host-independent local config error — it reflects the profile's floor, not
	// the origin, so it would learn every host) nor "no cipher suite supported by
	// both" (a Go SERVER-side string; on the origin leg we are the client, so it
	// never fires — origin cipher mismatch surfaces as the origin's handshake_failure
	// alert, which is correctly dropped as origin-controlled).
	if strings.Contains(msg, "server selected unsupported protocol version") {
		return autoExReasonUnsupported, true, false
	}
	// Generic / ambiguous / origin-controlled failures stay fail-close.
	return "", false, false
}

// isOriginCertVerifyErr reports whether err is an origin certificate VERIFICATION
// failure (untrusted issuer / expired / hostname mismatch) — the class that must
// never be auto-excluded (it is a Block decision, and the poisoning vector). Go
// wraps these in tls.CertificateVerificationError (Go 1.20+) over the x509 types.
func isOriginCertVerifyErr(err error) bool {
	// crypto/x509 returns these by VALUE, so the errors.As targets must be value
	// types (a *CertificateInvalidError target would never match and the check
	// would be dead code — the string fallback below would silently carry it).
	var cve x509.CertificateInvalidError
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

// auditSafe strips quotes and CR/LF so a value cannot forge a field in the audit
// ring / alert payload (log-injection defense-in-depth).
func auditSafe(s string) string {
	r := strings.NewReplacer(`"`, "", "\n", "", "\r", "")
	return r.Replace(s)
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
	// Specific certificate-rejection alerts a pinning client sends when it refuses
	// our forged leaf. Deliberately narrow: no generic "access denied"/handshake
	// failures (ambiguous). Learn-only + confirm-count already bound this path.
	if containsAny(msg,
		"bad certificate", "unknown certificate authority", "unknown ca",
		"certificate expired", "certificate unknown", "certificate revoked") {
		return autoExReasonClientPinned, true
	}
	return "", false
}

// decryptionScope returns the policy-boundary scope (the matched decryption
// profile's stable ID + display name) that owns any exclusion learned for this
// session. A fail-open session always has a concrete profile (resolveFailOpen
// required it), so the ID is non-empty on the learn/read paths.
func decryptionScope(match *PolicyMatch) (id, name string) {
	if p := resolveDecryptionProfile(match); p != nil {
		return p.ID, p.Name
	}
	return "", ""
}

// clientEvidence derives the opaque distinct-client token the confirm-count
// aggregates (B4). It prefers the AUTHENTICATED IDENTITY (true device/user
// independence) and falls back to the client address. IPv6 addresses collapse to
// /64 because a single host legitimately owns the whole prefix (SLAAC/privacy
// churn); IPv4 uses the RAW address — a /24 is a network of many devices, so
// bucketing it would over-collapse a legitimate enterprise fleet behind one NAT.
// Documented NAT/DHCP limitation: unauthenticated devices sharing one egress IP
// count as one client, so a host broken only for such a fleet needs failures from
// two distinct egress IPs (or two authenticated users) before it is excluded.
//
// ADR-0008: the reason gates whether IP-only evidence is ACCEPTABLE. For
// client_pinned — "the spoofable class", where the client fully controls the TLS
// alert it sends against our forged leaf — the raw-IPv4 confirm-count is near-zero
// protection against a deliberate poisoner (two egress IPs trivially meet
// confirmN=2). So an UNAUTHENTICATED client_pinned observation yields an EMPTY
// token, which the engine's Observe discards (it can never contribute toward
// promotion). Only two distinct AUTHENTICATED identities can promote a client_pinned
// exclusion; the operator remedy for unauthenticated pinned apps is the manual SSL
// Bypass list. The origin-observed reasons (client_cert_required, unsupported_params)
// are NOT the spoofable class (the origin, not the client, controls those signals),
// so they keep IP evidence and are unchanged.
func clientEvidence(reason AutoExcludeReason, identity, clientIP string) string {
	if identity != "" {
		return "id:" + identity
	}
	if reason == autoExReasonClientPinned {
		return "" // ADR-0008: IP-only evidence is not accepted for the spoofable class
	}
	if ip := net.ParseIP(clientIP); ip != nil && ip.To4() == nil {
		return "net6:" + ip.Mask(net.CIDRMask(64, 128)).String()
	}
	return "ip:" + clientIP
}

// recordAutoExclude records a qualifying inspect failure for (scope, host) and,
// when the observation PROMOTES it to an active exclusion (confirm-count of
// distinct client-evidence tokens reached), fires the audit + alert + metric.
// Safe to call on any failure site; it no-ops if the reason or scope is empty.
func recordAutoExclude(match *PolicyMatch, host string, reason AutoExcludeReason, id ProxyIdentity) {
	if reason == "" {
		return
	}
	scopeID, scopeName := decryptionScope(match)
	if scopeID == "" {
		return // no fail-open profile to scope to (gated caller, defensive)
	}
	client := clientEvidence(reason, id.Identity, id.ClientIP)
	if client == "" {
		// ADR-0008: an unauthenticated client_pinned observation carries no
		// acceptable evidence. Return BEFORE Observe — not just relying on Observe to
		// skip an empty token — because Observe creates/resets the pending
		// (scope,host,reason) window before it skips the token, so passing "" here
		// could reset an in-flight window and drop already-accumulated AUTHENTICATED
		// tokens (letting IP-only noise indefinitely block the two-identity promotion
		// path). Skipping the call makes empty evidence contribute NOTHING, as intended.
		return
	}
	if !autoExclude.Observe(scopeID, scopeName, host, reason, client) {
		return // still gathering confirmation, or already excluded
	}
	// Promotion: inspection is now OFF for this (scope, host) until the entry expires.
	autoExcludeLearns.record(string(reason), scopeName)
	// Strip quotes AND newlines from the audit/alert fields: host passed the IDNA
	// gate and scope passed nameRe (both newline-free today), but strip inline so a
	// future upstream relaxation can't inject into the audit ring (log-injection DiD).
	safeHost := auditSafe(host)
	safeScope := auditSafe(scopeName)
	logger.Printf("SSL_AUTOEXCLUDE_LEARN %s -> %q (scope=%q reason=%s) — inspection bypassed until TTL",
		sanitizeLog(id.ClientIP), sanitizeLog(safeHost), sanitizeLog(safeScope), reason)
	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  strings.ReplaceAll(id.ClientIP, `"`, ""),
		Action: "decryption.autoexclude.learn",
		Object: safeScope + "/" + safeHost,
		Detail: fmt.Sprintf("scope=%s reason=%s; SSL inspection auto-disabled for this profile+host until TTL", safeScope, reason),
	})
	go fireAlert("decryption_autoexclude", AlertPayload{
		Host:   safeHost,
		Detail: fmt.Sprintf("SSL inspection auto-disabled (profile=%s reason=%s)", safeScope, reason),
		Source: "proxy",
	})
	// F4: feed the promotion-rate detector. A single abnormal-rate alert fires on
	// a threshold crossing (poisoning-campaign signal) — the aggregate the
	// per-host alert above cannot provide.
	maybeFireAutoExcludeSurge(scopeName)
}

// autoExcludeRescueCounter counts LIVE-RESCUE events: sessions transparently
// bypassed on the FIRST client_cert_required origin signal (confirm-count-exempt),
// BEFORE — and independently of — any persistent-cache promotion. This closes the
// F1 observability gap: the promotion path fired audit+alert+metric, but the
// rescue path (which actually stops inspecting the CURRENT session) emitted only a
// log line. A single client colluding with a cert-demanding origin under a
// fail-open rule can force per-session bypasses that never reach the confirm-count
// and so were previously invisible to the audit ring, the SIEM alert stream, and
// metrics. Exposed as culvert_decrypt_autoexclude_rescue_total (metrics.go).
var autoExcludeRescueCounter int64

// recordAutoExcludeRescue makes the live-rescue ACT first-class observability,
// mirroring recordAutoExclude's promotion triple (metric + audit + alert) but
// fired on the rescue itself rather than on confirm-count promotion. It does NOT
// change the security decision (the caller has already decided to bypass); it only
// makes that decision loud and attributable (actor = triggering client IP).
//
// The reason is always ReasonClientCertRequired: the origin classifier returns
// rescue=true for that reason ONLY (pinned by TestClassifyOriginInspectFailure_
// TightenedTriggers), so the caller passes it explicitly rather than threading it
// back through maybeFailOpenOrigin's bool return.
func recordAutoExcludeRescue(match *PolicyMatch, host string, reason AutoExcludeReason, id ProxyIdentity) {
	atomic.AddInt64(&autoExcludeRescueCounter, 1)
	_, scopeName := decryptionScope(match)
	// Strip quotes AND newlines before the audit/alert/log fields (log-injection
	// DiD — same posture as recordAutoExclude).
	safeHost := auditSafe(host)
	safeScope := auditSafe(scopeName)
	safeClient := auditSafe(id.ClientIP)
	logger.Printf("SSL_AUTOEXCLUDE_RESCUE %s -> %q (scope=%q reason=%s) — current session bypassed on first signal (confirm-count-exempt)",
		sanitizeLog(id.ClientIP), sanitizeLog(safeHost), sanitizeLog(safeScope), reason)
	auditAdd(AuditEntry{
		TS:     time.Now().UnixMilli(),
		Time:   time.Now().Format("2006-01-02 15:04:05"),
		Actor:  strings.ReplaceAll(id.ClientIP, `"`, ""),
		Action: "decryption.autoexclude.rescue",
		Object: safeScope + "/" + safeHost,
		Detail: fmt.Sprintf("scope=%s reason=%s; live-rescue: this session bypassed SSL inspection (confirm-count-exempt; the persistent exclusion still requires the confirm-count)", safeScope, reason),
	})
	// Detail carries host AND client because alerts.Store.Dispatch suppresses
	// duplicates for 30s keyed on event+Detail (internal/alerts/store.go): a
	// per-profile-only Detail would collapse rescues to DIFFERENT hosts/clients in
	// the same window into one alert — hiding the very repeated-evasion pattern this
	// exposes. Including both makes each distinct (host, client) a distinct alert.
	go fireAlert("decryption_autoexclude_rescue", AlertPayload{
		Host:   safeHost,
		Detail: fmt.Sprintf("SSL inspection live-bypassed for one session (host=%s client=%s profile=%s reason=%s)", safeHost, safeClient, safeScope, reason),
		Source: "proxy",
	})
}

// maybeFailOpenOrigin handles an UPSTREAM (origin-leg) inspect-handshake failure
// under a fail-open profile. It classifies the error, learns a qualifying host,
// and reports whether the caller should RESCUE the current session as a
// transparent bypass (true) instead of returning 502. Only client-cert-required
// (a specific, structured signal) may rescue the triggering session (B3);
// unsupported-params learns but returns false (the next session self-heals). A
// cert-verify or unrecognized failure returns false and never learns.
func maybeFailOpenOrigin(host string, match *PolicyMatch, id ProxyIdentity, err error) (rescue bool) {
	if !resolveFailOpen(match) {
		return false
	}
	reason, learn, rescueOK := classifyOriginInspectFailure(err)
	if !learn {
		return false
	}
	recordAutoExclude(match, host, reason, id)
	return rescueOK
}

// maybeFailOpenClient learns a CLIENT-leg pinning rejection under a fail-open
// profile. Learn-only: the client already aborted its handshake against our
// forged leaf, so the current session cannot be rescued — the NEXT session to the
// (scope, host) self-heals via the cache once the confirm-count is met.
func maybeFailOpenClient(host string, match *PolicyMatch, id ProxyIdentity, err error) {
	if !resolveFailOpen(match) {
		return
	}
	reason, learn := classifyClientInspectFailure(err)
	if !learn {
		return
	}
	recordAutoExclude(match, host, reason, id)
}

// autoExcludeHitCounter counts sessions bypassed because of a learned exclusion
// (the self-heal read path). Exposed via metrics.go.
var autoExcludeHitCounter int64

func recordAutoExcludeHit() { atomic.AddInt64(&autoExcludeHitCounter, 1) }

// autoExcludeLearnCounter is a cardinality-capped {reason,scope} learn counter,
// mirroring decProfMintlsRejects. The reason set is a bounded engine enum and the
// scope is an admin-created profile name (validated charset), but the pair is
// capped defensively and inline-sanitized so CodeQL sees the guard.
type autoExcludeLearnCounter struct {
	mu     sync.RWMutex
	counts map[string]*learnLabel
	order  []string
}

type learnLabel struct {
	reason string
	scope  string
	n      int64
}

const maxAutoExcludeLabels = 200 // bound {reason,scope} cardinality

var autoExcludeLearns = &autoExcludeLearnCounter{counts: make(map[string]*learnLabel)}

func (c *autoExcludeLearnCounter) record(reason, scope string) {
	if reason == "" {
		return
	}
	k := reason + "\x00" + scope
	c.mu.RLock()
	ll, ok := c.counts[k]
	c.mu.RUnlock()
	if ok {
		atomic.AddInt64(&ll.n, 1)
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if ll, ok = c.counts[k]; ok {
		atomic.AddInt64(&ll.n, 1)
		return
	}
	if len(c.order) >= maxAutoExcludeLabels {
		k = reason + "\x00_other_" // fold overflow scopes into a shared bucket
		scope = "_other_"
		if ll, ok = c.counts[k]; ok {
			atomic.AddInt64(&ll.n, 1)
			return
		}
	}
	c.counts[k] = &learnLabel{reason: reason, scope: scope, n: 1}
	c.order = append(c.order, k)
}

func (c *autoExcludeLearnCounter) writePrometheus(w *strings.Builder) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if len(c.order) == 0 {
		return
	}
	w.WriteString("\n# HELP culvert_decrypt_autoexclude_total Hosts auto-excluded from SSL inspection (fail-open learn events), by reason and profile scope\n")
	w.WriteString("# TYPE culvert_decrypt_autoexclude_total counter\n")
	for _, k := range c.order {
		ll := c.counts[k]
		reason := strings.ReplaceAll(ll.reason, `"`, "")
		scope := strings.ReplaceAll(ll.scope, `"`, "")
		fmt.Fprintf(w, "culvert_decrypt_autoexclude_total{reason=%q,scope=%q} %d\n", reason, scope, atomic.LoadInt64(&ll.n))
	}
}
