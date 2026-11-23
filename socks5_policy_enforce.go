package main

// socks5_policy_enforce.go — SWG-901: proxy.socks5_policy_mode: enforce.
//
// The Stage-2 verdict decides the connection, with the CONNECT dispatcher's
// semantics (applyPolicyDecision) mapped onto what a SOCKS5 server can say:
//
//	match == nil, default allow → proceed, request log "OK default-allow Allow"
//	match == nil, default deny  → reply 0x02, POLICY_DEFAULT_DENY
//	unknown action              → reply 0x02, POLICY_BLOCK (SEC-POLICYACTION-1)
//	Drop                        → no reply, RST (SO_LINGER 0), POLICY_DROP (D6)
//	Block_Page                  → reply 0x02, POLICY_BLOCK
//	Redirect                    → reply 0x02, POLICY_REDIRECT (a raw tunnel cannot redirect)
//	Allow + TLS inspection      → reply 0x02, POLICY_BLOCK, action inspection_unsupported
//	Allow                       → proceed to the SSRF guard and dial; the OK entry carries the rule
//
// 0x02 is RFC 1928's "connection not allowed by ruleset". It is the real
// decision path, so — unlike shadow — it charges exactly what a CONNECT
// charges: PolicyStore.Evaluate (rule hit counter and last-hit stamp),
// ruleMet (Prometheus rule hits), statBlocked, and one request-log entry per
// decision with identity, rule name, rule ID and auth source. A panic in the
// evaluator is NOT recovered here: it unwinds into handleSOCKS5's
// recoverGoroutine, which closes the connection — fail closed.
//
// Learning observation stays out of SOCKS5: the request-path learning wall
// test lists this file.

import (
	"net"
	"sync/atomic"
)

// socks5EnforcePolicy evaluates the destination with the resolved principal and
// dispatches the verdict. It returns the grant and true when the connection
// may proceed; false means it has refused it.
func socks5EnforcePolicy(conn net.Conn, who ProxyIdentity, host string, atyp byte) (socks5Grant, bool) {
	noteSOCKS5RequestATYP(atyp)
	policyHost := socks5PolicyHost(host)
	match := policyStore.Evaluate(who.ClientIP, who.Identity, who.AuthSource, policyHost, who.Groups)
	var rule *PolicyRule
	if match != nil {
		rule = match.Rule
		ruleMet.RecordHit(match.Rule.Name) // the CONNECT dispatcher's first act on any match
	}
	v := classifySOCKS5Policy(rule, defaultPolicyAllows())
	// The CONNECT SSL decision, side effects included (explicit bypass-list and
	// learned fail-open exclusions are its generic exceptions): if CONNECT
	// would inspect this tunnel, SOCKS5 cannot serve it.
	if !v.refuse && match != nil && resolveSSLDecision(match, policyHost, who.ClientIP).Action == SSLInspect {
		v.refuse, v.reason = true, socks5ReasonInspection
	}
	noteSOCKS5PolicyDecision(socks5PolicyEnforce, v)
	if v.refuse {
		refuseSOCKS5ByPolicy(conn, who, host, match, v)
		return socks5Grant{}, false
	}
	if match == nil {
		return socks5Grant{ruleMatched: "default-allow", actionTaken: string(ActionAllow)}, true
	}
	return socks5Grant{match: match, ruleMatched: match.Rule.Name, actionTaken: string(ActionAllow)}, true
}

// socks5RefusalStatus is the request-log status and actionTaken for a refusal
// by a matched rule — the CONNECT dispatcher's taxonomy, plus the one reason
// CONNECT never needs (inspection_unsupported, recorded as a POLICY_BLOCK so
// SIEM/UI status filters keep working).
func socks5RefusalStatus(match *PolicyMatch, reason string) (status, actionTaken string) {
	if reason == socks5ReasonInspection {
		return "POLICY_BLOCK", socks5ReasonInspection
	}
	action, known := canonicalPolicyAction(match.Action)
	switch {
	case !known:
		return "POLICY_BLOCK", string(match.Action)
	case action == ActionDrop:
		return "POLICY_DROP", string(ActionDrop)
	case action == ActionRedirect:
		return "POLICY_REDIRECT", string(ActionRedirect)
	}
	return "POLICY_BLOCK", string(ActionBlockPage)
}

// refuseSOCKS5ByPolicy records and executes an enforce refusal: statBlocked, one
// request-log entry, one log line, then reply 0x02 — or, for Drop, no reply and
// an RST. Accounting lands BEFORE the reply: the reply is what the client
// observes, so anything recorded after it races a reader acting on the refusal.
func refuseSOCKS5ByPolicy(conn net.Conn, who ProxyIdentity, host string, match *PolicyMatch, v socks5Verdict) {
	clientIP := who.ClientIP
	fields := socks5LogFields(who)
	atomic.AddInt64(&statBlocked, 1)
	if match == nil {
		recordRequestAuth(clientIP, "SOCKS5", host, "POLICY_DEFAULT_DENY", "", "", who.Identity, fields)
		logger.Printf("SOCKS5 POLICY_DEFAULT_DENY %s -> %q {mode=enforce reason=default identity=%s auth_source=%s action_taken=deny}",
			clientIP, sanitizeLog(host), sanitizeLogFieldToken(who.Identity), sanitizeLogFieldToken(who.AuthSource))
		socks5Reply(conn, 0x02)
		return
	}
	fields.RuleID = match.Rule.ID
	status, actionTaken := socks5RefusalStatus(match, v.reason)
	recordRequestAuth(clientIP, "SOCKS5", host, status, match.Rule.Name, actionTaken, who.Identity, fields)
	logger.Printf("SOCKS5 %s %s -> %q {mode=enforce reason=%s rule=%q rule_id=%q action=%q identity=%s auth_source=%s action_taken=%s}",
		sanitizeLogFieldToken(status), clientIP, sanitizeLog(host), sanitizeLogFieldToken(v.reason),
		sanitizeLogFieldToken(match.Rule.Name), sanitizeLogFieldToken(match.Rule.ID), sanitizeLogFieldToken(string(match.Action)),
		sanitizeLogFieldToken(who.Identity), sanitizeLogFieldToken(who.AuthSource), sanitizeLogFieldToken(actionTaken))
	if status == "POLICY_DROP" {
		socks5Reset(conn)
		return
	}
	socks5Reply(conn, 0x02)
}

// socks5Reset arms an RST for the caller's deferred Close (SO_LINGER 0): the
// SOCKS5 analogue of the CONNECT Drop's hijack-and-close — the client sees the
// connection die with no reply, as for any covert drop (proposal D6).
func socks5Reset(conn net.Conn) {
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetLinger(0)
	}
}
