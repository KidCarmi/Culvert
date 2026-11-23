package main

// socks5_auth.go — SOCKS5 method selection and RFC 1929 USER/PASS (SWG-901
// stage 3).
//
// RFC 1929 is a NON-interactive, password-only exchange, so SOCKS5 resolves a
// credential through the shared proxy credential resolver on its password-only
// channel (proxy_credential.go, credentialChannelSOCKS5):
//
//   - supported: IdP-registry LDAP profiles (directory bind) and a legacy
//     (YAML) LDAP provider — the same providers, order, caches and resulting
//     identity/groups/auth source as HTTP proxy Basic for the same credential;
//   - refused: OIDC (token introspection; interactive login) and SAML
//     (browser-only) identities — refused cleanly with reason
//     provider_not_supported_for_socks5 — and the local admin-console account,
//     which is never a SOCKS5 identity and never a fallback.
//
// A NO-AUTH client (offered only when no credential backend exists at all and
// proxy authentication has never been established, ADR-0063) is "unauth" with
// no identity.

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync/atomic"
)

// socks5UnauthSource is the auth source of a SOCKS5 client that negotiated
// NO-AUTH: the value HTTP stamps when no credentials were presented
// (resolveRequestAuth), so Stage-2 rules scoped to "unauth" mean the same
// thing on both listeners.
const socks5UnauthSource = "unauth"

// socks5AuthRequired reports whether SOCKS5 must demand RFC 1929 USER/PASS:
// any account exists (cfg.AuthEnabled, SEC-AUTHENABLED-1) or any validator can
// verify a presented credential — including an IdP-registry profile, which
// cfg.AuthEnabled does not see. It is HTTP Stage-1's credential term
// (credCapable || requiredWithoutVerifier, resolveRequestAuth). The SSO and
// Exempt-default terms do not apply: SOCKS5 has no interactive flow, and it
// has no Stage-1 auth rules (an auth rule with protocol "socks5" is refused at
// validation, authpolicy.go validateAuthProtocol).
//
// Requiring USER/PASS does not mean anything can satisfy it: on a gateway
// whose only accounts are admin-console accounts, or whose only providers are
// OIDC/SAML, every SOCKS5 credential is refused (fail closed) rather than
// NO-AUTH being offered.
//
// The durable proxy-authentication posture (ADR-0063, proxy_auth_posture.go)
// is the third term, mirroring HTTP's requiredWithoutVerifier: once proxy
// authentication has been established, NO-AUTH is never offered again, even
// after the last provider is removed, disabled or fails to load; the client
// must offer USER/PASS and is refused (reason
// socks5AuthReasonPostureNoProvider when nothing at all is left). One atomic
// load, evaluated first.
func socks5AuthRequired() bool {
	return cfg.ProxyAuthEstablished() || cfg.AuthEnabled() || hasCredentialCapableProvider()
}

// SOCKS5 USER/PASS refusal reasons. Bounded: these constants are the only
// values the counter below is indexed by. Neither reaches the client, which
// sees the RFC 1929 failure status only.
const (
	// socks5AuthReasonInvalid: a SOCKS5-capable provider exists and did not
	// accept the credential (wrong password, unknown user, admin-console
	// credential of a user who is not in the directory).
	socks5AuthReasonInvalid = "invalid_credentials"
	// socks5AuthReasonUnsupported: the credential can only belong to a
	// provider SOCKS5 cannot use — nothing password-verifying is configured
	// (only admin-console accounts, OIDC or SAML), or the username's email
	// domain routes to an interactive (OIDC/SAML) profile.
	socks5AuthReasonUnsupported = "provider_not_supported_for_socks5"
	// socks5AuthReasonPostureNoProvider: proxy authentication has been
	// established on this node (ADR-0063) and no proxy identity provider of
	// any kind is left, so nothing can verify the credential.
	socks5AuthReasonPostureNoProvider = "auth_established_no_provider"
)

// socks5AuthFailures counts USER/PASS refusals by reason: invalid,
// unsupported, established-without-provider.
var socks5AuthFailures [3]atomic.Int64

// socks5AuthRefusalReason classifies a refused credential. Only the username
// is consulted (for its email-domain routing hint); the password never is.
func socks5AuthRefusalReason(user string) string {
	if !passwordProviderConfigured() {
		if socks5PostureWithoutProvider() {
			return socks5AuthReasonPostureNoProvider
		}
		return socks5AuthReasonUnsupported
	}
	if at := strings.LastIndexByte(user, '@'); at >= 0 && idpRegistry != nil && idpRegistry.RouteByDomain(user[at+1:]) != nil {
		return socks5AuthReasonUnsupported
	}
	return socks5AuthReasonInvalid
}

// socks5PostureWithoutProvider: the posture is established and no proxy
// identity provider of any kind (legacy, credential-capable or interactive
// registry profile) is configured.
func socks5PostureWithoutProvider() bool {
	return cfg.ProxyAuthEstablished() && !hasCredentialCapableProvider() &&
		(idpRegistry == nil || !idpRegistry.HasEnabledInteractiveProfile())
}

func noteSOCKS5AuthFailure(reason string) {
	switch reason {
	case socks5AuthReasonUnsupported:
		socks5AuthFailures[1].Add(1)
	case socks5AuthReasonPostureNoProvider:
		socks5AuthFailures[2].Add(1)
	default:
		socks5AuthFailures[0].Add(1)
	}
}

// socks5Negotiate performs the SOCKS5 greeting (VER NMETHODS METHODS) and, when
// authentication is required, the RFC 1929 username/password sub-negotiation,
// writing the method-selection and auth-status replies. It returns the resolved
// principal and true iff the client may proceed to the request phase. Every
// failure path (bad greeting, no acceptable method, short read, auth failure)
// is fully handled here — reply + stats + request log — and returns false so
// the caller simply closes the connection.
func socks5Negotiate(conn net.Conn, clientIP string) (ProxyIdentity, bool) {
	// Greeting: VER(1) NMETHODS(1) METHODS(N)
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil || hdr[0] != 0x05 {
		return ProxyIdentity{}, false
	}
	methods := make([]byte, hdr[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return ProxyIdentity{}, false
	}

	if !socks5AuthRequired() {
		conn.Write([]byte{0x05, 0x00}) //nolint:errcheck // best-effort no-auth method selection; a write error surfaces on the next read
		return ProxyIdentity{ClientIP: clientIP, AuthSource: socks5UnauthSource}, true
	}

	// Auth required: the client must offer USER/PASS (0x02).
	if !bytes.Contains(methods, []byte{0x02}) {
		conn.Write([]byte{0x05, 0xFF}) //nolint:errcheck // best-effort "no acceptable method" reply before close
		return ProxyIdentity{}, false
	}
	conn.Write([]byte{0x05, 0x02}) //nolint:errcheck // best-effort USER/PASS method selection; error surfaces on the next read

	uname, passwd, ok := readSOCKS5UserPass(conn)
	if !ok {
		return ProxyIdentity{}, false
	}
	user := string(uname)
	// CHAOS-57/76: the fairness key is the raw peer — SOCKS5 carries no
	// forwarding header, so there is nothing here for realClientIP to resolve.
	identity, groups, source, authOK := resolvePresentedCredential(credentialChannelSOCKS5, clientFairnessKey(clientIP), user, string(passwd))
	// B5: Zero credentials from memory immediately after auth check.
	clear(uname)
	clear(passwd)
	if !authOK {
		reason := socks5AuthRefusalReason(user)
		noteSOCKS5AuthFailure(reason)
		conn.Write([]byte{0x01, 0x01}) //nolint:errcheck // best-effort auth-failure reply before close
		atomic.AddInt64(&statAuthFail, 1)
		recordRequest(clientIP, "SOCKS5", "", "AUTH_FAIL", "", reason, "", "")
		logger.Printf("SOCKS5 AUTH_FAIL %s {reason=%s}", clientIP, sanitizeLogFieldToken(reason))
		return ProxyIdentity{}, false
	}
	conn.Write([]byte{0x01, 0x00}) //nolint:errcheck // best-effort auth-success reply; error surfaces on the next read
	return ProxyIdentity{ClientIP: clientIP, Identity: identity, AuthSource: source, Groups: groups}, true
}

// readSOCKS5UserPass reads the RFC 1929 sub-negotiation
// VER(1) ULEN(1) UNAME PLEN(1) PASSWD. The caller owns (and zeroes) the
// returned buffers.
func readSOCKS5UserPass(r io.Reader) (uname, passwd []byte, ok bool) {
	subHdr := make([]byte, 2)
	if _, err := io.ReadFull(r, subHdr); err != nil {
		return nil, nil, false
	}
	uname = make([]byte, subHdr[1])
	if _, err := io.ReadFull(r, uname); err != nil {
		return nil, nil, false
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, plenBuf); err != nil {
		clear(uname)
		return nil, nil, false
	}
	passwd = make([]byte, plenBuf[0])
	if _, err := io.ReadFull(r, passwd); err != nil {
		clear(uname)
		clear(passwd)
		return nil, nil, false
	}
	return uname, passwd, true
}

// writeSOCKS5AuthMetrics emits the USER/PASS refusal counter. Called from the
// SOCKS5 block of handleMetrics, so it is present only where the listener is
// configured.
func writeSOCKS5AuthMetrics(w io.Writer) {
	_, _ = fmt.Fprintf(w, `
# HELP culvert_socks5_auth_failures_total SOCKS5 username/password authentications refused, by reason
# TYPE culvert_socks5_auth_failures_total counter
culvert_socks5_auth_failures_total{reason=%q} %d
culvert_socks5_auth_failures_total{reason=%q} %d
culvert_socks5_auth_failures_total{reason=%q} %d
`, socks5AuthReasonInvalid, socks5AuthFailures[0].Load(), socks5AuthReasonUnsupported, socks5AuthFailures[1].Load(),
		socks5AuthReasonPostureNoProvider, socks5AuthFailures[2].Load())
}
