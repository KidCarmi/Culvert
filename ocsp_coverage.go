package main

// ocsp_coverage.go — CHAOS-65: which TLS handshakes actually consult the
// revocation checker, and saying so out loud.
//
// `proxy.ocsp_check: true` (or POST /api/ocsp) enables the checker, logs
// "OCSP: upstream certificate revocation checking enabled", and lights up an
// admin panel with counters. What it does NOT do is put the check on the
// handshake a Secure Web Gateway actually performs.
//
// ConfigureTLSConfigOCSP installs the callbacks on exactly one object: the
// operator TLS template behind the shared upstream *http.Transport
// (upstream_transport.go). That transport carries the plain-HTTP forward path
// — which never negotiates TLS to the origin — and a TLS connection to an
// https:// PARENT proxy, if one is configured. Every inspected HTTPS request
// takes a different path: handleTunnelInspect and handleInspectNativeALPN
// build their own tls.Config from scratch in upstreamInspectTLSConfig
// (proxy_tunnel.go), and nothing attaches the OCSP callbacks to it. So on the
// one path where this appliance terminates and validates an origin
// certificate on behalf of a client, revocation is not checked.
//
// That is the register's §1 theme exactly — a security control that reports
// itself healthy while doing nothing — and an operator cannot act on a
// control they cannot see fail. The counters stay at zero either way, so
// "working perfectly" and "never consulted" render identically.
//
// **Why the gap is REPORTED here rather than closed by wiring the callbacks
// in.** Doing that would make every inspected HTTPS request depend on
// reaching an external OCSP responder, FAIL-CLOSED, on a network where
// outbound port 80 to arbitrary responder hosts is very often exactly what
// egress policy forbids. The failure mode is a total HTTPS outage for the
// fleet, arriving the moment an operator flips a checkbox that today does
// almost nothing — a posture change with a blast radius the flag's current
// wording does not warn anyone about. The engine had to be made safe first
// (CHAOS-65 ships that); wiring it to the inspect path is a deliberate
// product decision about failure posture, and needs a soft-fail mode
// (observe-only counters, or fail-open-and-alert) designed alongside it.
//
// Recorded as register row **OCSP-8**. The agreement between what this file
// CLAIMS and what the code DOES is pinned by ocsp_coverage_test.go, so
// whoever wires the inspect path must update the claim in the same change.

import "strings"

// ocspPathCoverage is one TLS-handshake path and whether it consults the
// revocation checker.
type ocspPathCoverage struct {
	// Path is a stable identifier, also used as the /metrics label value.
	Path string `json:"path"`
	// Checked reports whether the OCSP callbacks are installed on the
	// tls.Config this path hands to crypto/tls.
	Checked bool `json:"checked"`
	// Detail is a fixed, bounded string — never an error or a host.
	Detail string `json:"detail"`
}

// ocspCoverage reports revocation-check coverage per TLS-handshake path.
//
// The values are CONSTANT because the wiring is: ConfigureTLSConfigOCSP has
// exactly two call sites (mtls_ocsp_startup.go and the /api/ocsp toggle), both
// targeting upstreamOpTLSCfg. Nothing here is inferred at runtime, and
// ocsp_coverage_test.go asserts each row against the real tls.Config the named
// path builds, so a claim cannot drift away from the code.
func ocspCoverage() []ocspPathCoverage {
	return []ocspPathCoverage{
		{
			Path:    "upstream_transport",
			Checked: true,
			Detail:  "shared upstream transport (https:// parent proxy handshakes)",
		},
		{
			Path:    "ssl_inspect_origin",
			Checked: false,
			Detail:  "inspected HTTPS origin handshakes build their own TLS config; revocation is NOT checked (CHAOS-65 OCSP-8)",
		},
		{
			Path:    "connect_bypass",
			Checked: false,
			Detail:  "bypassed CONNECT tunnels are relayed raw; this proxy never sees the certificate",
		},
	}
}

// ocspUncheckedEnforcingPaths returns the paths where this appliance DOES
// validate an origin certificate on a client's behalf and yet does not consult
// the revocation checker. connect_bypass is deliberately absent: a bypassed
// tunnel is relayed raw, so there is no certificate to check and nothing to
// report as a gap.
func ocspUncheckedEnforcingPaths() []string {
	var out []string
	for _, c := range ocspCoverage() {
		if !c.Checked && c.Path != "connect_bypass" {
			out = append(out, c.Path)
		}
	}
	return out
}

// logOCSPCoverageWarning states the coverage gap at the moment the control is
// turned on — the only moment an operator is looking. It is emitted from both
// enable paths (the startup slice and the admin toggle) so neither can quietly
// promise more than the wiring delivers.
func logOCSPCoverageWarning() {
	gaps := ocspUncheckedEnforcingPaths()
	if len(gaps) == 0 {
		return
	}
	logWarnf("OCSP: revocation checking covers the upstream transport only — "+
		"inspected HTTPS origin handshakes (%s) are NOT revocation-checked; "+
		"see docs/operator/ocsp-revocation-checking.md", strings.Join(gaps, ", "))
}
