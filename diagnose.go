package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Diagnostic command framework (M3). Product-level, typed operations — NEVER a
// shell (DIAGNOSTIC-COMMAND-FRAMEWORK §Absolute rule). No verb takes free-form OS
// input, runs sh -c, or reaches a host binary; the verb set is a FIXED in-binary
// registry, so allowlisting is structural. Every verb returns a typed, versioned
// JSON contract (schema_version) that the API, CLI, and GUI all render identically.
//
// This file ships the first verb — `diagnose storage` — a purely LOCAL, read-only
// health probe (writability + free space + data-dir stat). Network verbs
// (dns/tls/upstream), which require SSRF guards, and cluster fan-out are deferred.

// diagnoseSchemaVersion is bumped when any diagnose output contract changes shape.
const diagnoseSchemaVersion = 1

// storageMinFreeWarnBytes is the free-space floor below which storage is flagged
// (not fatal — the bundle path has its own preflight; this is an advisory signal).
const storageMinFreeWarnBytes = 256 << 20 // 256 MiB

type storageCheck struct {
	Name   string `json:"name"`
	Path   string `json:"path"` // server-side path (INTERNAL; a live admin read, never bundled)
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type storageDiagnosis struct {
	SchemaVersion int            `json:"schema_version"`
	GeneratedAt   string         `json:"generated_at"`
	OK            bool           `json:"ok"` // all checks passed
	DataDir       string         `json:"data_dir"`
	FreeBytes     uint64         `json:"free_bytes"`
	TotalBytes    uint64         `json:"total_bytes"`
	UsedPct       float64        `json:"used_pct"`
	Checks        []storageCheck `json:"checks"`
}

// probeWritable creates and removes a uniquely-named temp file in an EXISTING dir
// to prove the process can actually write there — a stat/permission bit can lie
// (read-only mount, full disk, SELinux). The probe file is always removed
// (create+remove is the whole test); a failure to create is the diagnostic signal.
// It deliberately does NOT create dir: the diagnostic must not mutate storage or
// pre-create the support tree (which the bundle path owns, at 0700). Callers stat
// first and only probe dirs that already exist.
func probeWritable(dir string) (ok bool, detail string) {
	f, err := os.CreateTemp(dir, ".diag-write-*")
	if err != nil {
		return false, "create: " + err.Error()
	}
	name := f.Name()
	_, wErr := f.WriteString("culvert-storage-probe")
	cErr := f.Close()
	rmErr := os.Remove(name)
	switch {
	case wErr != nil:
		return false, "write: " + wErr.Error()
	case cErr != nil:
		return false, "close: " + cErr.Error()
	case rmErr != nil:
		return false, "cleanup: " + rmErr.Error()
	}
	return true, ""
}

// diagnoseStorage runs the local storage probe. now is injected for deterministic
// timestamps in tests.
func diagnoseStorage(now time.Time) storageDiagnosis {
	d := storageDiagnosis{
		SchemaVersion: diagnoseSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		DataDir:       dataDir,
	}

	if usedPct, free, total, err := diskUsage(dataDir); err == nil {
		d.FreeBytes, d.TotalBytes, d.UsedPct = free, total, usedPct
		free64 := free
		d.Checks = append(d.Checks, storageCheck{
			Name: "free_space", Path: dataDir, OK: free64 >= storageMinFreeWarnBytes,
			Detail: byteCountDetail(free64, storageMinFreeWarnBytes),
		})
	} else {
		d.Checks = append(d.Checks, storageCheck{
			Name: "free_space", Path: dataDir, OK: false, Detail: "statfs: " + err.Error(),
		})
	}

	// Writability of the data dir and the two critical support subdirs. A subdir
	// that does not yet exist is NOT created here — the diagnostic must not mutate
	// storage or pre-seed the support tree (the bundle path owns that, at 0700). An
	// absent subdir is fine as long as its parent is writable, which the
	// data_dir_writable check establishes.
	for _, c := range []struct{ name, path string }{
		{"data_dir_writable", dataDir},
		{"support_dir_writable", filepath.Join(dataDir, "support")},
		{"bundles_dir_writable", supportBundlesDir()},
	} {
		fi, err := os.Stat(c.path)
		switch {
		case err == nil && fi.IsDir():
			ok, detail := probeWritable(c.path)
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: ok, Detail: detail})
		case err == nil: // exists but is not a directory
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: false, Detail: "not a directory"})
		case os.IsNotExist(err):
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: true, Detail: "absent (created on first bundle)"})
		default:
			d.Checks = append(d.Checks, storageCheck{Name: c.name, Path: c.path, OK: false, Detail: "stat: " + err.Error()})
		}
	}

	d.OK = true
	for i := range d.Checks {
		if !d.Checks[i].OK {
			d.OK = false
			break
		}
	}
	return d
}

// byteCountDetail renders a compact "have X, want ≥ Y MiB" advisory for the check.
func byteCountDetail(have, want uint64) string {
	return "free=" + mib(have) + "MiB floor=" + mib(want) + "MiB"
}

func mib(n uint64) string { return strconv.FormatUint(n/(1<<20), 10) }

// apiDiagnoseStorage runs the local storage diagnosis (POST, operator). It is
// read-only except for a create+remove writability probe, and touches no network.
func apiDiagnoseStorage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	d := diagnoseStorage(time.Now())
	auditEvent(r, "diagnose.storage", "storage", boolResult(d.OK))
	jsonOK(w, d)
}

func boolResult(ok bool) string {
	if ok {
		return "ok"
	}
	return "degraded"
}

// ── diagnose upstream ─────────────────────────────────────────────────────────

type upstreamProbe struct {
	URL          string `json:"url"` // already redacted to host:port by the pool's List()
	Healthy      bool   `json:"healthy"`
	Circuit      string `json:"circuit"` // closed|open|half-open
	Failures     int64  `json:"failures"`
	RetryAfterMs int64  `json:"retry_after_ms,omitempty"`
}

type upstreamDiagnosis struct {
	SchemaVersion int             `json:"schema_version"`
	GeneratedAt   string          `json:"generated_at"`
	Enabled       bool            `json:"enabled"`
	OK            bool            `json:"ok"` // enabled ⇒ at least one USABLE proxy; disabled ⇒ trivially ok (direct)
	Count         int             `json:"count"`
	HealthyCount  int             `json:"healthy_count"`
	UsableCount   int             `json:"usable_count"` // healthy AND circuit not open (matches the selection path)
	Proxies       []upstreamProbe `json:"proxies"`
}

// upstreamCounts returns (healthy, usable) over a status snapshot. "Usable"
// mirrors the selection path (up.Healthy.Load() && up.CB.Allow()): a proxy with an
// OPEN breaker is skipped even while its Healthy flag is set, so counting only
// Healthy would report OK in the exact all-circuits-open outage operators are
// troubleshooting. A half-open breaker still admits a probe, so it is usable.
func upstreamCounts(list []UpstreamStatus) (healthy, usable int) {
	for i := range list {
		if list[i].Healthy {
			healthy++
			if list[i].Circuit != "open" {
				usable++
			}
		}
	}
	return healthy, usable
}

// diagnoseUpstream surfaces the upstream pool's EXISTING health-loop + circuit
// state — it performs NO new dial and reads only the redacted List() (host:port,
// never credentials). now is injected for deterministic timestamps in tests.
func diagnoseUpstream(now time.Time) upstreamDiagnosis {
	d := upstreamDiagnosis{
		SchemaVersion: diagnoseSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Enabled:       upstreamPool.Enabled(),
	}
	list := upstreamPool.List() // redacted, in-memory snapshot; no outbound I/O
	d.Count = len(list)
	d.Proxies = make([]upstreamProbe, 0, len(list))
	for i := range list {
		s := &list[i]
		d.Proxies = append(d.Proxies, upstreamProbe{
			URL: s.URL, Healthy: s.Healthy, Circuit: s.Circuit,
			Failures: s.Failures, RetryAfterMs: s.RetryAfterMs,
		})
	}
	d.HealthyCount, d.UsableCount = upstreamCounts(list)
	// Disabled = direct egress (no pool), which is a healthy posture, not a fault.
	// Enabled = at least one USABLE proxy (healthy + breaker not open), else all
	// upstream egress is effectively down even if flags still read "healthy".
	d.OK = !d.Enabled || d.UsableCount > 0
	return d
}

// apiDiagnoseUpstream reports upstream pool health (POST, operator). Read-only,
// no new dial, no network, no shell.
func apiDiagnoseUpstream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	d := diagnoseUpstream(time.Now())
	auditEvent(r, "diagnose.upstream", "upstream", boolResult(d.OK))
	jsonOK(w, d)
}

// ── diagnose dns ──────────────────────────────────────────────────────────────

// diagnoseDNSTimeout bounds the resolution probe so a slow/hostile resolver can
// never hang the request or tie up the proxy.
const diagnoseDNSTimeout = 3 * time.Second

// diagnoseMaxAddrs caps the addresses reported for one host (a wildcard/round-robin
// record could otherwise return an unbounded set).
const diagnoseMaxAddrs = 16

// diagnoseLookupIP is the resolver seam — overridden in tests so no real DNS is hit.
var diagnoseLookupIP = func(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}

// validDiagnoseHost enforces that the probe target is a valid bare hostname —
// LDH-label grammar (letters/digits/hyphen), each label 1..63 bytes with no
// leading/trailing hyphen, no empty labels (rejects trailing dots and "a..b"),
// total ≤ 253, and no underscore (so SRV-style names like "_sip._tcp.internal"
// are refused). This keeps an operator-supplied string from being anything but a
// resolvable hostname (defence-in-depth alongside the SSRF guard below).
func validDiagnoseHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for _, label := range strings.Split(h, ".") {
		if !validDiagnoseLabel(label) {
			return false
		}
	}
	return true
}

// validDiagnoseLabel enforces the LDH-label grammar for a single dot-separated
// label of validDiagnoseHost: 1..63 bytes, no leading/trailing hyphen, and
// letters/digits/hyphen only.
func validDiagnoseLabel(label string) bool {
	if label == "" || len(label) > 63 {
		return false
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		isLDH := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-'
		if !isLDH {
			return false
		}
	}
	return true
}

type dnsDiagnosis struct {
	SchemaVersion int      `json:"schema_version"`
	GeneratedAt   string   `json:"generated_at"`
	Host          string   `json:"host"`
	Resolved      bool     `json:"resolved"`
	Blocked       bool     `json:"blocked"` // resolved to a private/internal IP → refused (SSRF guard)
	OK            bool     `json:"ok"`
	Addresses     []string `json:"addresses,omitempty"` // PUBLIC addresses only
	DurationMs    int64    `json:"duration_ms"`
	Error         string   `json:"error,omitempty"`
}

// diagnoseDNS resolves host under a bounded context and enforces the SSRF guard:
// if ANY resolved address is private/internal the probe is REFUSED (blocked=true,
// addresses omitted) so the diagnostic cannot be used to map internal infra from
// the proxy's network position. now/ctx are injected for deterministic tests.
func diagnoseDNS(ctx context.Context, host string, now time.Time) dnsDiagnosis {
	d := dnsDiagnosis{SchemaVersion: diagnoseSchemaVersion, GeneratedAt: now.UTC().Format(time.RFC3339), Host: host}

	lctx, cancel := context.WithTimeout(ctx, diagnoseDNSTimeout)
	defer cancel()
	start := now
	addrs, err := diagnoseLookupIP(lctx, host)
	d.DurationMs = int64(time.Since(start) / time.Millisecond)
	if err != nil {
		d.Error = boundedErr(err.Error())
		return d
	}
	d.Resolved = len(addrs) > 0

	// SSRF guard (inline so CodeQL sees it): a single private hit blocks the whole
	// result — never expose any address for a target that touches internal space.
	for i := range addrs {
		if isPrivateIP(addrs[i].IP) {
			d.Blocked = true
			d.Addresses = nil
			return d
		}
	}
	for i := range addrs {
		if len(d.Addresses) >= diagnoseMaxAddrs {
			break
		}
		d.Addresses = append(d.Addresses, addrs[i].IP.String())
	}
	d.OK = d.Resolved
	return d
}

// boundedErr caps a resolver error string so a pathological message can't bloat
// the response (the diagnostic surfaces cause, not a novel).
func boundedErr(s string) string {
	const maxLen = 256
	if len(s) > maxLen {
		return s[:maxLen] + "…"
	}
	return s
}

// apiDiagnoseDNS runs a bounded, SSRF-guarded DNS resolution probe (POST, operator).
func apiDiagnoseDNS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	var body struct {
		Host string `json:"host"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	host := strings.TrimSpace(body.Host)
	if !validDiagnoseHost(host) {
		http.Error(w, "invalid host (bare hostname required; no scheme/port/path)", http.StatusBadRequest)
		return
	}
	d := diagnoseDNS(r.Context(), host, time.Now())
	// Audit with the sanitised host so a hostile hostname can't forge a log line.
	auditEvent(r, "diagnose.dns", sanitizeLog(host), dnsResult(d))
	jsonOK(w, d)
}

func dnsResult(d dnsDiagnosis) string {
	switch {
	case d.Blocked:
		return "blocked"
	case d.OK:
		return "resolved"
	default:
		return "unresolved"
	}
}

// ── diagnose tls ──────────────────────────────────────────────────────────────

// diagnoseTLSTimeout bounds the whole probe (dial + handshake).
const diagnoseTLSTimeout = 5 * time.Second

// diagnoseMaxSANs caps the SANs reported for one leaf (a pathological cert could
// otherwise carry thousands).
const diagnoseMaxSANs = 32

// tlsHandshakeProbe is the connect+handshake seam — overridden in tests so no real
// network is used. The default implementation applies the SSRF connect guard
// (ssrfControl) and performs the handshake with verification DISABLED so the peer
// chain can be inspected even when it is invalid/expired; validity is reported
// separately (chain_verified). ServerName drives SNI + later verification.
var tlsHandshakeProbe = func(ctx context.Context, hostport, serverName string) (*tls.ConnectionState, error) {
	raw, err := (&net.Dialer{Timeout: diagnoseTLSTimeout, Control: ssrfControl}).DialContext(ctx, "tcp", hostport)
	if err != nil {
		return nil, err
	}
	// #nosec G402 -- verification is intentionally deferred: this is a diagnostic
	// that must observe even an invalid/expired chain, then reports validity via a
	// separate cert.Verify (summarizeTLSState). It is never used to carry traffic.
	conn := tls.Client(raw, &tls.Config{ServerName: serverName, InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	defer conn.Close() //nolint:errcheck // best-effort; the ConnectionState is copied out below
	if err := conn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	cs := conn.ConnectionState()
	return &cs, nil
}

type tlsLeaf struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DNSNames  []string `json:"dns_names,omitempty"`
}

type tlsDiagnosis struct {
	SchemaVersion   int      `json:"schema_version"`
	GeneratedAt     string   `json:"generated_at"`
	Host            string   `json:"host"`
	Port            string   `json:"port"`
	Blocked         bool     `json:"blocked"` // private/internal target refused (SSRF guard)
	OK              bool     `json:"ok"`      // handshake ok AND chain verifies AND not expired
	HandshakeOK     bool     `json:"handshake_ok"`
	Version         string   `json:"version,omitempty"`      // e.g. "TLS 1.3"
	CipherSuite     string   `json:"cipher_suite,omitempty"` // e.g. "TLS_AES_128_GCM_SHA256"
	ChainVerified   bool     `json:"chain_verified"`
	Expired         bool     `json:"expired"`
	DaysUntilExpiry int      `json:"days_until_expiry"`
	Leaf            *tlsLeaf `json:"leaf,omitempty"`
	Error           string   `json:"error,omitempty"`
	DurationMs      int64    `json:"duration_ms"`
}

// summarizeTLSState turns a completed handshake's ConnectionState into the typed
// diagnosis: negotiated params, leaf identity/expiry, and chain verification
// against the system roots for host. Pure (no I/O) so it is fully testable with a
// fabricated cert.
func summarizeTLSState(host string, cs *tls.ConnectionState, now time.Time) tlsDiagnosis {
	d := tlsDiagnosis{
		HandshakeOK: true,
		Version:     tls.VersionName(cs.Version),
		CipherSuite: tls.CipherSuiteName(cs.CipherSuite),
	}
	if len(cs.PeerCertificates) == 0 {
		d.Error = "no peer certificate"
		return d
	}
	leaf := cs.PeerCertificates[0]
	sans := leaf.DNSNames
	if len(sans) > diagnoseMaxSANs {
		sans = sans[:diagnoseMaxSANs]
	}
	d.Leaf = &tlsLeaf{
		Subject:   leaf.Subject.String(),
		Issuer:    leaf.Issuer.String(),
		NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  leaf.NotAfter.UTC().Format(time.RFC3339),
		DNSNames:  sans,
	}
	d.Expired = now.Before(leaf.NotBefore) || now.After(leaf.NotAfter)
	d.DaysUntilExpiry = int(leaf.NotAfter.Sub(now).Hours() / 24)

	// Chain verification against the system roots, with the intermediates the peer
	// presented. A failure is reported (not fatal) — the diagnostic's job is to say
	// WHY, e.g. self-signed/expired/untrusted.
	roots, _ := x509.SystemCertPool()
	inter := x509.NewCertPool()
	for _, c := range cs.PeerCertificates[1:] {
		inter.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       host,
		Roots:         roots,
		Intermediates: inter,
		CurrentTime:   now,
	}); err == nil {
		d.ChainVerified = true
	} else {
		d.Error = boundedErr(err.Error())
	}
	d.OK = d.ChainVerified && !d.Expired
	return d
}

// diagnoseTLS parses host[:port] (default 443), enforces the SSRF guard, performs
// a bounded handshake via the seam, and summarizes it. now/ctx injected for tests.
func diagnoseTLS(ctx context.Context, hostArg string, now time.Time) tlsDiagnosis {
	host, port := hostArg, "443"
	if h, p, err := net.SplitHostPort(hostArg); err == nil {
		host, port = h, p
	}
	d := tlsDiagnosis{SchemaVersion: diagnoseSchemaVersion, GeneratedAt: now.UTC().Format(time.RFC3339), Host: host, Port: port}
	if !validDiagnoseHost(host) || !validPort(port) {
		d.Error = "invalid host:port (bare hostname + 1..65535 port)"
		return d
	}
	hostport := net.JoinHostPort(host, port)

	// The whole probe — including the SSRF resolution preflight — runs under the
	// deadline so a wedged resolver can never exceed the advertised bound
	// (isPrivateHost delegates to a context.Background() LookupHost, so it is NOT
	// used here; the DNS lookup below is context-bounded instead).
	lctx, cancel := context.WithTimeout(ctx, diagnoseTLSTimeout)
	defer cancel()
	start := now

	// SSRF guard (inline so CodeQL sees it): resolve under the deadline and refuse a
	// target that resolves to a private/internal address before any dial. The
	// connect-layer ssrfControl in the seam is the DNS-rebinding backstop.
	addrs, rErr := diagnoseLookupIP(lctx, host)
	if rErr != nil {
		d.Error = boundedErr(rErr.Error())
		d.DurationMs = int64(time.Since(start) / time.Millisecond)
		return d
	}
	for i := range addrs {
		if isPrivateIP(addrs[i].IP) {
			d.Blocked = true
			d.DurationMs = int64(time.Since(start) / time.Millisecond)
			return d
		}
	}

	cs, err := tlsHandshakeProbe(lctx, hostport, host)
	dur := int64(time.Since(start) / time.Millisecond)
	if err != nil {
		d.Error = boundedErr(err.Error())
		d.DurationMs = dur
		return d
	}
	sum := summarizeTLSState(host, cs, now)
	sum.SchemaVersion, sum.GeneratedAt, sum.Host, sum.Port, sum.DurationMs = d.SchemaVersion, d.GeneratedAt, host, port, dur
	return sum
}

// validPort reports whether s is a decimal port in 1..65535.
func validPort(s string) bool {
	n, err := strconv.Atoi(s)
	return err == nil && n >= 1 && n <= 65535
}

// apiDiagnoseTLS runs a bounded, SSRF-guarded TLS handshake diagnosis (POST, operator).
func apiDiagnoseTLS(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	var body struct {
		Host string `json:"host"`
	}
	if err := decodeJSON(r, &body); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}
	hostArg := strings.TrimSpace(body.Host)
	if hostArg == "" {
		http.Error(w, "host is required (hostname[:port])", http.StatusBadRequest)
		return
	}
	d := diagnoseTLS(r.Context(), hostArg, time.Now())
	auditEvent(r, "diagnose.tls", sanitizeLog(hostArg), tlsResult(d))
	jsonOK(w, d)
}

func tlsResult(d tlsDiagnosis) string {
	switch {
	case d.Blocked:
		return "blocked"
	case d.OK:
		return "ok"
	case d.HandshakeOK:
		return "handshake-ok-untrusted"
	default:
		return "failed"
	}
}

// registerDiagnoseRoutes wires the diagnose verb surface.
func registerDiagnoseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/diagnose/storage", apiDiagnoseStorage)
	mux.HandleFunc("/api/diagnose/upstream", apiDiagnoseUpstream)
	mux.HandleFunc("/api/diagnose/dns", apiDiagnoseDNS)
	mux.HandleFunc("/api/diagnose/tls", apiDiagnoseTLS)
}
