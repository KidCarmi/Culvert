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

	"github.com/KidCarmi/Culvert/internal/halease"
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
		}
		// 2F-C: usable is the pool's own eligibility verdict (credential
		// usable AND probe unprobed/healthy AND breaker admitting), so an
		// unprobed new entry counts as usable and an unusable/mismatched
		// credential never does.
		if list[i].Eligible {
			usable++
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

// ── diagnose cluster ──────────────────────────────────────────────────────────

// clusterDiagnosis is the typed, versioned contract for `diagnose cluster`. It is
// built ENTIRELY from in-memory HA/cluster state via mutex-guarded accessors — it
// performs NO network I/O (no RPC to peers, no etcd dial) and exposes NO secret or
// infrastructure detail: peer/standby addresses, tokens, and cert material are
// deliberately omitted. Only health booleans, counts, and the fencing epoch are
// surfaced so the diagnostic answers "is the cluster posture healthy?" without
// re-exposing anything an operator can't already see on /api/cluster/ha.
type clusterDiagnosis struct {
	SchemaVersion  int    `json:"schema_version"`
	GeneratedAt    string `json:"generated_at"`
	Role           string `json:"role"` // standalone|control-plane|leader|standby|data-plane
	OK             bool   `json:"ok"`
	HAEnabled      bool   `json:"ha_enabled"`
	Term           uint64 `json:"term,omitempty"`
	AutoFailover   bool   `json:"auto_failover"`
	LeaseMode      string `json:"lease_mode"` // none|lease
	LeaseValid     bool   `json:"lease_valid,omitempty"`
	Epoch          int64  `json:"epoch,omitempty"`
	WriteAuthority bool   `json:"write_authority"`
	NodesTotal     int    `json:"nodes_total"`
	NodesConnected int    `json:"nodes_connected"`
	SyncFailCount  int    `json:"sync_fail_count,omitempty"`
	LastSyncOK     string `json:"last_sync_ok,omitempty"`
	Detail         string `json:"detail,omitempty"`
}

// clusterInputs is the pure snapshot the diagnosis core consumes. Keeping the
// role/OK logic separate from the global reads makes it fully testable without
// mutating the HA/cluster singletons (which would race the live loops).
type clusterInputs struct {
	haStatus     HAStatus
	nodeRole     string // authoritative clusterRole.role: standalone|control-plane|data-plane
	leaseMode    string
	leaseValid   bool
	epoch        int64
	writeAllowed bool // RAW lease-layer primitive (globalHA.WriteAllowed)
	total        int
	connected    int
	dpActive     bool
}

// effectiveWriteAuthority collapses the lease-layer primitive with the HA role,
// mirroring haIssuanceAllowed(): with HA disabled a node always has write
// authority; an HA standby never does (WriteAllowed is only the lease primitive
// and returns true in legacy mode, which would mislead failover diagnostics); an
// HA leader has it exactly when the lease permits. Reporting this — not the raw
// primitive — keeps /api/diagnose/cluster consistent with /healthz.
func effectiveWriteAuthority(st HAStatus, leaseWriteAllowed bool) bool {
	if !st.Enabled {
		return true
	}
	if st.Role != "leader" {
		return false
	}
	return leaseWriteAllowed
}

// clusterRoleAndOK derives the role label, the health verdict, and an advisory
// detail string from a cluster snapshot. Standalone and data-plane presence are
// healthy postures by construction; a control-plane is healthy when every enrolled
// node is connected; an HA leader additionally needs live write authority; an HA
// standby is healthy while its sync loop is not failing. The role label comes from
// the authoritative clusterRole snapshot (nodeRole), so an enabled control plane
// reports "control-plane" even before its first data-plane node enrolls.
func clusterRoleAndOK(in clusterInputs) (role string, ok bool, detail string) {
	nodesOK := in.total == 0 || in.connected == in.total
	switch {
	case in.nodeRole == "data-plane" || in.dpActive:
		// A data-plane node's detailed sync health is surfaced via the cluster
		// status API; here we confirm the DP client is live.
		return "data-plane", true, "data-plane node; detailed sync health via /api/cluster"
	case in.haStatus.Enabled:
		return haRoleAndOK(in, nodesOK)
	case in.nodeRole == "control-plane" || in.total > 0:
		// Authoritative CP role (covers a freshly enabled CP with zero enrolled
		// nodes) or, defensively, any node that already has enrollments.
		if !nodesOK {
			return "control-plane", false, "some enrolled nodes not connected"
		}
		return "control-plane", true, ""
	default:
		return "standalone", true, ""
	}
}

// haRoleAndOK resolves the leader/standby verdict for an HA-enabled control plane
// (split out of clusterRoleAndOK to keep each function under the cyclop threshold).
func haRoleAndOK(in clusterInputs, nodesOK bool) (role string, ok bool, detail string) {
	switch in.haStatus.Role {
	case "leader":
		ok = in.writeAllowed && nodesOK
		switch {
		case in.leaseMode == "lease" && !in.leaseValid:
			detail = "leader fencing lease not valid"
		case !nodesOK:
			detail = "some enrolled nodes not connected"
		}
		return "leader", ok, detail
	case "standby":
		if in.haStatus.SyncFailCount != 0 {
			return "standby", false, "standby sync loop is failing"
		}
		return "standby", true, ""
	default:
		return "control-plane", nodesOK, ""
	}
}

// diagnoseClusterFrom builds the typed diagnosis from a snapshot. Pure (no I/O),
// so tests drive every role/health branch with fabricated inputs.
func diagnoseClusterFrom(in clusterInputs, now time.Time) clusterDiagnosis {
	role, ok, detail := clusterRoleAndOK(in)
	d := clusterDiagnosis{
		SchemaVersion:  diagnoseSchemaVersion,
		GeneratedAt:    now.UTC().Format(time.RFC3339),
		Role:           role,
		OK:             ok,
		HAEnabled:      in.haStatus.Enabled,
		Term:           in.haStatus.Term,
		AutoFailover:   in.haStatus.AutoFailover,
		LeaseMode:      in.leaseMode,
		WriteAuthority: effectiveWriteAuthority(in.haStatus, in.writeAllowed),
		NodesTotal:     in.total,
		NodesConnected: in.connected,
		Detail:         detail,
	}
	if in.leaseMode == "lease" {
		d.LeaseValid = in.leaseValid
		d.Epoch = in.epoch
	}
	if in.haStatus.Role == "standby" {
		d.SyncFailCount = in.haStatus.SyncFailCount
		d.LastSyncOK = in.haStatus.LastSyncOK
	}
	return d
}

// ── diagnose config ───────────────────────────────────────────────────────────

// configCollectionSize is the non-secret size of one config-snapshot collection —
// a COUNT only, never the values. It answers "how big is my policy set / blocklist
// / category set" for config-apply triage.
type configCollectionSize struct {
	Name string `json:"name"`
	Size int    `json:"size"`
}

// configDiagnosis is the typed contract for `diagnose config`. It reports whether
// the live configuration snapshot the CP would push (and a DP would apply) passes
// the same structural cap validation (validateConfigSnapshot) that gates a real
// sync, plus non-secret collection sizes and the policy/epoch versions. It NEVER
// surfaces any snapshot value (rules, hosts, session HMAC, IdP secrets) — only
// counts and the pass/fail verdict.
type configDiagnosis struct {
	SchemaVersion int    `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	// OK is the AGGREGATE-safe verdict: true unless the snapshot is a real
	// problem for THIS node's role. A standalone node never syncs config over
	// the cluster wire, so an over-cap snapshot is advisory (warn), not a
	// failure — keeping OK true so a lone appliance is not marked DEGRADED for a
	// cluster-sync bound it does not exercise. A syncing node (CP or DP) keeps
	// the hard verdict: over-cap ⇒ OK false.
	OK     bool   `json:"ok"`
	Status string `json:"status"` // "ok" | "warn" | "degraded"
	// Syncing reports whether this node participates in CP↔DP config sync, i.e.
	// whether the per-slice caps actually gate anything for it.
	Syncing        bool                   `json:"syncing"`
	PolicyVersion  int64                  `json:"policy_version"`
	Epoch          int64                  `json:"epoch"`
	Sizes          []configCollectionSize `json:"sizes"`
	Utilization    []snapshotSliceCap     `json:"utilization"`              // size vs cap for every capped slice
	MaxUtilPercent int                    `json:"max_util_percent"`         // highest size/cap across all slices
	MaxUtilSlice   string                 `json:"max_util_slice,omitempty"` // the slice at MaxUtilPercent
	Error          string                 `json:"error,omitempty"`          // first cap violation (names the collection + cap)
	Note           string                 `json:"note,omitempty"`           // human explanation of a warn verdict
	// PublishRejected is set on a Control Plane when the most recent config
	// publish was refused at commit (over-cap) — the fleet is running the last
	// valid snapshot, not the live config. Empty when the last publish succeeded.
	PublishRejected   string `json:"publish_rejected,omitempty"`
	PublishRejectedAt string `json:"publish_rejected_at,omitempty"`
}

// configWarnUtilPercent is the utilization at which a slice trips the amber
// "approaching cap" tier — an early passive signal before a slice actually
// overflows and (for a syncing node) breaks the fleet.
const configWarnUtilPercent = 80

// diagnoseConfigFrom validates a snapshot and summarizes its non-secret sizes.
// Pure (no I/O), so tests drive the branches with a fabricated snapshot + role.
// syncing = this node participates in config sync (CP or DP); it decides whether
// an over-cap snapshot is a hard failure (degraded) or advisory (warn).
func diagnoseConfigFrom(snap ConfigSnapshot, syncing bool, now time.Time) configDiagnosis {
	util := configSnapshotSliceCaps(snap)
	maxPct, maxSlice := 0, ""
	for _, s := range util {
		if s.Cap <= 0 {
			continue
		}
		pct := s.Size * 100 / s.Cap
		if pct > maxPct {
			maxPct, maxSlice = pct, s.Name
		}
	}
	d := configDiagnosis{
		SchemaVersion: diagnoseSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Syncing:       syncing,
		PolicyVersion: snap.PolicyVersion,
		Epoch:         snap.Epoch,
		Sizes: []configCollectionSize{
			{"policy_rules", len(snap.PolicyRules)},
			{"blocked_hosts", len(snap.BlockedHosts)},
			{"ip_list", len(snap.IPList)},
			{"ssl_bypass_patterns", len(snap.SSLBypassPatterns)},
			{"url_categories", len(snap.URLCategories)},
			{"category_groups", len(snap.CategoryGroups)},
			{"file_profiles", len(snap.FileProfiles)},
			{"rewrite_rules", len(snap.RewriteRules)},
			{"dpi_patterns", len(snap.DPIPatterns)},
			{"pac_exclusions", len(snap.PACExclusions)},
			{"threat_feed_urls", len(snap.ThreatFeedURLs)},
			{"threat_feed_domains", len(snap.ThreatFeedDomains)},
			{"node_groups", len(snap.NodeGroups)},
			{"bandwidth_policies", len(snap.BandwidthPolicies)},
			{"decryption_profiles", len(snap.DecryptionProfiles)},
		},
		Utilization:    util,
		MaxUtilPercent: maxPct,
		MaxUtilSlice:   maxSlice,
	}
	switch err := validateConfigSnapshot(snap); {
	case err != nil && syncing:
		// A syncing node with an over-cap snapshot is genuinely broken: a CP
		// cannot push it and a DP would reject it wholesale.
		d.Status, d.OK, d.Error = "degraded", false, boundedErr(err.Error())
	case err != nil && !syncing:
		// Standalone: the cap only gates cluster sync, which this node does not
		// do. Surface it as advisory so the aggregate health stays green — this
		// is the false-positive DEGRADED a lone appliance used to hit.
		d.Status, d.OK, d.Error = "warn", true, boundedErr(err.Error())
		d.Note = "over the cluster-sync cap, but this node is standalone (not syncing) so proxying is unaffected; the cap would block CP→DP sync if you enable clustering"
	case maxPct >= configWarnUtilPercent:
		d.Status, d.OK = "warn", true
		d.Note = "a config collection is approaching its cap"
	default:
		d.Status, d.OK = "ok", true
	}
	return d
}

// diagnoseCluster gathers the live in-memory HA/cluster snapshot and produces the
// diagnosis. Every accessor here is a mutex-guarded READ; none dials the network.
func diagnoseCluster(now time.Time) clusterDiagnosis {
	mode, valid, epoch := globalHA.leaseHealth()
	total, connected := globalClusterStore.NodeCounts()
	clusterRoleMu.RLock()
	nodeRole := clusterRole.role
	clusterRoleMu.RUnlock()
	in := clusterInputs{
		haStatus:     globalHA.Status(),
		nodeRole:     nodeRole,
		leaseMode:    mode,
		leaseValid:   valid,
		epoch:        epoch,
		writeAllowed: globalHA.WriteAllowed(),
		total:        total,
		connected:    connected,
		dpActive:     activeDPClient.Load() != nil,
	}
	return diagnoseClusterFrom(in, now)
}

// apiDiagnoseCluster reports cluster/HA posture (POST, operator). Read-only over
// in-memory state — no network, no shell, no secret/infra detail.
func apiDiagnoseCluster(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	d := diagnoseCluster(time.Now())
	auditEvent(r, "diagnose.cluster", d.Role, boolResult(d.OK))
	jsonOK(w, d)
}

// ── diagnose etcd ─────────────────────────────────────────────────────────────

// etcdProbeTimeout hard-bounds the fencing-lease reachability Read so a wedged or
// unreachable etcd endpoint cannot hang the handler. Generous enough for a
// cross-AZ round-trip; the etcd client's own dial is lazy so an unreachable
// endpoint surfaces as a deadline, not a stall.
const etcdProbeTimeout = 5 * time.Second

// etcdDiagnosis is the raw reachability fact for the HA fencing-lease (etcd)
// backend: is it reachable from THIS node, and what lease state does it report.
// Read-only and verdict-free beyond reachable/not — split-brain/quorum ANALYSIS
// is the TAC Cloud tier's job, not the appliance's. The etcd endpoints are never
// echoed (operator infra detail); only the lease's own holder/epoch (already
// surfaced on /api/cluster/ha) and a bounded transport error are returned.
type etcdDiagnosis struct {
	SchemaVersion int    `json:"schema_version"`
	GeneratedAt   string `json:"generated_at"`
	Configured    bool   `json:"configured"`             // an etcd fencing lease is armed on this node
	OK            bool   `json:"ok"`                     // reachable (or n/a when not configured)
	Status        string `json:"status"`                 // ok|error|n/a
	Reachable     bool   `json:"reachable,omitempty"`    // the bounded Read returned
	Holder        string `json:"holder,omitempty"`       // current lease holder candidate ID ("" = free)
	Epoch         int64  `json:"epoch,omitempty"`        // fencing epoch reported by the backend
	ValidForMs    int64  `json:"valid_for_ms,omitempty"` // remaining lease time per the backend
	LatencyMs     int64  `json:"latency_ms,omitempty"`   // probe round-trip
	Error         string `json:"error,omitempty"`        // bounded transport error when unreachable
	Note          string `json:"note,omitempty"`
}

// classifyEtcdProbe turns a probe outcome into the typed diagnosis. Pure (no
// I/O), so tests drive not-configured / reachable / unreachable without an etcd.
func classifyEtcdProbe(configured bool, st halease.Status, latency time.Duration, err error, now time.Time) etcdDiagnosis {
	d := etcdDiagnosis{
		SchemaVersion: diagnoseSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Configured:    configured,
	}
	if !configured {
		d.Status, d.OK = "n/a", true
		d.Note = "no etcd fencing lease configured on this node (legacy manual-failover or standalone HA); nothing to probe"
		return d
	}
	d.LatencyMs = latency.Milliseconds()
	if err != nil {
		d.Status, d.OK, d.Error = "error", false, boundedErr(err.Error())
		d.Note = "etcd fencing-lease backend is unreachable from this node — leadership is denied fail-closed until it recovers"
		return d
	}
	d.Reachable, d.OK, d.Status = true, true, "ok"
	d.Holder = st.Holder
	d.Epoch = st.Epoch
	if st.ValidFor > 0 {
		d.ValidForMs = st.ValidFor.Milliseconds()
	}
	if st.Holder == "" {
		d.Note = "etcd reachable; the fencing lease is currently free (no live leader holds it)"
	}
	return d
}

// diagnoseEtcd runs the bounded, read-only reachability probe against the
// configured etcd fencing-lease backend and classifies the result. The Read
// never mutates lease state (Provider.Read contract).
func diagnoseEtcd(ctx context.Context, now time.Time) etcdDiagnosis {
	start := time.Now()
	configured, st, err := globalHA.probeLeaseBackend(ctx)
	latency := time.Since(start)
	return classifyEtcdProbe(configured, st, latency, err, now)
}

// apiDiagnoseEtcd probes the HA fencing-lease (etcd) backend's reachability from
// this node (POST, operator). Read-only: a bounded, no-mutation Read against the
// operator-configured etcd endpoints. The endpoints are STARTUP config, never
// attacker-controllable, so the outbound is not SSRF-relevant and (unlike
// dns/tls) is deliberately NOT isPrivateHost-guarded — a fencing etcd normally
// lives on a private address; the context timeout is the only bound needed.
func apiDiagnoseEtcd(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), etcdProbeTimeout)
	defer cancel()
	d := diagnoseEtcd(ctx, time.Now())
	auditEvent(r, "diagnose.etcd", "etcd", boolResult(d.OK))
	jsonOK(w, d)
}

// diagnoseConfig assembles the live config snapshot and diagnoses it. The snapshot
// build is a read-only assembly over the config stores; the snapshot VALUES never
// leave this function (only counts + the verdict are returned).
func diagnoseConfig(now time.Time) configDiagnosis {
	syncing := nodeParticipatesInConfigSync()
	d := diagnoseConfigFrom(CurrentConfigSnapshot(), syncing, now)
	// P1 commit-time validation: if the CP's last publish was rejected (over-cap),
	// the fleet is on a stale snapshot — surface it as a degraded, named error
	// even if the operator has since trimmed the live config back under the cap
	// (the fleet only recovers on the next successful publish).
	if msg, ts := globalConfigStore.LastPublishError(); msg != "" {
		d.PublishRejected, d.PublishRejectedAt = msg, ts
		d.Status, d.OK = "degraded", false
		if d.Error == "" {
			d.Error = "last config publish rejected: " + msg
		}
	}
	return d
}

// nodeParticipatesInConfigSync reports whether this node actually exchanges
// ConfigSnapshots over the cluster wire — i.e. whether the per-slice caps gate
// anything for it. True for a Control Plane (it publishes snapshots) or an
// active Data Plane (it applies them); false for a standalone appliance, for
// which the caps are a dormant cluster-sync bound.
func nodeParticipatesInConfigSync() bool {
	clusterRoleMu.RLock()
	role := clusterRole.role
	clusterRoleMu.RUnlock()
	return role == "control-plane" || role == "data-plane" || activeDPClient.Load() != nil
}

// apiDiagnoseConfig reports live config-snapshot validity + non-secret sizes
// (POST, operator). Read-only, no network, no shell, no snapshot values.
func apiDiagnoseConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	d := diagnoseConfig(time.Now())
	auditEvent(r, "diagnose.config", "config", boolResult(d.OK))
	jsonOK(w, d)
}

// ── diagnose support ────────────────────────────────────────────────────────

// supportDiagnosis reports support-bundle STORE health: how many bundles are
// persisted, their aggregate on-disk size, the age spread, the retention bounds
// in force, and the janitor's activity (last sweep + evictions since boot). It
// answers "is my support-bundle store healthy, and why did a bundle disappear?"
// — counts, sizes, and a timestamp only, never bundle content. Read-only, no
// network, no shell.
type supportDiagnosis struct {
	SchemaVersion       int            `json:"schema_version"`
	GeneratedAt         string         `json:"generated_at"`
	OK                  bool           `json:"ok"`
	BundleCount         int            `json:"bundle_count"`
	PendingCount        int            `json:"pending_count"` // created but not yet approved
	TotalBytes          int64          `json:"total_bytes"`   // aggregate bundle.csb.tgz size
	OldestAgeHours      int64          `json:"oldest_age_hours,omitempty"`
	NewestAgeHours      int64          `json:"newest_age_hours,omitempty"`
	RetentionKeep       int            `json:"retention_keep"`
	RetentionMaxAgeDays int            `json:"retention_max_age_days"`
	RetentionEvicted    int64          `json:"retention_evicted_total"`
	LastSweep           string         `json:"retention_last_sweep,omitempty"`
	Checks              []storageCheck `json:"checks"`
}

// countBundleDirs returns how many csb_-shaped subdirectories exist under the
// bundle store (the RAW on-disk bundle count, before manifest parsing). An absent
// store is (0, nil) — a healthy empty store, created on the first bundle. A
// present-but-unreadable directory returns the ReadDir error so the caller can
// fault the diagnosis instead of silently reporting empty.
func countBundleDirs() (int, error) {
	entries, err := os.ReadDir(supportBundlesDir())
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil // no bundle written yet
		}
		return 0, err
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() && supportBundleIDRe.MatchString(e.Name()) {
			n++
		}
	}
	return n, nil
}

// diagnoseSupport inspects the persisted support-bundle store. now is injected for
// deterministic timestamps in tests. It only reads bundle summaries (secret-free by
// construction) and the retention observability atoms — it never opens a bundle.
func diagnoseSupport(now time.Time) supportDiagnosis {
	d := supportDiagnosis{
		SchemaVersion:       diagnoseSchemaVersion,
		GeneratedAt:         now.UTC().Format(time.RFC3339),
		RetentionKeep:       supportRetentionKeepVal(),
		RetentionMaxAgeDays: int(supportRetentionMaxAgeVal() / (24 * time.Hour)),
		RetentionEvicted:    supportRetentionEvicted.Load(),
	}
	if u := supportRetentionLastSweep.Load(); u > 0 {
		d.LastSweep = time.Unix(u, 0).UTC().Format(time.RFC3339)
	}

	sums := listSupportBundles() // newest-first, path-guarded, secret-free
	d.BundleCount = len(sums)
	var oldest, newest time.Time
	for i := range sums {
		s := &sums[i]
		d.TotalBytes += s.SizeBytes
		if s.State == bundleStatePending {
			d.PendingCount++
		}
		if t, err := time.Parse(time.RFC3339, s.CreatedAt); err == nil {
			if oldest.IsZero() || t.Before(oldest) {
				oldest = t
			}
			if t.After(newest) {
				newest = t
			}
		}
	}
	if !oldest.IsZero() {
		d.OldestAgeHours = int64(now.Sub(oldest).Hours())
		d.NewestAgeHours = int64(now.Sub(newest).Hours())
	}

	d.Checks = supportStoreChecks(now, oldest, d.BundleCount)

	d.OK = true
	for i := range d.Checks {
		if !d.Checks[i].OK {
			d.OK = false
			break
		}
	}
	return d
}

// supportStoreChecks builds the health checks for the bundle store. Split out of
// diagnoseSupport to keep it under the cyclop threshold. now/oldest are injected;
// bundleCount is the PARSED-summary count from listSupportBundles.
func supportStoreChecks(now, oldest time.Time, bundleCount int) []storageCheck {
	dir := supportBundlesDir()
	var checks []storageCheck

	// Store readability + manifest integrity. listSupportBundles is deliberately
	// LENIENT — empty on a ReadDir error, silently skips unreadable/corrupt
	// manifests — so a broken store would otherwise read as a healthy EMPTY store
	// (Codex #834). Cross-check the raw csb_-shaped subdir count against the parsed
	// count: a ReadDir failure or a shortfall (a dir present but not parsed) faults.
	rawDirs, readErr := countBundleDirs()
	switch {
	case readErr != nil:
		checks = append(checks, storageCheck{Name: "bundles_dir_readable", Path: dir, OK: false, Detail: "readdir: " + readErr.Error()})
	case rawDirs > bundleCount:
		checks = append(checks, storageCheck{Name: "bundles_dir_readable", Path: dir, OK: false,
			Detail: strconv.Itoa(rawDirs-bundleCount) + " bundle dir(s) unreadable/corrupt (present on disk but not parsed)"})
	default:
		checks = append(checks, storageCheck{Name: "bundles_dir_readable", Path: dir, OK: true})
	}

	// Count cap honored. The janitor evicts oldest-first on a new build and on the
	// age tick, so an overflow beyond keep signals a stuck/failing janitor. keep==0
	// disables the cap. Read the configurable cap once (Slice B).
	keep := supportRetentionKeepVal()
	if keep > 0 {
		overCap := bundleCount > keep
		detail := ""
		if overCap {
			detail = "count " + strconv.Itoa(bundleCount) + " exceeds keep cap " + strconv.Itoa(keep)
		}
		checks = append(checks, storageCheck{Name: "within_count_cap", Path: dir, OK: !overCap, Detail: detail})
	}

	// Age cap honored. A store can sit under the count cap with only a few bundles
	// yet still hold ones older than max-age if the background janitor is stopped or
	// failing (Codex #834) — the count cap alone can't catch that. maxAge<=0 disables.
	maxAge := supportRetentionMaxAgeVal()
	if maxAge > 0 && !oldest.IsZero() {
		overAge := now.Sub(oldest) > maxAge
		detail := ""
		if overAge {
			detail = "oldest bundle age " + strconv.FormatInt(int64(now.Sub(oldest).Hours())/24, 10) + "d exceeds max-age " +
				strconv.Itoa(int(maxAge/(24*time.Hour))) + "d — the age janitor may be stopped or failing"
		}
		checks = append(checks, storageCheck{Name: "within_age_cap", Path: dir, OK: !overAge, Detail: detail})
	}
	return checks
}

// apiDiagnoseSupport reports support-bundle store health (POST, operator).
// Read-only, no network, no shell, no bundle content.
func apiDiagnoseSupport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	d := diagnoseSupport(time.Now())
	auditEvent(r, "diagnose.support", "support", boolResult(d.OK))
	jsonOK(w, d)
}

// ── diagnose all ──────────────────────────────────────────────────────────────

// allDiagnosis aggregates every NO-INPUT local diagnostic into one snapshot so an
// operator/TAC can run a single "local health" check. It deliberately excludes the
// dns/tls verbs (they require a target host and touch the network); all four
// members here are local + in-memory (storage does only its own create+remove
// writability probe). OK is the AND of the members — a single degraded check makes
// the aggregate degraded.
type allDiagnosis struct {
	SchemaVersion int               `json:"schema_version"`
	GeneratedAt   string            `json:"generated_at"`
	OK            bool              `json:"ok"`
	Storage       storageDiagnosis  `json:"storage"`
	Upstream      upstreamDiagnosis `json:"upstream"`
	Cluster       clusterDiagnosis  `json:"cluster"`
	Config        configDiagnosis   `json:"config"`
}

// diagnoseAll runs the no-input local verbs and aggregates them. now is injected
// for deterministic timestamps in tests. No verb here audits on its own (the
// per-verb audit lives in the individual handlers), so the caller emits one
// diagnose.all event.
func diagnoseAll(now time.Time) allDiagnosis {
	d := allDiagnosis{
		SchemaVersion: diagnoseSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339),
		Storage:       diagnoseStorage(now),
		Upstream:      diagnoseUpstream(now),
		Cluster:       diagnoseCluster(now),
		Config:        diagnoseConfig(now),
	}
	d.OK = d.Storage.OK && d.Upstream.OK && d.Cluster.OK && d.Config.OK
	return d
}

// apiDiagnoseAll runs every no-input local diagnostic in one call (POST, operator).
// Read-only (bar the storage writability probe), no network, no shell.
func apiDiagnoseAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireRole(w, r, RoleOperator) {
		return
	}
	d := diagnoseAll(time.Now())
	auditEvent(r, "diagnose.all", "all", boolResult(d.OK))
	jsonOK(w, d)
}

// registerDiagnoseRoutes wires the diagnose verb surface.
func registerDiagnoseRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/api/diagnose/storage", apiDiagnoseStorage)
	mux.HandleFunc("/api/diagnose/upstream", apiDiagnoseUpstream)
	mux.HandleFunc("/api/diagnose/dns", apiDiagnoseDNS)
	mux.HandleFunc("/api/diagnose/tls", apiDiagnoseTLS)
	mux.HandleFunc("/api/diagnose/cluster", apiDiagnoseCluster)
	mux.HandleFunc("/api/diagnose/etcd", apiDiagnoseEtcd)
	mux.HandleFunc("/api/diagnose/config", apiDiagnoseConfig)
	mux.HandleFunc("/api/diagnose/support", apiDiagnoseSupport)
	mux.HandleFunc("/api/diagnose/all", apiDiagnoseAll)
}
