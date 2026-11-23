//go:build socks5_e2e

package main

// env.go — everything the cases run against: the upstream servers, the hosts
// override, the LDAP directory process and the Culvert process itself.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Hostnames the cases use. All of them resolve to the upstream address through
// the hosts override; none of them is ever looked up in real DNS.
const (
	hostAllow    = "allow.e2e.test"
	hostDrop     = "drop.e2e.test"
	hostBlock    = "block.e2e.test"
	hostRedirect = "redirect.e2e.test"
	hostInspect  = "inspect.e2e.test"
	hostGroup    = "group.e2e.test"
	hostIdentity = "identity.e2e.test"
	hostThreat   = "malware.e2e.test"
	hostUnlisted = "unlisted.e2e.test"
	hostPortal   = "portal.e2e.test" // the Redirect rule's target; must resolve for isSafeRedirectURL
)

var allHosts = []string{hostAllow, hostDrop, hostBlock, hostRedirect, hostInspect, hostGroup, hostIdentity, hostThreat, hostUnlisted, hostPortal}

// Directory fixture. The admin-console account is deliberately NOT a
// directory user.
const (
	ldapPeopleBase = "ou=people,dc=e2e,dc=test"
	ldapServiceDN  = "cn=culvert-svc,ou=service,dc=e2e,dc=test"
	ldapServicePW  = "svc-secret-e2e"
	groupEngDN     = "cn=engineering,ou=groups,dc=e2e,dc=test"
	groupFinDN     = "cn=finance,ou=groups,dc=e2e,dc=test"
	aliceDN        = "uid=alice,ou=people,dc=e2e,dc=test"
	bobDN          = "uid=bob,ou=people,dc=e2e,dc=test"
	idpProfileID   = "corp-ldap"

	adminUser = "admin"
	adminPass = "Admin-Console-Pw-9!" // admin-console (local) account; never a directory user
)

var (
	credAlice      = &cred{"alice", "alice-pw-e2e"}
	credBob        = &cred{"bob", "bob-pw-e2e"}
	credAliceWrong = &cred{"alice", "not-alices-password"}
	credAdmin      = &cred{adminUser, adminPass}
	credUnknown    = &cred{"mallory", "whatever-pw"}
)

type cred struct{ User, Pass string }

// guardPrivateRanges mirrors internal/ssrf privateRanges (IPv4 part). It is
// used ONLY to pick an upstream address the production guard will admit; the
// guard itself is never changed. The Allow cases then prove Culvert agreed.
var guardPrivateRanges = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/4", "240.0.0.0/4",
}

func guardWouldRefuse(ip net.IP) bool {
	for _, r := range guardPrivateRanges {
		_, n, _ := net.ParseCIDR(r)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// pickUpstreamIP returns a local IPv4 address the SSRF guard classifies as
// public (for example a TEST-NET address on the container interface).
func pickUpstreamIP(flagVal string) (string, error) {
	if flagVal != "" && flagVal != "auto" {
		ip := net.ParseIP(flagVal)
		if ip == nil || ip.To4() == nil {
			return "", fmt.Errorf("-upstream-ip %q is not an IPv4 address", flagVal)
		}
		if guardWouldRefuse(ip) {
			return "", fmt.Errorf("-upstream-ip %s is in a range the SSRF guard refuses; every Allow case would fail", flagVal)
		}
		return flagVal, nil
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.To4() == nil || guardWouldRefuse(n.IP) {
			continue
		}
		return n.IP.String(), nil
	}
	return "", errors.New("no local IPv4 address outside the SSRF guard's private ranges; " +
		"add one (e.g. `ip addr add 198.51.100.10/32 dev lo`) and pass -upstream-ip, see README")
}

// bindHosts bind-mounts a hosts file over /etc/hosts. It refuses unless this
// process is in a mount namespace of its own (run.sh starts it under
// `unshare -m`), so the host's /etc/hosts is never touched.
func bindHosts(dir, ip string) error {
	// run.sh records the mount namespace it was started in before calling
	// `unshare -m`; ours must differ from it (and from PID 1's, where that is
	// visible).
	self, err := os.Readlink("/proc/self/ns/mnt")
	outer := os.Getenv("CULVERT_E2E_OUTER_MNTNS")
	initNS, _ := os.Readlink("/proc/1/ns/mnt")
	if err != nil || outer == "" || self == outer || self == initNS {
		return fmt.Errorf("refusing to bind-mount /etc/hosts outside a private mount namespace (self=%q outer=%q init=%q); run via run.sh (unshare -m)", self, outer, initNS)
	}
	content := fmt.Sprintf("127.0.0.1 localhost\n%s %s\n", ip, strings.Join(allHosts, " "))
	p := filepath.Join(dir, "hosts")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		return err
	}
	if err := syscall.Mount(p, "/etc/hosts", "", syscall.MS_BIND, ""); err != nil {
		return fmt.Errorf("bind-mount hosts: %w", err)
	}
	addrs, err := net.DefaultResolver.LookupHost(context.Background(), hostAllow)
	if err != nil || len(addrs) == 0 || addrs[0] != ip {
		return fmt.Errorf("hosts override not effective: %s -> %v (%v)", hostAllow, addrs, err)
	}
	return nil
}

// ── Upstream servers ────────────────────────────────────────────────────────

type upstreams struct {
	ip                          string
	echoPort, httpPort, tlsPort int
	caPool                      *x509.CertPool // the upstream test CA (NOT Culvert's)
	closers                     []io.Closer
}

const (
	upstreamHTTPBody = "hello-from-upstream"
	upstreamTLSBody  = "hello-from-upstream-tls"
)

func startUpstreams(ip string) (*upstreams, error) {
	u := &upstreams{ip: ip}
	// TCP echo.
	ln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, fmt.Errorf("echo listen on %s: %w", ip, err)
	}
	u.closers = append(u.closers, ln)
	u.echoPort = ln.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(30 * time.Second))
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	// Plain HTTP.
	hln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	u.closers = append(u.closers, hln)
	u.httpPort = hln.Addr().(*net.TCPAddr).Port
	hsrv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, upstreamHTTPBody)
	})}
	go func() { _ = hsrv.Serve(hln) }()
	// HTTPS with a leaf from the upstream test CA.
	caCert, caKey, err := newCA("Culvert E2E Upstream Test CA")
	if err != nil {
		return nil, err
	}
	u.caPool = x509.NewCertPool()
	u.caPool.AddCert(caCert)
	leaf, err := newLeaf(caCert, caKey, append([]string{"*.e2e.test"}, allHosts...))
	if err != nil {
		return nil, err
	}
	tln, err := net.Listen("tcp", net.JoinHostPort(ip, "0"))
	if err != nil {
		return nil, err
	}
	u.closers = append(u.closers, tln)
	u.tlsPort = tln.Addr().(*net.TCPAddr).Port
	tsrv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, upstreamTLSBody)
	})}
	go func() {
		_ = tsrv.Serve(tls.NewListener(tln, &tls.Config{Certificates: []tls.Certificate{leaf}, MinVersion: tls.VersionTLS12}))
	}()
	return u, nil
}

func (u *upstreams) close() {
	for _, c := range u.closers {
		_ = c.Close()
	}
}

func newCA(cn string) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"Culvert SOCKS5 E2E"}},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, key, err
}

func newLeaf(ca *x509.Certificate, caKey *ecdsa.PrivateKey, names []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// ── LDAP directory process ──────────────────────────────────────────────────

type ldapProc struct {
	addr   string
	events string
	cmd    *exec.Cmd
}

func startLDAP(bin, dir string) (*ldapProc, error) {
	type user struct {
		UID         string   `json:"uid"`
		DN          string   `json:"dn"`
		Password    string   `json:"password"`
		Mail        string   `json:"mail"`
		DisplayName string   `json:"displayName"`
		MemberOf    []string `json:"memberOf"`
	}
	fx := map[string]any{
		"peopleBase": ldapPeopleBase,
		"userAttr":   "uid",
		"service":    map[string]string{"dn": ldapServiceDN, "password": ldapServicePW},
		"users": []user{
			{UID: "alice", DN: aliceDN, Password: credAlice.Pass, Mail: "alice@e2e.test", DisplayName: "Alice", MemberOf: []string{groupEngDN}},
			{UID: "bob", DN: bobDN, Password: credBob.Pass, Mail: "bob@e2e.test", DisplayName: "Bob", MemberOf: []string{groupFinDN}},
		},
	}
	fxPath := filepath.Join(dir, "ldap-fixture.json")
	if err := writeJSON(fxPath, fx); err != nil {
		return nil, err
	}
	ready := filepath.Join(dir, "ldap-ready")
	events := filepath.Join(dir, "ldap-events.jsonl")
	logf, err := os.Create(filepath.Join(dir, "ldapserver.log"))
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(bin, "-listen", "127.0.0.1:0", "-fixture", fxPath, "-ready-file", ready, "-events", events)
	cmd.Stdout, cmd.Stderr = logf, logf
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(ready); err == nil && len(b) > 0 {
			return &ldapProc{addr: string(b), events: events, cmd: cmd}, nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	return nil, errors.New("ldapserver did not become ready in 15s")
}

func (l *ldapProc) stop() {
	if l != nil && l.cmd != nil && l.cmd.Process != nil {
		_ = l.cmd.Process.Signal(syscall.SIGTERM)
		_, _ = l.cmd.Process.Wait()
	}
}

// ── Culvert process ─────────────────────────────────────────────────────────

type culvert struct {
	mode                         string
	dir                          string
	proxyPort, uiPort, socksPort int
	reqLog, logPath              string
	metricsToken                 string
	cmd                          *exec.Cmd
	caPool                       *x509.CertPool // Culvert's inspection root, fetched from the admin API
}

func freePort() (int, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port, nil
}

// policyRules is the access policy every mode loads. Order is priority.
func policyRules() []map[string]any {
	return []map[string]any{
		{"priority": 1, "name": "allow-clean", "destFQDN": hostAllow, "action": "Allow", "sslAction": "Bypass"},
		{"priority": 2, "name": "drop-rule", "destFQDN": hostDrop, "action": "Drop"},
		{"priority": 3, "name": "block-page", "destFQDN": hostBlock, "action": "Block_Page"},
		{"priority": 4, "name": "redirect-rule", "destFQDN": hostRedirect, "action": "Redirect", "redirectURL": "https://" + hostPortal + "/blocked"},
		// Allow WITH TLS inspection: CONNECT inspects it; SOCKS5 enforce must
		// refuse it (inspection_unsupported), never tunnel it uninspected.
		{"priority": 5, "name": "inspect-allow", "destFQDN": hostInspect, "action": "Allow", "sslAction": "Inspect", "tlsSkipVerify": true},
		// Group + auth-source scoped rule (LDAP group DN, verbatim memberOf).
		{"priority": 6, "name": "group-eng-allow", "sourceGroup": groupEngDN, "authSource": "ldap:" + idpProfileID, "destFQDN": hostGroup, "action": "Allow", "sslAction": "Bypass"},
		{"priority": 7, "name": "group-others-block", "destFQDN": hostGroup, "action": "Block_Page"},
		// Identity-scoped rule (the LDAP profile's identity is the user DN).
		{"priority": 8, "name": "identity-bob-allow", "sourceIdentity": bobDN, "destFQDN": hostIdentity, "action": "Allow", "sslAction": "Bypass"},
		{"priority": 9, "name": "identity-others-block", "destFQDN": hostIdentity, "action": "Block_Page"},
		// An Allow rule for a feed-listed domain: the feed must win, in every mode.
		{"priority": 10, "name": "threat-listed-allow", "destFQDN": hostThreat, "action": "Allow", "sslAction": "Bypass"},
	}
}

func startCulvert(bin, mode, dir string, ldapAddr string) (*culvert, error) {
	c := &culvert{mode: mode, dir: dir, metricsToken: "e2e-metrics-token"}
	var err error
	for _, p := range []*int{&c.proxyPort, &c.uiPort, &c.socksPort} {
		if *p, err = freePort(); err != nil {
			return nil, err
		}
	}
	data := filepath.Join(dir, "data")
	if err := os.MkdirAll(data, 0o700); err != nil {
		return nil, err
	}
	now := time.Now().UTC().Format(time.RFC3339)
	// Threat feed DB: one domain entry (what the SOCKS5/CONNECT domain gate
	// reads) plus one URL entry. The URL entry is load-bearing: the feed
	// counts only URLs as "entries", and an empty count makes the scheduler
	// sync the public feeds at startup — which would send traffic off-box.
	feed := map[string]any{
		"last_sync": now, "last_success": now,
		"urls":    map[string]any{"http://" + hostThreat + "/payload.exe": map[string]string{"source": "e2e-local", "added_at": now}},
		"domains": map[string]any{hostThreat: map[string]string{"source": "e2e-local", "added_at": now}},
	}
	idp := []map[string]any{{
		"id": idpProfileID, "name": "E2E LDAP", "type": "ldap", "enabled": true, "emailDomains": []string{},
		"ldap": map[string]any{
			"url": "ldap://" + ldapAddr, "bindDn": ldapServiceDN, "bindPassword": ldapServicePW,
			"baseDn": ldapPeopleBase, "userFilter": "(uid=%s)", "cacheTtlSeconds": 10,
		},
	}}
	files := map[string]any{"threatfeed.json": feed, "idp_profiles.json": idp, "policy.json": policyRules()}
	for name, v := range files {
		if err := writeJSON(filepath.Join(dir, name), v); err != nil {
			return nil, err
		}
	}
	c.reqLog = filepath.Join(dir, "requests.jsonl")
	c.logPath = filepath.Join(dir, "culvert.log")
	// legacy is exercised as the DEFAULT: the key is absent, which is what
	// every existing deployment runs.
	modeLine := ""
	if mode != "legacy" {
		modeLine = fmt.Sprintf("  socks5_policy_mode: %s\n", mode)
	}
	yaml := fmt.Sprintf(`proxy:
  port: %d
  ui_port: %d
  socks5_port: %d
%s  policy_file: %q
  idp_profiles_file: %q
  metrics_token: %q
auth:
  user: %q
  pass: %q
default_action: deny
security_scan:
  threat_feed_db: %q
  sync_interval: "24h"
request_log_file: %q
`, c.proxyPort, c.uiPort, c.socksPort, modeLine,
		filepath.Join(dir, "policy.json"), filepath.Join(dir, "idp_profiles.json"), c.metricsToken,
		adminUser, adminPass, filepath.Join(dir, "threatfeed.json"), c.reqLog)
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(yaml), 0o600); err != nil {
		return nil, err
	}
	logf, err := os.Create(c.logPath)
	if err != nil {
		return nil, err
	}
	c.cmd = exec.Command(bin, "-config", cfgPath, "-ui-no-tls")
	c.cmd.Dir = dir
	// A minimal environment: no proxy variables (test traffic stays local),
	// a private data dir, and the requested parallelism.
	c.cmd.Env = []string{"PATH=/usr/local/bin:/usr/bin:/bin", "HOME=" + dir, "CULVERT_DATA_DIR=" + data, "GOMAXPROCS=2"}
	c.cmd.Stdout, c.cmd.Stderr = logf, logf
	if err := c.cmd.Start(); err != nil {
		return nil, err
	}
	if err := c.waitReady(); err != nil {
		c.stop()
		return nil, err
	}
	if err := c.fetchCA(); err != nil {
		c.stop()
		return nil, err
	}
	return c, nil
}

func (c *culvert) waitReady() error {
	deadline := time.Now().Add(45 * time.Second)
	cl := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	for time.Now().Before(deadline) {
		if c.cmd.ProcessState != nil {
			return errors.New("culvert exited during startup")
		}
		resp, err := cl.Get(fmt.Sprintf("http://127.0.0.1:%d/health", c.proxyPort))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK && c.socksAcceptsGreeting() {
				return nil
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	return fmt.Errorf("culvert (%s) not ready within 45s; see %s", c.mode, c.logPath)
}

// socksAcceptsGreeting is true once the SOCKS5 listener answers a greeting
// (the startup posture gate closes connections without one until then).
func (c *culvert) socksAcceptsGreeting() bool {
	conn, err := net.DialTimeout("tcp", c.socksAddr(), 2*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte{5, 1, 2}); err != nil {
		return false
	}
	b := make([]byte, 2)
	_, err = io.ReadFull(conn, b)
	return err == nil && b[0] == 5 && b[1] == 2
}

// fetchCA signs in to the admin API with the admin-console account and
// downloads Culvert's inspection root, so an inspected CONNECT tunnel can be
// verified against it (and told apart from the upstream's own certificate).
func (c *culvert) fetchCA() error {
	jar, _ := cookiejar.New(nil)
	cl := &http.Client{Timeout: 5 * time.Second, Jar: jar, Transport: &http.Transport{Proxy: nil}}
	base := fmt.Sprintf("http://127.0.0.1:%d", c.uiPort)
	body, _ := json.Marshal(map[string]string{"user": adminUser, "pass": adminPass})
	resp, err := cl.Post(base+"/api/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("admin login: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("admin login: HTTP %d", resp.StatusCode)
	}
	resp, err = cl.Get(base + "/api/ca-cert")
	if err != nil {
		return fmt.Errorf("ca-cert: %w", err)
	}
	defer resp.Body.Close()
	pemBytes, _ := io.ReadAll(resp.Body)
	blk, _ := pem.Decode(pemBytes)
	if resp.StatusCode != http.StatusOK || blk == nil {
		return fmt.Errorf("ca-cert: HTTP %d, no PEM", resp.StatusCode)
	}
	ca, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return err
	}
	c.caPool = x509.NewCertPool()
	c.caPool.AddCert(ca)
	return nil
}

func (c *culvert) socksAddr() string { return fmt.Sprintf("127.0.0.1:%d", c.socksPort) }
func (c *culvert) proxyAddr() string { return fmt.Sprintf("127.0.0.1:%d", c.proxyPort) }

func (c *culvert) stop() {
	if c.cmd == nil || c.cmd.Process == nil {
		return
	}
	_ = c.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = c.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		_ = c.cmd.Process.Kill()
		<-done
	}
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}
