package main

// FE-6B.1 CORRECTION ROUND — RED matrix, committed on the reviewed candidate
// 935891f4 BEFORE any product change. External review blocker B1: the
// activation of the admin-listener certificate was CLAIMED from a boot-time
// selection flag (uiCustomTLSActive, set when resolveUITLSCertKey picked the
// persisted pair at process start) that (a) never observes whether the
// listener actually bound and what it serves, (b) stays true after the
// persisted pair is REPLACED or DELETED without a restart — so the inventory
// showed pair B's identity beside "active" while the listener still served A —
// and (c) is the one variable behind BOTH `uiCert.active` (GET
// /api/certificates) and `ui_custom_cert_active` (GET /api/settings/network),
// so their agreement proved nothing.
//
// The authorised correction publishes a server-owned LISTENER posture and the
// SERVED certificate identity from the listener's own bind evidence, separately
// from the persisted-pair identity; `active` is derived from that evidence
// (served == persisted), and activation that has not been observed stays
// UNKNOWN. These rows pin that contract; every served identity is checked
// against a REAL TLS handshake with the bound listener.
//
//	C01 A served, B persisted (no restart): active is FALSE; the listener still
//	    names A (the TLS peer certificate IS A); the persisted identity is B.
//	C02 restart activates B: served == persisted, active TRUE.
//	C03 a plain-HTTP listener (no certificate, self-signing off) never claims
//	    activation, before or after a pair is persisted.
//	C04 an explicitly configured pair (-tls-cert/-tls-key) is served
//	    (tls_configured) and a persisted pair is NOT active.
//	C05 before the listener binds, activation is UNKNOWN — never true from the
//	    boot flag alone.
//	C06 deleting the persisted pair while A is served: the served identity
//	    stays A, the persisted pair is absent, active is FALSE.
//	C07 the auto self-signed posture carries its served identity; a persisted
//	    pair beside it is not active.
//	C08 the network-settings read carries the SAME listener evidence object.
//	C09 a listener that stopped is no longer evidence: unknown again.

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"
	"time"

	"github.com/KidCarmi/Culvert/internal/ca"
)

func fe6b1cNode(t *testing.T) (dir string, mux *http.ServeMux) {
	t.Helper()
	dir = fe6b0Node(t)
	resetAdminUIHealthForTest()
	t.Cleanup(resetAdminUIHealthForTest)
	return dir, fe6b0Mux()
}

// fe6b1cBootSelect replays the boot-time selection (main.go: resolveUITLSCertKey
// runs before startUI) from a clean flag state.
func fe6b1cBootSelect(t *testing.T, explicitCert, explicitKey string) (certPath, keyPath string) {
	t.Helper()
	uiCustomTLSActive = false
	uiCustomTLSCorrupt = false
	return resolveUITLSCertKey(explicitCert, explicitKey)
}

// fe6b1cServe binds the admin listener the way startUI does — the operator /
// persisted pair when given, else the auto self-signed config when selfSigned,
// else plain HTTP — and returns its address plus a stop func that waits for the
// serve loop to exit.
func fe6b1cServe(t *testing.T, certPath, keyPath string, selfSigned bool) (addr string, stop func()) {
	t.Helper()
	port, release := occupyPort(t)
	release()
	srv := newTestAdminServer()
	if certPath == "" && selfSigned {
		cfg, err := selfSignedTLS()
		if err != nil {
			t.Fatalf("selfSignedTLS: %v", err)
		}
		srv.TLSConfig = cfg
	}
	noteAdminUIConfigured(port)
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		serveAdminUIWithRetry(srv, port, certPath, keyPath, stopCh)
	}()
	waitForAdminUI(t, 5*time.Second, "the admin listener to bind", func() bool {
		return adminUIListenerState().Serving
	})
	addr = net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	return addr, func() {
		close(stopCh)
		_ = srv.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatalf("the serve loop did not exit")
		}
	}
}

// fe6b1cPeerFingerprint performs a REAL TLS handshake with the bound listener
// and returns the certificate it presented, in the inventory's fingerprint
// format. Trust is skipped on purpose: the identity, not the chain, is what
// these rows compare.
func fe6b1cPeerFingerprint(t *testing.T, addr string) string {
	t.Helper()
	d := &net.Dialer{Timeout: 3 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test peer-identity read
	if err != nil {
		t.Fatalf("tls dial %s: %v", addr, err)
	}
	defer conn.Close() //nolint:errcheck
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatalf("no peer certificate from %s", addr)
	}
	return ca.FingerprintOf(certs[0])
}

// fe6b1cPEMFingerprint is the inventory-format fingerprint of a PEM leaf.
func fe6b1cPEMFingerprint(t *testing.T, certPEM []byte) string {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("not PEM")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return ca.FingerprintOf(leaf)
}

func fe6b1cInventory(t *testing.T, mux *http.ServeMux) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, viewerCtx(getReq("/api/certificates")))
	if w.Code != http.StatusOK {
		t.Fatalf("inventory = %d %s", w.Code, w.Body.String())
	}
	return fe6b0Decode(w)
}

func fe6b1cNetwork(t *testing.T) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	apiNetworkSettings(w, viewerCtx(getReq("/api/settings/network")))
	if w.Code != http.StatusOK {
		t.Fatalf("network = %d %s", w.Code, w.Body.String())
	}
	return fe6b0Decode(w)
}

func fe6b1cUICert(t *testing.T, inv map[string]any) map[string]any {
	t.Helper()
	uc, _ := inv["uiCert"].(map[string]any)
	if uc == nil {
		t.Fatalf("no uiCert in %v", inv)
	}
	return uc
}

// fe6b1cListener returns the server-owned listener evidence, failing the row
// when the read model carries none (the reviewed candidate).
func fe6b1cListener(t *testing.T, m map[string]any, key string) map[string]any {
	t.Helper()
	l, _ := m[key].(map[string]any)
	if l == nil {
		t.Fatalf("no %q listener evidence on the read model (activation is claimed without evidence): %v", key, m)
	}
	return l
}

func fe6b1cServed(t *testing.T, l map[string]any) map[string]any {
	t.Helper()
	s, _ := l["servedCertificate"].(map[string]any)
	if s == nil {
		t.Fatalf("no servedCertificate in %v", l)
	}
	return s
}

func fe6b1cAssertNotActive(t *testing.T, mux *http.ServeMux, why string) {
	t.Helper()
	inv := fe6b1cInventory(t, mux)
	if act, _ := fe6b1cUICert(t, inv)["active"].(bool); act {
		t.Fatalf("uiCert.active = true (%s)", why)
	}
	if act, _ := fe6b1cNetwork(t)["ui_custom_cert_active"].(bool); act {
		t.Fatalf("ui_custom_cert_active = true (%s)", why)
	}
}

// fe6b1cServeA seeds pair A through the admin API, replays the boot selection,
// binds the listener with it and proves the peer certificate is A.
func fe6b1cServeA(t *testing.T, mux *http.ServeMux) (fpA, addr string, stop func()) {
	t.Helper()
	fe6b0eSeedPair(t, mux, "ui-a.fe6b1c")
	fpA, _ = fe6b1cUICert(t, fe6b1cInventory(t, mux))["fingerprint"].(string)
	if fpA == "" {
		t.Fatalf("no persisted fingerprint for A")
	}
	certPath, keyPath := fe6b1cBootSelect(t, "", "")
	if certPath != customUITLSCertPath() {
		t.Fatalf("boot selection did not pick the persisted pair: %q", certPath)
	}
	addr, stop = fe6b1cServe(t, certPath, keyPath, false)
	if got := fe6b1cPeerFingerprint(t, addr); got != fpA {
		t.Fatalf("TLS peer = %s, want A %s", got, fpA)
	}
	return fpA, addr, stop
}

// ── C01 / C02 ───────────────────────────────────────────────────────────────

func TestFE6B1C_C01_ReplacedPairWithoutRestartIsNotActive(t *testing.T) {
	_, mux := fe6b1cNode(t)
	fpA, addr, stop := fe6b1cServeA(t, mux)
	defer stop()

	inv := fe6b1cInventory(t, mux)
	if act, _ := fe6b1cUICert(t, inv)["active"].(bool); !act {
		t.Fatalf("A served and persisted: uiCert.active must be true")
	}
	l := fe6b1cListener(t, inv, "listener")
	if l["state"] != "serving" || l["posture"] != "tls_custom" {
		t.Fatalf("listener = %v, want serving/tls_custom", l)
	}
	if got := fe6b1cServed(t, l)["fingerprint"]; got != fpA {
		t.Fatalf("servedCertificate.fingerprint = %v, want %s", got, fpA)
	}

	// Replace the persisted pair with B WITHOUT a restart.
	_, _, _ = fe6b0eSeedPair(t, mux, "ui-b.fe6b1c")
	inv = fe6b1cInventory(t, mux)
	fpB, _ := fe6b1cUICert(t, inv)["fingerprint"].(string)
	if fpB == "" || fpB == fpA {
		t.Fatalf("persisted identity after replace = %q, want a new pair", fpB)
	}
	if act, _ := fe6b1cUICert(t, inv)["active"].(bool); act {
		t.Fatalf("B persisted while the listener still serves A: uiCert.active must be FALSE (the reviewed candidate reports true)")
	}
	if act, _ := fe6b1cNetwork(t)["ui_custom_cert_active"].(bool); act {
		t.Fatalf("ui_custom_cert_active must be FALSE after the replacement")
	}
	l = fe6b1cListener(t, inv, "listener")
	if got := fe6b1cServed(t, l)["fingerprint"]; got != fpA {
		t.Fatalf("the served identity must stay A after B is persisted; got %v", got)
	}
	if sp, _ := l["servesPersistedPair"].(bool); sp {
		t.Fatalf("servesPersistedPair must be false when served != persisted")
	}
	if got := fe6b1cPeerFingerprint(t, addr); got != fpA {
		t.Fatalf("real TLS peer after replace = %s, want A %s", got, fpA)
	}
}

func TestFE6B1C_C02_RestartActivatesThePersistedPair(t *testing.T) {
	_, mux := fe6b1cNode(t)
	_, _, stop := fe6b1cServeA(t, mux)
	_, _, _ = fe6b0eSeedPair(t, mux, "ui-b.fe6b1c")
	stop()

	// C09 first: a listener that has STOPPED is no longer evidence.
	l := fe6b1cListener(t, fe6b1cInventory(t, mux), "listener")
	if l["state"] != "unknown" {
		t.Fatalf("after the listener stopped: state = %v, want unknown", l["state"])
	}

	// "Restart": boot selection again, listener again.
	certPath, keyPath := fe6b1cBootSelect(t, "", "")
	addr, stop2 := fe6b1cServe(t, certPath, keyPath, false)
	defer stop2()
	inv := fe6b1cInventory(t, mux)
	fpB, _ := fe6b1cUICert(t, inv)["fingerprint"].(string)
	if got := fe6b1cPeerFingerprint(t, addr); got != fpB {
		t.Fatalf("TLS peer after restart = %s, want B %s", got, fpB)
	}
	if act, _ := fe6b1cUICert(t, inv)["active"].(bool); !act {
		t.Fatalf("served == persisted after the restart: uiCert.active must be true")
	}
	l = fe6b1cListener(t, inv, "listener")
	if got := fe6b1cServed(t, l)["fingerprint"]; got != fpB {
		t.Fatalf("servedCertificate after restart = %v, want B %s", got, fpB)
	}
	if sp, _ := l["servesPersistedPair"].(bool); !sp {
		t.Fatalf("servesPersistedPair must be true when served == persisted")
	}
}

// ── C03 plain HTTP ──────────────────────────────────────────────────────────

func TestFE6B1C_C03_PlainHTTPListenerNeverClaimsActivation(t *testing.T) {
	_, mux := fe6b1cNode(t)
	certPath, keyPath := fe6b1cBootSelect(t, "", "")
	if certPath != "" || keyPath != "" {
		t.Fatalf("no persisted pair: boot selection must pick nothing")
	}
	_, stop := fe6b1cServe(t, "", "", false)
	defer stop()

	inv := fe6b1cInventory(t, mux)
	l := fe6b1cListener(t, inv, "listener")
	if l["state"] != "serving" || l["posture"] != "plain_http" {
		t.Fatalf("listener = %v, want serving/plain_http", l)
	}
	if _, has := l["servedCertificate"]; has {
		t.Fatalf("a plain-HTTP listener serves no certificate: %v", l)
	}
	// A pair persisted AFTER boot is not in use on this listener.
	fe6b0eSeedPair(t, mux, "ui-a.fe6b1c")
	fe6b1cAssertNotActive(t, mux, "plain-HTTP listener with a pair persisted after boot")
	l = fe6b1cListener(t, fe6b1cInventory(t, mux), "listener")
	if l["posture"] != "plain_http" {
		t.Fatalf("posture after a persisted pair = %v, want plain_http", l["posture"])
	}
}

// ── C04 explicitly configured pair ──────────────────────────────────────────

func TestFE6B1C_C04_ExplicitlyConfiguredCertificateTakesPrecedence(t *testing.T) {
	dir, mux := fe6b1cNode(t)
	fe6b0eSeedPair(t, mux, "ui-a.fe6b1c")
	certC, keyC, _ := fe6b0CAPair(t, "ui-configured.fe6b1c", false)
	fpC := fe6b1cPEMFingerprint(t, certC)
	certPath := filepath.Join(dir, "explicit.crt")
	keyPath := filepath.Join(dir, "explicit.key")
	if err := os.WriteFile(certPath, certC, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyC, 0o600); err != nil {
		t.Fatal(err)
	}
	gotCert, gotKey := fe6b1cBootSelect(t, certPath, keyPath)
	if gotCert != certPath || gotKey != keyPath {
		t.Fatalf("explicit pair must win the boot selection: %q %q", gotCert, gotKey)
	}
	addr, stop := fe6b1cServe(t, gotCert, gotKey, false)
	defer stop()
	if got := fe6b1cPeerFingerprint(t, addr); got != fpC {
		t.Fatalf("TLS peer = %s, want the configured pair %s", got, fpC)
	}
	inv := fe6b1cInventory(t, mux)
	l := fe6b1cListener(t, inv, "listener")
	if l["posture"] != "tls_configured" {
		t.Fatalf("posture = %v, want tls_configured", l["posture"])
	}
	if got := fe6b1cServed(t, l)["fingerprint"]; got != fpC {
		t.Fatalf("servedCertificate = %v, want %s", got, fpC)
	}
	if fe6b1cUICert(t, inv)["present"] != true {
		t.Fatalf("the persisted pair A must still be reported present")
	}
	fe6b1cAssertNotActive(t, mux, "an explicitly configured certificate is served")
}

// ── C05 unknown before bind ─────────────────────────────────────────────────

func TestFE6B1C_C05_ActivationIsUnknownBeforeTheListenerBinds(t *testing.T) {
	_, mux := fe6b1cNode(t)
	fe6b0eSeedPair(t, mux, "ui-a.fe6b1c")
	certPath, _ := fe6b1cBootSelect(t, "", "")
	if certPath != customUITLSCertPath() {
		t.Fatalf("boot selection must pick the persisted pair")
	}
	// No listener has bound. The boot flag alone must not become a claim.
	inv := fe6b1cInventory(t, mux)
	if act, _ := fe6b1cUICert(t, inv)["active"].(bool); act {
		t.Fatalf("uiCert.active = true before any listener bound (claimed from the boot flag alone)")
	}
	l := fe6b1cListener(t, inv, "listener")
	if l["state"] != "unknown" || l["posture"] != "unknown" {
		t.Fatalf("listener = %v, want unknown/unknown", l)
	}
	if _, has := l["servedCertificate"]; has {
		t.Fatalf("no served identity may be published before a bind: %v", l)
	}
}

// ── C06 delete while served ─────────────────────────────────────────────────

func TestFE6B1C_C06_DeletingThePersistedPairWhileServedKeepsTheServedIdentity(t *testing.T) {
	_, mux := fe6b1cNode(t)
	fpA, addr, stop := fe6b1cServeA(t, mux)
	defer stop()

	rev := fe6b0cUIRevision(t, mux)
	if code, m := fe6b0cUIDelete(mux, fe6b0OpID(), rev); code != http.StatusOK {
		t.Fatalf("delete = %d %v", code, m)
	}
	inv := fe6b1cInventory(t, mux)
	uc := fe6b1cUICert(t, inv)
	if uc["pairState"] != uiPairAbsent {
		t.Fatalf("pairState after delete = %v, want absent", uc["pairState"])
	}
	if act, _ := uc["active"].(bool); act {
		t.Fatalf("uiCert.active = true after the persisted pair was deleted (the reviewed candidate keeps the boot flag)")
	}
	if act, _ := fe6b1cNetwork(t)["ui_custom_cert_active"].(bool); act {
		t.Fatalf("ui_custom_cert_active = true after the delete")
	}
	l := fe6b1cListener(t, inv, "listener")
	if l["posture"] != "tls_custom" {
		t.Fatalf("posture = %v, want tls_custom (the listener still serves A)", l["posture"])
	}
	if got := fe6b1cServed(t, l)["fingerprint"]; got != fpA {
		t.Fatalf("servedCertificate after delete = %v, want A %s", got, fpA)
	}
	if got := fe6b1cPeerFingerprint(t, addr); got != fpA {
		t.Fatalf("real TLS peer after delete = %s, want A %s", got, fpA)
	}
}

// ── C07 self-signed posture ─────────────────────────────────────────────────

func TestFE6B1C_C07_SelfSignedListenerPostureAndIdentity(t *testing.T) {
	_, mux := fe6b1cNode(t)
	addr, stop := fe6b1cServe(t, "", "", true)
	defer stop()
	peer := fe6b1cPeerFingerprint(t, addr)
	inv := fe6b1cInventory(t, mux)
	l := fe6b1cListener(t, inv, "listener")
	if l["posture"] != "tls_self_signed" {
		t.Fatalf("posture = %v, want tls_self_signed", l["posture"])
	}
	if got := fe6b1cServed(t, l)["fingerprint"]; got != peer {
		t.Fatalf("servedCertificate = %v, want the TLS peer %s", got, peer)
	}
	fe6b0eSeedPair(t, mux, "ui-a.fe6b1c")
	fe6b1cAssertNotActive(t, mux, "self-signed listener with a pair persisted after boot")
	l = fe6b1cListener(t, fe6b1cInventory(t, mux), "listener")
	if sp, _ := l["servesPersistedPair"].(bool); sp {
		t.Fatalf("servesPersistedPair must be false on a self-signed listener")
	}
}

// ── C08 both reads carry the same evidence ──────────────────────────────────

func TestFE6B1C_C08_NetworkSettingsCarryTheSameListenerEvidence(t *testing.T) {
	_, mux := fe6b1cNode(t)
	_, _, stop := fe6b1cServeA(t, mux)
	defer stop()
	inv := fe6b1cListener(t, fe6b1cInventory(t, mux), "listener")
	net := fe6b1cListener(t, fe6b1cNetwork(t), "ui_listener")
	if !reflect.DeepEqual(inv, net) {
		t.Fatalf("listener evidence differs between reads:\n inventory %v\n network   %v", inv, net)
	}
}
