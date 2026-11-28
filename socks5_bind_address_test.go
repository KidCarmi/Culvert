package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestSOCKS5BindAddress_Validation pins what -socks5-bind / proxy.socks5_bind
// accept: empty (every interface) or an IP literal. Hostnames are refused so
// the bound interface never depends on DNS.
func TestSOCKS5BindAddress_Validation(t *testing.T) {
	for _, ok := range []string{"", "127.0.0.1", "10.20.30.40", "0.0.0.0", "::1", "::", "fd00::5"} {
		if err := validateSOCKS5BindAddress(ok); err != nil {
			t.Errorf("%q: want accepted, got %v", ok, err)
		}
	}
	for _, bad := range []string{
		"localhost", "proxy.corp.example", "[::1]", "127.0.0.1:1080", ":1080",
		" 127.0.0.1", "127.0.0.1 ", "256.1.1.1", "fe80::1%eth0", "*",
	} {
		if err := validateSOCKS5BindAddress(bad); err == nil {
			t.Errorf("%q: want rejected, got nil", bad)
		}
	}
}

// TestSOCKS5ListenAddr_DefaultIsTheHistoricalBind pins that an unset bind
// address yields exactly the pre-change ":<port>" (every interface).
func TestSOCKS5ListenAddr_DefaultIsTheHistoricalBind(t *testing.T) {
	if got, want := socks5ListenAddr("", 1080), fmt.Sprintf(":%d", 1080); got != want {
		t.Fatalf("default listen address = %q, want %q (the historical bind)", got, want)
	}
	if got := socks5ListenAddr("127.0.0.1", 1080); got != "127.0.0.1:1080" {
		t.Errorf("IPv4 listen address = %q", got)
	}
	if got := socks5ListenAddr("::1", 1080); got != "[::1]:1080" {
		t.Errorf("IPv6 listen address = %q", got)
	}
}

// TestResolveSOCKS5Bind_PrecedenceAndValidation pins the CLI-over-YAML pick on
// the resolved value and that the flag cannot bypass validation.
func TestResolveSOCKS5Bind_PrecedenceAndValidation(t *testing.T) {
	str := func(v string) *string { return &v }
	cases := []struct {
		name    string
		flag    *string
		yaml    string
		want    string
		wantErr bool
	}{
		{"nothing set: every interface", nil, "", "", false},
		{"empty flag, empty yaml", str(""), "", "", false},
		{"yaml only", str(""), "127.0.0.1", "127.0.0.1", false},
		{"flag wins over yaml", str("10.0.0.7"), "127.0.0.1", "10.0.0.7", false},
		{"whitespace-only flag falls back to yaml", str("   "), "127.0.0.1", "127.0.0.1", false},
		{"invalid flag refused", str("localhost"), "", "", true},
		{"invalid flag refused even with a valid yaml", str("proxy.local"), "127.0.0.1", "", true},
	}
	for _, tc := range cases {
		got, err := resolveSOCKS5Bind(tc.flag, tc.yaml)
		if tc.wantErr {
			if err == nil || !strings.Contains(err.Error(), "-socks5-bind") {
				t.Errorf("%s: want an error naming -socks5-bind, got %q, %v", tc.name, got, err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v; want %q", tc.name, got, err, tc.want)
		}
	}
}

// TestFileConfig_SOCKS5BindValidatedAtLoad pins the config.yaml gate: an
// invalid proxy.socks5_bind fails the load with an error naming the key.
func TestFileConfig_SOCKS5BindValidatedAtLoad(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "config.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	fc, err := loadFileConfig(write("proxy:\n  socks5_port: 1080\n  socks5_bind: 127.0.0.1\n"))
	if err != nil {
		t.Fatalf("valid proxy.socks5_bind refused: %v", err)
	}
	if fc.Proxy.SOCKS5Bind != "127.0.0.1" {
		t.Fatalf("proxy.socks5_bind = %q, want 127.0.0.1", fc.Proxy.SOCKS5Bind)
	}

	fc, err = loadFileConfig(write("proxy:\n  socks5_port: 1080\n"))
	if err != nil || fc.Proxy.SOCKS5Bind != "" {
		t.Fatalf("absent proxy.socks5_bind must load as empty (every interface), got %q, %v", fc.Proxy.SOCKS5Bind, err)
	}

	if _, err := loadFileConfig(write("proxy:\n  socks5_port: 1080\n  socks5_bind: socks.corp.example\n")); err == nil ||
		!strings.Contains(err.Error(), "proxy.socks5_bind") {
		t.Fatalf("hostname proxy.socks5_bind must fail the load naming the key, got %v", err)
	}
}

// nonLoopbackIPv4ForTest returns a local, non-loopback IPv4 address, or "" when
// the host has none (the interface-exclusion half of the bind gates is then
// skipped; the address assertions still run).
func nonLoopbackIPv4ForTest(t *testing.T) string {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipn, ok := a.(*net.IPNet); ok && !ipn.IP.IsLoopback() && ipn.IP.To4() != nil {
			return ipn.IP.String()
		}
	}
	return ""
}

func stopSOCKS5ForTest(t *testing.T, srv *socks5Supervisor) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Stop(ctx); err != nil {
		t.Errorf("Stop: %v", err)
	}
}

// TestSOCKS5Bind_ExplicitLoopbackBindsLoopbackOnly starts the real supervisor
// with 127.0.0.1 and proves the listener holds loopback only: its address is
// 127.0.0.1:<port>, and another interface's address on the same port is still
// free to bind. The negative control runs the default (empty) bind on the same
// host and requires that interface's address to be HELD — so the exclusion
// half can fail, rather than passing on a host where it means nothing.
//
// No connection is opened to the listener (see assertPortHeld for why: an
// accepted session outlives the test and races the next one's globals).
func TestSOCKS5Bind_ExplicitLoopbackBindsLoopbackOnly(t *testing.T) {
	socks5ChaosSetup(t)
	other := nonLoopbackIPv4ForTest(t)

	port := freeSOCKS5Port(t)
	srv := startSOCKS5("127.0.0.1", port)
	waitForSOCKS5(t, 5*time.Second, "the loopback listener to bind", func() bool { return srv.Addr() != nil })
	tcp, ok := srv.Addr().(*net.TCPAddr)
	if !ok || !tcp.IP.Equal(net.IPv4(127, 0, 0, 1)) || tcp.Port != port {
		t.Fatalf("explicit 127.0.0.1 bind listens on %v, want 127.0.0.1:%d", srv.Addr(), port)
	}
	if other != "" {
		ln, err := ctxListen(net.JoinHostPort(other, fmt.Sprint(port)))
		if err != nil {
			t.Fatalf("%s:%d could not be bound while SOCKS5 is bound to 127.0.0.1 only — the listener holds more than loopback: %v",
				other, port, err)
		}
		_ = ln.Close()
	}
	stopSOCKS5ForTest(t, srv)

	// Negative control: the default bind holds every interface.
	socks5ChaosSetup(t)
	port = freeSOCKS5Port(t)
	def := startSOCKS5("", port)
	t.Cleanup(func() { stopSOCKS5ForTest(t, def) })
	waitForSOCKS5(t, 5*time.Second, "the default listener to bind", func() bool { return def.Addr() != nil })
	dtcp, ok := def.Addr().(*net.TCPAddr)
	if !ok || !dtcp.IP.IsUnspecified() || dtcp.Port != port {
		t.Fatalf("default bind listens on %v, want the unspecified address on port %d (every interface)", def.Addr(), port)
	}
	if other != "" {
		if ln, err := ctxListen(net.JoinHostPort(other, fmt.Sprint(port))); err == nil {
			_ = ln.Close()
			t.Fatalf("negative control: %s:%d was free under the default bind, so the loopback-only check above proves nothing on this host",
				other, port)
		}
	}
}
