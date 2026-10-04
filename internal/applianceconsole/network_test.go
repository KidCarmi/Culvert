package applianceconsole

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestIPv6MultipleNICsAndVLANRemainVisible(t *testing.T) {
	c, _ := fixture(t)
	if err := os.MkdirAll(filepath.Join(c.sources.NetDir, "vlan20", "lower_eth0"), 0o700); err != nil {
		t.Fatal(err)
	}
	nics, addresses := c.network(`[{"ifname":"eth0","operstate":"UP","addr_info":[{"family":"inet6","local":"2001:db8::1","prefixlen":64}]},{"ifname":"vlan20","operstate":"UP","addr_info":[{"family":"inet","local":"192.0.2.20","prefixlen":24}]},{"ifname":"docker0","addr_info":[{"family":"inet","local":"172.17.0.1","prefixlen":16}]}]`)
	if len(nics) != 2 || len(addresses) != 2 || !slices.Contains(addresses, "2001:db8::1") {
		t.Fatalf("lost interface/address: %v %v", nics, addresses)
	}
	c.sources.Probe = func(_ context.Context, args []string) string {
		if args[0] == "/usr/sbin/ip" {
			return `[{"ifname":"eth0","addr_info":[{"family":"inet6","local":"2001:db8::1","prefixlen":64}]}]`
		}
		return ""
	}
	s := c.Collect(context.Background())
	if s.ManagementURLs[0] != "https://[2001:db8::1]:9090" {
		t.Fatal(s.ManagementURLs)
	}
}

func TestPublicNetworkFilesAllowlistAndBoundOutput(t *testing.T) {
	dir := t.TempDir()
	host := filepath.Join(dir, "hostname")
	resolver := filepath.Join(dir, "resolver")
	if err := os.WriteFile(host, []byte("bad\x1b[2J\nname"), 0o600); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsRune(readHostname(host), '\x1b') {
		t.Fatal("hostname injection")
	}
	if err := os.WriteFile(resolver, []byte("nameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch PRIVATE\nnameserver INVALID\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readDNS(resolver); len(got) != 2 {
		t.Fatal(got)
	}
	if readHostname(filepath.Join(dir, "missing")) != "unknown" {
		t.Fatal("missing hostname invented")
	}
	if err := os.WriteFile(host, []byte(strings.Repeat("a", maxOutput+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	if readHostname(host) != "unknown" {
		t.Fatal("oversized metadata accepted")
	}
	if got := readGateway(`[{"gateway":"192.0.2.1","dev":"eth0"}]`); got != "192.0.2.1 (eth0)" {
		t.Fatal(got)
	}
}
