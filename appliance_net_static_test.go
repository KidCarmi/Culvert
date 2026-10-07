package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// culvert-net static used to accept any value of the right SHAPE
// (`999.1.1.1/99`), install it into netplan and only then validate, so a
// typo failed first boot AND persisted into the next boot (Codex P1,
// PR #1528). These drive the real script with stubbed id/ip/netplan.

type netHarness struct {
	t                  *testing.T
	dir, stubs, np, nl string
}

func newNetHarness(t *testing.T, generateFails bool) *netHarness {
	t.Helper()
	return newNetHarnessFailing(t, generateFails, false)
}

// newNetHarnessFailing lets generate and/or apply fail while the candidate
// static file (address 10.0.10.9) is installed.
func newNetHarnessFailing(t *testing.T, generateFails, applyFails bool) *netHarness {
	t.Helper()
	d := t.TempDir()
	h := &netHarness{t: t, dir: d, stubs: filepath.Join(d, "stubs"), np: filepath.Join(d, "60-culvert.yaml"), nl: filepath.Join(d, "netplan.log")}
	if err := os.MkdirAll(h.stubs, 0o750); err != nil {
		t.Fatal(err)
	}
	candidateInstalled := `[ "$(cat "` + h.np + `" 2>/dev/null | grep -c 10.0.10.9)" = 0 ] || exit 1`
	gen, apply := "exit 0", "exit 0"
	if generateFails {
		gen = candidateInstalled
	}
	if applyFails {
		apply = candidateInstalled
	}
	for name, body := range map[string]string{
		"id": "echo 0",
		// The first route query is the interface detection; later ones are
		// the settle wait, which sees no default route until route_after
		// queries have passed (a DHCP lease arriving after netplan apply).
		"ip": `case "$*" in *route*) n=$(( $(cat "` + filepath.Join(d, "route_calls") + `" 2>/dev/null || echo 0) + 1 )); echo "$n" > "` + filepath.Join(d, "route_calls") + `"
  after=$(cat "` + filepath.Join(d, "route_after") + `" 2>/dev/null || echo 0)
  if [ "$n" -eq 1 ] || [ "$n" -gt "$after" ]; then echo "default via 10.0.10.1 dev ens192"; fi;;
*) echo "ens192 UP";; esac`,
		"netplan": `echo "$1" >> "` + h.nl + `"; if [ "$1" = generate ]; then ` + gen + `; fi; if [ "$1" = apply ]; then ` + apply + `; fi`,
	} {
		p := filepath.Join(h.stubs, name)
		if err := os.WriteFile(p, []byte("#!/usr/bin/env bash\n"+body+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return h
}

func (h *netHarness) run(args ...string) (out string, code int) {
	h.t.Helper()
	abs, _ := filepath.Abs(filepath.Join(pkgSourceDir(), "appliance", "provision", "culvert-net"))
	// #nosec G204 -- program is the literal "bash"; abs is the checked-in script's path.
	c := exec.CommandContext(h.t.Context(), "bash", append([]string{abs}, args...)...)
	c.Env = append(os.Environ(), "PATH="+h.stubs+":"+os.Getenv("PATH"), "CULVERT_NET_NETPLAN_FILE="+h.np, "CULVERT_NET_SETTLE_SECS=3")
	b, _ := c.CombinedOutput()
	return string(b), c.ProcessState.ExitCode()
}

func TestCulvertNetStatic_RejectsOutOfRangeValuesBeforeWritingNetplan(t *testing.T) {
	for name, args := range map[string][]string{
		"octet out of range":      {"static", "999.1.1.1/24", "10.0.10.1"},
		"ipv4 prefix > 32":        {"static", "10.0.10.5/33", "10.0.10.1"},
		"prefix missing":          {"static", "10.0.10.5", "10.0.10.1"},
		"gateway out of range":    {"static", "10.0.10.5/24", "10.0.10.256"},
		"gateway family mismatch": {"static", "10.0.10.5/24", "fe80::1"},
		"gateway outside subnet":  {"static", "192.168.1.10/24", "192.168.2.1"},
		"gateway is own address":  {"static", "10.0.10.5/24", "10.0.10.5"},
		"gateway is network addr": {"static", "10.0.10.5/24", "10.0.10.0"},
		"gateway is broadcast":    {"static", "10.0.10.5/24", "10.0.10.255"},
		"ipv6 gateway off-prefix": {"static", "2001:db8::5/64", "2001:db9::1"},
		"dns out of range":        {"static", "10.0.10.5/24", "10.0.10.1", "10.0.10.2,300.1.1.1"},
		"search domain YAML":      {"static", "10.0.10.5/24", "10.0.10.1", "", "corp.example]"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newNetHarness(t, false)
			out, code := h.run(args...)
			if code != 2 {
				t.Fatalf("exit %d, want 2:\n%s", code, out)
			}
			if _, err := os.Stat(h.np); !os.IsNotExist(err) {
				t.Fatalf("an invalid value reached %s", h.np)
			}
			if b, _ := os.ReadFile(h.nl); len(b) != 0 {
				t.Fatalf("netplan ran for an invalid value: %s", b)
			}
		})
	}
}

// CONTROL: valid values (both families) are written and applied.
func TestCulvertNetStatic_AcceptsValidValues(t *testing.T) {
	for name, args := range map[string][]string{
		"ipv4": {"static", "10.0.10.5/24", "10.0.10.1", "10.0.10.2,10.0.10.3", "corp.example"},
		"ipv6": {"static", "2001:db8::5/64", "2001:db8::1"},
		// The usual IPv6 next hop: link-local, reachable on the interface.
		"ipv6 link-local gateway": {"static", "2001:db8::5/64", "fe80::1"},
		// A /31 point-to-point link has no network/broadcast addresses.
		"ipv4 /31 peer": {"static", "10.0.10.0/31", "10.0.10.1"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newNetHarness(t, false)
			out, code := h.run(args...)
			if code != 0 {
				t.Fatalf("exit %d:\n%s", code, out)
			}
			b, err := os.ReadFile(h.np)
			if err != nil || !strings.Contains(string(b), "addresses: ["+args[1]+"]") {
				t.Fatalf("netplan file missing the address: %v\n%s", err, b)
			}
			if nl, _ := os.ReadFile(h.nl); string(nl) != "generate\napply\n" {
				t.Fatalf("netplan calls = %q", nl)
			}
		})
	}
}

// A value netplan itself rejects must not persist: the previous file comes
// back, and with no previous file nothing is left behind.
func TestCulvertNetStatic_RestoresThePreviousFileWhenNetplanRejects(t *testing.T) {
	h := newNetHarness(t, true)
	prev := "# previous\nnetwork: {version: 2}\n"
	if err := os.WriteFile(h.np, []byte(prev), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := h.run("static", "10.0.10.9/24", "10.0.10.1")
	if code != 1 || !strings.Contains(out, "previous network configuration is kept") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if b, _ := os.ReadFile(h.np); string(b) != prev {
		t.Fatalf("previous netplan file not restored:\n%s", b)
	}
	if nl, _ := os.ReadFile(h.nl); strings.Contains(string(nl), "apply") {
		t.Fatal("a rejected configuration was applied")
	}

	h2 := newNetHarness(t, true)
	if _, code := h2.run("static", "10.0.10.9/24", "10.0.10.1"); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if _, err := os.Stat(h2.np); !os.IsNotExist(err) {
		t.Fatal("a rejected configuration was left in place with no previous file to restore")
	}
}

// Codex review (PR #1528): `netplan apply` can fail AFTER generate accepted the
// file. First boot reports any failure here as "stays on DHCP", so the new
// static file must not survive into the next boot either: the previous file
// (or none) comes back and is re-applied.
func TestCulvertNetStatic_RestoresThePreviousFileWhenApplyFails(t *testing.T) {
	h := newNetHarnessFailing(t, false, true)
	prev := "# previous\nnetwork: {version: 2}\n"
	if err := os.WriteFile(h.np, []byte(prev), 0o600); err != nil {
		t.Fatal(err)
	}
	out, code := h.run("static", "10.0.10.9/24", "10.0.10.1")
	if code != 1 || !strings.Contains(out, "previous network configuration was restored") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if b, _ := os.ReadFile(h.np); string(b) != prev {
		t.Fatalf("previous netplan file not restored after a failed apply:\n%s", b)
	}
	nl, _ := os.ReadFile(h.nl)
	if got := strings.Fields(string(nl)); strings.Join(got, ",") != "generate,apply,generate,apply" {
		t.Fatalf("netplan calls = %q; want the candidate tried, then the previous file regenerated and re-applied", got)
	}

	h2 := newNetHarnessFailing(t, false, true)
	if _, code := h2.run("static", "10.0.10.9/24", "10.0.10.1"); code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	if _, err := os.Stat(h2.np); !os.IsNotExist(err) {
		t.Fatal("an unappliable configuration was left in place with no previous file to restore")
	}
}

// routeAfter withholds the default route from the settle wait for n route
// queries (two per poll: IPv4 and IPv6).
func (h *netHarness) routeAfter(n int) {
	h.t.Helper()
	if err := os.WriteFile(filepath.Join(h.dir, "route_after"), []byte(strconv.Itoa(n)), 0o600); err != nil {
		h.t.Fatal(err)
	}
}

func (h *netHarness) routeQueries() int {
	b, _ := os.ReadFile(filepath.Join(h.dir, "route_calls"))
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// ESXi qualification of #1528: after a failed apply the rollback said
// "restored" while the interface had no default route yet (netplan apply
// returns before the DHCP lease). It now waits for the route, and says so
// when it does not come back.
func TestCulvertNet_RollbackReportsRestoredOnlyOnceTheRouteIsBack(t *testing.T) {
	h := newNetHarnessFailing(t, false, true)
	h.routeAfter(6)
	out, code := h.run("static", "10.0.10.9/24", "10.0.10.1")
	if code != 1 || !strings.Contains(out, "previous network configuration was restored (default via 10.0.10.1 dev ens192)") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if q := h.routeQueries(); q <= 6 {
		t.Fatalf("restored was reported after %d route queries; the route only returns after 6", q)
	}

	h2 := newNetHarnessFailing(t, false, true)
	h2.routeAfter(1 << 20)
	out, code = h2.run("static", "10.0.10.9/24", "10.0.10.1")
	if code != 1 || strings.Contains(out, "was restored") || !strings.Contains(out, "re-applied, but ens192 has no default route after 3s") {
		t.Fatalf("a rollback that never converged was reported as restored (exit %d):\n%s", code, out)
	}
}

func TestCulvertNet_DHCPReportsRestoredOnlyWithALease(t *testing.T) {
	h := newNetHarness(t, false)
	h.routeAfter(4)
	out, code := h.run("dhcp")
	if code != 0 || !strings.Contains(out, "DHCP restored on ens192 (default via 10.0.10.1 dev ens192)") || h.routeQueries() <= 4 {
		t.Fatalf("exit %d after %d route queries:\n%s", code, h.routeQueries(), out)
	}

	h2 := newNetHarness(t, false)
	h2.routeAfter(1 << 20)
	out, code = h2.run("dhcp")
	if code != 1 || strings.Contains(out, "DHCP restored") || !strings.Contains(out, "no default route after 3s") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

// A static configuration that applied stays applied, so first boot (which
// reads a failure as "staying on DHCP") still gets exit 0 — with a warning
// rather than a claim.
func TestCulvertNetStatic_AppliedWithoutARouteWarnsButSucceeds(t *testing.T) {
	h := newNetHarness(t, false)
	h.routeAfter(1 << 20)
	out, code := h.run("static", "10.0.10.9/24", "10.0.10.1")
	if code != 0 || !strings.Contains(out, "applied on ens192, but it has no default route after 3s") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if b, _ := os.ReadFile(h.np); !strings.Contains(string(b), "10.0.10.9/24") {
		t.Fatalf("the applied static file was not kept:\n%s", b)
	}
}
