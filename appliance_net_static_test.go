package main

import (
	"os"
	"os/exec"
	"path/filepath"
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
	d := t.TempDir()
	h := &netHarness{t: t, dir: d, stubs: filepath.Join(d, "stubs"), np: filepath.Join(d, "60-culvert.yaml"), nl: filepath.Join(d, "netplan.log")}
	if err := os.MkdirAll(h.stubs, 0o750); err != nil {
		t.Fatal(err)
	}
	gen := "exit 0"
	if generateFails {
		gen = `[ "$(cat "` + h.np + `" 2>/dev/null | grep -c 10.0.10.9)" = 0 ] || exit 1`
	}
	for name, body := range map[string]string{
		"id":      "echo 0",
		"ip":      `case "$*" in *route*) echo "default via 10.0.10.1 dev ens192";; *) echo "ens192 UP";; esac`,
		"netplan": `echo "$1" >> "` + h.nl + `"; if [ "$1" = generate ]; then ` + gen + `; fi`,
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
	c.Env = append(os.Environ(), "PATH="+h.stubs+":"+os.Getenv("PATH"), "CULVERT_NET_NETPLAN_FILE="+h.np)
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
