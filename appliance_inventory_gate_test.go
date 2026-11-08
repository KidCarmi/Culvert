package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// #1528 FB-1 remediation: QEMU campaign 2 (run 42402656551) stopped at
// E/kernel-cve-assumptions because the image shipped /usr/bin/perf (the
// linux-tools-common wrapper) and the BPF tracing tools. The build now purges
// an EXACT reviewed list (never an autoremove), and an inventory gate refuses
// any image that still carries a forbidden package, command or path: once in
// the guest and once from outside it, before the VMDK/OVA is written.

var diagnosticToolingPurge = []string{
	"bpfcc-tools", "bpftrace", "hwdata", "ieee-data", "libbpfcc", "libclang-cpp18",
	"libclang1-18", "libllvm18", "linux-tools-common", "python3-bpfcc", "python3-netaddr",
	"ubuntu-kernel-accessories",
}

func purgeListNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for _, l := range strings.Split(readSource(t, "appliance/build/diagnostic-tooling-purge.txt"), "\n") {
		l, _, _ = strings.Cut(l, "#")
		if f := strings.Fields(l); len(f) > 0 {
			names = append(names, f[0])
		}
	}
	slices.Sort(names)
	return names
}

func TestDiagnosticToolingPurge_IsTheReviewedExactList(t *testing.T) {
	if got := purgeListNames(t); !slices.Equal(got, diagnosticToolingPurge) {
		t.Fatalf("diagnostic-tooling-purge.txt lists %v, the reviewed set is %v", got, diagnosticToolingPurge)
	}
}

func TestDiagnosticToolingPurge_IsExactNotAnAutoremove(t *testing.T) {
	pg := readSource(t, "appliance/build/prepare-guest.sh")
	for _, l := range strings.Split(pg, "\n") {
		if s := strings.TrimSpace(l); !strings.HasPrefix(s, "#") && strings.Contains(s, "autoremove") {
			t.Errorf("prepare-guest.sh must not autoremove: %s", s)
		}
	}
	for _, want := range []string{
		`purge_list="$(sed 's/#.*//' "$APPL/diagnostic-tooling-purge.txt" | awk 'NF{print $1}' | sort -u)"`,
		`[[ "$(wc -l <<<"$purge_list")" -eq 12 ]]`,
		// each listed package must be installed (a stale list stops the build)
		`which is not installed: review the list against this base image`,
		// the simulated purge removes exactly the list
		`would_purge="$(DEBIAN_FRONTEND=noninteractive apt_snap -s -qq purge $purge_list | awk '$1=="Purg" || $1=="Remv" {print $2}' | sort -u)"`,
		`[[ "$would_purge" == "$purge_list" ]]`,
		`DEBIAN_FRONTEND=noninteractive apt_snap -y -qq purge $purge_list`,
		`> "$STATE/removed-diagnostic-tooling.txt"`,
		// required product, kernel, guest-tools and maintenance packages survive
		`for keep in "$GUEST_KERNEL_META" "linux-image-${newest_kver}-generic" "linux-modules-${newest_kver}-generic"`,
		`ubuntu-server open-vm-tools cloud-init unattended-upgrades openssh-server nftables apt python3`,
		`docker-ce docker-ce-cli containerd.io docker-compose-plugin plymouth plymouth-theme-ubuntu-text; do`,
		// a later OS update cannot bring the tooling back
		`Package: linux-tools-* bpftrace bpfcc-tools python3-bpfcc libbpfcc ubuntu-kernel-accessories\nPin: release *\nPin-Priority: -1\n`,
		`/etc/apt/preferences.d/culvert-no-diagnostic-tooling`,
		`apt_cache_snap policy "$p" | awk '/Candidate:/{print $2}')" == "(none)"`,
	} {
		if !strings.Contains(pg, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	// After the last pinned install, before the snapshot is left behind.
	plym := strings.Index(pg, "plymouth plymouth-theme-ubuntu-text plymouth-label fontconfig")
	purge := strings.Index(pg, "apt_snap -y -qq purge $purge_list")
	restore := strings.Index(pg, "\napt_snap_sources_restore\n")
	if plym < 0 || purge < 0 || restore < 0 || plym >= purge || purge >= restore {
		t.Errorf("the purge must follow the plymouth install and precede apt_snap_sources_restore (offsets %d, %d, %d)", plym, purge, restore)
	}
}

func TestInventoryGate_RulesCoverTheHardeningCriterion(t *testing.T) {
	rules := readSource(t, "appliance/build/forbidden-inventory.txt")
	have := map[string]bool{}
	for _, l := range strings.Split(rules, "\n") {
		if f := strings.Fields(l); len(f) >= 3 && !strings.HasPrefix(f[0], "#") {
			have[f[0]+" "+f[1]] = true
		}
	}
	for _, want := range []string{
		"command perf", "package linux-tools-*", "path /usr/lib/linux-tools", // E/kernel-cve-assumptions
		"package bpftrace", "package bpfcc-tools", "package python3-bpfcc", "package libbpfcc",
		"package ubuntu-kernel-accessories", "command bpftrace", "command *-bpfcc", "command *.bt",
		"package snapd",
	} {
		if !have[want] {
			t.Errorf("forbidden-inventory.txt has no %q rule", want)
		}
	}
	// Every pinned (never-reinstalled) tool is also forbidden by the gate.
	for _, p := range []string{"bpftrace", "bpfcc-tools", "python3-bpfcc", "libbpfcc", "ubuntu-kernel-accessories"} {
		if !have["package "+p] {
			t.Errorf("%s is pinned out by prepare-guest.sh but not forbidden by the gate", p)
		}
	}
}

func TestInventoryGate_RunsTwiceBeforePackaging(t *testing.T) {
	pg := readSource(t, "appliance/build/prepare-guest.sh")
	for _, want := range []string{
		`python3 -I "$APPL/inventory-gate.py" --rules "$APPL/forbidden-inventory.txt"`,
		`--dpkg-list "$STATE/dpkg-list.txt" --present "$gate_present" --out "$STATE/inventory-gate.txt"`,
	} {
		if !strings.Contains(pg, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	if i, j := strings.Index(pg, `| sort > "$STATE/dpkg-list.txt"`), strings.Index(pg, `"$APPL/inventory-gate.py"`); i < 0 || j < i {
		t.Error("the in-guest gate must run on the final dpkg-list.txt")
	}
	bo := readSource(t, "appliance/build/build-ova.sh")
	for _, want := range []string{
		`cp "$HERE/diagnostic-tooling-purge.txt" "$HERE/forbidden-inventory.txt" "$HERE/inventory-gate.py" "$OV/opt/culvert-appliance/"`,
		`virt-ls -a "$DISK" "$d" > "$WORK/inventory-ls.txt" || die`,
		`python3 "$HERE/inventory-gate.py" --rules "$HERE/forbidden-inventory.txt" --dpkg-list "$OUT/dpkg-list.txt"`,
		`|| die "inventory gate failed on the finished disk (see above); nothing is packaged"`,
		`> "$OUT/inventory-gate-guest.txt"`,
		`> "$OUT/removed-diagnostic-tooling.txt"`,
	} {
		if !strings.Contains(bo, want) {
			t.Errorf("build-ova.sh must contain %q", want)
		}
	}
	gate := strings.Index(bo, `python3 "$HERE/inventory-gate.py"`)
	vmdk := strings.Index(bo, `qemu-img convert -p -f qcow2 -O vmdk`)
	if gate < 0 || vmdk < 0 || gate > vmdk {
		t.Errorf("the outside-the-guest gate must run before the VMDK is written (offsets %d, %d)", gate, vmdk)
	}
}

type gateCase struct {
	name    string
	dpkg    string
	present string
	rules   string
	code    int
	want    string
}

func runInventoryGate(t *testing.T, c gateCase) (code int, output string) {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	rules := filepath.Join(pkgSourceDir(), "appliance", "build", "forbidden-inventory.txt")
	if c.rules != "" {
		rules = write("rules.txt", c.rules)
	}
	cmd := exec.CommandContext(t.Context(), "python3", "-I", filepath.Join(pkgSourceDir(), "appliance", "build", "inventory-gate.py"), //nolint:gosec // test-owned paths
		"--rules", rules, "--dpkg-list", write("dpkg.txt", c.dpkg), "--present", write("present.txt", c.present))
	out, err := cmd.CombinedOutput()
	var ee *exec.ExitError
	switch {
	case err == nil:
		return 0, string(out)
	case errors.As(err, &ee):
		return ee.ExitCode(), string(out)
	default:
		t.Fatalf("running the gate: %v", err)
		return -1, ""
	}
}

func TestInventoryGate_Behaviour(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	const base = "apt\t2.8.3\tamd64\nlibc6:amd64\t2.39-0ubuntu8.6\tamd64\nlinux-image-7.0.0-42-generic\t7.0.0-42.42~24.04.1\tamd64\n"
	const path = "/usr/bin/ls\n/usr/bin/python3\n/usr/sbin/nft\n"
	for _, c := range []gateCase{
		{name: "clean image passes", dpkg: base, present: path, code: 0, want: "inventory gate: PASS"},
		{name: "perf wrapper command", dpkg: base, present: path + "/usr/bin/perf\n", code: 1, want: "FORBIDDEN command perf: /usr/bin/perf"},
		{name: "perf in /usr/local/sbin", dpkg: base, present: path + "/usr/local/sbin/perf\n", code: 1, want: "FORBIDDEN command perf"},
		{name: "linux-tools-common package", dpkg: base + "linux-tools-common\t6.8.0-147.147\tall\n", present: path, code: 1, want: "FORBIDDEN package linux-tools-*: linux-tools-common=6.8.0-147.147"},
		{name: "a versioned perf build", dpkg: base + "linux-tools-7.0.0-42-generic\t7.0.0-42.42\tamd64\n", present: path, code: 1, want: "FORBIDDEN package linux-tools-*"},
		{name: "versioned perf directory", dpkg: base, present: path + "/usr/lib/linux-tools/7.0.0-42-generic/perf\n", code: 1, want: "FORBIDDEN path /usr/lib/linux-tools"},
		{name: "arch-qualified BPF library", dpkg: base + "libbpfcc:amd64\t0.29.1\tamd64\n", present: path, code: 1, want: "FORBIDDEN package libbpfcc: libbpfcc=0.29.1"},
		{name: "BCC tool", dpkg: base, present: path + "/usr/sbin/execsnoop-bpfcc\n", code: 1, want: "FORBIDDEN command *-bpfcc"},
		{name: "bpftrace script", dpkg: base, present: path + "/usr/sbin/opensnoop.bt\n", code: 1, want: "FORBIDDEN command *.bt"},
		{name: "snapd came back", dpkg: base + "snapd\t2.66\tamd64\n", present: path, code: 1, want: "FORBIDDEN package snapd"},
		{name: "a name that only contains perf is not perf", dpkg: base + "libperf-dummy\t1\tamd64\n", present: path + "/usr/bin/perftest\n", code: 0, want: "PASS"},
		{name: "empty inventory is unusable", dpkg: "", present: path, code: 2, want: "no installed packages"},
		{name: "malformed inventory line", dpkg: "apt 2.8.3 amd64\n", present: path, code: 2, want: "not <package>TAB<version>TAB<arch>"},
		{name: "no /usr/bin listing is unusable", dpkg: base, present: "/usr/sbin/nft\n", code: 2, want: "no /usr/bin entries"},
		{name: "relative present path", dpkg: base, present: path + "usr/bin/x\n", code: 2, want: "not absolute paths"},
		{name: "malformed rule", dpkg: base, present: path, rules: "command perf\n", code: 2, want: "expected '<package|command|path> <pattern> <criterion>'"},
		{name: "rule file with no command rule", dpkg: base, present: path, rules: "package snapd why\n", code: 2, want: "no command rule"},
		{name: "relative path rule", dpkg: base, present: path, rules: "package a b\ncommand c d\npath usr/lib x\n", code: 2, want: "a path rule must be absolute"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, out := runInventoryGate(t, c)
			if code != c.code || !strings.Contains(out, c.want) {
				t.Fatalf("exit %d (want %d); output must contain %q:\n%s", code, c.code, c.want, out)
			}
		})
	}
}
