package main

import (
	"os"
	"os/exec"
	"regexp"
	"strings"
	"testing"
)

// TestBuildOVA_RootGrownInPlace pins the fix for an OVA that could not boot
// under BIOS: virt-resize renumbers the cloud image's partitions (14,15,16,1 →
// 1,2,3,4) while the BIOS GRUB core image still names /boot as partition 16,
// so every BIOS boot stopped at "grub rescue>" (found by the QEMU appliance
// lab; UEFI was unaffected). The build must grow the root partition in place
// and refuse a changed layout.
func TestBuildOVA_RootGrownInPlace(t *testing.T) {
	raw, err := os.ReadFile("appliance/build/build-ova.sh")
	if err != nil {
		t.Fatal(err)
	}
	var code []string
	for _, l := range strings.Split(string(raw), "\n") {
		if s := strings.TrimSpace(l); s != "" && !strings.HasPrefix(s, "#") {
			code = append(code, l)
		}
	}
	body := strings.Join(code, "\n")
	if regexp.MustCompile(`(^|[\s;&|(])virt-resize(\s|$)`).MatchString(body) {
		t.Error("build-ova.sh invokes virt-resize, which renumbers partitions and breaks BIOS GRUB")
	}
	for _, want := range []string{"part-resize /dev/sda 1 -34", "resize2fs /dev/sda1", `"$layout_before" == "$layout_after"`} {
		if !strings.Contains(body, want) {
			t.Errorf("build-ova.sh lost %q (in-place root growth + layout guard)", want)
		}
	}
}

// TestPrepareGuest_SSHPolicyValidationNeedsNoImageHostKey pins the fix for an
// OVA build that could not complete: prepare-guest.sh validates the effective
// sshd policy with `sshd -T`, which exits "no hostkeys available" when the
// image has none — and the image deliberately has none (cloud-init generates
// them at first boot; build-ova.sh refuses an image shipping any). The
// validation must bring its own throwaway key (-h) and keep it out of /etc/ssh.
func TestPrepareGuest_SSHPolicyValidationNeedsNoImageHostKey(t *testing.T) {
	raw, err := os.ReadFile("appliance/build/prepare-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	calls := regexp.MustCompile(`(?m)^[^#\n]*sshd -T[^\n]*$`).FindAllString(string(raw), -1)
	if len(calls) == 0 {
		t.Fatal("prepare-guest.sh no longer validates the effective sshd policy")
	}
	for _, c := range calls {
		if !regexp.MustCompile(`\s-h\s+"\$validate_key_dir/key"`).MatchString(c) {
			t.Errorf("sshd -T without a throwaway host key (-h) fails on a key-less image: %s", strings.TrimSpace(c))
		}
	}
	if !strings.Contains(string(raw), `mktemp -d /run/culvert-sshd-validate.`) || !strings.Contains(string(raw), `rm -rf "$validate_key_dir"`) {
		t.Error("the validation key must live outside /etc/ssh and be removed")
	}
	// Behavioural proof where an sshd binary exists: a config whose only host
	// key is missing fails exactly as the build did, and passes with -h.
	sshd := "/usr/sbin/sshd"
	if _, err := os.Stat(sshd); err != nil {
		t.Skip("no sshd on this host; static checks above still apply")
	}
	d := t.TempDir()
	cfg := d + "/sshd_config"
	if err := os.WriteFile(cfg, []byte("HostKey "+d+"/absent\nAllowUsers culvert-operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.CommandContext(t.Context(), sshd, "-T", "-f", cfg, "-C", "user=culvert-operator,host=localhost,addr=127.0.0.1").CombinedOutput(); err == nil { //nolint:gosec // G204: the system sshd binary, test-owned args
		t.Fatalf("sshd -T unexpectedly succeeded without a host key: %s", out)
	}
	key := d + "/key"
	if out, err := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil { //nolint:gosec // G204: fixed binary, test-owned temp path
		t.Skipf("ssh-keygen unavailable: %v %s", err, out)
	}
	out, err := exec.CommandContext(t.Context(), sshd, "-T", "-f", cfg, "-h", key, "-C", "user=culvert-operator,host=localhost,addr=127.0.0.1").CombinedOutput() // #nosec G204 -- fixed binary, test-owned args
	if err != nil || !strings.Contains(string(out), "allowusers culvert-operator") {
		t.Fatalf("sshd -T with a throwaway key failed: %v %s", err, out)
	}
}

// Boot time (ESXi recovery blocker): the image carries the measured 4 MiB
// read-ahead for whole disks of every bus a supported hypervisor presents.
func TestPrepareGuest_InstallsReadAheadRule(t *testing.T) {
	ps, err := os.ReadFile("appliance/build/prepare-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ps), `install -m 0644 "$APPL/provision/60-culvert-readahead.rules" /etc/udev/rules.d/60-culvert-readahead.rules`) {
		t.Fatal("prepare-guest.sh does not install the read-ahead rule")
	}
	rule, err := os.ReadFile("appliance/provision/60-culvert-readahead.rules")
	if err != nil {
		t.Fatal(err)
	}
	r := string(rule)
	for _, want := range []string{`ENV{DEVTYPE}=="disk"`, `ATTR{queue/read_ahead_kb}="4096"`, "sd*", "vd*", "nvme*n*"} {
		if !strings.Contains(r, want) {
			t.Errorf("read-ahead rule lacks %q", want)
		}
	}
}

// Every provisioning file prepare-guest.sh installs from $APPL/provision must
// be one build-ova.sh copies into the image, or the OVA build dies inside the
// guest with "No such file".
func TestBuildOVA_CopiesEveryProvisionFilePrepareGuestInstalls(t *testing.T) {
	ps, err := os.ReadFile("appliance/build/prepare-guest.sh")
	if err != nil {
		t.Fatal(err)
	}
	bo, err := os.ReadFile("appliance/build/build-ova.sh")
	if err != nil {
		t.Fatal(err)
	}
	copied := map[string]bool{}
	loop := regexp.MustCompile(`(?s)for runtime_file in (.*?); do\s+\[\[ -f "\$REPO/appliance/provision/`).FindSubmatch(bo)
	if loop == nil {
		t.Fatal("build-ova.sh provisioning copy loop not found")
	}
	for _, f := range strings.Fields(strings.ReplaceAll(string(loop[1]), "\\", " ")) {
		copied[f] = true
	}
	refs := regexp.MustCompile(`\$APPL/provision/([A-Za-z0-9._-]+)`).FindAllStringSubmatch(string(ps), -1)
	if len(refs) < 3 {
		t.Fatalf("found only %d provisioning references in prepare-guest.sh; the scan is not matching", len(refs))
	}
	for _, m := range refs {
		if !copied[m[1]] {
			t.Errorf("prepare-guest.sh installs %s but build-ova.sh does not copy it into the image", m[1])
		}
	}
}
