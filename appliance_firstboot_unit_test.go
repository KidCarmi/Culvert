package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The first-boot unit's ordering must not form a cycle with cloud-init.
// Ubuntu's cloud-final.service is After=multi-user.target, and this unit is
// WantedBy=multi-user.target (so the target orders itself after it). Ordering
// the unit After=cloud-final.service therefore closes a loop, and systemd
// breaks it by DELETING culvert-firstboot.service's start job: the appliance
// boots, SSH comes up, and first boot never runs (QEMU lab run 37144426441,
// "Ordering cycle found, skipping culvert-firstboot.service").

const firstbootUnitPath = "appliance/provision/culvert-firstboot.service"

func firstbootUnitDirectives(t *testing.T, key string) []string {
	t.Helper()
	raw, err := os.ReadFile(firstbootUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && k == key {
			out = append(out, strings.Fields(v)...)
		}
	}
	return out
}

func TestFirstbootUnit_NotOrderedAfterCloudFinal(t *testing.T) {
	after := firstbootUnitDirectives(t, "After")
	wanted := firstbootUnitDirectives(t, "WantedBy")
	has := func(list []string, u string) bool {
		for _, x := range list {
			if x == u {
				return true
			}
		}
		return false
	}
	if has(wanted, "multi-user.target") && has(after, "cloud-final.service") {
		t.Error("culvert-firstboot.service is WantedBy=multi-user.target and After=cloud-final.service; " +
			"cloud-final is After=multi-user.target, so systemd deletes the first-boot job")
	}
	// The ordering the unit exists for must survive: cloud-init applies the
	// OVF/NoCloud identity (users_groups, ssh, set_passwords) in its init stage.
	for _, u := range []string{"cloud-init.service", "cloud-config.service", "docker.service"} {
		if !has(after, u) {
			t.Errorf("culvert-firstboot.service lost After=%s", u)
		}
	}
}

// cloudInit261Units carries the ordering directives of cloud-init
// 26.1-0ubuntu1~24.04.1 (the version in the appliance image), with the
// commands replaced; nothing else of those units matters to systemd's
// ordering decision.
var cloudInit261Units = map[string]string{
	"cloud-init-local.service": "[Unit]\nDefaultDependencies=no\nWants=network-pre.target\nAfter=systemd-remount-fs.service\nBefore=network-pre.target\nBefore=shutdown.target\nBefore=sysinit.target\nConflicts=shutdown.target\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
	"cloud-init.service":       "[Unit]\nDefaultDependencies=no\nWants=cloud-init-local.service\nAfter=cloud-init-local.service\nAfter=systemd-networkd-wait-online.service\nAfter=networking.service\nBefore=network-online.target\nBefore=systemd-user-sessions.service\nBefore=sysinit.target\nBefore=shutdown.target\nConflicts=shutdown.target\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
	"cloud-config.target":      "[Unit]\nWants=cloud-init-local.service cloud-init.service\nAfter=cloud-init-local.service cloud-init.service\n",
	"cloud-config.service":     "[Unit]\nAfter=network-online.target cloud-config.target\nWants=network-online.target cloud-config.target\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
	"cloud-final.service":      "[Unit]\nAfter=network-online.target time-sync.target cloud-config.service rc-local.service\nAfter=multi-user.target\nBefore=apt-daily.service\nWants=network-online.target cloud-config.service\n[Service]\nType=oneshot\nExecStart=/bin/true\n",
	"cloud-init.target":        "[Unit]\nAfter=multi-user.target\n",
	"docker.service":           "[Unit]\nDescription=stub\n[Service]\nExecStart=/bin/true\n",
}

// orderingCycleReport loads unit + cloud-init into systemd-analyze and returns
// any ordering-cycle lines for a multi-user.target start transaction.
func orderingCycleReport(t *testing.T, unit string) string {
	t.Helper()
	dir := t.TempDir()
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range cloudInit261Units {
		write(name, body)
	}
	write("culvert-firstboot.service", regexp.MustCompile(`(?m)^ExecStart=.*$`).ReplaceAllString(unit, "ExecStart=/bin/true"))
	link := func(target, u string) {
		d := filepath.Join(dir, target+".wants")
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join("..", u), filepath.Join(d, u)); err != nil {
			t.Fatal(err)
		}
	}
	link("multi-user.target", "culvert-firstboot.service")
	link("multi-user.target", "cloud-init.target") // the cloud-init generator's link
	for _, u := range []string{"cloud-init-local.service", "cloud-init.service", "cloud-config.service", "cloud-final.service"} {
		link("cloud-init.target", u)
	}
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()
	// The trailing ':' appends systemd's default search path: the real
	// multi-user.target is needed (a hermetic stub target loses the cycle, which
	// the broken-ordering control in the caller would catch).
	cmd := exec.CommandContext(ctx, "systemd-analyze", "verify", "--man=no", "multi-user.target")
	cmd.Env = append(os.Environ(), "SYSTEMD_UNIT_PATH="+dir+":")
	out, err := cmd.CombinedOutput()
	// A verification that did not complete proves nothing: no cycle lines from
	// a killed or failed run must never read as "no cycle". Exit status alone
	// is not the verdict either — systemd-analyze exits 0 with a cycle present,
	// so the caller still checks the output (and the control proves it would).
	if ctx.Err() != nil {
		t.Fatalf("systemd-analyze verify did not complete within %v (%v); output:\n%s", verifyTimeout, ctx.Err(), out)
	}
	if err != nil {
		t.Fatalf("systemd-analyze verify failed: %v; output:\n%s", err, out)
	}
	var cycles []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(l), "ordering cycle") || strings.Contains(l, "to break ordering cycle") {
			cycles = append(cycles, l)
		}
	}
	if len(cycles) > 0 {
		t.Logf("systemd-analyze verify output:\n%s", out)
	}
	return strings.Join(cycles, "\n")
}

// verifyTimeout bounds one systemd-analyze run (it loads the host's units too).
var verifyTimeout = time.Minute

func TestFirstbootUnit_NoOrderingCycleWithCloudInit(t *testing.T) {
	if _, err := exec.LookPath("systemd-analyze"); err != nil {
		t.Skip("systemd-analyze not available")
	}
	raw, err := os.ReadFile(firstbootUnitPath)
	if err != nil {
		t.Fatal(err)
	}
	// Control: the shipped-broken ordering must be seen as a cycle, or this
	// harness proves nothing.
	broken := regexp.MustCompile(`(?m)^After=.*$`).ReplaceAllString(string(raw), "After=cloud-final.service docker.service network-online.target")
	if rep := orderingCycleReport(t, broken); !strings.Contains(rep, "culvert-firstboot.service") {
		t.Fatalf("control: systemd-analyze did not report the known cycle; output:\n%s", rep)
	}
	if rep := orderingCycleReport(t, string(raw)); rep != "" {
		t.Errorf("culvert-firstboot.service forms an ordering cycle with cloud-init:\n%s", rep)
	}
}
