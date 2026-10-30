package main

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"
)

// #1528 M2 (ASTRA 27 Oct): two kernel HIGH findings on the HWE kernel have a
// prerequisite the appliance can take away without losing a function.
//
//   - AF_PACKET TX_RING (CVE-2026-98503) needs CAP_NET_RAW to open a packet
//     socket. The ClamAV sidecar ran with Docker's default capability set,
//     which includes it. No Culvert or ClamAV process uses raw sockets, so
//     every service on the Culvert/ClamAV images drops it.
//   - io_uring (CVE-2026-98858): Docker's default seccomp profile already
//     denies io_uring inside containers; the host side is closed by
//     kernel.io_uring_disabled = 2 in a sysctl drop-in the OVA build installs.

func TestM2Hardening_IoUringDisabledOnTheGuest(t *testing.T) {
	conf := readSource(t, "appliance/provision/sysctl-culvert-hardening.conf")
	re := regexp.MustCompile(`(?m)^kernel\.io_uring_disabled\s*=\s*(\S+)\s*$`)
	m := re.FindAllStringSubmatch(conf, -1)
	if len(m) != 1 || m[0][1] != "2" {
		t.Fatalf("sysctl-culvert-hardening.conf must set kernel.io_uring_disabled = 2 exactly once, got %q", m)
	}
	src := readSource(t, "appliance/build/prepare-guest.sh")
	for _, want := range []string{
		`install -m 0644 "$APPL/provision/sysctl-culvert-hardening.conf" /etc/sysctl.d/99-culvert-hardening.conf`,
		`grep -qxE 'kernel\.io_uring_disabled[[:space:]]*=[[:space:]]*2' /etc/sysctl.d/99-culvert-hardening.conf`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
}

func TestM2Hardening_NoServiceKeepsNetRaw(t *testing.T) {
	type service struct {
		Image   string   `yaml:"image"`
		Build   any      `yaml:"build"`
		CapAdd  []string `yaml:"cap_add"`
		CapDrop []string `yaml:"cap_drop"`
	}
	ours := regexp.MustCompile(`^culvert/(proxy|clamav):`)
	// HA builds proxy/dp from the repo root instead of naming an image.
	builtHere := func(b any) bool {
		ctx := b
		if m, ok := b.(map[string]any); ok {
			ctx = m["context"]
		}
		c, _ := ctx.(string)
		return c == "." || c == "./" || c == "./appliance/clamav"
	}
	for _, f := range []string{"docker-compose.yml", "docker-compose.ha.yml"} {
		var doc struct {
			Services map[string]service `yaml:"services"`
		}
		if err := yaml.Unmarshal([]byte(readSource(t, f)), &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		checked := 0
		for name, s := range doc.Services {
			if !ours.MatchString(s.Image) && !builtHere(s.Build) {
				continue
			}
			checked++
			if !slices.ContainsFunc(s.CapDrop, coversNetRaw) {
				t.Errorf("%s: service %q (%s) must cap_drop NET_RAW", f, name, s.Image)
			}
			for _, c := range s.CapAdd {
				if coversNetRaw(c) {
					t.Errorf("%s: service %q must not cap_add %s", f, name, c)
				}
			}
		}
		// Not vacuous: both files run the sidecar and the proxy.
		if checked < 3 {
			t.Errorf("%s: only %d Culvert/ClamAV services found; the image pattern no longer matches", f, checked)
		}
	}
}

// coversNetRaw reports whether a compose capability name grants or removes
// NET_RAW (directly or via ALL).
func coversNetRaw(c string) bool {
	return c == "NET_RAW" || c == "CAP_NET_RAW" || c == "ALL"
}
