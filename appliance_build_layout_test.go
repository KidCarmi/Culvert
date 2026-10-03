package main

import (
	"os"
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
