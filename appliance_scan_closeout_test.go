package main

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The 7e53720d exact-byte scan (#1528) found three things the gates passed:
// the OVA booting a kernel four ABIs behind its own pinned snapshot, an unused
// snapd carrying most host-binary findings, and the application image shipping
// an Alpine package whose fix was already published because the runtime
// stage's `apk upgrade` layer was replayed from the build cache. These walls
// keep each fix in place.

func readSource(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(pkgSourceDir(), rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPrepareGuest_ShipsTheSnapshotsNewestKernelOnly(t *testing.T) {
	src := readSource(t, "appliance/build/prepare-guest.sh")
	for _, want := range []string{
		// a plain `upgrade` keeps a new kernel ABI back
		`--force-confold --with-new-pkgs upgrade`,
		// every older-ABI kernel package is purged ...
		`'linux-image-[0-9]*' 'linux-modules-[0-9]*' 'linux-modules-extra-[0-9]*'`,
		`'linux-headers-[0-9]*' 'linux-tools-[0-9]*' 'linux-cloud-tools-[0-9]*'`,
		`| grep -vE -- "-${newest_kver//./\\.}(-|\$)" || true)"`,
		`apt-get -y -qq purge $stale_kpkgs`,
		// ... and the build refuses unless exactly one kernel remains
		`[[ "$(find /boot -maxdepth 1 -name 'vmlinuz-*' | wc -l)" == 1 ]] ||`,
		// ... and it is the snapshot's candidate of the HWE image meta, not a
		// held-back kernel, and the kernel that meta depends on
		`meta="$GUEST_KERNEL_META"`,
		`[[ -n "$want_img" && -e "/boot/vmlinuz-${want_img#linux-image-}" ]]`,
		`[[ "$inst" == "$cand" ]] || { echo "$meta is $inst, the snapshot's candidate is $cand (kernel held back)"`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	if regexp.MustCompile(`--force-confold upgrade\n`).MatchString(src) {
		t.Error("the snapshot upgrade must not run without --with-new-pkgs (the kernel would stay behind)")
	}
	// the kernel step runs inside the pinned-snapshot block, before the
	// evidence of what moved is taken
	up := strings.Index(src, `--with-new-pkgs upgrade`)
	one := strings.Index(src, `name 'vmlinuz-*' | wc -l)" == 1 ]]`)
	after := strings.Index(src, `after="$(dpkg-query -W`)
	if up < 0 || one < up || after < one {
		t.Fatalf("order must be upgrade → purge old kernel → one-kernel check → evidence (upgrade=%d check=%d evidence=%d)", up, one, after)
	}
}

// The GA 24.04 kernel (6.8.0) carried 5 CRITICAL and 138 HIGH CVEs open in
// Canonical's tracker with no fixed 6.8.0 package; the supported HWE kernel in
// the same pinned snapshot carried 0 CRITICAL and 23 HIGH. The build installs
// the HWE IMAGE metapackage the manifest names, removes the GA metapackage
// chain so it cannot pull the 6.8 ABI back, and refuses an image where any of
// that does not hold.
func TestPrepareGuest_ShipsTheHWEKernel(t *testing.T) {
	man := readSource(t, "appliance/build/manifest.env")
	if !regexp.MustCompile(`(?m)^GUEST_KERNEL_META=linux-image-virtual-hwe-24\.04$`).MatchString(man) {
		t.Error("manifest.env must pin GUEST_KERNEL_META=linux-image-virtual-hwe-24.04 (the image meta, no headers)")
	}
	src := readSource(t, "appliance/build/prepare-guest.sh")
	for _, want := range []string{
		`install --no-install-recommends "$GUEST_KERNEL_META"`,
		`linux-virtual linux-image-virtual linux-headers-virtual \`,
		`DEBIAN_FRONTEND=noninteractive apt-get -y -qq purge $ga_meta`,
		`"$GUEST_KERNEL_META is not installed after the GA metapackage purge"`,
		`echo "a GA kernel metapackage is installed again" >&2; exit 1`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	// HWE install and GA removal happen before the one-kernel purge.
	inst := strings.Index(src, `install --no-install-recommends "$GUEST_KERNEL_META"`)
	purge := strings.Index(src, `apt-get -y -qq purge $stale_kpkgs`)
	if inst < 0 || purge < inst {
		t.Fatalf("the HWE kernel must be installed before the superseded kernel is purged (install=%d purge=%d)", inst, purge)
	}
	ova := readSource(t, "appliance/build/build-ova.sh")
	for _, want := range []string{
		`DOCKER_CE_VERSION GUEST_KERNEL_META VM_DISK_GB`,
		`grep -q "^${GUEST_KERNEL_META}	" "$OUT/dpkg-list.txt" || die`,
		`[[ "$(grep -cE '^linux-image-[0-9]' "$OUT/dpkg-list.txt")" == 1 ]] || die`,
		`die "a GA kernel metapackage is installed in the guest"`,
	} {
		if !strings.Contains(ova, want) {
			t.Errorf("build-ova.sh must contain %q", want)
		}
	}
}

// CVE-2025-40190 (ext4 EA-inode refcount underflow) needs an ext4 filesystem
// with the ea_inode feature: the kernel rejects an xattr entry naming an EA
// inode on a filesystem without it. The build refuses an image where any ext4
// filesystem carries the feature, and records what it read.
func TestBuildOVA_NoExt4FilesystemHasEAInode(t *testing.T) {
	ova := readSource(t, "appliance/build/build-ova.sh")
	for _, want := range []string{
		`guestfish --ro -a "$DISK" run : list-filesystems | awk -F': ' '$2=="ext4"{print $1}'`,
		`run : tune2fs-l "$fs" | awk -F': *' '$1=="Filesystem features"{print $2}'`,
		`if grep -qw ea_inode <<<"$feats"; then die`,
		`[[ -s "$OUT/ext4-features.txt" ]] || die "no ext4 filesystem found in the image (features not checked)"`,
	} {
		if !strings.Contains(ova, want) {
			t.Errorf("build-ova.sh must contain %q", want)
		}
	}
}

// vmwgfx's open ioctl CVEs need a process that can open a DRM node. Plymouth
// (root) is the only DRM client on the appliance, so every DRM node is
// root:root 0600 and logind's uaccess tag is dropped before 73-seat-late
// applies it.
func TestPrepareGuest_DRMNodesAreRootOnly(t *testing.T) {
	rule := readSource(t, "appliance/provision/72-culvert-drm.rules")
	want := `SUBSYSTEM=="drm", KERNEL=="card[0-9]*|renderD[0-9]*|controlD[0-9]*", GROUP="root", MODE="0600", TAG-="uaccess"`
	if !strings.Contains(rule, want) {
		t.Errorf("72-culvert-drm.rules must contain %q", want)
	}
	src := readSource(t, "appliance/build/prepare-guest.sh")
	if !strings.Contains(src, `install -m 0644 "$APPL/provision/72-culvert-drm.rules" /etc/udev/rules.d/72-culvert-drm.rules`) {
		t.Error("prepare-guest.sh must install 72-culvert-drm.rules")
	}
	// udev orders rules files by name: the rule must sort after
	// 70-uaccess.rules (which adds the tag) and before 73-seat-late.rules
	// (which applies it), so the installed name must keep its 72- prefix.
	rules := []string{"73-seat-late.rules", "72-culvert-drm.rules", "70-uaccess.rules"}
	sort.Strings(rules)
	if rules[1] != "72-culvert-drm.rules" {
		t.Errorf("udev order is %v; the DRM rule must sit between 70-uaccess and 73-seat-late", rules)
	}
}

func TestPrepareGuest_PurgesSnapdAndPinsItOut(t *testing.T) {
	src := readSource(t, "appliance/build/prepare-guest.sh")
	for _, want := range []string{
		"apt-get -y -qq purge snapd\n",
		`rm -rf /var/lib/snapd /var/cache/snapd /snap`,
		// the purge must not take the server metapackage (and with it, at the
		// next autoremove, open-vm-tools and the security auto-updates)
		`for keep in ubuntu-server open-vm-tools unattended-upgrades; do`,
		`|| { echo "$keep is no longer installed after the snapd purge" >&2; exit 1; }`,
		`printf 'Package: snapd\nPin: release *\nPin-Priority: -1\n' > /etc/apt/preferences.d/culvert-no-snapd`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	if strings.Contains(src, "purge snapd lxd-installer") || regexp.MustCompile(`purge[^\n]*lxd-installer`).MatchString(src) {
		t.Error("lxd-installer must not be purged: ubuntu-server DEPENDS on it")
	}
	purge := strings.Index(src, `apt-get -y -qq purge snapd`)
	after := strings.Index(src, `after="$(dpkg-query -W`)
	if purge < 0 || after < purge {
		t.Error("snapd must be purged before the shipped package evidence is taken")
	}
}

func TestAppImage_RuntimeStageIsNeverReplayedFromCache(t *testing.T) {
	df := readSource(t, "Dockerfile")
	at := strings.Index(df, "\nFROM alpine:3.24 AS runtime\n")
	if at < 0 {
		t.Fatal("the final stage must be named `runtime` so the builds can exclude it from the cache")
	}
	if !strings.Contains(df[at:], "RUN apk upgrade --no-cache") {
		t.Error("the runtime stage must upgrade Alpine packages")
	}
	if strings.LastIndex(df, "\nFROM ") != at {
		t.Error("`runtime` must be the final stage")
	}
	for _, wf := range []string{".github/workflows/_build-image.yml", ".github/workflows/ci.yml"} {
		if !strings.Contains(readSource(t, wf), "no-cache-filters: runtime") {
			t.Errorf("%s must build with no-cache-filters: runtime (a cached apk layer ships stale packages)", wf)
		}
	}
}

func TestDeepGate_FailsOnAnyFixableOSPackageFinding(t *testing.T) {
	wf := readSource(t, ".github/workflows/pr-deep-gate.yml")
	i := strings.Index(wf, "Scan image OS packages (any fixable finding, any severity)")
	if i < 0 {
		t.Fatal("the Deep gate must scan the image's OS packages at every severity")
	}
	step := wf[i:]
	if j := strings.Index(step, "\n      - "); j > 0 {
		step = step[:j]
	}
	for _, want := range []string{"--pkg-types os", "--ignore-unfixed", "--ignorefile /dev/null", "--exit-code 1", "culvert:ci-smoke"} {
		if !strings.Contains(step, want) {
			t.Errorf("the OS-package scan step must carry %q", want)
		}
	}
	if strings.Contains(step, "--severity") {
		t.Error("the OS-package scan must not filter by severity (a MEDIUM stale package passed the HIGH/CRITICAL gate)")
	}
}

// Unused kernel modules are made unloadable: the CRITICAL/HIGH residuals of
// the exact-byte scans (sctp, nfsd, kvm_amd, ...), and — because the HWE
// kernel's linux-modules carries every module — each module an unprivileged
// process could autoload over the network API that the GA disk did not carry.
func TestPrepareGuest_UnusedKernelModulesCannotLoad(t *testing.T) {
	conf := readSource(t, "appliance/provision/modprobe-culvert-unused.conf")
	for _, m := range []string{"sctp", "nfsd", "kvm", "kvm_amd", "kvm_intel", "ksmbd", "cifs",
		"can", "can_raw", "can_bcm", "can_gw", "can_isotp", "can_j1939", "pppoe", "pppox",
		"ib_core", "ib_cm", "iw_cm", "rdma_cm", "ib_uverbs", "rdma_ucm", "ib_umad", "dccp", "tipc",
		// residual HIGH CVEs on the HWE kernel (see the file)
		"ip_vs", "openvswitch", "vxlan", "target_core_mod", "target_core_iblock", "snd", "snd_pcm", "soundcore",
		"bluetooth", "btusb", "hci_vhci", "rfcomm", "bnep", "hidp", "bluetooth_6lowpan", "rxrpc", "kafs",
		"amdgpu", "idpf", "scsi_debug",
		// unprivileged network autoload the GA 6.8 disk did not carry
		"batman_adv", "caif_socket", "cfg80211", "gtp", "kcm", "l2tp_core", "l2tp_ip", "l2tp_ip6",
		"l2tp_netlink", "l2tp_ppp", "macsec", "mpls_router", "mptcp_diag", "nfc", "ovpn", "qrtr",
		"rds", "smc", "smc_diag", "tipc_diag", "xsk_diag"} {
		for _, want := range []string{"\nblacklist " + m + "\n", "\ninstall " + m + " /bin/false\n", "\nsoftdep " + m + " pre: post:\n"} {
			if !strings.Contains(conf, want) {
				t.Errorf("modprobe-culvert-unused.conf must contain %q", strings.TrimSpace(want))
			}
		}
	}
	src := readSource(t, "appliance/build/prepare-guest.sh")
	for _, want := range []string{
		`install -m 0644 "$APPL/provision/modprobe-culvert-unused.conf" /etc/modprobe.d/culvert-unused.conf`,
		// the check reads its module list from the installed file itself
		`denied_mods="$(awk '$1=="install" && $3=="/bin/false"{print $2}' /etc/modprobe.d/culvert-unused.conf)"`,
		`[[ "$(wc -w <<<"$denied_mods")" -ge 65 ]] ||`,
		`for m in $denied_mods kvm-amd can-raw; do`,
		`modprobe -n -v "$m" 2>&1 | tail -n 1 | grep -qE '^install /bin/false[[:space:]]*$' || { echo "modprobe would still load $m" >&2; exit 1; }`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	// VMware Tools needs vsock: it must never be denied.
	if regexp.MustCompile(`(?m)^(install|blacklist) (vsock|vmw_vsock\w*)\b`).MatchString(conf) {
		t.Error("vsock must stay loadable: open-vm-tools uses it")
	}
	// Every other unprivileged-autoloadable module is reviewed, and the build
	// refuses a disk where that does not hold (in both directions).
	for _, want := range []string{
		`netload="$(awk '$1=="alias" && $2 ~ /^(net-pf-[0-9]+$|net-pf-[0-9]+-proto-|tcp-ulp-)/ {print $3}' "${kmods[0]}" | tr - _ | sort -u)"`,
		`reviewed="$(awk '!/^#/ && NF {print $1}' "$APPL/provision/net-autoload-reviewed.txt" | tr - _ | sort -u)"`,
		`[[ -z "$unreviewed" ]] || { echo "unprivileged-autoloadable modules neither denied nor reviewed:`,
		`[[ -z "$stale" ]] || { echo "net-autoload-reviewed.txt lists modules this kernel does not ship with such an alias:`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	reviewed := readSource(t, "appliance/provision/net-autoload-reviewed.txt")
	for _, line := range strings.Split(reviewed, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 || strings.HasPrefix(f[0], "#") {
			continue
		}
		if strings.Contains(conf, "\ninstall "+f[0]+" /bin/false\n") {
			t.Errorf("%s is both denied and reviewed as loadable", f[0])
		}
		if len(f) < 2 {
			t.Errorf("net-autoload-reviewed.txt: %s has no reason", f[0])
		}
	}
	if !strings.Contains(readSource(t, "appliance/build/build-ova.sh"), " net-autoload-reviewed.txt ") {
		t.Error("build-ova.sh must copy net-autoload-reviewed.txt into the guest")
	}
}
