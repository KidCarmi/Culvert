package main

import (
	"os"
	"path/filepath"
	"regexp"
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
		// ... and it is the snapshot's candidate, not a held-back kernel
		`for meta in linux-image-virtual linux-image-generic; do`,
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

// The replacement's exact-byte scan left five CRITICAL kernel CVEs with no
// fixed 6.8.0 package. Three are in modules not on the disk (kvm_amd,
// nvmet_tcp, ib_srpt ship in linux-modules-extra); the other two, and two
// unused protocols, are made unloadable here.
func TestPrepareGuest_UnusedKernelModulesCannotLoad(t *testing.T) {
	conf := readSource(t, "appliance/provision/modprobe-culvert-unused.conf")
	for _, m := range []string{"sctp", "nfsd", "dccp", "tipc"} {
		for _, want := range []string{"\nblacklist " + m + "\n", "\ninstall " + m + " /bin/false\n"} {
			if !strings.Contains(conf, want) {
				t.Errorf("modprobe-culvert-unused.conf must contain %q", strings.TrimSpace(want))
			}
		}
	}
	src := readSource(t, "appliance/build/prepare-guest.sh")
	for _, want := range []string{
		`install -m 0644 "$APPL/provision/modprobe-culvert-unused.conf" /etc/modprobe.d/culvert-unused.conf`,
		`for m in sctp nfsd dccp tipc; do`,
		`modprobe -n -v "$m" 2>&1 | grep -qE '^install /bin/false[[:space:]]*$' || { echo "modprobe would still load $m" >&2; exit 1; }`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("prepare-guest.sh must contain %q", want)
		}
	}
	// linux-modules-extra carries the other three CRITICAL subsystems; the
	// build must not start installing it.
	if regexp.MustCompile(`apt-get[^\n]*install[^\n]*linux-modules-extra`).MatchString(src) {
		t.Error("prepare-guest.sh must not install linux-modules-extra (kvm_amd, nvmet_tcp, ib_srpt)")
	}
}
