package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// FB-1 (docs/appliance/evidence/combined/future-build/FB-1-APT-SNAPSHOT.md):
// the guest build passed `-o Acquire::Snapshot`, an option APT 2.8.3 does not
// have, so OVA 325c142a was built from the LIVE archive (57 of its 680
// versions are not in the pinned snapshot). These tests pin the fix:
//   T1/T2  static walls over prepare-guest.sh, apt-snapshot.sh, manifest.env
//          and build-ova.sh;
//   T3     the offline reconciler, including the real 325c142a inventory
//          against real snapshot stanzas (red case: exactly the 57);
//   plus behaviour of the guest library itself (pins, sources, call shapes).
// T4 (network, isolated APT root) is appliance/build/snapshot-pin-check.sh;
// T5 is the next built OVA.

const (
	fb1PrepareGuest = "appliance/build/prepare-guest.sh"
	fb1AptLib       = "appliance/build/apt-snapshot.sh"
	fb1Manifest     = "appliance/build/manifest.env"
	fb1BuildOVA     = "appliance/build/build-ova.sh"
	fb1Reconciler   = "appliance/build/reconcile-package-provenance.py"
	fb1Fixtures     = "appliance/build/testdata/provenance"
	fb1Nonsnapshot  = "docs/appliance/evidence/combined/esxi-325c142a/kernel-42/provenance-nonsnapshot-57.tsv"
)

var fb1Suites = []string{"noble", "noble-updates", "noble-security", "noble-backports"}

var fb1Components = []string{"main", "restricted", "universe", "multiverse"}

// The selected snapshot (31 Oct pin raise) and its reviewed InRelease hashes:
// gpgv-verified, fetched twice byte-identical, and equal to the indexes the
// approved kernel-42 transaction was evaluated against
// (fb1-snapshot-20261029/authn.tsv, esxi-325c142a/kernel-42/apt-indexes.txt).
const fb1PinnedSnapshot = "20261029T180000Z"

var fb1ReviewedPins = map[string]string{
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE":     "cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0",
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_UPDATES":   "1af76bea40c6b8ddbc51a51046c5a3e7912c9611536e97afc673a4b1c39d1886",
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY":  "d90e89008640e66a6eacc13ffaad0fbbd205877cc51acdd8d4f99f9d21fcfee0",
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_BACKPORTS": "b6a0b10bb67d8da7ecb72a3f62dda5f408091d5a1abe8cbda2380f4af6b705cd",
}

// The reviewed Docker .deb SHA-256 pins: read from Docker's gpgv-verified
// index AND hashed from the downloaded files (31 Oct); the engine three equal
// M1's recorded identities.
var fb1ReviewedDockerDebs = map[string]string{
	"DOCKER_CE_DEB_SHA256":             "95ddf7a2d8b8c0eb82d8597d4d604e294dcf741081f2e228524d5ab9bfd7c8ae",
	"DOCKER_CE_CLI_DEB_SHA256":         "74747b5c99000279b9b2c7eb82543b4121d8436a58aa3be7e78ac6681d74794f",
	"CONTAINERD_IO_DEB_SHA256":         "f811ab57d1f4bb0cce19df7d526da8c711d8ebea0447cc83da1999188e664122",
	"DOCKER_COMPOSE_PLUGIN_DEB_SHA256": "9725be1df7fd5ccc6b21ac24112885896c8d134345e3f4aa20b3c2064ef4620e",
}

// The T3 fixtures are real stanzas of the PREVIOUS pin 20261002T120000Z: the
// snapshot OVA 325c142a was supposed to be built from, which makes its real
// inventory a red case (57 live-only versions). Their InRelease pins are
// computed by the test, not taken from the manifest.
const fb1FixtureSnapshot = "20261002T120000Z"

func fb1Read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// fb1CodeLines drops comments and blank lines (comments may name the defect).
func fb1CodeLines(src string) []string {
	var out []string
	for _, l := range strings.Split(src, "\n") {
		if s := strings.TrimSpace(l); s != "" && !strings.HasPrefix(s, "#") {
			out = append(out, l)
		}
	}
	return out
}

func fb1ManifestVars(t *testing.T) map[string]string {
	t.Helper()
	m := map[string]string{}
	for _, l := range strings.Split(fb1Read(t, fb1Manifest), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(l), "="); ok && !strings.HasPrefix(k, "#") {
			m[k] = strings.Trim(v, `"`)
		}
	}
	return m
}

// T1: no call can carry the ignored option, every pinned apt call goes
// through the snapshot helpers, and the two false claims are gone.
func TestAptSnapshotFB1_T1_EveryPinnedAptCallIsSnapshotAware(t *testing.T) {
	pg := fb1Read(t, fb1PrepareGuest)
	lib := fb1Read(t, fb1AptLib)
	for name, src := range map[string]string{fb1PrepareGuest: pg, fb1AptLib: lib} {
		for _, l := range fb1CodeLines(src) {
			if strings.Contains(l, "Acquire::Snapshot") {
				t.Errorf("%s still passes Acquire::Snapshot, which APT ignores: %s", name, strings.TrimSpace(l))
			}
		}
	}

	// In prepare-guest.sh the only raw apt calls are the live update AFTER
	// the snapshot sources are restored, and the final cache clean.
	raw := regexp.MustCompile(`(^|[\s;&|(])apt-(get|cache)(\s|$)`)
	restored := false
	for _, l := range fb1CodeLines(pg) {
		s := strings.TrimSpace(l)
		if s == "apt_snap_sources_restore" {
			restored = true
		}
		if !raw.MatchString(s) {
			continue
		}
		switch {
		case s == "apt-get clean":
		case s == "apt-get -qq update" && restored:
		default:
			t.Errorf("prepare-guest.sh calls APT outside the snapshot helpers: %s", s)
		}
	}
	if !restored {
		t.Error("prepare-guest.sh never restores the Ubuntu sources (apt_snap_sources_restore)")
	}

	// Ordering of the pinned section.
	order := []string{
		"apt_snap_require_pins",
		"apt_snap_sources_enable /etc/apt/sources.list.d/docker.list",
		"apt_snap_update -qq",
		"apt_snap_verify_inrelease",
		`"docker-ce=${DOCKER_CE_VERSION}"`,
		"apt_snap install -y -qq --no-install-recommends pigz psmisc",
		`apt_snap_acquisition_receipt /var/cache/apt/archives "$STATE/acquired-debs.tsv"`,
		`apt_snap_verify_docker_debs "$STATE/acquired-debs.tsv"`,
		"--with-new-pkgs upgrade",
		`apt_snap -y -qq install --no-install-recommends "$GUEST_KERNEL_META"`,
		`cand="$(apt_cache_snap policy "$meta"`,
		`want_img="$(apt_cache_snap depends "$meta"`,
		"apt_snap -y -qq purge snapd",
		"plymouth plymouth-theme-ubuntu-text plymouth-label fontconfig",
		"apt_snap_sources_restore",
		// The final receipt is taken after every install and before the cache is cleaned.
		`log "acquisition receipt:`,
		"apt-get clean",
	}
	pos := -1
	for _, want := range order {
		i := strings.Index(pg, want)
		if i < 0 {
			t.Errorf("prepare-guest.sh lost %q", want)
			continue
		}
		if i < pos {
			t.Errorf("prepare-guest.sh: %q is out of order", want)
		}
		pos = i
	}

	// The helpers: --snapshot on every call, --error-on=any on the update.
	for fn, wants := range map[string][]string{
		"apt_snap": {`apt-get "${APT_SNAP_OPTS[@]}" --snapshot "$GUEST_APT_SNAPSHOT"`,
			`-o APT::Get::Always-Include-Phased-Updates=true -o APT::Keep-Downloaded-Packages=true "$@"`},
		"apt_snap_update": {`--snapshot "$GUEST_APT_SNAPSHOT" --error-on=any "$@" update`},
		"apt_cache_snap":  {`apt-cache "${APT_SNAP_OPTS[@]}" --snapshot "$GUEST_APT_SNAPSHOT" "$@"`},
	} {
		body := fb1ShellFunc(t, lib, fn)
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("apt-snapshot.sh %s lost %q", fn, w)
			}
		}
	}

	// The two false claims FB-1 names.
	if strings.Contains(fb1Read(t, fb1Manifest), "apt -o Acquire::Snapshot") {
		t.Error("manifest.env still documents the ignored `apt -o Acquire::Snapshot`")
	}
	if strings.Contains(pg, "would refuse the whole update") {
		t.Error("prepare-guest.sh still claims a source without snapshot=no would refuse the update (it is used live, FB-1 E4)")
	}
}

func fb1ShellFunc(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "\n"+name+"() {")
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	end := strings.Index(src[start:], "\n}\n")
	if end < 0 {
		t.Fatalf("function %s not terminated", name)
	}
	return src[start : start+end]
}

// T2: the pins exist and are the reviewed values; Ubuntu opts in, Docker
// opts out; build-ova.sh verifies the indexes and reconciles, fail-closed.
func TestAptSnapshotFB1_T2_PinsSourcesAndReconciliationAreWired(t *testing.T) {
	m := fb1ManifestVars(t)
	if m["GUEST_APT_SNAPSHOT"] != fb1PinnedSnapshot {
		t.Errorf("GUEST_APT_SNAPSHOT=%q: the reviewed pins below belong to %s", m["GUEST_APT_SNAPSHOT"], fb1PinnedSnapshot)
	}
	for k, want := range fb1ReviewedDockerDebs {
		if m[k] != want {
			t.Errorf("manifest.env %s=%q, the reviewed Docker .deb SHA-256 is %s", k, m[k], want)
		}
	}
	hex64 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	for k, want := range fb1ReviewedPins {
		if !hex64.MatchString(m[k]) {
			t.Errorf("manifest.env %s=%q is not a SHA-256", k, m[k])
		} else if m[k] != want {
			t.Errorf("manifest.env %s=%s, the reviewed FB-1 value is %s", k, m[k], want)
		}
	}

	lib := fb1Read(t, fb1AptLib)
	if !strings.Contains(lib, `print "Snapshot: yes"`) {
		t.Error("apt-snapshot.sh no longer opts the Ubuntu sources into snapshots")
	}
	pg := fb1Read(t, fb1PrepareGuest)
	if !regexp.MustCompile(`deb \[arch=amd64 signed-by=/etc/apt/keyrings/docker\.gpg snapshot=no\] \$\{DOCKER_APT_URL\}`).MatchString(pg) {
		t.Error("the Docker source must declare snapshot=no")
	}

	bo := fb1Read(t, fb1BuildOVA)
	for _, want := range []string{
		`cp "$HERE/apt-snapshot.sh" "$OV/opt/culvert-appliance/apt-snapshot.sh"`,
		`SNAP_BASE="https://snapshot.ubuntu.com/ubuntu/${GUEST_APT_SNAPSHOT}"`,
		`[[ "$got" == "$pin" ]] || die "snapshot $GUEST_APT_SNAPSHOT $suite InRelease is $got, manifest pins $pin"`,
		`die "the $suite/$comp index does not match its InRelease"`,
		`[[ "$docker_fpr" == "$DOCKER_APT_KEY_FPR" ]] || die`,
		`gpgv --keyring "$PROV/docker/key.gpg" "$PROV/docker/InRelease"`,
		`python3 "$HERE/reconcile-package-provenance.py" --dpkg-list "$OUT/dpkg-list.txt"`,
		`--out "$OUT/package-provenance.tsv" || die "package provenance reconciliation failed (FB-1)`,
		`--acquired "$OUT/acquired-debs.tsv"`,
		`|| die "the guest wrote no acquisition receipt (acquired-debs.tsv)"`,
		`printf '\n# ── recorded by build-ova.sh ──\nGUEST_APT_BUILD_START=%s\n' "$GUEST_APT_BUILD_START"`,
	} {
		if !strings.Contains(bo, want) {
			t.Errorf("build-ova.sh lost %q", want)
		}
	}
	for _, pin := range []string{"DOCKER_CE_VERSION", "DOCKER_CE_CLI_VERSION", "CONTAINERD_IO_VERSION", "DOCKER_COMPOSE_PLUGIN_VERSION",
		"DOCKER_CE_DEB_SHA256", "DOCKER_CE_CLI_DEB_SHA256", "CONTAINERD_IO_DEB_SHA256", "DOCKER_COMPOSE_PLUGIN_DEB_SHA256"} {
		if !strings.Contains(bo, "=$"+pin+`"`) {
			t.Errorf("build-ova.sh does not hand %s to the reconciler", pin)
		}
	}
	// The build start is recorded once and the ID judged against it BEFORE
	// anything is fetched (the base image is the first fetch).
	rec0 := strings.Index(bo, `GUEST_APT_BUILD_START="$(date -u +%Y%m%dT%H%M%SZ)"`)
	chk := strings.Index(bo, "\napt_snap_require_pins\n")
	fetch := strings.Index(bo, "curl -fsSL")
	if rec0 < 0 || chk < rec0 || fetch < chk || strings.Count(bo, `GUEST_APT_BUILD_START="$(`) != 1 {
		t.Errorf("build start must be recorded exactly once and checked before the first fetch (record=%d check=%d fetch=%d)", rec0, chk, fetch)
	}
	// The base inventory is read from the VERIFIED base image file before any
	// guest step touches a disk, and the reconciler is handed it.
	verified := strings.Index(bo, `die "base image SHA256 mismatch (manifest BASE_IMAGE_SHA256)"`)
	baseRead := strings.Index(bo, `virt-cat -a "$BASE_FILE" /var/lib/dpkg/status > "$OUT/base-dpkg-status.txt"`)
	diskMade := strings.Index(bo, `qemu-img convert -q -O qcow2 "$BASE_FILE" "$DISK"`)
	guest := strings.Index(bo, `virt-customize -a "$DISK"`)
	if verified < 0 || baseRead < verified || diskMade < baseRead || guest < diskMade {
		t.Errorf("the base dpkg status must be read from the verified base file before the disk and the guest step (verify=%d read=%d disk=%d guest=%d)",
			verified, baseRead, diskMade, guest)
	}
	for _, want := range []string{
		`--base-status "$OUT/base-dpkg-status.txt"`,
		`[[ -s "$OUT/base-dpkg-status.txt" ]] || die`,
		`"base_dpkg_status_sha256": E["BI_BASE_STATUS_SHA"]`,
	} {
		if !strings.Contains(bo, want) {
			t.Errorf("build-ova.sh lost %q", want)
		}
	}
	// Reconcile after the guest inventory is read, before anything is packaged.
	inv := strings.Index(bo, `virt-cat -a "$DISK" /var/lib/culvert-appliance/dpkg-list.txt`)
	rec := strings.Index(bo, `reconcile-package-provenance.py`)
	pkg := strings.Index(bo, "# ── 6. VMDK + OVF + OVA")
	if inv < 0 || rec < 0 || pkg < 0 || inv >= rec || rec >= pkg {
		t.Errorf("reconciliation must run after the dpkg-list extraction and before packaging (inv=%d rec=%d pkg=%d)", inv, rec, pkg)
	}
}

// --- guest library behaviour (offline) ---

func fb1Bash(t *testing.T, env []string, script string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	lib, err := filepath.Abs(fb1AptLib)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(t.Context(), "bash", "-c", `set -euo pipefail; . "$LIB"; `+script) //nolint:gosec // test-owned script
	cmd.Env = append(append(os.Environ(), "LIB="+lib), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// fb1PinEnv: the manifest pins with ID id and a recorded build start that is
// after every ID the tests treat as valid (and long before "now" is relevant).
func fb1PinEnv(id string) []string {
	return fb1PinEnvAt(id, "20261031T120000Z")
}

func fb1PinEnvAt(id, buildStart string) []string {
	env := []string{"GUEST_APT_SNAPSHOT=" + id, "GUEST_APT_BUILD_START=" + buildStart}
	for k, v := range fb1ReviewedPins {
		env = append(env, k+"="+v)
	}
	return env
}

func TestAptSnapshotFB1_RequirePinsRefusesBadIDsAndPins(t *testing.T) {
	if out, err := fb1Bash(t, fb1PinEnv(fb1PinnedSnapshot), "apt_snap_require_pins"); err != nil {
		t.Fatalf("valid pins refused: %v %s", err, out)
	}
	// A real leap day is a real instant (control for the calendar check).
	if out, err := fb1Bash(t, fb1PinEnvAt("20240229T235959Z", "20240301T000000Z"), "apt_snap_require_pins"); err != nil {
		t.Fatalf("29 Feb 2024 23:59:59 refused: %v %s", err, out)
	}
	for name, env := range map[string][]string{
		// ASTRA's two reproductions on aa02e66e: shape-valid, calendar-impossible.
		"30 Feb":                        fb1PinEnv("20260230T120000Z"),
		"month 13, day 40, 25:61:99":    fb1PinEnv("20251340T256199Z"),
		"29 Feb of a non-leap year":     fb1PinEnv("20260229T000000Z"),
		"hour 24":                       fb1PinEnv("20261029T240000Z"),
		"minute 60":                     fb1PinEnv("20261029T236000Z"),
		"second 60":                     fb1PinEnv("20261029T235960Z"),
		"day 00":                        fb1PinEnv("20261000T120000Z"),
		"no Z":                          fb1PinEnv("20261029T180000"),
		"leading space":                 fb1PinEnv(" 20261029T180000Z"),
		"malformed ID":                  fb1PinEnv("2026-10-02"),
		"empty ID":                      fb1PinEnv(""),
		"future ID (served as now, E6)": fb1PinEnv("20991231T000000Z"),
		"ID equal to the build start":   fb1PinEnvAt("20261031T120000Z", "20261031T120000Z"),
		"ID after the build start":      fb1PinEnvAt(fb1PinnedSnapshot, "20261029T175959Z"),
		"no recorded build start":       fb1PinEnvAt(fb1PinnedSnapshot, ""),
		"impossible build start":        fb1PinEnvAt(fb1PinnedSnapshot, "20261131T000000Z"),
		"missing InRelease pin":         append(fb1PinEnv(fb1PinnedSnapshot), "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY="),
		"short InRelease pin":           append(fb1PinEnv(fb1PinnedSnapshot), "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE=cdb2f31d"),
	} {
		if out, err := fb1Bash(t, env, "apt_snap_require_pins"); err == nil {
			t.Errorf("%s accepted: %s", name, out)
		}
	}
}

// The ID is judged against the ONE recorded build start, not the moving
// clock: an ID earlier than now but after the recorded instant is refused,
// and an ID before the recorded instant passes whatever the clock says.
func TestAptSnapshotFB1_RequirePinsUsesTheRecordedInstantNotTheClock(t *testing.T) {
	// 2020: both are long before "now"; a clock-based check would accept the ID.
	if out, err := fb1Bash(t, fb1PinEnvAt("20200102T000000Z", "20200101T000000Z"), "apt_snap_require_pins"); err == nil {
		t.Errorf("an ID after the recorded build start (but before now) was accepted: %s", out)
	}
	// A clock reading 1970 must not matter either: the stub answers any
	// "what time is it" call with 1970 (the pre-fix check would then refuse
	// every ID) and only delegates parsing (-d) to the real date.
	bin := t.TempDir()
	stub := "#!/bin/sh\ncase \" $* \" in *\" -d \"*) exec /bin/date \"$@\" ;; esac\necho 19700101T000000Z\n"
	if err := os.WriteFile(filepath.Join(bin, "date"), []byte(stub), 0o700); err != nil { //nolint:gosec // executable test stub
		t.Fatal(err)
	}
	env := append(fb1PinEnvAt(fb1PinnedSnapshot, "20261031T120000Z"), "PATH="+bin+":/usr/bin:/bin")
	if out, err := fb1Bash(t, env, "apt_snap_require_pins"); err != nil {
		t.Errorf("an ID before the recorded build start was refused: %v %s", err, out)
	}

	// The check must not depend on `date` REJECTING an impossible date. GNU
	// date does; a normalizing implementation (busybox, BSD -j) rolls
	// 2026-02-30 over to 2026-03-02 and exits 0. The round trip (the
	// normalized instant must equal the input) catches it.
	norm := t.TempDir()
	nstub := "#!/bin/sh\ncase \" $* \" in *\" -d \"*) case \"$*\" in *2026-02-30*) echo 20260302T120000Z; exit 0 ;; esac; exec /bin/date \"$@\" ;; esac\necho 20261031T120000Z\n"
	if err := os.WriteFile(filepath.Join(norm, "date"), []byte(nstub), 0o700); err != nil { //nolint:gosec // executable test stub
		t.Fatal(err)
	}
	nenv := append(fb1PinEnvAt("20260230T120000Z", "20261031T120000Z"), "PATH="+norm+":/usr/bin:/bin")
	if out, err := fb1Bash(t, nenv, "apt_snap_require_pins"); err == nil || !strings.Contains(out, "20260230T120000Z") {
		t.Errorf("an impossible ID was accepted because date normalized it: %v %s", err, out)
	}
	// Control: the same normalizing stub still accepts a real instant.
	nenv = append(fb1PinEnvAt(fb1PinnedSnapshot, "20261031T120000Z"), "PATH="+norm+":/usr/bin:/bin")
	if out, err := fb1Bash(t, nenv, "apt_snap_require_pins"); err != nil {
		t.Errorf("a real ID was refused under the normalizing date stub: %v %s", err, out)
	}
}

// The in-guest InRelease check, against an APT lists directory.
func TestAptSnapshotFB1_VerifyInReleaseFailsClosed(t *testing.T) {
	root := t.TempDir()
	lists := filepath.Join(root, "var", "lib", "apt", "lists")
	if err := os.MkdirAll(lists, 0o750); err != nil {
		t.Fatal(err)
	}
	id := "20261002T120000Z"
	env := []string{"APT_SNAP_ROOT=" + root, "GUEST_APT_SNAPSHOT=" + id}
	contents := map[string]string{}
	for _, s := range fb1Suites {
		body := "Suite: " + s + "\nfixture\n"
		contents[s] = body
		sum := sha256.Sum256([]byte(body))
		env = append(env, "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_"+map[string]string{
			"noble": "NOBLE", "noble-updates": "UPDATES", "noble-security": "SECURITY", "noble-backports": "BACKPORTS",
		}[s]+"="+hex.EncodeToString(sum[:]))
	}
	write := func() {
		for s, b := range contents {
			if err := os.WriteFile(filepath.Join(lists, "snapshot.ubuntu.com_ubuntu_"+id+"_dists_"+s+"_InRelease"), []byte(b), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	write()
	if out, err := fb1Bash(t, env, "apt_snap_verify_inrelease"); err != nil {
		t.Fatalf("matching InRelease files refused: %v %s", err, out)
	}
	// A different InRelease (a future ID serves the current state) fails.
	sec := filepath.Join(lists, "snapshot.ubuntu.com_ubuntu_"+id+"_dists_noble-security_InRelease")
	if err := os.WriteFile(sec, []byte("Suite: noble-security\nDate: today\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := fb1Bash(t, env, "apt_snap_verify_inrelease"); err == nil || !strings.Contains(out, "noble-security InRelease is") {
		t.Errorf("a changed InRelease passed: %v %s", err, out)
	}
	// A missing one (the index was not fetched) fails; it is never skipped.
	write()
	if err := os.Remove(sec); err != nil {
		t.Fatal(err)
	}
	if out, err := fb1Bash(t, env, "apt_snap_verify_inrelease"); err == nil || !strings.Contains(out, "was not fetched") {
		t.Errorf("a missing InRelease passed: %v %s", err, out)
	}
	// Live lists alone (a source that was not snapshotted, E4/E9) fail too.
	if err := os.WriteFile(filepath.Join(lists, "security.ubuntu.com_ubuntu_dists_noble-security_InRelease"), []byte(contents["noble-security"]), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := fb1Bash(t, env, "apt_snap_verify_inrelease"); err == nil {
		t.Errorf("a live list stood in for the snapshot one: %s", out)
	}
}

func TestAptSnapshotFB1_SourcesOptInAndRestore(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "etc", "apt", "sources.list.d")
	if err := os.MkdirAll(d, 0o750); err != nil {
		t.Fatal(err)
	}
	orig := "Types: deb\nURIs: http://archive.ubuntu.com/ubuntu/\nSuites: noble noble-updates noble-backports\nComponents: main\n" +
		"Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg\n\n" +
		"types: deb\nURIs: http://security.ubuntu.com/ubuntu/\nSuites: noble-security\nComponents: main\nSnapshot: no\n"
	src := filepath.Join(d, "ubuntu.sources")
	docker := filepath.Join(d, "docker.list")
	reset := func(dockerLine string) {
		if err := os.WriteFile(src, []byte(orig), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(docker, []byte(dockerLine), 0o600); err != nil {
			t.Fatal(err)
		}
		_ = os.Remove(src + ".culvert-pre-snapshot")
	}
	good := "deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg snapshot=no] https://download.docker.com/linux/ubuntu noble stable\n"
	env := []string{"APT_SNAP_ROOT=" + root, "D=" + docker}

	reset(good)
	if out, err := fb1Bash(t, env, `apt_snap_sources_enable "$D"`); err != nil {
		t.Fatalf("enable refused: %v %s", err, out)
	}
	got := fb1Read(t, src)
	if strings.Count(got, "Snapshot: yes") != 2 || strings.Contains(got, "Snapshot: no") {
		t.Errorf("every stanza must carry exactly one Snapshot: yes (an existing Snapshot: line replaced):\n%s", got)
	}
	if out, err := fb1Bash(t, env, `apt_snap_sources_restore`); err != nil {
		t.Fatalf("restore failed: %v %s", err, out)
	}
	if fb1Read(t, src) != orig {
		t.Error("restore did not return the image's original Ubuntu sources")
	}

	// A Docker source without snapshot=no is refused.
	reset("deb [arch=amd64 signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu noble stable\n")
	if out, err := fb1Bash(t, env, `apt_snap_sources_enable "$D"`); err == nil {
		t.Errorf("a Docker source without snapshot=no was accepted: %s", out)
	}
	// Any other source would be resolved live (E4): refused.
	reset(good)
	stray := filepath.Join(d, "ppa.list")
	if err := os.WriteFile(stray, []byte("deb http://ppa.launchpadcontent.net/x/y/ubuntu noble main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := fb1Bash(t, env, `apt_snap_sources_enable "$D"`); err == nil || !strings.Contains(out, "ppa.list") {
		t.Errorf("a stray source was accepted: %v %s", err, out)
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "extra.sources"), []byte("Types: deb\nURIs: http://example.invalid/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := fb1Bash(t, env, `apt_snap_sources_enable "$D"`); err == nil {
		t.Errorf("a stray deb822 source was accepted: %s", out)
	}
}

// The exact argv each helper hands APT (a stub on PATH records it).
func TestAptSnapshotFB1_HelpersPassTheSnapshotSelector(t *testing.T) {
	bin := t.TempDir()
	for _, tool := range []string{"apt-get", "apt-cache"} {
		stub := "#!/bin/sh\necho " + tool + " \"$@\"\n"
		if err := os.WriteFile(filepath.Join(bin, tool), []byte(stub), 0o755); err != nil { //nolint:gosec // executable test stub
			t.Fatal(err)
		}
	}
	env := append(fb1PinEnv(fb1PinnedSnapshot), "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := fb1Bash(t, env, `apt_snap_update -qq; apt_snap install -y pigz; apt_cache_snap policy systemd`)
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	want := "apt-get --snapshot 20261029T180000Z --error-on=any -qq update\n" +
		"apt-get --snapshot 20261029T180000Z -o APT::Get::Always-Include-Phased-Updates=true -o APT::Keep-Downloaded-Packages=true install -y pigz\n" +
		"apt-cache --snapshot 20261029T180000Z policy systemd\n"
	if out != want {
		t.Errorf("helper argv:\n%s\nwant:\n%s", out, want)
	}
	if out, err := fb1Bash(t, env, `apt_snap update`); err == nil {
		t.Errorf("apt_snap update must be refused (it would skip --error-on=any): %s", out)
	}
}

// --- T3: the offline reconciler ---

type fb1Index struct {
	snapDir, dockerDir string
	pins               map[string]string
	// receipt: the guest's acquisition receipt rows
	// (package, version, arch, sha256, file). nil omits --acquired.
	receipt []string
	// baseStatus: the base image's pre-transaction dpkg status (--base-status).
	// "" writes one that holds every non-Docker inventory row — the tests of
	// index integrity then exercise only the index; the binding tests below
	// pass the REAL base image status. noBase omits --base-status.
	baseStatus string
	noBase     bool
}

// fb1RealBaseStatus is /var/lib/dpkg/status of the pinned base image
// (serial 20260926, BASE_IMAGE_SHA256 6a81c375…), read with `virt-cat -a
// <image> /var/lib/dpkg/status` — the build-ova.sh command — from the image
// verified against its pin and Ubuntu's signed SHA256SUMS.
const fb1RealBaseStatusSHA256 = "3fde68c0b3bf65d2708cf0d263f9a28feeb64c75a4d42249ebd2d555b10dcc28"

func fb1RealBaseStatus(t *testing.T) string {
	t.Helper()
	p := filepath.Join(fb1Fixtures, "base-dpkg-status-20260926.txt")
	sum := sha256.Sum256([]byte(fb1Read(t, p)))
	if got := hex.EncodeToString(sum[:]); got != fb1RealBaseStatusSHA256 {
		t.Fatalf("base status fixture is not the 20260926 image's (sha256 %s)", got)
	}
	return p
}

// fb1BaseKeys parses a dpkg status file into installed name/version/arch rows.
func fb1BaseKeys(t *testing.T, path string) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, st := range strings.Split(fb1Read(t, path), "\n\n") {
		f := map[string]string{}
		for _, l := range strings.Split(st, "\n") {
			if k, v, ok := strings.Cut(l, ": "); ok && !strings.HasPrefix(l, " ") {
				f[k] = v
			}
		}
		if f["Package"] != "" && strings.HasSuffix(f["Status"], " installed") {
			out[f["Package"]+"\t"+f["Version"]+"\t"+f["Architecture"]] = true
		}
	}
	return out
}

// fb1StatusFile renders name\tversion\tarch rows as a dpkg status file.
func fb1StatusFile(t *testing.T, rows []string, status string) string {
	t.Helper()
	var sb strings.Builder
	for _, r := range rows {
		f := strings.Split(r, "\t")
		fmt.Fprintf(&sb, "Package: %s\nStatus: %s\nPriority: optional\nArchitecture: %s\nVersion: %s\nDescription: fixture\n\n", f[0], status, f[2], f[1])
	}
	p := filepath.Join(t.TempDir(), "base-dpkg-status.txt")
	if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// fb1Stanza returns Filename and SHA256 of (pkg, version, arch) in a
// Packages file.
func fb1Stanza(t *testing.T, packages, pkg, ver, arch string) (filename, sha string) {
	t.Helper()
	for _, st := range strings.Split(fb1Read(t, packages), "\n\n") {
		f := map[string]string{}
		for _, l := range strings.Split(st, "\n") {
			if k, v, ok := strings.Cut(l, ": "); ok {
				f[k] = v
			}
		}
		if f["Package"] == pkg && f["Version"] == ver && f["Architecture"] == arch {
			return f["Filename"], f["SHA256"]
		}
	}
	t.Fatalf("%s %s %s not in %s", pkg, ver, arch, packages)
	return "", ""
}

// fb1ReceiptRow is one acquisition-receipt row for a stanza of packages.
func fb1ReceiptRow(t *testing.T, packages, pkg, ver, arch string) string {
	t.Helper()
	fn, sha := fb1Stanza(t, packages, pkg, ver, arch)
	return strings.Join([]string{pkg, ver, arch, sha, filepath.Base(fn)}, "\t")
}

// fb1DockerReceipt: the four pinned Docker packages acquired with the bytes
// the (real) Docker index lists — which are the reviewed pins.
func fb1DockerReceipt(t *testing.T, dockerDir string) []string {
	t.Helper()
	m := fb1ManifestVars(t)
	var rows []string
	for _, p := range [][2]string{{"docker-ce", "DOCKER_CE_VERSION"}, {"docker-ce-cli", "DOCKER_CE_CLI_VERSION"},
		{"containerd.io", "CONTAINERD_IO_VERSION"}, {"docker-compose-plugin", "DOCKER_COMPOSE_PLUGIN_VERSION"}} {
		rows = append(rows, fb1ReceiptRow(t, filepath.Join(dockerDir, "Packages"), p[0], m[p[1]], "amd64"))
	}
	return rows
}

// fb1BuildIndexes copies the committed real-stanza fixtures into a temp dir
// and writes InRelease files listing their SHA-256, the way the archive does.
// The pins are the SHA-256 of those InRelease files. mutate may edit the
// Packages files BEFORE the InRelease is written (a consistent index) — edits
// after it model a tampered or truncated index.
func fb1BuildIndexes(t *testing.T, mutate func(dir string)) fb1Index {
	t.Helper()
	tmp := t.TempDir()
	ix := fb1Index{snapDir: filepath.Join(tmp, "snapshot"), dockerDir: filepath.Join(tmp, "docker"), pins: map[string]string{}}
	for _, sub := range []string{"snapshot", "docker"} {
		if err := os.CopyFS(filepath.Join(tmp, sub), os.DirFS(filepath.Join(fb1Fixtures, sub))); err != nil {
			t.Fatal(err)
		}
	}
	if mutate != nil {
		mutate(tmp)
	}
	sumFile := func(p string) (string, int) {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		s := sha256.Sum256(b)
		return hex.EncodeToString(s[:]), len(b)
	}
	for _, suite := range fb1Suites {
		var sb strings.Builder
		fmt.Fprintf(&sb, "Origin: Ubuntu\nSuite: %s\nNote: test fixture; stanzas are real snapshot "+fb1FixtureSnapshot+" entries\nSHA256:\n", suite)
		for _, comp := range fb1Components {
			h, n := sumFile(filepath.Join(ix.snapDir, suite+"-"+comp+".Packages"))
			fmt.Fprintf(&sb, " %s %16d %s/binary-amd64/Packages\n", h, n, comp)
		}
		p := filepath.Join(ix.snapDir, suite+".InRelease")
		if err := os.WriteFile(p, []byte(sb.String()), 0o600); err != nil {
			t.Fatal(err)
		}
		ix.pins[suite], _ = sumFile(p)
	}
	h, n := sumFile(filepath.Join(ix.dockerDir, "Packages"))
	dockerInRelease := fmt.Sprintf("Origin: Docker\nSuite: noble\nSHA256:\n %s %16d stable/binary-amd64/Packages\n", h, n)
	if err := os.WriteFile(filepath.Join(ix.dockerDir, "InRelease"), []byte(dockerInRelease), 0o600); err != nil {
		t.Fatal(err)
	}
	ix.receipt = fb1DockerReceipt(t, ix.dockerDir)
	return ix
}

func fb1Reconcile(t *testing.T, ix fb1Index, inventory string, extra ...string) (combined, tsv string, err error) {
	t.Helper()
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}
	m := fb1ManifestVars(t)
	out := filepath.Join(t.TempDir(), "package-provenance.tsv")
	args := []string{"-I", fb1Reconciler, "--dpkg-list", inventory, "--snapshot-dir", ix.snapDir,
		"--snapshot-id", fb1FixtureSnapshot, "--docker-dir", ix.dockerDir,
		"--docker-uri", "https://download.docker.com/linux/ubuntu", "--out", out}
	for _, s := range fb1Suites {
		args = append(args, "--pin", s+"="+ix.pins[s])
	}
	pins := map[string]string{
		"docker-ce": m["DOCKER_CE_VERSION"], "docker-ce-cli": m["DOCKER_CE_CLI_VERSION"],
		"containerd.io": m["CONTAINERD_IO_VERSION"], "docker-compose-plugin": m["DOCKER_COMPOSE_PLUGIN_VERSION"],
	}
	shas := map[string]string{
		"docker-ce": m["DOCKER_CE_DEB_SHA256"], "docker-ce-cli": m["DOCKER_CE_CLI_DEB_SHA256"],
		"containerd.io": m["CONTAINERD_IO_DEB_SHA256"], "docker-compose-plugin": m["DOCKER_COMPOSE_PLUGIN_DEB_SHA256"],
	}
	// extra: "name=version" overrides a version pin, "sha:name=hex" a byte
	// pin, "sha:name=" drops it.
	for _, kv := range extra {
		k, v, _ := strings.Cut(kv, "=")
		if name, ok := strings.CutPrefix(k, "sha:"); ok {
			shas[name] = v
			continue
		}
		pins[k] = v
	}
	for k, v := range pins {
		args = append(args, "--docker-pin", k+"="+v)
	}
	for k, v := range shas {
		if v != "" {
			args = append(args, "--docker-deb-sha256", k+"="+v)
		}
	}
	if ix.receipt != nil {
		rp := filepath.Join(t.TempDir(), "acquired-debs.tsv")
		if err := os.WriteFile(rp, []byte(strings.Join(ix.receipt, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--acquired", rp)
	}
	if !ix.noBase {
		base := ix.baseStatus
		if base == "" {
			var rows []string
			for _, r := range strings.Split(strings.TrimSpace(fb1Read(t, inventory)), "\n") {
				if f := strings.Split(r, "\t"); len(f) == 3 && pins[f[0]] == "" {
					rows = append(rows, r)
				}
			}
			base = fb1StatusFile(t, rows, "install ok installed")
		}
		args = append(args, "--base-status", base)
	}
	cmd := exec.CommandContext(t.Context(), "python3", args...) //nolint:gosec // test-owned paths
	raw, runErr := cmd.CombinedOutput()
	written, _ := os.ReadFile(out)
	return string(raw), string(written), runErr
}

func fb1Inventory(t *testing.T, rows []string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "dpkg-list.txt")
	if err := os.WriteFile(p, []byte(strings.Join(rows, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func fb1RealInventory(t *testing.T) []string {
	t.Helper()
	raw := strings.TrimRight(fb1Read(t, filepath.Join(fb1Fixtures, "inventory-325c142a.tsv")), "\n")
	sum := sha256.Sum256([]byte(raw + "\n"))
	// The exact-byte inventory of OVA 325c142a (scan run 40579).
	if got := hex.EncodeToString(sum[:]); got != "675a0773a0422e56e648ca5d90177d6d99056fbcb01ee1aeb0991af2f1b70aff" {
		t.Fatalf("inventory fixture is not the 325c142a inventory (sha256 %s)", got)
	}
	return strings.Split(raw, "\n")
}

// The 57 the evidence recorded, as "name\tversion".
func fb1Recorded57(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	for _, l := range strings.Split(fb1Read(t, fb1Nonsnapshot), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 2 || strings.HasPrefix(l, "#") || f[0] == "package" {
			continue
		}
		out[f[0]+"\t"+f[1]] = true
	}
	if len(out) != 57 {
		t.Fatalf("recorded non-snapshot list has %d rows, want 57", len(out))
	}
	return out
}

var fb1NotInSnapshot = regexp.MustCompile(`(?m)^  package\t(\S+)\t(\S+) \S+ is not in snapshot ` + fb1FixtureSnapshot + `$`)

// T3(a): the real 325c142a inventory against real snapshot stanzas fails,
// naming exactly the 57 versions the evidence recorded — the build that
// shipped would have been refused.
func TestAptSnapshotFB1_T3a_Real325c142aInventoryFailsOnExactlyThe57(t *testing.T) {
	ix := fb1BuildIndexes(t, nil)
	combined, tsv, err := fb1Reconcile(t, ix, fb1Inventory(t, fb1RealInventory(t)))
	if err == nil {
		t.Fatalf("325c142a reconciled clean:\n%s", combined)
	}
	if tsv != "" {
		t.Error("a failed reconciliation wrote package-provenance.tsv")
	}
	got := map[string]bool{}
	for _, m := range fb1NotInSnapshot.FindAllStringSubmatch(combined, -1) {
		got[m[1]+"\t"+m[2]] = true
	}
	want := fb1Recorded57(t)
	var missing, extra []string
	for k := range want {
		if !got[k] {
			missing = append(missing, k)
		}
	}
	for k := range got {
		if !want[k] {
			extra = append(extra, k)
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing)+len(extra) > 0 {
		t.Errorf("not exactly the recorded 57: missing %v, extra %v", missing, extra)
	}
	if !strings.Contains(combined, "57 problem(s)") {
		t.Errorf("expected exactly 57 problems (the 4 Docker packages at their pins are not among them):\n%s", combined)
	}
}

// T3(b): the same inventory without the 57 reconciles; every row is
// accounted for, with its origin and the .deb hash from the verified index.
// fb1SnapshotReceiptRow is a receipt row for (pkg, ver, arch) from whichever
// fixture Packages file lists it — the bytes the authenticated index names.
func fb1SnapshotReceiptRow(t *testing.T, ix fb1Index, pkg, ver, arch string) string {
	t.Helper()
	want := []string{"Package: " + pkg, "Version: " + ver, "Architecture: " + arch}
	for _, suite := range fb1Suites {
		for _, comp := range fb1Components {
			pf := filepath.Join(ix.snapDir, suite+"-"+comp+".Packages")
			for _, st := range strings.Split(fb1Read(t, pf), "\n\n") {
				lines := strings.Split(st, "\n")
				if slices.Contains(lines, want[0]) && slices.Contains(lines, want[1]) && slices.Contains(lines, want[2]) {
					return fb1ReceiptRow(t, pf, pkg, ver, arch)
				}
			}
		}
	}
	t.Fatalf("%s %s %s is in no fixture index", pkg, ver, arch)
	return ""
}

// fb1RealBuildCase: the 623 in-snapshot rows of the real 325c142a inventory,
// the REAL base image status, and a receipt holding the four Docker packages
// plus exactly the Ubuntu rows the base image does not already carry at that
// version/architecture (what a build must download). It returns the index,
// the inventory rows and the rows that need an acquisition.
func fb1RealBuildCase(t *testing.T) (ix fb1Index, rows, need []string) {
	t.Helper()
	ix = fb1BuildIndexes(t, nil)
	ix.baseStatus = fb1RealBaseStatus(t)
	base := fb1BaseKeys(t, ix.baseStatus)
	bad := fb1Recorded57(t)
	for _, r := range fb1RealInventory(t) {
		f := strings.Split(r, "\t")
		if bad[f[0]+"\t"+f[1]] {
			continue
		}
		rows = append(rows, r)
		docker := strings.HasPrefix(r, "docker-") || strings.HasPrefix(r, "containerd.io\t")
		if !docker && !base[r] {
			need = append(need, r)
			ix.receipt = append(ix.receipt, fb1SnapshotReceiptRow(t, ix, f[0], f[1], f[2]))
		}
	}
	return ix, rows, need
}

func TestAptSnapshotFB1_T3b_InSnapshotInventoryPasses(t *testing.T) {
	ix, rows, need := fb1RealBuildCase(t)
	combined, tsv, err := fb1Reconcile(t, ix, fb1Inventory(t, rows))
	if err != nil {
		t.Fatalf("an all-in-snapshot inventory failed: %v\n%s", err, combined)
	}
	var data []string
	for _, l := range strings.Split(strings.TrimRight(tsv, "\n"), "\n") {
		if !strings.HasPrefix(l, "#") && !strings.HasPrefix(l, "package\t") {
			data = append(data, l)
		}
	}
	if len(data) != 623 {
		t.Fatalf("package-provenance.tsv has %d rows, want 623", len(data))
	}
	acquired := map[string]bool{}
	for _, r := range need {
		acquired[r] = true
	}
	origins, bindings := map[string]int{}, map[string]int{}
	for _, l := range data {
		f := strings.Split(l, "\t")
		if len(f) != 9 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(f[7]) || !strings.HasSuffix(f[6], ".deb") {
			t.Fatalf("malformed provenance row: %q", l)
		}
		origins[f[3]]++
		bindings[f[8]]++
		// Docker rows and every Ubuntu row the base image lacks at this
		// version were acquired; only base-image rows are inherited.
		want := "inherited-base-image"
		if f[3] == "docker" || acquired[f[0]+"\t"+f[1]+"\t"+f[2]] {
			want = "acquired-verified"
		}
		if f[8] != want {
			t.Errorf("%s binding %q, want %q", f[0], f[8], want)
		}
	}
	if bindings["acquired-verified"] != 4+len(need) || bindings["inherited-base-image"] != 623-4-len(need) || len(need) == 0 {
		t.Errorf("bindings %v with %d Ubuntu rows needing an acquisition", bindings, len(need))
	}
	if !strings.Contains(tsv, fb1RealBaseStatusSHA256) {
		t.Error("provenance header does not record the base status SHA-256")
	}
	if origins["docker"] != 4 || origins["ubuntu-snapshot"] != 619 {
		t.Errorf("origins %v, want 4 docker + 619 ubuntu-snapshot", origins)
	}
	for _, s := range fb1Suites {
		if !strings.Contains(tsv, s+"="+ix.pins[s]) {
			t.Errorf("provenance header does not record the %s InRelease pin", s)
		}
	}
	// The real docker-ce .deb the M1 evidence verified.
	if !strings.Contains(tsv, "docker-ce\t5:29.9.2-1~ubuntu.24.04~noble\tamd64\tdocker\t") ||
		!strings.Contains(tsv, "95ddf7a2d8b8c0eb82d8597d4d604e294dcf741081f2e228524d5ab9bfd7c8ae") {
		t.Error("docker-ce row does not carry the verified .deb SHA-256")
	}
}

func fb1Minimal(rows ...string) []string {
	base := []string{
		"adduser\t3.137ubuntu1\tall",
		"containerd.io\t2.4.2-3~ubuntu.24.04~noble\tamd64",
		"docker-ce\t5:29.9.2-1~ubuntu.24.04~noble\tamd64",
		"docker-ce-cli\t5:29.9.2-1~ubuntu.24.04~noble\tamd64",
		"docker-compose-plugin\t5.6.1-1~ubuntu.24.04~noble\tamd64",
	}
	return append(base, rows...)
}

func TestAptSnapshotFB1_T3_NegativeCasesFailClosed(t *testing.T) {
	ix := fb1BuildIndexes(t, nil)
	if out, _, err := fb1Reconcile(t, ix, fb1Inventory(t, fb1Minimal())); err != nil {
		t.Fatalf("control: the minimal inventory must pass: %s", out)
	}
	cases := []struct {
		name  string
		rows  []string
		pins  []string
		match string
	}{
		{"(c) a Docker package off its pin", nil, []string{"docker-ce=5:29.9.0-1~ubuntu.24.04~noble"},
			"docker-ce\t5:29.9.2-1~ubuntu.24.04~noble amd64 is not the manifest pin 5:29.9.0-1"},
		{"(d) an unknown or local package", []string{"culvert-local-tool\t1.0\tamd64"}, nil,
			"culvert-local-tool\t1.0 amd64 is not in snapshot"},
		{"(d) a live-only version", []string{"systemd\t255.4-1ubuntu8.18\tamd64"}, nil,
			"systemd\t255.4-1ubuntu8.18 amd64 is not in snapshot"},
		{"(d) the right version, the wrong architecture", []string{"adduser\t3.137ubuntu1\tamd64"}, nil,
			"adduser\t3.137ubuntu1 amd64 is not in snapshot"},
	}
	for _, c := range cases {
		inv := fb1Minimal(c.rows...)
		out, tsv, err := fb1Reconcile(t, ix, fb1Inventory(t, inv), c.pins...)
		if err == nil || !strings.Contains(out, c.match) || tsv != "" {
			t.Errorf("%s: err=%v tsv=%d bytes\n%s", c.name, err, len(tsv), out)
		}
	}
	// (c) at its pin, but the pin is not in Docker's verified index.
	off := fb1Minimal()
	off[3] = "docker-ce-cli\t5:29.9.1-1~ubuntu.24.04~noble\tamd64"
	if out, _, err := fb1Reconcile(t, ix, fb1Inventory(t, off), "docker-ce-cli=5:29.9.1-1~ubuntu.24.04~noble"); err == nil ||
		!strings.Contains(out, "docker-ce-cli\t5:29.9.1-1~ubuntu.24.04~noble amd64 is not in Docker's verified index") {
		t.Errorf("a Docker version absent from Docker's index passed:\n%s", out)
	}
	// A pinned Docker package that is not installed.
	inv := fb1Minimal()[:4]
	if out, _, err := fb1Reconcile(t, ix, fb1Inventory(t, inv)); err == nil || !strings.Contains(out, "docker-compose-plugin\tpinned") {
		t.Errorf("a missing pinned Docker package passed:\n%s", out)
	}
	// An empty inventory proves nothing.
	if out, _, err := fb1Reconcile(t, ix, fb1Inventory(t, nil)); err == nil || !strings.Contains(out, "no installed packages") {
		t.Errorf("an empty inventory passed:\n%s", out)
	}
}

// fb1Edit rewrites a file under dir (after the InRelease was written, so the
// index no longer matches it; before, via fb1BuildIndexes' mutate, so it does).
func fb1Edit(t *testing.T, path string, edit func(string) string) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(edit(string(b))), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAptSnapshotFB1_T3_IndexIntegrityFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		before  func(t *testing.T, dir string) // consistent index edit
		after   func(t *testing.T, ix *fb1Index)
		failure string // "" means the reconciliation must pass
		tsvHas  string
	}{
		{name: "(e) missing index", failure: "noble/main\tmissing noble-main.Packages",
			after: func(t *testing.T, ix *fb1Index) {
				if err := os.Remove(filepath.Join(ix.snapDir, "noble-main.Packages")); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "(e) emptied index", failure: "noble-security/main\tnoble-security-main.Packages is e3b0c442",
			after: func(t *testing.T, ix *fb1Index) {
				fb1Edit(t, filepath.Join(ix.snapDir, "noble-security-main.Packages"), func(string) string { return "" })
			}},
		{name: "(e) missing InRelease", failure: "noble-updates\tmissing or empty InRelease",
			after: func(t *testing.T, ix *fb1Index) {
				if err := os.Remove(filepath.Join(ix.snapDir, "noble-updates.InRelease")); err != nil {
					t.Fatal(err)
				}
			}},
		{name: "(f) InRelease differs from its pin", failure: "noble-security\tInRelease is",
			after: func(_ *testing.T, ix *fb1Index) {
				ix.pins["noble-security"] = fb1ReviewedPins["GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY"]
			}},
		{name: "tampered Packages under a valid InRelease", failure: "InRelease lists",
			after: func(t *testing.T, ix *fb1Index) {
				fb1Edit(t, filepath.Join(ix.snapDir, "noble-main.Packages"), func(b string) string {
					return strings.Replace(b, "Version: 3.137ubuntu1", "Version: 3.137ubuntu1+evil", 1)
				})
			}},
		{name: "tampered Docker index", failure: "docker/stable",
			after: func(t *testing.T, ix *fb1Index) {
				fb1Edit(t, filepath.Join(ix.dockerDir, "Packages"), func(b string) string { return b + "\nPackage: docker-ce\n" })
			}},
		{name: "two different .debs for one version", failure: "two different .deb hashes",
			before: func(t *testing.T, dir string) {
				fb1Edit(t, filepath.Join(dir, "snapshot", "noble-backports-main.Packages"), func(string) string {
					return "Package: adduser\nArchitecture: all\nVersion: 3.137ubuntu1\nFilename: pool/main/a/adduser/adduser_3.137ubuntu1_all.deb\n" +
						"SHA256: " + strings.Repeat("0", 64) + "\n"
				})
			}},
		// The real archive lists ocl-icd 2.3.2-1build1 under pool/universe in
		// noble and pool/main in noble-updates, with the same SHA-256: one .deb.
		{name: "same .deb under two pool paths is one package",
			tsvHas: "noble/main,noble-backports/main\tpool/main/a/adduser/adduser_3.137ubuntu1_all.deb,pool/universe/",
			before: func(t *testing.T, dir string) {
				body := fb1Read(t, filepath.Join(dir, "snapshot", "noble-main.Packages"))
				i := strings.Index(body, "Package: adduser\n")
				j := strings.Index(body[i:], "\n\n")
				stanza := strings.Replace(body[i:i+j+1], "pool/main/", "pool/universe/", 1)
				fb1Edit(t, filepath.Join(dir, "snapshot", "noble-backports-main.Packages"), func(string) string { return stanza })
			}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var before func(string)
			if c.before != nil {
				before = func(dir string) { c.before(t, dir) }
			}
			ix := fb1BuildIndexes(t, before)
			if c.after != nil {
				c.after(t, &ix)
			}
			out, tsv, err := fb1Reconcile(t, ix, fb1Inventory(t, fb1Minimal()))
			if c.failure == "" {
				if err != nil || !strings.Contains(tsv, c.tsvHas) {
					t.Errorf("expected to pass with %q: %v\n%s\n%s", c.tsvHas, err, out, tsv)
				}
				return
			}
			if err == nil || !strings.Contains(out, c.failure) || tsv != "" {
				t.Errorf("expected failure %q, got err=%v:\n%s", c.failure, err, out)
			}
		})
	}
}

// ASTRA's reproduction on aa02e66e: an internally consistent Docker index
// (InRelease lists the Packages hash) that names DIFFERENT bytes for the
// pinned name/version/architecture was accepted. The reviewed byte pin now
// refuses it, and so does the acquisition receipt.
func TestAptSnapshotFB1_DockerByteBindingRefusesASelfConsistentIndex(t *testing.T) {
	m := fb1ManifestVars(t)
	evil := strings.Repeat("e", 64)
	ix := fb1BuildIndexes(t, func(dir string) {
		fb1Edit(t, filepath.Join(dir, "docker", "Packages"), func(b string) string {
			return strings.Replace(b, "SHA256: "+m["DOCKER_CE_DEB_SHA256"], "SHA256: "+evil, 1)
		})
	})
	// The receipt matches the doctored index, i.e. the attacker controls both.
	for i, r := range ix.receipt {
		if strings.HasPrefix(r, "docker-ce\t") {
			ix.receipt[i] = strings.Replace(r, m["DOCKER_CE_DEB_SHA256"], evil, 1)
		}
	}
	out, tsv, err := fb1Reconcile(t, ix, fb1Inventory(t, fb1Minimal()))
	if err == nil || tsv != "" {
		t.Fatalf("a self-consistent Docker index with other bytes was accepted:\n%s", out)
	}
	for _, want := range []string{
		"docker-ce 5:29.9.2-1~ubuntu.24.04~noble amd64 is listed as " + evil + ", the reviewed pin is " + m["DOCKER_CE_DEB_SHA256"],
		"is " + evil + ", the reviewed pin is " + m["DOCKER_CE_DEB_SHA256"],
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
}

func TestAptSnapshotFB1_AcquisitionReceiptFailsClosed(t *testing.T) {
	adduser := func(t *testing.T, ix fb1Index) string {
		return fb1ReceiptRow(t, filepath.Join(ix.snapDir, "noble-main.Packages"), "adduser", "3.137ubuntu1", "all")
	}
	cases := []struct {
		name    string
		edit    func(t *testing.T, ix *fb1Index)
		extra   []string
		failure string
		tsvHas  string
	}{
		{name: "control: an acquired Ubuntu .deb with the indexed bytes is acquired-verified",
			edit:   func(t *testing.T, ix *fb1Index) { ix.receipt = append(ix.receipt, adduser(t, *ix)) },
			tsvHas: "adduser\t3.137ubuntu1\tall\tubuntu-snapshot\t"},
		{name: "same name/version/arch, different bytes (Ubuntu)",
			edit: func(t *testing.T, ix *fb1Index) {
				r := strings.Split(adduser(t, *ix), "\t")
				r[3] = strings.Repeat("a", 64)
				ix.receipt = append(ix.receipt, strings.Join(r, "\t"))
			},
			failure: "adduser\t3.137ubuntu1 all (adduser_3.137ubuntu1_all.deb) is " + strings.Repeat("a", 64) + ", the authenticated snapshot index lists"},
		{name: "same name/version/arch, different bytes (Docker)",
			edit: func(t *testing.T, ix *fb1Index) {
				for i, r := range ix.receipt {
					if strings.HasPrefix(r, "containerd.io\t") {
						f := strings.Split(r, "\t")
						f[3] = strings.Repeat("b", 64)
						ix.receipt[i] = strings.Join(f, "\t")
					}
				}
			},
			failure: "containerd.io\t2.4.2-3~ubuntu.24.04~noble amd64 (containerd.io_2.4.2-3~ubuntu.24.04~noble_amd64.deb) is " + strings.Repeat("b", 64)},
		{name: "one package acquired as two different files",
			edit: func(t *testing.T, ix *fb1Index) {
				r := strings.Split(adduser(t, *ix), "\t")
				ix.receipt = append(ix.receipt, strings.Join(r, "\t"))
				r[3], r[4] = strings.Repeat("c", 64), "adduser-other.deb"
				ix.receipt = append(ix.receipt, strings.Join(r, "\t"))
			},
			failure: "adduser\t3.137ubuntu1 all was acquired as two different files"},
		{name: "an acquired .deb the snapshot does not list",
			edit: func(t *testing.T, ix *fb1Index) {
				ix.receipt = append(ix.receipt, "evil-tool\t1.0\tamd64\t"+strings.Repeat("d", 64)+"\tevil-tool_1.0_amd64.deb")
			},
			failure: "evil-tool\t1.0 amd64 (evil-tool_1.0_amd64.deb) is not in snapshot"},
		{name: "a pinned Docker package installed without an acquisition of its bytes",
			edit: func(t *testing.T, ix *fb1Index) {
				ix.receipt = slices.DeleteFunc(ix.receipt, func(r string) bool { return strings.HasPrefix(r, "docker-ce-cli\t") })
			},
			failure: "docker-ce-cli\t5:29.9.2-1~ubuntu.24.04~noble amd64 is installed but no verified acquisition of its bytes exists"},
		{name: "no acquisition receipt",
			edit:    func(t *testing.T, ix *fb1Index) { ix.receipt = []string{} },
			failure: "acquired\t-\tthe acquisition receipt is empty"},
		{name: "a malformed receipt row",
			edit: func(t *testing.T, ix *fb1Index) {
				ix.receipt = append(ix.receipt, "adduser\t3.137ubuntu1\tall\tnot-a-hash\tx.deb")
			},
			failure: "not <package>TAB<version>TAB<arch>TAB<sha256>TAB<file>"},
		{name: "a Docker version pin without a reviewed byte pin",
			extra:   []string{"sha:docker-compose-plugin="},
			failure: "no reviewed .deb SHA-256 for docker-compose-plugin"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ix := fb1BuildIndexes(t, nil)
			if c.edit != nil {
				c.edit(t, &ix)
			}
			out, tsv, err := fb1Reconcile(t, ix, fb1Inventory(t, fb1Minimal()), c.extra...)
			if c.failure == "" {
				if err != nil || !strings.Contains(tsv, c.tsvHas) || !strings.Contains(tsv, "acquired-verified") {
					t.Errorf("expected to pass with %q: %v\n%s\n%s", c.tsvHas, err, out, tsv)
				}
				return
			}
			if err == nil || !strings.Contains(out, c.failure) || tsv != "" {
				t.Errorf("expected failure %q, got err=%v:\n%s", c.failure, err, out)
			}
		})
	}
	// --acquired is a required argument: no receipt file, no reconciliation.
	ix := fb1BuildIndexes(t, nil)
	ix.receipt = nil
	if out, _, err := fb1Reconcile(t, ix, fb1Inventory(t, fb1Minimal())); err == nil || !strings.Contains(out, "--acquired") {
		t.Errorf("a reconciliation without --acquired ran:\n%s", out)
	}
}

// ASTRA (4f56bdfc): a package with no acquisition receipt must not fall back
// to inherited-base-image unless that exact package/version/architecture is
// in the base image's pre-transaction dpkg status. Real data first: the real
// 325c142a rows, the real base image status, a receipt with exactly what a
// build downloads; then single and complete receipt deletions.
func TestAptSnapshotFB1_MissingReceiptNeedsTheBaseInventory(t *testing.T) {
	ix, rows, need := fb1RealBuildCase(t)
	base := fb1BaseKeys(t, ix.baseStatus)
	baseVer := map[string]string{}
	for k := range base {
		f := strings.Split(k, "\t")
		baseVer[f[0]] = f[1]
	}
	var upgraded, added string
	for _, r := range need {
		name := strings.Split(r, "\t")[0]
		if _, ok := baseVer[name]; ok && upgraded == "" {
			upgraded = r
		}
		if _, ok := baseVer[name]; !ok && added == "" {
			added = r
		}
	}
	if upgraded == "" || added == "" {
		t.Fatalf("the real case lacks an upgraded (%q) or a newly installed (%q) package", upgraded, added)
	}
	t.Logf("%d Ubuntu rows need an acquisition; upgraded probe %q, new probe %q", len(need), upgraded, added)
	without := func(drop func(row string) bool) fb1Index {
		c := ix
		c.receipt = slices.DeleteFunc(slices.Clone(ix.receipt), drop)
		return c
	}
	nameOf := func(r string) string { return strings.Split(r, "\t")[0] }
	cases := []struct {
		name, drop, want string
	}{
		{"an upgraded package without its receipt", upgraded,
			nameOf(upgraded) + "\t" + strings.Split(upgraded, "\t")[1] + " " + strings.Split(upgraded, "\t")[2] +
				" has no verified acquisition and the base image had " + baseVer[nameOf(upgraded)]},
		{"a newly installed package without its receipt", added,
			nameOf(added) + "\t" + strings.Split(added, "\t")[1] + " " + strings.Split(added, "\t")[2] +
				" has no verified acquisition and it is not in the base image"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cut := without(func(r string) bool { return strings.HasPrefix(r, nameOf(c.drop)+"\t") })
			out, tsv, err := fb1Reconcile(t, cut, fb1Inventory(t, rows))
			if err == nil || !strings.Contains(out, c.want) || tsv != "" {
				t.Errorf("deleting the receipt of %q was accepted or misreported: %v\n%s", c.drop, err, out)
			}
		})
	}
	t.Run("every Ubuntu receipt row deleted", func(t *testing.T) {
		cut := without(func(r string) bool {
			return !strings.HasPrefix(r, "docker-") && !strings.HasPrefix(r, "containerd.io\t")
		})
		out, _, err := fb1Reconcile(t, cut, fb1Inventory(t, rows))
		if got := strings.Count(out, " has no verified acquisition and "); err == nil || got != len(need) {
			t.Errorf("refused %d rows, want exactly the %d not in the base image: %v\n%s", got, len(need), err, out)
		}
	})
}

// Synthetic: what counts as "in the base image" is the exact triple of an
// INSTALLED package, and the base status is required.
func TestAptSnapshotFB1_MissingReceiptBaseInventoryIsExact(t *testing.T) {
	adduser := "adduser\t3.137ubuntu1\tall"
	syn := []struct {
		name    string
		base    string
		receipt bool
		want    string
	}{
		{"control: in the base image at this version and arch", fb1StatusFile(t, []string{adduser}, "install ok installed"), false, ""},
		{"control: an older base version, but acquired", fb1StatusFile(t, []string{"adduser\t3.136\tall"}, "install ok installed"), true, ""},
		{"an older base version, not acquired", fb1StatusFile(t, []string{"adduser\t3.136\tall"}, "install ok installed"), false,
			"adduser\t3.137ubuntu1 all has no verified acquisition and the base image had 3.136"},
		{"same version, other architecture", fb1StatusFile(t, []string{"adduser\t3.137ubuntu1\tamd64"}, "install ok installed"), false,
			"adduser\t3.137ubuntu1 all has no verified acquisition and it is not in the base image"},
		{"only config files left in the base image", fb1StatusFile(t, []string{adduser, "zlib1g\t1:1.3\tamd64"}, "deinstall ok config-files"), false,
			"base-status\t-\tno installed packages"},
		{"an empty base status", fb1StatusFile(t, nil, ""), false, "base-status\t-\tno installed packages"},
	}
	for _, c := range syn {
		t.Run(c.name, func(t *testing.T) {
			sx := fb1BuildIndexes(t, nil)
			sx.baseStatus = c.base
			if c.receipt {
				sx.receipt = append(sx.receipt, fb1ReceiptRow(t, filepath.Join(sx.snapDir, "noble-main.Packages"), "adduser", "3.137ubuntu1", "all"))
			}
			out, tsv, err := fb1Reconcile(t, sx, fb1Inventory(t, fb1Minimal()))
			if c.want == "" {
				if err != nil || !strings.Contains(tsv, "adduser\t3.137ubuntu1\tall\t") {
					t.Errorf("expected to pass: %v\n%s", err, out)
				}
				return
			}
			if err == nil || !strings.Contains(out, c.want) {
				t.Errorf("expected %q: %v\n%s", c.want, err, out)
			}
		})
	}
	// --base-status is required.
	sx := fb1BuildIndexes(t, nil)
	sx.noBase = true
	if out, _, err := fb1Reconcile(t, sx, fb1Inventory(t, fb1Minimal())); err == nil || !strings.Contains(out, "--base-status") {
		t.Errorf("a reconciliation without --base-status ran:\n%s", out)
	}
}

// fb1Deb builds a real .deb with the given control fields and returns its
// path and SHA-256 (the receipt reads fields from the file, not its name).
func fb1Deb(t *testing.T, dir, pkg, ver, arch, payload string) (path, sum string) {
	t.Helper()
	if _, err := exec.LookPath("dpkg-deb"); err != nil {
		t.Skip("dpkg-deb not available")
	}
	root := filepath.Join(t.TempDir(), "pkg")
	// dpkg-deb requires a 0755..0775 control directory.
	if err := os.MkdirAll(filepath.Join(root, "DEBIAN"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "DEBIAN"), 0o755); err != nil { //nolint:gosec // dpkg-deb's required mode
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr", "share", "doc"), 0o750); err != nil {
		t.Fatal(err)
	}
	control := fmt.Sprintf("Package: %s\nVersion: %s\nArchitecture: %s\nMaintainer: test <t@example.invalid>\nDescription: fb1 fixture\n", pkg, ver, arch)
	if err := os.WriteFile(filepath.Join(root, "DEBIAN", "control"), []byte(control), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr", "share", "doc", pkg), []byte(payload), 0o600); err != nil {
		t.Fatal(err)
	}
	path = filepath.Join(dir, "x_"+pkg+".deb")                                                               // deliberately not the canonical name
	cmd := exec.CommandContext(t.Context(), "dpkg-deb", "--root-owner-group", "-Zxz", "--build", root, path) //nolint:gosec // test-owned paths
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("dpkg-deb: %v %s", err, out)
	}
	b, err := os.ReadFile(path) //nolint:gosec // test-owned path
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(b)
	return path, hex.EncodeToString(h[:])
}

// The guest-side half of the byte binding: the receipt records what the
// files are, and the Docker check refuses anything but the reviewed bytes.
func TestAptSnapshotFB1_GuestReceiptAndDockerByteCheck(t *testing.T) {
	m := fb1ManifestVars(t)
	cache := t.TempDir()
	type deb struct{ name, verVar, shaVar string }
	debs := []deb{{"docker-ce", "DOCKER_CE_VERSION", "DOCKER_CE_DEB_SHA256"}, {"docker-ce-cli", "DOCKER_CE_CLI_VERSION", "DOCKER_CE_CLI_DEB_SHA256"},
		{"containerd.io", "CONTAINERD_IO_VERSION", "CONTAINERD_IO_DEB_SHA256"}, {"docker-compose-plugin", "DOCKER_COMPOSE_PLUGIN_VERSION", "DOCKER_COMPOSE_PLUGIN_DEB_SHA256"}}
	env := []string{"C=" + cache, "R=" + filepath.Join(t.TempDir(), "acquired-debs.tsv")}
	for _, d := range debs {
		_, sum := fb1Deb(t, cache, d.name, m[d.verVar], "amd64", "payload "+d.name)
		env = append(env, d.verVar+"="+m[d.verVar], d.shaVar+"="+sum) // pins = these fixture bytes
	}
	_, other := fb1Deb(t, cache, "pigz", "2.8-1", "amd64", "pigz")
	out, err := fb1Bash(t, env, `apt_snap_acquisition_receipt "$C" "$R" && apt_snap_verify_docker_debs "$R" && cat "$R"`)
	if err != nil {
		t.Fatalf("receipt/check on the pinned bytes failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "pigz\t2.8-1\tamd64\t"+other+"\tx_pigz.deb") || strings.Count(out, "\n") != 5 {
		t.Errorf("receipt rows (fields from the .deb, hash of the bytes):\n%s", out)
	}
	// Same name/version/arch, different bytes: refused.
	envBad := append(slices.Clone(env), "CONTAINERD_IO_DEB_SHA256="+strings.Repeat("f", 64))
	if out, err := fb1Bash(t, envBad, `apt_snap_acquisition_receipt "$C" "$R" && apt_snap_verify_docker_debs "$R"`); err == nil ||
		!strings.Contains(out, "containerd.io "+m["CONTAINERD_IO_VERSION"]+": acquired .deb is") {
		t.Errorf("different bytes for a pinned Docker package were accepted: %v\n%s", err, out)
	}
	// A different version than the pin: refused.
	envVer := append(slices.Clone(env), "DOCKER_CE_VERSION=5:29.9.1-1~ubuntu.24.04~noble")
	if out, err := fb1Bash(t, envVer, `apt_snap_acquisition_receipt "$C" "$R" && apt_snap_verify_docker_debs "$R"`); err == nil ||
		!strings.Contains(out, "docker-ce: acquired "+m["DOCKER_CE_VERSION"]+" amd64, manifest pins 5:29.9.1") {
		t.Errorf("a Docker version off its pin was accepted: %v\n%s", err, out)
	}
	// Missing, and duplicated: refused.
	if err := os.Remove(filepath.Join(cache, "x_docker-compose-plugin.deb")); err != nil {
		t.Fatal(err)
	}
	if out, err := fb1Bash(t, env, `apt_snap_acquisition_receipt "$C" "$R" && apt_snap_verify_docker_debs "$R"`); err == nil ||
		!strings.Contains(out, "docker-compose-plugin: expected exactly one acquired .deb, receipt has: none") {
		t.Errorf("a missing Docker .deb was accepted: %v\n%s", err, out)
	}
	fb1Deb(t, cache, "docker-compose-plugin", m["DOCKER_COMPOSE_PLUGIN_VERSION"], "amd64", "payload docker-compose-plugin")
	dup := filepath.Join(cache, "y_docker-compose-plugin.deb")
	b, err := os.ReadFile(filepath.Join(cache, "x_docker-compose-plugin.deb"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dup, b, 0o600); err != nil { //nolint:gosec // G703: test-chosen path under t.TempDir()
		t.Fatal("could not duplicate the .deb")
	}
	if out, err := fb1Bash(t, env, `apt_snap_acquisition_receipt "$C" "$R" && apt_snap_verify_docker_debs "$R"`); err == nil ||
		!strings.Contains(out, "docker-compose-plugin: expected exactly one acquired .deb") {
		t.Errorf("a duplicated Docker .deb was accepted: %v\n%s", err, out)
	}
	// An empty cache is not a receipt.
	if out, err := fb1Bash(t, []string{"C=" + t.TempDir(), "R=" + filepath.Join(t.TempDir(), "r")}, `apt_snap_acquisition_receipt "$C" "$R"`); err == nil {
		t.Errorf("an empty package cache produced a receipt: %s", out)
	}
}

const fb1SelectionEvidence = "docs/appliance/evidence/combined/future-build/fb1-snapshot-20261029"

// The manifest pin is the one the selection evidence authenticated, that
// evidence equals the indexes the approved kernel-42 transaction used, and
// the committed 325c comparison has no downgrade, unknown origin or Docker
// change, and resolves exactly the approved kernel.
func TestAptSnapshotFB1_SelectedSnapshotMatchesItsEvidence(t *testing.T) {
	m := fb1ManifestVars(t)
	suiteVar := map[string]string{"noble": "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE", "noble-updates": "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_UPDATES",
		"noble-security": "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY", "noble-backports": "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_BACKPORTS"}
	seen := 0
	for _, l := range strings.Split(strings.TrimSpace(fb1Read(t, filepath.Join(fb1SelectionEvidence, "authn.tsv"))), "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 5 || suiteVar[f[0]] == "" {
			t.Fatalf("authn.tsv row %q", l)
		}
		seen++
		if m[suiteVar[f[0]]] != f[1] || f[2] != "fetch2=identical" || !strings.Contains(f[3], "Good signature") ||
			!strings.HasSuffix(f[4], "F6ECB3762474EDA9D21B7022871920D1991BC93C") {
			t.Errorf("%s: manifest %s, evidence %q", f[0], m[suiteVar[f[0]]], l)
		}
	}
	if seen != 4 {
		t.Errorf("authn.tsv covers %d suites, want 4", seen)
	}
	k42 := fb1Read(t, "docs/appliance/evidence/combined/esxi-325c142a/kernel-42/apt-indexes.txt")
	for _, v := range suiteVar {
		if !strings.Contains(k42, "sha256="+m[v]) {
			t.Errorf("%s=%s is not an index the approved kernel-42 transaction used", v, m[v])
		}
	}
	rows := strings.Split(strings.TrimSpace(fb1Read(t, filepath.Join(fb1SelectionEvidence, "compare-325c142a.tsv"))), "\n")
	classes := map[string]int{}
	for _, l := range rows[1:] {
		f := strings.Split(l, "\t")
		classes[f[4]]++
		switch f[4] {
		case "unchanged", "docker-pinned":
			if f[2] != f[3] {
				t.Errorf("%s classed %s but %s -> %s", f[0], f[4], f[2], f[3])
			}
		case "upgrade":
			if f[0] != "linux-image-virtual-hwe-24.04" || f[3] != "7.0.0-42.42~24.04.1" {
				t.Errorf("unexpected upgrade %q (only the approved kernel transition may move)", l)
			}
		case "added":
			if !strings.Contains(f[0], "7.0.0-42-generic") || f[3] != "7.0.0-42.42~24.04.1" {
				t.Errorf("unexpected addition %q", l)
			}
		case "removed-kernel":
			if !strings.Contains(f[0], "7.0.0-38-generic") {
				t.Errorf("unexpected removal %q", l)
			}
		default:
			t.Errorf("conflict row %q", l)
		}
	}
	if len(rows)-1 != 684 || classes["unchanged"] != 671 || classes["docker-pinned"] != 4 || classes["upgrade"] != 1 ||
		classes["added"] != 4 || classes["removed-kernel"] != 4 {
		t.Errorf("comparison classes %v over %d rows", classes, len(rows)-1)
	}
}
