package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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

// The reviewed FB-1 §5 values (gpgv-verified, fetched twice byte-identical).
var fb1ReviewedPins = map[string]string{
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE":     "cdb2f31d809f589719a53c6ad15f255b27569c4059542ada282aaa21b8e164b0",
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_UPDATES":   "6e43c5996bd6cf1d1fe7389a3d6ec383761635cdad2dfb58c020bded199235af",
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY":  "3b358f744efb789bab437ac77209ac20be2c8665197ce274f65c5f812bd4d519",
	"GUEST_APT_SNAPSHOT_INRELEASE_SHA256_BACKPORTS": "dc4d31dc0a8897dbecfd0375a4041b4aeb4a6fae00c688cf923daec3c4a258f8",
}

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
		"--with-new-pkgs upgrade",
		`apt_snap -y -qq install --no-install-recommends "$GUEST_KERNEL_META"`,
		`cand="$(apt_cache_snap policy "$meta"`,
		`want_img="$(apt_cache_snap depends "$meta"`,
		"apt_snap -y -qq purge snapd",
		"plymouth plymouth-theme-ubuntu-text plymouth-label fontconfig",
		"apt_snap_sources_restore",
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
		"apt_snap":        {`apt-get "${APT_SNAP_OPTS[@]}" --snapshot "$GUEST_APT_SNAPSHOT" "$@"`},
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
	if m["GUEST_APT_SNAPSHOT"] != "20261002T120000Z" {
		t.Errorf("GUEST_APT_SNAPSHOT=%q: the reviewed pins below belong to 20261002T120000Z", m["GUEST_APT_SNAPSHOT"])
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
	} {
		if !strings.Contains(bo, want) {
			t.Errorf("build-ova.sh lost %q", want)
		}
	}
	for _, pin := range []string{"DOCKER_CE_VERSION", "DOCKER_CE_CLI_VERSION", "CONTAINERD_IO_VERSION", "DOCKER_COMPOSE_PLUGIN_VERSION"} {
		if !strings.Contains(bo, "=$"+pin+`"`) {
			t.Errorf("build-ova.sh does not hand %s to the reconciler", pin)
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

func fb1PinEnv(id string) []string {
	env := []string{"GUEST_APT_SNAPSHOT=" + id}
	for k, v := range fb1ReviewedPins {
		env = append(env, k+"="+v)
	}
	return env
}

func TestAptSnapshotFB1_RequirePinsRefusesBadIDsAndPins(t *testing.T) {
	if out, err := fb1Bash(t, fb1PinEnv("20261002T120000Z"), "apt_snap_require_pins"); err != nil {
		t.Fatalf("valid pins refused: %v %s", err, out)
	}
	for name, env := range map[string][]string{
		"future ID (served as 'now', E6)": fb1PinEnv("20991231T000000Z"),
		"malformed ID":                    fb1PinEnv("2026-10-02"),
		"empty ID":                        fb1PinEnv(""),
		"missing pin":                     append(fb1PinEnv("20261002T120000Z"), "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_SECURITY="),
		"short pin":                       append(fb1PinEnv("20261002T120000Z"), "GUEST_APT_SNAPSHOT_INRELEASE_SHA256_NOBLE=cdb2f31d"),
	} {
		if out, err := fb1Bash(t, env, "apt_snap_require_pins"); err == nil {
			t.Errorf("%s accepted: %s", name, out)
		}
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
	env := append(fb1PinEnv("20261002T120000Z"), "PATH="+bin+":"+os.Getenv("PATH"))
	out, err := fb1Bash(t, env, `apt_snap_update -qq; apt_snap install -y pigz; apt_cache_snap policy systemd`)
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	want := "apt-get --snapshot 20261002T120000Z --error-on=any -qq update\n" +
		"apt-get --snapshot 20261002T120000Z install -y pigz\n" +
		"apt-cache --snapshot 20261002T120000Z policy systemd\n"
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
		fmt.Fprintf(&sb, "Origin: Ubuntu\nSuite: %s\nNote: test fixture; stanzas are real snapshot 20261002T120000Z entries\nSHA256:\n", suite)
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
		"--snapshot-id", "20261002T120000Z", "--docker-dir", ix.dockerDir,
		"--docker-uri", "https://download.docker.com/linux/ubuntu", "--out", out}
	for _, s := range fb1Suites {
		args = append(args, "--pin", s+"="+ix.pins[s])
	}
	pins := map[string]string{
		"docker-ce": m["DOCKER_CE_VERSION"], "docker-ce-cli": m["DOCKER_CE_CLI_VERSION"],
		"containerd.io": m["CONTAINERD_IO_VERSION"], "docker-compose-plugin": m["DOCKER_COMPOSE_PLUGIN_VERSION"],
	}
	for _, kv := range extra {
		k, v, _ := strings.Cut(kv, "=")
		pins[k] = v
	}
	for k, v := range pins {
		args = append(args, "--docker-pin", k+"="+v)
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

var fb1NotInSnapshot = regexp.MustCompile(`(?m)^  package\t(\S+)\t(\S+) \S+ is not in snapshot 20261002T120000Z$`)

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
func TestAptSnapshotFB1_T3b_InSnapshotInventoryPasses(t *testing.T) {
	ix := fb1BuildIndexes(t, nil)
	bad := fb1Recorded57(t)
	var rows []string
	for _, r := range fb1RealInventory(t) {
		f := strings.Split(r, "\t")
		if !bad[f[0]+"\t"+f[1]] {
			rows = append(rows, r)
		}
	}
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
	origins := map[string]int{}
	for _, l := range data {
		f := strings.Split(l, "\t")
		if len(f) != 8 || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(f[7]) || !strings.HasSuffix(f[6], ".deb") {
			t.Fatalf("malformed provenance row: %q", l)
		}
		origins[f[3]]++
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
