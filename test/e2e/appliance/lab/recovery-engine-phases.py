"""Per-phase engine/stack recovery split from an already-captured recovery_guest
dump, in the SAME boundaries ASTRA measured on real ESXi (PR #1528 comment
6230967268 / 5978949299), so a lab run and an ESXi boot are directly comparable.

    recovery-engine-phases.py GUEST.txt [GUEST.txt ...]

Each argument is an `R-<profile>-<n>-guest.txt` produced by recovery_guest in
appliance-lab.sh. Everything here is already in that file — this script only
re-reads it into ASTRA's phase shape; it collects nothing new and runs offline.

Columns (seconds unless noted; '.' when the source line is absent):
  file                the guest.txt
  kernel_s            `Startup finished in N (kernel)`      (firmware/loader excluded — no guest clock there)
  userspace_s        `+ N (userspace)`                      (kernel start -> graphical.target)
  apparmor_s dbus_s   apparmor.service / dbus.service       (blame; the pre-containerd services ASTRA named)
  containerd_s        containerd.service                    (blame)
  ctrd_meta_gap_s     containerd "metadata content store policy set" -> next "loading plugin"
                      (ASTRA's single largest ESXi item: 43.02->54.53 = 11.5 s at ~30-53 ms;
                       expect ~1.3 s at the 12 ms lab profile — a latency-bound read burst)
  docker_s            docker.service                        (blame)
  stack_resume_s      culvert-stack-resume.service          (blame; compose up -> ClamAV ready)
  bootfsck_s          UEFI + BOOT systemd-fsck               (blame; root fsck is condition-skipped — ruled out)
  ctrd_read_mib       containerd.service IOReadBytes         (DefaultIOAccounting, per-unit)
  docker_read_mib     docker.service IOReadBytes

The point is the RATIO across injected latencies: a phase whose seconds grow
with the dm-delay profile is latency-bound (its cost is reads, not CPU); a phase
that stays flat is fixed work. Run the same bytes at esxi12 and esxi30 and read
down each column.
"""
import re
import sys

MONO = re.compile(r"^\[\s*([0-9]+\.[0-9]+)\]")


def blame(lines, unit):
    # blame prints e.g. "15.618s culvert-stack-resume.service" or "578ms dbus.service".
    for ln in lines:
        m = re.match(r"\s*([0-9.]+)(ms|s)\s+" + re.escape(unit) + r"\s*$", ln)
        if m:
            v = float(m.group(1))
            return v / 1000.0 if m.group(2) == "ms" else v
    return None


def startup_split(lines):
    k = u = None
    for ln in lines:
        m = re.search(r"Startup finished in ([0-9.]+)s \(kernel\)", ln)
        if m:
            k = float(m.group(1))
        m = re.search(r"\+ ([0-9.]+)s \(userspace\)", ln)
        if m:
            u = float(m.group(1))
    return k, u


def containerd_metadata_gap(lines):
    # The monotonic ts of "metadata content store policy set", then the ts of
    # the NEXT "loading plugin" line. containerd loads the bolt metadata DB there
    # and the following plugin init is the read burst that blows up under latency.
    meta_ts = None
    for ln in lines:
        m = MONO.match(ln)
        if not m:
            continue
        ts = float(m.group(1))
        if meta_ts is None:
            if "metadata content store policy set" in ln:
                meta_ts = ts
        elif "loading plugin" in ln:
            return round(ts - meta_ts, 3)
    return None


def unit_read_mib(lines, unit):
    for ln in lines:
        if ln.startswith(unit + " ") and "IOReadBytes=" in ln:
            m = re.search(r"IOReadBytes=([0-9]+)", ln)
            if m:
                return round(int(m.group(1)) / 1048576.0, 1)
    return None


def fmt(v, nd=2):
    return "." if v is None else (f"{v:.{nd}f}" if isinstance(v, float) else str(v))


def main(argv):
    cols = ["file", "kernel_s", "userspace_s", "apparmor_s", "dbus_s",
            "containerd_s", "ctrd_meta_gap_s", "docker_s", "stack_resume_s",
            "bootfsck_s", "ctrd_read_mib", "docker_read_mib"]
    print("\t".join(cols))
    for path in argv:
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError as e:
            print(f"{path}\tERROR {e}")
            continue
        k, u = startup_split(lines)
        uefi = blame(lines, "systemd-fsck@dev-disk-by\\x2dlabel-UEFI.service")
        boot = blame(lines, "systemd-fsck@dev-disk-by\\x2dlabel-BOOT.service")
        bootfsck = None if uefi is None and boot is None else (uefi or 0) + (boot or 0)
        row = [path.split("/")[-1], k, u,
               blame(lines, "apparmor.service"), blame(lines, "dbus.service"),
               blame(lines, "containerd.service"), containerd_metadata_gap(lines),
               blame(lines, "docker.service"), blame(lines, "culvert-stack-resume.service"),
               bootfsck, unit_read_mib(lines, "containerd.service"),
               unit_read_mib(lines, "docker.service")]
        print("\t".join(fmt(v) for v in row))


if __name__ == "__main__":
    main(sys.argv[1:])
