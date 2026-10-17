"""Per-phase engine/stack recovery split from an already-captured recovery_guest
dump, in the SAME boundaries ASTRA measured on real ESXi (PR #1528). It only
re-reads that file; it collects nothing new and runs offline.

    recovery-engine-phases.py GUEST.txt [GUEST.txt ...]

Durations are parsed with full `Nh Nmin N.Ns` / `Nms` support (systemd prints
minutes once a phase crosses 60 s — the earlier seconds-only parse dropped the
userspace figure at high latency). Service boundaries come from the MONOTONIC
unit timestamps (ExecMainStart/ActiveEnter/ExecMainExit, µs since kernel start),
not from `blame` — `blame` is wall-duration per unit and can double-count
parallel work; the monotonic stamps place each service on the real timeline.

What this does NOT claim: these are elapsed intervals, not isolated read cost.
Read and write latency both change between profiles unless the profile holds one
fixed; CPU, scheduling and metadata work also land in elapsed time. Use the
read/write-isolation profiles (r*w* in the recovery-ab job) and the boot-I/O
sampler to attribute cost — this table is the timeline, not the attribution.

Columns (seconds unless noted; '.' when the source line is absent):
  file
  kernel_s            `Startup finished in N (kernel)`      (firmware/loader excluded)
  userspace_s         `+ N (userspace)`                     (kernel start -> graphical.target)
  apparmor_s dbus_s   apparmor.service / dbus.service        (blame)
  containerd_at_s     containerd ExecMainStart               (monotonic, s since kernel)
  containerd_span_s   containerd ExecMainStart -> ActiveEnter
  ctrd_meta_gap_s     containerd "metadata content store policy set" -> next "loading plugin"
  docker_at_s         docker ExecMainStart                   (monotonic)
  docker_span_s       docker ExecMainStart -> ActiveEnter
  stack_at_s          culvert-stack-resume ExecMainStart     (monotonic)
  stack_span_s        culvert-stack-resume ExecMainStart -> ExecMainExit (oneshot)
  uefi_fsck_s boot_fsck_s  UEFI and BOOT systemd-fsck, REPORTED SEPARATELY
                      (they run concurrently; do NOT add them — root fsck is
                       condition-skipped, so neither is the 141 s cause)
  ctrd_read_mib       containerd.service IOReadBytes          (attributed total, NOT a per-phase proof)
  docker_read_mib     docker.service IOReadBytes
"""
import re
import sys

MONO = re.compile(r"^\[\s*([0-9]+\.[0-9]+)\]")
DUR = re.compile(r"([0-9.]+)(h|min|ms|s)")


def parse_dur(tok):
    """'1min 6.363s' -> 66.363; '578ms' -> 0.578; '26.691s' -> 26.691."""
    total = 0.0
    found = False
    for m in DUR.finditer(tok):
        v = float(m.group(1))
        u = m.group(2)
        total += v * 3600 if u == "h" else v * 60 if u == "min" else v / 1000 if u == "ms" else v
        found = True
    return total if found else None


def blame(lines, unit):
    # "15.618s culvert-stack-resume.service" / "578ms dbus.service" / "1min 3s foo".
    pat = re.compile(r"\s*(.+?)\s+" + re.escape(unit) + r"\s*$")
    for ln in lines:
        m = pat.match(ln)
        if m:
            return parse_dur(m.group(1))
    return None


def startup_split(lines):
    for ln in lines:
        m = re.search(r"Startup finished in (.+?) \(kernel\) \+ (.+?) \(userspace\)", ln)
        if m:
            return parse_dur(m.group(1)), parse_dur(m.group(2))
    return None, None


def mono(lines, unit_id, field):
    # unit-timestamps line: "ExecMainStart...=N ExecMainExit...=N Id=<id>.service ActiveEnter...=N"
    for ln in lines:
        if "Id=" + unit_id + ".service" in ln:
            m = re.search(field + r"=([0-9]+)", ln)
            if m:
                us = int(m.group(1))
                return us / 1e6 if us > 0 else None
    return None


def containerd_metadata_gap(lines):
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


def span(lines, unit_id, a, b):
    s0 = mono(lines, unit_id, a)
    s1 = mono(lines, unit_id, b)
    return round(s1 - s0, 3) if s0 is not None and s1 is not None else None


def fmt(v, nd=2):
    return "." if v is None else (f"{v:.{nd}f}" if isinstance(v, float) else str(v))


def main(argv):
    cols = ["file", "kernel_s", "userspace_s", "apparmor_s", "dbus_s",
            "containerd_at_s", "containerd_span_s", "ctrd_meta_gap_s",
            "docker_at_s", "docker_span_s", "stack_at_s", "stack_span_s",
            "uefi_fsck_s", "boot_fsck_s", "ctrd_read_mib", "docker_read_mib"]
    print("\t".join(cols))
    for path in argv:
        try:
            lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
        except OSError as e:
            print(f"{path}\tERROR {e}")
            continue
        k, u = startup_split(lines)
        row = [path.split("/")[-1], k, u,
               blame(lines, "apparmor.service"), blame(lines, "dbus.service"),
               mono(lines, "containerd", "ExecMainStartTimestampMonotonic"),
               span(lines, "containerd", "ExecMainStartTimestampMonotonic", "ActiveEnterTimestampMonotonic"),
               containerd_metadata_gap(lines),
               mono(lines, "docker", "ExecMainStartTimestampMonotonic"),
               span(lines, "docker", "ExecMainStartTimestampMonotonic", "ActiveEnterTimestampMonotonic"),
               mono(lines, "culvert-stack-resume", "ExecMainStartTimestampMonotonic"),
               span(lines, "culvert-stack-resume", "ExecMainStartTimestampMonotonic", "ExecMainExitTimestampMonotonic"),
               blame(lines, "systemd-fsck@dev-disk-by\\x2dlabel-UEFI.service"),
               blame(lines, "systemd-fsck@dev-disk-by\\x2dlabel-BOOT.service"),
               unit_read_mib(lines, "containerd.service"),
               unit_read_mib(lines, "docker.service")]
        print("\t".join(fmt(v, 3) for v in row))


if __name__ == "__main__":
    main(sys.argv[1:])
