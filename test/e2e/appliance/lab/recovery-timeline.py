#!/usr/bin/env python3
"""Recovery timeline for one maintenance reboot (appliance-lab.sh recovery).

  recovery-timeline.py T0 KERNEL READY TRAFFIC AV PHASE FIRST_JOINT END \
      DISK0 DISK1 BUDGET ACCEPT_EPOCH ACCEPT_LAG SAMPLES OUT.json
      -> writes OUT.json, prints the recovery seconds or "none"
  recovery-timeline.py --describe OUT.json
      -> one-line summary

All instants are monotonic seconds on the host; T0 is the authenticated
acceptance of the reboot. An empty instant means "never reached".
"""
import json
import sys

NAMES = ["kernel", "first_ready_clamav_ok", "first_traffic_allow_block", "first_eicar_blocked_by_clamav",
         "first_operator_phase_ready", "first_joint_sample", "third_consecutive_joint_sample"]


def build(argv):
    t0 = float(argv[0])
    pts = {n: (round(float(v) - t0, 1) if v else None) for n, v in zip(NAMES, argv[1:8])}
    a = [int(x) for x in argv[8].split()]
    b = [int(x) for x in argv[9].split()]
    d = [y - x for x, y in zip(a, b)]
    out = {
        "t0": "authenticated acceptance (LABACCEPT, host epoch %s; detection-to-t0 lag %ss subtracted)" % (argv[11], argv[12]),
        "seconds_after_acceptance": pts,
        "recovery_seconds": pts["third_consecutive_joint_sample"],
        "budget_seconds": int(argv[10]),
        "joint_samples_taken": int(argv[13]),
        "host_device": {"reads": d[0], "read_mib": round(d[2] * 512 / 1048576, 1), "read_ms": d[3],
                        "writes": d[4], "write_mib": round(d[6] * 512 / 1048576, 1), "write_ms": d[7],
                        "io_ticks_ms": d[9]},
    }
    with open(argv[14], "w") as f:
        json.dump(out, f, indent=1)
    rec = out["recovery_seconds"]
    return "none" if rec is None else str(rec)


def describe(path):
    d = json.load(open(path))
    p, h = d["seconds_after_acceptance"], d["host_device"]
    parts = [f"{k}=+{v}s" if v is not None else f"{k}=never" for k, v in p.items()]
    return " ".join(parts) + f"; samples={d['joint_samples_taken']}; host disk: {h['reads']} reads/{h['read_mib']} MiB, {h['writes']} writes/{h['write_mib']} MiB"


if __name__ == "__main__":
    if sys.argv[1:2] == ["--describe"]:
        print(describe(sys.argv[2]))
    else:
        print(build(sys.argv[1:]))
