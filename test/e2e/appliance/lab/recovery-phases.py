"""Per-phase split of lab recovery timings (R-esxi12-N-timeline.json + console marks).

recovery-phases.py DIR... ; each DIR is an unpacked lab evidence directory.
Phases: shutdown (t0 -> 'reboot: Restarting system'), firmware (-> 'Linux version', no guest code),
kernel -> console banner, console -> first ready+ClamAV ok, ready -> third joint sample.
read_ms/IO and write_ms/IO are the host block device's mean service time per request;
the esxi12 profile injects 12 ms per read and 3 ms per write (dm-delay), the rest is the runner's disk.
"""
import json,sys,os,re
print("run\treboot\trecovery\tshutdown(t0->restart)\tfirmware(restart->kernel)\tkernel->console\tconsole->ready\tready->3rd\tread_ms/IO\twrite_ms/IO\tio_ticks_s\tread_MiB")
for d in sys.argv[1:]:
    for i in (1,2,3):
        t=json.load(open(f"{d}/R-esxi12-{i}-timeline.json")); s=t["seconds_after_acceptance"]; h=t["host_device"]
        m={}
        for l in open(f"{d}/R-esxi12-{i}-console-marks.tsv"):
            ts,msg=l.split("\t",1)
            if "Restarting system" in msg: m.setdefault("restart",float(ts))
            if "Linux version" in msg: m.setdefault("kernel",float(ts))
            if msg.startswith("Culvert appliance ") and "status" not in msg: m.setdefault("console",float(ts))
        print("\t".join(str(x) for x in [d,i,round(t["recovery_seconds"],1),m.get("restart"),round(m["kernel"]-m["restart"],2),round(m["console"]-m["kernel"],2),
            round(s["first_ready_clamav_ok"]-m["console"],1),round(t["recovery_seconds"]-s["first_ready_clamav_ok"],1),
            round(h["read_ms"]/h["reads"],2),round(h["write_ms"]/h["writes"],2),round(h["io_ticks_ms"]/1000,1),h["read_mib"]]))
