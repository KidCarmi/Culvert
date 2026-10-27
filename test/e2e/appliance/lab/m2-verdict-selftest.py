#!/usr/bin/env python3
"""m2-verdict-selftest.py — focused receipts that m2-verdict.py fails closed.

Starts from m2-fixtures/pass.txt (which must PASS every check), then applies
one mutation at a time and requires the named check to FAIL with the named
reason. Valid-empty cases must still PASS. Prints one line per case; exits 1
if any expectation is not met. Run by `appliance-lab.sh selftest`.
"""
import importlib.util
import json
import os
import re
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("m2v", os.path.join(HERE, "m2-verdict.py"))
m2v = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m2v)
BASE = open(os.path.join(HERE, "m2-fixtures", "pass.txt")).read().split("\n")


def replace_obs(lines, ctx, name, rc, body, err=()):
    """Replace one observation record (header + its out/err lines)."""
    out, skip, done = [], False, False
    hdr = re.compile(r"^m2-obs %s %s rc=" % (re.escape(ctx), re.escape(name)))
    for l in lines:
        if hdr.match(l):
            out.append("m2-obs %s %s rc=%d lines=%d" % (ctx, name, rc, len(body)))
            out += ["m2-out %s %s| %s" % (ctx, name, b) for b in body]
            out += ["m2-err %s %s| %s" % (ctx, name, e) for e in err]
            skip, done = True, True
            continue
        if skip and re.match(r"^m2-(out|err) %s %s\|" % (re.escape(ctx), re.escape(name)), l):
            continue
        skip = False
        out.append(l)
    assert done, (ctx, name)
    return out


def body_of(lines, ctx, name):
    p = "m2-out %s %s| " % (ctx, name)
    return [l[len(p):] for l in lines if l.startswith(p)]


def with_json(lines, ctx, f):
    d = json.loads(body_of(lines, ctx, "nft-json")[0])
    f(d["nftables"])
    return replace_obs(lines, ctx, "nft-json", 0, [json.dumps(d, separators=(",", ":"))])


def add_rule(expr):
    def f(items):
        items.append({"rule": {"family": "ip6", "table": "filter", "chain": "FORWARD", "handle": 999, "expr": expr}})
    return f


def sub(lines, pat, rep, count=1):
    s = "\n".join(lines)
    n = len(re.findall(pat, s, flags=re.M))
    assert n >= 1, pat
    return re.sub(pat, rep, s, count=count, flags=re.M).split("\n")


def drop_records(lines, ctx, names):
    """Remove whole observation records, as the guest does when it never
    acquired a context (no header, no out/err lines)."""
    pat = re.compile(r"^m2-(obs %s (%s) rc=|(out|err) %s (%s)\|)" % (
        re.escape(ctx), "|".join(names), re.escape(ctx), "|".join(names)))
    return [l for l in lines if not pat.match(l)]


def netns(lines, add=(), drop_ns=None, summary=None):
    """Rebuild the namespace census: base per-process lines minus `drop_ns`,
    plus `add`, with a summary recomputed from the lines unless given."""
    body = [b for b in body_of(lines, "host", "netns-census") if not b.startswith("summary ")]
    body = [b for b in body if drop_ns is None or b.split()[1] != drop_ns] + list(add)
    if summary is None:
        n = {k: sum(1 for b in body if b.split()[0] == k) for k in ("ns", "unreadable-alive", "exited")}
        summary = "summary procs=%d read=%d unreadable_alive=%d exited=%d" % (
            sum(n.values()), n["ns"], n["unreadable-alive"], n["exited"])
    return replace_obs(lines, "host", "netns-census", 0, body + ([summary] if summary else []))


def fds(items, procs=88, fds=256, **over):
    """A descriptor census with its summary recomputed from `items`;
    keyword overrides falsify single counters (or drop them with None)."""
    kind = {"rings": "ring", "unreadable_alive": "unreadable-alive", "exited": "exited",
            "fd_vanished": "fd-vanished", "fd_unreadable": "fd-unreadable"}
    kv = {"procs": procs, "fds": fds}
    kv.update({k: sum(1 for i in items if i.split()[0] == v) for k, v in kind.items()})
    kv.update(over)
    summ = "summary " + " ".join("%s=%s" % (k, v) for k, v in kv.items() if v is not None)
    return replace_obs(BASE, "host", "io_uring-fds", 0, list(items) + [summ])


def top_with(lines, ctx, extra_pids=(), outcome_lines=()):
    """Add pids to the recorded docker top and outcome lines after it."""
    body = body_of(lines, ctx, "top") + [str(p) for p in extra_pids]
    out = replace_obs(lines, ctx, "top", 0, body)
    i = max(k for k, l in enumerate(out) if l.startswith("m2-out %s top| " % ctx))
    return out[:i + 1] + list(outcome_lines) + out[i + 1:]


B = BASE
CASES = [
    # (name, mutated transcript, gpriv rc, check suffix that must fail (None = all pass), reason substring)
    ("baseline passes", B, 0, None, ""),
    ("valid empty: container ruleset with no tables", with_json(B, "culvert", lambda it: it.__setitem__(slice(1, None), [])), 0, None, ""),
    ("valid empty: container IPv6 route table empty", replace_obs(B, "culvert", "routes6", 0, []), 0, None, ""),
    ("transport rc!=0", B, 1, "transcript", "transport rc=1"),
    ("transcript truncated (no m2-end)", [l for l in B if l != "m2-end"], 0, "transcript", "no m2-end"),
    ("record truncated (line count mismatch)", sub(B, r"^(m2-obs host links rc=0 lines=)(\d+)$", r"\g<1>99"), 0, "preconditions", "lines recorded"),
    ("ip link fails", replace_obs(B, "host", "links", 1, [], ["Cannot open netlink socket"]), 0, "preconditions", "host links: rc=1"),
    ("ip link rc=0 but empty", replace_obs(B, "host", "links", 0, []), 0, "preconditions", "no loopback"),
    ("ip -4 route fails", replace_obs(B, "culvert", "routes4", 2, []), 0, "preconditions", "culvert routes4: rc=2"),
    ("ip -4 route rc=0 but empty", replace_obs(B, "host", "routes4", 0, []), 0, "preconditions", "no loopback local route"),
    ("ip -6 route fails", replace_obs(B, "host", "routes6", 255, [], ["RTNETLINK answers: error"]), 0, "preconditions", "host routes6: rc=255"),
    ("encap route present", replace_obs(B, "host", "routes6", 0, ["2001:db8::/64  encap seg6 mode encap segs 1 [ 2001:db8::1 ] dev ens4 metric 1024"]), 0, "preconditions", "encap route"),
    ("VLAN link present", replace_obs(B, "host", "links", 0, body_of(B, "host", "links") + ["9: ens4.10@ens4: <BROADCAST> mtu 1500 qdisc noqueue \\    link/ether 00:11:22:33:44:55 brd ff:ff:ff:ff:ff:ff promiscuity 0 \\    vlan protocol 802.1Q id 10 <REORDER_HDR>"]), 0, "preconditions", "VLAN link"),
    ("tc fails", replace_obs(B, "culvert-clamav", "qdisc", 1, []), 0, "preconditions", "culvert-clamav qdisc: rc=1"),
    ("taprio qdisc present", replace_obs(B, "host", "qdisc", 0, body_of(B, "host", "qdisc") + ["qdisc taprio 8001: dev ens4 root refcnt 2"]), 0, "preconditions", "qdisc taprio"),
    ("module read fails", replace_obs(B, "host", "modules", 1, [], ["cat: /proc/modules: Permission denied"]), 0, "preconditions", "host modules: rc=1"),
    ("module read empty", replace_obs(B, "host", "modules", 0, []), 0, "preconditions", "lacks nf_tables"),
    ("precondition module loaded", replace_obs(B, "host", "modules", 0, body_of(B, "host", "modules") + ["act_ct 36864 0 - Live 0x0"]), 0, "preconditions", "act_ct"),
    # ── namespace census: per-process outcomes, reconciled with the three
    # separately acquired contexts (the census lines are synthetic edits of the
    # real fixture; the pid numbers are invented) ──
    ("netns census fails", replace_obs(B, "host", "netns-census", 1, []), 0, "preconditions", "netns-census: rc=1"),
    ("netns: extra namespace", netns(B, add=["ns net:[4026599999] 4242"]), 0, "preconditions", "outside the three contexts"),
    ("netns: live process unreadable", netns(B, add=["unreadable-alive 4243 runc"]), 0, "preconditions", "unreadable for a live process"),
    ("netns: expected context missing", netns(B, drop_ns="net:[4026532268]"), 0, "preconditions", "absent from the census: culvert=net:[4026532268]"),
    ("netns: valid disappearance (exited)", netns(B, add=["exited 4244", "exited 4245"]), 0, None, ""),
    ("netns: exited line not counted", netns(B, add=["exited 4244"], summary="summary procs=88 read=88 unreadable_alive=0 exited=0"), 0, "preconditions", "lines and summary disagree"),
    ("netns: summary missing a counter", netns(B, summary="summary procs=88 read=88 exited=0"), 0, "preconditions", "summary counters"),
    ("netns: no summary", netns(B, summary=""), 0, "preconditions", "no summary"),
    ("netns: unrecognised line (old format)", netns(B, add=["net:[4026531833] 4246"]), 0, "preconditions", "unrecognised line"),
    ("netns: container context not acquired", drop_records(replace_obs(B, "culvert", "pid", 1, [], ["Error: No such object: culvert"]), "culvert", ["netns", "links", "routes4", "routes6", "qdisc", "nft-json", "nft-text", "ipv6-conf"]), 0, "preconditions", "only 2 of 3 context namespaces acquired"),
    ("IPv6 forwarding on an interface", sub(B, r"^(m2-out culvert ipv6-conf\| eth0 forwarding=)0", r"\g<1>1"), 0, "preconditions", "forwarding=1"),
    ("ipv6-conf unreadable", replace_obs(B, "host", "ipv6-conf", 3, []), 0, "preconditions", "host ipv6-conf: rc=3"),
    ("ipv6-conf value missing", sub(B, r"^(m2-out host ipv6-conf\| all forwarding=)0", r"\g<1>"), 0, "preconditions", "unparseable"),
    ("NIC outside e1000/vmxnet3", replace_obs(B, "host", "nics", 0, ["/sys/class/net/ens4 i40e"]), 0, "preconditions", "i40e"),
    ("nft fails (installed)", replace_obs(B, "host", "nft-json", 1, [], ["netlink: Error: cache initialization failed"]), 0, "ruleset", "host nft-json: host nft-json: rc=1"),
    ("nft absent", replace_obs(B, "culvert", "nft-json", 127, [], ["nsenter: failed to execute nft: No such file or directory"]), 0, "ruleset", "rc=127"),
    ("nft error text on stdout", replace_obs(B, "host", "nft-json", 0, ["Error: Could not process rule: Operation not permitted"]), 0, "ruleset", "host nft-json"),
    ("ruleset is not the host's (no inet culvert)", with_json(B, "host", lambda it: it.__setitem__(slice(None), [x for x in it if not ("table" in x and x["table"]["name"] == "culvert") and not (any(k in x for k in ("chain", "rule")) and list(x.values())[0].get("table") == "culvert")])), 0, "ruleset", "lacks the appliance"),
    ("payload write (mangle th)", with_json(B, "host", add_rule([{"mangle": {"key": {"payload": {"protocol": "th", "field": "dport"}}, "value": 80}}])), 0, "ruleset", "non-metadata write"),
    ("payload write at raw offset", with_json(B, "host", add_rule([{"mangle": {"key": {"payload": {"base": "th", "offset": 16, "len": 16}}, "value": 0}}])), 0, "ruleset", "non-metadata write"),
    ("NFQUEUE statement", with_json(B, "host", add_rule([{"queue": {"num": 0}}])), 0, "ruleset", "unclassified statement queue"),
    ("exthdr match", with_json(B, "host", add_rule([{"match": {"op": "==", "left": {"exthdr": {"name": "rt", "field": "type"}}, "right": 4}}])), 0, "ruleset", "match.left: unreviewed expression exthdr"),
    ("socket match", with_json(B, "host", add_rule([{"match": {"op": "==", "left": {"socket": {"key": "transparent"}}, "right": 1}}])), 0, "ruleset", "match.left: unreviewed expression socket"),
    ("xt TPROXY target", with_json(B, "host", add_rule([{"xt": {"type": "target", "name": "TPROXY"}}])), 0, "ruleset", "xt target TPROXY"),
    ("flowtable object", with_json(B, "host", lambda it: it.append({"flowtable": {"family": "inet", "table": "x", "name": "ft"}})), 0, "ruleset", "flowtable ft"),
    # ── nested operands: the "ok" cases and the socket/jhash/numgen cases are REAL
    # nft -j output (m2-fixtures/nested-nft.txt); the rest are synthetic shapes. ──
    ("nested ok: dnat to 10.0.0.1:8080", with_json(B, "host", add_rule([{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}}, "right": 80}}, {"dnat": {"addr": "10.0.0.1", "port": 8080}}])), 0, None, ""),
    ("nested ok: dnat to tcp dport map", with_json(B, "host", add_rule([{"dnat": {"addr": {"map": {"key": {"payload": {"protocol": "tcp", "field": "dport"}}, "data": {"set": [[80, "10.0.0.2"], [443, "10.0.0.3"]]}}}}}])), 0, None, ""),
    ("nested ok: dnat to 10.0.0.0/24", with_json(B, "host", add_rule([{"dnat": {"addr": {"prefix": {"addr": "10.0.0.0", "len": 24}}}}])), 0, None, ""),
    ("nested ok: snat to ip saddr map", with_json(B, "host", add_rule([{"snat": {"addr": {"map": {"key": {"payload": {"protocol": "ip", "field": "saddr"}}, "data": {"set": [["10.0.0.1", "1.2.3.4"]]}}}}}])), 0, None, ""),
    ("nested ok: meta mark set tcp dport", with_json(B, "host", add_rule([{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"payload": {"protocol": "tcp", "field": "dport"}}}}])), 0, None, ""),
    ("nested ok: ct mark set meta mark", with_json(B, "host", add_rule([{"mangle": {"key": {"ct": {"key": "mark"}}, "value": {"meta": {"key": "mark"}}}}])), 0, None, ""),
    ("nested: ct mark set socket mark", with_json(B, "host", add_rule([{"mangle": {"key": {"ct": {"key": "mark"}}, "value": {"socket": {"key": "mark"}}}}])), 0, "ruleset", "mangle.value: unreviewed expression socket"),
    ("nested: meta mark set jhash ip saddr", with_json(B, "host", add_rule([{"mangle": {"key": {"meta": {"key": "mark"}}, "value": {"jhash": {"mod": 4, "expr": {"payload": {"protocol": "ip", "field": "saddr"}}}}}}])), 0, "ruleset", "mangle.value: unreviewed expression jhash"),
    ("nested: dnat to socket mark map", with_json(B, "host", add_rule([{"dnat": {"addr": {"map": {"key": {"socket": {"key": "mark"}}, "data": {"set": [[1, "10.0.0.1"]]}}}}}])), 0, "ruleset", "dnat.addr.map.key: unreviewed expression socket"),
    ("nested: dnat to numgen map", with_json(B, "host", add_rule([{"dnat": {"addr": {"map": {"key": {"numgen": {"mode": "inc", "mod": 2, "offset": 0}}, "data": {"set": [[0, "10.0.0.1"], [1, "10.0.0.2"]]}}}}}])), 0, "ruleset", "dnat.addr.map.key: unreviewed expression numgen"),
    ("nested: exthdr inside a map's data set", with_json(B, "host", add_rule([{"dnat": {"addr": {"map": {"key": {"meta": {"key": "mark"}}, "data": {"set": [[1, {"exthdr": {"name": "frag", "field": "id"}}]]}}}}}])), 0, "ruleset", "unreviewed expression exthdr"),
    ("nested: unknown NAT parameter", with_json(B, "host", add_rule([{"dnat": {"addr": "10.0.0.1", "proto": {"socket": {"key": "mark"}}}}])), 0, "ruleset", "dnat with unexpected parameters"),
    ("nested: unknown payload field", with_json(B, "host", add_rule([{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport", "inner": {"exthdr": {}}}}, "right": 1}}])), 0, "ruleset", "unexpected fields"),
    ("nested: expression in a counter parameter", with_json(B, "host", add_rule([{"counter": {"packets": {"socket": {"key": "mark"}}, "bytes": 0}}])), 0, "ruleset", "non-literal parameter"),
    ("nested: unknown log parameter", with_json(B, "host", add_rule([{"log": {"prefix": "x", "mystery": 1}}])), 0, "ruleset", "unexpected parameters"),
    ("nested: two-key operand object", with_json(B, "host", add_rule([{"match": {"op": "==", "left": {"payload": {"protocol": "tcp", "field": "dport"}, "socket": {"key": "mark"}}, "right": 1}}])), 0, "ruleset", "unrecognised operand"),
    ("io_uring_disabled not 2", sub(B, r"^(m2-obs host sysctl rc=0 lines=3\nm2-out host sysctl\| )2", r"\g<1>1"), 0, "hardening", "io_uring_disabled=1"),
    ("sysctl read fails", replace_obs(B, "host", "sysctl", 255, []), 0, "hardening", "host sysctl: rc=255"),
    ("host io_uring_setup opens", replace_obs(B, "host", "io_uring-setup", 0, ["opened"]), 0, "hardening", "io_uring_setup"),
    # ── descriptor census (synthetic lines; real summary shape) ──
    ("fd: ring held", fds(["ring 1234 dockerd /proc/1234/fd/9"]), 0, "hardening", "rings held"),
    ("fd: fd dir unreadable, process alive", fds(["unreadable-alive 777 containerd"]), 0, "hardening", "fd directory unreadable for a live process"),
    ("fd: descriptor present but unreadable", fds(["fd-unreadable 1 21 systemd"]), 0, "hardening", "descriptor still present but unreadable"),
    ("fd: valid disappearance (exited + fd-vanished)", fds(["exited 4250", "fd-vanished 4251 7"]), 0, None, ""),
    ("fd: census read nothing", fds([], procs=0, fds=0), 0, "hardening", "read nothing"),
    ("fd: unreadable line not counted", fds(["fd-unreadable 1 21 systemd"], fd_unreadable=0), 0, "hardening", "1 fd-unreadable lines, summary says 0"),
    ("fd: summary missing a counter (old format)", fds([], fd_unreadable=None), 0, "hardening", "summary counters"),
    ("fd: unrecognised line", fds(["mystery 1"]), 0, "hardening", "unrecognised line"),
    ("fd census failed", replace_obs(B, "host", "io_uring-fds", 1, []), 0, "hardening", "io_uring census"),
    ("probe: AF_PACKET opens as root", sub(B, r"^(m2-probe culvert-clamav as=root rc=)0( uid=0 afpacket=)errno:EPERM", r"\g<1>1\g<2>opened"), 0, "hardening", "probe culvert-clamav as=root"),
    ("probe not run", [l for l in B if not l.startswith("m2-probe culvert as=default ")], 0, "hardening", "probe culvert as=default: not run"),
    ("process keeps NET_RAW", sub(B, r"^(m2-proc culvert-clamav .*netraw-eff=)0 netraw-bnd=0", r"\g<1>1 netraw-bnd=1"), 0, "hardening", "netraw-eff=1"),
    # ── container processes: every pid in the recorded docker top has one outcome ──
    ("top fails", replace_obs(B, "culvert", "top", 1, [], ["Error response from daemon: container is not running"]), 0, "hardening", "culvert top: rc=1"),
    ("top non-numeric pid", replace_obs(B, "culvert", "top", 0, ["PID", "abc"]), 0, "hardening", "non-numeric pid"),
    ("process status unreadable, alive", top_with(B, "culvert", [4260], ["m2-proc-unreadable culvert 4260"]), 0, "hardening", "m2-proc-unreadable culvert 4260"),
    ("process exited before its read (valid)", top_with(B, "culvert", [4261], ["m2-proc-exited culvert 4261"]), 0, None, ""),
    ("listed pid with no outcome", top_with(B, "culvert", [4262]), 0, "hardening", "pid 4262 from docker top has no outcome"),
    ("pid read but not listed", top_with(B, "culvert", [], ["m2-proc-exited culvert 4263"]), 0, "hardening", "4263 read but not in the recorded docker top"),
    ("pid with two outcomes", top_with(B, "culvert", [4264], ["m2-proc-exited culvert 4264", "m2-proc-unreadable culvert 4264"]), 0, "hardening", "pid 4264 from docker top has"),
    ("no container process read", [l for l in B if not l.startswith("m2-proc culvert ")], 0, "hardening", "no process of culvert read"),
    ("ordering: sysctl after containerd", sub(B, r"^m2-out host ordering\| ActiveEnterTimestampMonotonic=4512338$", "m2-out host ordering| ActiveEnterTimestampMonotonic=9999999"), 0, "ordering", "systemd-sysctl active"),
    ("ordering read fails", replace_obs(B, "host", "ordering", 1, []), 0, "ordering", "host ordering: rc=1"),
    ("sysctl drop-in missing", replace_obs(B, "host", "sysctl-file", 1, [], ["sha256sum: no such file"]), 0, "ordering", "sysctl-file: rc=1"),
    ("EICAR scan error", replace_obs(B, "clamav", "eicar", 2, ["ERROR: Could not connect to clamd"]), 0, "clamav", "clamav eicar: rc=2"),
    ("EICAR clean", replace_obs(B, "clamav", "eicar", 0, ["stream: OK"]), 0, "clamav", "clamav eicar: rc=0"),
]


def main():
    bad = 0
    for name, lines, rc, must_fail, why in CASES:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as t:
            t.write("\n".join(lines) + "\n")
        res = m2v.run(t.name, "t", rc)
        os.unlink(t.name)
        fails = {n.split("-", 1)[1]: d for st, n, d in res if st == "fail"}
        if must_fail is None:
            ok = not fails
            got = "all pass" if ok else "unexpected fail: %s" % fails
        else:
            ok = must_fail in fails and why in fails[must_fail]
            got = ("%s fails: %s" % (must_fail, fails.get(must_fail, "")[:150])) if must_fail in fails else "did NOT fail %s (fails: %s)" % (must_fail, sorted(fails))
        bad += not ok
        print("%s\t%s\t%s" % ("ok" if ok else "WRONG", name, got))
    print("%d cases, %d wrong" % (len(CASES), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
