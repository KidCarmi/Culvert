#!/usr/bin/env python3
"""m2-verdict.py TRANSCRIPT TAG [GPRIV_RC] — verdicts for one #1528 M2 checkpoint.

Reads the transcript m2-guest.sh produced and prints one line per check:
    <pass|fail><TAB><check name><TAB><detail>

Fail closed: an observation counts only if it was ACQUIRED (an m2-obs record
with the expected exit status) and PARSED (its output has the expected shape,
including a positive control where one exists). An unreadable observation is
reported as such and fails its check; it is never treated as an empty one.
A valid empty result (no VLAN link, no encap route) is a pass only when the
same observation also shows what it must show if the read really worked
(e.g. the loopback interface, the appliance's own firewall table).
"""
import json
import re
import sys

CTXS = ("host", "culvert", "culvert-clamav")
CONTAINERS = ("culvert", "culvert-clamav")
ALLOWED_QDISC = {"fq_codel", "noqueue", "pfifo_fast", "mq", "fq"}
# Modules that call ipv6_find_hdr / skb_checksum_setup, or are needed for a
# precondition (RESIDUAL-DISPOSITION.md §3, §5): none may be loaded.
PRECOND_MODULES = (
    "8021q act_ct act_pedit act_mirred act_skbedit sch_taprio sch_mqprio nf_flow_table "
    "nft_flow_offload nfnetlink_queue openvswitch ip6_tables ip6t_ah ip6t_frag ip6t_hbh "
    "ip6t_rt ip6t_srh nf_socket_ipv6 nft_socket xt_socket xt_TPROXY nft_tproxy xt_HMARK "
    "xt_ipvs xt_l2tp ip_vs ip_vs_pe_sip xen_netback i40e ixgbe mlx5_core nft_exthdr"
).split()

# ── nftables rule classification (the explicit ruleset gate) ───────────────
# Every expression of every rule must be one of these, each with the reason it
# cannot write packet bytes at the transport offset ipv6_find_hdr returns
# (CVE-2026-98532). Anything else is "review required" and fails the gate.
VERDICT_ONLY = {"accept", "drop", "reject", "jump", "goto", "return", "continue",
                "counter", "log", "limit", "notrack", "quota"}
# Matches read packet bytes only through nft_payload_eval -> skb_copy_bits,
# or no packet bytes at all (meta, ct).
MATCH_LEAVES = {"payload", "meta", "ct", "&", "|", "^", "<<", ">>", "concat",
                "set", "range", "prefix", "elem"}
# NAT rewrites go through nf_nat_ipv6_manip_pkt, which finds the L4 header
# itself with ipv6_skip_exthdr (nf_nat_proto.c), not nft's transport offset.
NAT_EXPRS = {"snat", "dnat", "masquerade", "redirect"}
XT_TARGETS = {"MASQUERADE": "nf_nat", "DNAT": "nf_nat", "SNAT": "nf_nat", "REDIRECT": "nf_nat"}
# xt matches: tcp/udp read through skb_header_pointer (xt_tcpudp.c); the
# others read no transport-header bytes.
XT_MATCHES = {"tcp", "udp", "addrtype", "conntrack", "state", "comment", "mark"}
# Mangles of metadata (meta/ct keys) change no packet bytes.
MANGLE_OK_KEYS = {"meta", "ct"}


def leaves(node, out):
    """Collect the expression keys of a match operand. Literal containers
    (prefix, range, elem) hold values, not expressions, and are not walked."""
    if isinstance(node, dict):
        for k, v in node.items():
            out.add(k)
            if k in ("&", "|", "^", "<<", ">>", "concat", "set"):
                leaves(v, out)
    elif isinstance(node, list):
        for v in node:
            leaves(v, out)


def classify_rule_expr(e):
    """None when allowed, else a short reason."""
    if not isinstance(e, dict) or len(e) != 1:
        return "unparseable expression %r" % (e,)
    (k, v), = e.items()
    if k in VERDICT_ONLY:
        return None
    if k == "match":
        ks = set()
        leaves(v.get("left"), ks)
        leaves(v.get("right"), ks)
        bad = sorted(x for x in ks if x not in MATCH_LEAVES)
        return None if not bad else "match reads %s" % ",".join(bad)
    if k in NAT_EXPRS:
        return None
    if k == "xt":
        t, n = v.get("type"), v.get("name")
        if t == "target" and n in XT_TARGETS:
            return None
        if t == "match" and n in XT_MATCHES:
            return None
        return "xt %s %s" % (t, n)
    if k == "mangle":
        key = v.get("key", {})
        kk = set(key) if isinstance(key, dict) else {"?"}
        if kk <= MANGLE_OK_KEYS:
            return None
        return "payload write (mangle %s)" % ",".join(sorted(kk))
    return "unclassified statement %s" % k


def nft_review(doc):
    """(rules, tables, [problems]) or raises ValueError on a malformed document."""
    items = doc["nftables"]
    if not isinstance(items, list) or not items or "metainfo" not in items[0]:
        raise ValueError("no metainfo")
    rules, tables, problems = 0, [], []
    for it in items:
        if "table" in it:
            tables.append("%s %s" % (it["table"]["family"], it["table"]["name"]))
        if "flowtable" in it:
            problems.append("flowtable %s" % it["flowtable"].get("name"))
        if "rule" in it:
            r = it["rule"]
            rules += 1
            for e in r["expr"]:
                why = classify_rule_expr(e)
                if why:
                    problems.append("%s/%s/%s#%s: %s" % (r["family"], r["table"], r["chain"], r.get("handle"), why))
    return rules, tables, problems


# ── transcript ───────────────────────────────────────────────────────────────
def load(path):
    obs, out, err, raw = {}, {}, {}, []
    for line in open(path, encoding="utf-8", errors="replace"):
        line = line.rstrip("\n")
        raw.append(line)
        m = re.match(r"^m2-obs (\S+) (\S+) rc=(-?\d+) lines=(\d+)$", line)
        if m:
            obs[(m.group(1), m.group(2))] = (int(m.group(3)), int(m.group(4)))
            out.setdefault((m.group(1), m.group(2)), [])
            continue
        m = re.match(r"^m2-(out|err) (\S+) (\S+)\| ?(.*)$", line)
        if m:
            (out if m.group(1) == "out" else err).setdefault((m.group(2), m.group(3)), []).append(m.group(4))
    return obs, out, err, raw


class Eval:
    def __init__(self, path):
        self.obs, self.out, self.err, self.raw = load(path)

    def get(self, ctx, name, ok_rc=(0,)):
        """Lines of an acquired observation, or raise Unavailable."""
        if (ctx, name) not in self.obs:
            raise Unavailable("%s %s: not recorded" % (ctx, name))
        rc, n = self.obs[(ctx, name)]
        lines = self.out.get((ctx, name), [])
        if rc not in ok_rc:
            e = " ".join(self.err.get((ctx, name), []))[:160]
            raise Unavailable("%s %s: rc=%d %s" % (ctx, name, rc, e))
        if len(lines) != n:
            raise Unavailable("%s %s: %d lines recorded, %d expected" % (ctx, name, len(lines), n))
        return lines

    def line(self, prefix):
        return [l for l in self.raw if l.startswith(prefix)]


class Unavailable(Exception):
    pass


def run(path, tag, gpriv_rc):
    E = Eval(path)
    res = []

    def report(name, problems, ok_detail):
        if problems:
            res.append(("fail", "%s-%s" % (tag, name), "; ".join(problems)))
        else:
            res.append(("pass", "%s-%s" % (tag, name), ok_detail))

    transport = []
    if gpriv_rc != 0:
        transport.append("console transport rc=%d" % gpriv_rc)
    if not E.line("m2-begin "):
        transport.append("no m2-begin")
    if "m2-end" not in E.raw:
        transport.append("transcript incomplete (no m2-end)")
    report("transcript", transport, "complete (begin..end, transport rc 0)")

    # hardening ------------------------------------------------------------
    hp, hd = [], []
    try:
        s = E.get("host", "sysctl")
        if len(s) != 3 or not all(x.strip().isdigit() for x in s):
            raise Unavailable("host sysctl: unparseable %r" % s)
        if s[0] != "2":
            hp.append("kernel.io_uring_disabled=%s" % s[0])
        hd.append("io_uring_disabled=%s" % s[0])
    except Unavailable as x:
        hp.append(str(x))
    try:
        r = E.get("host", "io_uring-setup")
        if r != ["errno:EPERM"]:
            hp.append("host io_uring_setup %r" % r)
        else:
            hd.append("host io_uring_setup EPERM")
    except Unavailable as x:
        hp.append(str(x))
    try:
        f = E.get("host", "io_uring-fds")
        m = [l for l in f if l.startswith("summary ")]
        if len(m) != 1:
            raise Unavailable("io_uring-fds: no summary")
        kv = dict(x.split("=") for x in m[0].split()[1:])
        if int(kv["procs"]) == 0 or int(kv["fds"]) == 0:
            hp.append("io_uring census read nothing (%s)" % m[0])
        if int(kv["rings"]) != 0:
            hp.append("io_uring rings held: %s" % " | ".join(l for l in f if l.startswith("ring ")))
        if int(kv["unreadable_alive"]) != 0:
            hp.append("processes alive but unreadable: %s" % " | ".join(l for l in f if l.startswith("unreadable-alive ")))
        hd.append("io_uring descriptor census: %s rings among %s fds of %s processes (exited during scan %s, fds vanished %s; corroboration, not proof)" % (
            kv["rings"], kv["fds"], kv["procs"], kv["exited"], kv["fd_vanished"]))
    except (Unavailable, KeyError, ValueError) as x:
        hp.append("io_uring census: %s" % x)
    for c in CONTAINERS:
        procs = E.line("m2-proc %s " % c)
        if not procs:
            hp.append("no process of %s read" % c)
        for l in procs:
            if not l.endswith(" netraw-eff=0 netraw-bnd=0 netadmin-bnd=0 sysadmin-bnd=0 seccomp=2"):
                hp.append(l)
        for u in ("root", "default"):
            l = E.line("m2-probe %s as=%s " % (c, u))
            ok = len(l) == 1 and re.search(r" rc=0 uid=\d+ afpacket=errno:EPERM io_uring=errno:EPERM netns=errno:EPERM userns=errno:EPERM ", l[0] + " ")
            if not ok:
                hp.append("probe %s as=%s: %s" % (c, u, l[0] if l else "not run"))
        if ("m2-probe-removed %s rc=0" % c) not in E.raw:
            hp.append("probe not removed from %s" % c)
    for l in E.line("m2-proc-unreadable "):
        hp.append(l)
    hd.append("%d container processes without NET_RAW/NET_ADMIN/SYS_ADMIN, seccomp 2; probe refused AF_PACKET, io_uring, new netns, new userns as root and as the container user in both containers" % len(E.line("m2-proc ")))
    report("hardening", hp, "; ".join(hd))

    # ordering ---------------------------------------------------------------
    op = []
    try:
        blocks, cur = [], {}
        for l in E.get("host", "ordering"):
            if not l.strip():
                if cur:
                    blocks.append(cur)
                cur = {}
                continue
            k, _, v = l.partition("=")
            cur[k] = v
        if cur:
            blocks.append(cur)
        by = {b.get("Id"): b for b in blocks}
        sy = int(by["systemd-sysctl.service"]["ActiveEnterTimestampMonotonic"])
        ct = int(by["containerd.service"]["ExecMainStartTimestampMonotonic"])
        dk = int(by["docker.service"]["ExecMainStartTimestampMonotonic"])
        if not (0 < sy < ct and sy < dk):
            op.append("systemd-sysctl active at %dus, containerd started %dus, dockerd %dus" % (sy, ct, dk))
        od = "this boot: systemd-sysctl active at %.3fs, before containerd (%.3fs) and dockerd (%.3fs)" % (sy / 1e6, ct / 1e6, dk / 1e6)
    except (Unavailable, KeyError, ValueError) as x:
        op.append("ordering: %s" % x)
        od = ""
    try:
        fs = E.get("host", "sysctl-file")
        if len(fs) != 1 or not re.match(r"^[0-9a-f]{64}  /etc/sysctl.d/99-culvert-hardening.conf$", fs[0]):
            op.append("sysctl file: %r" % fs)
        else:
            od += "; drop-in sha256 %s" % fs[0][:12]
    except Unavailable as x:
        op.append(str(x))
    report("ordering", op, od)

    # network contexts ---------------------------------------------------------
    pp, pd, rp, rd = [], [], [], []
    try:
        census = E.get("host", "netns-census")
        seen = {l.split()[0] for l in census if l.startswith("net:[")}
        if not seen:
            raise Unavailable("netns census empty")
    except Unavailable as x:
        pp.append(str(x))
        seen = set()
    mine = {}
    for ctx in CTXS:
        try:
            n = E.get(ctx, "netns")
            if len(n) != 1 or not n[0].startswith("net:["):
                raise Unavailable("%s netns: %r" % (ctx, n))
            mine[ctx] = n[0]
        except Unavailable as x:
            pp.append(str(x))
            continue
        try:
            links = E.get(ctx, "links")
            if not any(re.match(r"^\d+: lo:", l) for l in links):
                raise Unavailable("%s links: no loopback in output" % ctx)
            vl = [l.split(":")[1].strip() for l in links if " vlan protocol " in l]
            if vl:
                pp.append("%s VLAN link(s): %s" % (ctx, ",".join(vl)))
        except Unavailable as x:
            pp.append(str(x))
        for fam in ("routes4", "routes6"):
            try:
                rr = E.get(ctx, fam)
                # IPv4 `table all` always holds the loopback local route; an
                # IPv6 table may be validly empty (IPv6 off in a container).
                if fam == "routes4" and not any(" dev lo " in l + " " and l.startswith("local ") for l in rr):
                    raise Unavailable("%s routes4: no loopback local route (not a real read)" % ctx)
                enc = [l for l in rr if " encap " in l]
                if enc:
                    pp.append("%s %s encap route(s): %s" % (ctx, fam, " | ".join(enc)))
            except Unavailable as x:
                pp.append(str(x))
        try:
            q = E.get(ctx, "qdisc")
            if not q:
                raise Unavailable("%s qdisc: empty (loopback always has one)" % ctx)
            kinds = {l.split()[1] for l in q if l.startswith("qdisc ")}
            if len(kinds) == 0:
                raise Unavailable("%s qdisc: unparseable" % ctx)
            for k in sorted(kinds - ALLOWED_QDISC):
                pp.append("%s qdisc %s" % (ctx, k))
        except Unavailable as x:
            pp.append(str(x))
        try:
            v6 = E.get(ctx, "ipv6-conf")
            if not v6:
                raise Unavailable("%s ipv6-conf: empty" % ctx)
            for l in v6:
                m = re.match(r"^(\S+) forwarding=(\d+) seg6=(\d+) ioam6=(\d+) disable=(\d+)$", l)
                if not m:
                    raise Unavailable("%s ipv6-conf unparseable: %r" % (ctx, l))
                if m.group(2) != "0" or m.group(3) != "0" or m.group(4) != "0":
                    pp.append("%s %s" % (ctx, l))
            names = {l.split()[0] for l in v6}
            if not {"all", "default", "lo"} <= names:
                raise Unavailable("%s ipv6-conf: missing all/default/lo" % ctx)
            pd.append("%s %d IPv6 interface entries" % (ctx, len(v6)))
        except Unavailable as x:
            pp.append(str(x))
        try:
            js = E.get(ctx, "nft-json")
            if len(js) != 1:
                raise Unavailable("%s nft-json: %d lines" % (ctx, len(js)))
            nrules, tables, probs = nft_review(json.loads(js[0]))
            if ctx == "host" and "inet culvert" not in tables:
                rp.append("host ruleset lacks the appliance's inet culvert table (not the real ruleset?)")
            rp.extend("%s %s" % (ctx, p) for p in probs)
            rd.append("%s: %d rules in [%s]" % (ctx, nrules, ", ".join(tables)))
        except (Unavailable, ValueError, KeyError, TypeError) as x:
            rp.append("%s nft-json: %s" % (ctx, x))
    if seen and len(mine) == len(CTXS):
        extra = seen - set(mine.values())
        if extra:
            pp.append("network namespace(s) outside the three contexts: %s" % ",".join(sorted(extra)))
        pd.insert(0, "network namespaces: exactly host + culvert + culvert-clamav (%d)" % len(seen))
    try:
        mods = E.get("host", "modules")
        names = {l.split()[0] for l in mods if l.strip()}
        if "nf_tables" not in names:
            raise Unavailable("module list lacks nf_tables (loaded by design): not a real read")
        bad = [m for m in PRECOND_MODULES if m in names]
        if bad:
            pp.append("precondition modules loaded: %s" % ",".join(bad))
        pd.append("%d modules loaded, none of the %d precondition modules" % (len(names), len(PRECOND_MODULES)))
    except Unavailable as x:
        pp.append(str(x))
    try:
        s = E.get("host", "sysctl")
        if len(s) == 3 and s[1] != "2":
            pp.append("kernel.unprivileged_bpf_disabled=%s" % s[1])
    except Unavailable:
        pass  # already a hardening failure
    try:
        nics = E.get("host", "nics")
        if not nics:
            raise Unavailable("no NIC driver read")
        drv = {l.split()[-1] for l in nics}
        if drv - {"e1000", "vmxnet3"}:
            pp.append("NIC driver(s) outside e1000/vmxnet3: %s" % ",".join(sorted(drv)))
        pd.append("NIC drivers %s" % ",".join(sorted(drv)))
    except Unavailable as x:
        pp.append(str(x))
    try:
        E.get("host", "mdb")
    except Unavailable as x:
        pp.append(str(x))
    report("preconditions", pp, "; ".join(pd) + "; no VLAN link, no encap route, qdiscs within the allowed set, IPv6 forwarding/seg6/ioam6 0 on every interface")
    report("ruleset", rp, "every rule expression classified (no payload write, no queue/flowtable/exthdr/socket/tproxy): " + "; ".join(rd))

    # clamav -------------------------------------------------------------------
    cp = []
    try:
        ev = E.get("clamav", "eicar", ok_rc=(1,))
        if not any(l.rstrip().endswith(" FOUND") for l in ev):
            cp.append("EICAR not FOUND: %r" % ev)
    except Unavailable as x:
        cp.append(str(x))
    try:
        ver = E.get("clamav", "version")
    except Unavailable as x:
        cp.append(str(x))
        ver = ["?"]
    fc = E.out.get(("clamav", "freshclam"), [])
    report("clamav", cp, "clamd found EICAR on a stream scan; %s; freshclam (recorded, not gated): %s" % (ver[0] if ver else "?", " | ".join(fc)[:200]))
    return res


if __name__ == "__main__":
    path, tag = sys.argv[1], sys.argv[2]
    rc = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    for st, name, detail in run(path, tag, rc):
        print("%s\t%s\t%s" % (st, name, detail))
