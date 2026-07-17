#!/usr/bin/env python3
"""
Scenario uniqueness / behavioral-coverage analysis.

The raw scenario count (215) OVER-states coverage: many scenarios are parametric
host/action permutations that exercise the SAME enforcement code path. This tool
computes a NORMALIZED BEHAVIORAL FINGERPRINT for each scenario — abstracting away
specific hostnames/category names and keeping only the behavioral structure
(match DIMENSIONS used, action, ssl mode, precedence shape, defaults, vector
protocol + source-class + polarity) — and reports the number of DISTINCT
behaviors, which is the honest coverage metric.
"""
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab.scenarios_full import FullGen
from lab import oracle

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def norm_rule(r):
    m = r.get("match", {})
    dims = tuple(sorted(k for k in ("src_ip", "identity", "group", "auth_source", "fqdn",
                                    "category", "category_group", "country", "schedule")
                        if m.get(k) is not None))
    return (dims, r.get("action", "allow"), r.get("ssl") or "", bool(r.get("file_profile")),
            bool(r.get("enabled") is False))


def behavioral_fp(sc):
    intent = sc["intent"]
    if intent.get("limitation"):
        return ("LIMITATION", sc["capabilities"][0] if sc["capabilities"] else "?")
    rules = intent.get("rules", [])
    rule_sig = tuple(sorted(norm_rule(r) for r in rules if r.get("kind", "access") == "access"))
    # precedence-sensitive? multiple rules whose priorities differ
    pris = [r.get("priority", 0) for r in rules]
    precedence = len(rules) >= 2 and len(set(pris)) > 1
    # vector shapes: (scheme, source-class, oracle-disposition)
    vshapes = set()
    for v in sc["vectors"]:
        src = "corp" if v.get("client_ip") == "192.0.2.2" else "other"
        try:
            disp = oracle.evaluate(intent, v).disposition
        except Exception:
            disp = "?"
        vshapes.add((v.get("scheme", "http"), src, disp))
    return (
        intent.get("default_action", "allow"),
        intent.get("default_auth", "Exempt"),
        bool(intent.get("configure_auth")),
        rule_sig,
        precedence,
        tuple(sorted(vshapes)),
        tuple(sorted(intent.get("objects", {}).keys())),
    )


def vector_polarity(sc):
    """Count positive (allow), negative (block/deny), boundary (neg-match) vectors."""
    pos = neg = 0
    for v in sc["vectors"]:
        try:
            d = oracle.evaluate(sc["intent"], v).disposition
        except Exception:
            continue
        if d == "allow":
            pos += 1
        else:
            neg += 1
    return pos, neg


def main():
    scs = FullGen().build_full()
    groups = defaultdict(list)
    for sc in scs:
        groups[behavioral_fp(sc)].append(sc["id"])

    distinct = len(groups)
    total = len(scs)
    # distributions
    cap_count = defaultdict(int)
    scheme_count = defaultdict(int)
    src_classes = set()
    pos_total = neg_total = 0
    action_count = defaultdict(int)
    for sc in scs:
        for c in sc["capabilities"]:
            cap_count[c] += 1
        for v in sc["vectors"]:
            scheme_count[v.get("scheme", "http")] += 1
            src_classes.add("corp" if v.get("client_ip") == "192.0.2.2" else "other")
        p, n = vector_polarity(sc)
        pos_total += p; neg_total += n
        for r in sc["intent"].get("rules", []):
            action_count[r.get("action", "allow")] += 1

    # superficial-variation clusters (same behavior, many scenarios)
    clusters = sorted(((len(ids), fp, ids) for fp, ids in groups.items() if len(ids) >= 4),
                      reverse=True)

    L = ["# Culvert Edge-Case Lab — Scenario Uniqueness & Behavioral Coverage\n"]
    L.append(f"- **Raw accepted scenarios:** {total}")
    L.append(f"- **Distinct behavioral fingerprints (effective unique coverage):** {distinct}")
    L.append(f"- **Behavioral-collapse ratio:** {total}/{distinct} = "
             f"**{total/distinct:.1f}× parametric multiplier** "
             f"({100*distinct/total:.0f}% of scenarios are behaviorally distinct)")
    L.append(f"- **Total test vectors:** {sum(scheme_count.values())}  "
             f"(positive/allow: {pos_total}, negative/block: {neg_total})")
    L.append(f"- **Protocol diversity (vectors):** " +
             ", ".join(f"{k}={v}" for k, v in sorted(scheme_count.items())))
    L.append(f"- **Source-class diversity:** {sorted(src_classes)} "
             f"(infra limit: only 2 locally-bindable client source IPs)")
    L.append(f"- **Action diversity (rules):** " +
             ", ".join(f"{k}={v}" for k, v in sorted(action_count.items())))
    L.append("")
    L.append("## Interpretation\n")
    L.append(f"The raw count of {total} is a PARAMETRIC EXPANSION over ~{distinct} distinct enforcement "
             "behaviors. Blocking `news.example.test` vs `media.corp.local` by exact FQDN is the SAME "
             "code path with a different string; such families inflate the count but not the behavioral "
             "coverage. The honest coverage metric is the **distinct-behavior count**. This is adequate "
             "for a broad regression sweep but should NOT be reported as '215 independent tests'.")
    L.append("")
    L.append("## Largest superficial-variation clusters (same behavior, many scenarios)\n")
    L.append("| Count | Behavior (normalized) | Example IDs |")
    L.append("|---|---|---|")
    for n, fp, ids in clusters[:15]:
        # summarize fp compactly
        da, dau, cauth, rule_sig, prec, vsh, objs = fp if len(fp) == 7 else ("?",)*7
        rules_desc = "; ".join(f"{'+'.join(d[0]) or 'any'}->{d[1]}{('/'+d[2]) if d[2] else ''}"
                               for d in rule_sig) if isinstance(rule_sig, tuple) else str(fp)
        L.append(f"| {n} | default={da}, rules=[{rules_desc}], precedence={prec} | "
                 f"{', '.join(ids[:3])}{' …' if len(ids) > 3 else ''} |")
    L.append("")
    L.append("## Coverage gaps revealed by normalization\n")
    L.append("- **Tenant diversity: LOW.** Only 2 source classes (corp `192.0.2.0/24` / other `127.0.0.0/8`); "
             "true multi-tenant matrices (N tenants, overlapping destinations) are under-covered.")
    L.append("- **Negative/boundary vectors present but thin** in some families (e.g. schedule has one "
             "active + one inactive; few over-match negative probes per wildcard).")
    L.append("- **Identity/group behavior: NONE** (no IdP; source-IP is the only 'identity' axis).")
    L.append("- **Failure-mode diversity: MODERATE** — cert-fail-closed, drop, conn-fail covered; "
             "auth-timeout, IdP-down, CP-down, partial-download NOT behaviorally exercised.")
    L.append("- **Protocol diversity: GOOD for http/https, THIN for socks5 (2), none for raw WebSocket "
             "frame assertions.**")

    out = os.path.join(LAB, "EDGE-CASE-SCENARIO-UNIQUENESS.md")
    open(out, "w").write("\n".join(L) + "\n")
    print(f"raw={total} distinct={distinct} ratio={total/distinct:.2f}x")
    print(f"wrote {out}")
    # machine-readable
    json.dump({"raw": total, "distinct_behaviors": distinct, "ratio": total/distinct,
               "vectors": sum(scheme_count.values()), "positive": pos_total, "negative": neg_total,
               "schemes": dict(scheme_count),
               "clusters": [{"count": n, "ids": ids} for n, _, ids in clusters]},
              open(os.path.join(LAB, "reports", "scenario-uniqueness.json"), "w"), indent=2)


if __name__ == "__main__":
    main()
