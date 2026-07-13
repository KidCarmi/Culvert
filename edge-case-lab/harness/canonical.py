#!/usr/bin/env python3
"""
R4: Canonical behavior normalization.

Collapses the 215 parametric scenarios into a canonical registry of distinct
enforcement BEHAVIORS (the honest coverage baseline), maps every scenario to a
canonical behavior id, and QUARANTINES scenarios whose negative vector is
accidentally permitted by a wildcard/broader allow rule (so it does not actually
exercise the intended block/deny path).

Outputs:
  edge-case-lab/EDGE-CASE-CANONICAL-BEHAVIORS.json  — the registry
  edge-case-lab/EDGE-CASE-SCENARIO-MAPPING.json     — scenario -> behavior + validity
  edge-case-lab/reports/canonical-summary.json      — counts
"""
import json
import os
import sys
from collections import defaultdict, Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab.scenarios_full import FullGen
from lab import oracle

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Vector ids that UNAMBIGUOUSLY imply a BLOCK/DENY outcome. A vector so named that
# the oracle computes as ALLOW is a misleading negative (does not exercise the block
# path it claims) — the M7 class. Deliberately NARROW: 'neg'/'other'/'boundary'/'guest'
# are allow-CONTROLS (verify unrelated traffic stays allowed) and are NOT flagged.
NEG_INTENT = ("deny", "restricted", "blocked")

DISP_EVIDENCE = {
    oracle.ALLOW: "POLICY_ALLOW | default-allow | AUTH_DEFAULT_EXEMPT",
    oracle.BLOCK_PAGE: "POLICY_BLOCK | POLICY_DEFAULT_DENY | FILE_BLOCKED | THREAT_BLOCKED",
    oracle.DROP: "POLICY_DROP",
    oracle.REDIRECT: "POLICY_REDIRECT",
    oracle.AUTH_CHALLENGE: "CRED_REQUIRED | 407",
    oracle.CONN_FAIL: "SSL_INSPECT cert error (tls_validation_fail) | upstream_fail",
}


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
    pris = [r.get("priority", 0) for r in rules]
    precedence = len(rules) >= 2 and len(set(pris)) > 1
    vshapes = set()
    for v in sc["vectors"]:
        src = "corp" if v.get("client_ip") == "192.0.2.2" else "other"
        try:
            disp = oracle.evaluate(intent, v).disposition
        except Exception:
            disp = "?"
        vshapes.add((v.get("scheme", "http"), src, disp))
    return (intent.get("default_action", "allow"), intent.get("default_auth", "Exempt"),
            bool(intent.get("configure_auth")), rule_sig, precedence,
            tuple(sorted(vshapes)), tuple(sorted(intent.get("objects", {}).keys())))


def policy_dimensions(sc):
    dims = set()
    for r in sc["intent"].get("rules", []):
        for k in r.get("match", {}):
            dims.add({"src_ip": "source", "fqdn": "url_object", "category": "url_category",
                      "category_group": "category_group", "schedule": "schedule",
                      "country": "geoip", "group": "identity_group",
                      "identity": "identity"}.get(k, k))
    if sc["intent"].get("default_action") == "deny":
        dims.add("default_deny")
    if sc["intent"].get("objects", {}).get("blocklist"):
        dims.add("threat_intel")
    return sorted(dims) or ["default"]


def detect_weak_negative(sc):
    """A scenario is misleading if a negative-intent vector is actually PERMITTED
    (oracle disposition == allow) — e.g. a 'deny-other' host covered by a *.wildcard
    permit. Such a vector does not exercise the block/deny path it implies."""
    problems = []
    intent = sc["intent"]
    if intent.get("limitation"):
        return problems
    for v in sc["vectors"]:
        vid = v.get("id", "").lower()
        is_neg_intent = any(t in vid for t in NEG_INTENT) and not any(t in vid for t in ("permit", "allow"))
        if not is_neg_intent:
            continue
        try:
            disp = oracle.evaluate(intent, v).disposition
        except Exception:
            continue
        if disp == oracle.ALLOW:
            problems.append({"vector": v.get("id"), "host": v.get("host"),
                             "issue": "negative-intent vector is permitted (covered by an allow/wildcard rule)"})
    return problems


def main():
    scs = FullGen().build_full()
    groups = defaultdict(list)
    for sc in scs:
        groups[behavioral_fp(sc)].append(sc)

    # assign canonical ids (stable order by first scenario id)
    ordered = sorted(groups.items(), key=lambda kv: kv[1][0]["id"])
    registry = []
    scen_to_cb = {}
    for i, (fp, members) in enumerate(ordered, 1):
        cbid = f"CB-{i:03d}"
        cap = Counter(c for m in members for c in m["capabilities"]).most_common(1)[0][0]
        intent0 = members[0]["intent"]
        # vector shapes across the behavior
        vshapes = fp[5] if len(fp) == 7 else ()
        schemes = sorted(set(s[0] for s in vshapes)) if vshapes else []
        disps = sorted(set(s[2] for s in vshapes)) if vshapes else []
        pos = [s for s in vshapes if s[2] == oracle.ALLOW]
        neg = [s for s in vshapes if s[2] in (oracle.BLOCK_PAGE, oracle.DROP)]
        bnd = [s for s in vshapes if s[2] in (oracle.REDIRECT, oracle.CONN_FAIL, oracle.AUTH_CHALLENGE)]
        failure_modes = []
        if oracle.CONN_FAIL in disps:
            failure_modes.append("tls_validation_fail_or_upstream")
        if intent0.get("limitation"):
            failure_modes.append("recorded_limitation")
        entry = {
            "behavior_id": cbid,
            "capability": cap,
            "policy_dimension": policy_dimensions(members[0]),
            "protocol": "+".join(schemes) or "n/a",
            "positive_vector": f"{pos[0][0]}/{pos[0][1]}-src -> allow" if pos else None,
            "negative_vector": f"{neg[0][0]}/{neg[0][1]}-src -> {neg[0][2]}" if neg else None,
            "boundary_vector": f"{bnd[0][0]}/{bnd[0][1]}-src -> {bnd[0][2]}" if bnd else None,
            "failure_mode": failure_modes or ["none"],
            "expected_decision": disps,
            "required_evidence": sorted({DISP_EVIDENCE.get(d, d) for d in disps}),
            "default_action": intent0.get("default_action"),
            "precedence_sensitive": bool(fp[4]) if len(fp) == 7 else False,
            "scenario_count": len(members),
            "scenarios": [m["id"] for m in members],
        }
        registry.append(entry)
        for m in members:
            scen_to_cb[m["id"]] = cbid

    # scenario mapping + validity
    mapping = []
    invalid = []
    param_only = 0
    behavior_first_seen = {}
    for sc in scs:
        cb = scen_to_cb[sc["id"]]
        weak = detect_weak_negative(sc)
        is_first = cb not in behavior_first_seen
        if is_first:
            behavior_first_seen[cb] = sc["id"]
        else:
            param_only += 1
        rec = {"id": sc["id"], "behavior_id": cb, "capabilities": sc["capabilities"],
               "canonical_representative": is_first,
               "validity": "quarantined_weak_negative" if weak else "valid",
               "weak_negative": weak}
        mapping.append(rec)
        if weak:
            invalid.append(sc["id"])

    summary = {
        "raw_scenarios": len(scs),
        "canonical_behaviors": len(registry),
        "effective_unique_coverage": len(registry),
        "parameter_only_variations": param_only,
        "invalid_or_misleading_scenarios": len(invalid),
        "quarantined_ids": invalid,
        "behavioral_collapse_ratio": round(len(scs) / max(1, len(registry)), 2),
    }

    json.dump(registry, open(os.path.join(LAB, "EDGE-CASE-CANONICAL-BEHAVIORS.json"), "w"), indent=2)
    json.dump(mapping, open(os.path.join(LAB, "EDGE-CASE-SCENARIO-MAPPING.json"), "w"), indent=2)
    json.dump(summary, open(os.path.join(LAB, "reports", "canonical-summary.json"), "w"), indent=2)
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
