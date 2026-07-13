#!/usr/bin/env python3
"""
Campaign Runner — orchestrates the five roles across isolated batches.

Usage:
  run_campaign.py --pilot            # run 5 diverse scenarios, verbose
  run_campaign.py --batches 7 --per 30   # full campaign
  run_campaign.py --all              # run every generated scenario once

Outputs (under edge-case-lab/):
  scenarios/<ID>.json     one manifest per accepted scenario (schema v1)
  evidence/<ID>/          api log, decision traces, probes, effective config
  reports/EDGE-CASE-RESULTS.json   machine-readable campaign results
"""
import argparse
import json
import os
import sys
import time
import traceback
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import harness as H
from lab import oracle
from lab.scenarios import Gen
from lab.scenarios_full import FullGen

LAB = H.LAB
SCEN_DIR = os.path.join(LAB, "scenarios")
EVID_DIR = os.path.join(LAB, "evidence")
REPORT_DIR = os.path.join(LAB, "reports")
for d in (SCEN_DIR, EVID_DIR, REPORT_DIR):
    os.makedirs(d, exist_ok=True)


def _now():
    return datetime.now(timezone.utc).isoformat()


def env_fingerprint(cv: H.Culvert) -> dict:
    return {
        "culvert_commit": cv.commit,
        "binary": H.CULVERT_BIN,
        "binary_mtime": _safe_mtime(H.CULVERT_BIN),
        "fixture_ip": H.FIXTURE_IP,
        "proxy": H.PROXY, "ui": H.UI,
        "captured_at": _now(),
    }


def _safe_mtime(p):
    try:
        return datetime.fromtimestamp(os.path.getmtime(p), timezone.utc).isoformat()
    except OSError:
        return None


SEVERITY = ["SECURITY_BYPASS", H.PRODUCT_BUG, H.MISSING_CAPABILITY, H.CONFIG_CONTRACT_GAP,
            H.UX_GAP, H.OBSERVABILITY_GAP, H.DOCUMENTATION_GAP, H.EXPECTED_LIMITATION,
            H.TEST_INFRA_FAILURE, H.INVALID_SCENARIO, H.PASS]


def worst(classes):
    for c in SEVERITY:
        if c in classes:
            return c
    return H.PASS


def run_scenario(cv: H.Culvert, sc: dict, env: dict) -> dict:
    """Execute one scenario end-to-end; return its result record + write manifest/evidence."""
    intent = sc["intent"]
    requires_auth = sc.get("requires_auth", False)

    # ---- limitation / coverage records: documented, not executed ----
    if intent.get("limitation"):
        triage = intent.get("triage", {})
        result = {"id": sc["id"], "title": sc["title"], "classification": triage.get("class", H.EXPECTED_LIMITATION),
                  "confidence": 0.9, "requires_auth": False, "vector_count": 0,
                  "vector_verdicts": [], "duration_ms": 0}
        _write_manifest(sc, intent, {"note": "coverage record — not executed"}, [], {},
                        result["classification"], 0.9, env, [])
        result["manifest"] = os.path.join("scenarios", f"{sc['id']}.json")
        result["_vector_results"] = []
        result["_intent"] = intent
        return result

    # ---- isolation: fresh /data + process restart per scenario ----
    # Strongest isolation (no config/cache/auto-learn/session/rate-limiter leakage
    # across scenarios) and keeps each scenario's mutations well under the 60/min
    # admin-API rate limit on a fresh process.
    cv.start(fresh=True)
    if requires_auth:
        cv.configure_admin()

    op = H.Operator(cv)
    ex = H.Executor(cv)
    rv = H.Reviewer()

    t0 = time.time()
    try:
        apply_report = op.apply(intent)
    except Exception as e:
        apply_report = {"errors": [f"apply exception: {e}"], "warnings": [], "created": [],
                        "readback": {}, "trace": traceback.format_exc()}
    effective = {}
    try:
        effective = op.export_effective()
    except Exception:
        pass

    # ---- config-persistence scenarios: restart WITHOUT wiping /data ----
    if intent.get("persistence_check"):
        cv.start(fresh=False)  # restart process, keep /data
        post = op.verify(intent)
        apply_report["persistence_after_restart"] = post

    vector_results = []
    classes = []
    for vec in sc["vectors"]:
        # Oracle FIRST — independent expectation before seeing actual.
        exp = oracle.evaluate(intent, vec)
        try:
            act = ex.run(vec)
        except Exception as e:
            act = H.ActualResult(disposition="exec_error", body_head=str(e))
        verdict = rv.classify_vector(exp, act, apply_report, sc)
        classes.append(verdict["verdict"])
        vector_results.append({
            "vector": vec,
            "expected": exp.to_dict(),
            "actual": act.to_dict(),
            "verdict": verdict,
        })

    primary = worst(classes)
    # scenario passes only if ALL vectors pass
    scenario_class = H.PASS if all(c == H.PASS for c in classes) else primary
    confidence = min([v["verdict"]["confidence"] for v in vector_results], default=0.0) \
        if scenario_class != H.PASS else 0.95
    dur_ms = int((time.time() - t0) * 1000)

    result = {
        "id": sc["id"], "title": sc["title"], "classification": scenario_class,
        "confidence": confidence, "requires_auth": requires_auth,
        "vector_count": len(sc["vectors"]),
        "vector_verdicts": [v["verdict"]["verdict"] for v in vector_results],
        "duration_ms": dur_ms,
    }

    _write_manifest(sc, intent, apply_report, vector_results, effective,
                    scenario_class, confidence, env, op.api_log, requires_auth)
    result["manifest"] = os.path.join("scenarios", f"{sc['id']}.json")
    result["_vector_results"] = vector_results  # for confirmation pass (not serialized to summary)
    result["_intent"] = intent
    return result


def _write_manifest(sc, intent, apply_report, vector_results, effective,
                    scenario_class, confidence, env, api_log, requires_auth=False):
    ev = os.path.join(EVID_DIR, sc["id"])
    os.makedirs(ev, exist_ok=True)
    with open(os.path.join(ev, "api_log.json"), "w") as f:
        json.dump(api_log, f, indent=2)
    with open(os.path.join(ev, "effective_config.json"), "w") as f:
        json.dump(effective, f, indent=2)
    with open(os.path.join(ev, "vectors.json"), "w") as f:
        json.dump(vector_results, f, indent=2)
    manifest = {
        "schema_version": "1.0.0",
        "id": sc["id"], "title": sc["title"],
        "administrator_requirement": sc["requirement"],
        "enterprise_validity_rationale": sc["rationale"],
        "comparable_product_capability": sc["product_category"],
        "capabilities": sc["capabilities"],
        "semantic_fingerprint": sc["fingerprint"],
        "notes": sc.get("notes", ""),
        "preconditions": {
            "baseline": "fresh /data + configured-admin" if requires_auth else "fresh /data + open-mode",
            "fixtures": "local origin_server on 192.0.2.2 (HTTP 18091 / HTTPS 18453), /etc/hosts routing",
            "network_topology": "single-node Culvert; TEST-NET-1 fixture; two client sources "
                                "(192.0.2.2 corp / 127.0.0.1 guest)",
            "requires_auth": requires_auth,
        },
        "intent": intent,
        "expected_culvert_objects": _describe_objects(intent),
        "configuration_steps": api_log,
        "apply_report": apply_report,
        "effective_config_excerpt": _config_excerpt(effective),
        "test_vectors": [
            {"vector": vr["vector"], "expected": vr["expected"],
             "actual": vr["actual"], "verdict": vr["verdict"]}
            for vr in vector_results
        ],
        "result_classification": scenario_class,
        "confidence_score": confidence,
        "cleanup_procedure": "API reset_config (delete rules, default-action allow) or fresh /data wipe "
                             "+ process restart between scenarios; fresh restart for bug confirmation.",
        "reproduction": {"env": env, "how": f"python3 edge-case-lab/harness/repro_one.py {sc['id']}"},
        "executed_at": _now(),
    }
    with open(os.path.join(SCEN_DIR, f"{sc['id']}.json"), "w") as f:
        json.dump(manifest, f, indent=2)


def _describe_objects(intent):
    obj = intent.get("objects", {})
    return {
        "categories": list((obj.get("categories") or {}).keys()),
        "category_groups": list((obj.get("category_groups") or {}).keys()),
        "decryption_profiles": list((obj.get("decryption_profiles") or {}).keys()),
        "blocklist": obj.get("blocklist", []),
        "ssl_bypass": obj.get("ssl_bypass", []),
        "access_rules": [r["name"] for r in intent.get("rules", []) if r.get("kind", "access") == "access"],
        "default_action": intent.get("default_action"),
        "default_auth": intent.get("default_auth"),
    }


def _config_excerpt(eff):
    if not isinstance(eff, dict):
        return {}
    return {k: eff.get(k) for k in ("defaultAction", "policyRules", "blocklist", "sslBypass")
            if k in eff}


def confirm_bug(cv: H.Culvert, sc: dict, env: dict) -> dict:
    """Re-run a candidate PRODUCT_BUG scenario in a FRESH clean instance."""
    cv.start(fresh=True)
    if sc.get("requires_auth"):
        cv.configure_admin()
    op = H.Operator(cv); ex = H.Executor(cv); rv = H.Reviewer()
    apply_report = op.apply(sc["intent"])
    confirmed = []
    for vec in sc["vectors"]:
        exp = oracle.evaluate(sc["intent"], vec)
        act = ex.run(vec)
        verdict = rv.classify_vector(exp, act, apply_report, sc)
        if verdict["verdict"] == H.PRODUCT_BUG:
            confirmed.append({"vector": vec, "expected": exp.to_dict(),
                              "actual": act.to_dict(), "verdict": verdict})
    return {"reproduced": bool(confirmed), "confirmations": confirmed,
            "clean_env": env_fingerprint(cv)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pilot", action="store_true")
    ap.add_argument("--all", action="store_true")
    ap.add_argument("--batches", type=int, default=0)
    ap.add_argument("--per", type=int, default=30)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    if args.pilot:
        scenarios = Gen().build()
        pick = ["SWG-0002", "SWG-0005", "SWG-0006", "SWG-0010", "SWG-0009"]
        scenarios = [s for s in scenarios if s["id"] in pick]
    else:
        scenarios = FullGen().build_full()
        if args.limit:
            scenarios = scenarios[:args.limit]

    cv = H.Culvert()
    cv.start(fresh=True)
    env = env_fingerprint(cv)
    print(f"# Culvert commit {env['culvert_commit'][:10]} | {len(scenarios)} scenarios")

    results = []
    bug_candidates = []
    batch_size = args.per if args.per else 30
    for i, sc in enumerate(scenarios):
        if i > 0 and i % batch_size == 0:
            print(f"  --- batch {i // batch_size + 1} ---")
        try:
            r = run_scenario(cv, sc, env)
        except Exception as e:
            print(f"  {sc['id']} EXCEPTION: {e}")
            traceback.print_exc()
            # try to recover the instance
            cv.start(fresh=True)
            continue
        results.append(r)
        tag = r["classification"]
        print(f"  {r['id']:9} {tag:24} conf={r['confidence']:.2f}  {sc['title'][:52]}")
        if tag == H.PRODUCT_BUG:
            bug_candidates.append(sc)

    # ---- confirmation pass for product-bug candidates ----
    confirmations = {}
    for sc in bug_candidates:
        print(f"  confirming {sc['id']} in clean env ...")
        try:
            confirmations[sc["id"]] = confirm_bug(cv, sc, env)
            print(f"    reproduced={confirmations[sc['id']]['reproduced']}")
        except Exception as e:
            confirmations[sc["id"]] = {"reproduced": None, "error": str(e)}

    cv.stop()

    # ---- summary ----
    summary = {
        "campaign": "edge-case-validation",
        "generated_at": _now(),
        "env": env,
        "counts": _counts(results),
        "confirmations": confirmations,
        "results": [{k: v for k, v in r.items() if not k.startswith("_")} for r in results],
    }
    out = os.path.join(REPORT_DIR, "EDGE-CASE-RESULTS.json" if not args.pilot else "PILOT-RESULTS.json")
    with open(out, "w") as f:
        json.dump(summary, f, indent=2)
    print(f"\n# wrote {out}")
    print(f"# counts: {json.dumps(summary['counts'])}")
    return summary


def _counts(results):
    c = {}
    for r in results:
        c[r["classification"]] = c.get(r["classification"], 0) + 1
    c["total"] = len(results)
    c["pass_rate"] = round(c.get("PASS", 0) / max(1, len(results)), 3)
    return c


if __name__ == "__main__":
    main()
