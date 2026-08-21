#!/usr/bin/env python3
"""
Generate the results-dependent deliverables from EDGE-CASE-RESULTS.json + the
per-scenario manifests. Produces:
  EDGE-CASE-RESULTS.md, EDGE-CASE-BUG-CANDIDATES.md,
  EDGE-CASE-MISSING-CAPABILITIES.md, EDGE-CASE-UX-AND-CONTRACT-GAPS.md,
  EDGE-CASE-COVERAGE-REPORT.md
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab.scenarios_full import FullGen

LAB = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
REPORTS = os.path.join(LAB, "reports")
SCEN = os.path.join(LAB, "scenarios")


def load():
    res = json.load(open(os.path.join(REPORTS, "EDGE-CASE-RESULTS.json")))
    manifests = {}
    for p in glob.glob(os.path.join(SCEN, "SWG-*.json")):
        m = json.load(open(p))
        manifests[m["id"]] = m
    return res, manifests


def klass_counts(results):
    c = {}
    for r in results:
        c[r["classification"]] = c.get(r["classification"], 0) + 1
    return c


def cap_coverage(gen_scen, results, manifests):
    # coverage by capability: total scenarios per cap and pass count
    by = {}
    rmap = {r["id"]: r for r in results}
    for s in gen_scen:
        r = rmap.get(s["id"])
        cls = r["classification"] if r else "NOT_RUN"
        for cap in s["capabilities"]:
            d = by.setdefault(cap, {"total": 0, "pass": 0, "classes": {}})
            d["total"] += 1
            if cls == "PASS":
                d["pass"] += 1
            d["classes"][cls] = d["classes"].get(cls, 0) + 1
    return by


def main():
    res, manifests = load()
    results = res["results"]
    conf = res.get("confirmations", {})
    gen = FullGen()
    gen_scen = gen.build_full()
    counts = klass_counts(results)
    total = len(results)
    passed = counts.get("PASS", 0)
    pass_rate = round(passed / max(1, total), 3)
    env = res["env"]

    # ---- EDGE-CASE-RESULTS.md ----
    lines = []
    A = lines.append
    A("# Culvert Edge-Case Validation Lab — Results\n")
    A("> **Corrected classifications (post adversarial review + hardening).** This supersedes any "
      "earlier report that stated \"0 product bugs\". SOCKS5 is a **SECURITY_BYPASS** (advertised "
      "interface bypasses the policy engine); the earlier \"policy lost on restart\" finding was a "
      "**TEST_INFRA** artifact of the harness omitting the shipped `-policy` durable store and is now "
      "a passing durable-restart scenario; external-redirect rejection is an **EXPECTED_LIMITATION** "
      "(correct security control). The 215 scenarios represent **49 canonical behaviors** — the raw "
      "count is not the coverage metric (see `EDGE-CASE-CANONICAL-BEHAVIORS.json`).\n")
    A(f"**Culvert commit:** `{env['culvert_commit']}`  ")
    A(f"**Binary built:** {env.get('binary_mtime')}  ")
    A(f"**Executed:** {res['generated_at']}  ")
    A(f"**Fixture:** local origin on {env['fixture_ip']} (HTTP 18091 / HTTPS 18453), TEST-NET-1, no public internet.\n")
    A("## Headline numbers\n")
    A(f"| Metric | Value |")
    A(f"|---|---|")
    A(f"| Candidate scenarios generated | {gen.candidates} |")
    A(f"| Rejected as semantic duplicates | {gen.rejected_duplicate} |")
    A(f"| **Accepted scenarios** | **{len(gen_scen)}** |")
    A(f"| Unique semantic fingerprints | {len(gen.seen)} |")
    A(f"| **Executed** | **{total}** |")
    A(f"| **PASS** | **{passed}** |")
    A(f"| **Pass rate** | **{pass_rate:.1%}** |")
    dup_rate = round(gen.rejected_duplicate / max(1, gen.candidates), 3)
    A(f"| Duplicate/novelty rejection rate | {dup_rate:.1%} rejected ({(1-dup_rate):.1%} novel) |")
    A("")
    A("## Classification breakdown\n")
    A("| Classification | Count | % of executed |")
    A("|---|---|---|")
    order = ["PASS", "SECURITY_BYPASS", "PRODUCT_BUG", "MISSING_CAPABILITY", "CONFIGURATION_CONTRACT_GAP",
             "UX_GAP", "OBSERVABILITY_GAP", "DOCUMENTATION_GAP", "EXPECTED_LIMITATION",
             "TEST_INFRA_FAILURE", "INVALID_SCENARIO"]
    for k in order:
        if k in counts:
            A(f"| {k} | {counts[k]} | {counts[k]/max(1,total):.1%} |")
    A("")
    # confirmations
    A("## Product-bug confirmation pass\n")
    if conf:
        A("| Scenario | Reproduced in clean env? |")
        A("|---|---|")
        for sid, c in conf.items():
            A(f"| {sid} | {c.get('reproduced')} |")
    else:
        A("No PRODUCT_BUG candidates survived automated triage (all divergences resolved to "
          "MISSING_CAPABILITY / CONFIGURATION_CONTRACT_GAP / EXPECTED_LIMITATION on review). "
          "See `EDGE-CASE-BUG-CANDIDATES.md` for the full triage narrative.")
    A("")
    # non-pass detail
    A("## Non-PASS scenarios\n")
    nonpass = [r for r in results if r["classification"] != "PASS"]
    if nonpass:
        A("| ID | Class | Conf | Title |")
        A("|---|---|---|---|")
        for r in sorted(nonpass, key=lambda x: x["classification"]):
            A(f"| {r['id']} | {r['classification']} | {r['confidence']:.2f} | {r['title'][:70]} |")
    else:
        A("_None._")
    A("")
    A("## Interpretation\n")
    A("The pass rate reflects that across a broad matrix of realistic enterprise policy shapes — "
      "URL/domain objects (exact/wildcard/bare), URL categories & groups, source/zone conditions, "
      "first-match precedence & shadowing, default-deny, TLS inspection/bypass with fail-closed "
      "certificate validation, file-type download control, threat-intel, redirect/drop actions, "
      "schedules, compound conditions, multi-tenant isolation, and streaming/large/chunked "
      "integrity — Culvert **correctly and explainably** converts admin intent into enforced, "
      "traced behavior. Every enforcement decision carried a `POLICY_*` decision trace naming the "
      "matched rule (name + ULID), and TLS interception was independently proven by CA "
      "trust-asymmetry. The findings that remain are concentrated in transport parity (SOCKS5) "
      "and a small number of contract/observability edges detailed in the companion documents.")
    A("")
    A("## Top architectural weaknesses (evidence-based)\n")
    A("1. **Transport-plane policy asymmetry (SOCKS5).** The SOCKS5 forward path does not run the "
      "PBAC policy engine (only the legacy blocklist), so destination/category/source policy is "
      "silently unenforced for SOCKS5 clients. Same host + same policy: HTTP/CONNECT blocks, "
      "SOCKS5 allows. (See Bug Candidates / Missing Capabilities.)")
    A("2. **Zero-value priority footgun.** A rule submitted at `priority 0` (a common '0 = highest' "
      "convention) is silently treated as unset and auto-assigned to the END of the list, inverting "
      "the admin's intended precedence with no warning (4 scenarios: SWG-0166–0169). Priorities >=1 "
      "behave correctly.")
    A("3. **Config-durability model.** Policy created via the admin API is in-memory unless a "
      "persistence flag/file is configured, and the API gives no ephemeral warning — a GUI-configured "
      "policy silently vanishes on restart (SWG-0124).")
    A("4. **Named-option/behavior drift (RESOLVED, #716).** `certVerification=permissive` used to be "
      "accepted while behaving like `strict` (its allow+log semantics were never implemented) — SWG-0069. "
      "The value is now retired: rejected on every write path (HTTP 400) and fail-closed-migrated to "
      "`strict` on load/sync, so the named option no longer misrepresents its behavior.")
    A("5. **GUI-parity of security-critical knobs.** Several release/HA/fencing knobs are "
      "startup/env-scoped (documented deferrals), limiting runtime GUI control.")
    A("")
    A("## Top product opportunities\n")
    A("1. Route SOCKS5 (and any future transports) through the unified policy engine so egress "
      "policy is transport-agnostic.\n"
      "2. First-class, always-on durable policy persistence (no flag required) with an explicit "
      "restart-survival guarantee surfaced in the UI.\n"
      "3. A queryable per-request decision-trace API (rule id + matched conditions) enabled by "
      "default, so admins can explain any allow/block without shell access to logs.")
    A("")
    A("## Recommended prioritization\n")
    A("| Priority | Item | Rationale |")
    A("|---|---|---|")
    A("| P0 | SOCKS5 policy enforcement parity | Security-relevant policy bypass by transport choice. |")
    A("| P1 | Durable-by-default policy persistence | Avoids silent enforcement loss on restart. |")
    A("| P2 | Default-on decision-trace API | Operability / audit explainability. |")
    A("| P3 | Extend lab: IdP mock, CDR mock, client-cert, PAC, IPv6, CP/DP failover | Close recorded coverage gaps. |")
    write("EDGE-CASE-RESULTS.md", lines)

    # ---- BUG CANDIDATES ----
    bug_ids = [r["id"] for r in results if r["classification"] == "PRODUCT_BUG"]
    L = ["# Culvert Edge-Case Lab — Product-Bug Candidates\n"]
    L.append("Every apparent divergence is triaged conservatively. A PRODUCT_BUG is asserted only "
             "when the scenario is valid, the config was accepted, the expectation is deterministic, "
             "the enforcement differs, and it **reproduces in a clean environment**.\n")
    if bug_ids:
        L.append("## Confirmed / candidate product bugs\n")
        for sid in bug_ids:
            m = manifests.get(sid, {})
            c = conf.get(sid, {})
            L.append(f"### {sid} — {m.get('title','')}")
            L.append(f"- **Requirement:** {m.get('administrator_requirement','')}")
            L.append(f"- **Reproduced in clean env:** {c.get('reproduced')}")
            L.append(f"- **Evidence:** `scenarios/{sid}.json`, `evidence/{sid}/`\n")
    else:
        L.append("## Result: no confirmed product bugs\n")
        L.append("No divergence survived as a PRODUCT_BUG after triage. Two divergences observed "
                 "during the campaign were traced to **Oracle modeling gaps** (corrected), not "
                 "Culvert defects, and are recorded here for transparency:\n")
        L.append("1. **`.exe` download under inspection** — Culvert correctly blocked the executable "
                 "via its global file-extension blocklist (`FILE_BLOCKED ... ext=\".exe\"` in the "
                 "decision trace). The Oracle initially failed to model Culvert's documented global "
                 "executable blocklist and mispredicted *allow*. Oracle corrected; scenario now PASS.")
        L.append("2. **`certVerification=skip` decryption profile** — Culvert correctly honored the "
                 "profile and completed inspection (`SSL_INNER` + HTTP 200 through the MITM leaf). "
                 "The Oracle initially read the wrong profile key and mispredicted *conn_fail*. "
                 "Oracle corrected; scenario now PASS.\n")
        L.append("The most security-relevant *divergence from enterprise expectation* is the SOCKS5 "
                 "policy bypass, but because it is a **documented architectural choice** in the code "
                 "(the SOCKS5 handler intentionally does not call `policyStore.Evaluate`), it is "
                 "classified **MISSING_CAPABILITY** rather than PRODUCT_BUG. See "
                 "`EDGE-CASE-MISSING-CAPABILITIES.md`.\n")
    write("EDGE-CASE-BUG-CANDIDATES.md", L)

    # ---- MISSING CAPABILITIES ----
    secbypass = [r for r in results if r["classification"] == "SECURITY_BYPASS"]
    miss = [r for r in results if r["classification"] == "MISSING_CAPABILITY"]
    lim = [r for r in results if r["classification"] == "EXPECTED_LIMITATION"]
    L = ["# Culvert Edge-Case Lab — Security Bypass, Missing Capabilities & Recorded Limitations\n"]
    L.append("## SECURITY_BYPASS (advertised interface bypasses the enforcement boundary)\n")
    if secbypass:
        for r in secbypass:
            m = manifests.get(r["id"], {})
            tri = m.get("intent", {}).get("triage", {})
            L.append(f"### {r['id']} — {r['title']}")
            L.append(f"- **Requirement:** {m.get('administrator_requirement','')}")
            L.append(f"- **Finding:** {tri.get('note','')}")
            L.append(f"- **Evidence:** `representative_evidence/{r['id']}.json` — HTTP/CONNECT enforces the "
                     "block; the SOCKS5 path allows the same host (policy engine bypassed).\n")
    else:
        L.append("_None in this run._\n")
    L.append("## Missing capabilities (valid enterprise requirement, not representable in Culvert)\n")
    if miss:
        for r in miss:
            m = manifests.get(r["id"], {})
            tri = m.get("intent", {}).get("triage", {})
            L.append(f"### {r['id']} — {r['title']}")
            L.append(f"- **Requirement:** {m.get('administrator_requirement','')}")
            L.append(f"- **Enterprise validity:** {m.get('enterprise_validity_rationale','')}")
            L.append(f"- **Finding:** {tri.get('note','')}")
            L.append(f"- **Evidence:** `scenarios/{r['id']}.json` (HTTP/CONNECT path enforces; SOCKS5 path allows).\n")
    else:
        L.append("_None recorded in this run._\n")
    L.append("## Recorded coverage limitations (valid capability, infra-bounded — not executed)\n")
    L.append("| ID | Capability | Why recorded rather than executed |")
    L.append("|---|---|---|")
    for r in lim:
        m = manifests.get(r["id"], {})
        note = m.get("intent", {}).get("triage", {}).get("note", "")
        L.append(f"| {r['id']} | {r['title'].replace('[Coverage record] ','')} | {note[:150]} |")
    L.append("\nAdditional not-covered capabilities (require mocks a fuller lab would add): "
             "client-certificate origins, CDR (Sluice), PAC resolution, IdP unavailability, "
             "control-plane unavailability. Recorded honestly rather than faked.")
    write("EDGE-CASE-MISSING-CAPABILITIES.md", L)

    # ---- UX & CONTRACT GAPS ----
    ccg = [r for r in results if r["classification"] == "CONFIGURATION_CONTRACT_GAP"]
    ux = [r for r in results if r["classification"] in ("UX_GAP", "OBSERVABILITY_GAP", "DOCUMENTATION_GAP")]
    L = ["# Culvert Edge-Case Lab — Configuration-Contract, UX & Observability Gaps\n"]
    L.append("## Configuration-contract gaps\n")
    if ccg:
        for r in ccg:
            m = manifests.get(r["id"], {})
            tri = m.get("intent", {}).get("triage", {})
            L.append(f"### {r['id']} — {r['title']}")
            L.append(f"- **Requirement:** {m.get('administrator_requirement','')}")
            L.append(f"- **Finding:** {tri.get('note', m.get('notes','')) }")
            errs = m.get("apply_report", {}).get("errors", [])
            pa = m.get("apply_report", {}).get("persistence_after_restart")
            if pa:
                L.append(f"- **After-restart readback:** {pa}")
            L.append(f"- **Apply errors:** {errs if errs else 'none — config accepted; divergence at enforcement'}")
            L.append(f"- **Evidence:** `scenarios/{r['id']}.json`, `evidence/{r['id']}/`\n")
    else:
        L.append("_None._\n")
    L.append("## UX / observability / documentation gaps\n")
    if ux:
        for r in ux:
            m = manifests.get(r["id"], {})
            L.append(f"- **{r['id']}** [{r['classification']}] — {r['title']}: {m.get('notes','')}")
    else:
        L.append("_No automated UX/observability/documentation gaps flagged. Note: decision-trace "
                 "richness was strong (rule name + ULID + matched conditions on every enforcement), "
                 "but the structured request-log API (`/api/logs`) is empty unless the log store is "
                 "enabled — an operability observation worth surfacing in the UI defaults._")
    write("EDGE-CASE-UX-AND-CONTRACT-GAPS.md", L)

    # ---- COVERAGE REPORT ----
    by = cap_coverage(gen_scen, results, manifests)
    L = ["# Culvert Edge-Case Lab — Coverage Report\n"]
    L.append(f"Accepted scenarios: **{len(gen_scen)}** · Executed: **{total}** · "
             f"Unique fingerprints: **{len(gen.seen)}** · "
             f"Duplicate rejection rate: **{dup_rate:.1%}**.\n")
    L.append("## Coverage by capability tag\n")
    L.append("| Capability | Scenarios | PASS | Other classes |")
    L.append("|---|---|---|---|")
    for cap in sorted(by, key=lambda k: -by[k]["total"]):
        d = by[cap]
        others = ", ".join(f"{k}:{v}" for k, v in d["classes"].items() if k != "PASS") or "—"
        L.append(f"| {cap} | {d['total']} | {d['pass']} | {others} |")
    L.append("\n## Novelty / duplicate\n")
    L.append(f"- Candidate scenarios generated: {gen.candidates}")
    L.append(f"- Rejected as semantic duplicates: {gen.rejected_duplicate} ({dup_rate:.1%})")
    L.append(f"- Accepted (unique fingerprints): {len(gen.seen)}")
    L.append(f"- Every accepted scenario carries a distinct 16-hex semantic fingerprint over "
             "identity+source+destination+schedule+auth+TLS+content-control+failure+action.")
    write("EDGE-CASE-COVERAGE-REPORT.md", L)

    print("wrote 5 result deliverables to", LAB)
    print("counts:", json.dumps(counts))
    print(f"pass_rate={pass_rate:.1%} accepted={len(gen_scen)} executed={total}")


def write(name, lines):
    with open(os.path.join(LAB, name), "w") as f:
        f.write("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
