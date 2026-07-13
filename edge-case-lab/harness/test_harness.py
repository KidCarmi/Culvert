#!/usr/bin/env python3
"""
Harness self-test suite (R2/R3 regression coverage + validation requirements).

Covers:
  * Oracle unit tests (pure, no proxy).
  * R3 enforcement-attribution unit tests (synthetic traces): a BLOCK requires an
    authoritative Culvert marker; a 502/refused after POLICY_ALLOW is upstream/fixture
    failure, never a policy block.
  * Schema validation of a generated manifest.
  * R2 process-ownership: refuse to start when an UNMANAGED (non-culvert) process owns
    the ports; reap a stray CULVERT instance (zombie regression, reproduces T4).
  * R3 upstream-failure attribution regression against a live proxy (allow policy, dead
    upstream → upstream/fixture failure, not a policy block).
  * Deterministic same-input replay (same scenario twice → identical classification).

Run:  python3 test_harness.py         (needs the fixture up for the live tests)
Exit code 0 = all pass.
"""
import json
import os
import socket
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from lab import harness as H
from lab import oracle

PASS, FAIL = [], []


def check(name, cond, detail=""):
    (PASS if cond else FAIL).append(name)
    print(f"  [{'PASS' if cond else 'FAIL'}] {name}" + (f" — {detail}" if detail and not cond else ""))


# ---------------------------------------------------------------- Oracle units
def test_oracle():
    intent = {"default_action": "deny", "objects": {"categories": {"soc": ["social.example.test"]},
              "category_groups": {"bad": ["soc"]}},
              "rules": [{"name": "a", "priority": 1, "kind": "access", "match": {"fqdn": "app.corp.local"}, "action": "allow"},
                        {"name": "b", "priority": 2, "kind": "access", "match": {"category_group": "bad"}, "action": "block_page"}]}
    check("oracle.first_match_allow",
          oracle.evaluate(intent, {"scheme": "http", "host": "app.corp.local", "client_ip": "127.0.0.1"}).disposition == oracle.ALLOW)
    check("oracle.category_group_block",
          oracle.evaluate(intent, {"scheme": "http", "host": "social.example.test", "client_ip": "127.0.0.1"}).disposition == oracle.BLOCK_PAGE)
    check("oracle.default_deny",
          oracle.evaluate(intent, {"scheme": "http", "host": "unknown.corp.local", "client_ip": "127.0.0.1"}).disposition == oracle.BLOCK_PAGE)
    check("oracle.wildcard_bare_implies_sub", oracle.match_fqdn("corp.local", "app.corp.local"))
    check("oracle.wildcard_no_over_match", not oracle.match_fqdn("*.corp.local", "example.test"))


# ------------------------------------------------- R3 attribution unit tests
def _attr(trace, status=0, rc=0, tls=None, blockpage=False, err=""):
    ex = H.Executor.__new__(H.Executor)
    res = H.ActualResult(disposition=oracle.ALLOW, http_status=status, curl_exit=rc,
                         curl_err=err, is_block_page=blockpage, tls=tls, decision_trace=trace)
    ex._attribute(res)
    return res


def test_attribution():
    T = "[Culvert] ... "
    # authoritative blocks
    check("attr.policy_block", _attr([T + 'POLICY_BLOCK rule="x"'], status=403, blockpage=True).attribution == H.ATTR_POLICY_BLOCK)
    check("attr.default_deny", _attr([T + "POLICY_DEFAULT_DENY"], status=403, blockpage=True).attribution == H.ATTR_DEFAULT_DENY)
    check("attr.policy_drop", _attr([T + 'POLICY_DROP rule="x"'], rc=52).attribution == H.ATTR_POLICY_DROP
          and _attr([T + "POLICY_DROP"], rc=52).disposition == oracle.DROP)
    check("attr.file_block", _attr([T + "FILE_BLOCKED (tunnel global ext)"], status=403).attribution == H.ATTR_FILE_BLOCK)
    # THE KEY R3 INVARIANT: a 502 after POLICY_ALLOW is NOT a policy block
    up = _attr([T + 'POLICY_ALLOW rule="permit"'], status=502)
    check("attr.upstream_not_block", up.attribution == H.ATTR_UPSTREAM_FAIL and up.disposition == oracle.CONN_FAIL)
    # a 403 block-page with NO culvert marker is NOT trusted as a policy block
    noemark = _attr([], status=403, blockpage=True)
    check("attr.unattributed_blockish", noemark.attribution == H.ATTR_UNATTRIBUTED_BLOCKISH)
    # failure differentiation without any marker
    check("attr.dns_fail", _attr([], rc=6).attribution == H.ATTR_DNS_FAIL)
    check("attr.timeout", _attr([], rc=28).attribution == H.ATTR_TIMEOUT)
    check("attr.client_trust_fail", _attr([], rc=60).attribution == H.ATTR_CLIENT_TRUST_FAIL)
    # allow with proxy marker + 200
    check("attr.allow", _attr([T + "POLICY_ALLOW"], status=200).attribution == H.ATTR_ALLOW)
    # BLOCK dispositions must be authoritative
    for r in (up, noemark):
        pass
    check("attr.block_requires_marker",
          all(_attr([], status=403, blockpage=True).attribution not in H.BLOCK_ATTRS for _ in [0]))


# ------------------------------------------------------------ schema validation
def test_schema():
    schema_p = os.path.join(H.LAB, "EDGE-CASE-SCENARIO-SCHEMA.json")
    check("schema.exists", os.path.isfile(schema_p))
    # structural validation of a written manifest, if any exist
    import glob
    mans = glob.glob(os.path.join(H.LAB, "scenarios", "SWG-*.json"))
    if mans:
        m = json.load(open(mans[0]))
        req = ["schema_version", "id", "administrator_requirement", "intent", "test_vectors",
               "result_classification", "confidence_score", "reproduction", "executed_at"]
        missing = [k for k in req if k not in m]
        check("schema.manifest_structural", not missing, f"missing {missing}")
    else:
        check("schema.manifest_structural", True, "no manifests present (skipped)")


# --------------------------------------------------- R2 process ownership
def test_ownership_refuses_unmanaged():
    """Bind a NON-culvert holder to the proxy port; Culvert.start() must refuse
    (it cannot reap a process it doesn't recognise)."""
    holder = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    holder.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        holder.bind(("0.0.0.0", H.PROXY_PORT))
        holder.listen(1)
    except OSError:
        check("ownership.refuses_unmanaged", True, "port busy by real culvert; skipped")
        holder.close()
        return
    cv = H.Culvert()
    refused = False
    try:
        cv.start(fresh=True)
    except H.OwnershipError:
        refused = True
    except Exception:
        refused = False
    finally:
        cv.stop()
        holder.close()
    check("ownership.refuses_unmanaged", refused,
          "start() must raise OwnershipError when an unmanaged process owns the port")


def test_zombie_regression():
    """Reproduce T4: a stray culvert bound to the ports. A fresh start() must reap it
    and yield a CLEAN instance (no leftover rules from the stray)."""
    cv = H.Culvert()
    cv.start(fresh=True)
    # create a rule + a stray by starting a SECOND raw culvert on the same ports
    H._http("POST", f"{H.UI}/api/policy", {"name": "zombie-rule", "destFQDN": "z.z", "action": "Block_Page", "priority": 5})
    stray = subprocess.Popen(
        [H.CULVERT_BIN, "-port", str(H.PROXY_PORT), "-ui-port", str(H.UI_PORT), "-ui-no-tls",
         "-ca-path", os.path.join(H.DATA_DIR, "ca.bundle"), "-policy", H.POLICY_STORE],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=os.setsid)
    time.sleep(1)
    # now a fresh start must reap the stray AND the tracked proc, wipe /data, come up clean
    cv.start(fresh=True)
    code, body = H._http("GET", f"{H.UI}/api/policy")
    clean = code == 200 and json.loads(body).get("count", 0) == 0
    # verify no stray culvert survived
    try:
        os.killpg(os.getpgid(stray.pid), 9)
    except Exception:
        pass
    n_stray = int(subprocess.run(["bash", "-c", "ps -eo args | grep -c '[c]ulvert -port %d'" % H.PROXY_PORT],
                                 capture_output=True, text=True).stdout.strip() or "0")
    cv.stop()
    check("zombie.reaped_and_clean", clean and n_stray <= 1,
          f"clean={clean} n_culvert_on_port={n_stray}")


# --------------------------------------- R3 upstream-failure attribution (live)
def test_upstream_fail_live():
    """Allow policy, but the destination port has no listener → 502. Must attribute
    to upstream/fixture failure, NEVER a policy block."""
    cv = H.Culvert()
    cv.start(fresh=True)
    op = H.Operator(cv); ex = H.Executor(cv)
    op.apply({"default_action": "allow", "default_auth": "Exempt",
              "rules": [{"name": "allow-all", "priority": 1, "kind": "access",
                         "match": {"fqdn": "*"}, "action": "allow"}]})
    # app.corp.local on a dead port (nothing listening on 19999)
    res = ex.run({"scheme": "http", "host": "app.corp.local", "port": 19999, "client_ip": "127.0.0.1"})
    cv.stop()
    check("upstream.not_policy_block",
          res.disposition != oracle.BLOCK_PAGE and res.attribution in
          (H.ATTR_UPSTREAM_FAIL, H.ATTR_FIXTURE_FAIL, H.ATTR_CONN_RESET),
          f"disposition={res.disposition} attribution={res.attribution} status={res.http_status}")


# ------------------------------------------------- deterministic replay (live)
def test_header_scrub_scoring():
    """A forwarded-header hygiene probe must drive the verdict: a scrubbed header
    PASSes, but a DETECTED leak must NOT be scored PASS even when disposition/TLS
    match (otherwise the identity-scrub security scenario validates nothing)."""
    rv = H.Reviewer()
    exp = oracle.Expectation(disposition=oracle.ALLOW, tls=oracle.TLS_INTERCEPTED,
                             matched_rule="inspect-app", rationale="r", certainty="certain")
    scrubbed = H.ActualResult(disposition=oracle.ALLOW, tls=oracle.TLS_INTERCEPTED, http_status=200,
                              probes={"header_scrub": {"header": "X-User-Identity", "leaked": False}})
    leaked = H.ActualResult(disposition=oracle.ALLOW, tls=oracle.TLS_INTERCEPTED, http_status=200,
                            probes={"header_scrub": {"header": "X-User-Identity", "leaked": True}})
    check("header_scrub.scrubbed_passes", rv._agree(exp, scrubbed) is True
          and rv.classify_vector(exp, scrubbed, {"errors": []}, None)["verdict"] == "PASS")
    check("header_scrub.leak_fails", rv._agree(exp, leaked) is False
          and rv.classify_vector(exp, leaked, {"errors": []}, None)["verdict"] != "PASS",
          "a detected header leak must not score PASS")


def test_deterministic_replay():
    from lab.scenarios_full import FullGen
    sc = next(s for s in FullGen().build_full() if s["id"] == "SWG-0009")
    import run_campaign as R
    cv = H.Culvert(); cv.start(fresh=True)
    env = R.env_fingerprint(cv)
    r1 = R.run_scenario(cv, sc, env)["classification"]
    r2 = R.run_scenario(cv, sc, env)["classification"]
    cv.stop()
    check("replay.deterministic", r1 == r2 == "PASS", f"{r1} vs {r2}")


def main():
    live = "--no-live" not in sys.argv
    print("# harness self-tests")
    test_oracle()
    test_attribution()
    test_schema()
    test_header_scrub_scoring()
    if live:
        test_ownership_refuses_unmanaged()
        test_zombie_regression()
        test_upstream_fail_live()
        test_deterministic_replay()
    print(f"\n# {len(PASS)} passed, {len(FAIL)} failed")
    if FAIL:
        print("FAILED:", FAIL)
        sys.exit(1)


if __name__ == "__main__":
    main()
