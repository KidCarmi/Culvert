#!/usr/bin/env python3
"""Mutation campaign for the cross-path differential.

Each mutant is one exact-string edit of production code. For each one, in a scratch copy of
the tree, two things are run and compared:
  new       test/policy-pathdiff/run.sh              (this verifier)
  existing  go test . ./internal/hostutil/           (the full existing root and hostutil suites)
A mutant is "killed" by a side when that side exits non-zero. Nothing here touches the
working tree. Usage: mutants.py <repo> <workdir> [ids...]
"""
import json, os, shutil, subprocess, sys, time

M = [
 ("M01", "enforcement keeps the port on the host", "proxy.go",
  "\thost := r.Host\n\tif h, _, err := net.SplitHostPort(host); err == nil {\n\t\thost = h\n\t}\n", "\thost := r.Host\n"),
 ("M02", "tester matches the raw authority (port not stripped)", "ui_policy.go",
  "testHost := bareDestHost(body.Host)", "testHost := body.Host"),
 ("M03", "tester skips host normalisation", "ui_policy.go",
  "\t\tnormHost:   normalizeHost(host),\n\t\tgroups:     groups,\n\t}\n\tmatched := evalAccessRules(ptrs",
  "\t\tnormHost:   host,\n\t\tgroups:     groups,\n\t}\n\tmatched := evalAccessRules(ptrs"),
 ("M04", "enforcement skips host normalisation", "policy.go",
  "\t\tnormHost:   normalizeHost(host),\n\t\tgroups:     groups,\n\t}\n\trule := evalAccessRules(rules, scanIndexFor",
  "\t\tnormHost:   host,\n\t\tgroups:     groups,\n\t}\n\trule := evalAccessRules(rules, scanIndexFor"),
 ("M05", "bare-name match loses its label boundary", "internal/hostutil/hostutil.go",
  "return n > 0 && host[n-1] == '.' && host[n:] == pattern", "return n > 0 && host[n:] == pattern"),
 ("M06", "IPv4-mapped destination literal no longer unmapped", "policy_destliteral.go",
  "return addr.Unmap().String()", "return addr.String()"),
 ("M07", "bulk replace does not sort by priority", "policy.go",
  "\tps.rules = out\n\tps.sortLocked()\n\tps.bumpVersion()\n\tps.mu.Unlock()\n}\n\n// warnLoadedRule", "\tps.rules = out\n\tps.bumpVersion()\n\tps.mu.Unlock()\n}\n\n// warnLoadedRule"),
 ("M08", "enforcement-only prefilter wrongly rejects the second rule", "policy.go",
  "\t\tif pre.rejectsAt(i) {\n\t\t\tcontinue\n\t\t}\n\t\trule := rules[i]\n\t\tif !ruleIsEnabled(rule) {",
  "\t\tif pre.rejectsAt(i) || (trace == nil && i == 1) {\n\t\t\tcontinue\n\t\t}\n\t\trule := rules[i]\n\t\tif !ruleIsEnabled(rule) {"),
 ("M09", "disabled rules decide", "policy.go", "\t\tif !ruleIsEnabled(rule) {\n\t\t\tif trace != nil {\n\t\t\t\ttrace(rule, accessSkipDisabled)",
  "\t\tif false && !ruleIsEnabled(rule) {\n\t\t\tif trace != nil {\n\t\t\t\ttrace(rule, accessSkipDisabled)"),
 ("M10", "CONNECT skips the policy decision", "proxy.go",
  "\tmatch := policyStore.Evaluate(clientIP, authenticatedIdentity, authenticatedSource, host, authenticatedGroups)\n",
  "\tmatch := policyStore.Evaluate(clientIP, authenticatedIdentity, authenticatedSource, host, authenticatedGroups)\n\tif r.Method == http.MethodConnect {\n\t\tmatch = nil\n\t}\n"),
 ("M11", "identity compared case-sensitively", "policy.go",
  'idOK := rule.SourceIdentity == "" || strings.EqualFold(rule.SourceIdentity, identity)', 'idOK := rule.SourceIdentity == "" || rule.SourceIdentity == identity'),
 ("M12", "invalid-host refusal removed on enforcement", "proxy.go",
  "\tnormHost, ok := destNormHost, destNormOK\n\tif !ok {", "\tnormHost, ok := destNormHost, destNormOK\n\tif false && !ok {"),
 ("M13a", "source CIDR match no longer unmaps the client (first site)", "policy.go",
  ("FIRST", 'return err == nil && addr.Zone() == "" && p.Contains(addr.Unmap())'), 'return err == nil && addr.Zone() == "" && p.Contains(addr)'),
 ("M13b", "source CIDR match no longer unmaps the client (second site)", "policy.go",
  ("LAST", 'return err == nil && addr.Zone() == "" && p.Contains(addr.Unmap())'), 'return err == nil && addr.Zone() == "" && p.Contains(addr)'),
 ("M14", "group names no longer trimmed before comparison", "policy.go",
  "strings.EqualFold(strings.TrimSpace(g), name)", "strings.EqualFold(g, name)"),
 # M15-M17 each undo one of the three fixes this verifier led to (#2055, #2053, #2050).
 ("M15", "zoned IPv6 destinations are no longer refused", "proxy_host_bounds.go",
  "func destIPv6Zoned(authority string) bool {\n", "func destIPv6Zoned(authority string) bool {\n\tif true {\n\t\treturn false\n\t}\n"),
 ("M16", "tester matches the typed text again, not the parsed request target", "proxy_host_bounds.go",
  "func wireDestAuthority(input string) (authority string, ok bool) {\n", "func wireDestAuthority(input string) (authority string, ok bool) {\n\tif true {\n\t\treturn input, true\n\t}\n"),
 ("M17", "an unknown action resolves to Allow", "authpolicy.go",
  "\treturn \"\", false\n}\n\n// subjectSourceBreadth", "\treturn ActionAllow, true\n}\n\n// subjectSourceBreadth"),
]

def apply(root, f, old, new):
    p = os.path.join(root, f); s = open(p, encoding="utf-8").read()
    which = None
    if isinstance(old, tuple): which, old = old
    n = s.count(old)
    if n == 0 or (which is None and n != 1): raise SystemExit(f"{f}: pattern occurs {n} times")
    i = s.rfind(old) if which == "LAST" else s.find(old)
    open(p, "w", encoding="utf-8").write(s[:i] + new + s[i + len(old):])

def run(cmd, cwd, timeout):
    t = time.time()
    try:
        r = subprocess.run(cmd, cwd=cwd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.returncode, time.time() - t, (r.stdout + r.stderr)[-3000:]
    except subprocess.TimeoutExpired:
        return 124, time.time() - t, "TIMEOUT"

if __name__ == "__main__":
    repo, work = os.path.abspath(sys.argv[1]), os.path.abspath(sys.argv[2])
    ids = set(sys.argv[3:])
    os.makedirs(work, exist_ok=True)
    for mid, desc, f, old, new in M + [("CLEAN", "no edit (control)", "policy.go", "package main", "package main")]:
        if ids and mid not in ids: continue
        out = os.path.join(work, mid + ".json")
        if os.path.exists(out): continue
        tree = os.path.join(work, "tree_" + mid)
        shutil.rmtree(tree, ignore_errors=True)
        shutil.copytree(repo, tree, ignore=shutil.ignore_patterns(".git"))
        apply(tree, f, old, new)
        b = run("go build ./... ", tree, 900)
        res = {"id": mid, "desc": desc, "file": f, "builds": b[0] == 0}
        if b[0] == 0:
            n = run("test/policy-pathdiff/run.sh " + os.path.join(work, "rep_" + mid), tree, 1500)
            reasons = sorted({l.split(":")[0].strip() if "drift" not in l else ("drift(" + l.split("(")[1].split(")")[0] + ")" if "drift (" in l else "drift(signature)")
                              for l in open(os.path.join(work, "rep_" + mid, "pathdiff.log"), errors="replace").read().splitlines()
                              if "behaviour drift" in l or "vacuous" in l or "not live" in l} ) if os.path.exists(os.path.join(work, "rep_" + mid, "pathdiff.log")) else []
            if os.environ.get("MUTANTS_NEW_ONLY") == "1":  # verifier side only (about a minute per mutant)
                res.update(new_exit=n[0], new_secs=round(n[1]), new_reasons=reasons)
                json.dump(res, open(out, "w"), indent=1); shutil.rmtree(tree, ignore_errors=True)
                print(json.dumps(res), flush=True); continue
            elog = os.path.join(work, "existing_" + mid + ".log")
            e = run("go test -count=1 -timeout 40m . ./internal/hostutil/ > " + elog + " 2>&1", tree, 2700)
            fails = sorted({l.split()[2] for l in open(elog, errors="replace").read().splitlines() if l.strip().startswith("--- FAIL")})[:20]
            res.update(new_exit=n[0], new_secs=round(n[1]), new_reasons=reasons, existing_exit=e[0], existing_secs=round(e[1]), existing_failing=fails)
        json.dump(res, open(out, "w"), indent=1)
        shutil.rmtree(tree, ignore_errors=True)
        print(json.dumps(res), flush=True)
