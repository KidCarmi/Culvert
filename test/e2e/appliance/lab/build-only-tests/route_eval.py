"""Evaluate every job-level `if:` of a workflow for given events (static).
Supports the subset used: contains(), ==, !=, !, &&, ||, (), string literals,
github.event_name, github.event.head_commit.message, inputs.route, github.ref.
contains() is case-insensitive like GitHub's; null coerces to ''."""
import re, sys, yaml

TOK = re.compile(r"\s*(\(|\)|&&|\|\||==|!=|!|,|'(?:[^']|'')*'|[A-Za-z_][\w.\-]*)")

def tokenize(s):
    pos, out = 0, []
    s = s.strip()
    while pos < len(s):
        m = TOK.match(s, pos)
        if not m: raise SyntaxError(s[pos:pos+30])
        out.append(m.group(1)); pos = m.end()
    return out

def evaluate(expr, ctx):
    toks = tokenize(expr); i = 0
    def peek(): return toks[i] if i < len(toks) else None
    def take(t=None):
        nonlocal i
        x = toks[i]; i += 1
        if t and x != t: raise SyntaxError(f"want {t} got {x}")
        return x
    def primary():
        t = peek()
        if t == "(":
            take("("); v = orx(); take(")"); return v
        if t == "!":
            take("!"); return not truthy(primary())
        if t.startswith("'"):
            take(); return t[1:-1].replace("''", "'")
        take()
        if t == "contains":
            take("("); a = orx(); take(","); b = orx(); take(")")
            return (str(b or "")).lower() in (str(a or "")).lower()
        if t in ("true", "false"): return t == "true"
        if t in ctx: return ctx[t]
        raise KeyError(t)
    def cmp():
        v = primary()
        while peek() in ("==", "!="):
            op = take(); w = primary()
            eq = (str(v).lower() if v is not None else "") == (str(w).lower() if w is not None else "")
            v = eq if op == "==" else not eq
        return v
    def andx():
        v = cmp()
        while peek() == "&&":
            take(); w = cmp(); v = truthy(v) and truthy(w)
        return v
    def orx():
        v = andx()
        while peek() == "||":
            take(); w = andx(); v = truthy(v) or truthy(w)
        return v
    v = orx()
    assert i == len(toks), toks[i:]
    return truthy(v)

def truthy(v): return bool(v)

def run(path, cases):
    d = yaml.safe_load(open(path))
    jobs = d["jobs"]
    bad = 0
    for name, ctx, want in cases:
        ran = []
        for j, v in jobs.items():
            cond = v.get("if", "success()")
            cond = re.sub(r"^\$\{\{\s*|\s*\}\}$", "", cond.strip())
            needs = v.get("needs")
            needs = [needs] if isinstance(needs, str) else (needs or [])
            ok = evaluate(cond, ctx)
            # a job whose `needs` did not run is skipped (no always() here)
            if ok and any(n not in ran for n in needs): ok = False
            if ok: ran.append(j)
        res = "PASS" if sorted(ran) == sorted(want) else "FAIL"
        bad += res == "FAIL"
        print(f"{res} {name}: runs={ran or 'nothing'}")
    return bad

if __name__ == "__main__":
    wf = sys.argv[1]; msg = sys.argv[2]
    def push(m): return {"github.event_name": "push", "github.event.head_commit.message": m, "inputs.route": None, "github.ref": "refs/heads/test/appliance-lab"}
    def disp(r): return {"github.event_name": "workflow_dispatch", "github.event.head_commit.message": None, "inputs.route": r, "github.ref": "refs/heads/test/appliance-lab"}
    cases = [
        ("preparation push (actual commit message)", push(msg), []),
        ("push [build-only] [lab-skip]", push("x [build-only] [lab-skip]"), []),
        ("push [lab-skip] [build-only] (order)", push("[lab-skip] y [build-only]"), []),
        ("push [BUILD-ONLY] [LAB-SKIP] (case)", push("[BUILD-ONLY] [LAB-SKIP]"), []),
        ("push [build-only] (the build route)", push("lab: run it [build-only]"), ["build-only"]),
        ("dispatch route=none (default)", disp("none"), []),
        ("dispatch route=build-only", disp("build-only"), ["build-only"]),
        ("dispatch route unset (API, no inputs)", disp(None), []),
        ("push untagged (legacy full route, unchanged)", push("lab: something"), ["guest-boot", "f-disk-1"]),
        ("push [lab-skip] alone", push("[lab-skip]"), []),
        ("push [preserve-image] (unchanged)", push("[preserve-image]"), ["preserve-image"]),
        ("push [fdisk-only] (unchanged)", push("[fdisk-only]"), ["f-disk-1"]),
    ]
    sys.exit(1 if run(wf, cases) else 0)
