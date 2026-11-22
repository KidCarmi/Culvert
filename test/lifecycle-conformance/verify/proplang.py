"""Model-agnostic property checker: state, transition and bounded-temporal properties.

A model provides:  inits() -> [state], events(state) -> [label], step(state, label) -> state,
                   observe(state) -> dict.   States must be hashable.
Property kinds (plain JSON data; this module only READS property files, never writes them):
  state      {"if": [atom..], "then": [atom..]}
  transition {"on": [event..]|null, "if": [atom..] (pre-state), "then": [atom..] (post-state)}
             post-state atoms may compare against the pre-state: [field, op, {"prev": field}]
  bounded    {"trigger": [atom..], "goal": [atom..], "within": k, "quantifier": "all"|"exists"}
             all   : every path from a trigger state reaches the goal within k steps
             exists: some path does
atom = [field, op, const] | [field, op, {"field": g}] | [field, op, {"prev": g}]
ops  = == != < <= > >= in notin
Verdicts: PASS, FAIL (with a shortest reproducing trace), VACUOUS (precondition never reached)."""
import time
from collections import deque

OPS = {"==": lambda a, b: a == b, "!=": lambda a, b: a != b, "<": lambda a, b: a < b, "<=": lambda a, b: a <= b,
       ">": lambda a, b: a > b, ">=": lambda a, b: a >= b, "in": lambda a, b: a in b, "notin": lambda a, b: a not in b}


class Incomplete(Exception):
    """Exploration could not be finished within the budget. Never treated as a pass."""


def _atom(a, obs, prev=None):
    f, op, rhs = a
    if isinstance(rhs, dict):
        rhs = prev[rhs["prev"]] if "prev" in rhs else obs[rhs["field"]]
    return OPS[op](obs[f], rhs)


def _all(atoms, obs, prev=None):
    return all(_atom(a, obs, prev) for a in atoms or [])


def validate(prop, fields):
    def atoms(lst, allow_prev):
        for a in lst or []:
            if not (isinstance(a, list) and len(a) == 3 and a[0] in fields and a[1] in OPS):
                raise ValueError(f"{prop.get('id')}: bad atom {a!r}")
            if isinstance(a[2], dict):
                k = set(a[2])
                if k not in ({"field"}, {"prev"}) or list(a[2].values())[0] not in fields or (k == {"prev"} and not allow_prev):
                    raise ValueError(f"{prop.get('id')}: bad reference in {a!r}")
    kind = prop.get("kind")
    if kind == "state":
        atoms(prop.get("if"), False), atoms(prop["then"], False)
    elif kind == "transition":
        atoms(prop.get("if"), False), atoms(prop["then"], True)
    elif kind == "bounded":
        atoms(prop["trigger"], False), atoms(prop["goal"], False)
        if prop["quantifier"] not in ("all", "exists") or not isinstance(prop["within"], int):
            raise ValueError(f"{prop.get('id')}: bad bounded property")
    else:
        raise ValueError(f"{prop.get('id')}: unknown kind {kind!r}")


def explore(model, max_states, deadline):
    """Complete breadth-first reachability or Incomplete. Returns (parents, succ)."""
    parents, succ, q = {}, {}, deque()
    for s in model.inits():
        if s not in parents:
            parents[s] = None
            q.append(s)
    while q:
        if time.monotonic() > deadline:
            raise Incomplete("time budget exhausted during exploration")
        s = q.popleft()
        out = []
        for e in model.events(s):
            t = model.step(s, e)
            out.append((e, t))
            if t not in parents:
                if len(parents) >= max_states:
                    raise Incomplete(f"more than {max_states} states")
                parents[t] = (s, e)
                q.append(t)
        succ[s] = out
    return parents, succ


def trace_to(parents, s):
    out = []
    while parents[s] is not None:
        s, e = parents[s]
        out.append(e)
    return out[::-1]


def check(model, props, max_states=200_000, max_seconds=60.0):
    """Returns (results, stats). Raises Incomplete if the state space was not fully explored."""
    deadline = time.monotonic() + max_seconds
    parents, succ = explore(model, max_states, deadline)
    obs = {s: model.observe(s) for s in parents}                 # dict order = BFS order
    fields = set(next(iter(obs.values())))
    results = []
    for p in props:
        validate(p, fields)
        r = {"id": p["id"], "kind": p["kind"], "status": p.get("status", "proposed"), "text": p.get("text", "")}
        if p["kind"] == "state":
            hit = [s for s in obs if _all(p.get("if"), obs[s])]
            bad = next((s for s in hit if not _all(p["then"], obs[s])), None)
            r.update(_verdict(parents, obs, hit, bad, None))
        elif p["kind"] == "transition":
            hit, bad = 0, None
            for s in obs:
                if not _all(p.get("if"), obs[s]):
                    continue
                for e, t in succ[s]:
                    if p.get("on") is not None and e not in p["on"]:
                        continue
                    hit += 1
                    if bad is None and not _all(p["then"], obs[t], obs[s]):
                        bad = (s, e, t)
            r.update(_verdict(parents, obs, hit, bad and bad[0], bad and [bad[1]], bad and bad[2]))
        else:
            hit = [s for s in obs if _all(p["trigger"], obs[s])]
            goal = {s for s in obs if _all(p["goal"], obs[s])}
            bad, tail = None, None
            for s in hit:
                tail = _escape(s, succ, goal, p["within"], p["quantifier"])
                if tail is not None:
                    bad = s
                    break
            r.update(_verdict(parents, obs, hit, bad, tail))
        results.append(r)
        if time.monotonic() > deadline:
            raise Incomplete("time budget exhausted while checking properties")
    return results, {"states": len(parents), "transitions": sum(len(v) for v in succ.values())}


def _escape(s, succ, goal, k, quantifier):
    """None if the bounded property holds from s; otherwise a witness path (event labels)."""
    if quantifier == "exists":
        seen, frontier = {s}, [s]
        for _ in range(k + 1):
            if any(x in goal for x in frontier):
                return None
            nxt = []
            for x in frontier:
                for _, t in succ[x]:
                    if t not in seen:
                        seen.add(t)
                        nxt.append(t)
            frontier = nxt
        return []

    def avoid(x, left):                      # a path of <= left steps that never meets the goal
        if x in goal:
            return None
        nexts = [(e, t) for e, t in succ[x] if t != x]
        if left == 0 or not nexts:
            return []
        for e, t in nexts:
            sub = avoid(t, left - 1)
            if sub is not None:
                return [e] + sub
        return None
    return avoid(s, k)


def _verdict(parents, obs, hit, bad, tail, final=None):
    if bad is not None:
        return {"verdict": "FAIL", "trace": trace_to(parents, bad) + (tail or []),
                "state": obs[final if final is not None else bad]}
    if not hit:
        return {"verdict": "VACUOUS"}
    return {"verdict": "PASS", "exercised": hit if isinstance(hit, int) else len(hit)}
