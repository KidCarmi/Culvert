#!/usr/bin/env python3
"""Deterministic migration checks. This is not a client or model-behavior test.

Run from any directory; the repository root is derived from this file. CI runs
``--self-test --diff-base <PR base>`` from the Fast PR Gate's ``docs-guidance``
job whenever a registered guidance path changes (see pr-fast-gate.yml).
"""
import argparse
import hashlib
import json
import re
import subprocess
import tempfile
from pathlib import Path

BASE = "3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af"
BLOB = "84e5b5c06e3972862f6ce2c75dce128a5635cddb"
DIGEST = "d52076cca7e76045e31000e4abe89d3b0262ed28d1e82a2c20a7f95d0f06853c"
SIZE = 464534
CTX = "docs/agent-context/"
CONVENTIONS = CTX + "conventions.md"
BLOCK = re.compile(rb"<!-- BEGIN preserved-block: ([^\n]+) -->\n(.*?)<!-- END preserved-block: \1 -->\n", re.S)
LINK = re.compile(r"\[[^\]\n]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")
IMPORT = re.compile(r"(?<!\w)@([A-Za-z0-9_./~-]+)")
# Every automatically discovered guidance file. A nested AGENTS.md/CLAUDE.md or
# a native skill that is not registered here fails validation, so the import
# wall and the load budgets below can never be bypassed by adding a file.
GUIDES = ("AGENTS.md", "CLAUDE.md", "internal/admission/AGENTS.md", "internal/admission/CLAUDE.md")
# The ONLY eager imports each Claude adapter may carry, in order, as repository
# paths after resolving the adapter's relative `@path`. Exact lists, never a
# count: a second adapter line that imports an unreviewed document is an eager
# load of that document in every Claude session.
EAGER_IMPORTS = {
    "CLAUDE.md": ["AGENTS.md", CONVENTIONS],
    "internal/admission/CLAUDE.md": ["internal/admission/AGENTS.md"],
}
# Documents that terminate the import chain: nothing they contain may import.
NO_IMPORTS = ("AGENTS.md", "internal/admission/AGENTS.md", CONVENTIONS)
SKILLS = {"culvert-verify": "verification.md", "culvert-review": "review-change.md"}
GUIDANCE_NAMES = {"AGENTS.md", "CLAUDE.md", "AGENTS.override.md"}
SKILL_RE = re.compile(r"\.(?:agents|claude)/skills/([^/]+)/SKILL\.md")
ROOT_BUDGET = 8192          # root AGENTS.md alone (shared Codex/Claude core)
CLAUDE_EAGER_BUDGET = 16384  # CLAUDE.md + AGENTS.md + conventions.md, loaded in every Claude session
CHAIN_BUDGET = 32768         # every registered guide + the eager conventions (Codex aggregate default)


def need(value, message):
    """Reject an invariant violation with a reviewable diagnostic."""
    if not value:
        raise ValueError(message)


def clean_text(path):
    """Exclude immutable source blocks when checking authored navigation."""
    return BLOCK.sub(b"", path.read_bytes()).decode()


def anchors(text):
    """Collect explicit anchors and GitHub-style heading anchors."""
    result = set(re.findall(r'<a\s+id="([^"]+)"', text))
    counts = {}
    for line in text.splitlines():
        if not re.match(r"^#{1,6} ", line):
            continue
        title = re.sub(r"^#+ | +#+$", "", line).strip().lower()
        title = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        count = counts.get(title, 0)
        counts[title] = count + 1
        result.add(title + (f"-{count}" if count else ""))
    return result


def resolve(root, source, link):
    """Resolve a checked relative link within the repository boundary."""
    path, _, anchor = link.partition("#")
    target = ((root / source).parent / path).resolve() if path else (root / source).resolve()
    need(target.is_relative_to(root.resolve()), f"Link escapes checkout: {source}: {link}")
    need(target.exists(), f"Missing link: {source}: {link}")
    if anchor and target.is_file() and target.suffix == ".md":
        need(anchor in anchors(target.read_text()), f"Missing anchor: {source}: {link}")
    return target.relative_to(root.resolve()).as_posix()


def section_text(text, anchor):
    """Select one authored heading body, excluding later sibling/child headings."""
    lines = text.splitlines(keepends=True)
    matches = []
    counts = {}
    for index, line in enumerate(lines):
        if not re.match(r"^#{1,6} ", line):
            continue
        title = re.sub(r"^#+ | +#+$", "", line).strip().lower()
        title = re.sub(r"[^\w\- ]", "", title).replace(" ", "-")
        count = counts.get(title, 0)
        counts[title] = count + 1
        matches.append((index, title + (f"-{count}" if count else "")))
    for pos, (start, name) in enumerate(matches):
        if name == anchor:
            end = matches[pos + 1][0] if pos + 1 < len(matches) else len(lines)
            return "".join(lines[start + 1:end])
    raise ValueError(f"Missing route source section: {anchor}")


def route_reaches_block(root, block, route):
    """Require the task section to reach the exact block directly or via its TOC."""
    source = route["source"]
    section = section_text(clean_text(root / source), route["section"])
    for link in LINK.findall(section):
        if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", link):
            continue
        if resolve(root, source, link) != block["destination"]:
            continue
        anchor = link.partition("#")[2]
        if anchor == block["anchor"]:
            return True
        if anchor:
            continue  # Another block in the same history is not this block.
        # A bucket route is valid only if its authored TOC links to this block.
        topics = section_text(clean_text(root / block["destination"]), "topics")
        if "#" + block["anchor"] in LINK.findall(topics):
            return True
    return False


def imports_of(root, relative):
    """Return the eager @imports a guidance document carries, resolved to repo paths."""
    found = []
    base = (root / relative).parent
    for raw in IMPORT.findall((root / relative).read_text()):
        target = (base / raw).resolve()
        need(target.is_relative_to(root.resolve()), f"Import escapes checkout: {relative}: @{raw}")
        found.append(target.relative_to(root.resolve()).as_posix())
    return found


def check_imports(root):
    """Exact adapter imports; terminal documents import nothing; targets exist."""
    for adapter, want in EAGER_IMPORTS.items():
        got = imports_of(root, adapter)
        need(got == want, f"Unexpected eager imports: {adapter}: {got} != {want}")
        for target in want:
            need((root / target).is_file(), f"Eager import target missing: {adapter}: {target}")
            need(target in NO_IMPORTS, f"Eager import target is not a terminal document: {adapter}: {target}")
    for terminal in NO_IMPORTS:
        got = imports_of(root, terminal)
        need(not got, f"Transitive eager import: {terminal}: {got}")


def discovered_guidance(root):
    """Every guidance-shaped file in the checkout, whether registered or not."""
    skip = {".git", "node_modules", "__pycache__"}
    found = set()
    for path in root.rglob("*"):
        if not path.is_file() or skip & set(path.relative_to(root).parts):
            continue
        relative = path.relative_to(root).as_posix()
        if path.name in GUIDANCE_NAMES or SKILL_RE.fullmatch(relative) or relative.startswith(".claude/rules/"):
            found.add(relative)
    return found


def registered_skill_paths():
    """Both native copies of every registered skill."""
    return {f".{tree}/skills/{name}/SKILL.md" for tree in ("agents", "claude") for name in SKILLS}


def is_guidance_shaped(path):
    """Would a client or this checker treat the path as agent guidance?"""
    return (Path(path).name in GUIDANCE_NAMES or path.startswith(CTX) or bool(SKILL_RE.fullmatch(path))
            or path.startswith(".claude/rules/"))


def is_registered_guidance(path):
    """Is the guidance path one this checker validates?"""
    return path in GUIDES or path.startswith(CTX) or path in registered_skill_paths()


def check_scope(changed, instruction_only):
    """Per-PR scope rule over a changed-path set; returns the guidance paths touched.

    Every changed guidance-shaped path must be registered (a new nested guide or
    skill is refused until check.py registers it). With instruction_only, every
    changed path must be registered guidance — the migration PR's own posture.
    """
    guidance = sorted(p for p in changed if is_guidance_shaped(p))
    for path in guidance:
        need(is_registered_guidance(path), f"Unregistered guidance change: {path}")
    if instruction_only:
        for path in sorted(changed):
            need(path in guidance, f"Out-of-scope change: {path}")
    return guidance


def changed_paths(root, diff_base):
    """Include tracked differences and task-local untracked files; refuse a bad base."""
    try:
        subprocess.run(["git", "rev-parse", "--verify", "--quiet", f"{diff_base}^{{commit}}"],
                       cwd=root, check=True, capture_output=True)
        tracked = subprocess.check_output(["git", "diff", "--name-only", diff_base, "--"], cwd=root, text=True).splitlines()
        untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=root, text=True).splitlines()
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise ValueError(f"Diff base is not a resolvable commit in this checkout: {diff_base}") from exc
    return set(tracked + untracked)


def validate(root, diff_base=None, instruction_only=False):
    """Check frozen provenance, current routes, discovery structure and scope."""
    ledger = json.loads((root / CTX / "preservation-map.json").read_text())
    need((ledger["baseline"], ledger["source_git_blob"], ledger["source_sha256"], ledger["source_bytes"]) ==
         (BASE, BLOB, DIGEST, SIZE), "Pinned provenance changed")
    found = {}
    for path in (root / CTX / "history").glob("*.md"):
        raw = path.read_bytes()
        matches = list(BLOCK.finditer(raw))
        need(len(matches) == raw.count(b"<!-- BEGIN preserved-block:"), f"Malformed block in {path}")
        need(len(matches) == raw.count(b"<!-- END preserved-block:"), f"Malformed end marker in {path}")
        for match in matches:
            name = match[1].decode()
            need(name not in found, f"Duplicate source owner: {name}")
            found[name] = (path.relative_to(root).as_posix(), match[2])
    rebuilt = bytearray()
    next_line = 1
    ids = set()
    for block in ledger["blocks"]:
        name = block["id"]
        need(name not in ids, f"Duplicate ledger id: {name}")
        ids.add(name)
        need(block["start_line"] == next_line, f"Source gap/overlap: {name}")
        next_line = block["end_line"] + 1
        need(name in found, f"Missing source block: {name}")
        destination, raw = found[name]
        need(destination == block["destination"], f"Wrong owner: {name}")
        need(len(raw) == block["bytes"], f"Byte length mismatch: {name}")
        need(hashlib.sha256(raw).hexdigest() == block["sha256"], f"Block hash mismatch: {name}")
        need(len(raw.splitlines()) == block["end_line"] - block["start_line"] + 1, f"Line range mismatch: {name}")
        need(block["anchor"] in anchors((root / destination).read_text()), f"Missing block anchor: {name}")
        need(block["current_routes"], f"No current route declared: {name}")
        for route in block["current_routes"]:
            need((root / route["source"]).is_file(), f"Missing current route: {name}: {route}")
        rebuilt.extend(raw)
    need(ids == set(found) and len(ids) == 108 and next_line == 347, "Incomplete source inventory")
    need(len(rebuilt) == SIZE and hashlib.sha256(rebuilt).hexdigest() == DIGEST, "Full source reconstruction mismatch")
    git_blob = hashlib.sha1(b"blob " + str(len(rebuilt)).encode() + b"\0" + rebuilt).hexdigest()
    need(git_blob == BLOB, "Reconstructed Git blob mismatch")

    docs = list((root / CTX).rglob("*.md")) + [root / path for path in GUIDES]
    docs += list((root / ".agents/skills").rglob("SKILL.md")) + list((root / ".claude/skills").rglob("SKILL.md"))
    graph = {}
    link_count = 0
    for path in docs:
        source = path.relative_to(root).as_posix()
        text = clean_text(path)
        need(not re.search(r"/workspace/|/tmp/culvert-(?:audit|guidance-pr)", text), f"Private workspace path: {source}")
        graph[source] = set()
        for link in LINK.findall(text):
            if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", link):
                continue
            graph[source].add(resolve(root, source, link))
            link_count += 1

    route_edges = 0
    for block in ledger["blocks"]:
        for route in block["current_routes"]:
            need(route_reaches_block(root, block, route),
                 f"Broken declared route-to-block edge: {block['id']}: {route}")
            route_edges += 1

    for path in GUIDES + (CONVENTIONS,):
        need((root / path).is_file(), f"Missing native guide: {path}")
    check_imports(root)
    registered = set(GUIDES) | registered_skill_paths()
    for path in sorted(discovered_guidance(root)):
        need(path in registered, f"Unregistered guidance file (register it in check.py or remove it): {path}")
    for path in (root / CTX).rglob("*"):
        need(path.name not in GUIDANCE_NAMES, "History/docs must not be auto-discovered guidance")
    need(not (root / ".claude/rules").exists(), "Unexpected auto-loaded Claude rules")
    need(not (root / "AGENTS.override.md").exists(), "Root override shadows canonical guide")
    sizes = {path: (root / path).stat().st_size for path in GUIDES + (CONVENTIONS,)}
    claude_eager = sizes["CLAUDE.md"] + sizes["AGENTS.md"] + sizes[CONVENTIONS]
    need(sizes["AGENTS.md"] <= ROOT_BUDGET, "Root exceeds reviewed 8 KiB budget")
    need(claude_eager <= CLAUDE_EAGER_BUDGET, "Claude root eager chain exceeds reviewed 16 KiB budget")
    need(sum(sizes.values()) < CHAIN_BUDGET, "Root plus admission adapter chain exceeds 32 KiB")

    for name, workflow in SKILLS.items():
        a = root / f".agents/skills/{name}/SKILL.md"
        c = root / f".claude/skills/{name}/SKILL.md"
        need(a.is_file() and c.is_file(), f"Missing native skill copy: {name}")
        need(a.read_bytes() == c.read_bytes(), f"Native skill drift: {name}")
        text = a.read_text()
        need(text.startswith(f"---\nname: {name}\ndescription: "), f"Invalid skill metadata: {name}")
        need(text.count("---\n") == 2, f"Invalid skill frontmatter: {name}")
        need(f"docs/agent-context/workflows/{workflow}" in text and "Read " in text, f"Missing canonical read: {name}")
        need("does not grant permission" in text, f"Missing scope boundary: {name}")

    cases = json.loads((root / CTX / "routing-cases.json").read_text())
    for case in cases:
        entry, target = case["entry"], case["route"].split("#")[0]
        via = case.get("via")
        if via:
            need(via in graph[entry] and target in graph[via], f"Broken two-step route: {case['id']}")
        else:
            need(target in graph[entry], f"Broken direct route: {case['id']}")
        if "#" in case["route"]:
            need(case["route"].split("#")[1] in anchors((root / target).read_text()), f"Missing case anchor: {case['id']}")
        for phrase in case["must_contain"]:
            need(phrase in (root / target).read_text(), f"Missing case evidence: {case['id']}: {phrase}")

    changed = changed_paths(root, diff_base) if diff_base else set()
    guidance_changed = check_scope(changed, instruction_only) if diff_base else []
    return bytes(rebuilt), {"blocks": len(ids), "source_bytes": len(rebuilt), "git_blob": git_blob,
        "checked_navigation_links": link_count, "declared_route_edges": route_edges, "static_route_cases": len(cases),
        "diff_base_checked": diff_base, "instruction_only": instruction_only if diff_base else None,
        "changed_paths": len(changed) if diff_base else None, "changed_guidance_paths": guidance_changed if diff_base else None,
        "root_bytes": sizes["AGENTS.md"], "codex_root_admission_bytes": sizes["AGENTS.md"] + sizes["internal/admission/AGENTS.md"],
        "claude_root_eager_bytes": claude_eager,
        "claude_root_admission_eager_bytes": claude_eager + sizes["internal/admission/AGENTS.md"] + sizes["internal/admission/CLAUDE.md"],
        "registered_guides_plus_conventions_bytes": sum(sizes.values()),
        "kind": "static integrity only; client behavior not tested"}


def self_test(root):
    """Reject damaged candidates and retain future-baseline compatibility."""
    mutations = [
        (CTX + "history/admission-and-connection-limits.md", b"RATE_LIMITED", b"RATE_LIMITeD"),
        ("CLAUDE.md", b"@AGENTS.md", b"@docs/agent-context/history/conventions.md"),
        ("CLAUDE.md", b"@docs/agent-context/conventions.md", b"@docs/agent-context/conventions.md\n@docs/agent-context/README.md"),
        ("AGENTS.md", b"# Culvert contributor guide", b"# Culvert contributor guide\nRead @docs/agent-context/history/conventions.md now."),
        (CONVENTIONS, b"# Current implementation conventions", b"# Current implementation conventions\nRead @docs/agent-context/history/conventions.md now."),
        ("AGENTS.md", b"docs/agent-context/domains/admission.md", b"docs/agent-context/domains/missing.md"),
        (CTX + "README.md", b"[proxy/TLS history](history/proxy-tls-and-certificates.md)", b"[proxy/TLS history](history/scanning.md)"),
        (CTX + "history/proxy-tls-and-certificates.md", b"(#claude-main-l175-l175)", b"(#claude-main-l176-l176)"),
        (".claude/skills/culvert-verify/SKILL.md", b"verification.md", b"review-change.md"),
        ("AGENTS.md", b"# Culvert contributor guide", b"x" * 8192 + b"\n# Culvert contributor guide"),
    ]
    # Each candidate is a full lightweight checkout copy to keep tests hermetic.
    import shutil
    with tempfile.TemporaryDirectory(prefix="culvert-guidance-check-") as tmp:
        candidate = Path(tmp) / "candidate"
        shutil.copytree(root, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__", "node_modules"))
        for relative, old, new in mutations:
            path = candidate / relative
            before = path.read_bytes()
            need(old in before, f"Negative-control fixture missing: {relative}")
            path.write_bytes(before.replace(old, new, 1))
            try:
                validate(candidate)
            except ValueError:
                pass
            else:
                raise ValueError(f"Negative control was not rejected: {relative}")
            finally:
                path.write_bytes(before)
        # Duplicate and missing historical ownership controls.
        p = candidate / CTX / "history/architecture-index.md"
        before = p.read_bytes()
        match = BLOCK.search(before)
        for raw in (before + match[0], before.replace(match[0], b"", 1)):
            p.write_bytes(raw)
            try:
                validate(candidate)
            except ValueError:
                pass
            else:
                raise ValueError("Historical ownership negative control was not rejected")
        p.write_bytes(before)
        # An unregistered nested guide and an unregistered skill must be refused.
        for relative in ("internal/connlimit/AGENTS.md", ".claude/skills/culvert-deploy/SKILL.md"):
            stray = candidate / relative
            stray.parent.mkdir(parents=True, exist_ok=True)
            stray.write_text("# Unreviewed guidance\n")
            try:
                validate(candidate)
            except ValueError:
                pass
            else:
                raise ValueError(f"Unregistered guidance negative control was not rejected: {relative}")
            finally:
                stray.unlink()
        # Ordinary later source work must not change frozen-source integrity.
        source = candidate / "proxy.go"
        source.write_bytes(source.read_bytes() + b"\n// Unrelated future-runtime fixture.\n")
        validate(candidate)
        # Scope rule: a mixed PR passes the standing gate; only --instruction-only
        # refuses it; an unregistered guidance change is refused in both modes.
        mixed = {"proxy.go", "AGENTS.md", CTX + "domains/admission.md"}
        need(check_scope(mixed, False) == ["AGENTS.md", CTX + "domains/admission.md"], "Scope rule miscounts guidance")
        for changed, instruction_only in ((mixed, True), ({"internal/connlimit/AGENTS.md"}, False)):
            try:
                check_scope(changed, instruction_only)
            except ValueError:
                pass
            else:
                raise ValueError(f"Scope negative control was not rejected: {sorted(changed)} instruction_only={instruction_only}")
        # A future PR compares with its chosen base, not the migration base.
        fixture = Path(tmp) / "future-git"
        fixture.mkdir()
        def git(*args):
            """Run Git only in the disposable future-history fixture."""
            return subprocess.check_output(["git", *args], cwd=fixture, stderr=subprocess.DEVNULL, text=True).strip()
        git("init", "-q")
        (fixture / "proxy.go").write_text("package main\n")
        git("add", "proxy.go")
        git("-c", "user.name=Static check fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Initial fixture")
        (fixture / "proxy.go").write_text("package main\n// Later runtime commit\n")
        git("add", "proxy.go")
        git("-c", "user.name=Static check fixture", "-c", "user.email=fixture@example.invalid", "commit", "-qm", "Later runtime fixture")
        future_base = git("rev-parse", "HEAD")
        (fixture / "AGENTS.md").write_text("Guidance edit\n")
        need(changed_paths(fixture, future_base) == {"AGENTS.md"}, "Future runtime commit contaminated per-PR diff")
        # An unresolvable base is an explicit failure, never a silent empty diff.
        try:
            changed_paths(fixture, "0" * 40)
        except ValueError:
            pass
        else:
            raise ValueError("Unresolvable diff base was not rejected")
    return {"negative_controls_rejected": len(mutations) + 2 + 2 + 2 + 1, "future_baseline_controls_passed": 2}


def main():
    """Run integrity checks and optional reconstruction/regression fixtures."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reconstruct", type=Path, help="Write reconstructed original bytes to this path")
    parser.add_argument("--diff-base", help="PR/task base commit: every changed guidance-shaped path must be registered; independent of frozen source provenance")
    parser.add_argument("--instruction-only", action="store_true", help="With --diff-base: refuse any changed path that is not registered guidance (the migration PR posture)")
    parser.add_argument("--self-test", action="store_true", help="Verify corruption, routing, import, discovery and scope negative controls")
    args = parser.parse_args()
    if args.instruction_only and not args.diff_base:
        parser.error("--instruction-only requires --diff-base")
    root = Path(__file__).resolve().parents[2]
    rebuilt, result = validate(root, args.diff_base, args.instruction_only)
    if args.reconstruct:
        args.reconstruct.write_bytes(rebuilt)
    if args.self_test:
        result.update(self_test(root))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
