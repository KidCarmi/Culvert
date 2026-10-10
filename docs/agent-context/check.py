#!/usr/bin/env python3
"""Deterministic migration checks. This is not a client or model-behavior test."""
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
BLOCK = re.compile(rb"<!-- BEGIN preserved-block: ([^\n]+) -->\n(.*?)<!-- END preserved-block: \1 -->\n", re.S)
LINK = re.compile(r"\[[^\]\n]*\]\(([^\s)]+)(?:\s+[^)]*)?\)")
GUIDES = ("AGENTS.md", "CLAUDE.md", "internal/admission/AGENTS.md", "internal/admission/CLAUDE.md")


def need(value, message):
    if not value:
        raise ValueError(message)


def clean_text(path):
    return BLOCK.sub(b"", path.read_bytes()).decode()


def anchors(text):
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
    path, _, anchor = link.partition("#")
    target = ((root / source).parent / path).resolve() if path else (root / source).resolve()
    need(target.is_relative_to(root.resolve()), f"Link escapes checkout: {source}: {link}")
    need(target.exists(), f"Missing link: {source}: {link}")
    if anchor and target.is_file() and target.suffix == ".md":
        need(anchor in anchors(target.read_text()), f"Missing anchor: {source}: {link}")
    return target.relative_to(root.resolve()).as_posix()


def changed_paths(root, diff_base):
    tracked = subprocess.check_output(["git", "diff", "--name-only", diff_base, "--"], cwd=root, text=True).splitlines()
    untracked = subprocess.check_output(["git", "ls-files", "--others", "--exclude-standard"], cwd=root, text=True).splitlines()
    return set(tracked + untracked)


def validate(root, diff_base=None):
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
        for route in block["current_routes"]:
            need((root / route).is_file(), f"Missing current route: {name}: {route}")
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

    for path in GUIDES:
        need((root / path).is_file(), f"Missing native guide: {path}")
    for path in ("CLAUDE.md", "internal/admission/CLAUDE.md"):
        imports = re.findall(r"(?<!\w)@([A-Za-z0-9_./~-]+)", (root / path).read_text())
        need(imports == ["AGENTS.md"], f"Unexpected eager imports: {path}")
    for path in ("AGENTS.md", "internal/admission/AGENTS.md"):
        need(not re.search(r"(?<!\w)@[A-Za-z0-9_./~-]+", (root / path).read_text()), f"Unreviewed eager imports: {path}")
    for path in (root / CTX).rglob("*"):
        need(path.name not in ("AGENTS.md", "CLAUDE.md", "AGENTS.override.md"), "History/docs must not be auto-discovered guidance")
    need(not (root / ".claude/rules").exists(), "Unexpected auto-loaded Claude rules")
    need(not (root / "AGENTS.override.md").exists(), "Root override shadows canonical guide")
    sizes = {path: (root / path).stat().st_size for path in GUIDES}
    need(sizes["AGENTS.md"] <= 8192, "Root exceeds reviewed 8 KiB budget")
    need(sum(sizes.values()) < 32768, "Root plus admission adapter chain exceeds 32 KiB")

    skills = {"culvert-verify": "verification.md", "culvert-review": "review-change.md"}
    for name, workflow in skills.items():
        a = root / f".agents/skills/{name}/SKILL.md"
        c = root / f".claude/skills/{name}/SKILL.md"
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

    if diff_base:
        for path in changed_paths(root, diff_base):
            allowed = path in GUIDES or path.startswith(CTX) or bool(re.fullmatch(r"\.(?:agents|claude)/skills/culvert-(?:verify|review)/SKILL\.md", path))
            need(allowed, f"Out-of-scope change: {path}")
    return bytes(rebuilt), {"blocks": len(ids), "source_bytes": len(rebuilt), "git_blob": git_blob,
        "checked_navigation_links": link_count, "static_route_cases": len(cases),
        "diff_base_checked": diff_base, "root_bytes": sizes["AGENTS.md"], "codex_root_admission_bytes": sizes["AGENTS.md"] + sizes["internal/admission/AGENTS.md"],
        "claude_root_admission_with_adapters_bytes": sum(sizes.values()), "kind": "static integrity only; client behavior not tested"}


def self_test(root):
    mutations = [
        (CTX + "history/admission-and-connection-limits.md", b"RATE_LIMITED", b"RATE_LIMITeD"),
        ("CLAUDE.md", b"@AGENTS.md", b"@docs/agent-context/history/conventions.md"),
        ("AGENTS.md", b"# Culvert contributor guide", b"# Culvert contributor guide\nRead @docs/agent-context/history/conventions.md now."),
        ("AGENTS.md", b"docs/agent-context/domains/admission.md", b"docs/agent-context/domains/missing.md"),
        (".claude/skills/culvert-verify/SKILL.md", b"verification.md", b"review-change.md"),
        ("AGENTS.md", b"# Culvert contributor guide", b"x" * 8192 + b"\n# Culvert contributor guide"),
    ]
    # Each candidate is a full lightweight checkout copy to keep tests hermetic.
    import shutil
    with tempfile.TemporaryDirectory(prefix="culvert-guidance-check-") as tmp:
        candidate = Path(tmp) / "candidate"
        shutil.copytree(root, candidate, ignore=shutil.ignore_patterns(".git", "__pycache__"))
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
        # Ordinary later source work must not change frozen-source integrity.
        source = candidate / "proxy.go"
        source.write_bytes(source.read_bytes() + b"\n// Unrelated future-runtime fixture.\n")
        validate(candidate)
        # A future PR compares with its chosen base, not the migration base.
        fixture = Path(tmp) / "future-git"
        fixture.mkdir()
        def git(*args):
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
    return {"negative_controls_rejected": len(mutations) + 2, "future_baseline_controls_passed": 2}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reconstruct", type=Path, help="Write reconstructed original bytes to this path")
    parser.add_argument("--diff-base", help="Optional task/PR base for instruction-only diff allowlist; independent of frozen source provenance")
    parser.add_argument("--self-test", action="store_true", help="Verify corruption and routing negative controls")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    rebuilt, result = validate(root, args.diff_base)
    if args.reconstruct:
        args.reconstruct.write_bytes(rebuilt)
    if args.self_test:
        result.update(self_test(root))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
