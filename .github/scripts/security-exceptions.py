#!/usr/bin/env python3
"""Validate Trivy exception metadata or summarize an unfiltered gosec report.

The risk register owns security decisions. This checks their links/expiry and
report completeness; neither metadata nor a scanner result proves safety.
"""
import argparse
import datetime
import json
from pathlib import Path
import re
import sys


CLAIMS = {"false-positive", "not-affected", "protected-by-control", "accepted-risk", "under-investigation"}


def check_trivy(path, today):
    metadata = {}
    seen = set()
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line:
            metadata = {}
            continue
        if line.startswith("#"):
            match = re.fullmatch(r"# exception-(owner|evidence|claim|scope): (.+)", line)
            if match:
                key, value = match.groups()
                if key in metadata:
                    raise ValueError(f"{path}:{number}: duplicate {key}")
                metadata[key] = value
            continue
        match = re.fullmatch(r"((?:CVE-\d{4}-\d{4,}|GHSA-[a-z0-9-]+)) exp:(\d{4}-\d{2}-\d{2})", line)
        if not match:
            raise ValueError(f"{path}:{number}: expected advisory ID and exp:YYYY-MM-DD")
        advisory, expiry = match.groups()
        if advisory in seen:
            raise ValueError(f"{path}:{number}: duplicate {advisory}")
        seen.add(advisory)
        if datetime.date.fromisoformat(expiry) <= today:
            raise ValueError(f"{path}:{number}: {advisory} expired at 00:00 UTC on {expiry}")
        if set(metadata) != {"owner", "evidence", "claim", "scope"}:
            raise ValueError(f"{path}:{number}: missing exception owner/evidence/claim/scope")
        if metadata["claim"] not in CLAIMS:
            raise ValueError(f"{path}:{number}: unknown security classification")
        # Security decisions stay in the existing register, with an explicit
        # evidence anchor. Checking that a link exists does not validate it.
        document, separator, anchor = metadata["evidence"].partition("#")
        if document != "docs/engineering/TECHNICAL-RISK-REGISTER.md" or not separator or not anchor:
            raise ValueError(f"{path}:{number}: evidence must link to a risk-register anchor")
        if not Path(document).is_file():
            raise ValueError(f"{path}:{number}: evidence document missing")
        contents = Path(document).read_text()
        headings = re.findall(r"^#+ (.+)$", contents, re.MULTILINE)
        anchors = {re.sub(r"[^\w -]", "", heading.lower()).replace(" ", "-") for heading in headings}
        anchors.update(re.findall(r'<a id="([^"]+)">', contents))
        if anchor not in anchors:
            raise ValueError(f"{path}:{number}: evidence anchor missing")
        metadata = {}
    return len(seen)


def report_gosec(path, root):
    report = json.loads(path.read_text())
    if report.get("Golang errors") != {} or report.get("Stats", {}).get("files", 0) <= 0:
        raise ValueError(f"{path}: scan incomplete (Go errors or no files)")
    issues = report.get("Issues")
    if not isinstance(issues, list):
        raise ValueError(f"{path}: missing findings array")
    if report.get("Stats", {}).get("found") != len(issues):
        raise ValueError(f"{path}: scan incomplete (finding count does not match retained findings)")
    print(f"### {path.stem}: unfiltered gosec advisory ({len(issues)} findings)")
    print("Includes globally excluded rules and inline #nosec sites. Findings require triage.")
    print("| Rule | Scope | Scanner description |")
    print("|---|---|---|")
    for issue in issues:
        scope = Path(issue["file"]).relative_to(root)
        detail = issue["details"].replace("|", "\\|").replace("\n", " ")
        print(f'| {issue["rule_id"]} | `{scope}:{issue["line"]}` | {detail} |')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("trivy", "gosec"))
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.mode == "trivy":
            count = check_trivy(args.path, datetime.datetime.now(datetime.timezone.utc).date())
            print(f"Trivy metadata: {count} active exceptions; evidence still requires review.")
        else:
            report_gosec(args.path, Path.cwd().resolve())
    except (ValueError, OSError, KeyError, TypeError) as error:
        print(f"::error::{error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
