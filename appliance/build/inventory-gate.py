#!/usr/bin/env python3
"""Pre-packaging inventory gate: refuse an appliance image that contains a
package, command or path forbidden by forbidden-inventory.txt.

  inventory-gate.py --rules forbidden-inventory.txt --dpkg-list dpkg-list.txt \
                    --present present-paths.txt [--out gate.txt]

--dpkg-list  the image's installed inventory, as prepare-guest.sh writes it:
             <package>[:<arch>] TAB <version> TAB <arch>
--present    absolute paths that exist on the image, one per line: every
             entry of each PATH directory, plus each forbidden `path` rule
             that exists. Built inside the guest (prepare-guest.sh) or from
             outside it (build-ova.sh, virt-ls).

Exit 0 and "inventory gate: PASS" when nothing matches; exit 1 naming every
match otherwise. Exit 2 on unusable input, so a missing or empty inventory,
an empty PATH listing or a malformed rule never reads as a clean image."""
import argparse
import fnmatch
import posixpath
import sys

PATH_DIRS = ("/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/bin", "/sbin")
KINDS = ("package", "command", "path")


def die(msg):
    print(f"inventory gate: UNUSABLE INPUT: {msg}", file=sys.stderr)
    sys.exit(2)


def read_rules(path):
    rules = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            parts = s.split(None, 2)
            if len(parts) < 3 or parts[0] not in KINDS:
                die(f"{path}:{n}: expected '<package|command|path> <pattern> <criterion>', got {s!r}")
            kind, pat, why = parts
            if kind == "path" and not pat.startswith("/"):
                die(f"{path}:{n}: a path rule must be absolute: {pat!r}")
            if kind == "command" and "/" in pat:
                die(f"{path}:{n}: a command rule is a file name, not a path: {pat!r}")
            rules.append((kind, pat, why))
    for k in ("package", "command"):
        if not any(r[0] == k for r in rules):
            die(f"{path}: no {k} rule (refusing a rule file that checks nothing of that kind)")
    return rules


def read_packages(path):
    pkgs = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            if not line.strip():
                continue
            cols = line.rstrip("\n").split("\t")
            if len(cols) != 3 or not cols[0]:
                die(f"{path}:{n}: not <package>TAB<version>TAB<arch>: {line.rstrip()!r}")
            pkgs.append((cols[0].split(":", 1)[0], cols[1]))
    if not pkgs:
        die(f"{path}: no installed packages")
    return pkgs


def read_present(path):
    with open(path, encoding="utf-8") as f:
        paths = {posixpath.normpath(p.strip()) for p in f if p.strip()}
    bad = [p for p in paths if not p.startswith("/")]
    if bad:
        die(f"{path}: not absolute paths: {sorted(bad)[:3]}")
    in_path = [p for p in paths if posixpath.dirname(p) in PATH_DIRS]
    if not any(posixpath.dirname(p) == "/usr/bin" for p in in_path):
        die(f"{path}: no /usr/bin entries (an empty PATH listing cannot prove a command is absent)")
    return paths


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", required=True)
    ap.add_argument("--dpkg-list", required=True)
    ap.add_argument("--present", required=True)
    ap.add_argument("--out")
    a = ap.parse_args()
    rules = read_rules(a.rules)
    pkgs = read_packages(a.dpkg_list)
    present = read_present(a.present)
    commands = sorted(p for p in present if posixpath.dirname(p) in PATH_DIRS)

    hits = []
    for kind, pat, why in rules:
        if kind == "package":
            found = [f"{n}={v}" for n, v in pkgs if fnmatch.fnmatchcase(n, pat)]
        elif kind == "command":
            found = [p for p in commands if fnmatch.fnmatchcase(posixpath.basename(p), pat)]
        else:
            norm = posixpath.normpath(pat)
            found = sorted(p for p in present if p == norm or p.startswith(norm + "/"))
        if found:
            more = f" (+{len(found) - 8} more)" if len(found) > 8 else ""
            hits.append(f"FORBIDDEN {kind} {pat}: {', '.join(found[:8])}{more} [{why}]")

    lines = [f"inventory gate: {len(rules)} rules; {len(pkgs)} packages; {len(commands)} PATH entries"]
    lines += hits
    lines.append("inventory gate: PASS" if not hits else f"inventory gate: FAIL ({len(hits)} rule(s) matched)")
    text = "\n".join(lines) + "\n"
    sys.stdout.write(text)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
    sys.exit(1 if hits else 0)


if __name__ == "__main__":
    main()
