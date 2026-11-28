#!/usr/bin/env python3
"""Render the SHIPPED compose files for the AGT-900 sudoers-mode e2e.

usage: render-shipped-compose.py <repo-root> <out-dir> <proxy-port> <ui-port> <run-dir>

Reads <repo-root>/docker-compose.yml and <repo-root>/docker-compose.maint-agent.yml
(the files an operator runs, and the override the agent merges onto its
recreate when compose_override_file is set) and writes them to <out-dir> with
the SMALLEST set of test-only substitutions, each applied exactly once (any
drift in the shipped files makes the render fail instead of silently testing
something else):

  docker-compose.yml
    1. proxy ports "8080:8080" / "9090:9090" (all host interfaces) become
       "127.0.0.1:<proxy-port>:8080" / "127.0.0.1:<ui-port>:9090", so the test
       never binds a public port or collides with a host service;
    2. proxy volumes gain "./ctl:/ctl", the harness's /ready stall control
       (the only way to land a kill inside the health gate).
  docker-compose.maint-agent.yml
    3. the host side of the agent-socket bind "/run/culvert-maint" becomes
       <run-dir>, so the private daemon never creates a directory in the
       host's /run. The container side is unchanged.

Everything else (services, container names, restart policies,
stop_grace_period, depends_on clamav service_healthy, the proxy command line,
environment, healthchecks, the cli and ha profiles, volumes, group_add and the
${CULVERT_MAINT_GID:?...} interpolation) is byte-for-byte the shipped file.
"""
import os
import sys


def sub_once(text, old, new, what):
    n = text.count(old)
    if n != 1:
        sys.exit(f"render-shipped-compose: {what}: expected exactly 1 match of {old!r}, found {n}")
    return text.replace(old, new)


def main():
    if len(sys.argv) != 6:
        sys.exit(__doc__)
    root, out, pport, uport, rundir = sys.argv[1:]
    with open(os.path.join(root, "docker-compose.yml"), encoding="utf-8") as f:
        main_yml = f.read()
    with open(os.path.join(root, "docker-compose.maint-agent.yml"), encoding="utf-8") as f:
        ovr = f.read()

    main_yml = sub_once(main_yml, '      - "8080:8080"', f'      - "127.0.0.1:{pport}:8080"', "proxy port")
    main_yml = sub_once(main_yml, '      - "9090:9090"', f'      - "127.0.0.1:{uport}:9090"', "ui port")
    # The proxy's volume list: "- proxy-data:/data" followed by the shipped
    # YARA comment (the cli service's entry is followed by the backup volume).
    marker = "    volumes:\n      - proxy-data:/data\n      # Uncomment to use your own YARA rules"
    main_yml = sub_once(main_yml, marker,
                        "    volumes:\n      - proxy-data:/data\n      - ./ctl:/ctl   # AGT-900 e2e only: /ready stall control\n"
                        "      # Uncomment to use your own YARA rules", "proxy volumes")
    ovr = sub_once(ovr, "      - /run/culvert-maint:/run/culvert-maint:ro",
                   f"      - {rundir}:/run/culvert-maint:ro", "agent socket bind")

    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "docker-compose.yml"), "w", encoding="utf-8") as f:
        f.write(main_yml)
    with open(os.path.join(out, "docker-compose.maint-agent.yml"), "w", encoding="utf-8") as f:
        f.write(ovr)


if __name__ == "__main__":
    main()
