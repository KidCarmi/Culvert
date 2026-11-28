#!/usr/bin/env bash
# AGT-900 e2e, sudoers mode: build the PRODUCTION privilege path inside a
# private mount namespace, then exec the harness in it.
#
# run.sh calls this as
#   unshare --mount --propagation private -- sudoers-env.sh <evidence-dir> -- <cmd...>
# so every mount below exists only in that namespace and disappears with it.
# The host's /etc, /usr/local, /var/lib, /var/log, sudoers, users and its
# /usr/bin/docker are never modified: they are overlaid (writes go to upper
# dirs under the run's work dir), and /usr/bin/docker is bind-mounted over.
#
# Inside the namespace it runs the REAL packaging/culvert-maint/install.sh,
# which creates the culvert-maint system user and group, installs the agent
# binary, renders the sudoers file (path-bound to the test's compose file,
# with the two-`-f` compose-override line), validates it with visudo -c,
# renders and installs the root-owned compose-cli wrapper (bound to the test's
# compose path and proxy repo) and seeds culvert/proxy:pinned. Only
# `systemctl daemon-reload` is stubbed (no systemd in the test environment).
# Then the shim placeholder is bind-mounted over /usr/bin/docker, the path the
# sudoers rules and the wrapper exec.
#
# Inputs (environment): AGT900_W, AGT900_PROJECT, AGT900_REPO, AGT900_DOCKER_HOST,
# AGT900_SEED_REF, AGT900_AGENT_SRC, AGT900_PROXY_PORT, AGT900_COMPOSE_OVERRIDE,
# AGT900_SHIM. Outputs (environment of <cmd>): AGT900_AGENT_UID, AGT900_AGENT_GID,
# AGT900_AGENT_BIN.
set -euo pipefail

EVID="$1"; shift
[ "${1:-}" = "--" ] && shift
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
W="$AGT900_W"
mkdir -p "$EVID"

# ── overlays: every write below lands in $W/ov/<dir>/up, never on the host ──
for d in /etc /usr/local /var/lib /var/log; do
  n="$(echo "$d" | tr / _)"
  mkdir -p "$W/ov/$n/up" "$W/ov/$n/work"
  mount -t overlay "agt900$n" -o "lowerdir=$d,upperdir=$W/ov/$n/up,workdir=$W/ov/$n/work" "$d"
done

# ── /etc/culvert-maint/config.toml: the shipped example with the test's values ──
mkdir -p /etc/culvert-maint
repo_re="$(printf '%s' "$AGT900_REPO" | sed 's/[.]/\\./g')"
sed -e "s|^compose_project_dir = .*|compose_project_dir = \"$AGT900_PROJECT\"|" \
    -e "s|^allow_peers = .*|allow_peers = [\"0\"]|" \
    -e "s|^# compose_override_file = .*|compose_override_file = \"$AGT900_COMPOSE_OVERRIDE\"|" \
    -e "s|^health_base_url = .*|health_base_url = \"http://127.0.0.1:$AGT900_PROXY_PORT\"|" \
    -e "s|^image_allowlist = .*|image_allowlist = '^$repo_re(:[A-Za-z0-9._-]+\|@sha256:[a-f0-9]{64})\$'|" \
    -e "s|^proxy_repo = .*|proxy_repo = \"$AGT900_REPO\"|" \
    -e "s|^#reconcile_on_startup = .*|reconcile_on_startup = \"converge\"|" \
    "$ROOT/packaging/culvert-maint/config.example.toml" > /etc/culvert-maint/config.toml
for k in "compose_project_dir = \"$AGT900_PROJECT\"" "compose_override_file = \"$AGT900_COMPOSE_OVERRIDE\"" "proxy_repo = \"$AGT900_REPO\"" 'privilege_mode = "sudoers"'; do
  grep -qxF "$k" /etc/culvert-maint/config.toml || { echo "sudoers-env: config render lost: $k" >&2; exit 1; }
done

# ── the real install.sh (systemctl stubbed) ──
mkdir -p "$W/stub"
printf '#!/bin/sh\necho "systemctl (stubbed by the AGT-900 e2e): $*"\n' > "$W/stub/systemctl"
chmod 755 "$W/stub/systemctl"
env PATH="$W/stub:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" DOCKER_HOST="$AGT900_DOCKER_HOST" \
    CULVERT_MAINT_SKIP_VERIFY=1 CULVERT_PROXY_SEED_REF="$AGT900_SEED_REF" \
    sh "$ROOT/packaging/culvert-maint/install.sh" "$AGT900_AGENT_SRC" > "$EVID/install.log" 2>&1 \
  || { echo "sudoers-env: install.sh failed:" >&2; cat "$EVID/install.log" >&2; exit 1; }
chgrp culvert-maint /etc/culvert-maint/config.toml   # install.sh's owner/mode for a config it installs
chmod 0640 /etc/culvert-maint/config.toml

uid="$(id -u culvert-maint)"; gid="$(id -g culvert-maint)"
[ "$uid" != 0 ] || { echo "sudoers-env: culvert-maint resolved to uid 0" >&2; exit 1; }
# The operator step install.sh asks for when compose_override_file is set: the
# agent runs compose with a scrubbed env, so the override's
# ${CULVERT_MAINT_GID:?} must come from <project>/.env.
echo "CULVERT_MAINT_GID=$gid" > "$AGT900_PROJECT/.env"

# ── the shim over /usr/bin/docker (the harness writes its body later) ──
mount --bind "$AGT900_SHIM" /usr/bin/docker

# ── evidence ──
{
  echo "== id culvert-maint"; id culvert-maint
  echo "== getent passwd culvert-maint"; getent passwd culvert-maint
  echo "== visudo -c"; visudo -c 2>&1
  echo "== sudo -l -U culvert-maint"; sudo -l -U culvert-maint 2>&1
  echo "== ls -l the sudoers file and the wrapper"
  ls -l /etc/sudoers.d/culvert-maint /usr/local/libexec/culvert-maint/compose-cli /usr/local/bin/culvert-maint
  echo "== rendered wrapper bindings"
  grep -E "^(COMPOSE_PATH|PROXY_REPO)=" /usr/local/libexec/culvert-maint/compose-cli
  echo "== a command the allowlist does NOT grant is refused"
  setpriv --reuid "$uid" --regid "$gid" --clear-groups sudo -n /usr/bin/docker ps 2>&1 || echo "(refused, exit $?)"
  echo "== the wrapper refuses a foreign repository"
  setpriv --reuid "$uid" --regid "$gid" --clear-groups sudo -n /usr/local/libexec/culvert-maint/compose-cli pull "evil.example/x@sha256:$(printf '0%.0s' $(seq 1 64))" 2>&1 || echo "(refused, exit $?)"
} > "$EVID/sudoers-evidence.txt" 2>&1
cp /etc/sudoers.d/culvert-maint "$EVID/sudoers.rendered"
cp /usr/local/libexec/culvert-maint/compose-cli "$EVID/compose-cli.rendered"
cp /etc/culvert-maint/config.toml "$EVID/config.toml"

export AGT900_AGENT_UID="$uid" AGT900_AGENT_GID="$gid"
export AGT900_AGENT_BIN=/usr/local/bin/culvert-maint
exec "$@"
