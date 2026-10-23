#!/usr/bin/env bash
# R6 runtime measurement: what the appliance's Compose invocations actually
# do on the wire. For each Compose binary, run the agent's allowlisted
# subcommands against an isolated debug dockerd, recording (1) every socket
# syscall Compose makes (strace) and (2) every Docker API endpoint it calls
# (logged by the tap relay in front of dockerd, incl. Upgrade headers and
# which side sends an HTTP/2 preface). Then force the documented build fallback
# (derivative image absent) and record the same.
set -u
B6="$(cd "$(dirname "$0")" && pwd)"
P="$B6/proj"
TAPLOG="$B6/tap.log"; : > "$TAPLOG"
"$B6/tap/tap" /tmp/b6x/p.sock /tmp/b6x/d.sock "$TAPLOG" & TAPPID=$!
sleep 0.5
export DOCKER_HOST=unix:///tmp/b6x/p.sock
trap 'kill $TAPPID 2>/dev/null' EXIT
OUT="$B6/measure"; rm -rf "$OUT"; mkdir -p "$OUT"
F=(-f "$P/docker-compose.yml" -f "$P/docker-compose.maint-agent.yml")
echo "# generated $(date -u +%FT%TZ); dockerd $(docker version --format '{{.Server.Version}}'); docker CLI $(docker version --format '{{.Client.Version}}')" > "$OUT/SUMMARY.txt"

step() { # step <version> <name> <timeout> <compose args...>
  local v="$1" name="$2" to="$3"; shift 3
  local off; off=$(wc -l < "$TAPLOG")
  local rc=0
  ( cd "$P" && DOCKER_CONFIG="$B6/cfg$v" timeout -s KILL "$to" \
      strace -f -qq -e trace=socket,connect,bind,listen,accept,accept4 -o "$OUT/$v-$name.strace" \
      docker compose "$@" ) > "$OUT/$v-$name.out" 2>&1 || rc=$?
  sleep 1
  tail -n +"$((off + 1))" "$TAPLOG" > "$OUT/$v-$name.tap"
  grep -oE '(REQ [A-Z]+ [^ ]+|UPGRADE [^ ]+|HTTP2-PREFACE)' "$OUT/$v-$name.tap" | sed -E 's#/v[0-9.]+/#/#; s#\?.*##' \
    | sed -E 's#/containers/[0-9a-f]{12,}#/containers/<id>#; s#/(images|volumes|networks|exec)/[^/ ]+#/\1/<x>#' \
    | sort | uniq -c > "$OUT/$v-$name.api"
  local inet unix bindl
  inet=$(grep -E 'connect\(.*(AF_INET|AF_INET6)' "$OUT/$v-$name.strace" | grep -oE 'sin6?_addr=[^,)]+|inet_pton\([^)]*\)|sin6?_port=htons\([0-9]+\)' | sort | uniq -c | tr '\n' ';')
  unix=$(grep -E 'connect\(.*AF_UNIX' "$OUT/$v-$name.strace" | grep -oE 'sun_path="[^"]+"' | sort | uniq -c | tr '\n' ';')
  bindl=$(grep -cE '^[0-9]+ +(bind|listen)\(' "$OUT/$v-$name.strace")
  printf '%s %-14s rc=%-3s unix-connects:[%s] inet-connects:[%s] bind/listen:%s session/grpc-calls:%s h2-preface(c>d,d>c):%s,%s\n' \
    "$v" "$name" "$rc" "$unix" "$inet" "$bindl" "$(grep -cE 'REQ POST /(session|grpc)' "$OUT/$v-$name.tap")" "$(grep -c 'c>d HTTP2-PREFACE' "$OUT/$v-$name.tap")" "$(grep -c 'd>c HTTP2-PREFACE' "$OUT/$v-$name.tap")" | tee -a "$OUT/SUMMARY.txt"
}

for v in 560 561; do
  mkdir -p "$B6/cfg$v/cli-plugins"
  ln -sf "$B6/x$v/usr/libexec/docker/cli-plugins/docker-compose" "$B6/cfg$v/cli-plugins/docker-compose"
  echo "== compose $v: $(DOCKER_CONFIG="$B6/cfg$v" docker compose version --short) sha256 $(sha256sum "$B6/x$v/usr/libexec/docker/cli-plugins/docker-compose" | cut -c1-16)" | tee -a "$OUT/SUMMARY.txt"
  step $v ps        60  "${F[@]}" ps --format json
  step $v up        120 "${F[@]}" up -d
  step $v cli-run   120 "${F[@]}" --profile cli run --rm cli --list-backups --backup-dir /backup
  step $v down      120 "${F[@]}" down
  # Documented fallback: the derivative tag is absent, so `up -d` builds it.
  docker rmi culvert/clamav:1.5.4-culvert.1 >/dev/null
  step $v up-build  240 "${F[@]}" up -d
  step $v down2     120 "${F[@]}" down
  docker tag culvert/proxy:pinned culvert/clamav:1.5.4-culvert.1
done
echo "done" >> "$OUT/SUMMARY.txt"
