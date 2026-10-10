#!/usr/bin/env bash
# test/e2e/appliance/clamav-image-qualify.sh — real-ClamAV end-to-end check
# for a candidate ClamAV sidecar image (CVE-2026-103111 decision, PR #1528).
#
# Runs the REAL clamd from CLAMAV_IMAGE (signatures baked into the image, so no
# freshclam egress is needed) behind the REAL Culvert proxy from PROXY_IMAGE and
# proves, through the proxy's plain-HTTP response scan:
#   1. a clean body is delivered;
#   2. EICAR is blocked (official signature database, built at runtime so the
#      repository never carries the test string);
#   3. a body matching a custom PCRE logical signature is blocked — the code
#      path that links libpcre2, i.e. the library the CVE is in;
#   4. a body carrying the same literal anchor but NOT matching the regex is
#      delivered — so it is the regex, not the anchor, that decides (control).
# It also records the pcre2 package version inside the image, and measures
# the scan posture while clamd is down (fail-open, see below).
#
# Usage: CLAMAV_IMAGE=<ref> PROXY_IMAGE=<ref> EVID=<dir> clamav-image-qualify.sh
# Exit 0 only if every check passed. TEST-ONLY; publishes nothing.
set -euo pipefail
: "${CLAMAV_IMAGE:?}" "${PROXY_IMAGE:?}" "${EVID:?}"
mkdir -p "$EVID"
N="cq-$$"; NET="$N-net"
JSONL="$EVID/clamav-image-qualify.jsonl"; : > "$JSONL"
FAILS=0
check() { # check <name> pass|fail <detail>
  python3 -c 'import json,sys; print(json.dumps({"check":sys.argv[1],"result":sys.argv[2],"detail":sys.argv[3]},separators=(",",":")))' "$1" "$2" "$3" >> "$JSONL"
  [[ "$2" == pass ]] || FAILS=$((FAILS+1))
  echo "$2 $1: $3"
}
cleanup() {
  docker rm -f "$N-clamd" "$N-proxy" "$N-origin" >/dev/null 2>&1 || true
  docker volume rm "$N-db" "$N-data" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker network create "$NET" >/dev/null
check image-identity pass "clamav=$(docker image inspect -f '{{.Id}}' "$CLAMAV_IMAGE") proxy=$(docker image inspect -f '{{.Id}}' "$PROXY_IMAGE")"
pcre="$(docker run --rm --entrypoint sh "$CLAMAV_IMAGE" -c "apk info -v 2>/dev/null | grep '^pcre2-[0-9]' || dpkg-query -W -f='\${Package}-\${Version}' libpcre2-8-0")"
check pcre2-version pass "$pcre"

# JIT guard (review trigger for the CVE-2026-103111 "not reachable" call):
# the advisory's flaw is in PCRE2's JIT path, and libclamav imports no
# pcre2_jit_* symbol and names none for dlsym. If a future image starts
# using JIT, this check FAILS and the disposition must be re-reviewed. It
# is non-vacuous: libclamav must import SOME pcre2 symbol, or the probe
# looked at the wrong library.
command -v nm >/dev/null || { check pcre2-jit-unused fail "nm (binutils) not installed on the runner — guard cannot run"; exit 1; }
lib="$(docker run --rm --entrypoint sh "$CLAMAV_IMAGE" -c 'for f in /usr/lib/libclamav.so.* /usr/lib/*/libclamav.so.*; do [ -e "$f" ] && readlink -f "$f"; done | sort -u | head -1')"
jdir="$(mktemp -d)"; cid="$(docker create "$CLAMAV_IMAGE")"
docker cp "$cid:$lib" "$jdir/libclamav.so" >/dev/null 2>&1 || true; docker rm -f "$cid" >/dev/null
imports="$(nm -D --undefined-only "$jdir/libclamav.so" 2>/dev/null | grep -c ' pcre2_' || true)"
jit="$(nm -D --undefined-only "$jdir/libclamav.so" 2>/dev/null | grep -c ' pcre2_jit' || true)"
named="$(grep -c 'pcre2_jit' "$jdir/libclamav.so" 2>/dev/null || true)"
rm -rf "${jdir:?}"
if [[ "${imports:-0}" -gt 0 && "${jit:-0}" -eq 0 && "${named:-0}" -eq 0 ]]; then
  check pcre2-jit-unused pass "$lib imports $imports pcre2 symbols, 0 pcre2_jit, no pcre2_jit name for dlsym"
else
  check pcre2-jit-unused fail "$lib: pcre2 imports=${imports:-?} pcre2_jit imports=${jit:-?} pcre2_jit names=${named:-?} — re-review CVE-2026-103111 reachability"
fi

# Origin: one busybox httpd serving the four bodies.
eicar='X5O!P%@AP[4\PZX54(P^)7CC)7}$'"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"'$H+H*'
docker run -d --name "$N-origin" --network "$NET" --network-alias origin busybox:stable \
  sh -c 'mkdir -p /www && echo clean-body-ok > /www/clean.txt &&
         printf "%s" "$1" > /www/eicar.txt &&
         printf "%s  \\n" "$1" > /www/eicar-unscanned.txt &&
         echo "header culvert-qual-123456-pcre trailer" > /www/pcre-hit.txt &&
         echo "header culvert-qual-abcdef-pcre trailer" > /www/pcre-miss.txt &&
         httpd -f -p 80 -h /www' sh "$eicar" >/dev/null

# clamd: named volume inherits the baked signatures on first mount; the
# custom PCRE logical signature is copied in before start. freshclam is off.
docker create --name "$N-clamd" --network "$NET" --network-alias clamav \
  -v "$N-db:/var/lib/clamav" -e CLAMAV_NO_FRESHCLAMD=true -e CLAMAV_NO_MILTERD=true "$CLAMAV_IMAGE" >/dev/null
printf '%s\n' 'Culvert.Qual.PCRE-1;Engine:81-255,Target:0;0&1;63756c766572742d7175616c2d;0/culvert-qual-[0-9]{6}-pcre/' > "$EVID/culvert-qual.ldb"
docker cp "$EVID/culvert-qual.ldb" "$N-clamd:/var/lib/clamav/culvert-qual.ldb"
docker start "$N-clamd" >/dev/null
ok=0
for _ in $(seq 1 120); do
  if docker exec "$N-clamd" clamdscan --ping 1 >/dev/null 2>&1; then ok=1; break; fi
  sleep 3
done
if [[ $ok == 1 ]]; then check clamd-up pass "clamd answered PING"; else check clamd-up fail "clamd never answered PING"; docker logs "$N-clamd" > "$EVID/clamd.log" 2>&1; exit 1; fi
docker exec "$N-clamd" sh -c 'clamdscan --version' > "$EVID/clamd-version.txt" 2>&1 || true

docker run -d --name "$N-proxy" --network "$NET" --network-alias proxy \
  -v "$N-data:/data" -e CULVERT_DEFAULT_ACTION=allow \
  "$PROXY_IMAGE" -port 8080 -ui-port 9090 -clamav-addr tcp:clamav:3310 >/dev/null
for _ in $(seq 1 60); do
  docker run --rm --network "$NET" busybox:stable wget -qO- http://proxy:8080/health >/dev/null 2>&1 && break
  sleep 1
done

fetch() { # fetch <path> -> prints "<status>|<body-head>"
  docker run --rm --network "$NET" -e http_proxy=http://proxy:8080 busybox:stable \
    sh -c "wget -S -O /tmp/b http://origin/$1 2>/tmp/h; s=\$(grep -m1 'HTTP/' /tmp/h | awk '{print \$2}'); printf '%s|%s' \"\${s:-none}\" \"\$(head -c 60 /tmp/b 2>/dev/null | tr -d '\n')\""
}
r="$(fetch clean.txt)";     [[ "$r" == 200\|clean-body-ok* ]] && check clean-delivered pass "$r" || check clean-delivered fail "$r"
r="$(fetch eicar.txt)";     [[ "$r" == 403\|* ]] && check eicar-blocked pass "$r" || check eicar-blocked fail "$r"
r="$(fetch pcre-hit.txt)";  [[ "$r" == 403\|* ]] && check pcre-signature-blocked pass "$r" || check pcre-signature-blocked fail "$r"
r="$(fetch pcre-miss.txt)"; [[ "$r" == 200\|*culvert-qual-abcdef* ]] && check pcre-control-delivered pass "$r" || check pcre-control-delivered fail "$r"
docker logs "$N-proxy" 2>&1 | grep -E "SCAN_BLOCKED" > "$EVID/proxy-scan-blocks.log" || true
docker logs "$N-clamd" > "$EVID/clamd.log" 2>&1 || true
grep -q "Culvert.Qual.PCRE-1" "$EVID/clamd.log" "$EVID/proxy-scan-blocks.log" \
  && check pcre-signature-named pass "Culvert.Qual.PCRE-1 named in clamd/proxy logs" \
  || check pcre-signature-named fail "custom PCRE signature not named in any log"
# Posture when clamd is DOWN, measured rather than asserted. This container is
# started WITHOUT CULVERT_AV_UNAVAILABLE, so it measures the DEFAULT `open`
# posture: fail-OPEN (internal/secscan clamScanError — "forwarding UNSCANNED";
# owner decision WK-1b). The installed appliance ships av_unavailable=closed
# (refuse); that posture is gated in-tree by av_unavailable_integration_test.go.
# The check pins that the documentation matches the shipped default; it is not
# a statement that fail-open is desirable.
# A body NEVER scanned before is required: Culvert caches verdicts by SHA-256
# (internal/hashcache), so re-fetching eicar.txt would be answered from the
# cache and measure nothing about the scanner. EICAR permits trailing
# whitespace, so eicar-unscanned.txt is still malware with a fresh hash.
docker stop "$N-clamd" >/dev/null
r="$(fetch eicar-unscanned.txt)"
[[ "$r" == 200\|* ]] && check clamd-down-posture-is-fail-open pass "$r (body delivered unscanned while clamd is down)" \
                     || check clamd-down-posture-is-fail-open fail "$r (posture changed; update sbom-cve-evidence.md)"
docker logs "$N-proxy" 2>&1 | grep -E "ClamAV error|SCAN_BLOCKED|unscanned|UNSCANNED" | tail -4 > "$EVID/proxy-clamd-down.log" || true
echo "FAILS=$FAILS"
[[ $FAILS == 0 ]]
