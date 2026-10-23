#!/usr/bin/env bash
# One F-P2 isolated arm, transcribed from the lab job "fp2-isolated"
# (.github/workflows/appliance-lab.yml on test/appliance-lab @ lab-commit.txt):
# stock clamd.conf, freshclam off, a FIXED signature set (db/, recorded once and
# shared by every arm), clamd's /tmp on its own 256 MiB loop ext4, the same five
# variants and headroom sweep, and the same verdict rule (count of EICAR streams
# answered a bare clean). Local run on a sandbox dockerd — not a lab run.
#
# fp2-arm.sh LABEL IMAGE PORT EXPECT(zero|nonzero)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
LABEL="$1" IMG="$2" PORT="$3" EXPECT="$4"
A="$HERE/arms/$LABEL"; E="$A/evidence"
rm -rf "$A"; mkdir -p "$E"
docker image inspect -f '{{.Id}}' "$IMG" | tee "$E/image-id.txt"
docker run --rm --entrypoint sh "$IMG" -c "apk info -v 2>/dev/null | grep -E '^(musl|musl-utils|pcre2|zlib|nghttp2-libs)-[0-9]'" | tee "$E/packages.txt"
docker run --rm --entrypoint cat "$IMG" /etc/clamav/clamd.conf > "$E/clamd.conf"
sha256sum "$E/clamd.conf" | tee "$E/clamd.conf.sha256"
truncate -s 256M "$A/tmp.img"; mkfs.ext4 -q -m 0 "$A/tmp.img"
mkdir -p "$A/tmpfs"; mount -o loop "$A/tmp.img" "$A/tmpfs"; chmod 1777 "$A/tmpfs"
df -B1 "$A/tmpfs" | tee "$E/tmpfs-df.txt"
cp -a "$HERE/db" "$A/db"; chmod -R a+rwX "$A/db"
docker rm -f "fp2-$LABEL" >/dev/null 2>&1
docker run -d --name "fp2-$LABEL" -e CLAMAV_NO_FRESHCLAMD=true -e CLAMAV_NO_MILTERD=true \
  -v "$A/tmpfs:/tmp" -v "$A/db:/var/lib/clamav" -p "127.0.0.1:$PORT:3310" "$IMG" > "$E/container.id"
r=""
for _ in $(seq 1 120); do
  r="$(printf 'zPING\0' | timeout 5 nc -q2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\0' || true)"
  [ "$r" = PONG ] && break; sleep 5
done
if [ "$r" != PONG ]; then docker logs "fp2-$LABEL" | tail -50; echo "clamd did not answer PING" >&2; exit 1; fi
printf 'zVERSION\0' | timeout 5 nc -q2 127.0.0.1 "$PORT" | tr -d '\0' | tee "$E/clamd-version.txt"; echo
docker exec "fp2-$LABEL" sh -c 'sha256sum /var/lib/clamav/*.c?d' | tee "$E/signatures.txt"
R="$E/requests.jsonl"; : > "$R"
H=0,4096,16384,65536,262144,1048576,4194304
alive() { printf 'zPING\0' | timeout 5 nc -q2 127.0.0.1 "$PORT" 2>/dev/null | tr -d '\0'; }
for v in "control 2 50 1 -1" "serial-full 14 10 1 0" "serial-sweep 28 10 1 $H" "conc8 14 10 8 $H" "conc8-full 14 10 8 0"; do
  set -- $v
  python3 -I "$HERE/fp2-isolated.py" 127.0.0.1 "$PORT" "$A/tmpfs" "$R" "$@"
  echo "$1 done; clamd: $(alive)" | tee -a "$E/variants.txt"
done
python3 -I "$HERE/fp2-isolated-report.py" "$R" "$E/REPORT.md" > /dev/null
n="$(python3 -I "$HERE/fp2-isolated-report.py" "$R" --count)"
docker logs "fp2-$LABEL" > "$E/clamd-container.log" 2>&1 || true
grep -c "Can't create temporary directory" "$E/clamd-container.log" > "$E/clamd-tmpdir-errors.txt" || true
docker rm -f "fp2-$LABEL" >/dev/null 2>&1; umount "$A/tmpfs"; rm -f "$A/tmp.img"; rm -rf "$A/db"
case "$EXPECT" in zero) [ "$n" -eq 0 ] && v=PASS || v=FAIL ;; nonzero) [ "$n" -gt 0 ] && v=PASS || v=FAIL ;; esac
echo "$LABEL wrong-cleans=$n requests=$(wc -l < "$R") tmpdir-errors=$(cat "$E/clamd-tmpdir-errors.txt") expect=$EXPECT verdict=$v" | tee "$E/verdict.txt"
