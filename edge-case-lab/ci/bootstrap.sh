#!/usr/bin/env bash
# Bootstrap the hermetic Edge-Case Validation Lab environment on a CI runner
# (or locally). Idempotent. Binds the TEST-NET fixture IP, generates the
# throwaway fixture certs, routes the fixture virtual hosts, builds the shipped
# proxy binary, and starts the deterministic origin fixture behind a ready-file
# health gate.
#
# No public internet is used: 192.0.2.0/24 is TEST-NET-1 (RFC 5737), which the
# proxy's SSRF guard treats as a dialable "public" range while RFC-1918 and
# loopback stay blocked (pinned by edge_case_lab_ssrf_guard_test.go).
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
lab="$repo/edge-case-lab"

echo "::group::lab bootstrap — dataDir + TEST-NET + hosts"
# 1. Writable dataDir (the proxy hardcodes dataDir=/data, no flag).
sudo mkdir -p /data && sudo chown "$(id -un)" /data

# 2. TEST-NET fixture IP on loopback (matches the validated lab topology).
if ! ip -4 addr show dev lo | grep -q '192\.0\.2\.2'; then
  sudo ip addr add 192.0.2.2/24 dev lo
fi

# 3. Route the fixture virtual hosts at the fixture IP.
HOSTS_LINE="192.0.2.2 app.corp.local intranet.corp.local media.corp.local files.corp.local partner.corp.local badssl.corp.local example.test social.example.test news.example.test tenantb.corp.local"
if ! grep -qF "app.corp.local" /etc/hosts; then
  echo "$HOSTS_LINE" | sudo tee -a /etc/hosts >/dev/null
fi
echo "::endgroup::"

echo "::group::lab bootstrap — fixture certs + proxy build"
# 4. Fixture TLS cert + sample files (deliberately kept out of git; regenerated
#    each run — no committed private key).
bash "$lab/fixtures/gen_fixtures.sh"

# 5. Build the shipped binary once.
( cd "$repo" && CGO_ENABLED=0 go build -o culvert . )
echo "::endgroup::"

echo "::group::lab bootstrap — start origin fixture"
# 6. Start the deterministic origin fixture with a ready-file health gate.
rm -f /tmp/fixture.ready
nohup python3 "$lab/fixtures/origin_server.py" --bind 192.0.2.2 \
  --http-port 18091 --https-port 18453 \
  --cert "$lab/fixtures/certs/fixture.crt" --key "$lab/fixtures/certs/fixture.key" \
  --files-dir "$lab/fixtures/files" --ready-file /tmp/fixture.ready \
  > /tmp/origin.log 2>&1 &

for _ in $(seq 1 40); do [ -f /tmp/fixture.ready ] && break; sleep 0.25; done
if [ ! -f /tmp/fixture.ready ]; then
  echo "origin fixture failed to start:"; cat /tmp/origin.log; exit 1
fi

# Health probe — a red probe here is TEST-INFRA, not a lab regression.
curl -fsS -m5 --resolve app.corp.local:18091:192.0.2.2 \
  http://app.corp.local:18091/ >/dev/null
echo "lab environment ready (binary: $repo/culvert, fixture: 192.0.2.2:18091/18453)"
echo "::endgroup::"
