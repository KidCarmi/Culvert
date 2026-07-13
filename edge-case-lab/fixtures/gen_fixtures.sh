#!/usr/bin/env bash
# Regenerate the lab's fixture TLS cert and sample files (kept out of git).
# Run once before starting the fixture origin server.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/certs" "$here/files"

# Self-signed fixture cert covering every fixture virtual host + the TEST-NET fixture IP.
openssl req -x509 -newkey rsa:2048 -nodes \
  -keyout "$here/certs/fixture.key" -out "$here/certs/fixture.crt" -days 3650 \
  -subj "/CN=fixture.local" \
  -addext "subjectAltName=DNS:fixture.local,DNS:app.corp.local,DNS:intranet.corp.local,DNS:media.corp.local,DNS:files.corp.local,DNS:partner.corp.local,DNS:badssl.corp.local,DNS:example.test,DNS:social.example.test,DNS:news.example.test,DNS:tenantb.corp.local,DNS:*.corp.local,IP:192.0.2.2,IP:127.0.0.1"

# Deterministic sample download fixtures.
printf 'MZ\x90\x00fake-pe-header-for-testing-only' > "$here/files/malware.exe"
printf 'MZ\x90\x00fake-pe-header-for-testing-only' > "$here/files/malware.bat"
head -c 1048576 /dev/zero | tr '\0' 'A' > "$here/files/big.bin"
printf '%%PDF-1.4 fake pdf fixture' > "$here/files/doc.pdf"
echo "fixtures regenerated in $here/{certs,files}"

# Reminder: add the fixture hostnames to /etc/hosts pointing at 192.0.2.2, e.g.
#   192.0.2.2 app.corp.local intranet.corp.local media.corp.local files.corp.local \
#             partner.corp.local badssl.corp.local example.test social.example.test \
#             news.example.test tenantb.corp.local
