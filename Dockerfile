# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o proxyshield .

# ── GeoIP stage ───────────────────────────────────────────────────────────────
# Downloads the DB-IP free country database (CC BY 4.0, ~6 MB) at image build
# time so no runtime network access or manual download is required.
# Attribution: https://db-ip.com
FROM alpine:3.21 AS geoip
RUN apk add --no-cache wget && \
    wget -qO- "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" \
      | gzip -d > /GeoLite2-Country.mmdb

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Security hardening (shift-left):
#   • Non-root user (proxy:proxy) — no elevated privileges at runtime
#   • Read-only root FS: run with --read-only + tmpfs mounts
#       docker run --read-only --tmpfs /tmp --tmpfs /data proxyshield
#   • Recommended seccomp profile: --security-opt seccomp=seccomp.json
#       (see deploy/seccomp.json)
#   • Drop all Linux capabilities: --cap-drop=ALL
#   • No new privileges: --security-opt no-new-privileges
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S proxy && adduser -S proxy -G proxy && \
    mkdir -p /data && chown proxy:proxy /data

# Switch to non-root user before COPY so all assets are owned by proxy from
# the start — no extra chown layer needed after the binary is written.
USER proxy
WORKDIR /app
COPY --from=builder --chown=proxy:proxy /app/proxyshield .
COPY --from=geoip   --chown=proxy:proxy /GeoLite2-Country.mmdb ./GeoLite2-Country.mmdb

# Default config (mount your own at /app/config.yaml)
COPY --chown=proxy:proxy config.example.yaml ./config.example.yaml

# Starter YARA rules — bundled at build time so scanning works out of the box.
# Mount a volume over /app/yara to supply your own rule set, then call
#   POST /api/security-scan/yara/reload  to load the new rules at runtime.
COPY --chown=proxy:proxy yara/ ./yara/

# /data is the persistent volume for the Root CA bundle, policy rules, and
# other state that must survive container restarts.
# Mount with: docker run -v proxyshield_data:/data ...
VOLUME ["/data"]

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["./proxyshield"]
# All persistent state lives in /data (mount as a Docker volume):
#   -ca-path        → Root CA bundle (ssl inspection)
#   -policy         → Policy rules (CRITICAL: without this, rules are lost on restart)
#   -geoip-db       → Bundled at build time from db-ip.com (CC BY 4.0)
#   -yara-rules-dir → Starter rules bundled in /app/yara (mount to override)
#   -threat-feed-db → Persisted threat feed DB in /data (populated on first run)
#   -clamav-addr    → Injected by docker-compose via the clamav sidecar
CMD ["-port", "8080", "-ui-port", "9090", \
     "-ca-path",        "/data/ca.bundle", \
     "-policy",         "/data/policy.json", \
     "-logfile",        "/data/proxy.log", \
     "-audit-log",      "/data/audit.jsonl", \
     "-geoip-db",       "/app/GeoLite2-Country.mmdb", \
     "-yara-rules-dir", "/app/yara", \
     "-threat-feed-db", "/data/threatfeeds.json"]
