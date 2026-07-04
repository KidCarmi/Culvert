# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS builder

WORKDIR /app
RUN apk add --no-cache git
COPY go.mod go.sum ./
RUN go mod download

COPY . .
# Version is embedded via ldflags. Priority:
#   1. Explicit VERSION build-arg (set by CI: --build-arg VERSION=x.y.z)
#   2. Git tag (auto-detected from .git — works for local docker compose builds)
#   3. Falls back to "dev"
ARG VERSION=
RUN if [ -z "$VERSION" ] && [ -d .git ]; then \
      VERSION=$(git describe --tags --abbrev=0 2>/dev/null || echo "dev"); \
    fi && \
    : "${VERSION:=dev}" && \
    echo "$VERSION" > /app/VERSION && \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o culvert .
# No `go mod tidy` here — the image must build from the EXACT reviewed module
# graph (go.mod/go.sum COPYed + `go mod download`ed above), not re-resolve deps
# at build time (a divergent-recipe supply-chain smell). Tidiness is enforced in
# CI (Fast Gate `go mod tidy -diff`). `-trimpath` strips build-path prefixes as
# reproducibility groundwork.

# ── GeoIP stage ───────────────────────────────────────────────────────────────
# Downloads the DB-IP free country database (CC BY 4.0, ~6 MB) at image build
# time so no runtime network access or manual download is required.
# Attribution: https://db-ip.com
#
# If the download fails (db-ip.com blocks some cloud/CI IPs), the build
# continues without GeoIP — country-based policy rules will be silently
# skipped until a valid .mmdb is mounted at runtime.
FROM alpine:3.24 AS geoip
RUN apk add --no-cache wget && \
    (wget -qO- "https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).mmdb.gz" \
      | gzip -d > /GeoLite2-Country.mmdb 2>/dev/null && \
      test -s /GeoLite2-Country.mmdb) || \
    (echo "WARN: GeoIP download failed — building without GeoIP database" >&2 && \
     rm -f /GeoLite2-Country.mmdb && touch /GeoLite2-Country.mmdb)

# ── Runtime stage ─────────────────────────────────────────────────────────────
# Security hardening (shift-left):
#   • Non-root user (proxy:proxy) — no elevated privileges at runtime
#   • Read-only root FS: run with --read-only + tmpfs mounts
#       docker run --read-only --tmpfs /tmp --tmpfs /data culvert
#   • Recommended seccomp profile: --security-opt seccomp=seccomp.json
#       (see deploy/seccomp.json)
#   • Drop all Linux capabilities: --cap-drop=ALL
#   • No new privileges: --security-opt no-new-privileges
FROM alpine:3.24

# /data and /backup are pre-created + chowned to proxy so that a FRESH named
# volume mounted over them (proxy-data:/data, culvert-backups:/backup) inherits
# proxy ownership — otherwise Docker creates the volume mountpoint root-owned and
# the non-root `cli` user (same image) gets "permission denied" writing the first
# backup to /backup. /backup is only used by the profile-gated `cli` service.
RUN apk upgrade --no-cache && \
    apk add --no-cache ca-certificates tzdata && \
    addgroup -S proxy && adduser -S proxy -G proxy && \
    mkdir -p /data /backup && chown proxy:proxy /data /backup

# Switch to non-root user before COPY so all assets are owned by proxy from
# the start — no extra chown layer needed after the binary is written.
USER proxy
WORKDIR /app
COPY --from=builder --chown=proxy:proxy /app/culvert .
COPY --from=builder --chown=proxy:proxy /app/VERSION ./VERSION
COPY --from=geoip   --chown=proxy:proxy /GeoLite2-Country.mmdb ./GeoLite2-Country.mmdb

# Default config (mount your own at /app/config.yaml)
COPY --chown=proxy:proxy config.example.yaml ./config.example.yaml

# Starter YARA rules — bundled at build time so scanning works out of the box.
# Mount a volume over /app/yara to supply your own rule set, then call
#   POST /api/security-scan/yara/reload  to load the new rules at runtime.
COPY --chown=proxy:proxy yara/ ./yara/

# /data is the persistent volume for the Root CA bundle, policy rules, and
# other state that must survive container restarts.
# Mount with: docker run -v culvert_data:/data ...
VOLUME ["/data"]

EXPOSE 8080 9090

# Liveness probe: /health (always 200 if process is alive)
# Readiness probe: /ready (200 when all subsystems operational, 503 otherwise)
# Kubernetes: use /health for livenessProbe, /ready for readinessProbe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["./culvert"]
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
