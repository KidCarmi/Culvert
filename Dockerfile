# ── Build stage ───────────────────────────────────────────────────────────────
FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o proxyshield .

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
    addgroup -S proxy && adduser -S proxy -G proxy

WORKDIR /app
COPY --from=builder /app/proxyshield .

# Default config (mount your own at /app/config.yaml)
COPY config.example.yaml ./config.example.yaml

RUN mkdir -p /data && chown proxy:proxy /data /app
USER proxy

EXPOSE 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s \
  CMD wget -qO- http://localhost:8080/health || exit 1

ENTRYPOINT ["./proxyshield"]
CMD ["-port", "8080", "-ui-port", "9090"]
