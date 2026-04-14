# Sluice — Content Disarm & Reconstruction (CDR) Engine

## Project Brief

Build **Sluice**, a standalone CDR (Content Disarm & Reconstruction) microservice
that strips active threats from files passing through a forward proxy. Sluice runs
as a Docker sidecar and integrates with the Culvert forward proxy via gRPC + mTLS.

The name "Sluice" comes from the water gate inside a culvert — it controls what
content flows through to the user.

**Repository:** Create a new repo `KidCarmi/Sluice`
**Language:** Go (match Culvert's stack for operational consistency)
**License:** MIT

---

## Architecture Overview

```
User → Browser → Culvert Proxy (SSL inspection)
                       ↓
                 Read response body
                       ↓
              File extension/header checks
                       ↓
              Body buffered (up to 50 MB)
                       ↓
         ┌──── gRPC call ────────────────────┐
         │                                    │
         │  Sluice CDR Engine                 │
         │  ┌────────────────────────────┐    │
         │  │ 1. Detect file type        │    │
         │  │ 2. Parse document structure│    │
         │  │ 3. Strip active content    │    │
         │  │    - Macros (VBA/XLM)      │    │
         │  │    - Embedded OLE objects   │    │
         │  │    - JavaScript in PDFs    │    │
         │  │    - External references   │    │
         │  │ 4. Rebuild clean document  │    │
         │  │ 5. Return sanitized bytes  │    │
         │  └────────────────────────────┘    │
         │                                    │
         └────────────────────────────────────┘
                       ↓
              ClamAV + YARA scan (on sanitized body)
                       ↓
              Forward clean file to user
```

---

## SSDLC Requirements (Non-Negotiable)

This project follows Secure Software Development Lifecycle from day one.

### Threat Model

| Threat | Impact | Mitigation |
|---|---|---|
| Malicious file crashes the parser | DoS on CDR service | Sandbox each file in a goroutine with timeout + memory limit |
| Zip bomb / decompression bomb | OOM crash | `io.LimitReader` on all decompression (50 MB cap) |
| Path traversal in archive entries | File write outside sandbox | `filepath.Base` + containment check on every extracted path |
| Polyglot files bypass detection | Threat passes through | Magic byte detection before parsing (don't trust Content-Type) |
| gRPC request flooding | Resource exhaustion | Max concurrent workers (10) + request queue with backpressure (50) |
| mTLS cert theft | Unauthorized access | Cert rotation support, short-lived certs, enrollment token revocation |
| Dependency supply chain | Compromised library | Pin all deps in go.mod, run govulncheck in CI, minimal dependencies |

### Secure Coding Standards

- **No `unsafe` package usage**
- **No `os/exec` unless absolutely necessary** (prefer pure Go libraries over shelling out to LibreOffice)
- **All file I/O through `io.LimitReader`** — never unbounded reads
- **All paths validated with `filepath.Clean` + containment check**
- **No hardcoded secrets** — certs and tokens from files/env vars only
- **Structured logging** — JSON mode, no user content in log messages without sanitization
- **Context-aware operations** — every gRPC handler, file operation, and network call uses `context.Context` with deadlines

### CI Pipeline (must have from first commit)

```yaml
- go vet ./...
- golangci-lint run
- gosec ./...
- govulncheck ./...
- go test -race -count=1 ./...
- go test -coverprofile=coverage.out ./... (threshold: 60%)
- trivy image scan
- gitleaks (no secrets in repo)
```

---

## gRPC Service Definition

```protobuf
syntax = "proto3";
package sluice.v1;

option go_package = "github.com/KidCarmi/Sluice/proto/sluicev1";

service SluiceService {
  // Sanitize processes a file and returns the sanitized version.
  // Streaming: client sends file chunks, server returns sanitized chunks.
  // This avoids buffering entire files in memory on either side.
  rpc Sanitize(stream SanitizeRequest) returns (stream SanitizeResponse);

  // Health returns the service status and capabilities.
  rpc Health(HealthRequest) returns (HealthResponse);

  // Enroll exchanges an enrollment token for mTLS client certificates.
  // Used by Culvert's admin GUI for one-click CDR setup.
  rpc Enroll(EnrollRequest) returns (EnrollResponse);
}

message SanitizeRequest {
  oneof payload {
    SanitizeHeader header = 1;  // First message: metadata
    bytes chunk = 2;             // Subsequent messages: file data chunks (64 KB each)
  }
}

message SanitizeHeader {
  string filename = 1;           // Original filename (for type detection)
  string content_type = 2;       // HTTP Content-Type header value
  int64 content_length = 3;      // Total file size in bytes (0 if unknown)
  string request_id = 4;         // Culvert's X-Request-ID for correlation
  string trace_parent = 5;       // W3C Traceparent for distributed tracing
}

message SanitizeResponse {
  oneof payload {
    SanitizeResult result = 1;   // First message: sanitization result metadata
    bytes chunk = 2;              // Subsequent messages: sanitized file data chunks
  }
}

message SanitizeResult {
  Status status = 1;
  string original_type = 2;      // Detected file type (e.g., "PDF", "DOCX")
  int64 original_size = 3;       // Original file size
  int64 sanitized_size = 4;      // Sanitized file size
  repeated Threat threats_removed = 5;  // What was stripped
  string error_message = 6;      // Non-empty if status is ERROR
}

enum Status {
  CLEAN = 0;          // File was already clean, passed through unchanged
  SANITIZED = 1;      // Active content was removed, file rebuilt
  BLOCKED = 2;        // File is unsalvageable (e.g., entire content is a macro)
  ERROR = 3;          // Processing error (check error_message)
  UNSUPPORTED = 4;    // File type not supported by CDR, passed through unchanged
}

message Threat {
  string type = 1;           // "macro", "ole_object", "javascript", "external_ref"
  string location = 2;       // Where in the document (e.g., "Sheet1/VBA/Module1")
  string description = 3;    // Human-readable description
  string severity = 4;       // "low", "medium", "high", "critical"
}

message HealthRequest {}

message HealthResponse {
  bool healthy = 1;
  string version = 2;
  repeated string supported_types = 3;  // ["pdf", "docx", "xlsx", "pptx"]
  int32 active_workers = 4;
  int32 max_workers = 5;
  int32 queue_depth = 6;
  int64 files_processed = 7;
  int64 threats_removed = 8;
}

message EnrollRequest {
  string token = 1;              // One-time enrollment token from Sluice CLI
}

message EnrollResponse {
  bytes ca_cert = 1;             // Sluice CA certificate (PEM)
  bytes client_cert = 2;         // Client certificate for Culvert (PEM)
  bytes client_key = 3;          // Client private key (PEM)
  string endpoint = 4;           // Sluice's gRPC endpoint (host:port)
}
```

---

## File Sanitization Specifications

### MVP: Office Documents (.docx, .xlsx, .pptx)

Office Open XML files are ZIP archives containing XML parts.

**Strip:**
- VBA macro code (`vbaProject.bin`, `*.vba`)
- XLM 4.0 macros (Excel legacy macros in sheet XML)
- Embedded OLE objects (`oleObject*.bin`)
- ActiveX controls (`activeX*.xml`, `activeX*.bin`)
- External data connections (`connections.xml`)
- Custom XML parts that reference external URIs
- Printer/mail merge data sources

**Preserve:**
- Text content, formatting, styles
- Images (re-encode to strip any embedded payloads)
- Charts, tables, formulas (non-macro)
- Document properties (title, author — sanitize for PII if configured)

**Implementation approach:**
1. Unzip the OOXML archive (with `io.LimitReader`, max 50 MB decompressed)
2. Parse `[Content_Types].xml` to enumerate parts
3. Remove prohibited content types and their relationships
4. Re-encode embedded images (`image/png` → decode → re-encode)
5. Rebuild the ZIP archive with only clean parts
6. Validate the rebuilt file opens correctly (optional self-test)

### MVP: PDF Documents (.pdf)

**Strip:**
- JavaScript actions (`/JS`, `/JavaScript`)
- Launch actions (`/Launch`)
- Embedded file attachments (`/EmbeddedFile`)
- Form submit actions (`/SubmitForm`)
- URI actions that auto-open (`/URI` with `/AA` auto-action)
- Encrypted streams with weak ciphers (potential obfuscation)
- XFA forms (XML Forms Architecture — frequent exploit vector)

**Preserve:**
- Text, images, vector graphics
- Page layout, fonts, bookmarks
- Standard hyperlinks (non-auto-action)
- Form fields (static, without submit actions)

**Implementation approach:**
1. Parse PDF structure (cross-reference table + object streams)
2. Walk the object tree, identify and remove dangerous objects
3. Rebuild cross-reference table with remaining objects
4. Re-linearize the PDF for streaming delivery

**Go libraries to evaluate:**
- `unidoc/unipdf` (commercial, most complete)
- `pdfcpu` (open source, good for structure manipulation)
- `ledongthuc/pdf` (simple reader, may need extension for writing)

---

## Project Structure

```
Sluice/
├── cmd/
│   └── sluice/
│       └── main.go              # Entrypoint, flag parsing, graceful shutdown
├── internal/
│   ├── server/
│   │   └── grpc.go              # gRPC server implementation
│   ├── sanitizer/
│   │   ├── sanitizer.go         # Sanitizer interface + dispatcher
│   │   ├── office.go            # OOXML sanitizer (docx, xlsx, pptx)
│   │   ├── pdf.go               # PDF sanitizer
│   │   └── detect.go            # File type detection (magic bytes)
│   ├── worker/
│   │   └── pool.go              # Bounded worker pool with backpressure
│   ├── auth/
│   │   ├── mtls.go              # mTLS certificate management
│   │   └── enroll.go            # Enrollment token generation + exchange
│   ├── metrics/
│   │   └── prometheus.go        # Prometheus metrics (files processed, latency)
│   └── config/
│       └── config.go            # YAML config + CLI flags
├── proto/
│   └── sluicev1/
│       ├── sluice.proto         # gRPC service definition (from above)
│       └── sluice_grpc.pb.go    # Generated
├── deploy/
│   ├── Dockerfile               # Multi-stage, distroless base
│   ├── docker-compose.yml       # Standalone deployment
│   └── docker-compose.culvert.yml  # Integrated with Culvert
├── scripts/
│   └── install.sh               # One-line installer (like Culvert's)
├── testdata/
│   ├── clean.docx               # Known-clean Office doc
│   ├── macro.docm               # Macro-enabled doc (test stripping)
│   ├── js.pdf                   # PDF with JavaScript (test stripping)
│   └── nested.zip               # Archive with embedded threats (v0.3)
├── .github/
│   └── workflows/
│       ├── ci.yml               # Build + test + SAST + govulncheck
│       └── security-gate.yml    # gosec + trivy + gitleaks + licenses
├── go.mod
├── go.sum
├── LICENSE                      # MIT
├── README.md
├── SECURITY.md                  # Vulnerability disclosure policy
├── CLAUDE.md                    # AI assistant coding conventions
└── config.example.yaml
```

---

## Configuration

```yaml
# config.yaml
server:
  grpc_addr: ":8443"
  tls:
    cert_file: /data/tls/server.pem
    key_file: /data/tls/server-key.pem
    ca_file: /data/tls/ca.pem        # Client CA for mTLS

workers:
  max_concurrent: 10                   # Max parallel sanitizations
  queue_depth: 50                      # Pending requests before 429
  timeout: 30s                         # Per-file timeout

limits:
  max_file_size: 52428800              # 50 MB
  max_decompressed_size: 104857600     # 100 MB (for archives, v0.3)

sanitization:
  office:
    enabled: true
    strip_macros: true
    strip_ole_objects: true
    strip_activex: true
    strip_external_connections: true
    re_encode_images: true
  pdf:
    enabled: true
    strip_javascript: true
    strip_launch_actions: true
    strip_attachments: true
    strip_xfa: true

logging:
  format: json                         # "json" or "text"
  level: info                          # debug, info, warn, error

metrics:
  prometheus_addr: ":9090"             # Prometheus scrape endpoint

enrollment:
  enabled: true
  token_file: /data/enrollment_token   # Auto-generated on first boot
```

---

## Docker Deployment

### Standalone

```dockerfile
# Dockerfile
FROM golang:1.25 AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /sluice ./cmd/sluice

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /sluice /sluice
EXPOSE 8443 9090
ENTRYPOINT ["/sluice"]
```

### Integrated with Culvert

```yaml
# docker-compose.culvert.yml — add to existing Culvert compose
services:
  sluice:
    image: ghcr.io/kidcarmi/sluice:latest
    container_name: culvert-sluice
    restart: unless-stopped
    ports:
      - "127.0.0.1:8443:8443"   # gRPC (localhost only)
      - "127.0.0.1:9190:9090"   # Prometheus metrics
    volumes:
      - sluice-data:/data
    environment:
      - TZ=UTC
    healthcheck:
      test: ["CMD", "/sluice", "--health"]
      interval: 30s
      timeout: 5s
      retries: 3

volumes:
  sluice-data:
```

---

## Integration Protocol with Culvert

### Enrollment Flow (one-click setup)

```
1. Admin deploys Sluice: docker compose up -d
2. Sluice generates enrollment token on first boot:
   → logs: "Enrollment token: eyJhbGciOi..."
   → saved to /data/enrollment_token

3. Admin opens Culvert GUI → Integrations → Add CDR
   → Enters: Sluice endpoint (IP:8443) + enrollment token
   → Culvert calls Sluice.Enroll(token)
   → Sluice returns: CA cert + client cert + client key
   → Culvert stores certs in /data/integrations/sluice/
   → Token is consumed (one-time use)
   → Connection established with mTLS

4. All subsequent calls use mTLS — no tokens needed
```

### Runtime Flow (per file)

```
Culvert handleTunnelInspect:
  1. Body buffered (existing code)
  2. File extension/magic checks (existing code)
  3. If CDR enabled AND file type supported:
     a. Open gRPC stream to Sluice
     b. Send SanitizeHeader (filename, content-type, size, request-id)
     c. Stream file chunks (64 KB each)
     d. Receive SanitizeResult + sanitized chunks
     e. Replace response body with sanitized content
     f. Update Content-Length header
     g. Log CDR_SANITIZED event with threats removed
  4. ClamAV + YARA scan sanitized body (existing code)
  5. Forward to client
```

### Error Handling

| Sluice response | Culvert action |
|---|---|
| `CLEAN` | Pass through unchanged |
| `SANITIZED` | Replace body with sanitized version, log threats |
| `BLOCKED` | Return 403 to client (file is unsalvageable) |
| `ERROR` | Fail-open: pass through + alert. Fail-closed: block + alert |
| `UNSUPPORTED` | Pass through unchanged (CDR doesn't handle this type) |
| Timeout (30s) | Fail-open/closed per config + circuit breaker |
| Connection refused | Circuit breaker opens + fail-open/closed |

---

## Metrics (Prometheus)

```
sluice_files_processed_total{type="pdf",result="sanitized"} 1247
sluice_files_processed_total{type="docx",result="clean"} 3891
sluice_threats_removed_total{type="macro"} 89
sluice_threats_removed_total{type="javascript"} 23
sluice_sanitize_duration_seconds_bucket{le="0.1"} 3200
sluice_sanitize_duration_seconds_bucket{le="1.0"} 4100
sluice_active_workers 3
sluice_queue_depth 0
sluice_file_size_bytes_bucket{le="1048576"} 2800
```

---

## Testing Requirements

### Unit Tests (per sanitizer)
- Clean file → CLEAN result, unchanged bytes
- Macro-enabled doc → SANITIZED result, macro removed, content preserved
- PDF with JavaScript → SANITIZED result, JS removed, text preserved
- Oversized file → ERROR, rejected before processing
- Corrupt/truncated file → ERROR, graceful handling (no panic)
- Empty file → CLEAN, pass through

### Integration Tests
- Full gRPC round-trip: connect → stream file → receive sanitized
- mTLS: valid cert accepted, invalid cert rejected
- Enrollment: token exchange → cert generation → subsequent mTLS works
- Backpressure: flood with max_workers+1 requests → oldest queued, excess rejected with 429
- Timeout: slow sanitization → client receives timeout error

### Fuzz Tests
- Feed random bytes to each sanitizer — must never panic
- Feed truncated valid files — must return ERROR, not crash
- Feed polyglot files — must detect correctly

---

## CLAUDE.md (for the Sluice repo)

```markdown
# Sluice

CDR (Content Disarm & Reconstruction) engine for the Culvert forward proxy.
Single Go binary, gRPC + mTLS, Docker-native.

## Build & Test

go build -o sluice ./cmd/sluice
go test -race -count=1 ./...
go test -coverprofile=coverage.out ./... (threshold: 60%)

## Code Conventions

- Package layout: cmd/ for entrypoint, internal/ for everything else
- Go version: 1.25 (match Culvert)
- Logging: structured JSON via slog (Go 1.21+ stdlib)
- Errors: return fmt.Errorf("context: %w", err)
- Concurrency: bounded worker pool, context.Context on every operation
- File I/O: always io.LimitReader, always filepath.Clean + containment
- No unsafe, no os/exec, no CGO
- Tests: _test.go in same package (whitebox)
```

---

## Roadmap

| Phase | Scope | Target |
|---|---|---|
| **v0.1 (MVP)** | Office (docx/xlsx/pptx) + PDF sanitization, gRPC server, mTLS, enrollment, Prometheus metrics, Docker image | 2-3 weeks |
| **v0.2** | Image re-encoding (strip EXIF/steganography), SVG script removal | +1 week |
| **v0.3** | Archive support (ZIP/7z/RAR recursive sanitize + repack) | +2 weeks |
| **v0.4** | HTML/email sanitization, configurable sanitization profiles | +1 week |
| **v1.0** | Production hardening, performance benchmarks, admin GUI in Sluice itself | +2 weeks |

---

## Key Design Principles

1. **Fail gracefully** — a crash in the PDF parser must not take down the service. Each file is processed in an isolated goroutine with recover().
2. **Never trust input** — every file is hostile. Magic bytes over Content-Type. LimitReader everywhere. Path traversal checks on every extracted filename.
3. **Observable** — every sanitization logs what was found and removed. Prometheus metrics on everything. Distributed tracing via Traceparent.
4. **Minimal dependencies** — fewer deps = smaller attack surface. Prefer stdlib. Every external dep must be justified.
5. **Culvert-native** — same Go version, same logging conventions, same CI pipeline structure, same Docker base image. An ops team running Culvert should feel at home with Sluice.
