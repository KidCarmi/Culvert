# appliance/clamav/Dockerfile — the ClamAV sidecar the appliance RUNS.
#
# ENGINE: official ClamAV 1.5.4, pinned by digest. The move from 1.4.6 to
# 1.5.4 (#1528, 2026-10-16) closes F-P2 — the detection bypass where clamd
# answers a clean verdict for a file it never scanned when it cannot create
# its per-scan temporary directory (libclamav scan_common rewrites the mkdir
# failure to CL_SUCCESS; reported to Cisco PSIRT as PSIRT-0035161972 against
# 1.4.6). In 1.5.x that per-scan mkdir runs ONLY under the debug option
# LeaveTemporaryFiles (ENGINE_OPTIONS_TMPDIR_RECURSION), which clamd leaves
# off by default; the default path uses the configured temp directory and
# creates no per-scan directory, so the edge that triggers F-P2 is not
# reached. The appliance does not enable LeaveTemporaryFiles. Evidence:
# docs/appliance/readiness-report.md §3k and test/e2e/appliance/lab/evidence/
# fp2-reproduction.md (lab branch); the [fp2-isolated] lab leg re-runs the
# reproduction against this candidate's baked sidecar and must deliver 0.
#
# CVEs: the official 1.5.4 image already ships pcre2 10.49-r0 (CVE-2026-103111,
# HIGH), zlib 1.3.2-r1 (CVE-2026-85091) and nghttp2-libs 1.70.0-r0
# (CVE-2026-58055) — the exact three versions the former 1.4.6 derivative
# upgraded by hand (the old pinned 1.4.6 build carried pcre2 10.48 / zlib
# 1.3.2-r0 / nghttp2-libs 1.69.0). The apk line below is therefore a VERIFIED
# NO-OP on this base: it asserts those versions are present rather than
# changing them, so a future base rebuild that regressed a package fails the
# build instead of shipping silently. It stays the smallest possible
# derivative: the pinned official image, no other package, file, user,
# entrypoint, healthcheck, port, volume or environment value changes.
#
# musl / musl-utils 1.2.6-r3 (CVE-2026-107891; the base ships 1.2.6-r2) is a
# REAL upgrade, not a no-op: Alpine secdb v3.24 lists the fix in -r3. Its
# impact text was not obtainable when pinned (no NVD record yet), so it is
# fixed rather than dispositioned. New bytes, so a new tag (culvert.2) and the
# F-P2 reproduction must re-run on THIS sidecar; earlier F-P2 evidence does
# not carry over (docs/appliance/r6-r7-security-dispositions.md).
#
# brotli-libs 1.2.1-r0 (CVE-2026-111497, HIGH; the base ships 1.2.0-r1) is
# likewise a REAL upgrade, found by the Deep gate's trivy scan of this sidecar
# on 2026-10-24. Alpine v3.24 main carries the fix in -r1. New bytes, so a new
# tag (culvert.3), and the F-P2 reproduction must re-run on THIS sidecar too.
#
# libcurl 8.23.0-r0 (CVE-2026-92392, HIGH, "HTTP/2 upload Use-After-Free"; the
# base ships 8.22.0-r0) is a REAL upgrade, found by the Deep gate's trivy scan
# on 2026-10-27. It is a SEPARATE `apk add` WITHOUT --upgrade on purpose:
# --upgrade also upgrades a package's dependencies, which for libcurl would
# float c-ares and ca-certificates-bundle to whatever Alpine ships that day
# (measured with apk 3.0.8 against the base). Plain `add` of the exact version
# changes libcurl alone. New bytes, so a new tag (culvert.4), and F-P2 must
# re-run on THIS sidecar.
#
# The tag (manifest.env CLAMAV_SIDECAR_REF) changes with EVERY content change:
# Compose builds this image only when its local tag is ABSENT, so new content
# under an old tag would never reach an existing appliance.
#
# It is BUILT LOCALLY and NEVER PUBLISHED: the OVA build bakes it
# (appliance/build/build-ova.sh) and docker-compose.yml builds it from this
# directory only when its local-only tag (manifest.env CLAMAV_SIDECAR_REF) is
# absent; Compose never pulls that name from a registry.
#
# 2026-10-08 (#1528, retained-OVA comparison): two OVA builds of the same
# source baked sidecars with different image IDs. Every package and library
# was byte-identical; the layer differed only in file mtimes and in
# /var/log/apk.log (an install log that records the build time). The log and
# apk's index cache are removed here, and build-ova.sh builds with
# rewrite-timestamp and refuses an OVA whose sidecar does not rebuild to the
# same image ID — so the same source bakes the same sidecar.
#
# The FROM digest must equal manifest.env CLAMAV_IMAGE_INDEX_DIGEST
# (pinned by TestClamAVSidecar_DerivesFromThePinnedOfficialImage).
FROM docker.io/clamav/clamav@sha256:638d90201ee7ee6a82d249a2fc23b132e578673b5f1f2766852b127676ca1ef6
RUN apk add --no-cache --upgrade 'pcre2=10.49-r0' 'zlib=1.3.2-r1' 'nghttp2-libs=1.70.0-r0' 'musl=1.2.6-r3' 'musl-utils=1.2.6-r3' 'brotli-libs=1.2.1-r0' \
 && test "$(apk info -v 2>/dev/null | grep '^musl-[0-9]')" = 'musl-1.2.6-r3' \
 && test "$(apk info -v 2>/dev/null | grep '^musl-utils-[0-9]')" = 'musl-utils-1.2.6-r3' \
 && test "$(apk info -v 2>/dev/null | grep '^pcre2-[0-9]')" = 'pcre2-10.49-r0' \
 && test "$(apk info -v 2>/dev/null | grep '^zlib-[0-9]')" = 'zlib-1.3.2-r1' \
 && test "$(apk info -v 2>/dev/null | grep '^nghttp2-libs-[0-9]')" = 'nghttp2-libs-1.70.0-r0' \
 && test "$(apk info -v 2>/dev/null | grep '^brotli-libs-[0-9]')" = 'brotli-libs-1.2.1-r0' \
 && apk add --no-cache 'libcurl=8.23.0-r0' \
 && test "$(apk info -v 2>/dev/null | grep '^libcurl-[0-9]')" = 'libcurl-8.23.0-r0' \
 && rm -rf /var/log/apk.log /var/cache/apk/*
