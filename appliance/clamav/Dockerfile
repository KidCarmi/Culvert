# appliance/clamav/Dockerfile — the ClamAV sidecar the appliance RUNS.
#
# CVE-2026-103111 (pcre2 < 10.49, HIGH): no official clamav/clamav image
# carries the fix (checked 2026-10-05: every 1.4 / 1.5 tag is the 2026-09-28
# build, which predates the 2026-09-30 advisory; the Debian variants are also
# affected and add other HIGH/CRITICAL findings — sbom-cve-evidence.md). This
# is the smallest possible derivative: the PINNED official 1.4.6 image, by
# digest, with exactly one package upgraded. No other package, file, user,
# entrypoint, healthcheck, port, volume or environment value changes.
#
# It is BUILT LOCALLY and NEVER PUBLISHED: the OVA build bakes it
# (appliance/build/build-ova.sh) and docker-compose.yml builds it from this
# directory only when its local-only tag (manifest.env CLAMAV_SIDECAR_REF) is
# absent; Compose never pulls that name from a registry. Switch back to the
# official image once upstream ships a build with pcre2 >= 10.49.
#
# The FROM digest must equal manifest.env CLAMAV_IMAGE_INDEX_DIGEST
# (pinned by TestClamAVSidecar_DerivesFromThePinnedOfficialImage).
FROM docker.io/clamav/clamav@sha256:57deb108fc4c72778aa83eafbca7bb7153e28c3f57c005afd38d31f16da86f23
RUN apk add --no-cache --upgrade 'pcre2=10.49-r0' \
 && test "$(apk info -v 2>/dev/null | grep '^pcre2-[0-9]')" = 'pcre2-10.49-r0'
