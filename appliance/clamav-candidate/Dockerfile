# appliance/clamav-candidate/Dockerfile — CANDIDATE ONLY, NOT PUBLISHED.
#
# Review artefact for CVE-2026-103111 (pcre2 < 10.49, PR #1528). As of
# 2026-10-03 no official clamav/clamav image carries the fix: the Alpine
# variants ship pcre2 10.48-r0 and the Debian 13 variants ship 10.46-1~deb13u2
# (fixed in ~deb13u3), and the newest official builds (2026-09-28) predate the
# advisory (2026-09-30). This file shows the smallest possible derivative:
# the PINNED official 1.4.6 image, by digest, with exactly one package
# upgraded. No other package, file, user, entrypoint, healthcheck, port,
# volume or environment value changes (verified by config hash in
# docs/appliance/sbom-cve-evidence.md).
#
# Nothing references this image: the appliance pin (appliance/build/
# manifest.env CLAMAV_IMAGE_*) stays on the official digest until the owner
# decides. CI BUILDS it (never pushes) and runs the real-ClamAV check
# test/e2e/appliance/clamav-image-qualify.sh against it.
#
# The FROM digest must equal manifest.env CLAMAV_IMAGE_INDEX_DIGEST
# (pinned by TestClamAVCandidate_DerivesFromThePinnedOfficialImage).
FROM docker.io/clamav/clamav@sha256:57deb108fc4c72778aa83eafbca7bb7153e28c3f57c005afd38d31f16da86f23
RUN apk add --no-cache --upgrade 'pcre2=10.49-r0' \
 && test "$(apk info -v 2>/dev/null | grep '^pcre2-[0-9]')" = 'pcre2-10.49-r0'
