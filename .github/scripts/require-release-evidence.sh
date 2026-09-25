#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# require-release-evidence.sh <sha> <wait|assert>
#
# THE release predicate. Resolves every row of .github/release-evidence.txt for
# <sha> and refuses unless all `mandatory` rows have a main-push run that
# concluded `success`. `advisory` rows are resolved and REPORTED (step summary +
# log) but never block.
#
# This exists because the predicate was previously written out by hand, twice,
# in four places (docker / catalog-pipeline / release / auto-tag), which is how
# the main-push image-publication path ended up with NO copy of it at all: the
# `docker` job's gate step was `if: startsWith(github.ref, 'refs/tags/v')`, so
# on a main push `latest` + the computed semver tags were pushed and signed
# ~29 minutes before the QA and Security verdicts were known (run 35507615339:
# "Apply version tag" 11:40:09Z, gate wait concluded 12:09:14Z). One script
# reading one manifest means a future publication path cannot be added with the
# predicate silently omitted.
#
# Fail-closed by construction:
#   • the manifest must exist, parse, and contain at least one mandatory row —
#     an empty or unreadable manifest is a hard refusal, never "nothing to
#     check" (the vacuous-pass vector);
#   • every row's verdict comes from require-gate.sh, which binds the evidence
#     to the workflow FILE PATH, the exact head_sha, event=push and
#     head_branch==main — so a run of another workflow, another SHA, or a
#     tag-triggered re-run of the same SHA can never authorize this release;
#   • a missing, pending, failed, cancelled, SKIPPED or neutral mandatory run
#     refuses.
#
# Modes are passed straight through to require-gate.sh:
#   wait   — poll (the gates run in parallel with the promoting run).
#   assert — the run must already exist and be green.
#
# Needs `actions: read` and a `gh` on PATH with GH_TOKEN set.
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SHA="${1:?usage: require-release-evidence.sh <sha> <wait|assert>}"
MODE="${2:?mode required: wait|assert}"

case "$MODE" in
  wait|assert) ;;
  *) echo "::error::unknown mode '${MODE}' (want wait|assert) — refusing"; exit 1 ;;
esac

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${RELEASE_EVIDENCE_MANIFEST:-${HERE}/../release-evidence.txt}"
REQUIRE_GATE="${REQUIRE_GATE_SH:-${HERE}/require-gate.sh}"

[ -r "$MANIFEST" ] || {
  echo "::error::release evidence manifest not readable at ${MANIFEST} — refusing"
  exit 1
}
[ -x "$REQUIRE_GATE" ] || [ -r "$REQUIRE_GATE" ] || {
  echo "::error::require-gate.sh not found at ${REQUIRE_GATE} — refusing"
  exit 1
}

summary() { [ -n "${GITHUB_STEP_SUMMARY:-}" ] && printf '%s\n' "$*" >> "$GITHUB_STEP_SUMMARY"; return 0; }

mandatory=()
advisory=()
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
  lineno=$((lineno + 1))
  line="${line%%#*}"                       # strip comments
  # shellcheck disable=SC2001
  line="$(echo "$line" | sed 's/[[:space:]]\{1,\}/ /g; s/^ //; s/ $//')"
  [ -z "$line" ] && continue
  wf="${line%% *}"
  cls="${line#* }"
  if [ "$wf" = "$cls" ]; then
    echo "::error::${MANIFEST}:${lineno}: row '${wf}' has no classification — refusing"
    exit 1
  fi
  case "$cls" in
    mandatory) mandatory+=("$wf") ;;
    advisory)  advisory+=("$wf") ;;
    *) echo "::error::${MANIFEST}:${lineno}: unknown classification '${cls}' for ${wf} (want mandatory|advisory) — refusing"; exit 1 ;;
  esac
done < "$MANIFEST"

if [ "${#mandatory[@]}" -eq 0 ]; then
  echo "::error::${MANIFEST} declares no mandatory evidence — an empty predicate would approve everything; refusing"
  exit 1
fi

echo "Release predicate for ${SHA} (mode=${MODE})"
echo "  mandatory: ${mandatory[*]}"
echo "  advisory : ${advisory[*]:-<none>}"
summary "### Release evidence — \`${SHA}\`"
summary ""
summary "| workflow | class | verdict |"
summary "| --- | --- | --- |"

failed=0
for wf in "${mandatory[@]}"; do
  if bash "$REQUIRE_GATE" "$wf" "$SHA" "$MODE"; then
    summary "| \`${wf}\` | mandatory | ✅ success |"
  else
    # require-gate.sh already emitted the ::error:: naming the conclusion.
    summary "| \`${wf}\` | mandatory | ❌ **REFUSED** |"
    failed=1
  fi
done

# Advisory rows are resolved in `assert` mode regardless of the caller's mode:
# an advisory verdict must never make the predicate WAIT, only report.
for wf in "${advisory[@]}"; do
  if bash "$REQUIRE_GATE" "$wf" "$SHA" assert >/dev/null 2>&1; then
    echo "advisory ${wf}: success"
    summary "| \`${wf}\` | advisory | ✅ success |"
  else
    echo "::warning::advisory evidence ${wf} is NOT green for ${SHA} — promotion continues (advisory row in .github/release-evidence.txt)"
    summary "| \`${wf}\` | advisory | ⚠️ not green (non-blocking) |"
  fi
done

if [ "$failed" -ne 0 ]; then
  echo "::error::release evidence predicate REFUSED for ${SHA} — no public tag or release asset may be promoted"
  summary ""
  summary "**Predicate REFUSED — promotion blocked.**"
  exit 1
fi

echo "release evidence predicate satisfied for ${SHA}"
summary ""
summary "**Predicate satisfied.**"
