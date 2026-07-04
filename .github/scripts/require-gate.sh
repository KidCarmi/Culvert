#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# require-gate.sh <workflow-file> <sha> <wait|assert>
#
# Verifies that a gate WORKFLOW FILE concluded `success` for <sha> on a push to
# main. This replaces the old check-run-NAME grep, which was spoofable: a
# check-run's display name is not a trust boundary — any job producing a check
# named "✅ Security Gate — APPROVED" satisfied it. Querying by workflow file
# path binds the gate to trusted, reviewed CI code that a job name cannot forge.
#
# Provenance binding (closes the tag-run collision): the gate workflows re-run
# on the tag push with the SAME head_sha (event=push, head_branch != main). The
# list-runs API returns runs newest-first, so the tag run is [0]. We therefore
# filter to `head_branch == "main"` ACROSS the array and take the latest such
# run — the main-push run is the only proof the commit was reviewed-green on
# main; a tag-triggered re-run of the same SHA must NEVER count as approval.
#
# Modes:
#   wait   — poll up to 30 min (auto-tag: the gate runs in PARALLEL on the same
#            main push, so "no completed run yet" means keep waiting).
#   assert — fail closed immediately if no successful main-push run exists
#            (tag-path guards on docker/catalog-pipeline/release: the main run
#            must already exist; qa-gate.yml doesn't even run on tags, so its
#            only possible run for this SHA is the main-push one).
#
# Fail-closed everywhere: a red conclusion fails NOW; a gh-api error aborts
# (never parsed as "pending"); an empty/absent main run is pending (wait) or a
# hard refusal (assert). Needs `actions: read` (list-workflow-runs endpoint).
#
# THREAT-MODEL LIMIT: on the tag path this script is checked out from the
# TAGGED tree — an attacker who can push an arbitrary tag can also strip this
# guard. F2 (this script) only defends against tagging a real, reviewed main
# commit that wasn't green. The only control against an attacker-controlled
# tagged tree is the repo ruleset restricting v* creation to the actions bot
# (F3, see roadmap/CI-REDESIGN.md).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

WF="${1:?usage: require-gate.sh <workflow-file> <sha> <wait|assert>}"
SHA="${2:?sha required}"
MODE="${3:?mode required: wait|assert}"
REPO="${GITHUB_REPOSITORY:?GITHUB_REPOSITORY not set}"

query_latest_main_run() {
  # Emit "<status>:<conclusion>" for the newest main-push run of WF at SHA,
  # or "none:null" when no such run exists. A gh-api failure returns non-zero
  # (caught by the caller → fail closed).
  gh api "repos/${REPO}/actions/workflows/${WF}/runs?head_sha=${SHA}&event=push&per_page=100" \
    --jq '([.workflow_runs[] | select(.head_branch == "main")][0]) as $r
          | (($r.status // "none") + ":" + ($r.conclusion // "null"))'
}

attempts=1
[ "$MODE" = "wait" ] && attempts=60

for i in $(seq 1 "$attempts"); do
  if ! RES="$(query_latest_main_run)"; then
    echo "::error::gh api failed querying ${WF} runs for ${SHA} — refusing (fail closed)"
    exit 1
  fi
  STATUS="${RES%%:*}"
  CONCL="${RES##*:}"

  case "$CONCL" in
    success)
      echo "${WF}: main-push run for ${SHA} concluded success."
      exit 0 ;;
    failure|cancelled|timed_out|action_required|startup_failure|stale)
      echo "::error::${WF} main-push run for ${SHA} concluded '${CONCL}' — refusing"
      exit 1 ;;
  esac

  # Not concluded yet (or no main-push run at all).
  if [ "$MODE" = "assert" ]; then
    echo "::error::${WF} has no successful main-push run for ${SHA} (status=${STATUS}, conclusion=${CONCL}) — refusing"
    exit 1
  fi
  echo "Attempt ${i}/${attempts}: ${WF} not concluded for ${SHA} (status=${STATUS}, conclusion=${CONCL}); waiting 30s..."
  sleep 30
done

echo "::error::${WF} did not conclude within timeout for ${SHA} — refusing (fail closed)"
exit 1
