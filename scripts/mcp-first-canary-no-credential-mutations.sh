#!/usr/bin/env bash
# mcp-first-canary-no-credential-mutations.sh — the §13 campaign for the CREDENTIAL-FREE
# FIRST-CANARY PATH (blocker #9, first disjunct).
#
# The property under test: every execution the First-Canary activation admits requires ZERO
# credential materialization. That is NOT a claim that Culvert cannot support authenticated MCP
# servers — it is an experiment-specific guarantee, and this campaign is what stops it decaying
# into an assumption.
#
# The defect it closes: blocker #14's ExactPolicyPermit refuses a matched rule carrying a
# CredentialProfile OBLIGATION, and that is only one of three authoritative credential statements
# — the one any enforcement path actually reads. The authoritative registry server record is read
# by NO enforcement path at all, and the catalog fingerprint reaches enforcement only through
# fingerprint equality. So policy saying "no credential" while the server record requires one is
# not a contradiction the engine can see: execution takes the no-broker branch and reaches a
# credential-REQUIRED upstream with NO Authorization header.
#
# Each mutation reintroduces ONE specific way that could come back, then runs the NAMED gate that
# must catch it. A mutation no test rejects is not a passing mutation: it is a hole.
#
#   M01  ExactPolicyPermit accepts a CredentialProfile obligation
#   M02  the authoritative server credential requirement is ignored
#   M03  the server statement is read from the fingerprint, so a disagreement passes
#   M04  the reviewed/catalog credential statement is ignored
#   M05  broker.Plan is consulted on the no-credential path
#   M06  broker.Materialize is reached on the no-credential path
#   M07  an Authorization header is attached despite an empty profile
#   M08  a credential-required decision falls through with no broker
#   M09  CredentialProfile is dropped from the tool fingerprint
#   M10  a stale reviewed set is accepted after the credential change
#   M11  auxiliary tools/list discovery carries a credential
#   M12  readiness consumes the POLICY fact, ignoring the authoritative inventory
#   M13  the readiness row is hard-coded true at the wiring step
#   M14  the resolver is constant-false (anti-vacuity: the positive control must fail)
#   M15  the transition commit forwards the wrong probe field
#   M16  the restart reconcile forwards the wrong probe field
#   M17  an engine error is reported as a credential-free answer
#   M18  the matrix doc's activation row list drifts from the table
#
# M14 is the anti-vacuity mutation §13 requires. A resolver returning constant false passes every
# negative gate above while making the First Canary permanently impossible, so the campaign is
# only meaningful if a POSITIVE control rejects it.
#
# A COMPILE FAILURE IS NOT PROOF unless the mutation targets a structural wall whose stated
# purpose is compile-time prevention (those declare --compile-wall).
#
# Usage:  scripts/mcp-first-canary-no-credential-mutations.sh [-k]
#         (-k: keep going after a surviving mutation; default stops at the first survivor)
set -uo pipefail
cd "$(dirname "$0")/.."

KEEP=0
[ "${1:-}" = "-k" ] && KEEP=1

# The campaign mutates tracked files IN PLACE and reverts them with `git checkout`.
# Running it against a dirty tree therefore DESTROYS uncommitted work.
if ! git diff --quiet || ! git diff --cached --quiet; then
  printf 'refusing to run: the working tree has uncommitted changes to tracked files.\n'
  git status --short
  exit 2
fi

PASS=0; SURVIVED=0; SKIPPED=0
declare -a SURVIVORS=()

revert() { git checkout -- "$@" 2>/dev/null || true; }

# IN-FLIGHT MUTATION RECOVERY (Codex P2 round 8, PR #1378).
#
# revert runs only AFTER `go test` returns. If the run is interrupted or killed in between --
# Ctrl-C, a harness reaping the process, the OOM killer, or the disk filling so the toolchain dies
# -- the shell exits with a DELIBERATELY DEFECTIVE production change still in the worktree. Later
# builds then compile against the wrong source, and the mutation can be committed by accident.
#
# This is not hypothetical: during this PR a run died mid-M12 and left ApproveLive rewritten to call
# promoteFor -- the exact authority-separation violation the Canary design forbids -- sitting
# uncommitted in a tracked file. It was noticed by `git status`, not by anything here.
#
# So the file under mutation is recorded before the first edit and cleared after the revert, and an
# EXIT/INT/TERM trap restores whatever is still recorded. EXIT covers the ordinary and `set -e`
# paths; INT and TERM cover the signals that skip it. SIGKILL cannot be trapped by anyone, which is
# why the campaign also refuses to start on a dirty tree -- a stranded mutation from a SIGKILLed run
# stops the next run rather than being silently re-measured.
MUTATING_FILE=""
restore_in_flight() {
  local rc=$?
  if [ -n "$MUTATING_FILE" ]; then
    printf "\n!! interrupted with %s still mutated — restoring it\n" "$MUTATING_FILE" >&2
    revert "$MUTATING_FILE"
    MUTATING_FILE=""
  fi
  return $rc
}
trap restore_in_flight EXIT
trap 'restore_in_flight; exit 130' INT
trap 'restore_in_flight; exit 143' TERM

# has_re / has_fixed use a herestring, never a producer pipe: under `set -o pipefail` a
# matched grep kills printf with SIGPIPE and the PIPELINE scores as failed.
has_re()    { grep -qE -- "$1" <<<"$2"; }
has_fixed() { grep -qF -- "$1" <<<"$2"; }

build_or_vet_failed() {
  has_re '\[build failed\]|\[setup failed\]|^vet: |^# github\.com/KidCarmi' "$1"
}

# gate_ran reports whether a `go test` invocation actually REACHED an assertion. The two
# ways it does not — the -run pattern matched nothing (exit 0, looks like a pass) and the
# package did not build (nonzero, looks like a catch) — are both misread by a bare status
# check, so every result decision goes through here.
gate_ran() {
  local id="$1" label="$2" out="$3"
  if has_fixed 'no tests to run' "$out"; then
    printf '      BROKEN GATE — %s matched no tests; this proves NOTHING\n' "$label"
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: BROKEN GATE ($label matched no tests)")
    return 1
  fi
  if build_or_vet_failed "$out"; then
    printf '      NOT PROVEN — %s did not BUILD, so no gate ran; this proves NOTHING\n' "$label"
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN ($label build/vet failure, not an assertion)")
    return 1
  fi
  return 0
}

# run_mutation <id> <description> [--compile-wall] <gate-regex> <package> <file> <perl-script...>
run_mutation() {
  local id="$1" desc="$2"; shift 2
  local compile_wall=0
  [ "${1:-}" = "--compile-wall" ] && { compile_wall=1; shift; }
  local gate="$1" pkg="$2" file="$3"; shift 3

  printf '\n[%s] %s\n' "$id" "$desc"
  printf '      gate: %s  (%s)\n' "$gate" "$pkg"

  local before; before="$(git rev-parse HEAD:"$file" 2>/dev/null || echo none)"
  MUTATING_FILE="$file" # armed BEFORE the first edit; the trap restores it if we die here
  for script in "$@"; do
    perl -0pi -e "$script" "$file"
  done
  local after; after="$(git hash-object "$file")"
  if [ "$before" = "$after" ]; then
    printf '      SKIPPED — the mutation did not change %s (pattern drifted)\n' "$file"
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: SKIPPED (pattern drifted in $file)")
    revert "$file"; MUTATING_FILE=""
    [ $KEEP -eq 0 ] && exit 1
    return
  fi

  local out; out="$(go test -count=1 -run "$gate" "$pkg" 2>&1)"
  local rc=$?
  revert "$file"; MUTATING_FILE=""

  if [ $compile_wall -eq 1 ]; then
    if build_or_vet_failed "$out"; then
      printf '      CAUGHT (structural wall: the mutation does not compile, as required)\n'
      PASS=$((PASS+1))
    else
      printf '      *** SURVIVED *** a compile-time wall must REJECT this at build time\n'
      SURVIVED=$((SURVIVED+1)); SURVIVORS+=("$id: $desc")
      [ $KEEP -eq 0 ] && { printf '\nstopping at first survivor (pass -k to continue)\n'; exit 1; }
    fi
    return
  fi

  if ! gate_ran "$id" "the gate in $pkg" "$out"; then
    printf '%s\n' "$out" | tail -8 | sed 's/^/        /'
    [ $KEEP -eq 0 ] && exit 1
    return
  fi

  if [ $rc -ne 0 ]; then
    printf '      CAUGHT (gate failed as required)\n'
    PASS=$((PASS+1))
  else
    printf '      *** SURVIVED *** the gate passed with the defect reintroduced\n'
    printf '%s\n' "$out" | tail -5 | sed 's/^/        /'
    SURVIVED=$((SURVIVED+1)); SURVIVORS+=("$id: $desc")
    [ $KEEP -eq 0 ] && { printf '\nstopping at first survivor (pass -k to continue)\n'; exit 1; }
  fi
}

printf 'MCP FIRST-CANARY CREDENTIAL-FREE PATH mutation campaign (blocker #9)\n'
printf '===================================================================\n'

PERMIT=internal/mcp/canary/permit.go
CREDFREE=internal/mcp/canary/credfree.go
RESOLVER=mcp_canary_policy_permit.go
PREFLIGHT=mcp_canary_preflight.go
RUN=internal/mcp/execution/run.go
FINGERPRINT=internal/mcp/catalog/fingerprint.go
DISCOVERY=internal/mcp/execution/discovery.go
ROLLOUT=mcp_rollout.go
MATRIXDOC=docs/design/mcp/CANARY-READINESS-MATRIX.md

# ── the three authoritative layers ────────────────────────────────────────────

# M01 — THE PERMIT ACCEPTS A CREDENTIAL OBLIGATION. Blocker #14's half of the property: an ALLOW
# carrying a credential_profile obligation would plan and materialize at call time.
run_mutation M01 \
  'ExactPolicyPermit accepts a CredentialProfile obligation' \
  'TestCredFreeE2E_PolicyObligationCredentialIsRefused' . "$PERMIT" \
  's/\tcase o\.CredentialProfile != "",\n/\tcase /'

# M02 — THE SERVER REQUIREMENT IS IGNORED. THE defect blocker #9 exists for: the policy permit is
# satisfied, the authoritative server record requires a credential, and nothing objects. Execution
# then reaches a credential-required upstream with no Authorization at all.
run_mutation M02 \
  'the authoritative server credential requirement is ignored' \
  'TestCredFreeE2E_ServerCredentialProfileIsRefused' . "$CREDFREE" \
  's/\tif in\.ServerCredentialProfile != "" \{\n\t\treturn CredFreeServerRequires\n\t\}\n//'

# M03 — THE SERVER STATEMENT IS READ FROM THE FINGERPRINT. Subtle and plausible: both are
# "the credential profile", so reading one for the other looks like a simplification. It collapses
# three statements to two and makes a registry/catalog disagreement invisible.
run_mutation M03 \
  'the server statement is read from the fingerprint, so a disagreement passes' \
  'TestCredFreeWall_CredentialFactsComeFromTheCapturedRecords' . "$RESOLVER" \
  's/ServerCredentialProfile:  string\(srv\.CredentialProfile\)/ServerCredentialProfile:  string(rec.Fingerprint.CredentialProfile)/'

# M04 — THE REVIEWED/CATALOG STATEMENT IS IGNORED. The fingerprint is what the four-eyes approval
# bound, so dropping it means the reviewed target's own credential claim stops being checked.
run_mutation M04 \
  'the reviewed/catalog credential statement is ignored' \
  'TestCredFree_EachLayerIsIndependentlyLoadBearing' ./internal/mcp/canary "$CREDFREE" \
  's/\tif in\.CatalogCredentialProfile != "" \{\n\t\treturn CredFreeCatalogRequires\n\t\}\n//'

# ── the execution path ────────────────────────────────────────────────────────

# M05 — THE BROKER IS CONSULTED ON THE NO-CREDENTIAL PATH. Dropping the profileRef term reads as a
# simplification of a nil check; it routes every execution through credential planning.
run_mutation M05 \
  'broker.Plan is consulted on the no-credential path' \
  'TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery' . "$RUN" \
  's/useBroker := e\.cfg\.Broker != nil && profileRef != ""/useBroker := e.cfg.Broker != nil/'

# M06 — MATERIALIZE IS REACHED ANYWAY. The same destination by a different route: the
# no-credential branch stops short-circuiting.
run_mutation M06 \
  'broker.Materialize is reached on the no-credential path' \
  'TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery' . "$RUN" \
  's/\t\tif !useBroker \{\n\t\t\treturn callUpstream\(""\)\n\t\t\}/\t\tif !useBroker \&\& e.cfg.Broker == nil {\n\t\t\treturn callUpstream("")\n\t\t}/'

# M07 — AN AUTHORIZATION HEADER IS ATTACHED ANYWAY. The upstream leg carries a credential the
# decision never authorized and no obligation covers.
run_mutation M07 \
  'an Authorization header is attached despite an empty profile' \
  'TestCredZeroUse_CanonicalPathNeverTouchesTheCredentialMachinery' . "$RUN" \
  's/\t\t\treturn callUpstream\(""\)/\t\t\treturn callUpstream("Bearer ambient")/'

# M08 — A CREDENTIAL-REQUIRED DECISION FALLS THROUGH WITH NO BROKER. The pre-existing fail-closed
# guard (ReasonCredentialProfileMissing) is the one §7 requires to stay intact.
run_mutation M08 \
  'a credential-required decision falls through with no broker' \
  'TestCredZeroUse_CredentialRequiredWithNoBrokerFailsClosed' . "$RUN" \
  's/\tcase in\.Decision\.Obligations\.CredentialProfile != "" && e\.cfg\.Broker == nil:/\tcase false:/'

# ── drift ─────────────────────────────────────────────────────────────────────

# M09 — CREDENTIALPROFILE LEAVES THE FINGERPRINT. This is the §10 dependency made executable: if
# the credential profile is not hashed into the tool identity, none -> profile-X does NOT change
# the fingerprint, every reviewed binding keeps matching, and the credential requirement can appear
# under a live activation with nothing noticing. The whole runtime drift guarantee rests here.
run_mutation M09 \
  'CredentialProfile is dropped from the tool fingerprint' \
  'TestCredFreeE2E_CredentialProfileChangesTheFingerprint' . "$FINGERPRINT" \
  's/\twriteSeg\(\[\]byte\(f\.CredentialProfile\)\)\n//'

# M10 — A STALE REVIEWED SET IS ACCEPTED. The activation keeps honouring a reviewed determination
# taken before the credential requirement appeared.
run_mutation M10 \
  'a stale reviewed set is accepted after the credential change' \
  'TestCredDrift_CredentialChangeBreaksTheReviewedBinding' . "$RESOLVER" \
  's/\t\treturn set\.ReviewedReadFirst\(cur\)/\t\t_ = set\n\t\treturn true/'

# ── auxiliary traffic ─────────────────────────────────────────────────────────

# M11 — DISCOVERY CARRIES A CREDENTIAL. tools/list runs OUTSIDE the policy decision, so a
# credential attached here rides no decision and is covered by no obligation.
run_mutation M11 \
  'auxiliary tools/list discovery carries a credential' \
  'TestCredZeroUse_AuxiliaryTrafficCarriesNoAuthorization' . "$DISCOVERY" \
  's/upstreamclient\.CallOptions\{Idempotent: true, WireID: "disc-" \+ string\(rec\.ID\)\}/upstreamclient.CallOptions{Idempotent: true, AuthHeader: "Bearer ambient", WireID: "disc-" + string(rec.ID)}/'

# ── the readiness wiring ──────────────────────────────────────────────────────

# M12 — READINESS CONSUMES THE POLICY FACT. The exact conflation blocker #9 names: "the policy
# permit already refuses credentials, so reuse it". It is true about the obligation and says
# nothing about the authoritative inventory.
run_mutation M12 \
  'readiness consumes the POLICY fact, ignoring the authoritative inventory' \
  'TestCredWall_ReadinessConsumesTheResolvedFactNotALiteral' . "$PREFLIGHT" \
  's/FirstCanaryCredentialFree: exact\.CredentialFree/FirstCanaryCredentialFree: exact.Permit/'

# M13 — THE ROW IS HARD-CODED TRUE. The cheapest way to defeat every behavioural gate at once,
# because the gates call the resolver directly and never see the wiring.
run_mutation M13 \
  'the readiness row is hard-coded true at the wiring step' \
  'TestCredWall_ReadinessConsumesTheResolvedFactNotALiteral' . "$PREFLIGHT" \
  's/FirstCanaryCredentialFree: exact\.CredentialFree/FirstCanaryCredentialFree: true/'

# M15 — THE TRANSITION COMMIT DROPS THE FACT. The commit path builds its own
# CanaryActivationInput; forwarding a different probe field there discards the credential verdict
# while every behavioural gate — which calls the resolver directly — keeps passing.
run_mutation M15 \
  'the transition commit forwards the wrong probe field' \
  'TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall' . "$ROLLOUT" \
  's/FirstCanaryCredentialFree: ai\.FirstCanaryCredentialFree,\n\t\t\tNow:/FirstCanaryCredentialFree: ai.ServerUsable,\n\t\t\tNow:/'

# M16 — THE RESTART RECONCILE DROPS THE FACT. Same defect at the other call site: a node that
# restarts into a Canary re-derives readiness there, so a discarded verdict re-arms an activation
# whose credential requirement reappeared while the node was down.
run_mutation M16 \
  'the restart reconcile forwards the wrong probe field' \
  'TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall' . "$ROLLOUT" \
  's/FirstCanaryCredentialFree: ai\.FirstCanaryCredentialFree,\n\t\t\t\t\tNow:/FirstCanaryCredentialFree: ai.ServerUsable,\n\t\t\t\t\tNow:/'

# ── anti-vacuity ──────────────────────────────────────────────────────────────

# M14 — THE RESOLVER IS CONSTANT-FALSE. It passes every negative gate above while making the First
# Canary permanently impossible — strictly worse than the defect, and invisible to a campaign with
# no positive control. §13 requires this to be REJECTED by a control, not by a negative.
run_mutation M14 \
  'the resolver is constant-false (anti-vacuity: a POSITIVE control must reject it)' \
  'TestCredFree_CanonicalCredentialFreePathIsOK' ./internal/mcp/canary "$CREDFREE" \
  's/func EvaluateCredentialFree\(in CredentialFreeInput\) CredentialFreeReason \{\n/func EvaluateCredentialFree(in CredentialFreeInput) CredentialFreeReason {\n\treturn CredFreeUnavailable\n/'

# M17 — AN ENGINE ERROR READS AS CREDENTIAL-FREE. On that path the Decision is the zero value, so
# the POLICY statement is "" and an empty inventory yields CredFreeOK: "provably credential-free"
# for a tuple whose policy verdict could not be computed. Found in self-review, not by a test.
run_mutation M17 \
  'an engine error is reported as a credential-free answer' \
  'TestCredWall_EngineErrorIsNotACredentialFreeAnswer' . "$RESOLVER" \
  's/Resolved:                 err == nil,/Resolved:                 true,/'

# M18 — THE MATRIX DOC'S ROW LIST DRIFTS. Inserting a row renumbers every row after it, and the
# prose that names rows by NUMBER silently stops describing the table. This document has produced
# that defect three times (its own paragraph records the first two); this PR produced it again in
# EIGHT places, of which review caught one. The gate derives the activation set from the exported
# evaluator behaviour and maps it through the table, so no hand-maintained number is trusted.
run_mutation M18 \
  "the matrix doc's activation row list drifts from the table" \
  'TestCredWall_MatrixDocActivationRowsMatchTheTable' . "$MATRIXDOC" \
  's/Rows 3, 4, 4a, 16, 17, 18, 19, 20, 21, 24 \(scope/Rows 3, 4, 4a, 16, 17, 18, 19, 20, 23 (scope/'

printf '\n===================================================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ ${#SURVIVORS[@]} -gt 0 ]; then
  printf '\nNOT PROVEN:\n'
  for s in "${SURVIVORS[@]}"; do printf '  - %s\n' "$s"; done
  exit 1
fi
printf 'every mutation was caught by a named gate.\n'
