#!/usr/bin/env bash
# mcp-first-canary-policy-permit-mutations.sh — the §14 campaign for the EXACT FIRST-CANARY
# POLICY PERMIT (blocker #14).
#
# The defect this closes: the readiness table's only policy row was PolicyHealthy, which is
# `mcpPolicy.composed()` — a snapshot EXISTS. Nothing asked what the exact request RESOLVES to.
# A node could hold an exact scope, a reviewed read-first target, a four-eyes live approval, a
# catalog-usable tool (blocker #13) and a valid budget, report Ready:true — and then have every
# request answered by default deny, an explicit DENY, a QUARANTINE, a REQUIRE_*, or an
# allow-class action whose obligation nothing on this node can satisfy.
#
# Each mutation reintroduces ONE specific way that could come back, then runs the NAMED gate
# that must catch it. A mutation no test rejects is not a passing mutation: it is a hole.
#
#   M01  PolicyHealthy is substituted for the exact permit
#   M02  default DENY is accepted as a permit
#   M03  an unmatched rule is treated as a permit
#   M04  DENY is accepted because it is "allow-class enough" (IsAllowClass)
#   M05  MONITOR is accepted
#   M06  ALLOW_ONCE is accepted without an allowance proof
#   M07  ALLOW_FOR_SESSION is accepted without a grant proof
#   M08  ALLOW_WITH_REDACTION is accepted without a transform proof
#   M09  a hard override is ignored
#   M10  a credential obligation is treated as satisfied
#   M11  a rate-limit obligation is treated as satisfied
#   M12  a ticket obligation is treated as satisfied
#   M13  the operation class is never checked
#   M14  the exact principal is dropped from the evaluated tuple
#   M15  the exact tool is dropped from the evaluated tuple
#   M16  the winner-invariance check is dropped
#   M17  the rejected-rule invariance check is dropped
#   M18  a truncated trace is accepted as proof
#   M19  an unbound field is declared bound
#   M20  the class check moves back behind the hard override
#   M21  the readiness row is deleted from the activation table
#   M22  the fact is hard-coded true at the wiring step
#   M23  the production probe stops resolving it
#   M24  the commit path drops the resolved fact
#   M25  the restart-reconcile path drops the resolved fact
#   M26  the row is classified node-level, so EvaluateNode starts asserting it
#   M27  the resolver straddles two inventory reads for one decision
#   M28  the resolver evaluates with a second engine (structural wall)
#   M29  the resolver hard-codes a rule identity (structural wall)
#   M30  the permit is persisted into the activation reviewed snapshot (structural wall)
#
# A COMPILE FAILURE IS NOT PROOF unless the mutation targets a structural wall whose stated
# purpose is compile-time prevention (those declare --compile-wall).
#
# Usage:  scripts/mcp-first-canary-policy-permit-mutations.sh [-k]
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

printf 'MCP FIRST-CANARY EXACT POLICY PERMIT mutation campaign\n'
printf '======================================================\n'

PERMIT=internal/mcp/canary/permit.go
READINESS=internal/mcp/canary/readiness.go
RESOLVER=mcp_canary_policy_permit.go
PREFLIGHT=mcp_canary_preflight.go
ROLLOUT=mcp_rollout.go
TUPLE=internal/mcp/runtime/permit_input.go
REVIEWED=internal/mcp/canary/reviewed.go

# ── the verdict itself ────────────────────────────────────────────────────────

# M01 — POLICYHEALTHY SUBSTITUTED FOR THE PERMIT. The exact defect, rebuilt: the resolver stops
# evaluating and reports whether a snapshot merely exists.
run_mutation M01 \
  'PolicyHealthy is substituted for the exact permit' \
  'TestPermitE2E_RejectionMatrix|TestPermitE2E_ProductionPreflightCarriesTheRow' \
  . "$RESOLVER" \
  's/\tr := canary\.EvaluateExactPermit\(buildExactPermitInput\(scope, reviewed, now\)\)\n\treturn r == canary\.PermitOK, r/\tif mcpPolicy.composed() {\n\t\treturn true, canary.PermitOK\n\t}\n\treturn false, canary.PermitTupleUnavailable/'

# M02/M03 — DEFAULT DENY ACCEPTED. The engine falls through to default deny with an empty
# MatchedRule and HardOverride false; dropping the matched-rule test makes that a permit.
run_mutation M02 \
  'default DENY is accepted as a permit (the matched-rule test is dropped)' \
  'TestPermit_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.MatchedRule == "" \{\n\t\treturn PermitNoMatchedRule\n\t\}\n//'

run_mutation M03 \
  'an unmatched rule is treated as a permit (the test is inverted)' \
  'TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.MatchedRule == "" \{\n\t\treturn PermitNoMatchedRule\n\t\}/\tif in.Decision.MatchedRule != "" \&\& false {\n\t\treturn PermitNoMatchedRule\n\t}/'

# M04 — "ALLOW-CLASS ENOUGH". The single most likely wrong turn: Action.IsAllowClass() reads as
# the obvious predicate and admits MONITOR, ALLOW_ONCE, ALLOW_FOR_SESSION and ALLOW_WITH_REDACTION,
# every one of which reaches EffectExecute and is then gated by state no preflight can observe.
run_mutation M04 \
  'the action test is relaxed to Action.IsAllowClass()' \
  'TestPermit_RejectionMatrix|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.Action != policy\.ActionAllow \{/\tif !in.Decision.Action.IsAllowClass() {/'

run_mutation M05 \
  'MONITOR is accepted as an executable permit' \
  'TestPermit_RejectionMatrix|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.Action != policy\.ActionAllow \{/\tif in.Decision.Action != policy.ActionAllow \&\& in.Decision.Action != policy.ActionMonitor {/'

run_mutation M06 \
  'ALLOW_ONCE is accepted without any allowance proof' \
  'TestPermit_RejectionMatrix|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.Action != policy\.ActionAllow \{/\tif in.Decision.Action != policy.ActionAllow \&\& in.Decision.Action != policy.ActionAllowOnce {/'

run_mutation M07 \
  'ALLOW_FOR_SESSION is accepted without any grant proof' \
  'TestPermit_RejectionMatrix|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.Action != policy\.ActionAllow \{/\tif in.Decision.Action != policy.ActionAllow \&\& in.Decision.Action != policy.ActionAllowForSession {/'

run_mutation M08 \
  'ALLOW_WITH_REDACTION is accepted without any transform proof' \
  'TestPermit_RejectionMatrix|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.Action != policy\.ActionAllow \{/\tif in.Decision.Action != policy.ActionAllow \&\& in.Decision.Action != policy.ActionAllowWithRedaction {/'

# M09 — THE HARD OVERRIDE IS IGNORED. A quarantined tool, a disabled server or a cross-tenant
# request all reach the verdict as a decision the operator rule could never have produced.
run_mutation M09 \
  'a hard override is ignored' \
  'TestPermit_RejectionMatrix|TestPermitE2E_QuarantinedToolIsHardOverridden|TestPermitE2E_HardOverrideDifferential' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Decision\.HardOverride \{\n\t\treturn PermitHardOverride\n\t\}\n//'

# ── obligation satisfiability (§6) ────────────────────────────────────────────

run_mutation M10 \
  'a credential obligation is treated as satisfied' \
  'TestPermit_EveryRefusedObligationActuallyRefuses|TestPermitE2E_CredentialFreeRuleIsRequired' \
  ./internal/mcp/canary "$PERMIT" \
  's/\t\to\.CredentialProfile != "",\n//'

run_mutation M11 \
  'a rate-limit obligation is treated as satisfied (no runtime consumer exists)' \
  'TestPermit_EveryRefusedObligationActuallyRefuses|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\t\to\.RateLimitProfile != "",\n//'

run_mutation M12 \
  'a ticket obligation is treated as satisfied (no runtime consumer exists)' \
  'TestPermit_EveryRefusedObligationActuallyRefuses|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\t\to\.TicketRequired,\n//'

# ── the exact tuple (§4/§8) ───────────────────────────────────────────────────

run_mutation M13 \
  'the operation class is never checked' \
  'TestPermit_RejectionMatrix|TestPermitE2E_WriteClassIsNotAPermit' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif !permitReadFirstClass\(in\.OperationClass\) \{\n\t\treturn PermitOperationClassNotReadFirst\n\t\}\n//'

run_mutation M14 \
  'the exact principal is dropped from the evaluated tuple' \
  'TestPermitE2E_WrongPrincipalAndWrongToolAreNotPermits' \
  ./internal/mcp/runtime "$TUPLE" \
  's/\t\t\tSubjectID: in\.SubjectID,/\t\t\tSubjectID: "any-principal",/'

run_mutation M15 \
  'the exact tool name is dropped from the evaluated tuple' \
  'TestPermitE2E_RejectionMatrix|TestPermitE2E_ExactPlainAllowIsAPermit' \
  ./internal/mcp/runtime "$TUPLE" \
  's/\top\.Operand = in\.ToolName/\top.Operand = "other-tool"/'

# ── the invariance proof (§4 "proof, not sample") ─────────────────────────────

run_mutation M16 \
  'the winner-invariance check is dropped (a rule may read an unbound field)' \
  'TestPermit_RejectionMatrix|TestPermitE2E_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tfor _, f := range in\.WinnerConditionFields \{\n\t\tif _, ok := permitBoundFieldSet\[f\]; !ok \{\n\t\t\treturn PermitVerdictNotInvariant\n\t\t\}\n\t\}\n//'

run_mutation M17 \
  'the rejected-rule invariance check is dropped' \
  'TestPermit_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\t\tif _, ok := permitBoundFieldSet\[f\]; !ok \{\n\t\t\treturn PermitVerdictNotInvariant\n\t\t\}\n\t\}\n\t\/\/ A truncated trace/\t}\n\t\/\/ A truncated trace/'

run_mutation M18 \
  'a truncated trace is accepted as proof' \
  'TestPermit_RejectionMatrix' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif in\.Trace\.Truncated \{\n\t\treturn PermitVerdictNotInvariant\n\t\}\n//'

run_mutation M19 \
  'a request-variable field is declared BOUND' \
  'TestPermit_RequestVariableFieldsAreNotBound' \
  ./internal/mcp/canary "$PERMIT" \
  's/\t\t"capability",/\t\t"capability",\n\t\t"session.assurance",/'

run_mutation M20 \
  'the class check moves back behind the hard override' \
  'TestPermitE2E_WriteClassIsNotAPermit' \
  ./internal/mcp/canary "$PERMIT" \
  's/\tif !permitReadFirstClass\(in\.OperationClass\) \{\n\t\treturn PermitOperationClassNotReadFirst\n\t\}\n\t\/\/ A hard override dominates/\t\/\/ A hard override dominates/;s/\tif in\.Decision\.MatchedRule == "" \{/\tif !permitReadFirstClass(in.OperationClass) {\n\t\treturn PermitOperationClassNotReadFirst\n\t}\n\tif in.Decision.MatchedRule == "" {/'

# ── the readiness row and its wiring ──────────────────────────────────────────

run_mutation M21 \
  'the permit row is deleted from the activation readiness table' \
  'TestEvaluate_EachFactIsIndependentlyLoadBearing|TestEvaluate_ReasonVocabularyParity' \
  ./internal/mcp/canary "$READINESS" \
  's/\t\{func\(f Facts\) bool \{ return f\.ExactPolicyPermit \}, ReasonExactPolicyNotExecutable, factActivation\},\n//'

run_mutation M22 \
  'the activation wiring hard-codes the fact true instead of taking the resolved value' \
  'TestPermitE2E_UnmetRowBlocksActivationReadiness' \
  . "$PREFLIGHT" \
  's/\tf\.ExactPolicyPermit = in\.ExactPolicyPermit/\tf.ExactPolicyPermit = true/'

run_mutation M23 \
  'the production probe stops resolving the fact' \
  'TestPermitE2E_ProductionPreflightCarriesTheRow' \
  . "$PREFLIGHT" \
  's/\t\tExactPolicyPermit: permit,/\t\tExactPolicyPermit: false,/'

run_mutation M24 \
  'the transition-commit path drops the resolved fact' \
  'TestCanaryCommitGate_AllowsWhenFullyReady' \
  . "$ROLLOUT" \
  's/\t\t\tExactPolicyPermit:  ai\.ExactPolicyPermit,\n//'

run_mutation M25 \
  'the restart-reconcile path drops the resolved fact' \
  'TestPermitE2E_UnmetRowBlocksActivationReadiness|TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall' \
  . "$ROLLOUT" \
  's/ExactPolicyPermit: ai\.ExactPolicyPermit,\n\t\t\t\t\tNow: time\.Now\(\),/Now: time.Now(),/'

run_mutation M26 \
  'the permit row is classified node-level, so EvaluateNode starts asserting it' \
  'TestEvaluateNode_ExcludesActivationInputs' \
  ./internal/mcp/canary "$READINESS" \
  's/\{func\(f Facts\) bool \{ return f\.ExactPolicyPermit \}, ReasonExactPolicyNotExecutable, factActivation\}/{func(f Facts) bool { return f.ExactPolicyPermit }, ReasonExactPolicyNotExecutable, factNode}/'

# ── coherence and the structural walls ────────────────────────────────────────

run_mutation M27 \
  'the resolver straddles two inventory reads for one decision' \
  'TestPermitWall_ResolverUsesTheSharedEvaluator' \
  . "$RESOLVER" \
  's/\tcat, servers, ok := mcpToolTrustReconcileSnapshotFor\(\)/\tcat, _, ok := mcpToolTrustReconcileSnapshotFor()\n\t_, servers2, _ := mcpToolTrustReconcileSnapshotFor()\n\tservers := servers2/'

run_mutation M28 --compile-wall \
  'the resolver evaluates with a second engine of its own' \
  'TestPermitWall_ResolverUsesTheSharedEvaluator' \
  . "$RESOLVER" \
  's/\tdec, trace, err := mcpruntime\.EvaluateExactPermitTuple\(snap, in\)/\tdec, trace, err := policy.NewEngine(policy.DefaultLimits()).Evaluate(snap, \&in)/'

run_mutation M29 \
  'the resolver hard-codes a rule identity' \
  'TestPermitWall_NoHardCodedRuleIdentity' \
  . "$RESOLVER" \
  's/\tif dec\.MatchedRule != "" \{/\tif dec.MatchedRule == "ALLOW_READ_T" {\n\t\t_ = dec\n\t}\n\tif dec.MatchedRule != "" {/'

run_mutation M30 \
  'the permit is persisted into the activation reviewed snapshot' \
  'TestPermitWall_FactIsNotPersistedIntoTheReviewedSnapshot' \
  . "$REVIEWED" \
  's/\tOperationClass policy\.OperationClass\n\}/\tOperationClass policy.OperationClass\n\tPolicyPermit bool\n}/'

printf '\n===========================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ "$SKIPPED" -gt 0 ]; then
  printf 'A SKIPPED mutation proves nothing: its pattern no longer matches the source.\n'
fi
for s in "${SURVIVORS[@]:-}"; do [ -n "$s" ] && printf 'SURVIVOR: %s\n' "$s"; done
[ "$SURVIVED" -eq 0 ] && [ "$SKIPPED" -eq 0 ] && exit 0
exit 1
