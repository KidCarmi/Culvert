#!/usr/bin/env bash
# mcp-canary-mutation-campaign.sh — Step 6B of the First Controlled Canary review.
#
# Each mutation reintroduces ONE specific defect the physical-effect accounting
# work exists to prevent, then runs the NAMED gate that must catch it. A mutation
# that no test rejects is not a passing mutation: it is a hole in the gates.
#
# A COMPILE FAILURE IS NOT PROOF unless the mutation targets a structural wall
# whose stated purpose is compile-time prevention. Mutations here are written to
# compile and change behavior, so the failure comes from an assertion.
#
# Usage:  scripts/mcp-canary-mutation-campaign.sh [-k]   (-k: keep going after a
#         surviving mutation; default stops at the first survivor)
set -uo pipefail
cd "$(dirname "$0")/.."

KEEP=0
[ "${1:-}" = "-k" ] && KEEP=1

# The campaign mutates tracked files IN PLACE and reverts them with `git checkout`.
# Running it against a dirty tree therefore DESTROYS uncommitted work — it did
# exactly that once, silently reverting an unrelated edit mid-run. Refuse to start
# unless every tracked file is committed.
if ! git diff --quiet || ! git diff --cached --quiet; then
  printf 'refusing to run: the working tree has uncommitted changes to tracked files.\n'
  printf 'this campaign mutates tracked files and reverts them with `git checkout --`,\n'
  printf 'which would discard that work. commit or stash first.\n'
  git status --short
  exit 2
fi

PASS=0; SURVIVED=0; SKIPPED=0
declare -a SURVIVORS=()

# revert restores the working tree to HEAD for the files a mutation touched.
revert() { git checkout -- "$@" 2>/dev/null || true; }

# mutate <id> <description> <gate-regex> <package> <file> <sed-script...>
# Applies the sed script(s) to <file>, runs <gate-regex> in <package>, and requires
# the run to FAIL. Anything else is a surviving mutation.
run_mutation() {
  local id="$1" desc="$2" gate="$3" pkg="$4" file="$5"; shift 5
  printf '\n[%s] %s\n' "$id" "$desc"
  printf '      gate: %s  (%s)\n' "$gate" "$pkg"

  local before; before="$(git rev-parse HEAD:"$file" 2>/dev/null || echo none)"
  for script in "$@"; do
    perl -0pi -e "$script" "$file"
  done
  local after; after="$(git hash-object "$file")"
  if [ "$before" = "$after" ]; then
    printf '      SKIPPED — the mutation did not change %s (pattern drifted)\n' "$file"
    SKIPPED=$((SKIPPED+1)); revert "$file"; return
  fi

  local out; out="$(go test -count=1 -run "$gate" "$pkg" 2>&1)"
  local rc=$?
  revert "$file"

  # A gate that matches NO TESTS exits 0 and reads exactly like a caught mutation
  # would if you only look at the exit code — except it proves nothing at all. This
  # silently mis-scored two mutations whose gates lived in a different package than
  # the one being run. Treat it as a campaign failure, never as a result.
  if printf '%s' "$out" | grep -q 'no tests to run'; then
    printf '      BROKEN GATE — the pattern matched no tests in %s; this proves NOTHING\n' "$pkg"
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: BROKEN GATE (no tests matched in $pkg)")
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

printf 'MCP Canary physical-effect mutation campaign\n'
printf '===========================================\n'

# ── (1) transparent Canary retries restored at the limits layer ─────────────
run_mutation M01 \
  'RetryFreeLimits silently produces RETRYING limits' \
  'TestRetryFree_ExactlyOnePhysicalSendOnAmbiguousDrop|TestRetryFreeLimits_RejectsContradictoryBudget' \
  ./internal/mcp/upstreamclient/ internal/mcp/upstreamclient/limits.go \
  's/\tbase\.RetryMode = RetryDisabled\n\tbase\.MaxReadRetries = 0\n/\tbase.RetryMode = RetryDefault\n/'

# ── (2) one reservation causes two physical POSTs ───────────────────────────
#
# RETRY-FREEDOM IS ENFORCED AT TWO INDEPENDENT POINTS, and this mutation had to be
# rewritten twice before it proved anything:
#
#   (a) RetryFreeLimits pins the retry BUDGET to zero, so `retryable` refuses a
#       second attempt on budget alone;
#   (b) Client.Call short-circuits on `Limits.RetriesDisabled()` before consulting
#       `retryable` at all.
#
# Removing either ALONE is behaviour-preserving, so both single-point mutations
# survive — correctly. That is a property of the design, not a hole in the gates,
# and scoring it as a hole would have pushed toward deleting one of the two
# mechanisms to make a mutation "work".
#
# Note also that NewLimits validates BEFORE fillLimitDefaults, so a filler that
# restores the budget under RetryDisabled slips past the contradiction check — which
# is precisely why (b) exists as a second line.
#
# The honest mutation removes BOTH, which is what "transparent Canary retries
# restored" actually is.
printf '\n[M02] transparent retries restored (BOTH enforcement points removed)\n'
printf '      gate: TestRetryFree_ExactlyOnePhysicalSendOnAmbiguousDrop  (./internal/mcp/upstreamclient/)\n'
perl -0pi -e 's/\tif out\.RetryMode == RetryDefault && out\.MaxReadRetries == 0 \{\n\t\tout\.MaxReadRetries = defMaxReadRetries\n\t\}/\tif out.MaxReadRetries == 0 {\n\t\tout.MaxReadRetries = defMaxReadRetries\n\t}/' internal/mcp/upstreamclient/limits.go
perl -0pi -e 's/\tretriesDisabled := c\.cfg\.Limits\.RetriesDisabled\(\)/\tretriesDisabled := false/' internal/mcp/upstreamclient/client.go
if git diff --quiet internal/mcp/upstreamclient/limits.go || git diff --quiet internal/mcp/upstreamclient/client.go; then
  printf '      SKIPPED — a pattern drifted; this proves NOTHING\n'
  SKIPPED=$((SKIPPED+1)); SURVIVORS+=("M02: pattern drifted")
  revert internal/mcp/upstreamclient/limits.go internal/mcp/upstreamclient/client.go
else
  m02_out=$(go test -count=1 -run 'TestRetryFree_ExactlyOnePhysicalSendOnAmbiguousDrop' ./internal/mcp/upstreamclient/ 2>&1); m02_rc=$?
  revert internal/mcp/upstreamclient/limits.go internal/mcp/upstreamclient/client.go
  if printf '%s' "$m02_out" | grep -q 'no tests to run'; then
    printf '      BROKEN GATE — no tests matched\n'; SKIPPED=$((SKIPPED+1)); SURVIVORS+=("M02: BROKEN GATE")
    [ $KEEP -eq 0 ] && exit 1
  elif [ $m02_rc -ne 0 ]; then
    printf '      CAUGHT (gate failed as required)\n'; PASS=$((PASS+1))
  else
    printf '      *** SURVIVED ***\n'; SURVIVED=$((SURVIVED+1)); SURVIVORS+=("M02: transparent retries restored")
    [ $KEEP -eq 0 ] && exit 1
  fi
fi

# ── (3) a physical send with no durable intent ──────────────────────────────
run_mutation M03 \
  'the upstream call proceeds without committing a send intent' \
  'TestEvidenceFreeze_CompletedInvocationIsSettledThroughTheRealSpool|TestHTTPSE2E_SuccessfulExecutionIsSettledNotOrphaned' \
  . internal/mcp/execution/run.go \
  's/\t\tattempt = rec\n/\t\t_ = rec\n/'

# ── (4) intent persistence fails but the send continues ─────────────────────
run_mutation M04 \
  'a failed send-intent commit no longer blocks the irreversible send' \
  'TestHTTPSE2E_IntentPersistFailureBlocksTheSend' \
  . internal/mcp/execution/run.go \
  's/\t\tif ierr != nil \{\n\t\t\tbf\.gateRefused, bf\.gateReason = true, mcperr\.ReasonOf\(ierr\)\n\t\t\treturn errLiveGateRefused\n\t\t\}\n/\t\tif ierr != nil {\n\t\t\trec = \&attemptRecord{}\n\t\t}\n/'

# ── (5) reservation identity omitted from the grant ─────────────────────────
run_mutation M05 \
  'the live gate grants without a reservation identity' \
  'TestMeteredExecution_|TestHTTPSE2E_EachPOSTCarriesADistinctAttemptID|TestConc03_' \
  . mcp_live_gate.go \
  's/\t\tReservationID:        resID,/\t\tReservationID:        "",/'

# ── (6) activation generation omitted from the grant ────────────────────────
run_mutation M06 \
  'the live gate grants without an activation generation' \
  'TestMeteredExecution_|TestHTTPSE2E_SuccessIsExactlyOnePhysicalPOST' \
  . mcp_live_gate.go \
  's/\t\tActivationGeneration: gen,/\t\tActivationGeneration: 0,/'

# ── (7) the final emergency-kill re-read is removed ─────────────────────────
run_mutation M07 \
  'preCallGuard no longer re-reads the emergency-kill generation' \
  'TestKillBoundary_|TestCanaryPrerequisite_' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\tif e\.cfg\.State\.KillGeneration\(\) != admKillGen \{\n\t\treturn errKilledAtBoundary \/\/ emergency stop is paramount, even if the tool also drifted or demoted\n\t\}\n//'

# ── (8) the final tool-freshness guard is removed ───────────────────────────
run_mutation M08 \
  'preCallGuard no longer consults tool freshness' \
  'TestConc07_' \
  . internal/mcp/execution/run.go \
  's/\tdrifted := in\.ToolStillCurrent != nil && !in\.ToolStillCurrent\(\)/\tdrifted := false/'

# ── (9) terminal outcome omitted on an upstream error ───────────────────────
run_mutation M09 \
  'no terminal outcome is recorded when the upstream call fails' \
  'TestHTTPSE2E_AmbiguityIsNeverRecordedAsNotExecuted' \
  . internal/mcp/execution/attempt_evidence.go \
  's/\tf := outcomeFacts\(in\)\n\tf\.Phase = model\.PhaseOutcome\n/\tif out.Reason == mcperr.ReasonUpstreamConnectFailed {\n\t\treturn\n\t}\n\tf := outcomeFacts(in)\n\tf.Phase = model.PhaseOutcome\n/'

# ── (10) terminal outcome omitted on a DLP block ────────────────────────────
run_mutation M10 \
  'no terminal outcome is recorded when response DLP blocks egress' \
  'TestHTTPSE2E_DLPBlockAfterPeerResponseStaysExecuted' \
  . internal/mcp/execution/attempt_evidence.go \
  's/\tf := outcomeFacts\(in\)\n\tf\.Phase = model\.PhaseOutcome\n/\tif out.Reason == mcperr.ReasonSecretDetected {\n\t\treturn\n\t}\n\tf := outcomeFacts(in)\n\tf.Phase = model.PhaseOutcome\n/'

# ── (11) an ambiguous send recorded as definitely_not_sent ──────────────────
run_mutation M11 \
  'the state assumed before the wire is definitely_not_sent' \
  'TestHTTPSE2E_AmbiguityIsNeverRecordedAsNotExecuted|TestHTTPSE2E_DLPBlockAfterPeerResponseStaysExecuted' \
  . internal/mcp/execution/run.go \
  's/\t\tsendState = model\.SendMayHaveBeenSent\n\t\tr, err := e\.cfg\.Upstream\.Call/\t\tsendState = model.SendDefinitelyNotSent\n\t\tr, err := e.cfg.Upstream.Call/'

# ── (12) an orphan is treated as never-sent, freeing it for resend ──────────
run_mutation M12 \
  'restart recovery resolves an orphan as settled + definitely_not_sent' \
  'TestRecovery_' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\t\tState:                AttemptReconciliationRequired,\n\t\tReconciliation:       known,\n/\t\tState:                AttemptSettled,\n\t\tTerminalSendState:    model.SendDefinitelyNotSent,\n\t\tReconciliation:       known,\n/'

# ── (13) release refunds the monotonic budget ───────────────────────────────
run_mutation M13 \
  'Release decrements the monotonic total, refunding allowance' \
  'TestConc12_|TestBudgetMonotonic|TestBudget' \
  ./internal/mcp/canary/ internal/mcp/canary/budget_enforce.go \
  's/\tif e\.inflight > 0 \{\n\t\te\.inflight--\n\t\}\n\}/\tif e.inflight > 0 {\n\t\te.inflight--\n\t}\n\tif e.total > 0 {\n\t\te.total--\n\t}\n}/'

# ── (14) auxiliary discovery traffic counted as a tool effect ───────────────
run_mutation M14 \
  'tools\/list is classified as a side-effect-bearing tool invocation' \
  'TestClassifyMethod|TestHTTPSE2E_AuxiliaryTrafficIsNotMetered' \
  ./internal/mcp/upstreamclient/ internal/mcp/upstreamclient/invocation.go \
  's/\treturn ClassDiscovery\n/\treturn ClassToolInvocation\n/'

# ── (15) malformed evidence loads permissively ──────────────────────────────
run_mutation M15 \
  'recovery accepts a malformed attempt identity instead of failing closed' \
  'TestRecovery_' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif !validAttemptID\(e\.Outcome\.AttemptID\) \{\n\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid, "execution\.recovery", "malformed attempt identity in evidence"\)\n\t\}\n//'

# ── (16) DecisionRef dropped from the terminal outcome ──────────────────────
run_mutation M16 \
  'the terminal outcome carries no decision reference (the shipped defect)' \
  'TestEvidenceFreeze_CompletedInvocationIsSettledThroughTheRealSpool|TestHTTPSE2E_SuccessfulExecutionIsSettledNotOrphaned|TestHTTPSE2E_EveryTerminalOutcomeIsPersistable' \
  . internal/mcp/execution/attempt_evidence.go \
  's/\t\tDecisionRef: rec\.decisionRef,/\t\tDecisionRef: "",/'

# ── (18) duplicate send intents silently resolved to the newest ─────────────
run_mutation M18 \
  'a duplicated send intent overwrites instead of failing closed' \
  'TestRecovery_' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\t\tif _, dup := intents\[id\]; dup \{[^}]*?\n\t\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid, "execution\.recovery", "duplicate send intent for one attempt"\)\n\t\t\}\n//s'

# ── (19) duplicate terminal outcomes silently resolved to the newest ────────
run_mutation M19 \
  'a duplicated terminal outcome overwrites instead of failing closed' \
  'TestRecovery_' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\t\tif _, dup := outcomes\[id\]; dup \{\n\t\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid, "execution\.recovery", "multiple terminal outcomes for one attempt"\)\n\t\t\}\n//'

# ── (20) reconciliation collapses unknown into not_received ─────────────────
run_mutation M20 \
  'an unprovable absence resolves as not_received' \
  'TestReconcile_ZeroWithoutCompletenessStaysRequired|TestReconcile_WitnessUnavailableStaysUnresolved' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/\tif obs\.Complete && obs\.CompletenessWatermark != "" \{\n\t\treturn model\.ReconNotReceived\n\t\}\n\treturn model\.ReconRequired/\treturn model.ReconNotReceived/'

# ── (23) no terminal outcome on ANY non-executed path ───────────────────────
#
# The reason-independent form of M09/M10. Those two name specific reasons, so a
# reason-code rename would silently defang them; this one cannot be dodged that way.
run_mutation M23 \
  'no terminal outcome is recorded on any path that did not execute' \
  'TestHTTPSE2E_AmbiguityIsNeverRecordedAsNotExecuted|TestHTTPSE2E_DLPBlockAfterPeerResponseStaysExecuted' \
  . internal/mcp/execution/attempt_evidence.go \
  's/\tf := outcomeFacts\(in\)\n\tf\.Phase = model\.PhaseOutcome\n/\tif !out.Executed {\n\t\treturn\n\t}\n\tf := outcomeFacts(in)\n\tf.Phase = model.PhaseOutcome\n/'

# ── (21) the reservation-breach detector silenced ───────────────────────────
run_mutation M21 \
  'a reservation bound to two attempts is no longer named as a breach' \
  'TestRedTeam08_' \
  . internal/mcp/execution/recovery.go \
  's/\trep\.ReservationBreaches = deriveReservationBreaches\(rep\)\n//'

# ── (22) the breach detector fires on empty reservation ids ─────────────────
run_mutation M22 \
  'attempts with NO reservation identity are grouped into a false breach' \
  'TestRedTeam08_' \
  . internal/mcp/execution/recovery.go \
  's/\t\t\tif a\.ReservationID != "" \{\n\t\t\t\tbyRes\[a\.ReservationID\] = append\(byRes\[a\.ReservationID\], a\.AttemptID\)\n\t\t\t\}\n/\t\t\tbyRes[a.ReservationID] = append(byRes[a.ReservationID], a.AttemptID)\n/'

# ── (24) redirects re-permitted under retry-disabled ────────────────────────
run_mutation M24 \
  'a retry-free client is allowed to follow redirects (a replayed POST body)' \
  'TestRetryFree_RejectsRedirects' \
  ./internal/mcp/upstreamclient/ internal/mcp/upstreamclient/limits.go \
  's/\tif c\.RetryMode == RetryDisabled && c\.MaxRedirects != 0 \{\n\t\treturn Limits\{\}, mcperr\.New\(mcperr\.ReasonListenerConfigInvalid, "upstreamclient\.limits", "retry-disabled mode must not permit redirects"\)\n\t\}\n//'

# ── (25) a negative witness count resolves as definitive absence ────────────
run_mutation M25 \
  'a negative observation count falls through and reads as proven-absent' \
  'TestReconcile_NegativeCountNeverResolvesAbsence' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/\tif obs\.Count < 0 \{\n\t\treturn model\.ReconRequired\n\t\}\n//'

# ── (26) reconciliation applied without checking its binding ────────────────
run_mutation M26 \
  'reconciliation evidence for a different reservation is applied anyway' \
  'TestRecovery_ReconciliationMustMatchTheIntentBinding' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\t\tif ev\.ReservationID != intent\.ReservationID \{\n\t\t\treturn RecoveredAttempt\{\}, mcperr\.New\(mcperr\.ReasonEventInvalid,\n\t\t\t\t"execution\.recovery", "reconciliation reservation mismatch against the send intent"\)\n\t\t\}\n//'

# ── (27) a never-sent attempt persisted as executed ─────────────────────────
run_mutation M27 \
  'the terminal outcome keeps the success-path execution state on a refusal' \
  'TestHTTPSE2E_BoundaryRefusalIsNotRecordedAsExecuted' \
  . internal/mcp/execution/attempt_evidence.go \
  's/\tif out\.ExecutionState != "" \{\n\t\tf\.Decision\.ExecutionState = out\.ExecutionState\n\t\}\n//'

# ── (28) uncertainty laundered into executed=false on the durable record ────
run_mutation M28 \
  'Outcome.Executed is derived from the terminal disposition instead of the send state' \
  'TestOutcomeTruth_' \
  . internal/mcp/execution/attempt_evidence.go \
  's/\t\tExecuted:      state\.MayHaveReachedPeer\(\),/\t\tExecuted:      out.Executed,/'

# ── (29) attempt evidence written under the pre-v3 stamp ────────────────────
run_mutation M29 \
  'the v3 stamp is dropped, so attempt evidence is written claiming v1' \
  'TestEvidenceFreeze_AttemptEvidenceIsStampedV3OnTheRealSpool' \
  . internal/mcp/events/decide.go \
  's/\tif ev\.CarriesAttemptEvidence\(\) \{\n\t\tev\.SchemaVersion = model\.SchemaVersionV3\n\t\}\n//'

# ── (30) a version rollback reported as spool corruption ────────────────────
run_mutation M30 \
  'the schema version is read only AFTER the strict decode and the digest' \
  'TestAttemptV3_ARollbackReportsASchemaFaultNotCorruption' \
  ./internal/mcp/events/spool/ internal/mcp/events/spool/recovery.go \
  's/\t\tif v, ok := peekSchemaVersion\(pt\); ok && !model\.SupportedSchemaVersion\(v\) \{\n\t\t\treturn nil, chain, spErr\(mcperr\.ReasonEventSchemaVersion, "record unknown schema version"\)\n\t\t\}\n//'

# ── (31) a demonstrable peer answer discarded as uncertainty ────────────────
run_mutation M31 \
  'the observed-response fact is dropped, so a peer that answered badly reads as maybe-sent' \
  'TestHTTPSE2E_AnUnusableAnswerIsStillAnAnswer' \
  . internal/mcp/upstreamclient/observed.go \
  's/\tif err == nil \|\| !facts\.responseObserved \{\n\t\treturn err\n\t\}\n\treturn &observedErr\{err: err\}/\treturn err/'

# ── (32) definitive absence accepted from a mismatched binding ──────────────
run_mutation M32 \
  'a proven ZERO for a different reservation/server/method resolves as never-happened' \
  'TestReconcile_DefinitiveAbsenceRequiresAMatchingBinding' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/\tif obs\.Complete && obs\.CompletenessWatermark != "" && bindingConsistent\(obs, orphan, expectServer, expectMethod\) \{/\tif obs.Complete \&\& obs.CompletenessWatermark != "" {/'

# ── (33) a peer answer discarded on the rejected-redirect path ──────────────
run_mutation M33 \
  'a 3xx refused by CheckRedirect is recorded as maybe-sent despite the peer answering' \
  'TestHTTPSE2E_ARejectedRedirectIsStillAnAnswer' \
  . internal/mcp/upstreamclient/transport.go \
  's/\t\tif resp != nil \{\n\t\t\treturn nil, legFacts\{responseObserved: true\}, classifyTransportError\(err\)\n\t\t\}\n//'

# ── (17) THE PROOF RULE ITSELF ──────────────────────────────────────────────
#
# The defect from M16 is invisible to a permissive test sink. This mutation proves
# that directly and two-sidedly: with DecisionRef dropped, the SINK-based executor
# gates still PASS (the defect survives there), while the REAL-SPOOL gate FAILS.
#
# A single-sided check would not establish the rule. If the sink-based run also
# failed, the rule would be unproven — the sink would have been sufficient after
# all, and this whole requirement would be ceremony.
printf '\n[M17] a permissive test sink hides an invalid event; only the real spool catches it\n'
printf '      gate: sink-side must PASS, real-spool side must FAIL\n'
perl -0pi -e 's/\t\tDecisionRef: rec\.decisionRef,/\t\tDecisionRef: "",/' internal/mcp/execution/attempt_evidence.go
if ! git diff --quiet internal/mcp/execution/attempt_evidence.go; then
  sink_out=$(go test -count=1 -run 'TestEvidence_|TestPhysicalEffect_' ./internal/mcp/execution/ 2>&1); sink_rc=$?
  spool_out=$(go test -count=1 -run 'TestEvidenceFreeze_CompletedInvocationIsSettledThroughTheRealSpool' . 2>&1); spool_rc=$?
  revert internal/mcp/execution/attempt_evidence.go
  if [ $sink_rc -eq 0 ] && [ $spool_rc -ne 0 ]; then
    printf '      CAUGHT (sink passed the defect through; the real-spool gate rejected it)\n'
    PASS=$((PASS+1))
  else
    printf '      *** SURVIVED *** sink_rc=%s spool_rc=%s\n' "$sink_rc" "$spool_rc"
    printf '%s\n' "$spool_out" | tail -4 | sed 's/^/        /'
    SURVIVED=$((SURVIVED+1)); SURVIVORS+=("M17: proof rule not demonstrated")
    [ $KEEP -eq 0 ] && exit 1
  fi
else
  printf '      SKIPPED — pattern drifted\n'; SKIPPED=$((SKIPPED+1)); revert internal/mcp/execution/attempt_evidence.go
fi

printf '\n===========================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ "$SKIPPED" -gt 0 ]; then
  printf 'A SKIPPED mutation proves nothing: its pattern no longer matches the source.\n'
fi
for s in "${SURVIVORS[@]:-}"; do [ -n "$s" ] && printf 'SURVIVOR: %s\n' "$s"; done
[ "$SURVIVED" -eq 0 ] && [ "$SKIPPED" -eq 0 ] && exit 0
exit 1
