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

# has_re / has_fixed search captured output WITHOUT a producer pipe.
#
# `printf '%s' "$out" | grep -q PATTERN` is WRONG under `set -o pipefail`, which this
# script sets: grep exits as soon as it matches, printf then dies of SIGPIPE (141),
# and pipefail reports the PIPELINE as failed even though the pattern matched. Every
# use of that idiom here was mis-scoring, each in a different direction — a matched
# build failure not setting build_broke, a matched "no tests to run" not raising
# BROKEN GATE, a matched race report read as "no race reported", and a matched
# attribution symbol read as missing (Codex round 19). A herestring has no producer
# to kill, so the exit status is grep's alone.
has_re()    { grep -qE -- "$1" <<<"$2"; }
has_fixed() { grep -qF -- "$1" <<<"$2"; }

# gate_ran reports whether a `go test` invocation actually REACHED an assertion.
#
# There are exactly two ways it does not, and both exit in a way that a bare status
# check misreads: the -run pattern matched no tests (exit 0 — indistinguishable from a
# pass), or the package did not build (nonzero — indistinguishable from a caught
# mutation). Every result decision in this script must go through this function.
#
# It exists because THREE CONSECUTIVE REVIEW ROUNDS found a hole in a hand-rolled
# copy of this logic (Codex 18/19/20): the build check was missing from run_mutation,
# then from M02 and M17, then the no-tests check was still missing from M17 — where
# `sink_rc == 0` is the CAUGHT condition, so a drifted sink pattern made the required
# control vacuous. Three holes in three rounds is a structural signal, not three
# coincidences: duplicated classification is what kept producing them.
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

# build_or_vet_failed reports that `go test` never reached an assertion. It is shared
# by run_mutation and by the two mutations that must drive `go test` themselves, so
# the header's "a compile failure is not proof" rule cannot hold in one place and not
# the other.
build_or_vet_failed() {
  has_re '\[build failed\]|\[setup failed\]|^vet: |^# github\.com/KidCarmi' "$1"
}

# mutate <id> <description> <gate-regex> <package> <file> <sed-script...>
# Applies the sed script(s) to <file>, runs <gate-regex> in <package>, and requires
# the run to FAIL. Anything else is a surviving mutation.
run_mutation() {
  local id="$1" desc="$2" gate="$3" pkg="$4" file="$5"; shift 5
  # A gate whose defect is a DATA RACE is invisible without the detector: the mutated
  # build passes and scores as a survivor. Such a mutation passes --race here, and the
  # flag is consumed before the perl scripts.
  local raceflag=() race_attr="" compile_wall=0
  while :; do
    case "${1:-}" in
      --race|--race=*)
        raceflag=(-race); race_attr="${1#--race}"; race_attr="${race_attr#=}"; shift ;;
      # The header rule says a compile failure is not proof UNLESS the mutation
      # targets a structural wall whose purpose is compile-time prevention. Such a
      # mutation declares itself here, and for it the build failure IS the proof.
      --compile-wall)
        compile_wall=1; shift ;;
      *) break ;;
    esac
  done
  printf '\n[%s] %s\n' "$id" "$desc"
  printf '      gate: %s  (%s)%s\n' "$gate" "$pkg" "${raceflag[0]:+ [race]}"

  local before; before="$(git rev-parse HEAD:"$file" 2>/dev/null || echo none)"
  for script in "$@"; do
    perl -0pi -e "$script" "$file"
  done
  local after; after="$(git hash-object "$file")"
  if [ "$before" = "$after" ]; then
    printf '      SKIPPED — the mutation did not change %s (pattern drifted)\n' "$file"
    SKIPPED=$((SKIPPED+1)); revert "$file"; return
  fi

  local out; out="$(go test "${raceflag[@]}" -count=1 -run "$gate" "$pkg" 2>&1)"
  local rc=$?
  revert "$file"

  # A compile-time wall is the ONE case where a build failure IS the proof, so it is
  # decided before gate_ran (which treats that same failure as "no gate ran").
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
    # A --race mutation must be caught BY THE DETECTOR, and a bare nonzero exit does not
    # establish that. `go test` compiles and vets before running, so a build break, a
    # vet failure, a panic, a timeout or an UNRELATED race all land here too — and each
    # would score the mutation as caught while proving nothing about the lock that was
    # removed (Codex round 17). The scoring is therefore evidence-based for these, not
    # exit-code-based: the output must carry a race report, and that report must name
    # the mutated access.
    if [ ${#raceflag[@]} -ne 0 ]; then
      if ! has_fixed 'WARNING: DATA RACE' "$out"; then
        printf '      NOT PROVEN — the gate failed but NO race was reported; this proves NOTHING\n'
        printf '%s\n' "$out" | tail -8 | sed 's/^/        /'
        SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN (gate failed without a race report)")
        [ $KEEP -eq 0 ] && exit 1
        return
      fi
      # race_attr is a comma-separated list of symbols that must ALL appear in the
      # report. Requiring both sides of the intended pair — the mutated writer and the
      # guarded reader — is what makes this attribution rather than "a race happened
      # somewhere in this package while the mutation was applied".
      local _attr_missing=""
      if [ -n "$race_attr" ]; then
        local _oldifs="$IFS"; IFS=','
        for pat in $race_attr; do
          has_fixed "$pat" "$out" || _attr_missing="$pat"
        done
        IFS="$_oldifs"
      fi
      if [ -n "$_attr_missing" ]; then
        printf '      NOT PROVEN — a race was reported but it does not name %s; this proves NOTHING\n' "$_attr_missing"
        printf '%s\n' "$out" | tail -8 | sed 's/^/        /'
        SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN (race not attributable to $_attr_missing)")
        [ $KEEP -eq 0 ] && exit 1
        return
      fi
      printf '      CAUGHT (race detector reported a race naming %s, as required)\n' "${race_attr:-the mutated access}"
      PASS=$((PASS+1))
      return
    fi
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
  if ! gate_ran M02 "the gate" "$m02_out"; then
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
  's/\t\tReservationID:        resID,/\t\tReservationID:        "",/' \
  's/\tresID, rerr := newCanaryReservationID\(\)/\t_, rerr := newCanaryReservationID()/'

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
  's/\tif obs\.Complete && obs\.CompletenessWatermark != "" && bindingCorroborated\(obs, orphan, expectServer, expectMethod\) \{\n\t\treturn model\.ReconNotReceived\n\t\}\n\treturn model\.ReconRequired/\treturn model.ReconNotReceived/'

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
  's/\tcase facts\.responseObserved:\n\t\treturn &observedErr\{err: err\}\n//'

# ── (32) definitive absence accepted from a mismatched binding ──────────────
run_mutation M32 \
  'a proven ZERO for a different reservation/server/method resolves as never-happened' \
  'TestReconcile_DefinitiveAbsenceRequiresAMatchingBinding' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/\tif obs\.Complete && obs\.CompletenessWatermark != "" && bindingCorroborated\(obs, orphan, expectServer, expectMethod\) \{/\tif obs.Complete \&\& obs.CompletenessWatermark != "" {/'

# ── (33) a peer answer discarded on the rejected-redirect path ──────────────
run_mutation M33 \
  'a 3xx refused by CheckRedirect is recorded as maybe-sent despite the peer answering' \
  'TestHTTPSE2E_ARejectedRedirectIsStillAnAnswer' \
  . internal/mcp/upstreamclient/transport.go \
  's/\t\tif resp != nil \{\n\t\t\treturn nil, legFacts\{responseObserved: true\}, classifyTransportError\(err\)\n\t\t\}\n//'

# ── (34) "exactly one" accepted from an unproven view ───────────────────────
run_mutation M34 \
  'one observed invocation resolves as received without a completeness proof' \
  'TestReconcile_ExactlyOneNeedsTheSameCompletenessProofAsAbsence' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/\t\tif !obs\.Complete \|\| obs\.CompletenessWatermark == "" \{\n\t\t\treturn model\.ReconRequired\n\t\t\}\n//'

# ── (35) corroboration weakened to mere non-contradiction ───────────────────
run_mutation M35 \
  'an unbound orphan is resolved by a view scoped to another authorization' \
  'TestReconcile_AnUnboundOrphanCannotBeResolvedByAnotherAuthorization' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/func corroborates\(observed, expected string\) bool \{\n\tif observed == "" \{\n\t\treturn true\n\t\}\n\treturn expected != "" && observed == expected\n\}/func corroborates(observed, expected string) bool {\n\treturn !disagrees(observed, expected)\n}/'

# ── (36) contradictory reconciliation discarded on a settled attempt ────────
run_mutation M36 \
  'the settled branch ignores reconciliation evidence for the same attempt' \
  'TestRecovery_ReconciliationAgainstASettledAttemptIsNotDiscarded' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif err := settledReconOK\(intent, out, recon\); err != nil \{\n\t\treturn RecoveredAttempt\{\}, err\n\t\}\n//'

# ── (37) repeated reconciliation deduped on verdict, not identity ───────────
run_mutation M37 \
  'a second reconciliation record naming another authorization is dropped as idempotent' \
  'TestRecovery_RepeatedReconciliationMustAgreeOnIdentityNotJustVerdict' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif prev\.ReservationID != e\.Reconciliation\.ReservationID \|\|\n\t\tprev\.ActivationGeneration != e\.Reconciliation\.ActivationGeneration \{\n\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid, "execution\.recovery",\n\t\t\t"reconciliation records for one attempt name different authorizations"\)\n\t\}\n//'

# ── (38) only one of the two proven-non-receipt states is checked ───────────
run_mutation M38 \
  'receipt against reconciled_not_received passes as a clean settled attempt' \
  'TestRecovery_ReceiptAgainstEitherProvenNonReceiptFailsClosed' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\t\tif !out\.PhysicalSendState\.MayHaveReachedPeer\(\) \{\n\t\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid,\n\t\t\t\t"execution\.recovery", "witness reported received against an outcome that proves the peer was not reached"\)\n\t\t\}/\t\tif out.PhysicalSendState == model.SendDefinitelyNotSent {\n\t\t\treturn mcperr.New(mcperr.ReasonEventInvalid,\n\t\t\t\t"execution.recovery", "witness reported received against a provably never-sent outcome")\n\t\t}/'

# ── (39) auxiliary traffic reaches the side-effect gate ────────────────────
run_mutation M39 \
  'lifecycle/discovery traffic consumes a Canary execution reservation' \
  'TestAuxiliaryTraffic_NeverReachesTheSideEffectGate|TestAuxiliaryTraffic_SurvivesARefusingGate' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\tif !upstreamclient\.ClassifyMethod\(in\.Method\)\.SideEffectBearing\(\) \{\n\t\treturn sideEffectAdmission\{\}, nil\n\t\}\n\td := e\.cfg\.LiveGate\.AdmitSideEffect/\td := e.cfg.LiveGate.AdmitSideEffect/'

# ── (40) resolved reconciliation verdicts unchecked against their facts ─────
run_mutation M40 \
  'a resolved verdict is committable with facts that cannot support it' \
  'TestReconciliation_ResolvedVerdictNeedsACompletenessProof|TestReconciliation_ResolvedVerdictMustMatchItsCount' \
  ./internal/mcp/events/model/ internal/mcp/events/model/validate.go \
  's/\treturn e\.Reconciliation\.validateVerdictAgainstFacts\(\)/\treturn nil/'

# ── (41) unmatched reconciliation evidence silently ignored ────────────────
run_mutation M41 \
  'reconciliation evidence naming no send intent yields a clean, empty report' \
  'TestRecovery_ReconciliationWithoutAnIntentFailsClosed' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tfor id := range idx\.recon \{\n\t\tif _, ok := idx\.intents\[id\]; !ok \{\n\t\t\treturn RecoveryReport\{\}, mcperr\.New\(mcperr\.ReasonEventInvalid,\n\t\t\t\t"execution\.recovery", "reconciliation evidence without a matching send intent"\)\n\t\t\}\n\t\}\n//'

# ── (42) not-received rejected against an AMBIGUOUS send ───────────────────
run_mutation M42 \
  'an unanswered POST can never be resolved by the witness that exists to resolve it' \
  'TestReconcile_AnUnansweredPostIsResolvableEndToEnd' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\t\tif out\.PhysicalSendState\.ProvesReceipt\(\) \{/\t\tif out.PhysicalSendState.MayHaveReachedPeer() {/'

# ── (43) reconciliation gated on settledness, not on knowledge ─────────────
run_mutation M43 \
  'a settled-but-ambiguous attempt is refused reconciliation' \
  'TestReconcile_GateIsUnresolvedKnowledgeNotSettledness|TestReconcile_AnUnansweredPostIsResolvableEndToEnd' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/\tif !orphan\.NeedsReconciliation\(\) \{/\tif orphan.State != AttemptReconciliationRequired {/'

# ── (44) a malformed count is copied onto the durable record ───────────────
run_mutation M44 \
  'the fail-closed record a malformed witness produces cannot be committed' \
  'TestReconcile_AMalformedCountYieldsACommittableRecord' \
  ./internal/mcp/execution/ internal/mcp/execution/reconcile.go \
  's/\tif obs\.Count > 0 \{\n\t\tev\.ObservationCount = obs\.Count\n\t\}/\tev.ObservationCount = obs.Count/'

# ── (45) a duplicate silenced by a weaker stated verdict ───────────────────
run_mutation M45 \
  'recovery trusts a stated verdict that understates its own duplicate facts' \
  'TestRecovery_ADuplicateIsNotSilencedByAWeakerVerdict' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif r\.ObservationCount > 1 \{\n\t\treturn model\.ReconConflict\n\t\}\n//'

# ── (46) the durable validator permits a non-conflict duplicate ────────────
run_mutation M46 \
  'a duplicate observation is committable under a non-conflict verdict' \
  'TestReconciliation_ADuplicateMustSayConflict' \
  ./internal/mcp/events/model/ internal/mcp/events/model/validate.go \
  's/\tif r\.ObservationCount > 1 && r\.Result != ReconConflict \{\n\t\treturn evtErr\(mcperr\.ReasonEventInvalid, "duplicate observations recorded under a non-conflict verdict"\)\n\t\}\n//'

# ── (47) read path enforces only the duplicate rule ────────────────────────
run_mutation M47 \
  'an unsupported resolved verdict is trusted on the less-validated read path' \
  'TestRecovery_ReadPathMirrorsTheDurableValidator' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif r\.ObservationCount < 0 \{\n\t\treturn model\.ReconRequired\n\t\}\n\tswitch r\.Result \{\n\tcase model\.ReconNotReceived:\n\t\tif r\.ObservationCount != 0 \|\| r\.CompletenessWatermark == "" \{\n\t\t\treturn model\.ReconRequired\n\t\t\}\n\tcase model\.ReconReceived:\n\t\tif r\.ObservationCount != 1 \|\| r\.CompletenessWatermark == "" \{\n\t\t\treturn model\.ReconRequired\n\t\t\}\n\t\}\n//'

# ── (48) idempotence compares the stated string, not knowledge ─────────────
run_mutation M48 \
  'a duplicate hidden behind a repeated verdict is dropped as a harmless repeat' \
  'TestRecovery_IdempotenceComparesKnowledgeNotTheStatedString' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tprevEff, curEff := effectiveReconResult\(prev\), effectiveReconResult\(e\.Reconciliation\)\n\tif prevEff == curEff \{/\tprevEff, curEff := prev.Result, e.Reconciliation.Result\n\tif prevEff == curEff {/'

# ── (49) read path ignores the structural coupling rules ───────────────────
run_mutation M49 \
  'a record shape the durable validator would refuse is indexed anyway' \
  'TestRecovery_ReadPathMirrorsTheStructuralCouplingRules' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif err := readPathAttemptRulesOK\(e\); err != nil \{\n\t\treturn err\n\t\}\n//'

# ── (50) inverse coupling: reconciliation evidence on an outcome ───────────
run_mutation M50 \
  'a duplicate embedded in a terminal outcome is dropped and the attempt settles' \
  'TestRecovery_ReadPathCouplingIsSymmetricAndStructural' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif e\.Reconciliation != nil && e\.Phase != model\.PhaseReconciliation \{\n\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid, "execution\.recovery",\n\t\t\t"reconciliation evidence on a non-reconciliation record"\)\n\t\}\n//'

# ── (51) decision ref checked for emptiness only ───────────────────────────
run_mutation M51 \
  'a malformed nonempty decision ref settles an attempt' \
  'TestRecovery_ReadPathCouplingIsSymmetricAndStructural' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/!model\.ValidDecisionRef\(e\.Outcome\.DecisionRef\)/e.Outcome.DecisionRef == ""/'

# ── (52) send state uncoupled from the phase ───────────────────────────────
run_mutation M52 \
  'a send intent may claim a physical send state recovery will silently drop' \
  'TestPhysicalSendState_IsCoupledToThePhase' \
  ./internal/mcp/events/model/ internal/mcp/events/model/validate.go \
  's/\tif e\.Outcome\.PhysicalSendState != SendStateUnset \{\n\t\treturn evtErr\(mcperr\.ReasonEventInvalid, "send intent claiming a physical send state"\)\n\t\}\n//'

# ── (53) outcome evidence uncoupled from its allowed phases (writer) ───────
run_mutation M53 \
  'an attempt outcome rides on a marker or denial record and recovery discards it' \
  'TestValidate_OutcomeEvidenceCouplingIsStatedOverTheAllowedSet' \
  ./internal/mcp/events/model/ internal/mcp/events/model/validate.go \
  's/\tif e\.Outcome != nil && e\.Phase != PhaseOutcome && e\.Phase != PhaseSendIntent \{\n\t\treturn evtErr\(mcperr\.ReasonEventInvalid, "outcome evidence on a phase that cannot carry it"\)\n\t\}\n//'

# ── (54) same coupling unmirrored on the read path ─────────────────────────
run_mutation M54 \
  'the read path indexes a record whose payload its phase cannot carry' \
  'TestRecovery_PayloadCouplingIsStatedOverTheAllowedSet' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif e\.Outcome != nil && e\.Phase != model\.PhaseOutcome && e\.Phase != model\.PhaseSendIntent \{\n\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid, "execution\.recovery",\n\t\t\t"outcome evidence on a record that cannot carry it"\)\n\t\}\n//'

# ── (55) send-intent state rule unmirrored on the read path ────────────────
run_mutation M55 \
  'a send intent claiming a receipt is indexed and the claim silently dropped' \
  'TestRecovery_PayloadCouplingIsStatedOverTheAllowedSet' \
  ./internal/mcp/execution/ internal/mcp/execution/recovery.go \
  's/\tif e\.Phase == model\.PhaseSendIntent && e\.Outcome != nil &&\n\t\te\.Outcome\.PhysicalSendState != model\.SendStateUnset \{\n\t\treturn mcperr\.New\(mcperr\.ReasonEventInvalid, "execution\.recovery",\n\t\t\t"send intent claiming a physical send state"\)\n\t\}\n//'

# ── (56) a local refusal recorded as an ambiguous send ─────────────────────
run_mutation M56 \
  'a call refused before any leg began is recorded may_have_been_sent' \
  'TestPhysicalSendState_ALocalRefusalIsNotAnAmbiguousSend' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\t\tif upstreamclient\.SendNeverStarted\(err\) \{/\t\tif false \&\& upstreamclient.SendNeverStarted(err) {/'

# ── (57) last-leg send facts carried out as whole-call facts ───────────────
#
# The dangerous direction: a leg that provably sent nothing OVERWRITES an earlier
# leg that may have reached the peer, so the caller records definitely_not_sent for
# an invocation that may already have executed.
run_mutation M57 \
  'the never-sent marker of the last retry leg becomes the whole-call claim' \
  'TestCallFacts_ALaterNeverSentLegDoesNotEraseAnEarlierAmbiguousSend' \
  ./internal/mcp/upstreamclient/ internal/mcp/upstreamclient/client.go \
  's/\t\tlastErr = markLegFacts\(err, call\)/\t\tlastErr = markLegFacts(err, facts)/'

# ── (58) never-sent folded as a disjunction instead of a conjunction ────────
#
# Same defect one layer down, at the fold itself: never-sent is the strongest claim
# in the lattice and requires UNANIMITY across legs. An OR lets one never-sent leg
# speak for legs that did send.
run_mutation M58 \
  'never-sent folds as a disjunction, so one silent leg speaks for the whole call' \
  'TestFoldLegFacts_DirectionsAreOppositeAndConservative' \
  ./internal/mcp/upstreamclient/ internal/mcp/upstreamclient/observed.go \
  's/\t\tneverSent:        call\.neverSent \&\& leg\.neverSent,/\t\tneverSent:        call.neverSent || leg.neverSent,/'

# ── (59) receipt folded as a conjunction instead of a disjunction ───────────
#
# The mirror direction. Receipt is monotonic knowledge — a later leg that saw no
# response cannot un-prove that an earlier one was answered.
run_mutation M59 \
  'an observed response is erased by a later leg that saw none' \
  'TestFoldLegFacts_DirectionsAreOppositeAndConservative' \
  ./internal/mcp/upstreamclient/ internal/mcp/upstreamclient/observed.go \
  's/\t\tresponseObserved: call\.responseObserved \|\| leg\.responseObserved,/\t\tresponseObserved: call.responseObserved \&\& leg.responseObserved,/'

# ── (60) the coordinator clock swapped without the coordinator lock ────────
#
# mcpToolTrustCoordinator.now() reads nowFn under mu.RLock because a background
# reconcile loop calls it concurrently. A test writer that skips the lock is a real
# data race — it is what turned the Fast gate red on 2c35dc4.
run_mutation M60 \
  'the tool-trust clock is swapped without the coordinator lock' \
  'TestToolTrustClock_SwapIsSynchronisedWithConcurrentReaders' \
  . mcp_tooltrust_clock_test.go '--race=swapToolTrustNowFn,mcpToolTrustCoordinator).now' \
  's/\tmcpToolTrust\.mu\.Lock\(\)\n\tprev := mcpToolTrust\.nowFn\n\tmcpToolTrust\.nowFn = fn\n\tmcpToolTrust\.mu\.Unlock\(\)\n/\tprev := mcpToolTrust.nowFn\n\tmcpToolTrust.nowFn = fn\n/'

# ══════════════════════════════════════════════════════════════════════════════
# BLOCKER #7 — whole-Canary automatic abort. Each mutation reintroduces one way a
# breach could stop a request without stopping the EXPERIMENT, or one way the
# experiment could keep authority it should have lost.
# ══════════════════════════════════════════════════════════════════════════════

run_mutation M61 \
  'admission no longer consults the abort latch' \
  'TestAutoStop_LatchedAbortMakesNewReservationImpossible|TestAutoStopConc02_BreachWhileManyAwaitAdmission' \
  . mcp_canary_runtime.go \
  's/\tif !cr\.aborter\.ExecutionEligible\(generation\) \{/\tif false {/'

run_mutation M62 \
  'the abort latch auto-clears when read' \
  'TestAutoStop_LatchedAbortMakesNewReservationImpossible|TestAutoStop_FirstCausePreservedAcrossLaterBreaches' \
  . internal/mcp/canary/abort_control.go \
  's/\treturn gen == c\.generation \&\& c\.aborted/\treturn false/'

run_mutation M63 \
  'a restart clears the abort latch' \
  'TestAutoStop_RestartAfterExpiryRestoresAborted|TestCanaryRuntime_RestartPreservesAbortLatch' \
  . internal/mcp/canary/abort_control.go \
  's/\treturn &AbortController\{generation: gen, aborted: snap\.Aborted, code: snap\.Code, atNanos: snap\.AtUnixNano\}/\treturn \&AbortController{generation: gen}/'

run_mutation M64 \
  'outcome evidence loss goes back to being metric-only' \
  'TestAutoStop_OutcomeEvidenceLossAbortsTheWholeCanary' \
  . internal/mcp/execution/attempt_evidence.go \
  's/\t\te\.cfg\.Safety\.Breach\(in\.Capability\.String\(\), rec\.generation, "outcome_evidence_loss"\)\n//'

run_mutation M65 \
  'tool fingerprint drift denies the request but does not abort' \
  'TestAutoStop_ToolFingerprintDriftAbortsTheWholeCanary' \
  . mcp_live_gate.go \
  's/\t\treturn false, "tool_fingerprint_drift"/\t\treturn false, ""/'

run_mutation M66 \
  'server identity drift denies the request but does not abort' \
  'TestAutoStop_ServerIdentityDriftAbortsTheWholeCanary' \
  . mcp_live_gate.go \
  's/\t\treturn false, "server_identity_drift"/\t\treturn false, ""/'

run_mutation M67 \
  'the breach funnel silently drops credential_safety_failure' \
  'TestAutoStop_CredentialSafetyFailureAbortsTheWholeCanary' \
  . mcp_canary_autostop.go \
  's/\tf\.rt\.tripCanaryAbortForGeneration\(f\.capb, gen, code, canaryNow\(\)\)/\tif code == "credential_safety_failure" {\n\t\treturn\n\t}\n\tf.rt.tripCanaryAbortForGeneration(f.capb, gen, code, canaryNow())/'

run_mutation M68 \
  'a reconciliation conflict is recorded but reaches no abort' \
  'TestAutoStop_WitnessConflictAbortsTheWholeCanary' \
  . internal/mcp/execution/reconcile.go \
  's/\t\te\.cfg\.Safety\.Breach\(capability, orphan\.ActivationGeneration, "independent_witness_mismatch"\)/\t\t_ = capability/'

run_mutation M69 \
  'a scope escape denies the request but does not abort' \
  'TestLiveAbort_BudgetExhaustionTripsWholeCanary|TestCanaryRuntime_ScopeEscapeTripsWholeCanaryAbort' \
  . mcp_canary_runtime.go \
  's/\t\tcr\.aborter\.Trip\("scope_escape", generation, now\)/\t\t_ = generation/'

run_mutation M70 \
  'budget exhaustion denies the request but does not abort' \
  'TestAutoStop_DeniedReservationItselfTripsBudgetExhausted' \
  . mcp_canary_runtime.go \
  's/\t\tcr\.aborter\.Trip\("budget_exhausted", generation, now\)/\t\t_ = generation/'

run_mutation M71 \
  'the deadline is only ever checked when a request arrives' \
  'TestAutoStop_WindowExpiresWithNoTrafficAtAll|TestAutoStop_RestartAfterExpiryRestoresAborted' \
  . mcp_canary_runtime.go \
  's/\treconcileWindowDeadlineLocked\(rt, capb, cr\)\n\treturn gen, nil/\treturn gen, nil/' \
  's/\treconcileWindowDeadlineLocked\(rt, capb, cr\)\n\}/}/'

run_mutation M72 \
  'a restart grants a fresh full window' \
  'TestAutoStop_RestartNeverGrantsAFreshWindow|TestAutoStop_RestartAfterExpiryRestoresAborted' \
  . internal/mcp/canary/budget_enforce.go \
  's/\treturn time\.Unix\(0, e\.startNanos\)\.Add\(e\.budget\.Window\)/\treturn time.Now().Add(e.budget.Window)/'

run_mutation M73 \
  'the error-rate sample floor is raised beyond the 3-execution corpus' \
  'TestHealth_SampleFloorFitsTheFirstCanaryCorpus|TestHealth_ErrorRateReachableWithinThreeExecutions' \
  ./internal/mcp/canary/ internal/mcp/canary/health.go \
  's/\tHealthSampleFloor = 2/\tHealthSampleFloor = 5/'

run_mutation M74 \
  'the latency hard limit is pushed past the upstream timeout, making it unreachable' \
  'TestHealth_SampleFloorFitsTheFirstCanaryCorpus|TestHealth_HardLatencyTripsOnOneAttemptWithNoFloor' \
  ./internal/mcp/canary/ internal/mcp/canary/health.go \
  's/\tHealthLatencyHardLimit = 15 \* time\.Second/\tHealthLatencyHardLimit = 45 * time.Second/'

run_mutation M75 \
  'a later breach overwrites the first abort reason' \
  'TestAutoStop_FirstCausePreservedAcrossLaterBreaches|TestAutoStopConc03_TwoBreachesRaceForFirstCause' \
  . internal/mcp/canary/abort_control.go \
  's/\tif !c\.aborted \{/\tif true {/'

run_mutation M76 \
  'the final live revalidation stops consulting the abort latch' \
  'TestAutoStop_LatchedAbortStopsAnAlreadyAdmittedRequestBeforeTheCall|TestAutoStopConc11_LatchDuringInflightAdmissionSendsNothingMore' \
  . mcp_canary_runtime.go \
  's/\tif !cr\.aborter\.ExecutionEligible\(gen\) \{\n\t\treturn false\n\t\}\n//'

run_mutation M77 \
  'the window watchdog fires but trips nothing' \
  'TestAutoStop_WindowExpiresWithNoTrafficAtAll' \
  . mcp_canary_autostop.go \
  's/\t\trt\.tripCanaryAbortForGeneration\(capb, gen, "window_expired", canaryNow\(\)\)/\t\t_ = capb/'

run_mutation M78 \
  'an expired window restores as a healthy, executable activation' \
  'TestAutoStop_RestartAfterExpiryRestoresAborted|TestAutoStopConc05_DeadlineVersusRestart' \
  . mcp_canary_autostop.go \
  's/\t\ttripAutoStopLocked\(rt, capb, cr, "window_expired", now\)\n\t\treturn/\t\treturn/'

# ══════════════════════════════════════════════════════════════════════════════
# CODEX ROUND 1 ON #1314 — every safety report is bound to its own activation
# ══════════════════════════════════════════════════════════════════════════════

run_mutation M79 \
  'a breach from a superseded activation stops the one that replaced it' \
  'TestAutoStop_StaleBreachNeverStopsTheNextActivation' \
  . mcp_canary_runtime.go \
  's/\tif wantGen != 0 && cr\.generation != wantGen \{/\tif false {/'

# The generation guard on the settled-attempt path is DELIBERATELY redundant with
# HealthMonitor.Observe's own strictness, so removing either one alone is caught by
# nothing — the other still holds, which is the point of defense in depth. The
# mutation therefore removes BOTH; a campaign entry that removed one and passed
# would be measuring the redundancy, not the property.
printf '\n[M80] a settled attempt from a superseded activation counts against the next one\n'
printf '      gate: TestAutoStop_StaleSettledAttemptNeverCountsAgainstTheNextActivation  (both guards removed)\n'
perl -0pi -e 's/cr\.health == nil \|\| cr\.generation != gen \{\n\t\treturn\n\t\}/cr.health == nil {\n\t\treturn\n\t}/' mcp_canary_autostop.go
perl -0pi -e 's/\tif h == nil \|\| gen != h\.generation \{\n\t\treturn ""\n\t\}/\tif h == nil {\n\t\treturn ""\n\t}/' internal/mcp/canary/health.go
if git diff --quiet mcp_canary_autostop.go || git diff --quiet internal/mcp/canary/health.go; then
  printf '      SKIPPED — pattern drifted\n'; SKIPPED=$((SKIPPED+1))
  revert mcp_canary_autostop.go internal/mcp/canary/health.go
else
  m80_out=$(go test -count=1 -run 'TestAutoStop_StaleSettledAttemptNeverCountsAgainstTheNextActivation' . 2>&1); m80_rc=$?
  revert mcp_canary_autostop.go internal/mcp/canary/health.go
  if ! gate_ran M80 "the stale-sample gate" "$m80_out"; then
    [ $KEEP -eq 0 ] && exit 1
  elif [ $m80_rc -ne 0 ]; then
    printf '      CAUGHT (gate failed as required)\n'; PASS=$((PASS+1))
  else
    printf '      *** SURVIVED *** the gate passed with both guards removed\n'
    SURVIVED=$((SURVIVED+1)); SURVIVORS+=("M80: stale samples enter the new population")
    [ $KEEP -eq 0 ] && exit 1
  fi
fi

run_mutation M81 \
  'an early watchdog fire disarms the activation instead of re-arming' \
  'TestAutoStop_EarlyWatchdogFireReArmsInsteadOfDisarming' \
  . mcp_canary_autostop.go \
  's/\t\t\trt\.rearmWindowWatchdog\(capb, gen, d\.Sub\(canaryNow\(\)\)\)\n//'

run_mutation M82 \
  'exhaustion never latches when the final slot is refused at the boundary' \
  'TestAutoStop_ExhaustionLatchesWhenTheFinalSlotNeverSends' \
  . mcp_canary_runtime.go \
  's/\tif cr\.enforcer\.Remaining\(\) <= 0 && cr\.enforcer\.Inflight\(\) == 0 \{\n\t\ttripAutoStopLocked\(rt, capb, cr, "budget_exhausted", canaryNow\(\)\)\n\t\}\n//'

run_mutation M83 \
  'restore trusts the abort latch instead of re-deriving what the counters prove' \
  'TestAutoStop_RestoreReDerivesABreachTheCountersAlreadyProve' \
  . mcp_canary_autostop.go \
  's/\tif code := cr\.health\.Verdict\(\); code != "" \{\n\t\ttripAutoStopLocked\(rt, capb, cr, code, canaryNow\(\)\)\n\t\treturn\n\t\}\n//'

run_mutation M84 \
  'a failed health persist is logged and the Canary carries on' \
  'TestAutoStop_HealthPersistFailureFailsClosed' \
  . mcp_canary_autostop.go \
  's/\t\t_ = rt\.removeRuntimeStateAfterSafetyPersistFailure\(capb, "health", err\)\n//'

run_mutation M85 \
  'a damaged health snapshot restores as a cleared detector' \
  'TestAutoStop_DamagedHealthSnapshotNeverRestoresAsExecutable|TestHealth_RestoreRefusesDamagedCounters' \
  . internal/mcp/canary/health.go \
  's/\tif snap\.Generation != gen \|\| !snap\.Valid\(\) \{\n\t\treturn nil, false\n\t\}/\tif snap.Generation != gen || !snap.Valid() {\n\t\treturn \&HealthMonitor{generation: gen}, true\n\t}/'

# ══════════════════════════════════════════════════════════════════════════════
# CODEX ROUND 2 ON #1314
# ══════════════════════════════════════════════════════════════════════════════

run_mutation M86 \
  'the final boundary trusts the async watchdog instead of re-checking the deadline' \
  'TestAutoStop_ExpiredWindowStopsAnAlreadyAdmittedRequestAtTheBoundary' \
  . mcp_canary_runtime.go \
  's/\tif cr\.enforcer != nil && !cr\.enforcer\.WindowOpen\(canaryNow\(\)\) \{\n\t\treturn false\n\t\}\n//'

run_mutation M87 \
  'a health snapshot may claim more samples than the activation ever reserved' \
  'TestAutoStop_InflatedSampleCountNeverRestoresAsExecutable|TestAutoStop_HonestSampleCountsStillRestore' \
  . mcp_canary_runtime.go \
  's/\tif healthOK && st\.HealthSnapshot\.Samples > st\.BudgetSnapshot\.TotalReserved \{\n\t\thealthOK = false\n\t\}\n//'

# ============================================================================
# CODEX ROUND 3 ON #1314
# ============================================================================

run_mutation M88 \
  'a snapshot may erase a hard-latency observation' \
  'TestHealth_RestoreRefusesAnErasedHardLatency|TestHealth_HardLatencyCounterBoundsAreConsistent' \
  ./internal/mcp/canary/ internal/mcp/canary/health.go \
  's/\tcase s\.Samples > 0 && s\.HardLatencies == 0 && s\.LatencySumNs >= int64\(s\.Samples\)\*int64\(HealthLatencyHardLimit\):\n\t\treturn false\n//'

run_mutation M89 \
  'the health breach is handed to a later step instead of latching under the lock' \
  'TestAutoStop_HealthBreachLatchesUnderTheSameLockAsTheObservation' \
  . mcp_canary_autostop.go \
  's/\tif code := cr\.health\.Observe\(gen, failed, latency\); code != "" \{\n\t\ttripAutoStopLocked\(rt, capb, cr, code, canaryNow\(\)\)\n\t\treturn \/\/ tripAutoStopLocked persisted \(or failed closed\) already\n\t\}/\tif code := cr.health.Observe(gen, failed, latency); code != "" {\n\t\t_ = code\n\t}/'

run_mutation M90 \
  'the final boundary tests only the upper deadline, admitting a rolled-back clock' \
  'TestAutoStop_ClockRollbackBehindActivationClosesTheBoundary' \
  . mcp_canary_runtime.go \
  's/\tif cr\.enforcer != nil && !cr\.enforcer\.WindowOpen\(canaryNow\(\)\) \{\n\t\treturn false\n\t\}/\tif cr.enforcer != nil {\n\t\tif d := cr.enforcer.WindowDeadline(); !d.IsZero() \&\& !canaryNow().Before(d) {\n\t\t\treturn false\n\t\t}\n\t}/'

# M91 REORDERS two blocks rather than editing one, so its mutation lives in a helper
# script (scripts/mutations/m91_settle_after_outcome.py) instead of a sed expression.
# The swap is written to COMPILE: a compile failure would prove nothing, per the
# header rule, so the helper exits 1 when its pattern no longer matches and the
# mutation is scored SKIPPED rather than as a pass.
printf '\n[M91] the terminal outcome is made durable before the health sample\n'
printf '      gate: TestAttemptSettled_IsReportedBeforeTheTerminalOutcomeCommit  (./internal/mcp/execution/)\n'
if ! python3 scripts/mutations/m91_settle_after_outcome.py || git diff --quiet internal/mcp/execution/run.go; then
  printf '      SKIPPED — pattern drifted\n'; SKIPPED=$((SKIPPED+1))
  revert internal/mcp/execution/run.go
else
  gofmt -w internal/mcp/execution/run.go
  m91_out=$(go test -count=1 -run 'TestAttemptSettled_IsReportedBeforeTheTerminalOutcomeCommit' ./internal/mcp/execution/ 2>&1); m91_rc=$?
  revert internal/mcp/execution/run.go
  if ! gate_ran M91 "the settle-order gate" "$m91_out"; then
    [ $KEEP -eq 0 ] && exit 1
  elif [ $m91_rc -ne 0 ]; then
    printf '      CAUGHT (gate failed as required)\n'; PASS=$((PASS+1))
  else
    printf '      *** SURVIVED *** the gate passed with the outcome written first\n'
    SURVIVED=$((SURVIVED+1)); SURVIVORS+=("M91: the health sample may lag the terminal outcome")
    [ $KEEP -eq 0 ] && exit 1
  fi
fi

# ============================================================================
# CODEX ROUND 4 ON #1314
# ============================================================================

run_mutation M92 \
  'the arm path tests only the upper deadline, so a clock behind the activation arms instead of latching' \
  'TestAutoStop_ClockBehindActivationLatchesAtRestoreInsteadOfArming|TestAutoStop_ClockInsideTheWindowStillArmsNormally' \
  . mcp_canary_autostop.go \
  's/\tif !cr\.enforcer\.WindowOpen\(now\) \{/\tif !now.Before(deadline) {/'

# M93 targets the RUNTIME path the restore gate cannot reach: the watchdog callback firing while
# the window is closed at its lower end. Reverting the accessor alone survived the restore gate
# (restore latches before any watchdog exists), which is why
# TestAutoStop_WatchdogFiringUnderRollbackLatchesInsteadOfReArming exists.
run_mutation M93 \
  'the watchdog callback re-arms forever on a rolled-back clock' \
  'TestAutoStop_WatchdogFiringUnderRollbackLatchesInsteadOfReArming|TestAutoStop_EarlyWatchdogFireReArmsInsteadOfDisarming' \
  . mcp_canary_autostop.go \
  's/globalCanaryRuntime\.windowDeadlineIfOpen\(capb\)/globalCanaryRuntime.windowDeadline(capb)/'

# ============================================================================
# CODEX ROUND 5 ON #1314
# ============================================================================

# M94's gate needs a fixture whose error carries the OBSERVED-RESPONSE fact. A bare
# error leaves the send state at may_have_been_sent, where the defective predicate
# ALSO reports failure — the first draft of this gate passed against both shapes and
# proved nothing (recorded in the review artifact).
# M94 derives failure from the SEND STATE instead of the upstream leg — the round-5 defect. It
# moved to run.go with the settle call in round 7; the predicate's own body is M96's target, so
# this one mutates the ARGUMENT and the two stay independent.
run_mutation M94 \
  'an upstream error response counts as a successful attempt' \
  'TestAttemptSettled_PeerErrorResponseCountsAsAFailure|TestAttemptSettled_SuccessfulExecutionIsNotAFailure' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/e\.reportAttemptSettled\(in, attempt, sendState, upstreamLegFailed\(upResp, upErr\)\)\n\t\t\tif release/e.reportAttemptSettled(in, attempt, sendState, !sendState.ProvesReceipt())\n\t\t\tif release/'

run_mutation M95 \
  'a window denial at admission is recorded as budget_exhausted' \
  'TestAutoStop_WindowDenialAtAdmissionRecordsWindowExpired|TestAutoStop_TotalExhaustionStillRecordsBudgetExhausted' \
  . mcp_canary_runtime.go \
  's/\tcase outcome == canary\.BudgetDeniedWindow:/\tcase false:/'

# M96/M97 are Codex round 6: the error-rate detector's third failure shape, and the operator
# surface's own window predicate.

run_mutation M96 \
  'a JSON-RPC error response counts as a successful attempt' \
  'TestAttemptSettled_PeerJSONRPCErrorCountsAsAFailure|TestAttemptSettled_SuccessfulExecutionIsNotAFailure' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/return err != nil \|\| resp == nil \|\| resp\.Error != nil/return err != nil || resp == nil/'

run_mutation M97 \
  'the operator status tests only the upper end of the window' \
  'TestAutoStop_StatusIsNeverMoreOptimisticThanAdmission' \
  . mcp_canary_autostop.go \
  's/st\.WindowExpired = windowClosed/st.WindowExpired = !canaryNow().Before(deadline)/'

# The reported AUTHORITY is a SECOND line, so it needs its own mutation — the M70 lesson: two
# paths to the same claim can each be deleted unnoticed while the other keeps the gate green.
run_mutation M98 \
  'a closed window still reports granted execution authority' \
  'TestAutoStop_StatusIsNeverMoreOptimisticThanAdmission' \
  . mcp_canary_autostop.go \
  's/\tcase active \&\& \(aborted \|\| windowClosed\):/\tcase active \&\& aborted:/'

# M99 is Codex round 7: the reservation goes back BEFORE the health sample is counted, so with
# MaxConcurrentExecutions of 1 a third request can reserve and cross Upstream.Call before the
# second failure latches elevated_error_rate. The two statements are simply swapped — the
# mutation compiles, releases exactly once, and differs only in ORDER.
run_mutation M99 \
  'the reservation is released before the health sample is counted' \
  'TestAttemptSettled_IsReportedBeforeTheReservationIsReleased' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\t\t\te\.reportAttemptSettled\(in, attempt, sendState, upstreamLegFailed\(upResp, upErr\)\)\n\t\t\tif release != nil \{\n\t\t\t\trelease\(\)\n\t\t\t\}\n/\t\t\tif release != nil {\n\t\t\t\trelease()\n\t\t\t}\n\t\t\te.reportAttemptSettled(in, attempt, sendState, upstreamLegFailed(upResp, upErr))\n/'

# M100-M102 are Codex round 8. The release ordering has to hold for EVERY step that decides
# authority, not only the health sample (M99) — the terminal outcome commit is itself the
# outcome_evidence_loss producer. And the failure classifier needs one entry in each direction:
# a pinned-identity mismatch is a breach rather than a sample, and a caller cancellation is not
# evidence about the target at all.
run_mutation M100 \
  'the slot is released before the terminal outcome commit can report evidence loss' \
  'TestBreach_OutcomeEvidenceLossIsReportedBeforeTheReservationIsReleased' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\t\te\.commitAttemptOutcome\(in, attempt, sendState, out\)\n\t\treleaseReservation\(releaseSlot\)/\t\treleaseReservation(releaseSlot)\n\t\te.commitAttemptOutcome(in, attempt, sendState, out)/'

run_mutation M101 \
  'a pinned-identity mismatch is reduced to one ordinary failed sample' \
  'TestBreach_TLSIdentityMismatchTripsServerIdentityDrift|TestBreach_OrdinaryUpstreamFailureIsNotIdentityDrift' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\t\te\.reportUpstreamTrustBreach\(in, attempt, upErr\)\n//'

run_mutation M102 \
  'a caller cancellation is charged against the target' \
  'TestAttemptSettled_CallerCancellationIsNotATargetFailure' \
  ./internal/mcp/execution/ internal/mcp/execution/run.go \
  's/\tif err != nil && mcperr\.ReasonOf\(err\) == mcperr\.ReasonUpstreamCancelled \{\n\t\treturn false\n\t\}\n//'

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
  if ! gate_ran M17 "the sink side" "$sink_out" || ! gate_ran M17 "the real-spool side" "$spool_out"; then
    [ $KEEP -eq 0 ] && exit 1
  elif [ $sink_rc -eq 0 ] && [ $spool_rc -ne 0 ]; then
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
