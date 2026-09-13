#!/usr/bin/env bash
# mcp-first-canary-catalog-usable-mutations.sh — the §12 campaign for GOVERNED CATALOG
# USABILITY AS A FIRST-CANARY ACTIVATION FACT (blocker #13).
#
# The defect this closes: the exact First-Canary tool was catalog.Quarantined, the policy
# engine hard-overrides a Quarantined tool to ActionQuarantine before any operator rule is
# consulted, and NOTHING in the activation preflight said so. A node could hold a valid live
# approval, a reviewed target, an exact scope and a read-first class, report Ready:true, and
# then have every request die at that override.
#
# Each mutation reintroduces ONE specific way that could come back, then runs the NAMED gate
# that must catch it. A mutation no test rejects is not a passing mutation: it is a hole.
#
#   M01  the readiness row is deleted from the activation table
#   M02  the fact is hard-coded true at the wiring step
#   M03  the production probe stops resolving it
#   M04  the commit path drops the resolved fact
#   M05  the restart-reconcile path drops the resolved fact
#   M06  the row is classified node-level, so EvaluateNode starts asserting it
#   M07  the resolver accepts any eligibility that is not the sticky floor
#   M08  the resolver stops comparing the scope's pinned fingerprint
#   M09  the resolver stops checking tenant ownership
#   M10  the resolver reports true for an empty scope
#   M11  the resolver reports true when the inventory is absent
#   M12  a live_execution approval promotes to catalog.Usable (authority collapse)
#   M13  the digest stops folding the fingerprint FORMAT version
#   M14  a data-plane file gains a promotion call (structural wall)
#
# A COMPILE FAILURE IS NOT PROOF unless the mutation targets a structural wall whose stated
# purpose is compile-time prevention (those declare --compile-wall).
#
# Usage:  scripts/mcp-first-canary-catalog-usable-mutations.sh [-k]
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
  for script in "$@"; do
    perl -0pi -e "$script" "$file"
  done
  local after; after="$(git hash-object "$file")"
  if [ "$before" = "$after" ]; then
    printf '      SKIPPED — the mutation did not change %s (pattern drifted)\n' "$file"
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: SKIPPED (pattern drifted in $file)")
    revert "$file"
    [ $KEEP -eq 0 ] && exit 1
    return
  fi

  local out; out="$(go test -count=1 -run "$gate" "$pkg" 2>&1)"
  local rc=$?
  revert "$file"

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

printf 'MCP FIRST-CANARY GOVERNED CATALOG USABILITY mutation campaign\n'
printf '============================================================\n'

READINESS=internal/mcp/canary/readiness.go
FPRINT=internal/mcp/catalog/fingerprint.go
PREFLIGHT=mcp_canary_preflight.go
ROLLOUT=mcp_rollout.go
TRUST=mcp_tooltrust.go
POLICYENG=internal/mcp/policy/engine.go

# M01 — THE ROW IS DELETED. The pure readiness table stops asserting usability at all, which is
# exactly the pre-#13 shape: every other activation fact still holds and the verdict is Ready.
run_mutation M01 \
  'the catalog-usability row is deleted from the activation readiness table' \
  'TestEvaluate_EachFactIsIndependentlyLoadBearing|TestEvaluate_ReasonVocabularyParity' \
  ./internal/mcp/canary "$READINESS" \
  's/\t\{func\(f Facts\) bool \{ return f\.ToolCatalogUsable \}, ReasonToolNotCatalogUsable, factActivation\},\n//'

# M02 — THE FACT IS ASSERTED, NOT RESOLVED. The wiring step hard-codes true, so the row is
# permanently met however Quarantined the tool is. This is the "runbook step" failure in code.
run_mutation M02 \
  'the activation wiring hard-codes the fact true instead of taking the resolved value' \
  'TestCatalogUsable_ProductionPreflightCarriesTheRow' \
  . "$PREFLIGHT" \
  's/\tf\.ToolCatalogUsable = in\.ToolCatalogUsable/\tf.ToolCatalogUsable = true/'

# M03 — THE PROBE STOPS RESOLVING IT. Authoritative node state is no longer consulted; the input
# arrives zero-valued, which fails closed — so the CONTROL half of the gate (a governed promotion
# must MEET the row) is what catches this. A defect that only ever fails closed is still a defect:
# it makes the fact unsatisfiable and the experiment un-runnable.
run_mutation M03 \
  'the production probe stops resolving the fact from authoritative catalog state' \
  'TestCatalogUsable_ProductionPreflightCarriesTheRow' \
  . "$PREFLIGHT" \
  's/\t\tToolCatalogUsable: canaryScopedToolsCatalogUsable\(scope\),/\t\tToolCatalogUsable: false,/'

# M04 — THE COMMIT PATH DROPS IT. The probe resolves the fact and the transition commit throws it
# away, so the serialized re-evaluation inside the commit never sees it.
run_mutation M04 \
  'the transition commit drops the resolved fact before re-evaluating the preflight' \
  'TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall' \
  . "$ROLLOUT" \
  's/\t\t\tToolCatalogUsable:  ai\.ToolCatalogUsable,\n//'

# M05 — THE RESTART PATH DROPS IT. A restart re-runs the activation preflight over the restored
# config; dropping the fact there lets a node resume a live mode a fresh commit would now reject.
run_mutation M05 \
  'the restart-reconcile preflight drops the resolved fact' \
  'TestCatalogUsable_EveryActivationInputFieldReachesEveryPreflightCall' \
  . "$ROLLOUT" \
  's/\t\t\t\t\tToolCatalogUsable: ai\.ToolCatalogUsable, Now: time\.Now\(\),/\t\t\t\t\tNow: time.Now(),/'

# M06 — THE ROW IS RECLASSIFIED NODE-LEVEL. EvaluateNode answers "is this NODE ready", a question
# no scope is supplied for, so a scope-derived fact there is answered against a zero value and
# reports every node un-ready for a scope nobody named.
run_mutation M06 \
  'the row is classified node-level, so EvaluateNode starts asserting a scope-derived fact' \
  'TestEvaluateNode_ExcludesActivationInputs' \
  ./internal/mcp/canary "$READINESS" \
  's/\{func\(f Facts\) bool \{ return f\.ToolCatalogUsable \}, ReasonToolNotCatalogUsable, factActivation\}/{func(f Facts) bool { return f.ToolCatalogUsable }, ReasonToolNotCatalogUsable, factNode}/'

# M07 — "NOT QUARANTINED" IS ACCEPTED AS USABLE. ReviewRequired and PendingNarrowing are also
# hard-overridden by the policy engine, so anything short of exactly Usable is the same outage.
run_mutation M07 \
  'the resolver accepts any eligibility that is merely not the sticky Quarantined floor' \
  'TestCatalogUsable_SeededToolIsQuarantinedAndNotUsable|TestCatalogUsable_LiveApprovalAloneNeverPromotes' \
  . "$PREFLIGHT" \
  's/\t\t\tif rec\.Eligibility != catalog\.Usable \{/\t\t\tif rec.Eligibility == catalog.ServerDisabled {/'

# M08 — THE PIN IS NOT COMPARED. A Usable record for SOME revision of the tool satisfies a scope
# pinned to a different one — F2 riding F1's promotion, the §5 defect.
run_mutation M08 \
  'the resolver stops comparing the record digest against the scope pinned fingerprint' \
  'TestCatalogUsable_UsableRecordDoesNotSatisfyAScopePinnedElsewhere' \
  . "$PREFLIGHT" \
  's/if !strings\.EqualFold\(hex\.EncodeToString\(sum\[:\]\), st\.Fingerprint\) \{/if !strings.EqualFold(hex.EncodeToString(sum[:]), hex.EncodeToString(sum[:])) {/'

# M09 — TENANT OWNERSHIP IS NOT CHECKED. A scope naming any tenant satisfies the fact for a server
# that tenant does not own.
run_mutation M09 \
  'the resolver stops checking that the naming tenant owns the server' \
  'TestCatalogUsable_TenantThatDoesNotOwnTheServerIsNotUsable' \
  . "$PREFLIGHT" \
  's/(scope naming a tenant that does not own this server resolves to no usable target\.\n\t\t\tti := mcpToolTrust\.loadTarget\(st\.Server, st\.Name\)\n)\t\t\tif !ti\.found \|\| ti\.target\.Tenant != tenant \{/$1\t\t\tif !ti.found \&\& tenant == "\\x00never" {/'

# M10 — AN EMPTY SCOPE IS "USABLE". Vacuous truth: a scope admitting no tool satisfies a fact about
# every tool it admits, so the row is met for an experiment with no reviewed target at all.
run_mutation M10 \
  'the resolver reports the fact satisfied for an empty scope (vacuous truth)' \
  'TestCatalogUsable_EmptyScopeIsNotVacuouslyUsable' \
  . "$PREFLIGHT" \
  's/\tif len\(scope\.Tools\) == 0 \|\| len\(scope\.Tenants\) == 0 \{\n\t\treturn false\n\t\}/\tif len(scope.Tools) == 0 || len(scope.Tenants) == 0 {\n\t\treturn true\n\t}/'

# M11 — AN ABSENT INVENTORY IS "USABLE". Fail-open on the exact condition under which nothing is
# known about the tool.
run_mutation M11 \
  'the resolver reports the fact satisfied when no inventory is published (fail-open)' \
  'TestCatalogUsable_AbsentInventoryFailsClosed' \
  . "$PREFLIGHT" \
  's/\tif reg == nil \|\| cat == nil \{\n\t\treturn false\n\t\}/\tif reg == nil || cat == nil {\n\t\treturn true\n\t}/'

# M12 — AUTHORITY COLLAPSE. ApproveLive gains the promotion ApproveShadow performs, so a
# live_execution approval makes a tool catalog.Usable. This is §2's central rule: the two approvals
# answer different questions and one must never satisfy the other.
run_mutation M12 \
  'a live_execution approval promotes the tool to catalog.Usable' \
  'TestCatalogUsable_LiveApprovalAloneNeverPromotes|TestCatalogUsable_ShadowAndLiveAreIndependentFacts' \
  . "$TRUST" \
  's/\t\/\/ Deliberately NO promoteFor \/ catalog mutation: live trust never materializes catalog\.Usable\.\n\treturn granted, nil/\tif _, perr := c.promoteFor(granted); perr != nil {\n\t\treturn nil, perr\n\t}\n\treturn granted, nil/'

# M13 — THE DIGEST STOPS BINDING THE FORMAT. The resolver has no separate format comparison BY
# DESIGN, because Sum folds FormatVersion in before any other segment. Remove that and the format
# binding silently disappears from every caller that rests on it — which is the whole point of
# pinning the property directly rather than restating it as a check.
run_mutation M13 \
  'the fingerprint digest stops folding the fingerprint FORMAT version' \
  'TestCatalogUsable_FingerprintFormatIsFoldedIntoTheBoundDigest' \
  . "$FPRINT" \
  's/\tvar ver \[2\]byte\n\tbinary\.BigEndian\.PutUint16\(ver\[:\], f\.FormatVersion\)\n\th\.Write\(ver\[:\]\)\n/\tvar ver [2]byte\n\th.Write(ver[:])\n/'

# M14 — THE DATA PLANE PROMOTES. A request-path file gains a catalog.Promote call, which is §8's
# forbidden shape: request traffic must never mutate catalog eligibility. The wall is by CALLER,
# so any promoter outside the governed coordinator fails it.
run_mutation M14 \
  'a data-plane file gains a catalog promotion call' \
  'TestCatalogUsable_OnlyTheGovernedCoordinatorPromotes' \
  . "$PREFLIGHT" \
  's/(func canaryScopedToolsCatalogUsable\(scope rollout\.ScopeSpec\) bool \{\n)/$1\tif false {\n\t\t_, c := mcpInventory.sharedInventory()\n\t\t_, _ = c.Promote(catalog.ToolKey{}, catalog.Fingerprint{})\n\t}\n/'

printf '\n===========================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ "$SKIPPED" -gt 0 ]; then
  printf 'A SKIPPED mutation proves nothing: its pattern no longer matches the source.\n'
fi
for s in "${SURVIVORS[@]:-}"; do [ -n "$s" ] && printf 'SURVIVOR: %s\n' "$s"; done
[ "$SURVIVED" -eq 0 ] && [ "$SKIPPED" -eq 0 ] && exit 0
exit 1
