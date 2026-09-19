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
# The mutations are NOT listed here. Each run_mutation call below carries its own one-line
# description as an argument, and that is the line the runner prints -- so it is the one statement
# of what a mutation does, and it cannot drift away from the mutation it describes. A header
# summary is a SECOND statement of the same fact: this file carried one, it stopped at M18 while
# the campaign grew to 30, and nothing noticed because nothing could.
#
# M14 is the anti-vacuity mutation §13 requires. A resolver returning constant false passes every
# negative gate in the campaign while making the First Canary permanently impossible, so the
# campaign is only meaningful if a POSITIVE control rejects it.
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

# BASELINE VERIFICATION (Codex P1, round 5, PR #1423).
#
# A mutation is scored CAUGHT when its named gate FAILS. That inference is valid ONLY if the gate
# PASSES on the UNMUTATED tree. If the gate is already red, every mutation pointed at it "catches"
# for free and the campaign measures nothing at all.
#
# This is not hypothetical, and it is why the check exists. The round-4 fix widened a wall's regex
# and left TestCredWall_EveryClaimedSurfaceIsScanned failing on the clean head, because §25d quotes
# the very phrase the widened matcher had just learned to recognise. The campaign was then run and
# recorded 21 caught / 0 survived / 0 skipped. Every one of those results was measured against a
# suite that was already failing. Codex found it; the campaign could not, because it never asked.
#
# The result is deliberately NOT "CAUGHT" and deliberately NOT "SURVIVED" — it is NOT PROVEN, the
# same verdict a mutation that fails to compile gets, and for the same reason: no gate ran that
# could distinguish the mutated tree from the clean one.
#
# Cached per (gate, package): the campaign points many mutations at the same gate, and re-running
# it per mutation would double a run that is already minutes long.
declare -A BASELINE=()
declare -A BASELINE_OUT=()
baseline_ok() {
  local gate="$1" pkg="$2" key="$1|$2"
  if [ -n "${BASELINE[$key]+set}" ]; then
    [ "${BASELINE[$key]}" = ok ]
    return
  fi
  local out rc
  out="$(go test -count=1 -run "$gate" "$pkg" 2>&1)"; rc=$?
  # A gate that matches nothing is not a green baseline either — it is a gate that cannot speak.
  if [ $rc -eq 0 ] && ! has_fixed 'no tests to run' "$out"; then
    BASELINE[$key]=ok
    return 0
  fi
  BASELINE[$key]=red
  BASELINE_OUT[$key]="$out"
  return 1
}

# PAYLOAD TARGETING (Codex round 9, PR #1423).
#
# The payloads are applied with perl in SLURP mode, so an s/// without /g replaces the FIRST match
# IN THE WHOLE FILE -- not the first match in the section the mutation is named after. M30's pattern
# was `mutations.sh` -- \d+ mutations`, which matched FOUR lines of the review document; the first
# is blocker 4's campaign row, ~1500 lines outside the section M30 targets. The mutation applied,
# edited an unrelated section, and the correctly-scoped gate saw nothing -- so it scored SURVIVED
# while the defect it models was never introduced. The campaign reported a hole that did not exist,
# which is the same failure as missing one: the score stopped describing the suite.
#
# Auditing the payloads by hand found the one instance. This makes the RUNNER prove the property
# instead: every payload must match EXACTLY ONE site. A miss (0) and an overreach (>1) are both
# NOT PROVEN, the same verdict a mutation that does not build gets, and for the same reason --
# nothing ran that could distinguish the mutated tree from the clean one. There is deliberately no
# opt-out for a payload that wants several sites: run_mutation already takes MULTIPLE payloads, so
# a mutation that needs several edits spells out each one, and a payload that cannot be anchored to
# a single site is a payload whose target is ambiguous.
#
# apply_payload prints how many SITES the payload matches, then applies it. The count must come
# from a /g run against an UNTOUCHED copy: a plain s/// returns 1 whether the pattern matched one
# site or forty, so counting substitutions would have reported M30 as a clean single hit -- the
# guard would have been decoration. eval(STRING) compiles the payload as perl source exactly as
# `perl -0pi -e` did, so the payloads themselves are unchanged.
apply_payload() {
  perl -0 -e '
    my ($f, $src) = @ARGV;
    open(my $in, "<", $f)  or die "open $f: $!";
    my $orig = do { local $/; <$in> };
    close $in;

    # how many sites does it match?
    $_ = $orig;
    my $sites = eval($src . "g");
    die $@ if $@;

    # apply it for real, from the untouched original
    $_ = $orig;
    eval($src);
    die $@ if $@;

    open(my $out, ">", $f) or die "write $f: $!";
    print $out $_;
    close $out;
    print $sites + 0;
  ' "$1" "$2"
}

# SELF-CHECK: THE SITE COUNTER MUST BE ABLE TO FAIL (Codex P2, round 10, PR #1423).
#
# The guard above is only worth having if apply_payload can really tell one site from several, and
# nothing in the campaign exercises that: every one of the 30 payloads matches exactly one site, so
# dropping the `/g` from the counting run -- or replacing the count with a constant 1 -- leaves all
# 30 passing while the guard is silently disabled, and the campaign reports 30 caught with the exact
# M30 ambiguity it exists to stop free to recur. Verified: with the `/g` the ambiguous M30 payload
# reports 4 sites; without it, 1.
#
# That is this campaign's own rule turned on the campaign: A CONTROL THAT CANNOT FAIL IS DECORATION.
# The manual verification of the counter is recorded in the review ledger, and a verification
# recorded in prose does not protect later runs -- which is the same gap between what an apparatus
# proves and what its record claims that every finding on this branch has been.
#
# A disagreement REFUSES TO START rather than warning: a counter that cannot distinguish 0 from 1
# from many makes every score after it unverified, the same reason a dirty tree and a red baseline
# refuse.
selfcheck_site_counter() {
  local dir; dir="$(mktemp -d)"
  local fixture="$dir/fixture.txt" fail=0 n
  printf 'token 1 widgets\ntoken 2 widgets\ntoken 3 widgets\nanchored 4 widgets\n' > "$fixture"

  # (1) an AMBIGUOUS payload must report every site it could land on, not the one it took.
  cp "$fixture" "$dir/a"
  n="$(apply_payload "$dir/a" 's/ \d+ widgets/ 999 widgets/')"
  [ "$n" = 4 ] || { printf 'SELF-CHECK: ambiguous payload reported %s site(s), expected 4\n' "$n" >&2; fail=1; }

  # (2) an ANCHORED payload must report exactly one, and must actually apply.
  cp "$fixture" "$dir/b"
  n="$(apply_payload "$dir/b" 's/anchored \d+ widgets/anchored 999 widgets/')"
  [ "$n" = 1 ] || { printf 'SELF-CHECK: anchored payload reported %s site(s), expected 1\n' "$n" >&2; fail=1; }
  cmp -s "$dir/b" "$fixture" && { printf 'SELF-CHECK: anchored payload counted but did not apply\n' >&2; fail=1; }

  # (3) a payload that matches nothing must report zero and leave the file alone.
  cp "$fixture" "$dir/c"
  n="$(apply_payload "$dir/c" 's/no such text anywhere/x/')"
  [ "$n" = 0 ] || { printf 'SELF-CHECK: non-matching payload reported %s site(s), expected 0\n' "$n" >&2; fail=1; }
  cmp -s "$dir/c" "$fixture" || { printf 'SELF-CHECK: non-matching payload changed the file\n' >&2; fail=1; }

  rm -rf "$dir"
  if [ $fail -ne 0 ]; then
    printf '\nrefusing to run: the payload site counter is broken, so no score it produced would\n' >&2
    printf '                 mean anything. Fix apply_payload before re-running.\n' >&2
    exit 3
  fi
}

# run_mutation <id> <description> [--compile-wall] <gate-regex> <package> <file> <perl-script...>
run_mutation() {
  local id="$1" desc="$2"; shift 2
  local compile_wall=0
  [ "${1:-}" = "--compile-wall" ] && { compile_wall=1; shift; }
  local gate="$1" pkg="$2" file="$3"; shift 3

  printf '\n[%s] %s\n' "$id" "$desc"
  printf '      gate: %s  (%s)\n' "$gate" "$pkg"

  if ! baseline_ok "$gate" "$pkg"; then
    printf '      NOT PROVEN — the gate is ALREADY RED (or matches nothing) on the UNMUTATED tree,\n'
    printf '                   so its failure after the mutation would prove nothing\n'
    printf '%s\n' "${BASELINE_OUT["$gate|$pkg"]}" | tail -6 | sed 's/^/        /'
    SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN (gate red on the unmutated tree)")
    [ $KEEP -eq 0 ] && exit 1
    return
  fi

  local before; before="$(git rev-parse HEAD:"$file" 2>/dev/null || echo none)"
  MUTATING_FILE="$file" # armed BEFORE the first edit; the trap restores it if we die here
  for script in "$@"; do
    local n; n="$(apply_payload "$file" "$script")"
    if [ "$n" != 1 ]; then
      printf '      NOT PROVEN — the payload matches %s site(s) in %s; exactly 1 is required.\n' \
        "$n" "$file"
      printf '                   A payload that can land somewhere other than where it claims to\n'
      printf '                   mutates the wrong thing and proves nothing.\n'
      SKIPPED=$((SKIPPED+1)); SURVIVORS+=("$id: NOT PROVEN (payload matches $n site(s), expected 1)")
      revert "$file"; MUTATING_FILE=""
      [ $KEEP -eq 0 ] && exit 1
      return
    fi
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

selfcheck_site_counter

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
READINESS=internal/mcp/canary/readiness.go
CREDMATRIX=mcp_canary_credential_matrix_test.go
OPERDOC=docs/operator/mcp-first-controlled-canary-review.md

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

# M19 — THE OBSERVABILITY BOUNDARY MOVES AND §25d's RESIDUAL PARAGRAPH STOPS BEING TRUE. That
# paragraph states the mid-window drift is NOT visible on a status read, because mcpCanaryStatus
# reports EvaluateNode, which skips every factActivation row. If EvaluateNode stops excluding them
# the claim inverts silently. Found by review (Codex P2, round 2) after the paragraph claimed the
# OPPOSITE — the gate behind it proved only that the FACT is live, never which SURFACE shows it.
# The gate fails in both directions and is anti-vacuous: this mutation empties the derived
# activation set, which a naive containment check would pass over.
run_mutation M19 \
  "EvaluateNode stops excluding activation facts, so the node status surface reports them" \
  'TestCredWall_NodeStatusSurfaceCannotReportActivationReasons' . "$READINESS" \
  's/if nodeOnly \&\& c.scope == factActivation {/if false \&\& nodeOnly \&\& c.scope == factActivation {/'

# M20 — THE CLAIM SURVIVES THE FIX. M19 stops the status surface from REPORTING an activation
# reason; it does not stop the code from CLAIMING otherwise, and round 3 found the claim in EIGHT
# places (three canary.Facts fields, the matrix row, the operator ledger, three test comments) —
# every one a factActivation row EvaluateNode excludes. The round-2 sweep missed them because it
# grepped the PHRASING ("next read") rather than the PROPOSITION ("make a node un-ready"). The gate
# derives the activation set from exported behaviour and reads the real source, so a fourth copy
# fails the build.
run_mutation M20 \
  "an activation fact's doc promises NODE readiness it cannot deliver" \
  'TestCredWall_NoActivationFactPromisesNodeReadiness' . "$READINESS" \
  's/after activation must be able to make the next FULL ACTIVATION PREFLIGHT refuse/after activation must be able to make a node un-ready, which a frozen copy cannot express/'

# M21 — THE WALL SCANS ONE FILE WHILE ITS RECORD CLAIMS SIX. M20's ledger entry says the class is
# closed across every surface that carried the claim; the first wall parsed only readiness.go, so
# reintroducing the promise in the matrix, the ledger or the test files left it green (Codex P2,
# round 4). That is the same overclaim the class is made of, one level up. This mutation puts the
# claim back into the MATRIX DOC — a surface the original wall never read.
run_mutation M21 \
  "the node-readiness promise returns on a surface the wall does not read" \
  'TestCredWall_EveryClaimedSurfaceIsScanned' . "$MATRIXDOC" \
  's/makes the next FULL ACTIVATION PREFLIGHT refuse\./can make the node un-ready./'

# M22 — THE SAME PROPOSITION, STATED POSITIVELY. Round 3 swept for the claim and fixed eight
# sites; every one was phrased NEGATIVELY ("makes a node un-ready"), because that is the phrasing
# the sweep and the matcher both looked for. Four sites stated the identical proposition the other
# way round — "this row only stops a node reporting Ready" — and survived untouched, one of them on
# ReasonExactPolicyNotExecutable, the reason string of an ACTIVATION fact. Codex round 5 found one.
#
# A proposition has a negation, and a matcher that only knows one polarity closes half a class.
# This mutation restores the positive form on the engine doc itself.
run_mutation M22 \
  "the node-readiness promise returns in the POSITIVE polarity the matcher used to miss" \
  'TestCredWall_EveryClaimedSurfaceIsScanned' . "$READINESS" \
  's/only stops the next FULL ACTIVATION PREFLIGHT admitting an experiment whose every call/only stops a node reporting Ready for an experiment whose every call/'

# M23 — THE ALLOWLIST GOES BACK TO PERMITTING WHOLE LINES. An entry's needle used to be matched
# with strings.Contains, so it permitted the entire line it appeared on: appending a fresh claim
# after an allowlisted quotation stayed green (Codex round 7). A permission to QUOTE one historical
# claim had become a permission to ASSERT a new one beside it, and reachability could not see it —
# reachability proves an entry is USED, never that it is NARROW. Matching is by SPAN now; this
# mutation restores the whole-line form.
run_mutation M23 \
  "an allowlist needle permits the whole line again, not just the claim it quotes" \
  'TestCredWall_AnAllowlistEntryPermitsOnlyWhatItQuotes' . "$CREDMATRIX" \
  's/if m\[0\] >= sp\[0\] && m\[1\] <= sp\[1\] \{/if m\[0\] >= 0 \&\& sp\[0\] >= 0 \{/'



# M24 — A CLAIM INSIDE QUOTES STOPS BEING A CLAIM. An earlier wall stripped every quoted span
# before testing a line. In Markdown that was meant to let the ledger cite the claims it documents;
# in GO SOURCE "quoted span" means STRING LITERAL, so it silently exempted the contents of every
# error message, log line and test-failure string in the repository — three real lines among them.
# The rule is gone and those lines are named in the allowlist instead. This mutation reintroduces
# "quoted means cited" in the reachability predicate, which strands every entry that needs it.
#
# Repointed in round 7: the previous form matched a line mentioning nodeReadyIndependence, which was
# DELETED that round, so the mutation stopped applying and scored SKIPPED — proving nothing, which
# is exactly why SKIPPED is not CAUGHT.
run_mutation M24 \
  "quoted text is treated as citation again, stranding the allowlist entries that need it" \
  'TestCredWall_AllowlistIsNotStale' . "$CREDMATRIX" \
  's/if needleCoversAClaim\(line, needle\) \{/if strings.Contains(line, "\\"") {\n\t\t\tcontinue\n\t\t}\n\t\tif needleCoversAClaim(line, needle) {/'



# M25 — A PERMISSION NOTHING EXERCISES. The allowlist staleness check originally asked only
# whether an entry's needle still appeared in the file. That cannot see an entry whose every line
# is already exempted by an earlier rule — which happened the moment the quotation rule was
# written, to an entry added minutes earlier in the same session.
#
# M25 SURVIVED its first run, and that survival is the more useful result. It weakened the check
# from REACHED back to merely present, and with every entry currently reachable the weakened form
# returned the same verdict on all of them: the gate passed with the defect in place, so it was
# proving nothing about reachability — it was riding on the allowlist happening to be clean. The
# predicate is now a named function with a control that drives it BOTH ways
# (TestCredWall_ReachabilityCheckCanActuallyFail), so this mutation has something to break.
run_mutation M25 \
  "the reachability check reports every allowlist entry as live" \
  'TestCredWall_ReachabilityCheckCanActuallyFail' . "$CREDMATRIX" \
  's/func allowlistEntryReached\(data, needle string\) bool \{/func allowlistEntryReached(data, needle string) bool {\n\t_ = data\n\t_ = needle\n\treturn true/'


# M26 — THE LEDGER'S FILE COUNT DRIFTS FROM THE WALKER'S. §25d states how many files the scan
# reads. Codex round 7 found it overstated by one — the walk removes the wall's own file — so the
# sentence recording the coverage fix committed the coverage overclaim. The number is now read back
# out of the document and compared to the walker.
run_mutation M26 \
  "the ledger overstates how many files the wall scans" \
  'TestCredWall_LedgerStatesTheRealScanCount' . "$OPERDOC" \
  's/SCANNED \(2,554 files\)/SCANNED (2,999 files)/'

# M27 — THE LEDGER UNDERSTATES THE PERMISSIONS IT INTRODUCED. Removing the quotation rule required
# naming each ledger quotation in the allowlist. The first version of that paragraph said three when
# four had been added, understating its own audit trail. The count is derived now.
run_mutation M27 \
  "the ledger undercounts the allowlist entries naming its own lines" \
  'TestCredWall_LedgerCountsItsOwnQuotationPermissions' . "$OPERDOC" \
  's/\*\*6 allowlist entries name ledger lines\*\*/**3 allowlist entries name ledger lines**/'

# NOTE ON PAYLOAD DURABILITY, THIRD INSTANCE (M31, round 12). M31 renamed a mention to `round 12`
# to model "a round the enumeration does not contain" -- and the same round ADDED Round 12 to the
# enumeration, so the payload still applied but no longer described a defect and the gate rightly
# passed. It scored SURVIVED: a reported hole that does not exist. M32 carried the same bomb with
# `13`. Both now name 97/98, which the enumeration (contiguous from 1, and at 12) cannot reach.
#
# The rule is broader than "do not hardcode today's text": A PAYLOAD MUST NOT NAME A VALUE THE
# DOCUMENT'S OWN GROWTH CAN MAKE VALID. The earlier two instances were payloads that stopped
# APPLYING; this one kept applying and stopped MEANING anything, which is harder to notice because
# the file really does change.
#
# NOTE ON PAYLOAD DURABILITY (learned twice: M24 in round 7, M28 in round 9). A payload that
# hardcodes the CURRENT text of a document stops applying the moment that document changes, and a
# mutation that does not apply scores SKIPPED — which proves nothing while looking like progress.
# Ledger payloads below therefore match the SHAPE (\d+) rather than today's value.
#
# M28 — THE ROUND TOTAL DRIFTS FROM THE ROUNDS THE SECTION DISCUSSES. §25d's summary states how
# many review rounds produced the defect classes. Codex round 8 found it saying "Five" while the
# paragraphs above it already recorded rounds 6 and 7 — a narrative number nobody derives drifts the
# moment the narrative grows, in a section whose whole subject is records that outrun what
# establishes them.
run_mutation M28 \
  "the ledger's review-round total drifts from the rounds it discusses" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/\*\*\d+ rounds, one defect shape\.\*\*/**1 rounds, one defect shape.**/'

# M29 — A ROUND VANISHES FROM THE ENUMERATION AND THE TOTAL STILL LOOKS RIGHT. §25d's round total
# is checked against its own structured list. The FIRST version of that gate compared the total to
# the largest "round N" numeral anywhere in the section, which a dropped entry would not shrink
# (Codex round 9) — the section's own defect class, inside the gate added one round earlier to
# close it. This mutation drops an entry and leaves the total alone.
run_mutation M29 \
  "a round entry vanishes from the enumeration while the total still reads 8" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/^- \*\*Round 4\*\* — the wall read ONE file.*?\n(?=- \*\*Round 5)//ms'

# M30 — THE LEDGER'S CAMPAIGN SIZE DRIFTS FROM THE SCRIPT. A second paragraph used to carry its own
# account of the campaign's growth and stopped at M21 while the script reached M28, so §25d gave two
# incompatible histories of one thing. The size is stated once now and derived from the script.
run_mutation M30 \
  "the ledger states a campaign size the script does not run" \
  'TestCredWall_LedgerStatesTheCampaignSize' . "$OPERDOC" \
  's/mcp-first-canary-no-credential-mutations\.sh` — \d+ mutations/mcp-first-canary-no-credential-mutations.sh` — 999 mutations/'

# M31 targets the clause Codex round 11 added, and it has to do so WITHOUT tripping the two older
# checks in the same gate. Deleting an entry would break contiguity or the total and be caught by
# those instead, proving nothing about the new clause; renaming a PROSE mention to a round the list
# does not contain leaves the total and the enumeration agreeing with each other -- which is exactly
# the state that was green before round 11 -- so only the new clause can reject it.
run_mutation M31 \
  "§25d discusses a round its enumeration does not contain" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/which Codex round 10 found/which Codex round 97 found/'

# M32 is M31's PLURAL twin, and it exists because M31 alone did not exercise what the gate claims.
# The first version of the round-name extractor matched only `round N`, so `rounds 7 and 8` -- a
# form §25d had contained all along -- was invisible to it, and the gate passed on that text only
# because 7 and 8 happen to be enumerated (Codex round 12). One mutation per FORM, not one per
# rule: a rule stated over several syntaxes is only as strong as the syntax that gets tested.
run_mutation M32 \
  "§25d names an unenumerated round in the PLURAL form the gate used to miss" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/in rounds 7 and 8/in rounds 7 and 98/'

# M33 is the OXFORD-COMMA form. M32 proved the plural arm reads `rounds A and B`; it did not prove
# the COMMA-LIST arm, whose parser accepted only one separator token and so stopped at the serial
# comma in `rounds 7, 8, and 98` (Codex round 13). Third form, third mutation -- the rule from
# round 12 applied to itself: a rule stated over several syntaxes is only as strong as the syntax
# that gets tested, and "comma list" and "comma list with a serial and" are different syntaxes.
#
# NOTE: M32 and M33 deliberately rewrite the SAME source phrase into two different shapes. Each
# mutation starts from the clean tree, so a payload must match what the file says AT REST -- the
# first draft of M33 targeted `in rounds 7 and 98`, which only exists once M32 has run, and would
# have scored SKIPPED forever.
run_mutation M33 \
  "§25d names an unenumerated round after an OXFORD COMMA" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/in rounds 7 and 8/in rounds 7, 8, and 97/'

# M34/M35 close the SEPARATOR treadmill, and they are two different gates, not one twice.
#
# M34 is the serial-`or` form (Codex round 14) -- the third natural-language separator in three
# rounds, after the plural `and` and the Oxford comma, each of which truncated the list SILENTLY.
# M35 is the answer to that pattern: an UNRECOGNISED connector must now FAIL rather than truncate,
# so the next form is reported instead of quietly dropping a round. M34 proves the parser reads the
# form; M35 proves the parser SAYS SO when it cannot.
run_mutation M34 \
  "§25d names an unenumerated round after a serial OR" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/in rounds 7 and 8/in rounds 7, 8, or 97/'

run_mutation M35 \
  "§25d names an unenumerated round after a one-word connector" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/in rounds 7 and 8/in rounds 7 plus 97/'

# M36 is the MULTI-WORD connector (Codex round 15). Round 14 answered the separator treadmill with
# "refuse what you cannot read", and that refusal matched ONE short token -- so `as well as`,
# `followed by` and `alongside` evaded BOTH the parser and the refusal, and M35 claimed to close a
# failure mode it did not. The collector now has no connector vocabulary at all, so M34/M35/M36 are
# three shapes of the same question: does a named round get seen whatever joins it to the last one?
run_mutation M36 \
  "§25d names an unenumerated round after a MULTI-WORD connector" \
  'TestCredWall_LedgerRoundCountMatchesItsOwnEnumeration' . "$OPERDOC" \
  's/in rounds 7 and 8/in rounds 7 as well as 97/'

printf '\n===================================================================\n'
printf 'caught: %d   survived: %d   skipped: %d\n' "$PASS" "$SURVIVED" "$SKIPPED"
if [ ${#SURVIVORS[@]} -gt 0 ]; then
  printf '\nNOT PROVEN:\n'
  for s in "${SURVIVORS[@]}"; do printf '  - %s\n' "$s"; done
  exit 1
fi
printf 'every mutation was caught by a named gate.\n'
