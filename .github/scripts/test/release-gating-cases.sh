#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# release-gating-cases.sh — behavioural tests for the release predicate and the
# image-promotion guard, against MOCKED publication operations.
#
# Every external effect is stubbed on PATH:
#   gh      — serves a canned workflow-runs page per (workflow, sha, event,
#             head_branch) and RECORDS each query, so a case can assert that a
#             refusal happened for the right reason and that evidence for
#             another SHA/workflow/event was never accepted.
#   docker  — serves a canned tag→digest resolution and RECORDS every
#             `imagetools create`, so "did this promote, and what exactly did it
#             point where" is observable without touching a registry.
#   git     — answers merge-base ancestry from a canned table.
#
# Nothing here contacts GitHub, ghcr.io, Sigstore or Rekor, and no release is
# created. Driven from Go by TestReleasePublicationGating_Behaviour so it runs
# under `go test ./...`.
#
# Usage: release-gating-cases.sh   (exit 0 = all cases pass)
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPTS="${REPO_ROOT}/.github/scripts"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()   { pass=$((pass+1)); printf '  PASS  %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "$2"; }

# ── mock harness ─────────────────────────────────────────────────────────────
BIN="$WORK/bin"; mkdir -p "$BIN"

cat > "$BIN/gh" <<'EOF'
#!/usr/bin/env bash
# Mock `gh api …/workflows/<wf>/runs?head_sha=…&event=…`.
# Fixture: $GH_FIXTURE, lines "<wf>|<sha>|<event>|<head_branch>|<status>|<conclusion>".
# GH_FAIL=1 makes every call fail (the API-error fail-closed path).
printf '%s\n' "$*" >> "${GH_CALLS:-/dev/null}"
[ "${GH_FAIL:-}" = "1" ] && { echo "mock gh: api error" >&2; exit 1; }
url="";
for a in "$@"; do case "$a" in */runs\?*|*/releases/*) url="$a";; esac; done
wf="${url#*/workflows/}"; wf="${wf%%/runs*}"
qs="${url#*\?}"
sha=""; ev=""
for kv in ${qs//&/ }; do
  case "$kv" in head_sha=*) sha="${kv#head_sha=}";; event=*) ev="${kv#event=}";; esac
done
out=""
while IFS='|' read -r fwf fsha fev fbr fst fcon; do
  [ -z "${fwf:-}" ] && continue
  case "$fwf" in \#*) continue;; esac
  [ "$fwf" = "$wf" ] && [ "$fsha" = "$sha" ] && [ "$fev" = "$ev" ] || continue
  # require-gate.sh filters to head_branch == "main" and takes the first match.
  [ "$fbr" = "main" ] || continue
  [ -z "$out" ] && out="${fst}:${fcon}"
done < "${GH_FIXTURE:-/dev/null}"
[ -z "$out" ] && out="none:null"
echo "$out"
EOF

cat > "$BIN/docker" <<'EOF'
#!/usr/bin/env bash
# Mock `docker buildx imagetools inspect <ref> --format {{.Manifest.Digest}}`
# and record `docker buildx imagetools create …`.
if [ "${2:-}" = "imagetools" ] && [ "${3:-}" = "inspect" ]; then
  ref="$4"; tag="${ref##*:}"
  while IFS='|' read -r ftag fdig; do
    [ -z "${ftag:-}" ] && continue
    [ "$ftag" = "$tag" ] && { echo "$fdig"; exit 0; }
  done < "${DOCKER_TAGS:-/dev/null}"
  echo "mock docker: no such tag $tag" >&2; exit 1
fi
if [ "${2:-}" = "imagetools" ] && [ "${3:-}" = "create" ]; then
  printf '%s\n' "$*" >> "${DOCKER_CREATES:-/dev/null}"; exit 0
fi
exit 0
EOF

cat > "$BIN/git" <<'EOF'
#!/usr/bin/env bash
# Mock `git merge-base --is-ancestor <a> <b>`: true iff "<a>|<b>" is in
# $GIT_ANCESTORS. Everything else is a no-op success.
if [ "${1:-}" = "merge-base" ] && [ "${2:-}" = "--is-ancestor" ]; then
  grep -qxF "${3}|${4}" "${GIT_ANCESTORS:-/dev/null}" && exit 0
  exit 1
fi
exit 0
EOF
chmod +x "$BIN"/*

export PATH="$BIN:$PATH"
export GITHUB_REPOSITORY="KidCarmi/Culvert"
export GH_TOKEN="mock"
unset GITHUB_STEP_SUMMARY || true

GREEN="3d8c9bb"; OTHER="deadbee"
MANIFEST="$WORK/manifest.txt"
printf 'security-release-gate.yml mandatory\nqa-gate.yml mandatory\ninstall-lifecycle-e2e.yml advisory\n' > "$MANIFEST"

# fixture(<lines…>) writes a gh fixture and points the mock at it.
fixture() { : > "$WORK/fx"; for l in "$@"; do printf '%s\n' "$l" >> "$WORK/fx"; done; export GH_FIXTURE="$WORK/fx"; }
both_green() { fixture \
  "security-release-gate.yml|$GREEN|push|main|completed|success" \
  "qa-gate.yml|$GREEN|push|main|completed|success" \
  "install-lifecycle-e2e.yml|$GREEN|push|main|completed|success"; }

predicate() { RELEASE_EVIDENCE_MANIFEST="$MANIFEST" bash "$SCRIPTS/require-release-evidence.sh" "$@"; }

# ─── 1. required evidence must be green ──────────────────────────────────────
both_green
if predicate "$GREEN" assert >/dev/null 2>&1; then ok "green mandatory evidence satisfies the predicate"
else bad "green mandatory evidence satisfies the predicate" "predicate refused a fully green SHA"; fi

for bad_concl in failure cancelled timed_out startup_failure stale skipped neutral; do
  fixture "security-release-gate.yml|$GREEN|push|main|completed|$bad_concl" \
          "qa-gate.yml|$GREEN|push|main|completed|success"
  if predicate "$GREEN" assert >/dev/null 2>&1; then
    bad "mandatory conclusion '$bad_concl' blocks promotion" "predicate APPROVED a '$bad_concl' gate"
  else ok "mandatory conclusion '$bad_concl' blocks promotion"; fi
done

# Pending (queued/in_progress, conclusion null) must refuse in assert mode.
fixture "security-release-gate.yml|$GREEN|push|main|in_progress|null" \
        "qa-gate.yml|$GREEN|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "pending mandatory evidence blocks promotion" "predicate APPROVED an in-progress gate"
else ok "pending mandatory evidence blocks promotion"; fi

# Entirely missing run.
fixture "qa-gate.yml|$GREEN|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "missing mandatory evidence blocks promotion" "predicate APPROVED with no security-gate run at all"
else ok "missing mandatory evidence blocks promotion"; fi

# gh API error must never be read as "pending, keep going".
both_green
if GH_FAIL=1 predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "an evidence-API error fails closed" "predicate APPROVED when the API was unreachable"
else ok "an evidence-API error fails closed"; fi

# A skipped gate must refuse IMMEDIATELY in `wait` mode too. Before the fix
# `skipped` fell through to the not-concluded-yet branch, so the main-push
# promotion path would have polled for the full 30 minutes before refusing —
# green-looking for half an hour on evidence that never existed. `timeout`
# makes that the failure it is.
fixture "security-release-gate.yml|$GREEN|push|main|completed|skipped" \
        "qa-gate.yml|$GREEN|push|main|completed|success"
if timeout 20 env RELEASE_EVIDENCE_MANIFEST="$MANIFEST" \
     bash "$SCRIPTS/require-release-evidence.sh" "$GREEN" wait >/dev/null 2>&1; then
  bad "a skipped gate refuses immediately in wait mode" "wait mode APPROVED a skipped gate"
elif [ "$?" -eq 124 ]; then
  bad "a skipped gate refuses immediately in wait mode" "wait mode polled instead of refusing (timed out)"
else ok "a skipped gate refuses immediately in wait mode"; fi

# ─── 2. evidence cannot be borrowed from elsewhere ───────────────────────────
fixture "security-release-gate.yml|$OTHER|push|main|completed|success" \
        "qa-gate.yml|$OTHER|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "another SHA's green run cannot authorize this release" "predicate APPROVED using $OTHER's evidence"
else ok "another SHA's green run cannot authorize this release"; fi

fixture "security-release-gate.yml|$GREEN|push|refs/tags/v9.9.9|completed|success" \
        "qa-gate.yml|$GREEN|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "a tag-branch run of the same SHA cannot self-approve" "predicate APPROVED a non-main head_branch run"
else ok "a tag-branch run of the same SHA cannot self-approve"; fi

fixture "security-release-gate.yml|$GREEN|workflow_dispatch|main|completed|success" \
        "qa-gate.yml|$GREEN|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "a dispatched run cannot substitute for the main-push run" "predicate APPROVED an event=workflow_dispatch run"
else ok "a dispatched run cannot substitute for the main-push run"; fi

# A green run of the WRONG workflow must not satisfy a mandatory row.
fixture "qa-gate.yml|$GREEN|push|main|completed|success" \
        "pr-fast-gate.yml|$GREEN|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "another workflow's green run cannot satisfy a mandatory row" "predicate APPROVED via pr-fast-gate.yml"
else ok "another workflow's green run cannot satisfy a mandatory row"; fi

# ─── 3. advisory rows report but never block ─────────────────────────────────
fixture "security-release-gate.yml|$GREEN|push|main|completed|success" \
        "qa-gate.yml|$GREEN|push|main|completed|success" \
        "install-lifecycle-e2e.yml|$GREEN|push|main|completed|failure"
out="$(predicate "$GREEN" assert 2>&1)"; rc=$?
if [ "$rc" -eq 0 ] && grep -q "advisory evidence install-lifecycle-e2e.yml is NOT green" <<<"$out"; then
  ok "a red advisory row is reported and does not block"
else bad "a red advisory row is reported and does not block" "rc=$rc out=$(tr '\n' ' ' <<<"$out")"; fi

# ─── 4. the manifest itself cannot go vacuous ────────────────────────────────
printf '# only comments\n' > "$WORK/empty.txt"
if RELEASE_EVIDENCE_MANIFEST="$WORK/empty.txt" bash "$SCRIPTS/require-release-evidence.sh" "$GREEN" assert >/dev/null 2>&1; then
  bad "an empty manifest refuses" "a predicate with no mandatory rows APPROVED"
else ok "an empty manifest refuses"; fi

if RELEASE_EVIDENCE_MANIFEST="$WORK/nope.txt" bash "$SCRIPTS/require-release-evidence.sh" "$GREEN" assert >/dev/null 2>&1; then
  bad "an unreadable manifest refuses" "a missing manifest APPROVED"
else ok "an unreadable manifest refuses"; fi

printf 'qa-gate.yml optional\n' > "$WORK/badcls.txt"
if RELEASE_EVIDENCE_MANIFEST="$WORK/badcls.txt" bash "$SCRIPTS/require-release-evidence.sh" "$GREEN" assert >/dev/null 2>&1; then
  bad "an unknown classification refuses" "manifest row 'optional' was accepted"
else ok "an unknown classification refuses"; fi

# The SHIPPED manifest must resolve against a fully green fleet, or the
# predicate is unsatisfiable in production.
ship_fx=""
while read -r wf cls; do
  case "${wf:-}" in ''|\#*) continue;; esac
  [ -n "${cls:-}" ] || continue
  ship_fx="${ship_fx}${wf}|${GREEN}|push|main|completed|success"$'\n'
done < <(sed 's/#.*//' "$REPO_ROOT/.github/release-evidence.txt" | tr -s ' \t' ' ')
printf '%s' "$ship_fx" > "$WORK/ship"; export GH_FIXTURE="$WORK/ship"
if bash "$SCRIPTS/require-release-evidence.sh" "$GREEN" assert >/dev/null 2>&1; then
  ok "the shipped manifest is satisfiable when every listed workflow is green"
else bad "the shipped manifest is satisfiable when every listed workflow is green" "shipped predicate refused an all-green fleet"; fi

# ─── 5. image promotion ──────────────────────────────────────────────────────
DIG="sha256:$(printf 'a%.0s' $(seq 64))"
DIG2="sha256:$(printf 'b%.0s' $(seq 64))"
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n' "$DIG" "$DIG" > "$WORK/tags"; export DOCKER_TAGS="$WORK/tags"
: > "$WORK/creates"; export DOCKER_CREATES="$WORK/creates"
: > "$WORK/anc"; export GIT_ANCESTORS="$WORK/anc"
promote() { bash "$SCRIPTS/promote-image-tags.sh" "$@"; }

: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest 1.2 1" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1 \
   && grep -q -- "--tag ghcr.io/x:latest" "$WORK/creates" \
   && grep -q -- "--tag ghcr.io/x:1.2.3" "$WORK/creates" \
   && grep -q -- "ghcr.io/x@$DIG" "$WORK/creates"; then
  ok "approved evidence promotes the intended digest onto the intended channels"
else bad "approved evidence promotes the intended digest onto the intended channels" "creates=$(cat "$WORK/creates")"; fi

: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG2" candidate-99 >/dev/null 2>&1; then
  bad "promotion refuses a digest this run did not build" "promoted a digest the candidate tag does not resolve to"
else
  [ -s "$WORK/creates" ] && bad "promotion refuses a digest this run did not build" "it still called imagetools create" \
                         || ok "promotion refuses a digest this run did not build"
fi

: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" sha-absent >/dev/null 2>&1; then
  bad "promotion refuses an unresolvable candidate tag" "promoted against a tag that is not in the registry"
else ok "promotion refuses an unresolvable candidate tag"; fi

: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha FLOATING_TAGS="latest" \
     promote ghcr.io/x "sha256:short" candidate-99 >/dev/null 2>&1; then
  bad "promotion refuses a malformed digest" "accepted 'sha256:short'"
else ok "promotion refuses a malformed digest"; fi

: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
  bad "promotion refuses an empty target set" "a no-op promotion reported success"
else ok "promotion refuses an empty target set"; fi

# Re-run of the SAME run: idempotent, promotes the same digest again.
: > "$WORK/creates"
for _ in 1 2; do
  RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
    promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1
done
if [ "$(grep -c "ghcr.io/x@$DIG" "$WORK/creates")" -eq 2 ]; then
  ok "re-running the owning run is idempotent (same digest, same channels)"
else bad "re-running the owning run is idempotent (same digest, same channels)" "creates=$(cat "$WORK/creates")"; fi

# ── supersession: floating channels defer, immutable version tags do not ────
printf 'oldsha|newtip\n' > "$WORK/anc"

# MAIN path shape (no immutable targets): a superseded re-run promotes NOTHING.
: > "$WORK/creates"
if RELEASE_SHA=oldsha CHANNEL_TIP=newtip FLOATING_TAGS="latest main 1.2.3" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
  if [ -s "$WORK/creates" ]; then
    bad "a superseded main-path re-run does not overwrite a newer candidate" "it repointed a channel backwards"
  else ok "a superseded main-path re-run does not overwrite a newer candidate"; fi
else bad "a superseded main-path re-run does not overwrite a newer candidate" "it failed instead of skipping cleanly"; fi

# TAG path shape: superseded must STILL publish its own immutable version tag,
# and must NOT move the floating channels. Skipping the version tag left a
# public release whose X.Y.Z was absent or pointed at another digest.
: > "$WORK/creates"
if RELEASE_SHA=oldsha CHANNEL_TIP=newtip IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="1.2 1" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
  if grep -q -- "--tag ghcr.io/x:1.2.3" "$WORK/creates" \
     && ! grep -q -- "--tag ghcr.io/x:1.2 " "$WORK/creates" \
     && ! grep -q -- "--tag ghcr.io/x:1 " "$WORK/creates"; then
    ok "a superseded tag run still promotes its immutable version tag"
  else bad "a superseded tag run still promotes its immutable version tag" "creates=$(cat "$WORK/creates")"; fi
else bad "a superseded tag run still promotes its immutable version tag" "it failed instead of promoting the immutable tag"; fi

: > "$WORK/creates"
RELEASE_SHA=oldsha CHANNEL_TIP=newtip IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
  promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1
if grep -q -- "--tag ghcr.io/x:latest" "$WORK/creates"; then
  bad "a superseded run never moves a floating channel" "it moved latest backwards"
else ok "a superseded run never moves a floating channel"; fi

# Divergent history (not the tip, not an ancestor) must REFUSE everything,
# immutable targets included — we cannot tell which release this even is.
: > "$WORK/creates"; : > "$WORK/anc"
if RELEASE_SHA=forked CHANNEL_TIP=newtip IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
  bad "a divergent SHA refuses promotion" "a force-pushed/divergent SHA was allowed to promote"
else
  [ -s "$WORK/creates" ] && bad "a divergent SHA refuses promotion" "it promoted anyway" \
                         || ok "a divergent SHA refuses promotion"
fi

# ─── 6. release-completeness gate ────────────────────────────────────────────
complete_list() {
  for p in "linux amd64" "linux arm64" "darwin amd64" "darwin arm64" "windows amd64"; do
    set -- $p; e=""; [ "$1" = windows ] && e=".exe"
    echo "culvert-$1-$2$e 100"; echo "culvert-$1-$2$e.sigstore.json 100"
  done
  for a in amd64 arm64; do echo "culvert-maint-linux-$a 100"; echo "culvert-maint-linux-$a.sigstore.json 100"; done
  for s in culvert.sbom.cdx.json culvert-maint.sbom.cdx.json; do echo "$s 100"; echo "$s.sigstore.json 100"; done
  echo "culvert-release-catalog-v1.2.3.tar.gz 100"
  echo "multiple.intoto.jsonl 100"
}
complete_list > "$WORK/assets"
if ASSERT_RELEASE_ASSETS_FILE="$WORK/assets" bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 >/dev/null 2>&1; then
  ok "a complete staged release passes the publication check"
else bad "a complete staged release passes the publication check" "$(ASSERT_RELEASE_ASSETS_FILE=$WORK/assets bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 2>&1 | tail -3)"; fi

complete_list | grep -v '^multiple.intoto.jsonl' > "$WORK/assets"
if ASSERT_RELEASE_ASSETS_FILE="$WORK/assets" bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 >/dev/null 2>&1; then
  bad "missing SLSA provenance blocks publication" "published without provenance"
else ok "missing SLSA provenance blocks publication"; fi

complete_list | grep -v '^culvert-release-catalog' > "$WORK/assets"
if ASSERT_RELEASE_ASSETS_FILE="$WORK/assets" bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 >/dev/null 2>&1; then
  bad "a missing signed catalog bundle blocks publication" "published without the catalog"
else ok "a missing signed catalog bundle blocks publication"; fi

complete_list | sed 's|^culvert-darwin-arm64.sigstore.json 100|culvert-darwin-arm64.sigstore.json 0|' > "$WORK/assets"
if ASSERT_RELEASE_ASSETS_FILE="$WORK/assets" bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 >/dev/null 2>&1; then
  bad "a zero-byte signature bundle blocks publication" "a 0-byte .sigstore.json counted as present"
else ok "a zero-byte signature bundle blocks publication"; fi

complete_list | grep -v '^culvert-windows-amd64.exe ' > "$WORK/assets"
if ASSERT_RELEASE_ASSETS_FILE="$WORK/assets" bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 >/dev/null 2>&1; then
  bad "a missing platform binary blocks publication" "published with windows/amd64 absent"
else ok "a missing platform binary blocks publication"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
