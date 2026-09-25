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
if [ "${2:-}" = "imagetools" ] && [ "${3:-}" = "inspect" ] && [ "${5:-}" = "--format" ] \
   && [ "${6:-}" = "{{json .Image}}" ]; then
  # Image config for the SHA-provenance check. Fixture: $DOCKER_LABELS, lines
  # "<digest>|<revision>"; a digest with no row yields a config carrying no
  # revision label at all.
  want="${4##*@}"
  while IFS='|' read -r fdig frev; do
    [ -z "${fdig:-}" ] && continue
    if [ "$fdig" = "$want" ]; then
      printf '{"linux/amd64":{"config":{"Labels":{"org.opencontainers.image.revision":"%s"}}}}\n' "$frev"
      exit 0
    fi
  done < "${DOCKER_LABELS:-/dev/null}"
  echo '{"linux/amd64":{"config":{"Labels":{}}}}'; exit 0
fi
if [ "${2:-}" = "imagetools" ] && [ "${3:-}" = "inspect" ]; then
  ref="$4"; tag="${ref##*:}"
  # A DIGEST reference resolves to itself when the image is present — that is
  # the reachability probe resolve-release-candidate.sh makes before reading any
  # 404 as "absent". DOCKER_AMBIGUOUS_TAG can name the digest hex to model an
  # unreachable registry.
  case "$ref" in
    *@sha256:*)
      if [ -n "${DOCKER_AMBIGUOUS_TAG:-}" ] && [ "$tag" = "$DOCKER_AMBIGUOUS_TAG" ]; then
        echo "ERROR: failed to do request: dial tcp: i/o timeout" >&2; exit 1
      fi
      echo "sha256:$tag"; exit 0 ;;
  esac
  # DOCKER_AMBIGUOUS_TAG: this tag's lookup fails for a reason that is NOT
  # "absent" — a transient registry/network fault. Verbatim-shaped so the
  # classifier is exercised on real wording, not on a sentinel.
  if [ -n "${DOCKER_AMBIGUOUS_TAG:-}" ] && [ "$tag" = "$DOCKER_AMBIGUOUS_TAG" ]; then
    echo "ERROR: failed to do request: Head \"https://ghcr.io/v2/x/manifests/$tag\": dial tcp 140.82.121.33:443: i/o timeout" >&2
    exit 1
  fi
  while IFS='|' read -r ftag fdig; do
    [ -z "${ftag:-}" ] && continue
    [ "$ftag" = "$tag" ] && { echo "$fdig"; exit 0; }
  done < "${DOCKER_TAGS:-/dev/null}"
  # Real GHCR wording for an absent tag; the classifier keys on it.
  echo "ERROR: $ref: not found" >&2; exit 1
fi
if [ "${2:-}" = "imagetools" ] && [ "${3:-}" = "create" ]; then
  printf '%s\n' "$*" >> "${DOCKER_CREATES:-/dev/null}"
  # A create makes the tag resolvable from here on, which is what lets a test
  # drive "bind, then retry and adopt the binding" against one fixture.
  if [ -n "${DOCKER_TAGS:-}" ]; then
    newdig=""; t=""; want_tag=0
    for a in "$@"; do
      if [ "$want_tag" = 1 ]; then t="${a##*:}"; want_tag=0; continue; fi
      case "$a" in
        --tag) want_tag=1 ;;
        *@sha256:*) newdig="${a##*@}" ;;
      esac
    done
    [ -n "$newdig" ] && [ -n "$t" ] && printf '%s|%s\n' "$t" "$newdig" >> "$DOCKER_TAGS"
  fi
  exit 0
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
export PROMOTE_INSPECT_RETRY_DELAY=0
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

# ── immutable tags are WRITE-ONCE ───────────────────────────────────────────
# The image build is not reproducible over time (floating base, apk upgrade,
# month-keyed GeoIP URL), so a re-run of a published tag legitimately builds a
# different digest. Repointing X.Y.Z at it would serve different bytes under a
# released version while its published catalog still pins the old digest.
: > "$WORK/anc"
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n1.2.3|%s\n' "$DIG" "$DIG" "$DIG2" > "$WORK/tags"
: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
  bad "a published exact tag is never repointed to a rebuild" "it overwrote an already-published version tag"
else
  [ -s "$WORK/creates" ] && bad "a published exact tag is never repointed to a rebuild" "it promoted anyway" \
                         || ok "a published exact tag is never repointed to a rebuild"
fi

# Same digest ⇒ idempotent re-run: succeed, promote nothing new for that tag.
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n1.2.3|%s\n' "$DIG" "$DIG" "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1 \
   && ! grep -q -- "--tag ghcr.io/x:1.2.3" "$WORK/creates" \
   && grep -q -- "--tag ghcr.io/x:latest" "$WORK/creates"; then
  ok "an exact tag already at this digest is a clean no-op, floating still moves"
else bad "an exact tag already at this digest is a clean no-op, floating still moves" "creates=$(cat "$WORK/creates")"; fi

# An ABSENT exact tag is promoted normally (the control — a write-once rule that
# refused everything would pass the case above while shipping no releases).
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n' "$DIG" "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1 \
   && grep -q -- "--tag ghcr.io/x:1.2.3" "$WORK/creates"; then
  ok "an unpublished exact tag is still promoted"
else bad "an unpublished exact tag is still promoted" "creates=$(cat "$WORK/creates")"; fi

# ── an ambiguous registry answer is not proof the tag is free ────────────────
# Reading every failed `imagetools inspect` as "absent" makes a transient
# registry/auth/network fault indistinguishable from a free tag, and the very
# next step would repoint an already-published X.Y.Z at the rebuild — the
# overwrite the write-once rule exists to prevent (Codex review, PR #1441).
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n' "$DIG" "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if DOCKER_AMBIGUOUS_TAG=1.2.3 \
   RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
  bad "an ambiguous exact-tag lookup refuses" "it promoted on an inspect failure it could not classify"
else
  [ -s "$WORK/creates" ] && bad "an ambiguous exact-tag lookup refuses" "it still called imagetools create" \
                         || ok "an ambiguous exact-tag lookup refuses"
fi

# CONTROL: the refusal above must come from CLASSIFICATION, not from refusing
# every lookup. A floating-only promotion never inspects an exact tag, so an
# ambiguous exact-tag answer for a tag this run does not target is irrelevant
# and the promotion still happens.
: > "$WORK/creates"
if DOCKER_AMBIGUOUS_TAG=9.9.9 \
   RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1 \
   && grep -q -- "--tag ghcr.io/x:1.2.3" "$WORK/creates"; then
  ok "an ambiguous answer about an unrelated tag does not block promotion"
else bad "an ambiguous answer about an unrelated tag does not block promotion" "creates=$(cat "$WORK/creates")"; fi

# ── a rebuilt D2 can NEVER replace an already-promoted D1 ────────────────────
# Not even while the GitHub Release is still a Draft. A registry tag is public
# the instant it is written, so Draft is not a visibility boundary for GHCR and
# must not license a repoint. An earlier revision of this branch allowed exactly
# that; the owner correction reverses it, and retry safety comes from the
# candidate binding instead (see section 7).
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n1.2.3|%s\n' "$DIG" "$DIG" "$DIG2" > "$WORK/tags"
for st in draft published absent "" garbage; do
  : > "$WORK/creates"
  if RELEASE_DRAFT_STATE="$st" RELEASE_TAG=v1.2.3 CHANNEL_TIP_TAG=v1.2.3 \
     RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
       promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
    bad "a rebuilt digest never replaces a promoted exact tag (release=${st:-<unset>})" "it repointed a public version tag"
  else
    [ -s "$WORK/creates" ] && bad "a rebuilt digest never replaces a promoted exact tag (release=${st:-<unset>})" "it promoted anyway" \
                           || ok "a rebuilt digest never replaces a promoted exact tag (release=${st:-<unset>})"
  fi
done

# CONTROL: the refusal above is about a CHANGED digest, not about refusing every
# retry. Promoting the SAME digest again — which is what the candidate binding
# guarantees a retry does — must be a clean idempotent no-op.
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n1.2.3|%s\n' "$DIG" "$DIG" "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if RELEASE_TAG=v1.2.3 CHANNEL_TIP_TAG=v1.2.3 \
   RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="latest" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1 \
   && ! grep -q -- "--tag ghcr.io/x:1.2.3" "$WORK/creates"; then
  ok "retrying with the bound digest leaves the promoted alias untouched"
else bad "retrying with the bound digest leaves the promoted alias untouched" "creates=$(cat "$WORK/creates")"; fi

# PARTIAL PUBLICATION: one alias written, the other not. A retry on the same
# candidate must complete the missing one and leave the written one alone.
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n1.2.3|%s\n' "$DIG" "$DIG" "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if RELEASE_TAG=v1.2.3 CHANNEL_TIP_TAG=v1.2.3 \
   RELEASE_SHA=tipsha CHANNEL_TIP=tipsha IMMUTABLE_TAGS="1.2.3 v1.2.3" FLOATING_TAGS="" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1 \
   && grep -q -- "--tag ghcr.io/x:v1.2.3" "$WORK/creates" \
   && ! grep -q -- "--tag ghcr.io/x:1.2.3 " "$WORK/creates"; then
  ok "a partial promotion is completed, not redone"
else bad "a partial promotion is completed, not redone" "creates=$(cat "$WORK/creates")"; fi

# ── two tags on one commit: ownership is TAG identity, not commit ────────────
printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n' "$DIG" "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if RELEASE_SHA=samesha CHANNEL_TIP=samesha RELEASE_TAG=v1.2.3 CHANNEL_TIP_TAG=v1.2.4 \
     IMMUTABLE_TAGS="1.2.3" FLOATING_TAGS="1.2 1" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1; then
  if grep -q -- "--tag ghcr.io/x:1.2.3" "$WORK/creates" \
     && ! grep -q -- "--tag ghcr.io/x:1.2 " "$WORK/creates"; then
    ok "a lower tag sharing the tip's commit does not own the floating channels"
  else bad "a lower tag sharing the tip's commit does not own the floating channels" "creates=$(cat "$WORK/creates")"; fi
else bad "a lower tag sharing the tip's commit does not own the floating channels" "it failed instead of promoting its own version"; fi

: > "$WORK/creates"
if RELEASE_SHA=samesha CHANNEL_TIP=samesha RELEASE_TAG=v1.2.4 CHANNEL_TIP_TAG=v1.2.4 \
     IMMUTABLE_TAGS="1.2.4" FLOATING_TAGS="1.2 1" \
     promote ghcr.io/x "$DIG" candidate-99 >/dev/null 2>&1 \
   && grep -q -- "--tag ghcr.io/x:1.2 " "$WORK/creates"; then
  ok "the highest tag does own the floating channels"
else bad "the highest tag does own the floating channels" "creates=$(cat "$WORK/creates")"; fi

printf 'sha-3d8c9bb|%s\ncandidate-99|%s\n' "$DIG" "$DIG" > "$WORK/tags"

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

# ─── 7. a published release is write-once ────────────────────────────────────
# Every asset step stages with draft:true, and action-gh-release applies that to
# an EXISTING release — so a re-run of an already-published tag takes it offline
# and cannot put it back (the rebuild's digest is refused against the write-once
# exact image tag, so publish-release never runs). The guard must refuse BEFORE
# anything is mutated (Codex review, PR #1441).
relguard() { GH_BIN="$BIN/ghrel" bash "$SCRIPTS/assert-release-unpublished.sh" "$@"; }
cat > "$BIN/ghrel" <<'EOF'
#!/usr/bin/env bash
# Mock `gh api repos/<r>/releases/tags/<t> --jq .draft`.
#   REL_STATE=draft|published|absent|error
case "${REL_STATE:-absent}" in
  draft)     echo true ;;
  published) echo false ;;
  error)     echo "gh: Bad gateway (HTTP 502)" >&2; exit 1 ;;
  *)         echo "gh: Not Found (HTTP 404)" >&2; exit 1 ;;
esac
EOF
chmod +x "$BIN/ghrel"

if REL_STATE=absent relguard v1.2.3 >/dev/null 2>&1; then
  ok "a first run with no existing release proceeds"
else bad "a first run with no existing release proceeds" "the guard refused a release that does not exist yet"; fi

if REL_STATE=draft relguard v1.2.3 >/dev/null 2>&1; then
  ok "a re-run against a still-draft release proceeds"
else bad "a re-run against a still-draft release proceeds" "the guard blocked the recoverable re-run it exists to allow"; fi

if REL_STATE=published relguard v1.2.3 >/dev/null 2>&1; then
  bad "a re-run against a PUBLISHED release refuses" "the guard let a run re-draft a public release"
else ok "a re-run against a PUBLISHED release refuses"; fi

if REL_STATE=error relguard v1.2.3 >/dev/null 2>&1; then
  bad "an unreadable release state fails closed" "the guard treated an API error as 'no release exists'"
else ok "an unreadable release state fails closed"; fi

# The guard is about the GitHub Release ONLY. It must not hand promotion any
# licence to move a public registry tag — that hop existed briefly and was the
# mechanism of the draft-state exception the owner reversed.
: > "$WORK/ghout"
REL_STATE=draft GITHUB_OUTPUT="$WORK/ghout" relguard v1.2.3 >/dev/null 2>&1
if [ -s "$WORK/ghout" ]; then
  bad "the release guard exports no promotion licence" "it emitted $(cat "$WORK/ghout")"
else ok "the release guard exports no promotion licence"; fi

# ─── 7. the release candidate binding (retry recovery) ───────────────────────
# The pipeline's answer to "this build is not reproducible over time": bind the
# version to ONE digest before anything is published, and make every retry
# resume on it rather than re-decide.
candidate() { bash "$SCRIPTS/resolve-release-candidate.sh" "$@"; }
SHA_A="3d8c9bb1c62b45bf66d9018e6d9f112c107e5108"
SHA_B="beefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
: > "$WORK/labels"; export DOCKER_LABELS="$WORK/labels"

# First run: no binding yet ⇒ create it from this run's digest, and say so.
printf '%s|%s\n' "$DIG" "$SHA_A" > "$WORK/labels"
printf 'candidate-99|%s\n' "$DIG" > "$WORK/tags"
: > "$WORK/creates"; : > "$WORK/ghout"
if RELEASE_SHA="$SHA_A" GITHUB_OUTPUT="$WORK/ghout" \
     candidate ghcr.io/x v1.2.3 "$DIG" >/dev/null 2>&1 \
   && grep -qx "digest=$DIG" "$WORK/ghout" && grep -qx 'binding=created' "$WORK/ghout" \
   && grep -q -- "--tag ghcr.io/x:candidate-v1.2.3" "$WORK/creates"; then
  ok "a first run binds the version to the digest it built"
else bad "a first run binds the version to the digest it built" "out=$(cat "$WORK/ghout") creates=$(cat "$WORK/creates")"; fi

# THE RETRY. The rebuild produced DIG2; the binding still names DIG. The run
# must adopt DIG and discard its own bytes — this is what stops a retry from
# repointing public version tags.
printf '%s|%s\n%s|%s\n' "$DIG" "$SHA_A" "$DIG2" "$SHA_A" > "$WORK/labels"
printf 'candidate-99|%s\ncandidate-v1.2.3|%s\n' "$DIG2" "$DIG" > "$WORK/tags"
: > "$WORK/creates"; : > "$WORK/ghout"
if RELEASE_SHA="$SHA_A" GITHUB_OUTPUT="$WORK/ghout" \
     candidate ghcr.io/x v1.2.3 "$DIG2" >/dev/null 2>&1 \
   && grep -qx "digest=$DIG" "$WORK/ghout" && grep -qx 'binding=reused' "$WORK/ghout"; then
  if [ -s "$WORK/creates" ]; then
    bad "a retry reuses the bound candidate and rebinds nothing" "it wrote $(cat "$WORK/creates")"
  else ok "a retry reuses the bound candidate and rebinds nothing"; fi
else bad "a retry reuses the bound candidate and rebinds nothing" "out=$(cat "$WORK/ghout")"; fi

# WRONG SHA: a binding built from another commit must never drive publication.
printf '%s|%s\n%s|%s\n' "$DIG" "$SHA_B" "$DIG2" "$SHA_A" > "$WORK/labels"
printf 'candidate-99|%s\ncandidate-v1.2.3|%s\n' "$DIG2" "$DIG" > "$WORK/tags"
: > "$WORK/ghout"
if RELEASE_SHA="$SHA_A" GITHUB_OUTPUT="$WORK/ghout" \
     candidate ghcr.io/x v1.2.3 "$DIG2" >/dev/null 2>&1; then
  bad "a candidate built from another commit refuses" "it published a foreign commit's bytes under this tag"
else ok "a candidate built from another commit refuses"; fi

# MISSING provenance: no revision label at all ⇒ unverifiable ⇒ refuse.
: > "$WORK/labels"
printf 'candidate-99|%s\ncandidate-v1.2.3|%s\n' "$DIG2" "$DIG" > "$WORK/tags"
if RELEASE_SHA="$SHA_A" candidate ghcr.io/x v1.2.3 "$DIG2" >/dev/null 2>&1; then
  bad "a candidate with no source-commit provenance refuses" "it accepted an unverifiable binding"
else ok "a candidate with no source-commit provenance refuses"; fi

# AMBIGUOUS binding lookup: not proof the version is unbound.
printf '%s|%s\n' "$DIG" "$SHA_A" > "$WORK/labels"
printf 'candidate-99|%s\n' "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if DOCKER_AMBIGUOUS_TAG=candidate-v1.2.3 RELEASE_SHA="$SHA_A" \
     candidate ghcr.io/x v1.2.3 "$DIG" >/dev/null 2>&1; then
  bad "an unreadable binding refuses rather than rebinding" "it bound over an unreadable answer"
else
  [ -s "$WORK/creates" ] && bad "an unreadable binding refuses rather than rebinding" "it wrote $(cat "$WORK/creates")" \
                         || ok "an unreadable binding refuses rather than rebinding"
fi

# The registry must be proven reachable before a 404 counts as "unbound".
printf 'candidate-99|%s\n' "$DIG" > "$WORK/tags"
: > "$WORK/creates"
if DOCKER_AMBIGUOUS_TAG="${DIG#sha256:}" RELEASE_SHA="$SHA_A" \
     candidate ghcr.io/x v1.2.3 "$DIG" >/dev/null 2>&1; then
  bad "an unreachable registry refuses before binding" "it bound without proving the registry answers"
else
  [ -s "$WORK/creates" ] && bad "an unreachable registry refuses before binding" "it wrote $(cat "$WORK/creates")" \
                         || ok "an unreachable registry refuses before binding"
fi

# MAIN path: no version tag, so nothing is bound and this run's digest passes
# through. The control that the binding never leaks onto the main branch.
printf 'candidate-99|%s\n' "$DIG" > "$WORK/tags"
: > "$WORK/creates"; : > "$WORK/ghout"
if RELEASE_SHA="$SHA_A" GITHUB_OUTPUT="$WORK/ghout" \
     candidate ghcr.io/x "" "$DIG" >/dev/null 2>&1 \
   && grep -qx "digest=$DIG" "$WORK/ghout" && grep -qx 'binding=passthrough' "$WORK/ghout" \
   && [ ! -s "$WORK/creates" ]; then
  ok "the main path binds nothing and passes its own digest through"
else bad "the main path binds nothing and passes its own digest through" "out=$(cat "$WORK/ghout") creates=$(cat "$WORK/creates")"; fi

# A malformed digest never reaches the registry.
if RELEASE_SHA="$SHA_A" candidate ghcr.io/x v1.2.3 "sha256:nope" >/dev/null 2>&1; then
  bad "a malformed digest refuses before any registry write" "it accepted a malformed digest"
else ok "a malformed digest refuses before any registry write"; fi

# ── THE RETRY, WIRED AS ci.yml WIRES IT ──────────────────────────────────────
# The two scripts were each correct in isolation and the workflow handed the
# promoter the WRONG candidate reference, so the retry path they exist to
# provide did not work end to end (Codex review, PR #1441). A re-run keeps its
# run id, so the rebuild force-pushes D2 over `candidate-<run_id>` while the
# binding still names D1 — checking promotion against the run-scoped tag then
# compares D1 to D2 and refuses every retry.
#
# This case therefore does NOT hand the promoter a hand-picked tag: it takes the
# candidate reference from the resolver's own output, which is what the workflow
# now does. It fails against the previous wiring.
printf '%s|%s\n%s|%s\n' "$DIG" "$SHA_A" "$DIG2" "$SHA_A" > "$WORK/labels"
printf 'candidate-99|%s\ncandidate-v1.2.3|%s\n1.2.3|%s\n' "$DIG2" "$DIG" "$DIG" > "$WORK/tags"
: > "$WORK/creates"; : > "$WORK/ghout"
if RELEASE_SHA="$SHA_A" GITHUB_OUTPUT="$WORK/ghout" \
     candidate ghcr.io/x v1.2.3 "$DIG2" candidate-99 >/dev/null 2>&1; then
  BOUND_DIG="$(sed -n 's/^digest=//p' "$WORK/ghout")"
  BOUND_TAG="$(sed -n 's/^candidate_tag=//p' "$WORK/ghout")"
  : > "$WORK/creates"
  if [ "$BOUND_TAG" = "candidate-v1.2.3" ] \
     && RELEASE_TAG=v1.2.3 CHANNEL_TIP_TAG=v1.2.3 RELEASE_SHA=tipsha CHANNEL_TIP=tipsha \
        IMMUTABLE_TAGS="1.2.3 v1.2.3" FLOATING_TAGS="latest" \
          promote ghcr.io/x "$BOUND_DIG" "$BOUND_TAG" >/dev/null 2>&1 \
     && grep -q -- "--tag ghcr.io/x:v1.2.3" "$WORK/creates" \
     && grep -q -- "ghcr.io/x@$DIG" "$WORK/creates" \
     && ! grep -q -- "ghcr.io/x@$DIG2" "$WORK/creates"; then
    ok "a retry whose rebuild differs still completes promotion on the bound digest"
  else
    bad "a retry whose rebuild differs still completes promotion on the bound digest" \
        "candidate_tag=$BOUND_TAG digest=$BOUND_DIG creates=$(cat "$WORK/creates")"
  fi
else bad "a retry whose rebuild differs still completes promotion on the bound digest" "resolver refused: $(cat "$WORK/ghout")"; fi

# CONTROL: the emitted reference is not a constant. On the main path there is no
# binding, so the run-scoped tag IS the authority — emitting `candidate-v` there
# would hand the promoter a reference that does not exist.
printf 'candidate-99|%s\n' "$DIG" > "$WORK/tags"
: > "$WORK/ghout"
if RELEASE_SHA="$SHA_A" GITHUB_OUTPUT="$WORK/ghout" \
     candidate ghcr.io/x "" "$DIG" candidate-99 >/dev/null 2>&1 \
   && grep -qx 'candidate_tag=candidate-99' "$WORK/ghout"; then
  ok "the main path promotes against the run-scoped candidate"
else bad "the main path promotes against the run-scoped candidate" "out=$(cat "$WORK/ghout")"; fi

# ─── 8. the staged release is resolved DRAFT-AWARE ───────────────────────────
# `GET /releases/tags/<tag>` does not return drafts. Every reader in the chain
# used it while the chain staged everything on a draft, so each was blind to
# the release it was reasoning about. These cases pin the replacement.
# shellcheck source=.github/scripts/lib/release.sh
. "$SCRIPTS/lib/release.sh"

relfile() { printf '%s' "$1" > "$WORK/releases.json"; echo "$WORK/releases.json"; }

# The ordinary staged shape: one draft for this tag.
RELEASE_LIST_FILE="$(relfile '[{"id":11,"tag_name":"v1.2.3","draft":true}]')" \
  got="$(resolve_staged_release_id o/r v1.2.3 2>/dev/null)" || got=""
[ "$got" = "11" ] && ok "a staged draft is resolved by id" \
                  || bad "a staged draft is resolved by id" "got '$got'"

# THE v1.0.234 SHAPE: a draft holding the assets AND a stray published release
# carrying the same tag. The draft is the staged one; the by-tag endpoint would
# have returned the other.
RELEASE_LIST_FILE="$(relfile '[{"id":22,"tag_name":"v1.2.3","draft":false},{"id":33,"tag_name":"v1.2.3","draft":true}]')" \
  got="$(resolve_staged_release_id o/r v1.2.3 2>/dev/null)" || got=""
[ "$got" = "33" ] && ok "a draft wins over a stray published release on the same tag" \
                  || bad "a draft wins over a stray published release on the same tag" "got '$got' (want the draft, 33)"

# CONTROL: with no draft, a single published release is the answer — otherwise
# a re-run after publication could never resolve anything.
RELEASE_LIST_FILE="$(relfile '[{"id":44,"tag_name":"v1.2.3","draft":false}]')" \
  got="$(resolve_staged_release_id o/r v1.2.3 2>/dev/null)" || got=""
[ "$got" = "44" ] && ok "a published release resolves when no draft exists" \
                  || bad "a published release resolves when no draft exists" "got '$got'"

# Other tags are never borrowed.
RELEASE_LIST_FILE="$(relfile '[{"id":55,"tag_name":"v9.9.9","draft":true}]')" \
  got="$(resolve_staged_release_id o/r v1.2.3 2>/dev/null)" && rc=0 || rc=1
[ "$rc" -ne 0 ] && ok "another tag's draft is never resolved" \
                || bad "another tag's draft is never resolved" "got '$got'"

# Ambiguity refuses rather than guessing which draft holds the assets.
RELEASE_LIST_FILE="$(relfile '[{"id":66,"tag_name":"v1.2.3","draft":true},{"id":77,"tag_name":"v1.2.3","draft":true}]')" \
  got="$(resolve_staged_release_id o/r v1.2.3 2>/dev/null)" && rc=0 || rc=1
[ "$rc" -ne 0 ] && ok "two drafts for one tag refuse" \
                || bad "two drafts for one tag refuse" "picked '$got'"

# Nothing at all refuses.
RELEASE_LIST_FILE="$(relfile '[]')" \
  resolve_staged_release_id o/r v1.2.3 >/dev/null 2>&1 && rc=0 || rc=1
[ "$rc" -ne 0 ] && ok "no release for the tag refuses" \
                || bad "no release for the tag refuses" "it resolved something"

# assert-release-complete.sh must ASSERT THE STAGED RELEASE. Fed the draft's
# asset list it passes; fed the stray published release's it refuses — which is
# precisely the v1.0.234 failure, now attributable to the right object.
full=""
for n in culvert-linux-amd64 culvert-linux-arm64 culvert-darwin-amd64 culvert-darwin-arm64 culvert-windows-amd64.exe; do
  full="${full}${n} 100
${n}.sigstore.json 100
"
done
for n in culvert-maint-linux-amd64 culvert-maint-linux-arm64 culvert.sbom.cdx.json culvert-maint.sbom.cdx.json; do
  full="${full}${n} 100
${n}.sigstore.json 100
"
done
full="${full}culvert-release-catalog-v1.2.3.tar.gz 100
multiple.intoto.jsonl 100
"
printf '%s' "$full" > "$WORK/assets-full.txt"
if ASSERT_RELEASE_ASSETS_FILE="$WORK/assets-full.txt" \
     bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 >/dev/null 2>&1; then
  ok "a complete staged release passes the completeness assert"
else bad "a complete staged release passes the completeness assert" "$(ASSERT_RELEASE_ASSETS_FILE="$WORK/assets-full.txt" bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 2>&1 | tail -3)"; fi

printf 'multiple.intoto.jsonl 100\n' > "$WORK/assets-prov.txt"
if ASSERT_RELEASE_ASSETS_FILE="$WORK/assets-prov.txt" \
     bash "$SCRIPTS/assert-release-complete.sh" v1.2.3 >/dev/null 2>&1; then
  bad "a provenance-only release is refused" "it accepted a release with no binaries"
else ok "a provenance-only release is refused"; fi

unset DOCKER_LABELS

# ─── STAGE 2B: the release verdict is the CONJUNCTION, from QA's side ────────
#
# Stage 2B stops security-release-gate.yml running the race suite on a main
# push and leaves it to qa-gate.yml. Nothing about the predicate changes — but
# that is now load-bearing in a way it was not before, because a green Security
# run on main no longer carries any race evidence of its own. If QA's row could
# ever be satisfied by something other than a successful main-push run of
# qa-gate.yml for the EXACT release SHA, stage 2B would have moved race
# coverage out of the release verdict rather than out of Security.
#
# The cases above vary Security with QA green. These mirror them: Security is
# GREEN throughout and only QA moves, so each refusal is attributable to QA's
# row alone.
sec_green_qa() {  # $1..$n = extra fixture lines for qa-gate.yml (may be none)
  local lines=("security-release-gate.yml|$GREEN|push|main|completed|success")
  lines+=("install-lifecycle-e2e.yml|$GREEN|push|main|completed|success")
  local extra
  for extra in "$@"; do lines+=("$extra"); done
  fixture "${lines[@]}"
}

# QA absent entirely — the shape a "Security is green, ship it" mistake makes.
sec_green_qa
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "2B: Security green + QA ABSENT refuses" "predicate APPROVED with no QA evidence at all"
else ok "2B: Security green + QA ABSENT refuses"; fi

# QA present but not successful, including the SKIPPED shape — which is exactly
# what a QA run whose jobs were all skipped would look like.
for qa_concl in failure cancelled timed_out startup_failure stale skipped neutral; do
  sec_green_qa "qa-gate.yml|$GREEN|push|main|completed|$qa_concl"
  if predicate "$GREEN" assert >/dev/null 2>&1; then
    bad "2B: Security green + QA '$qa_concl' refuses" "predicate APPROVED a '$qa_concl' QA run"
  else ok "2B: Security green + QA '$qa_concl' refuses"; fi
done

# QA still running: assert mode must refuse now rather than assume it will pass.
sec_green_qa "qa-gate.yml|$GREEN|push|main|in_progress|null"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "2B: Security green + QA PENDING refuses in assert mode" "predicate APPROVED a still-running QA run"
else ok "2B: Security green + QA PENDING refuses in assert mode"; fi

# QA green — but for another commit. Race evidence must bind to the release SHA.
sec_green_qa "qa-gate.yml|$OTHER|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "2B: Security green + QA green for the WRONG SHA refuses" "predicate APPROVED using $OTHER's QA run"
else ok "2B: Security green + QA green for the WRONG SHA refuses"; fi

# QA green for this SHA, but from a tag-triggered re-run rather than the main
# push. qa-gate.yml has no tag trigger at all, so this cannot arise today —
# which is precisely why it is worth pinning: it is the shape a future tag
# trigger would introduce, and it must not authorise a release.
sec_green_qa "qa-gate.yml|$GREEN|push|refs/tags/v9.9.9|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "2B: Security green + QA green on a TAG ref refuses" "predicate APPROVED a non-main head_branch QA run"
else ok "2B: Security green + QA green on a TAG ref refuses"; fi

# QA green for this SHA on main, but from a workflow_dispatch rather than the
# push. Stage 2B validation dispatches QA on branches by design, so a dispatch
# run must never be mistaken for main-push evidence.
sec_green_qa "qa-gate.yml|$GREEN|workflow_dispatch|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  bad "2B: Security green + QA green from a DISPATCH refuses" "predicate APPROVED a workflow_dispatch QA run as push evidence"
else ok "2B: Security green + QA green from a DISPATCH refuses"; fi

# CONTROL. Every case above refuses; a predicate that simply always refused
# would pass all of them and block every release. Both green, both main-push,
# both this SHA must APPROVE.
sec_green_qa "qa-gate.yml|$GREEN|push|main|completed|success"
if predicate "$GREEN" assert >/dev/null 2>&1; then
  ok "2B: CONTROL both workflows green on the main push APPROVES"
else bad "2B: CONTROL both workflows green on the main push APPROVES" "predicate refused a fully valid conjunction"; fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
