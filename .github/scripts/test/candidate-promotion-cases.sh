#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate-promotion-cases.sh — behavioural tests for build-once promotion:
# the candidate plan on main, the candidate record, the tag-run resolution, the
# qualification checks and auto-tag's version decision — every state
# transition, against MOCKED registry / Sigstore / git / go.
#
# Mocks on PATH (nothing leaves this machine; no tag, image or release is made):
#   docker — tag→digest resolution (DOCKER_TAGS "tag|digest"), image indexes
#            (DOCKER_INDEX "<digest>|<platform>|<manifest digest>" rows), config
#            revision labels (DOCKER_LABELS "<digest>|<revision>"), per-platform
#            file contents for create/cp (DOCKER_FILES dir), and it RECORDS
#            every `imagetools create`.
#   cosign — `verify-attestation` answers only for a fixture row whose type,
#            digest AND certificate identity/ref/trigger/repository/sha all
#            match the flags cosign was given (COSIGN_ATT rows
#            "type|digest|identity|ref|trigger|repo|sha|statement-file").
#   git    — tags from GIT_TAGS ("tag|sha"); `push` appends, or fails with
#            GIT_PUSH_FAIL; GIT_PUSH_RACE makes the push fail AFTER another
#            writer created the tag (on GIT_PUSH_RACE's sha).
#   go     — `version -m <file>` prints the compiler/GOOS/GOARCH written into
#            the fake binary.
#
# Driven from Go by TestCandidatePromotion_Behaviour.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SCRIPTS="${REPO_ROOT}/.github/scripts"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()  { pass=$((pass+1)); printf '  PASS  %s\n' "$1"; }
bad() { fail=$((fail+1)); printf '  FAIL  %s\n     -> %s\n' "$1" "$2"; }

BIN="$WORK/bin"; mkdir -p "$BIN"

cat > "$BIN/docker" <<'EOF'
#!/usr/bin/env bash
# buildx imagetools inspect|create, pull, create, cp, rm, run, logs
if [ "$1 $2" = "buildx imagetools" ]; then
  sub="$3"; shift 3
  if [ "$sub" = "inspect" ]; then
    if [ "$1" = "--raw" ]; then
      ref="$2"; d="${ref##*@}"
      rows="$(grep "^${d}|" "${DOCKER_INDEX:-/dev/null}" || true)"
      [ -n "$rows" ] || { echo "ERROR: ${ref}: not found" >&2; exit 1; }
      printf '%s\n' "$rows" | jq -Rn '{mediaType:"application/vnd.oci.image.index.v1+json",
        manifests: ([inputs | split("|") | {digest: .[2], platform: {os: (.[1]|split("/")[0]), architecture: (.[1]|split("/")[1])}}]
          + [{digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
              platform: {os: "unknown", architecture: "unknown"},
              annotations: {"vnd.docker.reference.type": "attestation-manifest"}}])}'
      exit 0
    fi
    ref="$1"
    if [ "${3:-}" = "{{json .Image}}" ]; then
      d="${ref##*@}"
      rev="$(awk -F'|' -v d="$d" '$1 == d {print $2}' "${DOCKER_LABELS:-/dev/null}")"
      printf '{"linux/amd64":{"config":{"Labels":{"org.opencontainers.image.revision":"%s"}}},"linux/arm64":{"config":{"Labels":{"org.opencontainers.image.revision":"%s"}}}}\n' "$rev" "$rev"
      exit 0
    fi
    tag="${ref##*:}"
    if [ -n "${DOCKER_AMBIGUOUS:-}" ] && [ "$tag" = "$DOCKER_AMBIGUOUS" ]; then
      echo "ERROR: failed to do request: dial tcp: i/o timeout" >&2; exit 1
    fi
    case "$ref" in *@sha256:*) echo "${ref##*@}"; exit 0 ;; esac
    dig="$(awk -F'|' -v t="$tag" '$1 == t {d=$2} END {print d}' "${DOCKER_TAGS:-/dev/null}")"
    [ -n "$dig" ] && { echo "$dig"; exit 0; }
    echo "ERROR: ${ref}: not found" >&2; exit 1
  fi
  if [ "$sub" = "create" ]; then
    printf '%s\n' "$*" >> "${DOCKER_CREATES:-/dev/null}"
    t=""; src=""
    while [ $# -gt 0 ]; do
      case "$1" in --tag) t="${2##*:}"; shift ;; *@sha256:*) src="${1##*@}" ;; esac
      shift
    done
    [ -n "$t" ] && [ -n "$src" ] && [ -n "${DOCKER_TAGS:-}" ] && printf '%s|%s\n' "$t" "$src" >> "$DOCKER_TAGS"
    exit 0
  fi
fi
case "$1" in
  pull)
    printf '%s\n' "$*" >> "${DOCKER_PULLS:-/dev/null}"
    # Docker's classic image store (the runners' default) keeps ONE image per
    # digest reference: pulling another platform under a digest it already
    # holds fails. That is what broke main run 36111817278.
    plat=""; ref=""
    shift
    while [ $# -gt 0 ]; do
      case "$1" in --platform) plat="$2"; shift ;; --quiet) ;; *) ref="$1" ;; esac
      shift
    done
    case "$ref" in
      *@sha256:*)
        d="${ref##*@}"
        held="$(awk -F'|' -v d="$d" '$1 == d {print $2}' "${DOCKER_STORE:-/dev/null}" | head -n1)"
        if [ -n "$held" ] && [ "$held" != "$plat" ]; then echo "cannot overwrite digest ${d}" >&2; exit 1; fi
        [ -n "$held" ] || printf '%s|%s\n' "$d" "$plat" >> "${DOCKER_STORE:-/dev/null}" ;;
    esac
    exit 0 ;;
  run)
    # -d → the proxy container; --entrypoint …culvert-maint → the agent's -version.
    case " $* " in
      *" --entrypoint "*) printf '%s\n' "${RUN_AGENT_VERSION:-}"; exit 0 ;;
      *" -d "*) echo "cid-proxy"; exit 0 ;;
    esac; exit 0 ;;
  logs) exit 0 ;;
  create) for a in "$@"; do case "$a" in linux/*) echo "cid-${a#linux/}";; esac; done; exit 0 ;;
  cp) src="$2"; dst="$3"; cid="${src%%:*}"; f="${src#*:}"
      p="${cid#cid-}"; s="${DOCKER_FILES}/${p}/$(basename "$f")"
      [ -f "$s" ] || { echo "no such file $f" >&2; exit 1; }
      cp "$s" "$dst"; exit 0 ;;
  rm) exit 0 ;;
esac
exit 0
EOF

cat > "$BIN/cosign" <<'EOF'
#!/usr/bin/env bash
[ "$1" = "verify-attestation" ] || exit 0
shift
typ="" ident="" issuer="" repo="" ref="" trig="" sha="" target=""
while [ $# -gt 0 ]; do
  case "$1" in
    --type) typ="$2"; shift ;;
    --certificate-identity) ident="$2"; shift ;;
    --certificate-oidc-issuer) issuer="$2"; shift ;;
    --certificate-github-workflow-repository) repo="$2"; shift ;;
    --certificate-github-workflow-ref) ref="$2"; shift ;;
    --certificate-github-workflow-trigger) trig="$2"; shift ;;
    --certificate-github-workflow-sha) sha="$2"; shift ;;
    -*) echo "mock cosign: unexpected flag $1" >&2; exit 3 ;;
    *) target="$1" ;;
  esac
  shift
done
[ "${COSIGN_FAIL:-}" = "1" ] && { echo "Error: fetching bundles: dial tcp: i/o timeout" >&2; exit 1; }
[ "$issuer" = "https://token.actions.githubusercontent.com" ] || { echo "mock cosign: wrong issuer" >&2; exit 1; }
d="${target##*@}"; found=0
while IFS='|' read -r ft fd fi fr ftr frepo fsha ffile; do
  [ -n "${ft:-}" ] || continue
  [ "$ft" = "$typ" ] && [ "$fd" = "$d" ] && [ "$fi" = "$ident" ] && [ "$fr" = "$ref" ] \
    && [ "$ftr" = "$trig" ] && [ "$frepo" = "$repo" ] && [ "$fsha" = "$sha" ] || continue
  printf '{"payloadType":"application/vnd.in-toto+json","payload":"%s","signatures":[{}]}\n' "$(base64 -w0 < "$ffile")"
  found=1
done < "${COSIGN_ATT:-/dev/null}"
[ "$found" = 1 ] || { echo "Error: no matching attestations" >&2; exit 1; }
EOF

cat > "$BIN/git" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${GIT_CALLS:-/dev/null}"
case "$1" in
  fetch) [ "${GIT_FETCH_FAIL:-}" = "1" ] && exit 1; exit 0 ;;
  tag)
    shift
    case "$1" in
      --points-at) awk -F'|' -v s="$2" '$2 == s {print $1}' "$GIT_TAGS"; exit 0 ;;
      --list) cut -d'|' -f1 "$GIT_TAGS" | sort -t. -k1,1V -k2,2n -k3,3n -r | sort -rV; exit 0 ;;
      -a) printf '%s\n' "$2" > "$WORK_PENDING"; exit 0 ;;
      -d) exit 0 ;;
    esac ;;
  rev-list) t="${3#refs/tags/}"; awk -F'|' -v t="$t" '$1 == t {print $2}' "$GIT_TAGS" | grep . ; exit $? ;;
  push)
    t="${3#refs/tags/}"
    if [ -n "${GIT_PUSH_RACE:-}" ]; then printf '%s|%s\n' "$t" "$GIT_PUSH_RACE" >> "$GIT_TAGS"; exit 1; fi
    [ "${GIT_PUSH_FAIL:-}" = "1" ] && exit 1
    printf '%s|%s\n' "$t" "$PUSH_SHA" >> "$GIT_TAGS"; printf '%s\n' "$t" >> "${GIT_PUSHES:-/dev/null}"; exit 0 ;;
esac
exit 0
EOF

cat > "$BIN/go" <<'EOF'
#!/usr/bin/env bash
[ "$1 $2" = "version -m" ] || exit 2
# The fake binary holds "compiler goos goarch".
read -r cc os arch < "$3"
printf '%s: %s\n\tpath\tx\n\tbuild\tGOARCH=%s\n\tbuild\tGOOS=%s\n' "$3" "$cc" "$arch" "$os"
EOF
cat > "$BIN/curl" <<'EOF2'
#!/usr/bin/env bash
printf '{"status":"%s","uptime":"1s","version":"%s"}' "${RUN_HEALTH_STATUS:-ok}" "${RUN_PROXY_VERSION:-}"
EOF2
chmod +x "$BIN"/*
export PATH="$BIN:$PATH"
export PROMOTE_INSPECT_RETRY_DELAY=0 WORK_PENDING="$WORK/pending"
unset GITHUB_STEP_SUMMARY GITHUB_OUTPUT RELEASE_REBUILD_AUTHORIZED_TAG || true

# shellcheck source=.github/scripts/lib/candidate.sh
. "$SCRIPTS/lib/candidate.sh"
IMG="ghcr.io/kidcarmi/culvert"
SHA="$(printf 'a%.0s' $(seq 40))"; OLD="$(printf 'b%.0s' $(seq 40))"; OTHER="$(printf 'c%.0s' $(seq 40))"
h64() { printf "$1%.0s" $(seq 64); }
D1="sha256:$(h64 1)"; D2="sha256:$(h64 2)"; LATEST="sha256:$(h64 9)"
A1="sha256:$(h64 3)"; R1="sha256:$(h64 4)"; A2="sha256:$(h64 5)"; R2="sha256:$(h64 6)"
TAG_ID="https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/tags/v1.0.5"

reset() {
  : > "$WORK/tags"; : > "$WORK/index"; : > "$WORK/labels"; : > "$WORK/att"; : > "$WORK/creates"
  : > "$WORK/gittags"; : > "$WORK/pushes"; : > "$WORK/gitcalls"; : > "$WORK/out"; : > "$WORK/store"
  export DOCKER_STORE="$WORK/store"
  export DOCKER_TAGS="$WORK/tags" DOCKER_INDEX="$WORK/index" DOCKER_LABELS="$WORK/labels" \
    DOCKER_CREATES="$WORK/creates" COSIGN_ATT="$WORK/att" GIT_TAGS="$WORK/gittags" \
    GIT_PUSHES="$WORK/pushes" GIT_CALLS="$WORK/gitcalls" GITHUB_OUTPUT="$WORK/out"
  unset DOCKER_AMBIGUOUS COSIGN_FAIL GIT_FETCH_FAIL GIT_PUSH_FAIL GIT_PUSH_RACE RELEASE_REBUILD_AUTHORIZED_TAG || true
  printf 'latest|%s\n' "$LATEST" >> "$WORK/tags"
}
out() { sed -n "s/^$1=//p" "$WORK/out" | tail -n1; }
index() { # index <digest> [platforms…] — default both required platforms
  local d="$1"; shift
  local ps=("$@"); [ "${#ps[@]}" -gt 0 ] || ps=(linux/amd64 linux/arm64)
  for p in "${ps[@]}"; do
    case "$p" in linux/amd64) m="$A1";; linux/arm64) m="$R1";; *) m="$A2";; esac
    [ "$d" = "$D2" ] && { [ "$p" = linux/amd64 ] && m="$A2"; [ "$p" = linux/arm64 ] && m="$R2"; }
    printf '%s|%s|%s\n' "$d" "$p" "$m" >> "$WORK/index"
  done
}
live_json() { # platforms json for digest $1 (both platforms)
  if [ "$1" = "$D2" ]; then printf '{"linux/amd64":"%s","linux/arm64":"%s"}' "$A2" "$R2"
  else printf '{"linux/amd64":"%s","linux/arm64":"%s"}' "$A1" "$R1"; fi
}
statement() { # statement <file> <type> <digest> <predicate-json>
  jq -n --arg t "$2" --arg d "${3#sha256:}" --argjson p "$4" \
    '{_type:"https://in-toto.io/Statement/v1", subject:[{name:"ghcr.io/kidcarmi/culvert", digest:{sha256:$d}}], predicateType:$t, predicate:$p}' > "$1"
}
record_pred() { # record_pred <digest> <sha> <version> [platforms-json]
  jq -n --arg d "$1" --arg s "$2" --arg v "$3" --argjson pl "${4:-$(live_json "$1")}" --arg img "$IMG" \
    '{schema:"culvert.release-candidate/v1", repository:"KidCarmi/Culvert", workflow:".github/workflows/ci.yml",
      ref:"refs/heads/main", event:"push", source_sha:$s, version:$v, image:$img, index_digest:$d,
      platforms:$pl, producer:{run_id:"111", run_attempt:"1", job:"docker"},
      build_inputs:{go_toolchain:"go1.26.8", builder_image:"golang:1.26.8-alpine@sha256:x"}}'
}
qual_pred() { # qual_pred <digest> <sha> <version> [result]
  jq -n --arg d "$1" --arg s "$2" --arg v "$3" --arg r "${4:-pass}" --argjson pl "$(live_json "$1")" \
    '{schema:"culvert.release-candidate-qualification/v1", result:$r, source_sha:$s, version:$v,
      index_digest:$d, platforms:$pl, producer:{run_id:"111", run_attempt:"1"}, checks:["platforms"]}'
}
attest() { # attest <type> <digest> <sha> <predicate-json> [identity] [subject-digest]
  local f; f="$(mktemp -p "$WORK")"
  statement "$f" "$1" "${6:-$2}" "$4"
  printf '%s|%s|%s|%s|%s|%s|%s|%s\n' "$1" "$2" "${5:-$CANDIDATE_IDENTITY}" "$CANDIDATE_REF" push "$CANDIDATE_REPOSITORY" "$3" "$f" >> "$WORK/att"
}
main_candidate() { # main_candidate <digest> <sha> <version> — pointer + record + qualification
  index "$1"; printf '%s|%s\n' "$1" "$2" >> "$WORK/labels"
  printf 'candidate-commit-%s|%s\n' "$2" "$1" >> "$WORK/tags"
  attest "$CANDIDATE_RECORD_TYPE" "$1" "$2" "$(record_pred "$1" "$2" "$3")"
  attest "$CANDIDATE_QUALIFICATION_TYPE" "$1" "$2" "$(qual_pred "$1" "$2" "$3")"
}
plan_main() { bash "$SCRIPTS/candidate-plan-main.sh" "$IMG" "$@" >"$WORK/log" 2>&1; }
plan_tag() { bash "$SCRIPTS/candidate-plan-tag.sh" "$IMG" "$@" >"$WORK/log" 2>&1; }
log_has() { grep -q -- "$1" "$WORK/log"; }
# refused <name> <reason> <cmd…> — the command must FAIL, and for the stated
# reason. Checking the reason is what stops a refusal for an unrelated fault (a
# broken seam, a missing variable) from passing as the behaviour under test.
refused() {
  local name="$1" why="$2"; shift 2
  if "$@" >"$WORK/log" 2>&1; then bad "$name" "it succeeded"
  elif grep -q -- "$why" "$WORK/log"; then ok "$name"
  else bad "$name" "refused, but not because '${why}': $(tr '\n' ' ' < "$WORK/log")"; fi
}

echo "── candidate-plan-main.sh ──"
reset; printf 'v1.0.3|%s\nv1.0.4|%s\n' "$OLD" "$OTHER" >> "$WORK/gittags"
if plan_main "$SHA" && [ "$(out mode)" = build ] && [ "$(out version)" = v1.0.5 ] && [ "$(out version_source)" = next-patch ]; then
  ok "a new commit builds and decides the next patch version"
else bad "a new commit builds and decides the next patch version" "$(cat "$WORK/log") | mode=$(out mode) version=$(out version)"; fi

reset; printf 'v1.0.3|%s\nv1.0.4|%s\n' "$SHA" "$OTHER" >> "$WORK/gittags"
if plan_main "$SHA" && [ "$(out mode)" = build ] && [ "$(out version)" = v1.0.3 ]; then
  ok "a commit that is already tagged keeps its version when its candidate must be rebuilt"
else bad "a commit that is already tagged keeps its version when its candidate must be rebuilt" "version=$(out version) $(cat "$WORK/log")"; fi

reset; main_candidate "$D1" "$SHA" v1.0.5; printf 'v1.0.4|%s\n' "$OTHER" >> "$WORK/gittags"
if plan_main "$SHA" && [ "$(out mode)" = reuse ] && [ "$(out digest)" = "$D1" ] && [ "$(out version)" = v1.0.5 ] && [ ! -s "$WORK/creates" ]; then
  ok "a retry reuses the commit's verified candidate and its version — no rebuild"
else bad "a retry reuses the commit's verified candidate and its version — no rebuild" "mode=$(out mode) $(cat "$WORK/log")"; fi

reset; index "$D1"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
if plan_main "$SHA"; then bad "a pointer without a verifiable record refuses (no rebuild)" "planned $(out mode)"
elif [ -z "$(out mode)" ] && log_has "deletes"; then ok "a pointer without a verifiable record refuses (no rebuild)"
else bad "a pointer without a verifiable record refuses (no rebuild)" "$(cat "$WORK/log")"; fi

reset; index "$D1"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$OTHER" "$(record_pred "$D1" "$OTHER" v1.0.5)"
refused "a record signed for another commit is not this commit's candidate" "no attestation of type" plan_main "$SHA"

reset; index "$D1" linux/amd64; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$SHA" "$(record_pred "$D1" "$SHA" v1.0.5)"
if plan_main "$SHA"; then bad "a record whose platforms differ from the live index refuses" "reused it"
elif log_has "differ from the live index"; then ok "a record whose platforms differ from the live index refuses"
else bad "a record whose platforms differ from the live index refuses" "$(cat "$WORK/log")"; fi

reset; export DOCKER_AMBIGUOUS="candidate-commit-${SHA}"
if plan_main "$SHA"; then bad "an unreadable pointer is not an absent one" "planned $(out mode)"
elif log_has "did not answer"; then ok "an unreadable pointer is not an absent one"
else bad "an unreadable pointer is not an absent one" "$(cat "$WORK/log")"; fi

reset; printf 'v1.0.3|%s\nv2.0.0|%s\n' "$SHA" "$SHA" >> "$WORK/gittags"
refused "a commit carrying two versions refuses" "carries 2 version tags" plan_main "$SHA"

reset
refused "a short SHA is never a candidate identity" "not a full 40-hex commit" plan_main "${SHA:0:7}"

reset; main_candidate "$D1" "$SHA" v1.0.5; printf 'v1.0.6|%s\n' "$SHA" >> "$WORK/gittags"
refused "a candidate whose version disagrees with the commit's tag refuses" "but the commit is tagged v1.0.6" plan_main "$SHA"

echo "── candidate-record.sh ──"
reset; index "$D1"
rec_env() { env GITHUB_REPOSITORY=KidCarmi/Culvert GITHUB_EVENT_NAME="${EV:-push}" GITHUB_REF=refs/heads/main \
  GITHUB_WORKFLOW_REF="KidCarmi/Culvert/.github/workflows/ci.yml@refs/heads/main" GITHUB_SHA="$SHA" \
  GITHUB_RUN_ID=222 GITHUB_RUN_ATTEMPT=2 GITHUB_JOB=docker "$@"; }
if rec_env bash "$SCRIPTS/candidate-record.sh" record "$IMG" "$D1" "$SHA" v1.0.5 "$WORK/pred.json" >"$WORK/log" 2>&1 \
   && jq -e --arg s "$SHA" --arg d "$D1" --argjson pl "$(live_json "$D1")" '
        .source_sha == $s and .index_digest == $d and .version == "v1.0.5" and .platforms == $pl
        and .repository == "KidCarmi/Culvert" and .workflow == ".github/workflows/ci.yml" and .event == "push"
        and .ref == "refs/heads/main" and .producer.run_id == "222" and .producer.run_attempt == "2"
        and (.build_inputs.go_toolchain | startswith("go1.")) and (.build_inputs.builder_image | test("^golang:.*@sha256:"))
        and (.build_inputs.dockerfile_sha256 | length) == 64' "$WORK/pred.json" >/dev/null; then
  ok "the candidate record binds commit, workflow, event, run/attempt, version, index + platform digests and build inputs"
else bad "the candidate record binds commit, workflow, event, run/attempt, version, index + platform digests and build inputs" "$(cat "$WORK/log"; cat "$WORK/pred.json" 2>/dev/null)"; fi

EV=workflow_dispatch refused "only a main push may record a candidate" "is not a push" \
  rec_env bash "$SCRIPTS/candidate-record.sh" record "$IMG" "$D1" "$SHA" v1.0.5 "$WORK/p2.json"

reset; index "$D1" linux/amd64
if rec_env bash "$SCRIPTS/candidate-record.sh" record "$IMG" "$D1" "$SHA" v1.0.5 "$WORK/p3.json" >"$WORK/log" 2>&1; then
  bad "a candidate missing a platform is never recorded" "recorded"
elif log_has "linux/arm64"; then ok "a candidate missing a platform is never recorded"
else bad "a candidate missing a platform is never recorded" "$(cat "$WORK/log")"; fi

reset; index "$D1"
if rec_env bash "$SCRIPTS/candidate-record.sh" point "$IMG" "$D1" "$SHA" >"$WORK/log" 2>&1 \
   && grep -q -- "--tag ${IMG}:candidate-commit-${SHA} ${IMG}@${D1}" "$WORK/creates"; then
  ok "the pointer is written to the recorded digest and read back"
else bad "the pointer is written to the recorded digest and read back" "$(cat "$WORK/log")"; fi

echo "── candidate-plan-tag.sh ──"
reset; main_candidate "$D1" "$SHA" v1.0.5
if plan_tag v1.0.5 "$SHA" && [ "$(out source)" = main-candidate ] && [ "$(out digest)" = "$D1" ] && [ "$(out build)" = false ]; then
  ok "handoff: the tag run reuses the qualified main candidate"
else bad "handoff: the tag run reuses the qualified main candidate" "source=$(out source) $(cat "$WORK/log")"; fi

reset; main_candidate "$D1" "$SHA" v1.0.5; index "$D2"; printf 'candidate-v1.0.5|%s\n' "$D2" >> "$WORK/tags"
if plan_tag v1.0.5 "$SHA" && [ "$(out source)" = binding ] && [ "$(out digest)" = "$D2" ]; then
  ok "retry / partial publication: an existing version binding wins over everything"
else bad "retry / partial publication: an existing version binding wins over everything" "source=$(out source) $(cat "$WORK/log")"; fi

reset; printf 'candidate-v1.0.5|%s\n' "$D2" >> "$WORK/tags"; export RELEASE_REBUILD_AUTHORIZED_TAG=v1.0.5
if plan_tag v1.0.5 "$SHA" && [ "$(out source)" = binding ] && [ "$(out build)" = false ]; then
  ok "an authorized rebuild never replaces bytes already bound to the version"
else bad "an authorized rebuild never replaces bytes already bound to the version" "source=$(out source)"; fi

reset; printf '1.0.5|%s\nv1.0.5|%s\n' "$D2" "$D2" >> "$WORK/tags"; main_candidate "$D1" "$SHA" v1.0.5
if plan_tag v1.0.5 "$SHA" && [ "$(out source)" = published ] && [ "$(out digest)" = "$D2" ]; then
  ok "an already-published exact version is adopted, never replaced"
else bad "an already-published exact version is adopted, never replaced" "source=$(out source)"; fi

reset; printf '1.0.5|%s\nv1.0.5|%s\n' "$D1" "$D2" >> "$WORK/tags"
refused "exact aliases on two digests refuse" "resolve to different digests" plan_tag v1.0.5 "$SHA"

reset; main_candidate "$D1" "$SHA" v1.0.5
if plan_tag v2.0.0 "$SHA"; then bad "manual tag: a candidate built as another version refuses" "adopted"
elif log_has "was built as v1.0.5" && log_has "RELEASE_REBUILD_AUTHORIZED_TAG=v2.0.0"; then ok "manual tag: a candidate built as another version refuses, naming the recovery"
else bad "manual tag: a candidate built as another version refuses, naming the recovery" "$(cat "$WORK/log")"; fi

reset; main_candidate "$D1" "$SHA" v1.0.5; export RELEASE_REBUILD_AUTHORIZED_TAG=v2.0.0
if plan_tag v2.0.0 "$SHA" && [ "$(out source)" = rebuild ] && [ "$(out build)" = true ]; then
  ok "manual tag: an owner-authorized rebuild for that exact tag builds"
else bad "manual tag: an owner-authorized rebuild for that exact tag builds" "source=$(out source)"; fi

reset; export RELEASE_REBUILD_AUTHORIZED_TAG=v9.9.9
refused "an authorization for another tag authorizes nothing" "no main-push candidate exists" plan_tag v1.0.5 "$SHA"

reset
if plan_tag v1.0.5 "$SHA"; then bad "pre-rollout tag with no candidate refuses (no silent rebuild)" "planned $(out source)"
elif log_has "no main-push candidate exists"; then ok "pre-rollout tag with no candidate refuses (no silent rebuild)"
else bad "pre-rollout tag with no candidate refuses (no silent rebuild)" "$(cat "$WORK/log")"; fi

reset; index "$D1"; printf '%s|%s\n' "$D1" "$SHA" >> "$WORK/labels"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$SHA" "$(record_pred "$D1" "$SHA" v1.0.5)"
if plan_tag v1.0.5 "$SHA"; then bad "failed/absent qualification: an unqualified candidate is never released" "adopted"
elif log_has "never qualified"; then ok "failed/absent qualification: an unqualified candidate is never released"
else bad "failed/absent qualification: an unqualified candidate is never released" "$(cat "$WORK/log")"; fi

reset; index "$D1"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$SHA" "$(record_pred "$D1" "$SHA" v1.0.5)"
attest "$CANDIDATE_QUALIFICATION_TYPE" "$D1" "$SHA" "$(qual_pred "$D1" "$SHA" v1.0.5 fail)"
refused "a failing qualification record does not qualify" "no passing qualification record" plan_tag v1.0.5 "$SHA"

reset; index "$D1"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$SHA" "$(record_pred "$D1" "$SHA" v1.0.5)"
attest "$CANDIDATE_QUALIFICATION_TYPE" "$D1" "$SHA" "$(qual_pred "$D2" "$SHA" v1.0.5)"
refused "a qualification of another digest does not qualify this one" "no passing qualification record" plan_tag v1.0.5 "$SHA"

reset; index "$D1"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$SHA" "$(record_pred "$D1" "$SHA" v1.0.5)" "$TAG_ID"
attest "$CANDIDATE_QUALIFICATION_TYPE" "$D1" "$SHA" "$(qual_pred "$D1" "$SHA" v1.0.5)" "$TAG_ID"
refused "wrong identity: records signed by anything but ci.yml on main are ignored" "no attestation of type" plan_tag v1.0.5 "$SHA"

reset; index "$D1"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$SHA" "$(record_pred "$D1" "$SHA" v1.0.5)" "" "$D2"
attest "$CANDIDATE_QUALIFICATION_TYPE" "$D1" "$SHA" "$(qual_pred "$D1" "$SHA" v1.0.5)"
refused "wrong digest: a record whose subject is another digest is ignored" "none names" plan_tag v1.0.5 "$SHA"

reset; index "$D1"; printf 'candidate-commit-%s|%s\n' "$SHA" "$D1" >> "$WORK/tags"
attest "$CANDIDATE_RECORD_TYPE" "$D1" "$SHA" "$(record_pred "$D2" "$SHA" v1.0.5)"
attest "$CANDIDATE_QUALIFICATION_TYPE" "$D1" "$SHA" "$(qual_pred "$D1" "$SHA" v1.0.5)"
refused "wrong digest: a record naming another index refuses" "record names index" plan_tag v1.0.5 "$SHA"

reset; main_candidate "$D1" "$SHA" v1.0.5; : > "$WORK/index"; index "$D1" linux/amd64
if plan_tag v1.0.5 "$SHA"; then bad "missing platform: an index without arm64 is not releasable" "adopted"
elif log_has "missing required platforms"; then ok "missing platform: an index without arm64 is not releasable"
else bad "missing platform: an index without arm64 is not releasable" "$(cat "$WORK/log")"; fi

reset; main_candidate "$D1" "$SHA" v1.0.5; export COSIGN_FAIL=1
refused "unavailable evidence: Sigstore unreachable refuses" "no attestation of type" plan_tag v1.0.5 "$SHA"

reset; main_candidate "$D1" "$SHA" v1.0.5; export DOCKER_AMBIGUOUS="candidate-v1.0.5" RELEASE_REBUILD_AUTHORIZED_TAG=v1.0.5
refused "an unreadable binding refuses even when a rebuild is authorized" "did not answer" plan_tag v1.0.5 "$SHA"

reset; main_candidate "$D1" "$OLD" v1.0.5
refused "superseded: another commit's candidate is never this tag's" "no main-push candidate exists" plan_tag v1.0.5 "$SHA"

echo "── candidate-verify-contents.sh ──"
contents() { # contents <amd64 compiler> <arm64 compiler> <arm64 goarch> <version file>
  mkdir -p "$WORK/files/amd64" "$WORK/files/arm64"
  for f in culvert culvert-maint; do
    printf '%s linux amd64\n' "$1" > "$WORK/files/amd64/$f"
    printf '%s linux %s\n' "$2" "$3" > "$WORK/files/arm64/$f"
  done
  printf '%s\n' "$4" > "$WORK/files/amd64/VERSION"; printf '%s\n' "$4" > "$WORK/files/arm64/VERSION"
  export DOCKER_FILES="$WORK/files"
}
verify() { bash "$SCRIPTS/candidate-verify-contents.sh" "$IMG" "$D1" "$SHA" v1.0.5 go1.26.8 >"$WORK/log" 2>&1; }
reset; index "$D1"; printf '%s|%s\n' "$D1" "$SHA" >> "$WORK/labels"; contents go1.26.8 go1.26.8 arm64 v1.0.5
if verify; then ok "a correct candidate verifies on both platforms"; else bad "a correct candidate verifies on both platforms" "$(cat "$WORK/log")"; fi
contents go1.26.8 go1.27.1 arm64 v1.0.5
if verify; then bad "an arm64 binary from another compiler fails qualification" "passed"
elif log_has "go1.27.1"; then ok "an arm64 binary from another compiler fails qualification"
else bad "an arm64 binary from another compiler fails qualification" "$(cat "$WORK/log")"; fi
contents go1.26.8 go1.26.8 amd64 v1.0.5
refused "an amd64 binary inside the arm64 image fails qualification" "GOARCH=amd64" verify
contents go1.26.8 go1.26.8 arm64 v1.0.4
refused "a wrong embedded version file fails qualification" "/app/VERSION says" verify
contents go1.26.8 go1.26.8 arm64 v1.0.5; : > "$WORK/labels"; printf '%s|%s\n' "$D1" "$OTHER" >> "$WORK/labels"
refused "a candidate built from another commit fails qualification" "names revision" verify
: > "$WORK/labels"; printf '%s|%s\n' "$D1" "$SHA" >> "$WORK/labels"; : > "$WORK/index"; index "$D1" linux/amd64
refused "a candidate missing a platform fails qualification" "want exactly 1" verify

echo "── candidate-run-check.sh ──"
runcheck() { RUN_CHECK_TRIES=2 RUN_CHECK_DELAY=0 DOCKER_PULLS="$WORK/pulls" bash "$SCRIPTS/candidate-run-check.sh" "$IMG" "$D1" v1.0.5 linux/arm64 >"$WORK/log" 2>&1; }
reset; index "$D1"; : > "$WORK/pulls"; export RUN_AGENT_VERSION=v1.0.5 RUN_PROXY_VERSION=v1.0.5
if runcheck && grep -q -- "--platform linux/arm64 ${IMG}@${R1}" "$WORK/pulls"; then
  ok "the running candidate reports its version on the platform it was pulled for, by that platform's digest"
else bad "the running candidate reports its version on the platform it was pulled for, by that platform's digest" "$(cat "$WORK/log")"; fi
export RUN_AGENT_VERSION=v1.0.4
refused "a running agent reporting another version fails qualification" "culvert-maint -version reports 'v1.0.4'" runcheck
export RUN_AGENT_VERSION=v1.0.5 RUN_PROXY_VERSION=dev
refused "a running proxy reporting another version fails qualification" "reports version 'dev'" runcheck
export RUN_PROXY_VERSION=v1.0.5 RUN_HEALTH_STATUS=degraded
refused "a proxy that is not healthy fails qualification" "status 'degraded'" runcheck
unset RUN_AGENT_VERSION RUN_PROXY_VERSION RUN_HEALTH_STATUS
reset; : > "$WORK/index"; index "$D1" linux/amd64; export RUN_AGENT_VERSION=v1.0.5 RUN_PROXY_VERSION=v1.0.5
refused "a platform missing from the index is never run" "no single manifest digest" runcheck
unset RUN_AGENT_VERSION RUN_PROXY_VERSION

echo "── the qualification sequence on one image store ──"
# qualify-candidate pulls every platform of ONE index on ONE runner: contents
# (amd64, arm64), execution (amd64, arm64), then the compose smoke (amd64).
# Against a store that keeps one image per digest reference this sequence
# failed on main run 36111817278 ("cannot overwrite digest").
qualify_sequence() {
  bash "$SCRIPTS/candidate-verify-contents.sh" "$IMG" "$D1" "$SHA" v1.0.5 go1.26.8 &&
  RUN_CHECK_TRIES=2 RUN_CHECK_DELAY=0 bash "$SCRIPTS/candidate-run-check.sh" "$IMG" "$D1" v1.0.5 linux/amd64 &&
  RUN_CHECK_TRIES=2 RUN_CHECK_DELAY=0 bash "$SCRIPTS/candidate-run-check.sh" "$IMG" "$D1" v1.0.5 linux/arm64 &&
  ref="$(bash "$SCRIPTS/candidate-platform-ref.sh" "$IMG" "$D1" linux/amd64)" &&
  [ "$ref" = "${IMG}@${A1}" ] && "$BIN/docker" pull --platform linux/amd64 "$ref"
}
reset; index "$D1"; printf '%s|%s\n' "$D1" "$SHA" >> "$WORK/labels"; contents go1.26.8 go1.26.8 arm64 v1.0.5
export RUN_AGENT_VERSION=v1.0.5 RUN_PROXY_VERSION=v1.0.5
if qualify_sequence >"$WORK/log" 2>&1 && ! grep -q "@${D1}|" "$WORK/store"; then
  ok "every platform is pulled by its own manifest digest, so one store holds them all"
else bad "every platform is pulled by its own manifest digest, so one store holds them all" "$(tr '\n' ' ' < "$WORK/log") store: $(tr '\n' ' ' < "$WORK/store")"; fi
: > "$WORK/store"; "$BIN/docker" pull --platform linux/amd64 "${IMG}@${D1}" >/dev/null
refused "the store model refuses a second platform under one index digest (the main-run failure)" "cannot overwrite digest" \
  "$BIN/docker" pull --platform linux/arm64 "${IMG}@${D1}"
: > "$WORK/index"; index "$D1" linux/amd64
refused "the platform reference refuses a platform the index lacks" "no single manifest digest" \
  bash "$SCRIPTS/candidate-platform-ref.sh" "$IMG" "$D1" linux/arm64
unset RUN_AGENT_VERSION RUN_PROXY_VERSION

echo "── decide-release-version.sh ──"
decide() { PUSH_SHA="$SHA" bash "$SCRIPTS/decide-release-version.sh" "$SHA" "$@" >"$WORK/log" 2>&1; }
reset; printf 'v1.0.4|%s\n' "$OTHER" >> "$WORK/gittags"
if decide v1.0.5 && [ "$(out tagged)" = created ] && grep -qx v1.0.5 "$WORK/pushes"; then
  ok "auto-tag tags the candidate's own version"
else bad "auto-tag tags the candidate's own version" "$(cat "$WORK/log")"; fi

reset; printf 'v1.0.5|%s\n' "$SHA" >> "$WORK/gittags"
if decide v1.0.5 && [ "$(out tagged)" = existing ] && [ ! -s "$WORK/pushes" ]; then
  ok "a retry after the tag landed is a no-op"
else bad "a retry after the tag landed is a no-op" "$(cat "$WORK/log")"; fi

reset; printf 'v1.0.5|%s\n' "$OTHER" >> "$WORK/gittags"
if decide v1.0.5; then bad "a version taken by another commit refuses" "tagged"
elif [ ! -s "$WORK/pushes" ] && log_has "is taken"; then ok "a version taken by another commit refuses"
else bad "a version taken by another commit refuses" "$(cat "$WORK/log")"; fi

reset; printf 'v1.0.4|%s\n' "$SHA" >> "$WORK/gittags"
refused "one version per commit" "One version per commit" decide v1.0.5

reset; printf 'v1.0.6|%s\n' "$OTHER" >> "$WORK/gittags"
if decide v1.0.5; then bad "a superseded candidate is not tagged below the current release" "tagged"
elif log_has "overtaken"; then ok "a superseded candidate is not tagged below the current release"
else bad "a superseded candidate is not tagged below the current release" "$(cat "$WORK/log")"; fi

reset; export GIT_PUSH_RACE="$SHA"
if decide v1.0.5 && [ "$(out tagged)" = existing ]; then ok "a concurrent writer of the SAME tag on the SAME commit is success"
else bad "a concurrent writer of the SAME tag on the SAME commit is success" "$(cat "$WORK/log")"; fi

reset; export GIT_PUSH_RACE="$OTHER"
refused "a concurrent writer of the same tag on ANOTHER commit refuses" "is taken" decide v1.0.5

reset; export GIT_FETCH_FAIL=1
refused "an unreadable remote refuses to decide" "cannot read tags" decide v1.0.5

reset
refused "a malformed version refuses" "is not vX.Y.Z" decide 1.0.5

echo
echo "candidate-promotion cases: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
