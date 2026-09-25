#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# candidate.sh — the release CANDIDATE's identity: one image, built once on a
# main push, reused by the tag run that releases it.
#
# Sourced, never executed. Consumers: candidate-plan-main.sh,
# candidate-record.sh, candidate-plan-tag.sh, candidate-verify-contents.sh.
#
# ── What a candidate is ──────────────────────────────────────────────────────
# The main-push run builds ONE multi-platform image index for its commit and
# signs a CANDIDATE RECORD over it: an in-toto attestation, keyless, whose
# certificate is issued to this repository's ci.yml on refs/heads/main for a
# `push` event at the exact commit. The record binds, in one signed statement:
#
#   source commit (full SHA)   repository + workflow + ref + event
#   producer run + attempt     intended version (vX.Y.Z)
#   image-index digest         the digest of every required platform manifest
#   build inputs               go.mod toolchain, builder image, input hashes
#
# After the candidate passes qualification (execution, scan, platforms,
# embedded version and compiler) the main run signs a second attestation, the
# QUALIFICATION record, over the same digest.
#
# ── Discovery never trusts a name ────────────────────────────────────────────
# The tag run finds the candidate through `candidate-commit-<full sha>`, a
# registry tag. Any job with `packages: write` can move a tag, so the pointer
# is only a hint: the tag run accepts the digest it names only after BOTH
# attestations verify against the pinned producer identity below, name the
# tag's own commit and version, and describe exactly the platforms the live
# index carries. A short SHA, a moving channel (`latest`, `main`) or an
# artifact name is never evidence.
#
# ── This identity is NOT the release identity ────────────────────────────────
# release_identity.env pins the OFFICIAL release signer: ci.yml on a v* TAG.
# The producer identity below is ci.yml on refs/heads/main — it vouches that a
# candidate was built and qualified, never that it was released. The tag run
# signs the reused digest under the release identity itself; widening
# release_identity.env to accept a main signature would let every main build
# pass for a release. TestCandidateIdentity_IsNotTheReleaseIdentity pins it.
#
# Seams: DOCKER_BIN, COSIGN_BIN, JQ_BIN.
# ─────────────────────────────────────────────────────────────────────────────

# shellcheck disable=SC2034 # the constants are read by the scripts that source this file
CANDIDATE_REPOSITORY="KidCarmi/Culvert"
CANDIDATE_WORKFLOW=".github/workflows/ci.yml"
CANDIDATE_REF="refs/heads/main"
CANDIDATE_EVENT="push"
CANDIDATE_IDENTITY="https://github.com/KidCarmi/Culvert/.github/workflows/ci.yml@refs/heads/main"
CANDIDATE_ISSUER="https://token.actions.githubusercontent.com"
CANDIDATE_RECORD_TYPE="https://github.com/KidCarmi/Culvert/attestations/release-candidate/v1"
CANDIDATE_QUALIFICATION_TYPE="https://github.com/KidCarmi/Culvert/attestations/release-candidate-qualification/v1"
# Every candidate must carry exactly these platforms, each exactly once.
CANDIDATE_PLATFORMS="linux/amd64 linux/arm64"

# valid_sha <sha> — a full 40-hex commit id. A short SHA is never an identity.
valid_sha() {
  case "$1" in
    *[!0-9a-f]*|"") return 1 ;;
  esac
  [ "${#1}" -eq 40 ]
}

# valid_version <vX.Y.Z>
valid_version() {
  printf '%s' "$1" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$'
}

# version_gt <a> <b> — true iff vA > vB (both valid).
version_gt() {
  [ "$1" != "$2" ] && [ "$(printf '%s\n%s\n' "${1#v}" "${2#v}" | sort -V | tail -n1)" = "${1#v}" ]
}

# candidate_pointer_tag <sha> — the discovery hint for a commit's candidate.
candidate_pointer_tag() { printf 'candidate-commit-%s' "$1"; }

# index_platforms <image> <digest>
#   Prints "<os>/<arch>[/<variant>] <manifest digest>" per platform manifest of
#   the index, sorted. BuildKit's attestation manifests (platform unknown/unknown,
#   annotated attestation-manifest) are excluded: they describe the image, they
#   are not a runnable platform. Fails (rc 1, message on stdout) if the digest
#   is not a readable image INDEX.
index_platforms() {
  local image="$1" digest="$2" raw rc=0
  raw="$("${DOCKER_BIN:-docker}" buildx imagetools inspect --raw "${image}@${digest}" 2>&1)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    printf '%s' "$raw"
    return 1
  fi
  printf '%s' "$raw" | "${JQ_BIN:-jq}" -r '
    if (.manifests | type) != "array" then error("not an image index") else . end
    | .manifests[]
    | select((.annotations["vnd.docker.reference.type"] // "") != "attestation-manifest")
    | select((.platform.os // "unknown") != "unknown")
    | "\(.platform.os)/\(.platform.architecture)\(if .platform.variant then "/" + .platform.variant else "" end) \(.digest)"
  ' 2>&1 | sort || return 1
}

# platform_digest <index_platforms output> <platform>
#   The manifest digest of exactly one platform of the index. Pull, create and
#   run the candidate by THIS digest, never by the index digest once per
#   platform: Docker's classic image store keeps ONE image per digest
#   reference, so pulling <image>@<index digest> for a second platform fails
#   with "cannot overwrite digest" (main run 36111817278). Fails unless the
#   platform appears exactly once with a well-formed digest.
platform_digest() {
  local d
  d="$(printf '%s\n' "$1" | awk -v p="$2" '$1 == p { print $2 }')"
  [ "$(printf '%s\n' "$d" | grep -c .)" -eq 1 ] && valid_digest "$d" || return 1
  printf '%s' "$d"
}

# platform_violations <index_platforms output>
#   Prints one line per violation of "exactly the required platforms, each
#   exactly once, each with a well-formed digest". Empty output = compliant.
platform_violations() {
  local lines="$1" p n
  for p in $CANDIDATE_PLATFORMS; do
    n="$(printf '%s\n' "$lines" | awk -v p="$p" '$1 == p' | grep -c . || true)"
    [ "$n" -eq 1 ] || echo "platform ${p}: found ${n} manifests, want exactly 1"
  done
  printf '%s\n' "$lines" | while read -r p d; do
    [ -n "${p:-}" ] || continue
    case " $CANDIDATE_PLATFORMS " in
      *" $p "*) ;;
      *) echo "unexpected platform ${p} in the index" ;;
    esac
    case "$d" in
      sha256:*) [ "${#d}" -eq 71 ] || echo "platform ${p}: malformed digest ${d}" ;;
      *) echo "platform ${p}: malformed digest ${d}" ;;
    esac
  done
}

# platforms_json <index_platforms output> — {"linux/amd64":"sha256:…",…}
platforms_json() {
  printf '%s\n' "$1" | "${JQ_BIN:-jq}" -Rn '[inputs | select(length > 0) | split(" ") | {(.[0]): .[1]}] | add // {}'
}

# verify_statements <type> <image> <digest> <sha>
#   Verifies every attestation of <type> on <image>@<digest> against the pinned
#   producer identity at commit <sha>, and prints the verified in-toto
#   statements as ONE JSON array. Only statements whose subject is <digest>
#   are kept. rc 0 with a non-empty array, rc 1 otherwise (the reason on
#   stdout). cosign's certificate checks do the trust work — issuer, exact
#   workflow identity on refs/heads/main, repository, commit and trigger —
#   and this function refuses rather than interpreting an unverified payload.
verify_statements() {
  local type="$1" image="$2" digest="$3" sha="$4" out rc=0 stmts
  out="$("${COSIGN_BIN:-cosign}" verify-attestation \
    --type "$type" \
    --certificate-identity "$CANDIDATE_IDENTITY" \
    --certificate-oidc-issuer "$CANDIDATE_ISSUER" \
    --certificate-github-workflow-repository "$CANDIDATE_REPOSITORY" \
    --certificate-github-workflow-ref "$CANDIDATE_REF" \
    --certificate-github-workflow-trigger "$CANDIDATE_EVENT" \
    --certificate-github-workflow-sha "$sha" \
    "${image}@${digest}" 2>/dev/null)" || rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "no attestation of type ${type} on ${image}@${digest} verifies against ${CANDIDATE_IDENTITY} at ${sha}"
    return 1
  fi
  # Each line is a DSSE envelope (base64 in-toto payload) or, from a bundle,
  # the statement itself. Anything unparseable is dropped, never guessed at.
  stmts="$(printf '%s\n' "$out" | "${JQ_BIN:-jq}" -c -n --arg d "${digest#sha256:}" --arg t "$type" '
    [inputs
      | (if has("payload") then (.payload | @base64d | fromjson) else . end)
      | select(.predicateType == $t)
      | select(any(.subject[]?; .digest.sha256 == $d))]' 2>/dev/null || true)"
  if [ -z "$stmts" ] || [ "$stmts" = "[]" ]; then
    echo "attestations of type ${type} verified but none names ${digest} as its subject"
    return 1
  fi
  printf '%s' "$stmts"
}

# record_violations <statements json> <image> <digest> <sha> <live platforms json>
#   Checks every verified candidate record against the facts it must bind.
#   All records on a digest must agree; any disagreement is a violation.
#   Prints violations; prints nothing when the records are consistent.
record_violations() {
  local stmts="$1" image="$2" digest="$3" sha="$4" live="$5"
  printf '%s' "$stmts" | "${JQ_BIN:-jq}" -r \
    --arg repo "$CANDIDATE_REPOSITORY" --arg wf "$CANDIDATE_WORKFLOW" \
    --arg ref "$CANDIDATE_REF" --arg ev "$CANDIDATE_EVENT" \
    --arg image "$image" --arg digest "$digest" --arg sha "$sha" \
    --argjson live "$live" '
    def check(c; msg): if c then empty else msg end;
    (map(.predicate) | unique | length) as $n
    | (if $n > 1 then "\($n) different candidate records on one digest — refusing to pick one" else empty end),
      (.[] | .predicate as $p |
        check($p.repository == $repo; "record names repository \($p.repository), want \($repo)"),
        check($p.workflow == $wf; "record names workflow \($p.workflow), want \($wf)"),
        check($p.ref == $ref; "record names ref \($p.ref), want \($ref)"),
        check($p.event == $ev; "record names event \($p.event), want \($ev)"),
        check($p.source_sha == $sha; "record names commit \($p.source_sha), want \($sha)"),
        check($p.image == $image; "record names image \($p.image), want \($image)"),
        check($p.index_digest == $digest; "record names index \($p.index_digest), want \($digest)"),
        check(($p.version // "") | test("^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$"); "record carries no valid version"),
        check(($p.producer.run_id // "") != "" and ($p.producer.run_attempt // "") != ""; "record names no producer run/attempt"),
        check(($p.build_inputs.go_toolchain // "") != ""; "record names no compiler"),
        check($p.platforms == $live; "record platforms \($p.platforms | tojson) differ from the live index \($live | tojson)"))' 2>&1
}

# qualification_violations <statements json> <digest> <sha> <version> <live platforms json>
qualification_violations() {
  local stmts="$1" digest="$2" sha="$3" version="$4" live="$5"
  printf '%s' "$stmts" | "${JQ_BIN:-jq}" -r \
    --arg digest "$digest" --arg sha "$sha" --arg version "$version" --argjson live "$live" '
    [.[] | .predicate
      | select(.result == "pass" and .source_sha == $sha and .index_digest == $digest
               and .version == $version and .platforms == $live)]
    | if length == 0 then "no passing qualification record for \($digest) at \($sha) as \($version)" else empty end' 2>&1
}
