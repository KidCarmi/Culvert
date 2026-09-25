#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# release.sh — resolve the release object a tag's assets are STAGED on.
#
# `GET /repos/{owner}/{repo}/releases/tags/{tag}` DOES NOT RETURN DRAFTS.
# Every reader in the release chain used it, and the chain stages everything on
# a draft, so every reader was blind to the very release it was reasoning about.
# On v1.0.234 that produced two release objects for one tag — a provenance-only
# published one (created by a draft-blind uploader) that became the
# repository's Latest, and the invisible draft holding all 19 real assets.
#
# resolve_staged_release_id lists releases instead, which returns drafts, and
# answers with the id of the one this tag is staged on.
#
# Contract, all fail-closed:
#   • exactly one DRAFT for the tag            → that id
#   • no draft, exactly one PUBLISHED release  → that id (a re-run after
#                                                publication; callers that must
#                                                refuse a published release use
#                                                assert-release-unpublished.sh)
#   • several drafts, or nothing               → refuse, naming what it saw
#
# A draft is preferred over a published release with the same tag on purpose:
# that pairing is the corruption above, and the staged assets are the draft's.
#
# Seams: GH_BIN, RELEASE_LIST_FILE (a JSON array, for tests).
# ─────────────────────────────────────────────────────────────────────────────

GH_BIN="${GH_BIN:-gh}"

# resolve_staged_release_id <repo> <tag>  → prints the id, or refuses (rc 1)
resolve_staged_release_id() {
  local repo="$1" tag="$2" list
  if [ -n "${RELEASE_LIST_FILE:-}" ]; then
    list="$(cat "$RELEASE_LIST_FILE")"
  elif ! list="$("$GH_BIN" api --paginate "repos/${repo}/releases" 2>&1)"; then
    echo "::error::cannot list releases of ${repo} (${list}) — refusing" >&2
    return 1
  fi

  local drafts published
  drafts="$(printf '%s' "$list" | jq -r --arg t "$tag" \
    '[.[] | select(.tag_name == $t and .draft == true) | .id] | .[]' 2>/dev/null || true)"
  published="$(printf '%s' "$list" | jq -r --arg t "$tag" \
    '[.[] | select(.tag_name == $t and .draft == false) | .id] | .[]' 2>/dev/null || true)"

  local ndraft npub
  ndraft="$(printf '%s' "$drafts" | grep -c . || true)"
  npub="$(printf '%s' "$published" | grep -c . || true)"

  if [ "$ndraft" -gt 1 ]; then
    echo "::error::${tag} has ${ndraft} DRAFT releases (ids: $(echo $drafts)) — refusing rather than guessing" >&2
    echo "::error::RECOVERY: an owner must delete the duplicates, keeping the one with the staged assets." >&2
    return 1
  fi
  if [ "$ndraft" -eq 1 ]; then
    if [ "$npub" -gt 0 ]; then
      echo "::warning::${tag} has BOTH a draft and $npub published release(s); using the draft ($(echo $drafts))." >&2
      echo "::warning::A published release alongside the draft means something uploaded outside the staging path." >&2
    fi
    printf '%s\n' "$drafts"
    return 0
  fi
  if [ "$npub" -eq 1 ]; then
    printf '%s\n' "$published"
    return 0
  fi
  if [ "$npub" -gt 1 ]; then
    echo "::error::${tag} has ${npub} published releases (ids: $(echo $published)) — refusing" >&2
    return 1
  fi
  echo "::error::no release object exists for ${tag} — refusing" >&2
  return 1
}
