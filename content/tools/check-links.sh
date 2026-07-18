#!/usr/bin/env bash
# check-links.sh — verify relative Markdown links inside content/ resolve to a
# real file. Reports intra-content links whose target is missing. Absolute URLs
# (http/https), in-page anchors (#...), and mailto: are skipped.
#
# Usage: content/tools/check-links.sh [root]   (default root: content)
# Exit: 0 if all relative links resolve, 1 otherwise. Missing targets are listed.
#
# Note: -e is deliberately NOT set — grep returns non-zero on a file with no
# links, which is normal (e.g. a lab-evidence page of code blocks). Errors are
# handled explicitly instead.
set -uo pipefail

root="${1:-content}"
missing=0

# Optional allowlist of planned (not-yet-built) link targets, one per line,
# written as they appear in the link ( e.g. ../03-policy/policy-engine.md ).
# These are forward references in an incrementally published set; a target is
# removed from the list once its page is committed. Genuine typos still fail.
allowlist="${root}/.forward-refs"
is_allowed() {
  [ -f "$allowlist" ] || return 1
  grep -qxF "$1" "$allowlist"
}

while IFS= read -r -d '' md; do
  dir="$(dirname "$md")"
  # Extract [text](target) link targets, one per line; tolerate no matches.
  targets="$(grep -oE '\]\([^)]+\)' "$md" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//' || true)"
  [ -z "$targets" ] && continue
  while IFS= read -r target; do
    [ -z "$target" ] && continue
    # Skip external, anchor-only, and mailto links.
    case "$target" in
      \#*|http://*|https://*|mailto:*) continue ;;
    esac
    path="${target%%#*}"   # strip any anchor fragment
    [ -z "$path" ] && continue
    if [ ! -e "$dir/$path" ]; then
      if is_allowed "$target"; then
        echo "PLANNED (allowlisted forward ref): $md -> $target"
      else
        echo "MISSING: $md -> $target"
        missing=$((missing + 1))
      fi
    fi
  done <<< "$targets"
done < <(find "$root" -name '*.md' -print0)

if [ "$missing" -gt 0 ]; then
  echo "Link check: FAILED ($missing missing target(s) above)"
  exit 1
fi
echo "Link check: OK (all relative links resolve under $root)"
