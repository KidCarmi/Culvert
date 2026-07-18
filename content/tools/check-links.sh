#!/usr/bin/env bash
# check-links.sh — verify relative Markdown links inside content/ resolve to a
# real file. Reports intra-content links whose target is missing. Absolute URLs
# (http/https), in-page anchors (#...), and mailto: are skipped.
#
# Usage: content/tools/check-links.sh [root]   (default root: content)
# Exit: 0 if all relative links resolve, 1 otherwise. Missing targets are listed.
set -euo pipefail

root="${1:-content}"
fail=0

# Optional allowlist of planned (not-yet-built) link targets, one per line,
# written as they appear in the link ( e.g. ../03-policy/policy-engine.md ).
# These are forward references in an incrementally published set; a target is
# removed from the list once its page is committed. Genuine typos still fail.
allowlist="${root}/.forward-refs"
is_allowed() {
  [ -f "$allowlist" ] || return 1
  grep -qxF "$1" "$allowlist"
}

# Iterate every markdown file under root.
while IFS= read -r -d '' md; do
  dir="$(dirname "$md")"
  # Extract [text](target) link targets, one per line.
  grep -oE '\]\([^)]+\)' "$md" 2>/dev/null | sed -E 's/^\]\(//; s/\)$//' | while IFS= read -r target; do
    # Strip any anchor fragment.
    path="${target%%#*}"
    # Skip empty (pure anchor), external, and mailto links.
    case "$target" in
      \#*|http://*|https://*|mailto:*) continue ;;
    esac
    [ -z "$path" ] && continue
    # Resolve relative to the file's directory.
    if [ ! -e "$dir/$path" ]; then
      if is_allowed "$target"; then
        echo "PLANNED (allowlisted forward ref): $md -> $target"
      else
        echo "MISSING: $md -> $target"
        echo "1" > /tmp/culvert_linkcheck_fail
      fi
    fi
  done
done < <(find "$root" -name '*.md' -print0)

if [ -f /tmp/culvert_linkcheck_fail ]; then
  rm -f /tmp/culvert_linkcheck_fail
  echo "Link check: FAILED (missing targets above)"
  exit 1
fi
echo "Link check: OK (all relative links resolve under $root)"
