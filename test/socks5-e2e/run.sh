#!/usr/bin/env bash
# SOCKS5 real-network end-to-end suite (SWG-901). Verification only; not a
# required CI gate. See test/socks5-e2e/README.md.
#
#   test/socks5-e2e/run.sh [--negative-control] [--modes enforce,shadow,legacy]
#                          [--work DIR] [--upstream-ip IP]
#
# Builds the REAL culvert binary from this checkout, the driver and the LDAP
# directory from this module, then runs the driver in a private mount
# namespace (unshare -m) so a hosts override can map the test hostnames to a
# local upstream address without touching the host's /etc/hosts.
#
# --negative-control additionally builds the binary from a TEMPORARY COPY of
# the tree with each mutants/*.patch applied (never the checkout) and requires
# the suite to FAIL against every mutant.
#
# Exit: 0 = suite passed (and, with --negative-control, every mutant caught);
#       1 = a case failed or a mutant survived; 2 = setup/harness error.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
NEG=0
MODES="enforce,shadow,legacy"
WORK=""
UPSTREAM_IP="auto"
while [ $# -gt 0 ]; do
  case "$1" in
    --negative-control) NEG=1 ;;
    --modes) MODES="$2"; shift ;;
    --work) WORK="$2"; shift ;;
    --upstream-ip) UPSTREAM_IP="$2"; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

export GOMAXPROCS=2
[ -n "$WORK" ] || WORK="$(mktemp -d -t culvert-socks5-e2e.XXXXXX)"
mkdir -p "$WORK/bin"
WORK="$(cd "$WORK" && pwd)"
echo "== work dir: $WORK"

# ── Prerequisites ────────────────────────────────────────────────────────────
for tool in go unshare; do
  command -v "$tool" >/dev/null || { echo "missing prerequisite: $tool" >&2; exit 2; }
done
if [ "$(id -u)" != 0 ]; then
  echo "needs root (or CAP_SYS_ADMIN) for the private mount namespace that carries the hosts override" >&2
  exit 2
fi
[ "$NEG" = 0 ] || command -v patch >/dev/null || { echo "missing prerequisite: patch" >&2; exit 2; }

# ── Build ────────────────────────────────────────────────────────────────────
# Builds use the caller's environment (module proxy, its CA bundle); the
# suite itself runs with every proxy variable removed.
echo "== build culvert (checkout: $ROOT)"
(cd "$ROOT" && CGO_ENABLED=0 go build -o "$WORK/bin/culvert" .) || { echo "build culvert failed" >&2; exit 2; }
echo "== build driver + ldapserver (module test/socks5-e2e)"
(cd "$HERE" && go build -tags socks5_e2e -o "$WORK/bin/driver" ./driver \
            && go build -tags socks5_e2e -o "$WORK/bin/ldapserver" ./ldapserver) || { echo "build driver/ldapserver failed" >&2; exit 2; }

OUTER_NS="$(readlink /proc/self/ns/mnt)"
run_driver() { # label culvert-binary modes results-basename
  env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy -u ALL_PROXY -u all_proxy -u NO_PROXY -u no_proxy \
    CULVERT_E2E_OUTER_MNTNS="$OUTER_NS" GOMAXPROCS=2 \
    unshare -m --propagation private \
    "$WORK/bin/driver" -label "$1" -culvert "$2" -modes "$3" -ldapserver "$WORK/bin/ldapserver" \
      -work "$WORK/run-$1" -upstream-ip "$UPSTREAM_IP" \
      -results "$WORK/$4.md" -results-json "$WORK/$4.json"
}

# ── The suite against the checkout ──────────────────────────────────────────
echo "== suite: checkout, modes=$MODES"
run_driver checkout "$WORK/bin/culvert" "$MODES" results-checkout > "$WORK/results-checkout.log" 2>&1
suite=$?
cat "$WORK/results-checkout.log"
case "$suite" in
  0) echo "== checkout: PASS" ;;
  1) echo "== checkout: FAIL (see the Failures section above; logs under $WORK/run-checkout)" ;;
  *) echo "== checkout: HARNESS ERROR ($suite)"; exit 2 ;;
esac
status=$suite

# ── Negative controls ───────────────────────────────────────────────────────
if [ "$NEG" = 1 ]; then
  before="$(cd "$ROOT" && git status --porcelain --untracked-files=no -- '*.go' 2>/dev/null)"
  summary=""
  for p in "$HERE"/mutants/*.patch; do
    name="$(basename "$p" .patch)"
    tree="$WORK/tree-$name"
    rm -rf "$tree"; mkdir -p "$tree"
    # A copy of the checkout without VCS metadata or the frontend's packages.
    tar -C "$ROOT" --exclude=./.git --exclude=./frontend/node_modules -cf - . | tar -C "$tree" -xf -
    if ! patch -s -p1 -d "$tree" < "$p"; then
      echo "mutant $name: patch does not apply to this checkout" >&2; exit 2
    fi
    echo "== negative control $name: $(head -1 "$p")"
    (cd "$tree" && CGO_ENABLED=0 go build -buildvcs=false -o "$WORK/bin/culvert-$name" .) || { echo "build mutant $name failed" >&2; exit 2; }
    rm -rf "$tree"
    run_driver "$name" "$WORK/bin/culvert-$name" enforce "results-$name" > "$WORK/results-$name.log" 2>&1
    rc=$?
    caught_by="$(grep -E '^- \*\*' "$WORK/results-$name.md" 2>/dev/null | sed -E 's/^- \*\*([^*]*)\*\*.*/\1/' | paste -sd ',' -)"
    case "$rc" in
      1) verdict="CAUGHT"; echo "   CAUGHT by: $caught_by"
         grep -E '^- \*\*' "$WORK/results-$name.md" | sed 's/^/   /' ;;
      0) verdict="SURVIVED"; status=1; echo "   SURVIVED: the suite passed against a known-unsafe binary" ;;
      *) echo "   HARNESS ERROR ($rc); see $WORK/results-$name.log"; exit 2 ;;
    esac
    summary+="| $name | $verdict | ${caught_by:-—} |"$'\n'
  done
  after="$(cd "$ROOT" && git status --porcelain --untracked-files=no -- '*.go' 2>/dev/null)"
  if [ "$before" != "$after" ]; then
    echo "the checkout's Go files changed during the negative-control run" >&2; exit 2
  fi
  {
    echo
    echo "## Negative controls ($(date -u '+%Y-%m-%d %H:%M') UTC)"
    echo
    echo "| Mutant | Verdict | Failing rows (mode case protocol) |"
    echo "|---|---|---|"
    printf '%s' "$summary"
  } | tee "$WORK/negative-control.md"
fi

echo "== artifacts: $WORK (results-*.md / *.json, per-mode culvert.log, requests.jsonl, ldap-events.jsonl)"
exit "$status"
