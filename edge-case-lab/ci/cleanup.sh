#!/usr/bin/env bash
# Stop the lab's fixture + proxy processes. Invoked from every job's `if: always()`
# cleanup step so a runner is never left with a listening origin fixture or a
# stray proxy — even when the tier failed. Always exits 0 (cleanup must not fail
# the job).
#
# Kills by the recorded fixture PID first (deterministic), then a targeted
# fallback. pkill excludes its own PID and, under Actions, the step body runs from
# a temp script (its args do not contain these patterns), so no self-match.
set +e

if [ -f /tmp/fixture.pid ]; then
  kill "$(cat /tmp/fixture.pid)" 2>/dev/null
  rm -f /tmp/fixture.pid
fi

pkill -f 'edge-case-lab/fixtures/origin_server.py' 2>/dev/null
pkill -x culvert 2>/dev/null

echo "lab cleanup done (fixture + proxy stopped)"
exit 0
