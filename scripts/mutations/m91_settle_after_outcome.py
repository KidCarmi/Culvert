#!/usr/bin/env python3
"""M91: move the health sample AFTER the terminal-outcome commit.

This reintroduces the crash window Codex round 3 named: with the outcome durable
first, a crash in between leaves the ledger proving a settled attempt while the
runtime snapshot omits its health sample. Restore legitimately accepts fewer
samples than reservations, so that missing sample is indistinguishable from one
that never happened.

Codex round 7 moved the settle out of commitAttemptOutcome and into the upstream
leg (so it also precedes the RELEASE), which changed the shape this mutation has
to produce. Reintroducing the defect now means deleting the call from run.go's
leg-scoped defer and re-adding it to the OUTER defer, after commitAttemptOutcome.
The settle-before-release property is M99's; this one owns settle-before-outcome.

The swap is written to COMPILE — a compile failure would prove nothing under the
campaign's own header rule. Exits 1 if either pattern no longer matches, so the
campaign scores it SKIPPED rather than as a pass.
"""
import sys

PATH = "internal/mcp/execution/run.go"

SETTLE = (
    "\t\t\te.reportAttemptSettled(in, attempt, sendState, "
    "upstreamLegFailed(upResp, upErr))\n"
)
OUTER = "\t\te.commitAttemptOutcome(in, attempt, sendState, out)\n"
OUTER_MUTATED = (
    "\t\te.commitAttemptOutcome(in, attempt, sendState, out)\n"
    "\t\te.reportAttemptSettled(in, attempt, sendState, "
    "upstreamLegFailed(upResp, upErr))\n"
)


def main() -> int:
    src = open(PATH).read()
    if SETTLE not in src or OUTER not in src:
        return 1
    src = src.replace(SETTLE, "", 1)
    src = src.replace(OUTER, OUTER_MUTATED, 1)
    open(PATH, "w").write(src)
    return 0


if __name__ == "__main__":
    sys.exit(main())
