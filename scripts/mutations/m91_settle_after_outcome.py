#!/usr/bin/env python3
"""M91: reorder the terminal-outcome commit BEFORE the health sample.

This mutation reintroduces the crash window Codex round 3 named: with the outcome
durable first, a crash in between leaves the ledger proving a settled attempt while
the runtime snapshot omits its health sample. Restore legitimately accepts fewer
samples than reservations, so that missing sample is indistinguishable from one that
never happened.

It is a REORDER, not an edit, which is why it lives in a file rather than a sed
script. The swap is written to COMPILE — a compile failure would prove nothing.
Exits 1 if the pattern no longer matches, so the campaign scores it SKIPPED rather
than as a pass.
"""
import sys

PATH = "internal/mcp/execution/attempt_evidence.go"
SETTLED_HEAD = "\t// One SETTLED post-admission attempt, for the population detectors."
SETTLED_TAIL = (
    "\tif state != model.SendStateUnset && state != model.SendDefinitelyNotSent {\n"
    "\t\te.cfg.Safety.AttemptSettled(in.Capability.String(), rec.generation, "
    "!state.ProvesReceipt(), e.cfg.Clock().Sub(rec.startedAt))\n"
    "\t}\n"
)
COMMIT_HEAD = (
    "\tif _, cerr := e.cfg.Events.CommitDecision(f); cerr != nil {\n"
    "\t\t// A physical invocation may have happened"
)
BREACH = 'e.cfg.Safety.Breach(in.Capability.String(), rec.generation, "outcome_evidence_loss")'


def main() -> int:
    src = open(PATH).read()
    try:
        i = src.index(SETTLED_HEAD)
        settled_end = src.index(SETTLED_TAIL) + len(SETTLED_TAIL)
        settled = src[i:settled_end]
        j = src.index(COMMIT_HEAD)
        k = src.index("\t}\n", src.index(BREACH)) + len("\t}\n")
        commit = src[j:k]
    except ValueError:
        return 1
    if "outcome_evidence_loss" not in commit or "AttemptSettled" not in settled:
        return 1
    open(PATH, "w").write(src[:i] + commit + "\n" + settled + src[k:])
    return 0


if __name__ == "__main__":
    sys.exit(main())
