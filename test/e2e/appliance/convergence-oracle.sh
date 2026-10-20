#!/usr/bin/env bash
# test/e2e/appliance/convergence-oracle.sh — the F-DISK recovery convergence
# verdict, extracted as PURE functions so the acceptance decision is locally
# testable WITHOUT a lab run (ASTRA 2026-10-20 §2 "mandatory convergence
# verdict"; the same approach ASTRA used to independently execute the
# operator-capture classifier against a synthetic input).
#
# Why this exists: a recovery scenario (midwrite / midimport-kill) can
# legitimately NOT converge in the lab — the disposable dind loop volume may be
# below the full category-import footprint, or the feed download can fail on the
# network. Neither is a product fault, so both are reported INFO. But the old
# harness counted only `fail` toward the exit code, so a run that EXERCISED
# convergence and only ever hit those INFO outcomes still exited 0 — and job
# SUCCESS was then read as convergence proof when none was observed. These two
# pure functions are the whole decision; `upgrade-enospc-qualify.sh` sources
# them and `convergence-oracle_test.sh` proves them red/green with no lab.

# classify_convergence <feedsync-outcome-line>
#   -> proven | unproven_lab | unproven_net | failed
#
#   proven        a real "FeedSync: sync complete" — the import certified the feed.
#   unproven_lab  "FeedSync: write REFUSED (disk_space)" AFTER space was freed:
#                 the lab volume is still below the import footprint. A sizing
#                 limit, NOT a product fault — but convergence is NOT proven.
#   unproven_net  "FeedSync: ... download/parse failed" — a network failure that
#                 says nothing about the disk. Convergence NOT proven.
#   failed        empty (no FeedSync outcome within the window) OR any disk-side
#                 error ("bulk write failed", "could not begin the import",
#                 "import written but could not be certified", or anything else
#                 not matched above). A product-side convergence failure.
classify_convergence() {
	case "${1:-}" in
	*"sync complete"*) echo proven ;;
	*"write REFUSED (disk_space)"*) echo unproven_lab ;;
	*"download/parse failed"*) echo unproven_net ;;
	"") echo failed ;;
	*) echo failed ;;
	esac
}

# convergence_exit_class <conv-path-ran:0|1> <conv-verdict> <fails>
#   -> pass | incomplete | fail
#
#   fails>0           -> fail        a disk-side convergence failure (or any other
#                                    check) already failed; the run fails (exit 1).
#   ran=1 & !proven   -> incomplete  convergence was EXERCISED but never PROVEN
#                                    (only a lab-sizing/network shortfall): the run
#                                    is INCONCLUSIVE for the convergence criterion
#                                    (exit 2), NEVER a pass. This is the mandatory
#                                    verdict — job SUCCESS can no longer be read as
#                                    convergence proof.
#   otherwise         -> pass        either convergence was proven, or the
#                                    convergence path was not exercised at all
#                                    (a non-recovery scenario).
convergence_exit_class() {
	local ran="${1:-0}" verdict="${2:-none}" fails="${3:-0}"
	if ((fails > 0)); then
		echo fail
		return
	fi
	if [[ "$ran" == 1 && "$verdict" != proven ]]; then
		echo incomplete
		return
	fi
	echo pass
}
