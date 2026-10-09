#!/usr/bin/env bash
# Loaded before lifecycle dispatch. The shared collector uses authenticated
# gpriv; the supplemental parser closes missing-row and truncated-output gaps.
esxi_engine_surface() {
  [[ ${ESXI_ENGINE_SURFACE:-0} == 1 ]] || return 0
  [[ ! -e $EV/E-engine-surface.txt && ! -e $EV/E-engine-completeness.txt ]] || {
    check E engine-evidence-fresh fail 'Existing engine evidence retained; refusing overwrite.'
    return 1
  }
  cmd_engine_surface
  if python3 "$ADAPTER_HERE/engine-surface-proof.py" "$EV/E-engine-surface.txt" \
      > "$EV/E-engine-completeness.txt" 2>&1; then
    check E engine-evidence-complete pass 'All 24 target-specific module refusals, effective rules, reviewed denylist digest and engine observations are present.'
  else
    check E engine-evidence-complete fail 'Incomplete or contradictory engine/module evidence; inspect E-engine-completeness.txt.'
  fi
}
