#!/usr/bin/env bash
# Loaded before lifecycle dispatch. The shared collector uses authenticated
# gpriv; the supplemental parser closes missing-row and truncated-output gaps.
esxi_engine_surface() {
  [[ ${ESXI_ENGINE_SURFACE:-0} == 1 ]] || return 0
  [[ ! -e $EV/E-engine-surface.txt && ! -e $EV/E-engine-completeness.txt && ! -e $EV/E-engine-inventory.txt ]] || {
    check E engine-evidence-fresh fail 'Existing engine evidence retained; refusing overwrite.'
    return 1
  }
  cmd_engine_surface
  local -a supplemental=()
  if [[ ${ESXI_ENGINE_SOURCE:?explicit engine candidate required} == 91e05872dfe5f96c94ec725b8b2dc2b1002116ab ]]; then
    # Separate immutable evidence keeps the shared collector's bytes and output
    # unchanged while binding its reviewed-list counts to the shipped source.
    if ! gpriv --timeout 30 > "$EV/E-engine-inventory.txt" <<'CULVERT_ENGINE_INVENTORY'
set -euo pipefail
path=/opt/culvert-appliance/provision/net-autoload-reviewed.txt
[[ -f "$path" && ! -L "$path" ]]
printf 'net-reviewed-file %s\n' "$(sha256sum "$path" | cut -d' ' -f1)"
CULVERT_ENGINE_INVENTORY
    then
      check E engine-inventory fail 'Authenticated supplemental inventory unavailable.'
      return 1
    fi
    supplemental=(--inventory "$EV/E-engine-inventory.txt")
  fi
  if python3 "$ADAPTER_HERE/engine-surface-proof.py" "$EV/E-engine-surface.txt" --source "${ESXI_ENGINE_SOURCE:?explicit engine candidate required}" "${supplemental[@]}" \
      > "$EV/E-engine-completeness.txt" 2>&1; then
    check E engine-evidence-complete pass 'All candidate-specific module refusals, effective rules, reviewed file digests and engine observations are present.'
  else
    check E engine-evidence-complete fail 'Incomplete or contradictory engine/module evidence; inspect E-engine-completeness.txt.'
  fi
}
