# Disposable slow/failed service observation

Use this fixture in a separate visual boot, outside the three formal recovery
cycles. Generate scripts offline from the final frozen controller:

```text
python -B test/e2e/appliance/esxi/visual-service-fixture.py --action install --owner-uuid EXACT_OWNED_API_UUID --output PRIVATE_INSTALL.sh
python -B test/e2e/appliance/esxi/visual-service-fixture.py --action remove --owner-uuid EXACT_OWNED_API_UUID --output PRIVATE_REMOVE.sh
```

Send the install script only through the existing authenticated local console
transport, with the same API ownership checks and a 60-second outer timeout.
It independently checks root, exact cd8 source, VMware UUID/SMBIOS alias,
first-boot completion, both maintenance locks and pending maintenance. It does
not start services or reboot. Start the private screenshot observer before a
separately authorized reboot. Do not include this deliberately delayed boot
in normal startup timing or availability acceptance results.

Two exclusive lab units are enabled before multi-user and Plymouth quit:
`culvert-lab-visual-delay.service` sleeps 45 seconds (50-second start limit),
and `culvert-lab-visual-failure.service` intentionally runs `/usr/bin/false`.
Root-only fired markers make each a one-boot fixture; no restart loop exists.
The ordering keeps the normal splash visible while the delay runs. Neither
unit overrides product services, getty, GRUB, access controls or readiness.
Review the actual splash/ESC diagnostics/menu and retain each unit's result
and journal before cleanup. A fixture failure is expected, but unrelated
product failures remain failures.

After both units are inactive/failed, use the generated remove script through
authenticated console. Cleanup requires the exact generator/lock-source,
owner/source receipt, unit bytes and enable-link targets. It resets only the
two fixture units' failed state, removes their unchanged units/links and
reloads systemd. It retains root-only install/remove receipts and fired
markers in `/var/lib/culvert-lab-visual-fixture`; no repeated install is
permitted. The receipts include full exact unit bytes and successful output
includes their SHA256 hashes. Any interrupted/ambiguous installation or
cleanup remains blocked for reconciliation; no automatic destructive retry.

The generator embeds only the reviewed lock/maintenance helper definitions
from the frozen `qualify-clamav-outage.py`, recording that file's hash. No
ClamAV operation or network client is dispatched. Keep generated payloads and
full diagnostic evidence private; publish only reviewed results/hashes.
