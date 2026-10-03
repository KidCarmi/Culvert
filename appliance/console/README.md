# Culvert boot console — first implementation slice

This additive component provides an ESXi-style local console after power-on.
It is a host Python application (standard library and Ubuntu's curses support),
independent of Docker and the Culvert application. There is no new network
listener. The displayed application URL remains `https://<address>:9090` and is
explicitly labelled unavailable until the application starts.

The public screen shows version/candidate status, assigned IPv4 addresses,
recorded firstboot checkpoints and live service observations. `F2` or `2` starts
normal Linux/PAM login as `culvert`; `F4` or `4` shows sanitized diagnostics.
Number keys work when a browser console intercepts function keys.

After authenticating, the operator gets network information, setup-token access
through the existing privileged status command, diagnostics, a confirmed retry
of incomplete provisioning, confirmed reboot/shutdown and a recovery shell.
The menu logs out after five minutes without input. An explicitly opened shell
retains normal shell behavior. Key-only installations still require the imported
SSH key; the menu never unlocks the account or invents a default password.
An administrator can set a console password through their authenticated SSH
session with `sudo passwd culvert`.

## Integration boundary with Opus

Files are contained here to avoid conflicts with the ongoing firstboot/image
fix. This slice does **not** modify `build-ova.sh`, `prepare-guest.sh`, firstboot,
the network helper, the existing status CLI, or the application UI. It does not
change the existing application readiness contract.

Two build hooks are needed when this component is accepted:

1. In `build-ova.sh`, beside the provision/os-maintenance overlay copy, copy
   `appliance/console` to `$OV/opt/culvert-appliance/console`.
2. In `prepare-guest.sh`, after the `culvert` account and existing helpers have
   been installed, run:

   ```bash
   bash /opt/culvert-appliance/console/install.sh
   ```

The installer checks Python curses, PAM login, sudo and the account before
installing the tty1 getty override and root-owned login profile hook. It does
not restart a live console, add sudo rules, change the firewall or configure
autologin. Normal tty2/serial/SSH login remains available. Do not add an ordering
dependency on Docker, network-online or culvert-firstboot: an unavailable
dependency must not prevent the menu appearing.

To evaluate in an **owned disposable guest** after copying this directory:

```bash
sudo bash /tmp/culvert-console-dev/install.sh
sudo systemctl daemon-reload
sudo systemctl restart getty@tty1.service
```

The latter command ends any tty1 session; run it through authenticated SSH only
in the disposable qualification VM. Reboot validation must then prove the same
menu appears without manually restarting getty.

Rollback through SSH or tty2:

```bash
sudo rm /etc/systemd/system/getty@tty1.service.d/culvert-console.conf
sudo rm /etc/profile.d/culvert-console.sh
sudo systemctl daemon-reload
sudo systemctl restart getty@tty1.service
```

## Shared status contract (schema version 1)

```bash
python3 -I /opt/culvert-appliance/console/launch.py --json
python3 -I /opt/culvert-appliance/console/launch.py --text
```

These are read-only and never include a setup token, `.env`, raw journals or
OVF data. Five fixed probes execute concurrently with four-second subprocess
timeouts (HTTP probes have two-second deadlines). Requests use loopback only,
disable proxies, do not follow redirects, and limit response size. Only the
self-signed loopback setup-status read uses a TLS verification exception.
No Docker API or command is required to render the display.

- `phase`: `unknown`, `waiting`, `running`, `failed`, `provisioned`, `ready`.
- `reason`: stable reason code; `message`: operator explanation.
- `steps`: each existing checkpoint is `recorded` or `not_recorded`. This is
  deliberately evidence of a marker, not a fabricated current step or percentage.
- `firstboot`: allowlisted systemd fields. A previous failure remains visible
  during automatic retry. An inactive incomplete unit is explicitly not running.
- `administrator_enrolled`: true only on an explicit `needsSetup: false`.
- `ready`: requires application health HTTP 200, explicit enrollment, readiness
  HTTP 200 and `ok` for policy_loaded, policy_posture, ca and setup_complete.
  Missing rows are not success. This is a conservative console summary.
- `traffic_verified`: always false; local health probes cannot prove a client
  successfully passes through the proxy.

Terminal text is restricted to printable ASCII so untrusted metadata cannot
inject terminal controls. Imported code is restricted to the root-owned install
directory with Python isolated mode. Public key presses can only refresh,
view this sanitized status, or invoke `/bin/login culvert` without `-f`.
Recovery actions additionally check the effective Unix identity, use fixed argv
and existing sudo authorization. No password is captured by the Python program.
Setup-token output stays on the authenticated terminal and is not a diagnostic
export. The public root-owned process is a narrow getty/login wrapper, not an
HTTP server and not an unauthenticated shell.

## Tests and remaining work

```bash
python3 -m unittest discover -s appliance/console -p 'test_*.py' -v
bash -n appliance/console/install.sh
bash -n appliance/console/profile.sh
```

Tests cover absent/broken services, malformed observations, stale checkpoints,
readiness/enrollment distinctions, terminal escape filtering, secret exclusion,
unauthenticated action refusal and retry/power confirmation boundaries.

Real ESXi smoke results are recorded separately; unit tests do not establish
PAM/getty/keyboard behavior. The incomplete ClamAV image remains a product
failure even if the console handles it correctly.

The [real ESXi smoke report](evidence/esxi-smoke.json) records the exact base OVA
and installed overlay hashes. All 26 tests passed in the Ubuntu guest; real
VMware keyboard/PAM login, invalid-password refusal, logout, stopped-Docker
operation and automatic console startup after reboot passed. The owned VM was
deleted afterward. This is development-overlay evidence, not a rebuilt OVA.
The console service reported about 14.1 MiB at one observation; this is not a
peak or whole-appliance resource qualification.

![ESXi boot console after reboot](evidence/esxi-boot-menu.png)

Some ESXi screenshot captures were partial even though the guest's virtual
terminal buffer held the complete menu. The retained reboot capture follows a
tty2/tty1 switch to force a redraw; no image editing was used. This capture
limitation remains recorded rather than counting a partial image as visual proof.

Follow-on work: persistent explicit firstboot step/error events, guided network
editing with host-side rollback (the current menu provides information/recovery
only), independent browser bootstrap service, and application wizard integration.
No network Apply button is offered before rollback is implemented. The proposed
full browser setup experience is not delivered by this console slice.
