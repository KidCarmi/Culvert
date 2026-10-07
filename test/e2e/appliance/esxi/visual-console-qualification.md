# Private ESXi visual qualification for cd8e4450

These controller helpers observe the exact candidate
`cd8e44505bd329e5de675592ad4c23f92a534d55`. They do not constitute visual PASS
evidence until the retained private frames have been reviewed. No live VM was
used to develop their offline tests.

## Freeze and cold boot

Include all new helpers and the updated `esxi-lab.py` and
`private-keystrokes.go` in the controller freeze. Rebuild the private keyboard
from the updated source; an old binary/build receipt is deliberately rejected.
Keep its existing source/binary hash receipt and private directory ACL. A cold
ESC probe requires that build to finish before boot, independently of the
passive screenshot observer. Never compile or type credentials inside the
30-second power-on rendezvous.

Set the optional scope field `"visual_capture_label": "cold-boot"` **before**
preflight/freeze. Start this in a separate controller process before `up`:

```text
python -B test/e2e/appliance/esxi/visual-capture.py --scope SCOPE --label cold-boot --seconds 300 --interval 1 --wait-owned-seconds 1800
python -B test/e2e/appliance/esxi/esxi-lab.py --scope SCOPE up
```

The observer waits for the exact imported UUID/reference in `owned.json` and
validates candidate/preflight/freeze and API ownership before capturing. It
never resolves an import-pending name. Its separate `visual-capture.lock`
allows `up` to retain `operation.lock`. The observer records an identity-,
scope-, and nonce-bound armed receipt only after seeing the owned VM powered
off and checking the private directory ACL. `up` waits at most 30 seconds for
that fresh receipt before power-on. A missing/invalid receipt leaves the
imported VM powered off and preserves its ledger; do not rerun import or
invent a recovery power-on bypass.

The gate establishes observer readiness, not frame-complete coverage. API
latency can still miss firmware or a short splash. Report the actual first
frame time and any gap. Sampling has 900-second, 900-frame, 16 MiB/frame and
128 MiB aggregate limits. In-flight API calls have independent 10-second
timeouts. Every frame includes dimensions, hashes and controller timing.

## Explicit keyboard probes and maintenance

Review a current private screenshot first, then supply its full SHA256:

```text
python -B test/e2e/appliance/esxi/visual-key.py --scope SCOPE --label splash-esc --key esc --expected-screen-sha256 REVIEWED_SHA256
python -B test/e2e/appliance/esxi/visual-key.py --scope SCOPE --label kernel-vt --key alt-f12 --expected-screen-sha256 REVIEWED_SHA256
python -B test/e2e/appliance/esxi/visual-key.py --scope SCOPE --label return-menu --key alt-f1 --expected-screen-sha256 REVIEWED_SHA256
```

Each command acquires `operation.lock`, captures and checks that the screen
still matches the reviewed hash, records intent, sends exactly one named key,
and retains before/after frames. A changing splash or blinking cursor can
cause a safe refusal. ESC is only for a reviewed visible splash; never send it
unattended or during PAM. Alt+F12 and Alt+F1 are the only VT probes; there is no
arbitrary key/text option. A missing completion receipt after intent means
ambiguous input: inspect evidence rather than retry automatically.

For maintenance, start another observer with a new label before the existing
authenticated maintenance dispatcher; the observer never dispatches reboot.
It permits the real lifecycle phases and bounded powered-off transitions.
The access-aware lifecycle normally leaves the ledger `powered-on`; the
legacy qualifier may use `qualification-started`, `restore-qualification-started`
or `baseline-completed`. Deleted ledgers, unknown phases and either fixed P1
identity-reset attempt namespace are refused. Reset visual coverage belongs
to the separate reset/bootstrap workflow.

## Review criteria and guest diagnostics

Review cold and maintenance frames for centered Culvert branding, readable
service progress, no stale corner text or blank graphics terminal, and the
menu/setup address at the dimensions actually reported by the captures.
Verify ESC exposes diagnostics and Alt+F12 shows the kernel VT; Alt+F1 must
return to a readable menu without weakening authentication. Retain the
initial credential screen privately. Delayed/failed-service rendering and
serial-only boot remain **NOT RUN** until separately bounded lab fixtures
are agreed and executed; these helpers do not stop or mask product services.

Run `visual-console-inspect.py` only through the existing authenticated local
PAM/sudo `gpriv` transport (use a 60-second outer command bound). Its optional
`--test-console-open` performs only an empty `: > /dev/console`, with TERM at
three seconds, KILL one second later and a six-second controller subprocess
bound. It records actual inherited getty `TTYReset`, tty1 `KDGETMODE`, active
VT, dimensions, splash/kernel-VT unit results and current-boot kernel journal.
It never performs `KDSETMODE`, resets getty, changes boot configuration, or
opens administrator SSH. Every command outcome is an observation; a blocked
diagnostic must not become PASS. BIOS absence of an EFI/ubuntu directory is
not itself a bootloader failure.

## Source findings to verify on ESXi

Compared with `2e3bcc2a`, the candidate adds `nomodeset`, Plymouth
`DeviceTimeout=0.1`, a shorter centered title, display-aware Plymouth startup,
and best-effort `KDGETMODE`/`KDSETMODE(KD_TEXT)` before console menu frames.
These address a late vmwgfx resolution switch and a getty text-mode reset
that can fail when `/dev/console` targets a missing serial device. Ubuntu's
bootloader identity and the local PAM/operator SSH boundary remain intact.

The new kernel VT service redirects future kernel messages to tty12 and
copies the last 300 lines there. Its best-effort `setlogcons` means service
success alone does not prove visible routing. Verify the actual VT. The
product comments also acknowledge that visible Plymouth temporarily hides
messages on serial; journal retention is not continuous serial display.
Headless PCI detection skips/quits Plymouth, which needs separate serial-only
qualification. Plymouth message/quit invocations in the initramfs script
have no explicit command timeout; a wedged client is an untested residual
case, not an observed defect in this run.

All PNGs, raw journal output, keyboard receipts and frame metadata stay under
the restricted run secrets directory. They may expose passwords or other
private state. Do not publish them automatically. Public reporting should
contain reviewed conclusions, source/controller hashes and explicit coverage
gaps, with separately reviewed/redacted images only if needed.
