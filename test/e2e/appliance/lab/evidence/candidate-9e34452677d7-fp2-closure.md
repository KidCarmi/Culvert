# F-P2 closure proof — candidate 1.5.4 (lab run 38890228477)

The F-P2 isolated reproduction (owner follow-up item 2) run as a control +
candidate matrix, each with a hard verdict on the number of EICAR streams
answered a bare clean ("stream: OK") — the detection bypass.

| entry | clamd | sidecar | wrong-cleans (EICAR to bare OK) | verdict | result |
|---|---|---|---|---|---|
| control-1.4.6-bad788e5 | ClamAV 1.4.6/28136 | culvert/clamav:1.4.6-culvert.3 (retained bad788e5 OVA) | 60 | expect > 0 | PASS — the bug reproduces |
| candidate-1.5.4-9e344526 | ClamAV 1.5.4/28150 | culvert/clamav:1.5.4-culvert.1 (baked in the candidate OVA) | 0 | expect 0 | PASS — F-P2 closed |

Both entries run the identical scripted INSTREAM client against the EXACT
sidecar extracted from each OVA (archive sha256 -> image id -> config, every
link re-hashed), stock clamd.conf, freshclam OFF, clamd's temp dir on its own
256 MiB loop ext4 so the fill exhausts the spool and nothing else. The 1.4.6
control answers a bare clean to 60 EICAR streams at the temp-dir-exhaustion
edge; the 1.5.4 candidate answers none, because 1.5.x runs the per-scan mkdir
only under the debug LeaveTemporaryFiles option (off by default), so the
scan_common path that rewrites the failed mkdir to a clean verdict is never
reached. The control proves the harness exercises the defect, so the
candidate's zero is meaningful rather than a harness that stopped testing.

Verdict mechanism: fp2-isolated-report.py --count (same classification as the
table), asserted in the job against the matrix's expectation. Evidence
artifacts: appliance-lab-fp2-isolated-control-1.4.6-bad788e5 and
appliance-lab-fp2-isolated-candidate-1.5.4-9e344526 (per-conversation sent-byte
sha256, verbatim reply, timing, temp free, clamd log, signature set, image
binding).

_Cache-bypass regression re-run on the 1.5.4 engine against the candidate OVA; the 60s clean-verdict quarantine logic is Culvert code, unchanged by the engine bump._
