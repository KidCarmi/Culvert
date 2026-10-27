# Fail-closed receipts for the M2 checkpoint verdicts (ASTRA 27 Oct 16:10, item 1)

Lab commit `69fb5f364ee19155f5bd7360f91d0509be38845a` on `test/appliance-lab`. sha256 of the files used:

| File | sha256 |
|---|---|
| `m2-guest.sh` | `158310c31516b536fc057e159c3622eac8b47f3702d903c66aa9d3a62fab4663` |
| `m2-verdict.py` | `c823d3b6efa9ee385e7f2146832e84368e7003e0a52cde2b27feb09715ccee37` |
| `m2-verdict-selftest.py` | `7ca793695471b42f2cfd74d9361ceb1d77f3dd60e5af08e2099efb58edc399db` |
| `m2-fixtures/pass.txt` | `b8a483816b21e1586581ec52c957cd0144a2519dc13404aff38d4fdc99c31365` |

| Receipt | Shows |
|---|---|
| `01-selftest.txt` | The passing fixture passes. The valid-empty cases (a container ruleset with no tables, an empty container IPv6 route table) pass. Each failure mode fails the named check with the named reason: failed or empty `ip`, failed `tc`, failed or empty module read, `nft` failing, absent or printing error text, a missing appliance table, payload writes, queue, exthdr, socket, TPROXY, flowtable, an extra netns, unreadable sysctls, held rings, live-but-unreadable processes, ordering, transport, truncation, the probe, and EICAR. **51 cases, 0 wrong.** |
| `02-mutation-rc.txt` | With the exit-status requirement removed, the self-test reports 14 WRONG cases and exits 1. |
| `02-mutation-lo.txt` | With the loopback positive control removed, it reports 1 WRONG case and exits 1. |
| `03-sandbox-real-*` | `m2-guest.sh` run for real in the producer sandbox (Docker 29.6.2, two stand-in containers). Each facility the sandbox lacks fails closed with its real reason: systemd, IPv6, `/proc/modules`, clamd, the appliance table, and the e1000/vmxnet3 NIC. |
| `04-stubbed-*` | The same run with `ip` failing (rc 1) and `nft` absent (rc 127) on PATH. Recorded as failures; preconditions and ruleset fail. |

**Limits:**
- These are producer-side runs. The sandbox is not the appliance guest, and the passing fixture substitutes the records its header lists.
- The guest-side run predates one line, the shellcheck directive comment at the top of `m2-guest.sh`; no behaviour changed.
- Nothing here is a guest-runtime result. That comes from the one replacement run.
