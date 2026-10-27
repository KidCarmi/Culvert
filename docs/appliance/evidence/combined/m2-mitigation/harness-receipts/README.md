# Fail-closed receipts for the M2 checkpoint verdicts

These answer ASTRA's 27 Oct 16:10 item 1 and 17:06 gaps 1–2. The lab commit is `e6bb0ff0d3be96449efcb65cd7f34b45658f3c39` on `test/appliance-lab`.

sha256 of the files used:

| File | sha256 |
|---|---|
| `m2-guest.sh` | `d21f8ebfe3c728e276781580d79f2c005c50e10ac4b85fb9233e79f86eb4ff02` |
| `m2-verdict.py` | `f82012297565975e1a6c327a24f051ea87f88dd813ed6ce1ac2ed1502199dc9f` |
| `m2-verdict-selftest.py` | `26a04cf6f848216f1fbff1addddb1a5ba89980e5556e61f62180b32d42edb54f` |
| `m2-fixtures/pass.txt` | `d4405f458cca2e0c5312384ac22beeae80517c6d6382ecd3bd870e90ccbca059` |
| `m2-fixtures/nested-nft.txt` | `1a876646ec75cc8e5cf73fec798bacee5a7232f69a429b1e4d971cf187394f9b` |

| Receipt | Shows |
|---|---|
| `01-selftest.txt` | **87 cases, 0 wrong.** The passing fixture passes, and the valid-empty and confirmed-disappearance cases pass. Each failure mode fails the named check with the named reason. |
| `02-mutations.txt` | Nine mutations of `m2-verdict.py`. Each is caught: the unmodified self-test exits 1. |
| `03-sandbox-real-*` | `m2-guest.sh` run for real in the producer sandbox (Docker, two stand-in containers). |
| `04-stubbed-*` | The same run with `ip` failing (rc 1) and `nft` absent (rc 127) on PATH. |
| `05-docker-down-*` | The same script with the Docker daemon stopped. |
| `06-disappearance.*` | The census functions are taken verbatim from `m2-guest.sh`. Three real processes are killed at the moment the census reaches each one. |

**What `01-selftest.txt` covers:**
- **Earlier failure modes:**
  - acquisition: failed or empty `ip`; failed `tc`; failed or empty module read;
  - `nft`: failing, absent, or printing error text; a missing appliance table;
  - forbidden rules: payload writes, queue, exthdr, socket, TPROXY, flowtable;
  - hardening and ordering: unreadable sysctls, ordering;
  - run integrity: transport, truncation, the probe, and EICAR.
- **New, census:**
  - outcomes: live-but-unreadable fd directories, namespaces and descriptors fail;
  - counting: summary/line disagreement, a missing counter, a missing summary, and an unrecognised line all fail;
  - reconciliation: an extra namespace fails, and so does an expected context missing from the census;
  - coverage: an unacquired container context fails as "only 2 of 3 … acquired".
- **New, containers:** a failed `docker top`, a non-numeric pid, a listed pid with no outcome or two outcomes, and a pid read but not listed all fail. A listed pid that exited before its read passes.
- **New, nested operands:**
  - **real `nft -j` output** (`m2-fixtures/nested-nft.txt`): six reviewed shapes pass, and `ct mark set socket mark`, `jhash` and `numgen` fail;
  - **synthetic shapes:** an exthdr in a map's data, an unknown NAT/payload/log field, an expression in a counter parameter, and a two-key operand all fail.

**What `02-mutations.txt` shows** (each mutation is caught):

| Mutation | WRONG cases |
|---|---|
| exit status ignored | 15 |
| loopback control removed | 1 |
| expected-namespace reconciliation removed | 1 |
| unreadable namespace accepted | 1 |
| unreadable descriptor treated as vanished | 1 |
| unreadable fd directory accepted | 1 |
| docker-top reconciliation removed | 2 |
| nested-operand validation removed | 9 |
| summary counter set not enforced | aborts with `KeyError` (exit 1) |

**What `03`–`06` show (real collector outcomes):**
- **Unreadable state that still exists fails.** The sandbox's PID 1 cannot be read even by root, so `fd-unreadable` ×21 and `unreadable-alive` are recorded and both checks fail (03, 04, 05).
- **Reconciliation.** In 03, the census namespaces reconcile with the three acquired contexts: there is no extra/missing failure.
- **Failed context acquisition.** In 05, `culvert pid: rc=1 Cannot connect to the Docker daemon…` is reported, and coverage fails as "only 1 of 3 context namespaces acquired".
- **Stubbed tools.** In 04, the stubbed `ip`/`nft` failures are recorded per context and fail preconditions and ruleset.
- **Confirmed disappearances.** In 06, each process killed at its fd-directory or namespace read is recorded as `exited`. The one killed at its first descriptor read is recorded as `fd-vanished` ×3. None is counted as a failure. In the same run, PID 1 is still `fd-unreadable` / `unreadable-alive`.
- **The other sandbox failures are real absences:** systemd, IPv6 sysctls, `/proc/modules`, clamd, the appliance table, and the e1000/vmxnet3 NIC.

**Limits:**
- These are producer-side runs. The sandbox is not the appliance guest. The passing fixture substitutes the records its header lists.
- `06` forces the timing with `ls`/`readlink` wrappers. The disappearance is real; the moment is chosen.
- Nothing here is a guest-runtime result. That comes from the one replacement run.
