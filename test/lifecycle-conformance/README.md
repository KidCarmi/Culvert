# Lifecycle conformance (shadow)

A deterministic, model-based check of the maintenance agent's `upgrades.apply`
lifecycle. **Shadow only: it is not a merge gate and must not be made one
without explicit owner approval of the properties it reports.**

## What it is

1. `model/culvert_apply.py` — a small explicit-state model of the apply flow:
   stages, write-ahead journal barrier, tag move, `compose up`, inline rollback,
   crash points.
2. `verify/` — a breadth-first model checker with state, transition and
   bounded-temporal properties. Counterexamples are shortest traces.
3. `gen_vectors.py` — derives every fault path (172), every crash point (147)
   and the full bounded input space of the recovery decision (435,456) from the
   model. No randomness.
4. `cmd/culvert-maint/internal/server/model_conformance_test.go` — replays
   those vectors against the **real** server, journal, orchestrator and runner.
   Only the process-exec layer and the health HTTP client are faked.
5. `mutation/mutate.py` — scheduled mutation campaign (see below).

## What a pass means — and does not mean

| Claim | Supported? |
|---|---|
| The agent's own Go logic behaves as the model says on every modelled path | Yes — executed against the real code |
| Docker behaves as the fake exec layer assumes | **No** — an assumption; validate against real Docker (`test/e2e/maint-agent`) |
| Startup crash recovery works end to end | **No** — the model's agent-restart step is not executed |
| Standalone/data rollback, migration, timeouts, concurrency are correct | **No** — not modelled |
| The properties are Culvert's contract | **No** — every property is `proposed` or `open`; none is owner-approved |

The model checker by itself verifies an abstraction. Only the conformance test
touches product code. Do not present either as "the lifecycle is verified".

## Running

```bash
test/lifecycle-conformance/run.sh /tmp/lifecycle-report
```

| Exit | Meaning |
|---|---|
| 0 | Model check complete; all three conformance suites ran and passed |
| 1 | A conformance vector mismatched the real code, or an owner-**approved** property failed |
| 2 | Incomplete: state/time budget hit, a vacuous property (its trigger is unreachable), a skipped or missing suite, or the properties file changed during the run. Never reported as a pass |

A failing `proposed` or `open` property is printed with its shortest trace and
does **not** change the exit code: the tool reports on unapproved properties,
it does not define the contract.

The conformance test carries the build tag `lifecycle_conformance`. A plain
`go test ./...` neither compiles nor runs it, so no existing gate changes.

## Property status

`model/properties.json` holds a `status` per property:

- `proposed` — checked and reported; never fails the run.
- `open` — a known open product question (linked to `contracts/registry.yaml`);
  reported only.
- `approved` — fails the run when violated. **Set only by the owner**, in the
  same change that records `owner_approved: true` for the matching registry
  contract. The checker verifies the file's hash is unchanged by its own run.

## When a conformance vector mismatches

A mismatch means the code and the model disagree. Either is legitimate:

- The change is unintended → fix the code.
- The change is intended → update `model/culvert_apply.py` in the same pull
  request, and say so in the description. The model is a second, independent
  statement of the lifecycle; keeping the two in step is the point.

## Workflows

- `.github/workflows/lifecycle-conformance-shadow.yml` — pull requests touching
  `cmd/culvert-maint/**`; under a minute; no secrets, no Docker, no network
  services. Not in the required checks.
- `.github/workflows/lifecycle-mutation-campaign.yml` — weekly and on demand.
  Mutates temp copies of seven lifecycle source files and records which mutants
  the existing tests and the conformance suite each kill. About 1h40m on four
  cores for 350 mutants, hence scheduled only.

Baseline measured at `ef94311` (350 mutants, 343 compiled): existing tests
killed 260 (75.8%), conformance alone 243 (70.8%), both together 277 (80.8%);
17 mutants were killed only by conformance, mostly journal-phase bookkeeping
that existing tests do not observe mid-flight. The conformance suite does not
replace the existing tests (34 kills are theirs alone).

## Promotion to a required gate

Not before all of:

1. The owner approves or rejects each property.
2. The fake-Docker assumptions are checked against real Docker.
3. Several weeks of shadow runs without a false alarm.
4. The check's name states its scope (`upgrades.apply` only) or the model grows.
