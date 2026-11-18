# Chaos engineering review — 2026-11-17

Reviewer: Culvert Chaos Engineer (automated round). Base revision `84b1b4c`
(`origin/main`), clean worktree at branch point. Recorded separately for the
reason the previous rounds were; [the register](../../roadmap/CHAOS-ENGINEERING-REVIEW.md)
stays the index.

Id claimed: **CHAOS-122**, in a committed placeholder row as commit one, before
any code, checked against `origin/main` rather than the working tree per the
register's 2026-09-25 amendment. `CHAOS-121` was the highest id anywhere on
`origin/main` at `84b1b4c`, and no open PR held a chaos id (#1931, #1705, #1549,
#1548, #1536, #1528, #1526 — #1931 is a terminology review, the rest are the
appliance and policy-design lines).

Every `file:line` below is at the **base revision** `84b1b4c`, so the defect
citations stay readable against the tree as it was before this round's edits.

---

## CHAOS-122 — The argv contract: the binary accepted command lines it could not parse, and booted with the rest of them discarded

Scope: **the handoff from the orchestrator to the process.** This round was
handed to it by name. CHAOS-121 found that `docker-compose.ha.yml` silently
discarded every flag it declared, fixed that one artifact, and recorded the
generic guard in its §10 with the decisive fact attached:

> **A `flag.NArg()` guard in `main`.** … It is the fail-closed answer to the
> class and it is recommended as its own change. It is deliberately **not** done
> here, and the reason is concrete rather than scope-shaped: **positional
> arguments are legitimately load-bearing on one path.**

So this round's job was the audit that note asked for, and then the guard. The
audit found the note's premise was right and its count was one short.

---

## 1. Executive summary

**CHAOS-122a (HIGH) — `main` called `flag.Parse()` with no `flag.NArg()` guard,
so an argv with an unparsed token started the gateway with every flag after that
token at its default, and reported healthy.**

Go's `flag` package stops parsing at the first argument that does not begin with
`-` and leaves it, and everything after it, in `flag.Args()`. `main.go:387`
called the package-level `flag.Parse()`; `handleOneShotCommands` (`main.go:413`)
dispatches on **flags** only, so nothing matched, nothing errored, and the
process fell straight through into normal startup.

CHAOS-121a was one instance of this. The reason it needs fixing in the binary
rather than only in the artifact is that **the static compose gate cannot reach
an orchestrator the repository does not ship** — a systemd unit, a Kubernetes
manifest, a hand-written `docker run`, or an operator pasting a documented
command line into a `command:` key. The image's exec-form
`ENTRYPOINT ["./culvert"]` means Docker *appends* a container command, so any
`command:` whose first token is not a flag reproduces the whole class.

**The partial case is sharper than the total one, because the surface still
looks configured.** Measured on the real binary at this revision, not inferred:

```
./culvert -port 18080 -ui-port 19090 STRAY_TOKEN \
    -policy <f> -audit-log <f> -ca-path <f>
```

| Observation | Result |
|---|---|
| Proxy + admin UI | came up on **18080/19090** — the flags *before* the stray token applied, so the deployment looks correct |
| `/health` | `{"status":"ok","uptime":"0m 1s",…,"ssl_inspection":"ready","admin_ui":"ready"}` |
| `/ready` | top-level `"status":"ready"`, with `policy_loaded: {"status":"fail","detail":"no rules"}` — the row is report-only, it does not gate |
| The three files the dropped flags name | **none created**: no `policy.json`, no `audit.jsonl`, no `ca.bundle` |
| Startup policy posture | `Policy: default action: allow`. The same argv **without** `STRAY_TOKEN` logged `Policy: default action: deny` |
| Any mention of `STRAY_TOKEN` | **none**, in any log line, on stdout or on stderr |

The posture line is the part that matters most. Dropping `-policy` does not
merely lose rules — it **inverts the default action**, because of the documented
configured-vs-empty rule ([errata](../agent-context/errata.md)): a configured
policy file denies even with zero usable rules, an absent one allows. The
control arm proves it: with the same policy file reached, the node logged
`default action: deny` and `1 rule(s) loaded`; with the stray token it logged
`allow` and `Policy: in-memory only`.

**This was a legibility failure, not a dark one, and the distinction is the
finding.** The per-subsystem degradation *is* logged:

```
UIUsers: WARNING — no roster file configured, so the admin roster is IN-MEMORY ONLY…
SSLCA: Root CA ready in-memory (set -ca-path + CULVERT_CA_PASSPHRASE for persistence)
Policy: in-memory only (set -policy <file> for persistence)
Policy: no rules configured; defaulting to Allow (passthrough).
```

Those lines are **identical to the ones a deliberately minimal deployment
emits.** Nothing distinguishes "the operator chose not to set `-policy`" from
"the orchestrator discarded the operator's `-policy`". An operator who reads
them concludes the node is configured the way it was asked to be. That is why
the fix is a refusal and not another warning: the correct signal is that the
process must not run at all.

**CHAOS-122b (MEDIUM) — `bootstrap-resolve`'s own FlagSet had the same defect,
and the flag it would discard is the anti-rollback floor.**

The subcommand parses into its own `flag.FlagSet` (`bootstrap_resolve.go:102`)
and had no `fs.NArg()` check either. The flag that matters is `--data-dir`,
which carries the rollback floor `scripts/install.sh` stages from a surviving
`proxy-data` volume (`stage_rollback_floor`, `install.sh:928`) so that a
reinstall cannot be silently downgraded below the version the host last
accepted — the mirror-replay downgrade the flag exists to close. A stray token
ahead of it resolves with floor 0 **and still prints a well-formed
`image_ref`**, so the installer's strict output-shape gate (`repo@sha256:<64
hex>`) would not have caught it; the fail-closed property there belongs to the
caller's shape gate, not to the parser.

Honest likelihood: the installer's own argv is correctly quoted and the
`--data-dir` pair is appended only when `stage_rollback_floor` succeeded, so the
installer was **not** itself exposed. The exposed shape is the hand-run form the
runbook documents (`catalog-bootstrap-install-runbook.md:107`) and any appliance
script that composes it.

**CHAOS-122c (LOW) — the privileged maintenance agent had it too.**

`cmd/culvert-maint/main.go:42` would have silently dropped `--config`, which
selects the config file and through it the journal, the compose path and the
command allowlist the agent runs under, and run against the built-in default
path instead. The shipped systemd unit passes a `--config` equal to that
default (`packaging/systemd/culvert-maint.service:56`), so it was unaffected
either way; a deployment whose config lives elsewhere was not.

---

## 2. The audit CHAOS-121 asked for

The note said a blanket guard breaks a shipped command and a correct guard must
be conditional. That is right. The audit found **two** positional consumers in
the shipped surface, not one — and the second one is why the guard's placement
matters more than its condition.

| Shape | Positional? | Disposition |
|---|---|---|
| `culvert bootstrap-resolve …` (`bootstrap_resolve.go:86`) | **yes** — `argv[1]` is the subcommand | Dispatched from `maybeRunBootstrapResolve` **before the global flag set is defined** (`main.go:192`) and it `os.Exit`s. It never reaches `flag.Parse`, so the guard neither sees nor affects it. CHAOS-121 §10 did not list this one; it is the reason the guard is safe to place where it is rather than needing a second exception. |
| `culvert --prepare-downgrade … --confirm <word>` | **yes** — one operand | The single exception. `--confirm` is an `IsBoolFlag` (`upstream_downgrade.go:301`), so it does not consume the following token and the Tier-3 word lands in `flag.Args()`, recovered by `prepareDowngradeConfirmWord` (`upstream_downgrade.go:314`). |
| `cli` service, `command: ["-h"]` | no | flags only |
| `docker compose --profile cli run --rm cli <flags>` | no | flags only |
| Maintenance agent compose-run templates (`templates_d16b.go:193-264`) | no | `--restore <path>`, `--older-than <dur>`, and a **bare** `--confirm` |
| Dockerfile `CMD` (`Dockerfile:208`) | no | flags only |
| `scripts/install.sh` | no | flags only, and correctly quoted |
| Every other compose `command:` | no | flags only (CHAOS-121's gate 1 keeps them that way) |

**The exception defers rather than duplicates.** `prepareDowngradeConfirmWord`
already rejects an unexpected tail, in three shapes (no word after a bare
`--confirm`; a word *and* a tail; a tail after `--confirm=<word>`). The guard
therefore stands aside for that one-shot entirely instead of adding a second,
weaker owner of the same tail — and a gate pins that the validator still does
its job, because the exception is only correct while that holds.

---

## 3. Failure scenarios

Each row is the pre-fix behaviour, verified on the real binary unless marked.

| # | Scenario | Pre-fix behaviour | Post-fix behaviour |
|---|---|---|---|
| 1 | Exec-form entrypoint + shell `command:` (CHAOS-121a's shape) | boots, all defaults, `/health` ok | `FATAL: refusing to start: 3 unparsed command-line argument(s) beginning with "sh"`, exit 2 |
| 2 | Stray token mid-argv, security flags after it | boots on the expected ports, **no CA, no policy, no audit**, posture flipped `deny`→`allow` | refused, exit 2, nothing written |
| 3 | Mistyped subcommand (`culvert bootstrapresolve --channel stable`) | **started a full proxy + admin UI** | refused, exit 2 |
| 4 | `--` terminator with flags after it | flags after `--` discarded silently | refused, exit 2 |
| 5 | `--restore <archive> --confirm <word>` | restore **committed**, `<word>` silently ignored | refused (deliberate change, §6) |
| 6 | `bootstrap-resolve … stray --data-dir <floor>` | resolved with **floor 0**, printed a valid `image_ref` | refused, exit 2, stdout empty |
| 7 | `culvert-maint stray --config <path>` | ran against the **default** config/journal/allowlist | refused before the config is read or the socket bound |
| 8 | `command: []` / no arguments at all | falls through into normal startup — a second proxy on the shared volume | **unchanged**: zero args means zero positionals, so this guard does not see it. Still mitigated only by the `cli` service's `["-h"]` (§8) |

Scenario 8 is stated as a non-fix deliberately: it is a different defect with
the same consequence, it is recorded as CHAOS-121 §7.1, and a guard on *absent*
argv is a daemon/one-shot distinction, not an argv-parse check.

---

## 4. Risk matrix

| Id | Severity | Likelihood (pre-fix) | Blast radius | Detection before this round |
|---|---|---|---|---|
| 122a | **HIGH** | **Realised at least once** — CHAOS-121a was this defect in a shipped artifact, and had been since the file existed | A node that forwards traffic with no policy file, no audit trail, no persisted Root CA, and a default action inverted from deny to allow | `/health` ok, `/ready` ready with a non-gating failed row, per-subsystem warnings indistinguishable from a deliberate minimal deployment. **No signal naming the cause.** |
| 122b | MEDIUM | LOW — the installer's own argv is safe; the documented hand-run form is not | A reinstall accepted below the host's recorded rollback floor (mirror-replay downgrade) | None. The installer's output-shape gate does not fire, because the output is well-formed |
| 122c | LOW | LOW — the shipped unit passes the default path | A privileged agent on a different journal, compose path and command allowlist than the operator configured | None at the argv layer; a missing default config would have failed loudly, an existing one would not |

---

## 5. Recovery assessment

| Property | Pre-fix | Post-fix |
|---|---|---|
| Automatic recovery | **None.** The process is healthy by its own report; nothing retries, nothing escalates, nothing degrades. The misconfiguration is stable and survives every restart | N/A — the process refuses to start, so there is no degraded state to recover from |
| Manual recovery | Requires an operator to *suspect* the argv. The nearest available evidence is a set of warnings that read as normal | The refusal names the rejected tail, the discarded-flag consequence and the exec-form-ENTRYPOINT cause, on stderr, at exit 2 |
| Data integrity | A boot with no `-ca-path` mints a **new Root CA**, so every client's installed trust anchor breaks; no `-audit-log` means the compliance record for that window does not exist and cannot be reconstructed | The refusal runs **before** the one-shot dispatch and therefore before `checkInterruptedRestore`, `checkDataDirSingleWriter` and anything that writes to the persisted-state root. Verified: the data dir has **0 entries** after a refusal |
| Failure mode | **Fail open**, silently | **Fail closed**, loudly — a crash loop with a diagnostic, which is the orchestrator-visible signal the class needs |

The "nothing on disk changed" half is a property of *where* the check sits, not
of what it returns, so it is pinned by its own gate: a reorder would keep the
refusal and silently lose the guarantee.

---

## 6. What changed, including one deliberate behaviour change

- `argv_guard.go` (new) — `refusePositionalArgs` (pure, table-tested) and the
  `checkPositionalArgs` seam over the real flag set. The file carries the
  measurement and the audit table, so the next reader does not re-derive them.
- `main.go` — the call, between `parseFlags` and `handleOneShotCommands`, with
  `os.Exit(2)`: the flag package's own usage-error code, which
  `runBootstrapResolve` already returns for this class.
- `bootstrap_resolve.go` — `fs.NArg()` refusal, exit 2, stdout left empty so the
  installer's shape gate never sees a partial answer.
- `cmd/culvert-maint/main.go` — `flag.NArg()` refusal before the config is read.
- `Dockerfile` — the contract recorded beside the `ENTRYPOINT` that causes it,
  which is where someone composing a `command:` actually looks.

**Deliberate behaviour change.** `--restore <archive> --confirm <word>`
previously committed the restore and silently ignored `<word>`; it is now
refused. An operator who typed a word meant it, and committing a restore while
discarding part of the argv is precisely the failure mode this change exists to
remove. The documented bare `--confirm` commit form is unaffected, as is the
maintenance agent, which appends a bare `--confirm`.

---

## 7. Operational, security and monitoring impact

**Operational.** The misconfiguration changes from a silently wrong healthy node
to a container that will not start. That is strictly better for a gateway whose
posture is "fail closed when recovery is impossible", and it is the shape an
orchestrator can act on: a crash loop is visible to `docker compose ps`, to a
restart-count alert and to a Kubernetes `CrashLoopBackOff`, none of which a
healthy-but-unpoliced node triggers. The cost is that an operator who was
unknowingly running a mangled argv now gets a stopped node instead of a running
one — which is the intended trade and should be called out in release notes.

**Security.** The pre-fix worst case is a node that forwards traffic with the
default action inverted from deny to allow, no policy file, no audit record of
what it allowed, and a Root CA regenerated on every boot. The audit gap is the
one that cannot be repaired after the fact.

**Monitoring visibility.** Unchanged by this round, and worth stating: `/health`
is liveness and correctly reported ok, and `/ready`'s `policy_loaded` row *did*
report `fail` while the top-level status stayed `ready`, because the row is
report-only unless `?strict=1`. So the readiness surface carried the evidence
and did not gate on it. That is a posture decision outside this round's scope,
recorded in §8.

---

## 8. Suggested improvements not taken

- **`/ready`'s `policy_loaded` row gates nothing by default.** During the
  reproduction the row read `{"status":"fail","detail":"no rules"}` while the
  envelope read `"status":"ready"`. For the argv class this no longer matters —
  the process refuses to start — but for every other route to an unpoliced node
  it does. Making it gate is a readiness-posture change with its own
  compatibility surface (orchestrators keyed on `/ready`), not a chaos round's
  to take unilaterally.
- **The no-arguments case (scenario 8) is still only mitigated by `["-h"]`.**
  `command: []` produces zero positionals, so this guard cannot see it, and
  `test/e2e/maint-agent/docker-compose.backup-e2e.yml` still carries that shape
  — the one `docker-compose.yml` was fixed away from. The real remedy is the
  `culvert daemon` subcommand CHAOS-121 §10 proposed, which makes "no flags"
  unambiguous; it is a wire-compatibility change.
- **`flag.NArg()` elsewhere.** `cmd/mcp-observe-acceptance` and `cmd/apibundle`
  have the same unguarded `flag.Parse()`. Both are developer tools, neither
  runs in a customer deployment, and neither holds a security posture; they are
  recorded rather than changed so the class is fully enumerated.
- **An HA smoke CI job.** Still the right remedy for "no CI job has ever brought
  `docker-compose.ha.yml` up", still out of scope, still recorded.

---

## 9. Required tests, and the mutation matrix

Six gates untagged (required lanes), one behind `proxybinload` — the tag the
existing real-binary gate for this same class
(`docker_compose_cli_no_second_proxy_test.go`) already uses — and one in the
agent module.

| Gate | Pins |
|---|---|
| `TestChaos122_RefusePositionalArgs` | the decision, 7 cases: the `sh -c` shape, a mid-argv stray, a mistyped subcommand, both prepare-downgrade forms, and two negative controls |
| `TestChaos122_PrepareDowngradeStillOwnsItsTail` | that the exception's own validator does reject an over-long tail — the exception is only safe while this holds |
| `TestChaos122_RefusalMessageNamesTheCauseAndTheTail` | the message is actionable without the source |
| `TestChaos122_RefusalSanitizesTheArgvItEchoes` | the CWE-117 barrier on operator-supplied argv (`sanitizeLog` + `%q`) |
| `TestChaos122_GuardRunsBeforeTheOneShotDispatch` | the **ordering**, and therefore the "nothing on disk changed" guarantee |
| `TestChaos122_BootstrapResolveRefusesAPositionalTail` | 122b, plus a negative control on the installer's real argv shape |
| `TestChaos122_RealBinaryRefusesTheComposeArgvAndWritesNothing` | the shipped binary: exit 2, the refusal on stderr, **0 entries** in the data dir, and a flags-only one-shot control that still works |
| `TestChaos122_AgentRefusesAPositionalTail` (agent module) | 122c, plus a `--version` negative control |

**Mutation matrix.** Every gate was verified failing against the pre-fix shape.

| Mutation | Result |
|---|---|
| Remove the `checkPositionalArgs` call from `main()` | ordering gate FAILS; real-binary gate FAILS: *"the binary did not refuse this argv: it was still running after 25s, i.e. it became a gateway with no persisted Root CA, no policy and no audit log while /health reported ok"* |
| `refusePositionalArgs` always returns nil | 3 unit gates FAIL, naming each discarded tail |
| Remove the `bootstrap-resolve` `fs.NArg()` guard | 122b gate FAILS |
| Drop the `sanitizeLog` barrier | CWE-117 gate FAILS |
| Remove the agent's `flag.NArg()` guard | agent gate FAILS |

**One gate defect the mutation run found, and fixed.** The real-binary gate
first used an unbounded `cmd.CombinedOutput()`. Under the mutation the binary
does not exit — it becomes a running proxy — so the gate **hung** instead of
failing. A gate that hangs under the defect it pins is not a gate; it now runs
under a 25s deadline and reports the non-exit as the failure, which is what the
table above shows.

---

## 10. Verification

Commands and results at the final tree, base `origin/main` `84b1b4c`.

| Check | Command | Result |
|---|---|---|
| New gates (untagged) | `go test -run TestChaos122 -count=1 .` | 6/6 pass |
| New gate (real binary) | `go test -tags proxybinload -run TestChaos122_RealBinary -count=1 .` | pass (1.9s) |
| New gate (agent module) | `cd cmd/culvert-maint && go test -run TestChaos122 -count=1 .` | pass |
| **Mutation** | five mutations, §9 | **all five FAIL, with the intended messages** |
| Adjacent suites | `go test -run 'Downgrade\|Restore\|Bootstrap\|DockerCompose\|Chaos121\|Chaos56\|InstallScript\|Confirm\|OneShot\|Backup' -count=1 .` | pass (20.9s) |
| Dockerfile/image gates | `go test -run 'Dockerfile\|Docker\|Image\|Entrypoint' -count=1 .` | pass |
| Root package | `go test -count=1 .` | `ok … 428.795s` (one failure on the first run, fixed — see below) |
| Whole module | `go test -count=1 ./...` | **exit 0**, 0 failures across all packages |
| Both modules build | `go build ./...` in root and `cmd/culvert-maint` | pass |
| Guidance checker | `python3 docs/agent-context/check.py` | exit 0 |
| Lint, the gate's own command | `GOTOOLCHAIN=go1.27.4 go install …golangci-lint@v2.15.0` then `golangci-lint run --timeout=10m --new-from-rev origin/main` | **0 issues** |
| Lint, full tree vs the same measurement on the base | `golangci-lint run --timeout=20m` on this tree and on a `84b1b4c` worktree | **174 issues on both, byte-identical per-linter breakdown** — this round adds none. Required because `cyclop`/`funlen`/`gocognit` attribute to a function's DECLARATION line, so `--new-from-rev` cannot see that `main()` grew; it is not over any threshold (the only `main.go` entries, `parseFlags` funlen and `initLifecycleContext` unparam, are pre-existing and untouched) |

**A repository invariant caught a defect in this round's own test.** The first
version of the ordering gate read `main.go` with a CWD-relative
`os.ReadFile`, and `TestTestFileReadsAreCWDIndependent` failed it: such a read
can flake under a concurrent `os.Chdir`. It is now anchored to
`pkgSourceDir()`. Recorded because the wall worked exactly as intended on a
first-party change.

**Not run, and why.** No container was built or started: this environment has no
Docker daemon. The argv behaviour is therefore verified by executing the
**real binary** with the exact argv Docker composes, plus Docker's documented
ENTRYPOINT/CMD append semantics — not from a running container. The
traffic-level differential was attempted and is **excluded as inconclusive**:
both the deny arm and the allow arm forwarded a loopback destination with HTTP
200, so that probe isolates nothing, and the posture claim rests on the
`default action: allow` / `deny` startup lines and the absent files instead. No
claim is made here that an arbitrary request is allowed through a deny-posture
node.

---

## 11. Residual risk

- **The no-arguments shape (scenario 8) is untouched** and still reaches normal
  startup. `["-h"]` is a workaround in one file; `backup-e2e.yml`'s
  `command: []` still carries the shape the main compose file was fixed away
  from.
- **This guard cannot see a *semantically* wrong argv**, only an unparseable
  one. `-policy /wrong/path.json` is accepted, and a path that cannot be read is
  a separate contract.
- **`/ready` still does not gate on `policy_loaded`** by default, so a node that
  reaches an unpoliced state by any route other than argv is still `ready`.
- **No CI job brings `docker-compose.ha.yml` up**, so the HA topology's
  convergence remains gated statically rather than empirically.
- **The refusal is a crash loop.** For a deployment that was unknowingly running
  a mangled argv, this round converts a running node into a stopped one. That is
  the correct trade for a security gateway and it is a behaviour change on
  upgrade; it belongs in the release notes, not only in this document.
