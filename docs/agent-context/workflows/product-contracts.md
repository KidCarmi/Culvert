# Changing behavior covered by a product contract

Scope: any change to code under a `code` path of an entry in
[contracts/registry.yaml](../../../contracts/registry.yaml). The
[design](../../engineering/PRODUCT-CONTRACTS.md) explains the gate and its limits.

Find the entries you touch:

```
go run ./cmd/contractcheck impact -base origin/main
```

Before modifying the behavior:

1. **Name the affected contract IDs.** Critical behavior with no entry is not
   exempt. Say so and propose an entry; do not assume it is free to change.
2. **State whether customer-observable behavior changes**, in one sentence an
   operator would understand.
3. **Name the authority that owns the behavior** (the entry's `authority`). Do
   not infer ownership from names, defaults or what the code happens to do.
4. **Assess deployed state:** upgrade, downgrade, backup/restore and recovery.
   On-disk and wire formats already exist on customer machines.
5. **Add or update executable contract tests** beside the owner. Never delete,
   skip or loosen a registered test, and never edit the registry so that an
   implementation passes.
6. **Escalate an intentional contract change.** Add an `amended` or `retired`
   record with the reason, stop, and ask the owner. Do not set `owner_approved`.
   A review by an agent or a bot is advice, not that approval.

`open` entries are undecided questions, not rules: report the question, do not
resolve it by implementation. Passing tests, lint and scanners do not show that
a contract is intact.

Checks for a change to the registry or its tooling:

```
go test -race ./internal/contracts
go run ./cmd/contractcheck validate
```
