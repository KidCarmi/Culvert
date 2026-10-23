# Preserved source: Build And Test

Historical evidence from main `3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af`, not current architectural authority.
Read the [current task routes](../README.md) and [verified errata](../errata.md) first.
No benchmark, status, location or instruction in these blocks is independently revalidated by moving it here.
Links inside preserved text retain their original spelling and source-root context; use each pinned source link to follow original references.
Do not import this file into startup instructions.

## Topics

- [Build and test](#claude-main-l092-l100)

<a id="claude-main-l092-l100"></a>

## Build and test

[Original lines 92–100](https://github.com/KidCarmi/Culvert/blob/3fcc07e7ab5d1e3bd4d19e6cadc8bb63b682f3af/CLAUDE.md#L92-L100) · `claude-main-L092-L100`

<!-- BEGIN preserved-block: claude-main-L092-L100 -->
## Build & Test

```bash
go build -o culvert .                       # build binary
go test ./...                               # run all tests
go test -race -count=1 -timeout=15m ./...   # race detector (CI mode)
go test -coverprofile=coverage.out ./...    # coverage report
```

<!-- END preserved-block: claude-main-L092-L100 -->
