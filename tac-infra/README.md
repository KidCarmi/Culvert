# tac-infra — moved

The TAC desired infrastructure state (OpenTofu modules, environments, provider
config, manifests, infra policy, monitoring, backup/DR) that formerly lived here
has been **extracted, with history preserved, to its own repository**:

> **https://github.com/KidCarmi/tac-infrastructure**

This directory is intentionally a pointer stub. The infrastructure repo holds
**only** desired state and consumes tac-platform's immutable artifacts **by
digest** (never a mutable tag). Culvert does not depend on it.

## Migration record
See [`/TAC-REPO-EXTRACTION.md`](../TAC-REPO-EXTRACTION.md) and the new repo's
`HISTORY-MIGRATION.md`.
