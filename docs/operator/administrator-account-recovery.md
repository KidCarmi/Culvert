# Administrator accounts — fenced writes, refusals and session invalidation

*Relevant to any node whose administrator roster is managed from the new
admin frontend (`/app/administrators`, FE-6A.2) or the admin API
(`/api/auth/users`, `/api/auth/lockouts`, `/api/auth/change-password`). The
roster is node-local (`-ui-users-file`, compose `/data/ui_users.json`).*

---

## 1. Fences

| Write | Fence (query string) | Missing | Stale |
|---|---|---|---|
| `POST /api/auth/users` (create) | `revision=` — the roster revision from `GET /api/auth/users` | `428 precondition_required` with `current.revision` | `409 stale` with `current.revision` |
| `PUT /api/auth/users` (role / password) | `revision=` | `428` | `409 stale` |
| `DELETE /api/auth/users?username=&revision=` | `revision=` | `428` | `409 stale` |
| `POST /api/auth/lockouts` (clear) | `generation=` — the lock-set generation from `GET /api/auth/lockouts` | `428` with `current.generation` | `409 stale` with `current.generation` |
| `POST /api/auth/change-password` (self) | `generation=` — the caller's own `securityGeneration` from `GET /api/auth/status` | `428` with `current.generation` | `409 stale` |

A stale write is never retried automatically. The frontend shows the token
it sent and the server's current one; reload the roster (or the lock set),
review, and submit again.

## 2. Refusals the frontend recognises (per endpoint)

| Code | Endpoints | Meaning |
|---|---|---|
| `user_exists` | create | the username is taken |
| `not_found` | update, delete, lockout clear | the target is gone — reload |
| `last_admin` | create, update (demotion), delete | the roster would be left with no administrator; the refusal is structured and final for this candidate |
| `invalid_credentials` | change-password | the current password you typed is wrong (403); nothing changed |
| `precondition_required` / `stale` | all | §1 |
| `persistence_not_configured` | create, update, delete, change-password | no `-ui-users-file`: the roster is in-memory and the write is refused rather than lost on restart |
| `persist_failed` | create, update, delete, change-password | the file write failed; nothing was applied |
| `invalid_input` | all | the body was rejected (weak password, unknown role, unknown field) |

A code the endpoint cannot emit, or an unrecognised code, is never rendered
as a verdict — the write is treated as unproven (§4). No server text is
ever shown.

## 3. Sessions

- A password change or a role change on another administrator invalidates
  that account's sessions (`sessionsRevoked` is the server's count;
  `selfAffected: false`).
- Your OWN password change (`/api/auth/change-password`, any role) answers
  `selfAffected: true`, re-issues your session cookie and invalidates every
  other device. The shell signs you out to the login boundary and clears
  every recovery marker; sign in again with the new credential.
- Deleting yourself, or changing your own role through the roster editor,
  also answers `selfAffected: true`; the frontend completes the teardown
  instead of continuing with a dead session.
- Revocation is durable: a pre-change cookie stays invalid across a
  restart.

The frontend claims a revocation ONLY from the server's own
`sessionsRevoked`/`selfAffected` facts. A lost or unverifiable response
claims nothing.

## 4. Unproven outcomes

A 2xx without a JSON media type, a body that does not decode, or a result
whose identity does not match the reviewed candidate is **unproven**: the
dialog closes (the password fields are dropped), the page latches every
mutation, the roster is re-read once (a transport death waits for
**Refresh**), and the roster shows what is true. Administrator writes carry
no operation identity — if a create was lost, reload: the account is either
on the roster or it is not.

## 5. Lockouts

The lock set is independent of the roster. **Clear** is a tier-2 ceremony
fenced on the lock-set generation, so a lock that appeared after you loaded
the page is never cleared by accident. Clearing resets the named account's
lock state (`404 not_found` when no such lock exists any more).

## 6. Ceremonies

| Action | Tier |
|---|---|
| Create account, change role, set a password | T2 review of the candidate (username, role, password presence) |
| Delete account | T3 — type the exact username; the roster revision is bound |
| Clear lockouts | T2, generation-bound |
| Change my password | current credential + generation |

## 7. Out of scope (recorded)

TOTP enrollment has no admin UI (GAP-2); a password update preserves an
existing TOTP binding. The roster read model states no persistence posture
— writes learn it as `persistence_not_configured`.
