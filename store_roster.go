package main

// store_roster.go — the FE-6A.0 Administrators roster transaction
// (FE-V37): every admin-API mutation of the ui_users.json roster commits
// PERSIST-BEFORE-PUBLISH under ONE mutation lock, fenced on the server-
// minted roster revision, with the last-admin guard decided against the
// candidate inside that lock. A persistence failure leaves the in-memory
// roster, the legacy mirror, the sessions and the revision untouched (R10,
// R11, R12, R13).

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var (
	errRosterLastAdmin     = errors.New("cannot demote or delete the last admin user")
	errRosterUserExists    = errors.New("user already exists")
	errRosterNotFound      = errors.New("user not found")
	errRosterPersistFailed = errors.New("persisting the admin roster failed; no change was applied")
	errRosterNotDurable    = errors.New("the admin roster has no persistence path configured; administrative mutations are refused")
)

// rosterStaleError carries the authoritative roster revision (409 stale).
type rosterStaleError struct{ Current int64 }

func (e *rosterStaleError) Error() string {
	return fmt.Sprintf("stale roster revision (current %d)", e.Current)
}

// rosterGenStaleError carries the authoritative per-user security generation
// (409 stale on the self-service password change, Blocker 1).
type rosterGenStaleError struct{ Current int64 }

func (e *rosterGenStaleError) Error() string {
	return fmt.Sprintf("stale security generation (current %d)", e.Current)
}

// userSecurityGen reads a record's generation with the pre-correction floor.
func userSecurityGen(u *uiAdminUser) int64 {
	if u == nil || u.securityGen <= 0 {
		return 1
	}
	return u.securityGen
}

// UserSecurityGeneration returns the durable security generation of a
// roster user. A legacy single-user deployment (identity only in the
// mirror) reads as generation 1; an unknown user reports ok=false.
func (c *Config) UserSecurityGeneration(username string) (gen int64, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if u := c.uiUsers[username]; u != nil {
		return userSecurityGen(u), true
	}
	if c.user != "" && username == c.user {
		return 1, true
	}
	return 0, false
}

// UserRoleAndGeneration returns the CURRENT durable role and generation of
// a roster user — what every authenticated request is validated against
// (Blocker 2): the cookie's embedded role is never trusted over the record.
func (c *Config) UserRoleAndGeneration(username string) (role UIRole, gen int64, ok bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	u := c.uiUsers[username]
	if u == nil {
		if c.user != "" && username == c.user {
			// Legacy single-user identity (mirror only): admin, generation 1
			// by definition — the same answer UserSecurityGeneration gives,
			// so a cookie issued for it validates until the roster entry
			// exists (a change-password migrates it and advances the gen).
			return RoleAdmin, 1, true
		}
		return "", 0, false
	}
	return u.role, userSecurityGen(u), true
}

// RosterDurable reports whether administrative roster mutations can be made
// durable (a persistence path is configured). Bootstrap paths (setup, the
// reset-password one-shot) keep their own contract; the admin API refuses
// mutations on a non-durable roster (Blocker 7).
func (c *Config) RosterDurable() bool { return c.uiUsersFilePath() != "" }

// RosterRevision returns the current fencing token (floor 1 so a caller can
// always echo a positive value).
func (c *Config) RosterRevision() int64 {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.rosterRevision <= 0 {
		return 1
	}
	return c.rosterRevision
}

// commitRoster runs one roster transaction: snapshot the live roster into
// a candidate copy → (optional) revision fence → mutate the candidate →
// persist the candidate with the NEXT revision → only then publish it
// (roster, revision, legacy mirror, auth cache). expectedRev == nil skips
// the fence (self-service paths); a non-nil mismatch is *rosterStaleError.
// Returns the revision now in force.
func (c *Config) commitRoster(expectedRev *int64, mutate func(tx *rosterTx) error) (int64, error) {
	c.saveUIUsersMu.Lock()
	defer c.saveUIUsersMu.Unlock()

	c.mu.RLock()
	path := c.uiUsersFile
	outcome := c.defaultAuthOutcome
	if outcome == "" {
		outcome = OutcomeDefault
	}
	current := c.rosterRevision
	if current <= 0 {
		current = 1
	}
	counter := c.securityCounter
	legacyUser := c.user
	next := make(map[string]*uiAdminUser, len(c.uiUsers)+1)
	for name, u := range c.uiUsers {
		if u == nil {
			continue
		}
		cp := *u
		cp.passHash = append([]byte(nil), u.passHash...)
		cp.backupCodes = append([]string(nil), u.backupCodes...)
		next[name] = &cp
	}
	c.mu.RUnlock()

	if expectedRev != nil && *expectedRev != current {
		return current, &rosterStaleError{Current: current}
	}
	tx := &rosterTx{next: next, counter: counter, legacyUser: legacyUser}
	if err := mutate(tx); err != nil {
		return current, err
	}
	nextRev := current + 1
	if path != "" {
		if err := writeRosterEnvelope(path, rosterEnvelope(next, string(outcome), nextRev, tx.counter)); err != nil {
			// CHAOS-70 (main #1469) meets the FE-6A.0 transaction here. Two
			// rules from that change apply to this write too:
			//   - fileutil.ErrReplacedNotSynced means the rename ALREADY landed
			//     the new envelope and only the parent-directory fsync failed
			//     (FE-6B.0 round 3's atomic-dir seam); every future reader,
			//     including a restart, sees the new roster, so refusing here
			//     would leave the FILE carrying a change the process denies —
			//     the memory/disk split this transaction exists to prevent.
			//     rosterChangeCommitted logs it and the commit proceeds.
			//   - every other write failure is a REFUSAL, nothing published,
			//     and it is charged to the same counter main's legacy-shaped
			//     handlers charge (culvert_admin_roster_persist_failures_total)
			//     so the metric is truthful on these handlers too.
			if !rosterChangeCommitted(err) {
				noteRosterPersistRefused(string(outcome), err)
				return current, fmt.Errorf("%w: %v", errRosterPersistFailed, err)
			}
		}
	}
	c.mu.Lock()
	c.uiUsers = next
	c.rosterRevision = nextRev
	c.securityCounter = tx.counter
	c.authRevision++
	c.cache.clear()
	c.syncLegacyMirrorLocked()
	c.mu.Unlock()
	return nextRev, nil
}

// rosterTx is the candidate a commitRoster mutation edits: the copied
// roster, the candidate security counter and the legacy mirror's username
// (so a legacy-only identity can be migrated inside the same transaction).
type rosterTx struct {
	next       map[string]*uiAdminUser
	counter    int64
	legacyUser string
}

func (tx *rosterTx) nextGen() int64 {
	tx.counter++
	return tx.counter
}

// CreateUIUser creates a NEW roster entry (409 user_exists when present —
// create is never an upsert, R13) under the roster fence (Blocker 4).
func (c *Config) CreateUIUser(username, password string, role UIRole, expectedRev int64) (int64, error) {
	if err := validatePasswordComplexity(password); err != nil {
		return 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}
	return c.commitRoster(&expectedRev, func(tx *rosterTx) error {
		if tx.next[username] != nil {
			return errRosterUserExists
		}
		return applyRosterSet(tx.next, username, hash, role, tx.nextGen)
	})
}

// rosterUpdate reports what a fenced update changed.
type rosterUpdate struct {
	Revision        int64
	RoleChanged     bool
	PasswordChanged bool
	PreviousRole    UIRole
	Generation      int64 // the user's security generation after the commit
}

// UpdateUIUser replaces the role and/or password of an EXISTING user under
// the roster fence. password "" keeps the credential; role "" keeps the
// role. TOTP enrollment is preserved; demoting the last admin is refused.
func (c *Config) UpdateUIUser(username, password string, role UIRole, expectedRev int64) (rosterUpdate, error) {
	var hash []byte
	if password != "" {
		if err := validatePasswordComplexity(password); err != nil {
			return rosterUpdate{}, err
		}
		h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return rosterUpdate{}, err
		}
		hash = h
	}
	var out rosterUpdate
	rev, err := c.commitRoster(&expectedRev, func(tx *rosterTx) error {
		existing := tx.next[username]
		if existing == nil {
			return errRosterNotFound
		}
		out.PreviousRole = existing.role
		target := existing.role
		if role != "" {
			target = role
		}
		out.RoleChanged = target != existing.role
		out.PasswordChanged = hash != nil
		if err := applyRosterSet(tx.next, username, hash, target, tx.nextGen); err != nil {
			return err
		}
		out.Generation = userSecurityGen(tx.next[username])
		return nil
	})
	out.Revision = rev
	return out, err
}

// DeleteUIUserFenced removes a user under the roster fence (404 not_found
// when absent, 409 last_admin).
func (c *Config) DeleteUIUserFenced(username string, expectedRev int64) (int64, error) {
	return c.commitRoster(&expectedRev, func(tx *rosterTx) error {
		if tx.next[username] == nil {
			return errRosterNotFound
		}
		return applyRosterDelete(tx.next, username)
	})
}

// ChangeUIUserPassword is the self-service credential replacement (the
// caller verified the current password). FE-6A.0 correction (Blockers 1/3):
// the request is FENCED on the target user's security generation as
// observed with the verified credential (*rosterGenStaleError when an
// administrator's role/password change landed in between; errRosterNotFound
// when the user was deleted), the check is re-decided INSIDE the roster
// transaction, the generation advances with the durable commit (every
// session issued under the previous generation becomes invalid), and a
// LEGACY single-user identity (mirror only, no roster entry) is migrated
// into the roster by the same persist-before-publish transaction — the live
// mirror, auth cache and sessions change only after the durable outcome.
func (c *Config) ChangeUIUserPassword(username, password string, expectedGen int64) (rev, gen int64, err error) {
	if err := validatePasswordComplexity(password); err != nil {
		return 0, 0, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return 0, 0, err
	}
	rev, err = c.commitRoster(nil, func(tx *rosterTx) error {
		existing := tx.next[username]
		switch {
		case existing == nil && tx.legacyUser != "" && username == tx.legacyUser:
			// Legacy mirror only: generation 1 by definition; migrate.
			if expectedGen != 1 {
				return &rosterGenStaleError{Current: 1}
			}
			tx.next[username] = &uiAdminUser{passHash: hash, role: RoleAdmin, securityGen: tx.nextGen()}
		case existing == nil:
			return errRosterNotFound
		default:
			if cur := userSecurityGen(existing); expectedGen != cur {
				return &rosterGenStaleError{Current: cur}
			}
			existing.passHash = hash
			existing.securityGen = tx.nextGen()
		}
		gen = userSecurityGen(tx.next[username])
		return nil
	})
	return rev, gen, err
}

// uiUsersFilePath returns the configured roster path ("" = in-memory).
func (c *Config) uiUsersFilePath() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.uiUsersFile
}
