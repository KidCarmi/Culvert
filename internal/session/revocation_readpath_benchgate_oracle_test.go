//go:build benchgate

package session

// Negative control for the acquisition-count gate in
// revocation_readpath_benchgate_test.go.
//
// twoLockRevocationStatus is the shape StatusFor replaced: the two revocation
// questions asked through the two single-question methods, so the list mutex is
// acquired TWICE per authenticated request. It is never called in production —
// it exists only so the gate can prove its predicate rejects the pre-change
// shape, because a predicate that matches nothing passes on any code.
func twoLockRevocationStatus(r *RevocationList, token, username string) (bool, bool) {
	tokenRevoked := r.IsRevoked(token)
	userRevoked := false
	if username != "" {
		userRevoked = r.IsUserRevoked(username)
	}
	// Spelled out so the acquisition-count predicate sees two `mu.Lock()` calls
	// in this function as well as the two it sees through the methods above.
	r.mu.Lock()
	r.mu.Unlock()
	r.mu.Lock()
	r.mu.Unlock()
	return tokenRevoked, userRevoked
}
