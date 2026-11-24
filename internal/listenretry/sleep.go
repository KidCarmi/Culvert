package listenretry

import "time"

// Ladder is a listener's rebind backoff schedule: Initial after the first
// failure, doubling on each further one, never above Ceiling.
type Ladder struct {
	Initial time.Duration
	Ceiling time.Duration
}

// Next returns the rung after cur: Initial when cur is zero or negative (no
// failure yet, or a reset), otherwise twice cur, capped at Ceiling.
func (l Ladder) Next(cur time.Duration) time.Duration {
	if cur <= 0 {
		return l.Initial
	}
	cur *= 2
	if cur > l.Ceiling {
		return l.Ceiling
	}
	return cur
}

// Clamp shortens a sleep that would straddle a listener's unavailability
// threshold. Threshold is how long the listener must have been failing before
// it is reported unavailable. Floor is the shortest sleep the clamp will
// return, so a threshold that is all but reached does not become a spin.
type Clamp struct {
	Threshold time.Duration
	Floor     time.Duration
}

// Sleep returns how long to sleep when the supervisor intended wait and the
// listener has been failing for failingFor.
//
// It returns wait unchanged when the threshold is already reached or passed,
// and when wait ends at or before the threshold. Otherwise it returns the time
// remaining to the threshold, or Floor when less than Floor remains.
//
// The Floor case does not compare Floor with wait: a wait shorter than Floor
// that straddles the threshold comes back as Floor, which is longer than the
// wait. Supervisors do not reach it (their shortest wait is a jittered first
// rung, well above the floor); the rule is kept as it was.
func (c Clamp) Sleep(wait, failingFor time.Duration) time.Duration {
	remaining := c.Threshold - failingFor
	if remaining <= 0 || wait <= remaining {
		return wait
	}
	if remaining < c.Floor {
		return c.Floor
	}
	return remaining
}
