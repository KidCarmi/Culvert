package main

import (
	"net"
	"net/netip"

	"github.com/KidCarmi/Culvert/internal/admission"
)

// Application composition handles; all admission implementation and state live
// in internal/admission. These aliases preserve the local adapter vocabulary.
type IPFilter = admission.IPFilter
type RateLimiter = admission.RateLimiter

var ipf = admission.NewIPFilter()
var rl = newRateLimiter()

func newIPFilter() *IPFilter                            { return admission.NewIPFilter() }
func newRateLimiter() *RateLimiter                      { return admission.NewRateLimiter() }
func prefixFromIPNet(n *net.IPNet) (netip.Prefix, bool) { return admission.PrefixFromIPNet(n) }

const hotThresholdPct = admission.HotThresholdPercent
