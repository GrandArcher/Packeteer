//go:build !linux

package traceroute

import (
	"context"
	"fmt"
	"net/netip"
	"time"
)

// Probe is the non-Linux stub. The container image is Linux; other
// systems still compile so a developer checkout builds. Discovery records
// the error as a lost probe and announces nothing.
func (udpHopper) Probe(context.Context, netip.Addr, netip.Addr, int, int, time.Duration) (netip.Addr, bool, error) {
	return netip.Addr{}, false, fmt.Errorf("traceroute: UDP discovery is only supported on linux")
}
