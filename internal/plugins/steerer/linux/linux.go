// Package linux is the non-BGP mode's steerer for a Linux router (#300):
// Packeteer runs on the router itself (the container needs host networking
// and NET_ADMIN) and keeps one static route per steered prefix in the main
// table with `ip route`. Every route carries protocol number Proto. The
// plugin lists and deletes only routes with that protocol, and refuses to
// add a route for a prefix the host already routes, because `ip route
// replace` would take that route over.
package linux

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"strconv"
	"strings"

	"github.com/GrandArcher/Packeteer/internal/pbr"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// TypeName is the config type.
const TypeName = "linux"

// Proto is the routing protocol number on every route this plugin owns.
// It is in the range the kernel leaves to administrators and clear of the
// numbers routing daemons use.
const Proto = 250

func init() { plugin.Steerers.Register(TypeName, New) }

// Config has no keys: the routes go in the main table, tagged with Proto.
type Config struct{}

// Steerer runs ip route on this host.
type Steerer struct {
	plugin.Base
	run pbr.Exec
}

// New is the plugin factory. It validates the config and runs nothing.
func New(c plugin.Config, _ plugin.Env) (plugin.Steerer, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("the linux steerer runs only on Linux")
	}
	return &Steerer{run: pbr.HostExec}, nil
}

func family(p netip.Prefix) string {
	if p.Addr().Is6() {
		return "-6"
	}
	return "-4"
}

// list reads the destinations of the main table for one family. With
// onlyOurs the kernel filters to the routes that carry Proto.
func (s *Steerer) list(ctx context.Context, fam string, onlyOurs bool) ([]netip.Prefix, error) {
	args := []string{fam, "route", "show"}
	if onlyOurs {
		args = append(args, "proto", strconv.Itoa(Proto))
	}
	out, err := s.run(ctx, args...)
	if err != nil {
		return nil, err
	}
	var ps []netip.Prefix
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if p, ok := parseDst(f[0]); ok {
			ps = append(ps, p)
		}
	}
	return ps, nil
}

// parseDst reads the destination column: a prefix, or a bare address for a
// host route. "default" and other words are not a destination here.
func parseDst(s string) (netip.Prefix, bool) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return netip.PrefixFrom(a, a.BitLen()), true
	}
	return netip.Prefix{}, false
}

// Install replaces nothing it does not own: a prefix with a route lacking
// Proto is refused.
func (s *Steerer) Install(ctx context.Context, r plugin.SteerRoute) error {
	p := r.Prefix.Masked()
	all, err := s.list(ctx, family(p), false)
	if err != nil {
		return err
	}
	ours, err := s.list(ctx, family(p), true)
	if err != nil {
		return err
	}
	if has(all, p) && !has(ours, p) {
		return fmt.Errorf("the host already has a route for %s that was not added with proto %d; remove it or leave the prefix out of the allowlist", p, Proto)
	}
	_, err = s.run(ctx, family(p), "route", "replace", p.String(), "via", r.NextHop.String(), "proto", strconv.Itoa(Proto))
	return err
}

func has(ps []netip.Prefix, p netip.Prefix) bool {
	for _, q := range ps {
		if q == p {
			return true
		}
	}
	return false
}

// Remove deletes the route for p that carries Proto. A route that is gone
// is not an error.
func (s *Steerer) Remove(ctx context.Context, p netip.Prefix) error {
	p = p.Masked()
	ours, err := s.list(ctx, family(p), true)
	if err != nil {
		return err
	}
	if !has(ours, p) {
		return nil
	}
	_, err = s.run(ctx, family(p), "route", "del", p.String(), "proto", strconv.Itoa(Proto))
	return err
}

// Owned lists the routes that carry Proto, both families.
func (s *Steerer) Owned(ctx context.Context) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, fam := range []string{"-4", "-6"} {
		ps, err := s.list(ctx, fam, true)
		if err != nil {
			return nil, err
		}
		out = append(out, ps...)
	}
	return out, nil
}
