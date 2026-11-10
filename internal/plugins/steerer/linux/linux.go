// Package linux is the non-BGP mode's steerer for a Linux router (#300):
// Packeteer runs on the router itself (the container needs host networking
// and NET_ADMIN) and keeps one static route per steered prefix in the main
// table over netlink. Every route carries protocol number Proto. The plugin
// lists the main table and changes or deletes only routes with that
// protocol, checked here rather than left to a filter of the ip tool
// (BusyBox's, in the image, does not filter by protocol). It refuses to add
// a route for a prefix the host already routes, because a replace would
// take that route over.
package linux

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"runtime"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

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

// routeTable is the main routing table as the steerer reaches it.
type routeTable interface {
	// list returns every main-table route of one family, any protocol.
	list(family int) ([]netlink.Route, error)
	replace(r *netlink.Route) error
	del(r *netlink.Route) error
}

// kernel is this host's main table over netlink.
type kernel struct{}

func (kernel) list(family int) ([]netlink.Route, error) {
	return netlink.RouteListFiltered(family, &netlink.Route{Table: unix.RT_TABLE_MAIN}, netlink.RT_FILTER_TABLE)
}
func (kernel) replace(r *netlink.Route) error { return netlink.RouteReplace(r) }
func (kernel) del(r *netlink.Route) error     { return netlink.RouteDel(r) }

// Steerer keeps static routes in this host's main table.
type Steerer struct {
	plugin.Base
	table routeTable
}

// New is the plugin factory. It validates the config and changes nothing.
func New(c plugin.Config, _ plugin.Env) (plugin.Steerer, error) {
	var cfg Config
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if runtime.GOOS != "linux" {
		return nil, errors.New("the linux steerer runs only on Linux")
	}
	return &Steerer{table: kernel{}}, nil
}

func family(p netip.Prefix) int {
	if p.Addr().Is6() {
		return netlink.FAMILY_V6
	}
	return netlink.FAMILY_V4
}

// dst is a route's destination; a route with none is the default route.
func dst(r netlink.Route, fam int) netip.Prefix {
	if r.Dst == nil {
		if fam == netlink.FAMILY_V6 {
			return netip.MustParsePrefix("::/0")
		}
		return netip.MustParsePrefix("0.0.0.0/0")
	}
	a, ok := netip.AddrFromSlice(r.Dst.IP)
	if !ok {
		return netip.Prefix{}
	}
	ones, _ := r.Dst.Mask.Size()
	return netip.PrefixFrom(a.Unmap(), ones).Masked()
}

// routes lists the main-table routes for p.
func (s *Steerer) routes(p netip.Prefix) ([]netlink.Route, error) {
	all, err := s.table.list(family(p))
	if err != nil {
		return nil, fmt.Errorf("list routes: %w", err)
	}
	var out []netlink.Route
	for _, r := range all {
		if dst(r, family(p)) == p {
			out = append(out, r)
		}
	}
	return out, nil
}

// Install replaces nothing it does not own: a prefix with a route lacking
// Proto is refused.
func (s *Steerer) Install(_ context.Context, r plugin.SteerRoute) error {
	p := r.Prefix.Masked()
	have, err := s.routes(p)
	if err != nil {
		return err
	}
	for _, h := range have {
		if h.Protocol != Proto {
			return fmt.Errorf("the host already has a route for %s that was not added with proto %d; remove it or leave the prefix out of the allowlist", p, Proto)
		}
	}
	route := &netlink.Route{
		Dst:      &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())},
		Gw:       r.NextHop.AsSlice(),
		Protocol: Proto,
		Table:    unix.RT_TABLE_MAIN,
	}
	if err := s.table.replace(route); err != nil {
		return fmt.Errorf("add route %s via %s: %w", p, r.NextHop, err)
	}
	return nil
}

// Remove deletes the routes for p that carry Proto. A route that is gone
// is not an error.
func (s *Steerer) Remove(_ context.Context, p netip.Prefix) error {
	p = p.Masked()
	have, err := s.routes(p)
	if err != nil {
		return err
	}
	var errs []error
	for i := range have {
		if have[i].Protocol != Proto {
			continue
		}
		if err := s.table.del(&have[i]); err != nil {
			errs = append(errs, fmt.Errorf("delete route %s: %w", p, err))
		}
	}
	return errors.Join(errs...)
}

// Owned lists the routes that carry Proto, both families.
func (s *Steerer) Owned(context.Context) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		all, err := s.table.list(fam)
		if err != nil {
			return nil, fmt.Errorf("list routes: %w", err)
		}
		for _, r := range all {
			if r.Protocol == Proto {
				out = append(out, dst(r, fam))
			}
		}
	}
	return out, nil
}
