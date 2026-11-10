package linux

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"

	"github.com/vishvananda/netlink"
	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeTable is a host's main routing table. Like the kernel it lists every
// route of the family, whatever its protocol: the steerer must pick its own.
type fakeTable struct {
	routes   []netlink.Route
	replaced int
	failList bool
	failAdd  bool
}

func ipnet(s string) *net.IPNet {
	p := netip.MustParsePrefix(s)
	return &net.IPNet{IP: p.Addr().AsSlice(), Mask: net.CIDRMask(p.Bits(), p.Addr().BitLen())}
}

func (f *fakeTable) list(fam int) ([]netlink.Route, error) {
	if f.failList {
		return nil, errors.New("netlink: operation not permitted")
	}
	var out []netlink.Route
	for _, r := range f.routes {
		if (r.Dst == nil || r.Dst.IP.To4() != nil) == (fam == netlink.FAMILY_V4) {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakeTable) replace(r *netlink.Route) error {
	if f.failAdd {
		return errors.New("netlink: operation not permitted")
	}
	f.replaced++
	for i := range f.routes {
		if f.routes[i].Dst != nil && f.routes[i].Dst.String() == r.Dst.String() {
			f.routes[i] = *r
			return nil
		}
	}
	f.routes = append(f.routes, *r)
	return nil
}

func (f *fakeTable) del(r *netlink.Route) error {
	for i := range f.routes {
		if f.routes[i].Dst != nil && f.routes[i].Dst.String() == r.Dst.String() && f.routes[i].Protocol == r.Protocol {
			f.routes = append(f.routes[:i], f.routes[i+1:]...)
			return nil
		}
	}
	return errors.New("no such process")
}

// find returns the route for dst, or nil.
func (f *fakeTable) find(dst string) *netlink.Route {
	for i := range f.routes {
		if f.routes[i].Dst != nil && f.routes[i].Dst.String() == dst {
			return &f.routes[i]
		}
	}
	return nil
}

// host is a router with a default route, two connected links, and a
// static route an operator added.
func host() *fakeTable {
	return &fakeTable{routes: []netlink.Route{
		{Dst: nil, Gw: net.ParseIP("192.0.2.3"), Protocol: 3},
		{Dst: ipnet("192.0.2.0/24"), Protocol: 2},
		{Dst: ipnet("198.51.100.0/24"), Protocol: 2},
		{Dst: ipnet("203.0.113.0/24"), Gw: net.ParseIP("192.0.2.1"), Protocol: 4},
	}}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestInstallRemoveBothFamilies(t *testing.T) {
	f := &fakeTable{}
	s := &Steerer{table: f}
	ctx := context.Background()
	v4 := plugin.SteerRoute{Prefix: pfx("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	v6 := plugin.SteerRoute{Prefix: pfx("2001:db8:1::/48"), NextHop: netip.MustParseAddr("2001:db8:ffff::1")}
	for _, r := range []plugin.SteerRoute{v4, v6} {
		if err := s.Install(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if r := f.find("198.51.100.0/24"); r == nil || !r.Gw.Equal(net.ParseIP("192.0.2.1")) || r.Protocol != Proto || r.Table != 254 {
		t.Fatalf("v4 route = %+v", r)
	}
	if r := f.find("2001:db8:1::/48"); r == nil || !r.Gw.Equal(net.ParseIP("2001:db8:ffff::1")) || r.Protocol != Proto {
		t.Fatalf("v6 route = %+v", r)
	}
	// Installing again, even through another gateway, replaces the one route.
	v4.NextHop = netip.MustParseAddr("198.51.100.1")
	if err := s.Install(ctx, v4); err != nil {
		t.Fatal(err)
	}
	if len(f.routes) != 2 || !f.find("198.51.100.0/24").Gw.Equal(net.ParseIP("198.51.100.1")) {
		t.Fatalf("routes = %+v", f.routes)
	}
	owned, err := s.Owned(ctx)
	if err != nil || len(owned) != 2 || owned[0] != v4.Prefix || owned[1] != v6.Prefix {
		t.Fatalf("owned = %v, %v", owned, err)
	}
	for _, r := range []plugin.SteerRoute{v4, v6} {
		if err := s.Remove(ctx, r.Prefix); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.routes) != 0 {
		t.Fatalf("routes stayed: %+v", f.routes)
	}
	if err := s.Remove(ctx, v4.Prefix); err != nil {
		t.Fatalf("removing a route that is gone: %v", err)
	}
}

// The table lists every protocol, as BusyBox's ip does even when asked for
// one: only routes with Proto are owned, removed, or replaced.
func TestForeignRoutesAreNeverTakenOrDeleted(t *testing.T) {
	f := host()
	s := &Steerer{table: f}
	ctx := context.Background()
	owned, err := s.Owned(ctx)
	if err != nil || len(owned) != 0 {
		t.Fatalf("owned = %v, %v; the host's own routes are not owned", owned, err)
	}
	err = s.Install(ctx, plugin.SteerRoute{Prefix: pfx("203.0.113.0/24"), NextHop: netip.MustParseAddr("198.51.100.1")})
	if err == nil || !strings.Contains(err.Error(), "already has a route") || f.replaced != 0 {
		t.Fatalf("err = %v, replaced %d", err, f.replaced)
	}
	for _, p := range []string{"203.0.113.0/24", "192.0.2.0/24", "0.0.0.0/0"} {
		if err := s.Remove(ctx, pfx(p)); err != nil {
			t.Fatal(err)
		}
	}
	if len(f.routes) != 4 || !f.find("203.0.113.0/24").Gw.Equal(net.ParseIP("192.0.2.1")) {
		t.Fatalf("a route without proto %d was changed or deleted: %+v", Proto, f.routes)
	}
	// Its own route beside them is found and removed alone.
	if err := s.Install(ctx, plugin.SteerRoute{Prefix: pfx("198.51.100.0/25"), NextHop: netip.MustParseAddr("198.51.100.1")}); err != nil {
		t.Fatal(err)
	}
	if owned, _ := s.Owned(ctx); len(owned) != 1 || owned[0] != pfx("198.51.100.0/25") {
		t.Fatalf("owned = %v", owned)
	}
	if err := s.Remove(ctx, pfx("198.51.100.0/25")); err != nil || len(f.routes) != 4 {
		t.Fatalf("remove: %v, routes %+v", err, f.routes)
	}
}

func TestNetlinkErrorsAreReturned(t *testing.T) {
	f := &fakeTable{failAdd: true}
	err := (&Steerer{table: f}).Install(context.Background(), plugin.SteerRoute{Prefix: pfx("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")})
	if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("err = %v", err)
	}
	f.failList = true
	if _, err := (&Steerer{table: f}).Owned(context.Background()); err == nil {
		t.Fatal("a failed listing was not reported")
	}
	if err := (&Steerer{table: f}).Remove(context.Background(), pfx("198.51.100.0/24")); err == nil {
		t.Fatal("a failed listing was not reported by Remove")
	}
}

func TestDst(t *testing.T) {
	for _, tc := range []struct {
		r    netlink.Route
		fam  int
		want string
	}{
		{netlink.Route{Dst: ipnet("198.51.100.0/24")}, netlink.FAMILY_V4, "198.51.100.0/24"},
		{netlink.Route{Dst: ipnet("192.0.2.9/32")}, netlink.FAMILY_V4, "192.0.2.9/32"},
		{netlink.Route{Dst: ipnet("2001:db8::/48")}, netlink.FAMILY_V6, "2001:db8::/48"},
		{netlink.Route{}, netlink.FAMILY_V4, "0.0.0.0/0"},
		{netlink.Route{}, netlink.FAMILY_V6, "::/0"},
	} {
		if got := dst(tc.r, tc.fam); got != pfx(tc.want) {
			t.Errorf("dst(%v) = %s, want %s", tc.r.Dst, got, tc.want)
		}
	}
}

func TestConfigAndRegistration(t *testing.T) {
	var n yaml.Node
	_ = yaml.Unmarshal([]byte("table: 5"), &n)
	if _, err := New(plugin.NewConfig(n.Content[0]), plugin.Env{}); err == nil {
		t.Error("an unknown key was accepted")
	}
	s, err := New(plugin.Config{}, plugin.Env{})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := s.(*Steerer).table.(kernel); !ok {
		t.Fatal("the plugin does not use the kernel table")
	}
	if !plugin.Steerers.Has(TypeName) {
		t.Fatal("linux is not registered as a steerer")
	}
}
