package linux

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// fakeIP is a host's main routing table. A route is "dst via gw proto N";
// proto "" is a route somebody else added.
type fakeIP struct {
	routes map[string]map[string]string // family -> dst -> "via gw proto N"
	log    []string
	fail   string
}

func newFakeIP() *fakeIP {
	return &fakeIP{routes: map[string]map[string]string{"-4": {}, "-6": {}}}
}

func (f *fakeIP) exec(_ context.Context, args ...string) (string, error) {
	f.log = append(f.log, strings.Join(args, " "))
	if f.fail != "" && strings.Contains(strings.Join(args, " "), f.fail) {
		return "", errors.New("ip: RTNETLINK answers: Operation not permitted")
	}
	fam, verb := args[0], args[2]
	tbl := f.routes[fam]
	switch verb {
	case "show":
		var sb strings.Builder
		for dst, info := range tbl {
			if len(args) > 3 && !strings.HasSuffix(info, "proto "+args[4]) {
				continue
			}
			fmt.Fprintf(&sb, "%s %s\n", dst, info)
		}
		sb.WriteString("default via 192.0.2.254 dev eth0\n")
		return sb.String(), nil
	case "replace":
		tbl[args[3]] = strings.Join(args[4:], " ")
	case "del":
		delete(tbl, args[3])
	}
	return "", nil
}

func newSteerer(f *fakeIP) *Steerer { return &Steerer{run: f.exec} }

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestInstallRemoveBothFamilies(t *testing.T) {
	f := newFakeIP()
	s := newSteerer(f)
	ctx := context.Background()
	v4 := plugin.SteerRoute{Prefix: pfx("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")}
	v6 := plugin.SteerRoute{Prefix: pfx("2001:db8:1::/48"), NextHop: netip.MustParseAddr("2001:db8:ffff::1")}
	for _, r := range []plugin.SteerRoute{v4, v6} {
		if err := s.Install(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.routes["-4"]["198.51.100.0/24"]; got != "via 192.0.2.1 proto 250" {
		t.Fatalf("v4 route = %q", got)
	}
	if got := f.routes["-6"]["2001:db8:1::/48"]; got != "via 2001:db8:ffff::1 proto 250" {
		t.Fatalf("v6 route = %q", got)
	}
	// Installing again, even through another gateway, replaces the one route.
	v4.NextHop = netip.MustParseAddr("198.51.100.1")
	if err := s.Install(ctx, v4); err != nil {
		t.Fatal(err)
	}
	if len(f.routes["-4"]) != 1 || f.routes["-4"]["198.51.100.0/24"] != "via 198.51.100.1 proto 250" {
		t.Fatalf("v4 routes = %v", f.routes["-4"])
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
	if len(f.routes["-4"])+len(f.routes["-6"]) != 0 {
		t.Fatalf("routes stayed: %v", f.routes)
	}
	if err := s.Remove(ctx, v4.Prefix); err != nil {
		t.Fatalf("removing a route that is gone: %v", err)
	}
}

func TestForeignRoutesAreNeverTakenOrDeleted(t *testing.T) {
	f := newFakeIP()
	f.routes["-4"]["203.0.113.0/24"] = "via 192.0.2.1 proto static"
	f.routes["-4"]["192.0.2.77"] = "dev eth0 scope link"
	s := newSteerer(f)
	ctx := context.Background()
	err := s.Install(ctx, plugin.SteerRoute{Prefix: pfx("203.0.113.0/24"), NextHop: netip.MustParseAddr("198.51.100.1")})
	if err == nil || !strings.Contains(err.Error(), "already has a route") {
		t.Fatalf("err = %v", err)
	}
	if f.routes["-4"]["203.0.113.0/24"] != "via 192.0.2.1 proto static" {
		t.Fatal("the host's own route was replaced")
	}
	for _, c := range f.log {
		if strings.Contains(c, "replace") {
			t.Fatalf("ip route replace ran: %s", c)
		}
	}
	if err := s.Remove(ctx, pfx("203.0.113.0/24")); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.routes["-4"]["203.0.113.0/24"]; !ok {
		t.Fatal("Remove deleted a route without proto 250")
	}
	owned, _ := s.Owned(ctx)
	if len(owned) != 0 {
		t.Fatalf("owned = %v; foreign routes are not owned", owned)
	}
}

func TestErrorsFromIPAreReturned(t *testing.T) {
	f := newFakeIP()
	f.fail = "replace"
	err := newSteerer(f).Install(context.Background(), plugin.SteerRoute{Prefix: pfx("198.51.100.0/24"), NextHop: netip.MustParseAddr("192.0.2.1")})
	if err == nil || !strings.Contains(err.Error(), "Operation not permitted") {
		t.Fatalf("err = %v", err)
	}
	f.fail = "show"
	if _, err := newSteerer(f).Owned(context.Background()); err == nil {
		t.Fatal("a failed listing was not reported")
	}
}

func TestParseDst(t *testing.T) {
	for in, want := range map[string]string{
		"198.51.100.0/24": "198.51.100.0/24",
		"192.0.2.9":       "192.0.2.9/32",
		"2001:db8::1":     "2001:db8::1/128",
		"default":         "",
		"unreachable":     "",
	} {
		got, ok := parseDst(in)
		if (want == "") == ok || (ok && got != pfx(want)) {
			t.Errorf("parseDst(%q) = %s %v, want %q", in, got, ok, want)
		}
	}
}

func TestConfigAndRegistration(t *testing.T) {
	var n yaml.Node
	_ = yaml.Unmarshal([]byte("table: 5"), &n)
	if _, err := New(plugin.NewConfig(n.Content[0]), plugin.Env{}); err == nil {
		t.Error("an unknown key was accepted")
	}
	if _, err := New(plugin.Config{}, plugin.Env{}); err != nil {
		t.Fatal(err)
	}
	if !plugin.Steerers.Has(TypeName) {
		t.Fatal("linux is not registered as a steerer")
	}
}
