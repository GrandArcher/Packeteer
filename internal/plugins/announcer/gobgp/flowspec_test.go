package gobgp

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/apiutil"
	"github.com/osrg/gobgp/v3/pkg/packet/bgp"
	"github.com/osrg/gobgp/v3/pkg/server"

	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

var fs4Family = &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_FLOW_SPEC_UNICAST}

const flowspecYAML = `
marker: "64512:668"
flowspec:
  redirect:
    - name: scrub-vrf
      route_target: "64512:777"
`

// newFlowSpecRouter is newRouter with the FlowSpec families on the
// session, and a view that offers them.
func newFlowSpecRouter(t *testing.T) (*fakeRouter, *rib.View) {
	t.Helper()
	r := newRouter(t)
	ctx := context.Background()
	if _, err := r.srv.UpdatePeer(ctx, &api.UpdatePeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: "127.0.0.2", PeerAsn: asn},
		Transport: &api.Transport{PassiveMode: true},
		AfiSafis: []*api.AfiSafi{
			{Config: &api.AfiSafiConfig{Family: v4Family, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: v6Family, Enabled: true}},
			{Config: &api.AfiSafiConfig{Family: fs4Family, Enabled: true}},
		},
	}}); err != nil {
		t.Fatal(err)
	}
	v, err := rib.New(rib.Options{
		ASN: asn, RouterID: netip.MustParseAddr("192.0.2.10"), ListenPort: -1,
		Neighbors: []rib.Neighbor{{Address: netip.MustParseAddr("127.0.0.1"), Port: uint16(r.port),
			LocalAddress: netip.MustParseAddr("127.0.0.2")}},
		Providers: map[netip.Addr]string{netip.MustParseAddr("192.0.2.1"): "transit-a"},
	})
	if err != nil {
		t.Fatal(err)
	}
	v.EnableFlowSpec()
	if err := v.Start(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = v.Stop(context.Background()) })
	return r, v
}

type fsSeen struct {
	nlri  string
	ext   []string
	comms map[uint32]bool
	lp    uint32
}

// flowSpecFromUs lists the FlowSpec rules the router learned from
// Packeteer.
func flowSpecFromUs(t *testing.T, srv *server.BgpServer) []fsSeen {
	return flowSpecFrom(t, srv, "127.0.0.2")
}

func flowSpecFrom(t *testing.T, srv *server.BgpServer, nbr string) []fsSeen {
	t.Helper()
	var out []fsSeen
	err := srv.ListPath(context.Background(), &api.ListPathRequest{TableType: api.TableType_GLOBAL, Family: fs4Family}, func(d *api.Destination) {
		for _, p := range d.Paths {
			if nbr != "*" && p.NeighborIp != nbr {
				continue
			}
			n, err := apiutil.GetNativeNlri(p)
			if err != nil {
				t.Error(err)
				continue
			}
			s := fsSeen{nlri: n.String(), comms: map[uint32]bool{}}
			attrs, err := apiutil.UnmarshalPathAttributes(p.Pattrs)
			if err != nil {
				t.Error(err)
				continue
			}
			for _, a := range attrs {
				switch v := a.(type) {
				case *bgp.PathAttributeExtendedCommunities:
					for _, e := range v.Value {
						s.ext = append(s.ext, e.String())
					}
				case *bgp.PathAttributeCommunities:
					for _, c := range v.Value {
						s.comms[c] = true
					}
				case *bgp.PathAttributeLocalPref:
					s.lp = v.Value
				}
			}
			out = append(out, s)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestFlowSpecConfigValidation(t *testing.T) {
	bad := map[string]string{
		"no name":        "marker: \"64512:668\"\nflowspec: {redirect: [{route_target: \"64512:1\"}]}",
		"bad rt":         "marker: \"64512:668\"\nflowspec: {redirect: [{name: v, route_target: \"64512\"}]}",
		"rt as 0":        "marker: \"64512:668\"\nflowspec: {redirect: [{name: v, route_target: \"0:1\"}]}",
		"4-octet rt":     "marker: \"64512:668\"\nflowspec: {redirect: [{name: v, route_target: \"65536:1\"}]}",
		"dup name":       "marker: \"64512:668\"\nflowspec: {redirect: [{name: v, route_target: \"64512:1\"}, {name: v, route_target: \"64512:2\"}]}",
		"dup rt":         "marker: \"64512:668\"\nflowspec: {redirect: [{name: v, route_target: \"64512:1\"}, {name: w, route_target: \"64512:1\"}]}",
		"unknown key":    "marker: \"64512:668\"\nflowspec: {rate: 5}",
		"nothing at all": "marker: \"64512:668\"",
	}
	for name, y := range bad {
		c, err := plugin.ConfigFromYAML(y)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewMitigation(c, plugin.Env{}); err == nil {
			t.Errorf("%s: config accepted", name)
		}
	}
	a := mustMitigation(t, flowspecYAML)
	cat := a.FlowSpecCatalog()
	if !cat.Enabled || len(cat.Targets) != 1 || cat.Targets[0] != (plugin.FlowSpecTarget{Name: "scrub-vrf", RouteTarget: "64512:777"}) {
		t.Fatalf("flowspec catalog = %+v", cat)
	}
	if a.Catalog().Blackhole || !a.FlowSpecEnabled() {
		t.Fatal("flowspec-only announcer reports blackhole or no flowspec")
	}
	if mustMitigation(t, "marker: \"64512:668\"\nflowspec: {}").FlowSpecCatalog().Targets == nil {
		t.Fatal("targets must be an empty list, not nil")
	}
	if mustMitigation(t, mitigationYAML).FlowSpecEnabled() {
		t.Fatal("flowspec reported without a flowspec block")
	}
}

func TestFlowSpecAnnounceWithdrawAndCrash(t *testing.T) {
	ctx := context.Background()
	r, v := newFlowSpecRouter(t)
	eventually(t, "session", v.Ready)
	allow := []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	out := mustAnnouncer(t)
	if err := out.Bind(v.Server(), "64512:666"); err != nil {
		t.Fatal(err)
	}
	m := mustMitigation(t, flowspecYAML+"blackhole: {next_hop: 192.0.2.66}\n")
	if err := m.Bind(v.Server(), "64512:666", allow, 3); err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParsePrefix("198.51.100.0/24")
	drop := plugin.FlowSpecRoute{Destination: dst, Action: plugin.MitigationFlowSpecDrop, LocalPref: 250, Community: "64512:666",
		Match: plugin.FlowSpecMatch{
			Source:           netip.MustParsePrefix("203.0.113.0/25"),
			Protocols:        []plugin.IPProtocol{17},
			DestinationPorts: []plugin.PortRange{{From: 53, To: 53}, {From: 1000, To: 2000}},
		}}
	bad := []plugin.FlowSpecRoute{
		{Destination: netip.MustParsePrefix("192.0.2.0/24"), Action: plugin.MitigationFlowSpecDrop, LocalPref: 250, Community: "64512:666"},
		{Destination: dst, Action: plugin.MitigationFlowSpecDrop, LocalPref: 250, Community: "64512:1"},
		{Destination: dst, Action: plugin.MitigationFlowSpecDrop, Community: "64512:666"},
		{Destination: dst, Action: plugin.MitigationFlowSpecDrop, RateMbps: 5, LocalPref: 250, Community: "64512:666"},
		{Destination: dst, Action: plugin.MitigationFlowSpecRateLimit, LocalPref: 250, Community: "64512:666"},
		{Destination: dst, Action: plugin.MitigationFlowSpecRateLimit, RateMbps: 1e9, LocalPref: 250, Community: "64512:666"},
		{Destination: dst, Action: plugin.MitigationFlowSpecRedirect, Target: "nowhere", LocalPref: 250, Community: "64512:666"},
		{Destination: dst, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"},
		{Destination: dst, Action: plugin.MitigationFlowSpecDrop, LocalPref: 250, Community: "64512:666",
			Match: plugin.FlowSpecMatch{Source: netip.MustParsePrefix("2001:db8::/32")}},
	}
	for _, b := range bad {
		if err := m.AnnounceFlowSpec(ctx, b); err == nil {
			t.Fatalf("announced invalid flowspec %+v", b)
		}
	}

	have := func(nlriHas []string, ext string) func() bool {
		return func() bool {
			for _, s := range flowSpecFromUs(t, r.srv) {
				ok := s.lp == 250 && s.comms[noExport] && len(s.ext) == 1 && s.ext[0] == ext
				for _, c := range []string{"64512:666", "64512:668"} {
					v, _ := parseCommunity(c)
					ok = ok && s.comms[v]
				}
				for _, n := range nlriHas {
					ok = ok && strings.Contains(s.nlri, n)
				}
				if ok {
					return true
				}
			}
			return false
		}
	}
	if err := m.AnnounceFlowSpec(ctx, drop); err != nil {
		t.Fatal(err)
	}
	eventually(t, "flowspec drop", have([]string{"198.51.100.0/24", "203.0.113.0/25", "==udp", "==53", ">=1000&<=2000"}, "discard"))

	// Same NLRI, new action: replaced in place.
	rl := drop
	rl.Action, rl.RateMbps = plugin.MitigationFlowSpecRateLimit, 8
	if err := m.AnnounceFlowSpec(ctx, rl); err != nil {
		t.Fatal(err)
	}
	eventually(t, "flowspec rate-limit", have([]string{"203.0.113.0/25"}, "rate: 1000000.000000"))
	if n := len(flowSpecFromUs(t, r.srv)); n != 1 {
		t.Fatalf("replace left %d rules", n)
	}

	rd := plugin.FlowSpecRoute{Destination: dst, Action: plugin.MitigationFlowSpecRedirect, Target: "scrub-vrf", LocalPref: 250, Community: "64512:666",
		Match: plugin.FlowSpecMatch{Protocols: []plugin.IPProtocol{6}}}
	if err := m.AnnounceFlowSpec(ctx, rd); err != nil {
		t.Fatal(err)
	}
	eventually(t, "flowspec redirect", have([]string{"==tcp"}, "redirect: 64512:777"))

	// The cap covers FlowSpec and RTBH together: 2 FlowSpec + 1 RTBH = 3.
	if err := m.Announce(ctx, plugin.MitigationRoute{Prefix: dst, Action: plugin.MitigationBlackhole, LocalPref: 250, Community: "64512:666"}); err != nil {
		t.Fatal(err)
	}
	third := drop
	third.Match = plugin.FlowSpecMatch{Protocols: []plugin.IPProtocol{1}}
	if err := m.AnnounceFlowSpec(ctx, third); err == nil || !strings.Contains(err.Error(), "max rules") {
		t.Fatalf("flowspec past the cap: %v", err)
	}

	if err := m.WithdrawFlowSpec(ctx, rd.Key()); err != nil {
		t.Fatal(err)
	}
	eventually(t, "flowspec withdraw", func() bool { return len(flowSpecFromUs(t, r.srv)) == 1 })
	if err := m.WithdrawFlowSpec(ctx, rd.Key()); err != nil {
		t.Fatalf("second withdraw: %v", err)
	}

	// Stop withdraws FlowSpec and RTBH.
	if err := m.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "stop withdraws flowspec", func() bool {
		_, bh := fromUs(collect(t, r.srv, v4Family), dst.String())
		return len(flowSpecFromUs(t, r.srv)) == 0 && !bh
	})

	// Crash: the session drops with no withdraw; the router forgets.
	if err := m.AnnounceFlowSpec(ctx, drop); err != nil {
		t.Fatal(err)
	}
	eventually(t, "flowspec before crash", func() bool { return len(flowSpecFromUs(t, r.srv)) == 1 })
	if err := v.Stop(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "flowspec gone with the session", func() bool { return len(flowSpecFromUs(t, r.srv)) == 0 })
}
