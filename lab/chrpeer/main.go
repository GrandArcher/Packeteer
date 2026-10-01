// Command chrpeer is a minimal BGP speaker for the MikroTik CHR lab
// (lab/e2e-chr.sh, #52). Each instance plays one neighbor of the CHR: a
// transit that originates a documentation prefix, an eBGP collector that
// only records what the CHR exports, or an iBGP speaker that announces a
// route without the Packeteer community (which the CHR's packeteer-in
// filter must reject). Documentation prefixes and private ASNs only.
//
//	chrpeer -asn 64496 -router-id 192.0.2.1 -local 192.0.2.1 \
//	    -peer 192.0.2.254 -peer-asn 64512 -announce 198.51.100.0/24 \
//	    -routes /tmp/transit-a.routes
//
// -routes is rewritten (write and rename) whenever the paths received from
// the CHR change: one line per path, "prefix next-hop communities", with
// communities comma-separated ("-" when there are none) and lines sorted.
// The speaker never listens; it connects out from -local. Graceful restart
// is never enabled.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"

	api "github.com/osrg/gobgp/v3/api"
	"github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/protobuf/types/known/anypb"
)

const noExport = 0xFFFFFF01

func main() {
	asn := flag.Uint("asn", 0, "local ASN")
	peerASN := flag.Uint("peer-asn", 0, "CHR ASN")
	routerID := flag.String("router-id", "", "BGP identifier")
	local := flag.String("local", "", "local address to connect from")
	peer := flag.String("peer", "", "CHR address")
	announce := flag.String("announce", "", "comma-separated prefixes to originate (next hop self)")
	community := flag.String("community", "", "comma-separated communities (ASN:value) on originated routes")
	routes := flag.String("routes", "", "file that lists the paths received from the CHR")
	hold := flag.Uint("hold", 9, "proposed hold time in seconds")
	flag.Parse()

	if *asn == 0 || *peerASN == 0 || *routerID == "" || *local == "" || *peer == "" {
		flag.Usage()
		os.Exit(2)
	}
	prefixes, err := parsePrefixes(*announce)
	if err != nil {
		log.Fatal(err)
	}
	comms, err := parseCommunities(*community)
	if err != nil {
		log.Fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	s := server.NewBgpServer()
	go s.Serve()
	if err := s.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn: uint32(*asn), RouterId: *routerID, ListenPort: -1,
	}}); err != nil {
		log.Fatal(err)
	}
	defer s.Stop()

	rec := &recorder{file: *routes, paths: map[string]string{}}
	if err := rec.flush(); err != nil {
		log.Fatal(err)
	}
	if err := s.WatchEvent(ctx, &api.WatchEventRequest{
		Peer: &api.WatchEventRequest_Peer{},
		Table: &api.WatchEventRequest_Table{Filters: []*api.WatchEventRequest_Table_Filter{
			{Type: api.WatchEventRequest_Table_Filter_ADJIN, Init: true},
		}},
	}, func(r *api.WatchEventResponse) {
		if p := r.GetPeer(); p != nil && p.Peer != nil {
			log.Printf("peer %s state %s", p.Peer.Conf.GetNeighborAddress(), p.Peer.State.GetSessionState())
			if p.Peer.State.GetSessionState() != api.PeerState_ESTABLISHED {
				rec.clear()
			}
		}
		if t := r.GetTable(); t != nil {
			for _, p := range t.Paths {
				rec.update(p)
			}
		}
	}); err != nil {
		log.Fatal(err)
	}

	if err := s.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf:      &api.PeerConf{NeighborAddress: *peer, PeerAsn: uint32(*peerASN)},
		Transport: &api.Transport{LocalAddress: *local, RemotePort: 179},
		Timers: &api.Timers{Config: &api.TimersConfig{
			ConnectRetry: 2, HoldTime: uint64(*hold), KeepaliveInterval: uint64(max(*hold/3, 1)),
		}},
		AfiSafis: []*api.AfiSafi{{Config: &api.AfiSafiConfig{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}, Enabled: true,
		}}},
	}}); err != nil {
		log.Fatal(err)
	}

	for _, p := range prefixes {
		path, err := buildPath(p, *local, comms, *asn == *peerASN)
		if err != nil {
			log.Fatal(err)
		}
		if _, err := s.AddPath(ctx, &api.AddPathRequest{TableType: api.TableType_GLOBAL, Path: path}); err != nil {
			log.Fatal(err)
		}
		log.Printf("originated %s next hop %s communities %q", p, *local, *community)
	}

	<-ctx.Done()
}

func parsePrefixes(s string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		p, err := netip.ParsePrefix(f)
		if err != nil || !p.Addr().Is4() || p != p.Masked() {
			return nil, fmt.Errorf("bad IPv4 prefix %q", f)
		}
		out = append(out, p)
	}
	return out, nil
}

func parseCommunities(s string) ([]uint32, error) {
	var out []uint32
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f == "" {
			continue
		}
		var hi, lo uint32
		if _, err := fmt.Sscanf(f, "%d:%d", &hi, &lo); err != nil || hi > 0xFFFF || lo > 0xFFFF {
			return nil, fmt.Errorf("bad community %q", f)
		}
		out = append(out, hi<<16|lo)
	}
	return out, nil
}

func buildPath(p netip.Prefix, nextHop string, comms []uint32, ibgp bool) (*api.Path, error) {
	nlri, err := anypb.New(&api.IPAddressPrefix{Prefix: p.Addr().String(), PrefixLen: uint32(p.Bits())})
	if err != nil {
		return nil, err
	}
	origin, err := anypb.New(&api.OriginAttribute{Origin: 0})
	if err != nil {
		return nil, err
	}
	nh, err := anypb.New(&api.NextHopAttribute{NextHop: nextHop})
	if err != nil {
		return nil, err
	}
	attrs := []*anypb.Any{origin, nh}
	if ibgp {
		lp, err := anypb.New(&api.LocalPrefAttribute{LocalPref: 100})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, lp)
	}
	if len(comms) > 0 {
		c, err := anypb.New(&api.CommunitiesAttribute{Communities: comms})
		if err != nil {
			return nil, err
		}
		attrs = append(attrs, c)
	}
	return &api.Path{
		Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
		Nlri:   nlri, Pattrs: attrs,
	}, nil
}

// recorder keeps the paths received from the CHR and mirrors them to a file.
type recorder struct {
	mu    sync.Mutex
	file  string
	paths map[string]string // prefix -> "next-hop communities"
}

func (r *recorder) update(p *api.Path) {
	var pfx api.IPAddressPrefix
	if p.Nlri == nil || p.Nlri.UnmarshalTo(&pfx) != nil {
		return
	}
	key := fmt.Sprintf("%s/%d", pfx.Prefix, pfx.PrefixLen)
	r.mu.Lock()
	defer r.mu.Unlock()
	if p.IsWithdraw {
		delete(r.paths, key)
		log.Printf("withdrawn %s", key)
	} else {
		val := describe(p.Pattrs)
		r.paths[key] = val
		log.Printf("received %s %s", key, val)
	}
	if err := r.flushLocked(); err != nil {
		log.Print(err)
	}
}

func (r *recorder) clear() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.paths)
	if err := r.flushLocked(); err != nil {
		log.Print(err)
	}
}

func (r *recorder) flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushLocked()
}

func (r *recorder) flushLocked() error {
	if r.file == "" {
		return nil
	}
	lines := make([]string, 0, len(r.paths))
	for k, v := range r.paths {
		lines = append(lines, k+" "+v+"\n")
	}
	sort.Strings(lines)
	tmp, err := os.CreateTemp(filepath.Dir(r.file), ".routes.*")
	if err != nil {
		return err
	}
	if _, err := tmp.WriteString(strings.Join(lines, "")); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), r.file)
}

// describe renders a path's next hop and communities.
func describe(attrs []*anypb.Any) string {
	nh := "-"
	var comms []string
	for _, a := range attrs {
		var n api.NextHopAttribute
		var c api.CommunitiesAttribute
		switch {
		case a.UnmarshalTo(&n) == nil:
			nh = n.NextHop
		case a.UnmarshalTo(&c) == nil:
			for _, v := range c.Communities {
				comms = append(comms, community(v))
			}
		}
	}
	if len(comms) == 0 {
		return nh + " -"
	}
	return nh + " " + strings.Join(comms, ",")
}

func community(v uint32) string {
	if v == noExport {
		return "no-export"
	}
	return fmt.Sprintf("%d:%d", v>>16, v&0xFFFF)
}
