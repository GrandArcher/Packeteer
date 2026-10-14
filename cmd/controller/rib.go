package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/pluginhost"
	_ "github.com/GrandArcher/Packeteer/internal/plugins/all"
	"github.com/GrandArcher/Packeteer/internal/rib"
	"github.com/GrandArcher/Packeteer/internal/syshealth"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// ribGate is the RIB surface the announcer controller consults.
type ribGate struct{ v *rib.View }

func (g ribGate) Ready() bool { return g.v != nil && g.v.Ready() }

func (g ribGate) Contains(p netip.Prefix) bool {
	if g.v == nil {
		return false
	}
	_, ok := g.v.Exact(p)
	return ok
}

// MoreSpecifics lists learned prefixes inside improvements, for
// more_specific (#56).
func (g ribGate) MoreSpecifics(parents []netip.Prefix) []netip.Prefix {
	if g.v == nil {
		return nil
	}
	return g.v.MoreSpecifics(parents)
}

// NextHop is the learned next hop of an exact prefix, for inbound steers.
func (g ribGate) NextHop(p netip.Prefix) (netip.Addr, bool) {
	if g.v == nil {
		return netip.Addr{}, false
	}
	rt, ok := g.v.Exact(p)
	return rt.NextHop, ok && rt.NextHop.IsValid()
}

// NativePath is the learned route's AS path, for bgp.as_path native.
func (g ribGate) NativePath(p netip.Prefix) ([]uint32, bool) {
	if g.v == nil {
		return nil, false
	}
	rt, ok := g.v.Exact(p)
	return rt.ASPath, ok
}

// ProviderPath is a provider's learned AS path, for bgp.as_path provider.
func (g ribGate) ProviderPath(p netip.Prefix, provider string) ([]uint32, bool) {
	if g.v == nil {
		return nil, false
	}
	return g.v.ProviderPath(p, provider)
}

// newRIB builds the learn-only RIB view, or returns nil when no BGP
// neighbors are configured.
func newRIB(cfg *config.Config, log *slog.Logger) (*rib.View, error) {
	if len(cfg.BGP.Neighbors) == 0 {
		return nil, nil
	}
	rid, err := parseAddr(cfg.RouterID)
	if err != nil {
		return nil, err
	}
	providers := map[netip.Addr]string{}
	usage := map[string]string{}
	addPath := map[string]bool{}
	var peerASN map[string]uint32
	for _, p := range cfg.Providers {
		nh, err := parseAddr(p.NextHop)
		if err != nil {
			return nil, err
		}
		providers[nh] = p.Name
		if p.Exchange != "" {
			if peerASN == nil {
				peerASN = map[string]uint32{}
			}
			peerASN[p.Name] = p.PeerASN
		}
		if p.BMP != "" {
			usage[p.Name] = p.BMP
		}
		if p.AddPath {
			addPath[p.Name] = true
		}
	}
	nbrs, egress, err := ribNeighbors(cfg)
	if err != nil {
		return nil, err
	}
	listen := int32(cfg.BGP.ListenPort)
	if listen == 0 {
		listen = -1
	}
	own, large, err := ownCommunity(cfg.PacketeerCommunity)
	if err != nil {
		return nil, err
	}
	warnBMPSelfFilter(log, usage, own, large)
	var lans []netip.Prefix
	for _, ex := range cfg.Exchanges {
		lans = append(lans, ex.ExchangeLANs()...)
	}
	return rib.New(rib.Options{ASN: cfg.ASN, RouterID: rid, ListenPort: listen,
		ListenAddresses: cfg.BGP.ListenAddresses, Neighbors: nbrs, Providers: providers, BMP: usage,
		AddPath: addPath, OwnCommunity: own, OwnLarge: large, Egress: egress, PeerASN: peerASN, LANs: lans, Logger: log})
}

// ribNeighbors is the iBGP sessions and, from each neighbor's providers,
// every provider's egress routers.
func ribNeighbors(cfg *config.Config) ([]rib.Neighbor, map[string][]netip.Addr, error) {
	var nbrs []rib.Neighbor
	egress := map[string][]netip.Addr{}
	for _, n := range cfg.BGP.Neighbors {
		a, err := parseAddr(n.Address)
		if err != nil {
			return nil, nil, err
		}
		for _, name := range n.Providers {
			egress[name] = append(egress[name], a)
		}
		nb := rib.Neighbor{Address: a, Port: uint16(n.Port), Passive: n.Passive, Description: n.Description, AddPath: n.AddPath}
		if n.LocalAddress != "" {
			if nb.LocalAddress, err = parseAddr(n.LocalAddress); err != nil {
				return nil, nil, err
			}
		}
		nbrs = append(nbrs, nb)
	}
	return nbrs, egress, nil
}

// warnBMPSelfFilter warns at startup that, with BMP in use, Packeteer's own
// routes are recognised in Loc-RIB (and in Adj-RIB-In reflected by another
// router) only by packeteer_community. A router or route reflector that
// strips it would let an injected route keep its prefix learned.
func warnBMPSelfFilter(log *slog.Logger, usage map[string]string, own uint32, large string) {
	if log == nil {
		return
	}
	for _, u := range usage {
		if u != config.BMPPrefer && u != config.BMPOnly {
			continue
		}
		if own == 0 && large == "" {
			log.Warn("bmp: packeteer_community is unset, so Packeteer's own routes reported over BMP Loc-RIB cannot be recognised; set it before mode: inject")
			return
		}
		log.Warn("bmp: Packeteer's own routes are recognised over BMP by packeteer_community (and on its own session by BGP ID); make sure no import policy or route reflector on the monitored routers strips that community")
		return
	}
}

// ownCommunity turns packeteer_community into the standard form
// asn<<16|value, or a large community string (RFC 8092). Both are zero
// when it is unset. A two-part value above 16 bits is rejected.
func ownCommunity(s string) (uint32, string, error) {
	if s == "" {
		return 0, "", nil
	}
	text, err := config.CommunityText(s)
	if err != nil {
		return 0, "", fmt.Errorf("packeteer_community %q: %w", s, err)
	}
	if strings.Count(text, ":") == 2 {
		return 0, text, nil
	}
	hi, lo, _ := strings.Cut(text, ":")
	a, err := strconv.ParseUint(hi, 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf("packeteer_community %q: %w", s, err)
	}
	b, err := strconv.ParseUint(lo, 10, 16)
	if err != nil {
		return 0, "", fmt.Errorf("packeteer_community %q: %w", s, err)
	}
	return uint32(a)<<16 | uint32(b), "", nil
}

// wireRIBSources points every RIB source (BMP) at the view. It runs before
// the plugins start, so no event is lost.
func wireRIBSources(plugins *pluginhost.Set, view *rib.View, health *syshealth.Tracker) error {
	if len(plugins.RIBSources) == 0 {
		return nil
	}
	if view == nil {
		return errors.New("rib_sources require bgp.neighbors")
	}
	for _, s := range plugins.RIBSources {
		s.Plugin.SetRIBSink(ribSink(view, health, s.Name))
	}
	return nil
}

// ribSink passes a source's events to the view and notes which routers
// have a monitoring session, for the System page. Only the events that
// change a router's state are noted, not the path updates.
func ribSink(view *rib.View, health *syshealth.Tracker, source string) func(plugin.RIBEvent) {
	return func(ev plugin.RIBEvent) {
		switch ev.Kind {
		case plugin.RIBRouterDown:
			health.Record(ribRouterKey(source, ev.Router), errors.New("monitoring session closed"))
		case plugin.RIBPeerUp:
			health.Record(ribRouterKey(source, ev.Router), nil)
		}
		view.ApplyRIB(ev)
	}
}

func ribRouterKey(source string, router netip.Addr) string {
	return ribRouterPrefix(source) + router.String()
}

func ribRouterPrefix(source string) string { return "rib/" + source + "/" }

func logRIB(ctx context.Context, v *rib.View, log *slog.Logger) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			log.Info("rib", "ready", v.Ready(), "prefixes", v.Len())
		}
	}
}
