package main

import (
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/GrandArcher/Packeteer/internal/config"
	"github.com/GrandArcher/Packeteer/internal/exchange"
	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// exchangePeerMonitor builds the BMP exchange peer session monitor (#147).
// Every configured exchange peer is watched; max_prefix only decides when
// the warning fires. It returns nil when there are no exchanges.
func exchangePeerMonitor(cfg *config.Config) *exchange.PeerMonitor {
	if cfg == nil || len(cfg.Exchanges) == 0 {
		return nil
	}
	var specs []exchange.PeerSpec
	for _, ex := range cfg.Exchanges {
		for _, p := range ex.Peers {
			nh, err := netip.ParseAddr(p.NextHop)
			if err != nil {
				continue // Validate reports it
			}
			specs = append(specs, exchange.PeerSpec{Exchange: ex.Name, Name: p.Name, NextHop: nh,
				MaxPrefix: p.MaxPrefix, WarnPct: ex.MaxPrefixWarnPct})
		}
	}
	if len(specs) == 0 {
		return nil
	}
	return exchange.NewPeerMonitor(specs)
}

// peerChangeEvent turns one exchange peer transition into its catalog
// event. An unknown kind returns a zero Event, which the caller skips.
func peerChangeEvent(now time.Time, c exchange.PeerChange) plugin.Event {
	fields := map[string]string{"exchange": c.Exchange, "peer": c.Peer, "router": c.Router.String()}
	switch c.Kind {
	case exchange.PeerChangeUp:
		return plugin.NewEvent(plugin.EventExchangePeerUp, now,
			fmt.Sprintf("exchange peer %s on %s is up", c.Peer, c.Exchange), fields)
	case exchange.PeerChangeDown:
		fields["reason"] = c.Reason
		return plugin.NewEvent(plugin.EventExchangePeerDown, now,
			fmt.Sprintf("exchange peer %s on %s is down (%s)", c.Peer, c.Exchange, c.Reason), fields)
	case exchange.PeerChangePrefixHigh:
		fields["prefixes"] = strconv.Itoa(c.Prefixes)
		fields["max_prefix"] = strconv.Itoa(c.MaxPrefix)
		return plugin.NewEvent(plugin.EventExchangeMaxPrefix, now,
			fmt.Sprintf("exchange peer %s on %s has %d of its %d max_prefix routes", c.Peer, c.Exchange, c.Prefixes, c.MaxPrefix), fields)
	case exchange.PeerChangePrefixOK:
		fields["prefixes"] = strconv.Itoa(c.Prefixes)
		fields["max_prefix"] = strconv.Itoa(c.MaxPrefix)
		return plugin.NewEvent(plugin.EventExchangeMaxPrefixCleared, now,
			fmt.Sprintf("exchange peer %s on %s is back below its max-prefix warning share", c.Peer, c.Exchange), fields)
	}
	return plugin.Event{}
}
