package bmp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/GrandArcher/Packeteer/pkg/plugin"
)

// DefaultLeakPort is the leak source's default BMP port, next to the RIB
// source's so both can listen on one host.
const DefaultLeakPort = DefaultPort + 1

// LeakConfig is the config of the bmp leak source (#199).
type LeakConfig struct {
	// Listen is host:port for the station (default ":11020").
	Listen string `yaml:"listen"`
	// ExternalRouters are routers outside the AS (a peer's or customer's,
	// or a looking-glass router) that send their post-policy Adj-RIB-In.
	// What they hold is what the outside sees of Packeteer.
	ExternalRouters []string `yaml:"external_routers"`
	// OwnRouters are the edge routers. Their post-policy Adj-RIB-Out toward
	// eBGP peers (RFC 8671) is read; a peer in the local AS is not.
	OwnRouters []string `yaml:"own_routers"`
	// IdleTimeout drops a router's session when no BMP message arrives for
	// this long. 0 (default) leaves it to TCP keepalive.
	IdleTimeout time.Duration `yaml:"idle_timeout"`
}

// LeakStation is the bmp leak source. It reuses the station and decoder of
// the RIB source, but its routers never feed the RIB view.
type LeakStation struct {
	st       *Station
	asn      uint32
	external map[netip.Addr]bool
	own      map[netip.Addr]bool

	mu   sync.Mutex
	sink func(plugin.LeakSighting)
}

func init() {
	plugin.LeakSources.Register("bmp", NewLeakSource)
}

// NewLeakSource validates the config. It does not listen.
func NewLeakSource(c plugin.Config, env plugin.Env) (plugin.LeakSource, error) {
	var cfg LeakConfig
	if err := c.Decode(&cfg); err != nil {
		return nil, err
	}
	if cfg.Listen == "" {
		cfg.Listen = ":" + strconv.Itoa(DefaultLeakPort)
	}
	if err := checkListen(cfg.Listen); err != nil {
		return nil, err
	}
	if len(cfg.ExternalRouters)+len(cfg.OwnRouters) == 0 {
		return nil, errors.New("bmp: external_routers or own_routers is required")
	}
	ext, err := parseRouters("external_routers", cfg.ExternalRouters)
	if err != nil {
		return nil, err
	}
	own, err := parseRouters("own_routers", cfg.OwnRouters)
	if err != nil {
		return nil, err
	}
	if cfg.IdleTimeout < 0 || (cfg.IdleTimeout > 0 && cfg.IdleTimeout < minIdleTimeout) {
		return nil, fmt.Errorf("bmp: idle_timeout %s: want 0 (off) or at least %s", cfg.IdleTimeout, minIdleTimeout)
	}
	log := env.Logger
	if log == nil {
		log = slog.Default()
	}
	l := &LeakStation{asn: env.ASN, external: map[netip.Addr]bool{}, own: map[netip.Addr]bool{}}
	st := &Station{listen: cfg.Listen, routers: map[netip.Addr]bool{}, adjOut: true, idle: cfg.IdleTimeout, log: log,
		conns: map[netip.Addr]*session{}}
	for _, a := range ext {
		l.external[a], st.routers[a] = true, true
	}
	for _, a := range own {
		if l.external[a] {
			return nil, fmt.Errorf("bmp: %s is in both external_routers and own_routers", a)
		}
		l.own[a], st.routers[a] = true, true
	}
	st.SetRIBSink(l.paths)
	l.st = st
	return l, nil
}

// SetLeakSink implements plugin.LeakSource.
func (l *LeakStation) SetLeakSink(fn func(plugin.LeakSighting)) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sink = fn
}

// Healthy is true while at least one router has a BMP session open.
func (l *LeakStation) Healthy() bool { return l.st.sessions() > 0 }

// Start implements plugin.Lifecycle.
func (l *LeakStation) Start(ctx context.Context) error { return l.st.Start(ctx) }

// Stop implements plugin.Lifecycle.
func (l *LeakStation) Stop(ctx context.Context) error { return l.st.Stop(ctx) }

// paths turns the decoder's events into sightings: an external router's
// Adj-RIB-In, or an own router's Adj-RIB-Out toward an eBGP peer.
func (l *LeakStation) paths(ev plugin.RIBEvent) {
	if ev.Kind != plugin.RIBPaths {
		return
	}
	out := ev.AdjRIBOut
	switch {
	case out && l.own[ev.Router] && ev.Peer.ASN != l.asn:
	case !out && ev.PostPolicy && l.external[ev.Router]:
	default:
		return
	}
	l.mu.Lock()
	fn := l.sink
	l.mu.Unlock()
	if fn == nil {
		return
	}
	for _, p := range ev.Paths {
		if p.Withdraw {
			continue
		}
		fn(plugin.LeakSighting{Prefix: p.Prefix, ASPath: p.ASPath, Communities: p.Communities,
			LargeCommunities: p.LargeCommunities, Seen: ev.Router.String(), OurExport: out})
	}
}
